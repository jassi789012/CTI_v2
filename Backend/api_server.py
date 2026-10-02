"""
CTI API Server — FastAPI Backend
=================================
REST + SSE API for the CTI platform frontend.

Endpoints:
  Chat Management:
    POST   /api/chats/new               — Create a new chat session
    GET    /api/chats                    — List all chat sessions
    GET    /api/chats/{thread_id}        — Get chat history
    DELETE /api/chats/{thread_id}        — Delete a chat session

  Agent Interaction:
    POST   /api/chats/{thread_id}/message — Send message & stream response (SSE)
    POST   /api/chats/{thread_id}/stop    — Stop the running agent/engine

  Search (Local DB):
    GET    /api/search/ip/{ip}           — Get all data for an IP
    GET    /api/search/cve/{cve_id}      — Get full CVE details + analysis
    GET    /api/stats                    — Get database statistics

Usage:
    uvicorn api_server:app --reload --port 8000
    
    Or:
    python api_server.py
"""

import asyncio
import json
import os
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from threading import Thread, Event

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

# ─── Paths ───────────────────────────────────────────────────────────────────
BACKEND_DIR = Path(r"c:\Users\jassi\OneDrive\Documents\CTI_V2\Backend")
sys.path.insert(0, str(BACKEND_DIR))

# ─── Load .env ───────────────────────────────────────────────────────────────
env_path = BACKEND_DIR.parent / ".env"
load_dotenv(env_path)

PG_CONN_STRING = (
    f"postgresql://{os.getenv('PG_USER', 'postgres')}:"
    f"{os.getenv('PG_PASSWORD', '')}@"
    f"{os.getenv('PG_HOST', 'localhost')}:"
    f"{os.getenv('PG_PORT', '5432')}/"
    f"{os.getenv('PG_DATABASE', 'cti_db')}"
)

# ─── Imports from our backend ────────────────────────────────────────────────
from main_agent import (
    stream_agent,
    get_chat_history,
    list_chat_sessions,
)
from db_manager import DBManager


# ═════════════════════════════════════════════════════════════════════════════
# Active task tracker (for stopping running agents)
# ═════════════════════════════════════════════════════════════════════════════

# Maps thread_id -> Event (set the event to signal cancellation)
_active_tasks: dict[str, Event] = {}


# ═════════════════════════════════════════════════════════════════════════════
# FastAPI App
# ═════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    # Startup: verify DB connection
    try:
        db = DBManager()
        db.init_tables()
        db.close()
        print("[API] ✅ Database connection verified")
    except Exception as e:
        print(f"[API] ⚠️  Database connection failed: {e}")
    
    yield
    
    # Shutdown: cancel all active tasks
    for event in _active_tasks.values():
        event.set()
    print("[API] Shutting down...")


app = FastAPI(
    title="CTI Platform API",
    description="Cyber Threat Intelligence API — Chat with an AI agent, run enumeration engines, and search the local database.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow frontend to connect from any origin during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═════════════════════════════════════════════════════════════════════════════
# Request/Response Models
# ═════════════════════════════════════════════════════════════════════════════

class MessageRequest(BaseModel):
    message: str


class NewChatResponse(BaseModel):
    thread_id: str


class ChatHistoryMessage(BaseModel):
    role: str
    content: str


class ChatSession(BaseModel):
    thread_id: str


class IPSearchResult(BaseModel):
    found: bool
    data: dict | None = None


class CVESearchResult(BaseModel):
    found: bool
    data: dict | None = None


class StatsResponse(BaseModel):
    total_hosts: int
    total_scans: int
    total_cves: int
    total_cve_analyses: int


# ═════════════════════════════════════════════════════════════════════════════
# Chat Management Endpoints
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/api/chats/new", response_model=NewChatResponse)
async def create_new_chat():
    """Create a new chat session and return the thread_id."""
    thread_id = f"chat_{uuid.uuid4().hex[:8]}"
    return NewChatResponse(thread_id=thread_id)


@app.get("/api/chats", response_model=list[ChatSession])
async def list_chats():
    """List all past chat session IDs."""
    sessions = list_chat_sessions()
    return [ChatSession(thread_id=sid) for sid in sessions]


@app.get("/api/chats/{thread_id}", response_model=list[ChatHistoryMessage])
async def get_history(thread_id: str):
    """Get the full message history for a chat session."""
    history = get_chat_history(thread_id)
    return [ChatHistoryMessage(**msg) for msg in history]


@app.delete("/api/chats/{thread_id}")
async def delete_chat(thread_id: str):
    """Delete a chat session's checkpoints from the database."""
    import psycopg2
    try:
        conn = psycopg2.connect(PG_CONN_STRING)
        with conn.cursor() as cur:
            # Delete from all checkpoint-related tables
            cur.execute(
                "DELETE FROM checkpoints WHERE thread_id = %s", (thread_id,)
            )
            cur.execute(
                "DELETE FROM checkpoint_writes WHERE thread_id = %s", (thread_id,)
            )
            cur.execute(
                "DELETE FROM checkpoint_blobs WHERE thread_id = %s", (thread_id,)
            )
        conn.commit()
        conn.close()
        return {"status": "deleted", "thread_id": thread_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete chat: {str(e)}")


# ═════════════════════════════════════════════════════════════════════════════
# Agent Streaming Endpoint (SSE)
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/api/chats/{thread_id}/message")
async def send_message(thread_id: str, request: MessageRequest):
    """
    Send a message to the AI agent and stream the response via SSE.
    
    The stream emits JSON events:
      - {"type": "token",      "content": "partial text..."}
      - {"type": "tool_start", "tool": "scan_ip_list", "input": {...}}
      - {"type": "tool_end",   "tool": "scan_ip_list", "output": "..."}
      - {"type": "done",       "thread_id": "chat_abc123"}
      - {"type": "error",      "message": "..."}
    """
    user_message = request.message
    if not user_message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    # Create a cancellation event for this thread
    cancel_event = Event()
    _active_tasks[thread_id] = cancel_event

    async def event_generator():
        """Run the agent in a background thread and yield SSE events."""
        queue = asyncio.Queue()
        loop = asyncio.get_event_loop()

        def _run_agent():
            """Runs in a background thread — feeds events into the async queue."""
            try:
                for event in stream_agent(user_message, thread_id=thread_id):
                    if cancel_event.is_set():
                        loop.call_soon_threadsafe(
                            queue.put_nowait,
                            {"type": "stopped", "message": "Agent stopped by user"}
                        )
                        return
                    loop.call_soon_threadsafe(queue.put_nowait, event)
            except Exception as e:
                loop.call_soon_threadsafe(
                    queue.put_nowait,
                    {"type": "error", "message": str(e)}
                )
            finally:
                # Signal that streaming is complete
                loop.call_soon_threadsafe(queue.put_nowait, None)

        # Start the agent in a background thread
        agent_thread = Thread(target=_run_agent, daemon=True)
        agent_thread.start()

        # Yield events from the queue as SSE
        while True:
            event = await queue.get()
            if event is None:
                break
            yield {
                "event": event.get("type", "message"),
                "data": json.dumps(event),
            }

        # Cleanup
        _active_tasks.pop(thread_id, None)

    return EventSourceResponse(event_generator())


@app.post("/api/chats/{thread_id}/stop")
async def stop_agent(thread_id: str):
    """Stop a currently running agent/engine for the given thread."""
    cancel_event = _active_tasks.get(thread_id)
    if cancel_event:
        cancel_event.set()
        return {"status": "stopping", "thread_id": thread_id}
    return {"status": "not_running", "thread_id": thread_id}


# ═════════════════════════════════════════════════════════════════════════════
# Search Endpoints (Local Database)
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/search/ip/{ip_address}")
async def search_ip(ip_address: str):
    """Search the local database for all data on an IP address."""
    try:
        db = DBManager()
        
        host = db.get_host_by_ip(ip_address)
        if not host:
            db.close()
            return {"found": False, "data": None}
        
        # Convert non-serializable types
        for key, value in host.items():
            if hasattr(value, 'isoformat'):
                host[key] = value.isoformat()
            elif not isinstance(value, (str, int, float, bool, list, dict, type(None))):
                host[key] = str(value)
        
        timeline = db.get_host_timeline(ip_address)
        for entry in timeline:
            for key, value in entry.items():
                if hasattr(value, 'isoformat'):
                    entry[key] = value.isoformat()
                elif not isinstance(value, (str, int, float, bool, list, dict, type(None))):
                    entry[key] = str(value)
        
        scan_count = db.get_scan_count(ip_address)
        
        db.close()
        
        return {
            "found": True,
            "data": {
                "host": host,
                "timeline": timeline,
                "scan_count": scan_count,
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/api/search/cve/{cve_id}")
async def search_cve(cve_id: str):
    """Search the local database for full CVE details + ChatGPT analysis."""
    try:
        db = DBManager()
        
        result = db.get_cve_full(cve_id.upper())
        db.close()
        
        if not result:
            return {"found": False, "data": None}
        
        # Convert non-serializable types
        def serialize(obj):
            if isinstance(obj, dict):
                return {k: serialize(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [serialize(item) for item in obj]
            elif hasattr(obj, 'isoformat'):
                return obj.isoformat()
            elif not isinstance(obj, (str, int, float, bool, type(None))):
                return str(obj)
            return obj
        
        return {"found": True, "data": serialize(result)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats():
    """Get database statistics (total hosts, scans, CVEs, analyses)."""
    try:
        db = DBManager()
        with db.conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM hosts")
            total_hosts = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM scans")
            total_scans = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM cve_details")
            total_cves = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM cve_analysis")
            total_cve_analyses = cur.fetchone()[0]
        
        db.close()
        
        return StatsResponse(
            total_hosts=total_hosts,
            total_scans=total_scans,
            total_cves=total_cves,
            total_cve_analyses=total_cve_analyses,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


# ═════════════════════════════════════════════════════════════════════════════
# Health Check
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    db_ok = False
    try:
        db = DBManager()
        db.close()
        db_ok = True
    except Exception:
        pass
    
    return {
        "status": "healthy" if db_ok else "degraded",
        "database": "connected" if db_ok else "disconnected",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ═════════════════════════════════════════════════════════════════════════════
# Run
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    print(f"\n{'=' * 60}")
    print(f"  CTI API Server")
    print(f"  http://localhost:8000")
    print(f"  Docs: http://localhost:8000/docs")
    print(f"{'=' * 60}\n")
    uvicorn.run("api_server:app", host="0.0.0.0", port=8000, reload=True)
