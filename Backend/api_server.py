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
from main_agent import stream_agent, resume_agent, get_pending_approval
from chat_persistence import ChatDB
from engine_manager import EngineManager
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
    # Startup: verify DB connection + init custom tables
    try:
        db = DBManager()
        db.init_tables()
        db.close()
        print("[API] OK - Data tables verified")
    except Exception as e:
        print(f"[API] ERROR - Data tables failed: {e}")
    
    try:
        chat_db = ChatDB()
        chat_db.init_tables()
        # Mark all 'running' tool calls as 'paused' since server just started
        # (any engine that was running before the restart is gone)
        with chat_db.conn.cursor() as cur:
            cur.execute("UPDATE tool_calls SET status = 'paused' WHERE status = 'running'")
            chat_db.conn.commit()
        chat_db.close()
        print("[API] OK - Chat tables verified + stale tool calls cleaned")
    except Exception as e:
        print(f"[API] ERROR - Chat tables failed: {e}")
    
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


@app.get("/api/chats")
async def list_chats():
    """List all chat sessions from our custom table."""
    try:
        db = ChatDB()
        threads = db.list_chat_threads()
        db.close()
        return [{"thread_id": t["thread_id"], "created_at": t["created_at"].isoformat() if t.get("created_at") else None} for t in threads]
    except Exception:
        return []


@app.get("/api/chats/{thread_id}")
async def get_history(thread_id: str):
    """Get the full message history + tool calls for a chat session."""
    try:
        db = ChatDB()
        messages = db.get_chat_history(thread_id)
        tool_calls = db.get_tool_calls(thread_id)
        db.close()
        
        # Serialize datetime objects
        for msg in messages:
            if msg.get("created_at") and hasattr(msg["created_at"], "isoformat"):
                msg["created_at"] = msg["created_at"].isoformat()
        for tc in tool_calls:
            if tc.get("created_at") and hasattr(tc["created_at"], "isoformat"):
                tc["created_at"] = tc["created_at"].isoformat()
        
        return {"messages": messages, "tool_calls": tool_calls}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/chats/{thread_id}")
async def delete_chat(thread_id: str):
    """Delete a chat session from custom tables + LangGraph checkpoints."""
    from engine_progress import cancel_engine

    # Stop any running agent/engine for this chat
    cancel_event = _active_tasks.get(thread_id)
    if cancel_event:
        cancel_event.set()
        cancel_engine(thread_id)

    # Delete from our custom tables
    try:
        db = ChatDB()
        db.delete_thread(thread_id)
        db.close()
    except Exception:
        pass

    # Delete from LangGraph checkpoint tables
    import psycopg2
    try:
        conn = psycopg2.connect(PG_CONN_STRING)
        with conn.cursor() as cur:
            cur.execute("DELETE FROM checkpoints WHERE thread_id = %s", (thread_id,))
            cur.execute("DELETE FROM checkpoint_writes WHERE thread_id = %s", (thread_id,))
            cur.execute("DELETE FROM checkpoint_blobs WHERE thread_id = %s", (thread_id,))
        conn.commit()
        conn.close()
    except Exception:
        pass

    return {"status": "deleted", "thread_id": thread_id}


# ═════════════════════════════════════════════════════════════════════════════
# Agent Streaming Endpoint (SSE)
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/api/chats/{thread_id}/message")
async def send_message(thread_id: str, request: MessageRequest):
    """
    Send a message to the AI agent and stream the response via SSE.
    Saves every token to our custom DB in real-time.
    Agent tools now return immediately (engines run in background).
    If the agent calls interrupt(), this stream yields a tool_approval event and stops.
    """
    user_message = request.message
    if not user_message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    cancel_event = Event()
    _active_tasks[thread_id] = cancel_event

    # Save user message to DB
    try:
        db = ChatDB()
        msg_idx = db.get_next_message_index(thread_id)
        db.insert_user_message(thread_id, user_message, msg_idx)
        assistant_msg_idx = msg_idx + 1
        assistant_row_id = db.insert_assistant_message(thread_id, assistant_msg_idx)
        db.close()
    except Exception as e:
        print(f"[API] Error saving user message: {e}")
        assistant_row_id = None
        assistant_msg_idx = 0

    async def event_generator():
        sse_queue = asyncio.Queue()
        loop = asyncio.get_event_loop()
        agent_done = Event()

        def _stream_agent():
            from main_agent import _chat_thread_local
            _chat_thread_local.assistant_msg_idx = assistant_msg_idx
            got_approval_request = False
            try:
                for event in stream_agent(user_message, thread_id=thread_id):
                    if cancel_event.is_set():
                        loop.call_soon_threadsafe(
                            sse_queue.put_nowait,
                            {"type": "stopped", "message": "Agent stopped by user"}
                        )
                        return

                    # Save tokens to DB as they arrive
                    if event.get("type") == "token" and assistant_row_id:
                        try:
                            db = ChatDB()
                            db.append_token(assistant_row_id, event["content"])
                            db.close()
                        except Exception:
                            pass

                    # When tool_approval fires, save a placeholder message
                    # so the assistant bubble isn't blank on reload
                    if event.get("type") == "tool_approval" and assistant_row_id:
                        got_approval_request = True
                        approval_text = f"I'd like to run **{event.get('engine_name', 'an engine')}** for:\n> {event.get('query', '')}"
                        try:
                            db = ChatDB()
                            db.append_token(assistant_row_id, approval_text)
                            db.close()
                        except Exception:
                            pass

                    loop.call_soon_threadsafe(sse_queue.put_nowait, event)
            except Exception as e:
                loop.call_soon_threadsafe(
                    sse_queue.put_nowait,
                    {"type": "error", "message": str(e)}
                )
            finally:
                if assistant_row_id:
                    try:
                        db = ChatDB()
                        if cancel_event.is_set():
                            db.complete_message(assistant_row_id, "\n\n*Agent stopped by user.*")
                        elif got_approval_request:
                            # Don't mark as complete — the agent is paused waiting for approval
                            db.complete_message(assistant_row_id)
                        else:
                            db.complete_message(assistant_row_id)
                        db.close()
                    except Exception:
                        pass
                agent_done.set()

        stream_thread = Thread(target=_stream_agent, daemon=True)
        stream_thread.start()

        while True:
            if agent_done.is_set() and sse_queue.empty():
                break
            try:
                event = await asyncio.wait_for(sse_queue.get(), timeout=0.3)
                yield {
                    "event": event.get("type", "message"),
                    "data": json.dumps(event),
                }
            except asyncio.TimeoutError:
                continue

        stream_thread.join(timeout=2)
        _active_tasks.pop(thread_id, None)

    return EventSourceResponse(event_generator())


# ═════════════════════════════════════════════════════════════════════════════
# Human-in-the-Loop: Approve / Decline Tool
# ═════════════════════════════════════════════════════════════════════════════

class ApprovalRequest(BaseModel):
    action: str  # "accept" or "decline"


@app.post("/api/chats/{thread_id}/approve")
async def approve_tool(thread_id: str, request: ApprovalRequest):
    """
    Accept or decline a pending tool approval request.
    Resumes the LangGraph agent with the human's decision.
    Returns an SSE stream with the agent's continuation.
    """
    human_response = {"action": request.action}

    cancel_event = Event()
    _active_tasks[thread_id] = cancel_event

    # Get assistant row for token saving
    try:
        db = ChatDB()
        assistant_row_id = db.insert_assistant_message(
            thread_id, db.get_next_message_index(thread_id)
        )
        db.close()
    except Exception:
        assistant_row_id = None

    async def event_generator():
        sse_queue = asyncio.Queue()
        loop = asyncio.get_event_loop()
        agent_done = Event()

        def _resume_agent():
            try:
                for event in resume_agent(thread_id, human_response):
                    if cancel_event.is_set():
                        loop.call_soon_threadsafe(
                            sse_queue.put_nowait,
                            {"type": "stopped", "message": "Agent stopped by user"}
                        )
                        return

                    if event.get("type") == "token" and assistant_row_id:
                        try:
                            db = ChatDB()
                            db.append_token(assistant_row_id, event["content"])
                            db.close()
                        except Exception:
                            pass

                    loop.call_soon_threadsafe(sse_queue.put_nowait, event)
            except Exception as e:
                loop.call_soon_threadsafe(
                    sse_queue.put_nowait,
                    {"type": "error", "message": str(e)}
                )
            finally:
                if assistant_row_id:
                    try:
                        db = ChatDB()
                        db.complete_message(assistant_row_id)
                        db.close()
                    except Exception:
                        pass
                agent_done.set()

        stream_thread = Thread(target=_resume_agent, daemon=True)
        stream_thread.start()

        while True:
            if agent_done.is_set() and sse_queue.empty():
                break
            try:
                event = await asyncio.wait_for(sse_queue.get(), timeout=0.3)
                yield {
                    "event": event.get("type", "message"),
                    "data": json.dumps(event),
                }
            except asyncio.TimeoutError:
                continue

        stream_thread.join(timeout=2)
        _active_tasks.pop(thread_id, None)

    return EventSourceResponse(event_generator())


# ═════════════════════════════════════════════════════════════════════════════
# Engine Live Progress (SSE) + Controls
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/engine/{engine_thread_id}/stream")
async def stream_engine(engine_thread_id: str):
    """
    SSE stream of live progress for a running engine.
    The frontend connects to this after receiving an engine_started event.
    """
    import queue as queue_module

    mgr = EngineManager()
    record = mgr.get_record(engine_thread_id)

    if not record:
        raise HTTPException(status_code=404, detail=f"Engine '{engine_thread_id}' not found")

    async def event_generator():
        progress_q = record.progress_queue
        while True:
            # First, drain any available items from the queue
            got_item = False
            while not progress_q.empty():
                try:
                    progress = progress_q.get_nowait()
                    got_item = True
                    yield {
                        "event": progress.get("type", "engine_progress"),
                        "data": json.dumps(progress),
                    }
                    # If this was a terminal event, stop
                    if progress.get("type") in ("engine_done", "engine_paused", "engine_error"):
                        return
                except queue_module.Empty:
                    break

            # Check if engine is done (after draining queue)
            if record.status in ("done", "error", "paused"):
                return

            # Wait for next item with timeout
            try:
                progress = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: progress_q.get(timeout=1.0)
                )
                yield {
                    "event": progress.get("type", "engine_progress"),
                    "data": json.dumps(progress),
                }
                if progress.get("type") in ("engine_done", "engine_paused", "engine_error"):
                    return
            except queue_module.Empty:
                # Send heartbeat to keep connection alive
                yield {"event": "heartbeat", "data": "{}"}

    return EventSourceResponse(event_generator())


@app.post("/api/engine/{engine_thread_id}/stop")
async def stop_engine(engine_thread_id: str):
    """Pause a running engine."""
    from engine_progress import cancel_engine as ep_cancel

    mgr = EngineManager()
    record = mgr.get_record(engine_thread_id)

    if record:
        # Signal via EngineManager (sets record.cancel_event)
        mgr.pause_engine(engine_thread_id)
        # Also signal via engine_progress (sets _cancel_events for the chat)
        ep_cancel(record.chat_thread_id)
    
    return {"status": "pausing", "engine_thread_id": engine_thread_id}


@app.post("/api/engine/{engine_thread_id}/resume")
async def resume_engine_endpoint(engine_thread_id: str):
    """
    Resume a paused engine. Returns the new SSE stream endpoint.
    """
    mgr = EngineManager()
    # Find the chat_thread_id from DB
    try:
        db = ChatDB()
        with db.conn.cursor() as cur:
            cur.execute(
                "SELECT thread_id FROM tool_calls WHERE engine_thread_id = %s LIMIT 1",
                (engine_thread_id,),
            )
            row = cur.fetchone()
        db.close()
        chat_thread_id = row[0] if row else None
    except Exception:
        chat_thread_id = None

    if not chat_thread_id:
        raise HTTPException(status_code=404, detail="Engine not found in database")

    record = mgr.resume_engine(engine_thread_id, chat_thread_id)
    if not record:
        raise HTTPException(status_code=404, detail="Could not resume engine")

    return {
        "status": "resumed",
        "engine_thread_id": engine_thread_id,
        "stream_url": f"/api/engine/{engine_thread_id}/stream",
    }


@app.get("/api/chats/{thread_id}/engines")
async def list_chat_engines(thread_id: str):
    """
    List all engine runs for a chat, with their current status.
    Also checks LangGraph agent state for pending approval interrupts.
    Used by frontend on chat open to check for running/paused engines.
    """
    mgr = EngineManager()
    engines = mgr.list_engines_for_chat(thread_id)

    # Serialize datetimes
    for eng in engines:
        if eng.get("created_at") and hasattr(eng["created_at"], "isoformat"):
            eng["created_at"] = eng["created_at"].isoformat()

    # Check if any engine is currently running in memory
    running_engine = mgr.get_running_engine(thread_id)

    # Check if there's a pending tool approval in LangGraph state
    # (e.g., server restarted while waiting for human to accept/decline)
    pending_approval = get_pending_approval(thread_id)

    return {
        "engines": engines,
        "has_running": running_engine is not None,
        "running_engine_thread_id": running_engine.engine_thread_id if running_engine else None,
        "pending_approval": pending_approval,
    }


@app.post("/api/chats/{thread_id}/stop")
async def stop_agent(thread_id: str):
    """Stop a currently running agent for the given thread."""
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
