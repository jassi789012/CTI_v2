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
from psycopg2.extras import RealDictCursor


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
        from engine_manager import EngineManager
        mgr = EngineManager()

        db = ChatDB()
        messages = db.get_chat_history(thread_id)
        db.close()

        # Get tool calls with real-time in-memory status
        tool_calls = mgr.list_engines_for_chat(thread_id)
        
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
    """Delete a chat session, stopping all running engines & agent tasks, and removing checkpoints."""
    from engine_progress import cancel_engine
    from engine_manager import EngineManager

    # 1. Stop any running agent task for this chat
    cancel_event = _active_tasks.get(thread_id)
    if cancel_event:
        cancel_event.set()

    # 2. Stop and cancel all running background engines for this chat
    mgr = EngineManager()
    stopped_engine_ids = mgr.stop_all_engines_for_chat(thread_id)

    # 3. Always signal cancellation in engine_progress for the chat
    cancel_engine(chat_thread_id=thread_id)

    # 4. Find all tool calls / engines from DB to cancel and collect IDs
    all_engine_ids = set(stopped_engine_ids)
    try:
        db = ChatDB()
        tool_calls = db.get_tool_calls(thread_id)
        for tc in tool_calls:
            eid = tc.get("engine_thread_id")
            if eid:
                all_engine_ids.add(eid)
                cancel_engine(engine_thread_id=eid)
        # Delete from our custom tables (chat_messages + tool_calls)
        db.delete_thread(thread_id)
        db.close()
    except Exception as e:
        print(f"[Delete Chat] Error cleaning ChatDB for {thread_id}: {e}")

    # 5. Delete from LangGraph checkpoint tables (both chat and engine runs)
    import psycopg2
    try:
        conn = psycopg2.connect(PG_CONN_STRING)
        with conn.cursor() as cur:
            # Delete chat thread checkpoints
            cur.execute("DELETE FROM checkpoints WHERE thread_id = %s", (thread_id,))
            cur.execute("DELETE FROM checkpoint_writes WHERE thread_id = %s", (thread_id,))
            cur.execute("DELETE FROM checkpoint_blobs WHERE thread_id = %s", (thread_id,))
            # Delete all associated engine checkpoints
            for eid in all_engine_ids:
                cur.execute("DELETE FROM checkpoints WHERE thread_id = %s", (eid,))
                cur.execute("DELETE FROM checkpoint_writes WHERE thread_id = %s", (eid,))
                cur.execute("DELETE FROM checkpoint_blobs WHERE thread_id = %s", (eid,))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Delete Chat] Error cleaning checkpoints for {thread_id}: {e}")

    return {
        "status": "deleted",
        "thread_id": thread_id,
        "stopped_engines": list(all_engine_ids),
    }


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

    mgr = EngineManager()
    if mgr.is_engine_running(thread_id):
        raise HTTPException(
            status_code=409,
            detail="An engine is already running in this chat. Pause it first to run another engine."
        )

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

                    # When db_results fires, save a markdown table for persistence
                    if event.get("type") == "db_results" and assistant_row_id:
                        try:
                            cols = event.get("columns", [])
                            rows = event.get("rows", [])
                            total = event.get("total", 0)
                            query = event.get("query", "")
                            md_lines = [f"\n\n**Query Results** ({total} row{'s' if total != 1 else ''})\n"]
                            md_lines.append(f"```sql\n{query}\n```\n")
                            if cols:
                                md_lines.append("| " + " | ".join(cols) + " |")
                                md_lines.append("| " + " | ".join(["---"] * len(cols)) + " |")
                                for row in rows[:50]:
                                    cells = [str(v).replace("|", "\\|")[:100] if v is not None else "\u2014" for v in row]
                                    md_lines.append("| " + " | ".join(cells) + " |")
                                if total > 50:
                                    md_lines.append(f"\n*...and {total - 50} more rows*")
                            md_table = "\n".join(md_lines) + "\n\n"
                            db = ChatDB()
                            db.append_token(assistant_row_id, md_table)
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
    if request.action == "accept":
        mgr = EngineManager()
        if mgr.is_engine_running(thread_id):
            raise HTTPException(
                status_code=409,
                detail="An engine is already running in this chat. Pause it first before starting this engine."
            )

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
            if record.status in ("done", "error", "paused", "stopped"):
                if record.status in ("paused", "stopped"):
                    yield {
                        "event": "engine_paused",
                        "data": json.dumps({"type": "engine_paused", "engine_thread_id": engine_thread_id}),
                    }
                elif record.status == "done":
                    yield {
                        "event": "engine_done",
                        "data": json.dumps({"type": "engine_done", "engine_thread_id": engine_thread_id}),
                    }
                elif record.status == "error":
                    yield {
                        "event": "engine_error",
                        "data": json.dumps({"type": "engine_error", "error": record.error or "Engine error"}),
                    }
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
                # Check status again in case it just became paused/done/stopped
                if record.status in ("paused", "stopped"):
                    yield {
                        "event": "engine_paused",
                        "data": json.dumps({"type": "engine_paused", "engine_thread_id": engine_thread_id}),
                    }
                    return
                elif record.status == "done":
                    yield {
                        "event": "engine_done",
                        "data": json.dumps({"type": "engine_done", "engine_thread_id": engine_thread_id}),
                    }
                    return
                elif record.status == "error":
                    yield {
                        "event": "engine_error",
                        "data": json.dumps({"type": "engine_error", "error": record.error or "Engine error"}),
                    }
                    return
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
        # Also signal via engine_progress (sets _cancel_events for both chat and engine)
        ep_cancel(chat_thread_id=record.chat_thread_id, engine_thread_id=engine_thread_id)
    else:
        ep_cancel(engine_thread_id=engine_thread_id)
    
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

    running_rec = mgr.get_running_engine(chat_thread_id)
    if running_rec and running_rec.engine_thread_id != engine_thread_id:
        raise HTTPException(
            status_code=409,
            detail="An engine is already running in this chat. Pause it first before resuming another engine."
        )

    try:
        record = mgr.resume_engine(engine_thread_id, chat_thread_id)
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))

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
    """Stop a currently running agent and any running engines for the given thread."""
    from engine_progress import cancel_engine
    from engine_manager import EngineManager

    stopped = False
    cancel_event = _active_tasks.get(thread_id)
    if cancel_event:
        cancel_event.set()
        stopped = True

    mgr = EngineManager()
    stopped_eids = mgr.stop_all_engines_for_chat(thread_id)
    if stopped_eids:
        stopped = True

    cancel_engine(chat_thread_id=thread_id)

    try:
        db = ChatDB()
        db.pause_all_running(thread_id)
        db.close()
    except Exception:
        pass

    return {
        "status": "stopping" if stopped else "not_running",
        "thread_id": thread_id,
        "stopped_engines": stopped_eids,
    }


# ═════════════════════════════════════════════════════════════════════════════
# Shodan-Style Query Parser
# ═════════════════════════════════════════════════════════════════════════════

import re as _re
import ipaddress

# Comprehensive Country code -> full name mapping for Shodan-style query shortcuts
_COUNTRY_CODE_MAP = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AD": "Andorra", "AO": "Angola",
    "AR": "Argentina", "AM": "Armenia", "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan",
    "BH": "Bahrain", "BD": "Bangladesh", "BY": "Belarus", "BE": "Belgium", "BZ": "Belize",
    "BR": "Brazil", "BG": "Bulgaria", "CA": "Canada", "CL": "Chile", "CN": "China",
    "CO": "Colombia", "CR": "Costa Rica", "HR": "Croatia", "CY": "Cyprus", "CZ": "Czech Republic",
    "DK": "Denmark", "EG": "Egypt", "EE": "Estonia", "FI": "Finland", "FR": "France",
    "GE": "Georgia", "DE": "Germany", "GR": "Greece", "HK": "Hong Kong", "HU": "Hungary",
    "IS": "Iceland", "IN": "India", "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq",
    "IE": "Ireland", "IL": "Israel", "IT": "Italy", "JP": "Japan", "JO": "Jordan",
    "KZ": "Kazakhstan", "KE": "Kenya", "KR": "South Korea", "KW": "Kuwait", "LV": "Latvia",
    "LB": "Lebanon", "LT": "Lithuania", "LU": "Luxembourg", "MY": "Malaysia", "MX": "Mexico",
    "MD": "Moldova", "MC": "Monaco", "MA": "Morocco", "NL": "Netherlands", "NZ": "New Zealand",
    "NG": "Nigeria", "NO": "Norway", "OM": "Oman", "PK": "Pakistan", "PA": "Panama",
    "PE": "Peru", "PH": "Philippines", "PL": "Poland", "PT": "Portugal", "QA": "Qatar",
    "RO": "Romania", "RU": "Russia", "SA": "Saudi Arabia", "RS": "Serbia", "SG": "Singapore",
    "SK": "Slovakia", "SI": "Slovenia", "ZA": "South Africa", "ES": "Spain", "LK": "Sri Lanka",
    "SE": "Sweden", "CH": "Switzerland", "TW": "Taiwan", "TH": "Thailand", "TR": "Turkey",
    "UA": "Ukraine", "AE": "United Arab Emirates", "GB": "United Kingdom", "UK": "United Kingdom",
    "US": "United States", "VN": "Vietnam"
}


def _parse_shodan_query(q: str) -> tuple[dict, list[str]]:
    """
    Parse a Shodan-style query string into structured filters and free-text terms.
    Supports dotted keys (http.title, ssl.cert.issuer.cn, ssh.fingerprint, etc.)
    and quoted phrases (country:"United States", product:"Apache httpd").
    
    Returns (filters_dict, free_text_terms_list).
    """
    filters = {}
    text_query = q

    # Match key:"quoted value" or key:value
    pattern = r'([a-zA-Z0-9_.]+):("([^"]+)"|(\S+))'
    for match in _re.finditer(pattern, q):
        key = match.group(1).lower()
        if match.group(3) is not None:
            val = match.group(3)
        else:
            val = match.group(4)

        text_query = text_query.replace(match.group(0), " ")
        filters[key] = val

    terms = [t for t in text_query.split() if t.strip()]
    return filters, terms


SEARCH_FILTERS_SCHEMA = [
    {
        "category": "General & Network",
        "description": "Network addresses, autonomous systems, open ports, and infrastructure",
        "filters": [
            {"name": "all", "description": "Searches across searchable banner fields", "example": "all:OpenSSH"},
            {"name": "ip", "description": "Matches a specific IP address", "example": "ip:103.125.155.37"},
            {"name": "net", "description": "Matches an IP address or CIDR network range", "example": "net:103.125.155.0/24"},
            {"name": "port", "description": "Matches an open port number", "example": "port:22"},
            {"name": "asn", "description": "Matches an Autonomous System Number (ASN)", "example": "asn:AS212317"},
            {"name": "org", "description": "Matches the organization associated with an IP", "example": 'org:"Hetzner Online"'},
            {"name": "isp", "description": "Matches the Internet Service Provider", "example": 'isp:"Akamai Connected Cloud"'},
            {"name": "hostname", "description": "Matches a hostname associated with a device", "example": "hostname:your-server.de"},
            {"name": "has_ipv6", "description": "Filters records based on IPv6 metadata availability", "example": "has_ipv6:true"}
        ]
    },
    {
        "category": "Geographic",
        "description": "Physical geolocation of scanned systems",
        "filters": [
            {"name": "country", "description": "Matches a two-letter country code or country name", "example": "country:IN"},
            {"name": "city", "description": "Matches the city associated with a device", "example": 'city:"Portland"'},
            {"name": "state", "description": "Matches the state or province associated with a device", "example": "state:California"},
            {"name": "region", "description": "Matches a geographic region when indexed", "example": 'region:"us-nj"'}
        ]
    },
    {
        "category": "Software & Device",
        "description": "Operating systems, application products, CPEs, and banner hashes",
        "filters": [
            {"name": "product", "description": "Matches an identified software product or service", "example": "product:openssh"},
            {"name": "version", "description": "Matches a detected software version", "example": "version:1.16.1"},
            {"name": "os", "description": "Matches the detected operating system", "example": "os:linux"},
            {"name": "cpe", "description": "Matches a Common Platform Enumeration identifier", "example": "cpe:openssh"},
            {"name": "tag", "description": "Matches a Shodan-assigned tag", "example": "tag:database"},
            {"name": "hash", "description": "Matches a banner hash", "example": "hash:12345"}
        ]
    },
    {
        "category": "Vulnerability & Security",
        "description": "Identified CVE vulnerabilities, SSL presence, and screenshot assets",
        "filters": [
            {"name": "vuln", "description": "Matches a specific vulnerability identifier, such as a CVE", "example": "vuln:CVE-2026-60002"},
            {"name": "has_vuln", "description": "Filters records based on the presence of vulnerability metadata", "example": "has_vuln:true"},
            {"name": "has_ssl", "description": "Filters records based on SSL/TLS metadata availability", "example": "has_ssl:true"},
            {"name": "has_screenshot", "description": "Filters records with screenshot metadata", "example": "has_screenshot:true"}
        ]
    },
    {
        "category": "HTTP & Web-Server",
        "description": "Web components, page titles, HTTP status codes, WAFs, and hashes",
        "filters": [
            {"name": "http.component", "description": "Matches detected web technologies or components", "example": "http.component:nginx"},
            {"name": "http.component_category", "description": "Matches the category of a detected web technology", "example": 'http.component_category:"Web servers"'},
            {"name": "http.favicon.hash", "description": "Matches a website favicon hash", "example": "http.favicon.hash:12345"},
            {"name": "http.html_hash", "description": "Matches the hash of HTTP HTML content", "example": "http.html_hash:12345"},
            {"name": "http.robots_hash", "description": "Matches the hash of robots.txt content", "example": "http.robots_hash:12345"},
            {"name": "http.securitytxt", "description": "Matches security.txt-related metadata", "example": "http.securitytxt:contact"},
            {"name": "http.status", "description": "Matches an HTTP response status code", "example": "http.status:200"},
            {"name": "http.title", "description": "Matches text in an HTTP page title", "example": 'http.title:"Apache2 Debian"'},
            {"name": "http.waf", "description": "Matches detected web application firewall metadata", "example": "http.waf:cloudflare"},
            {"name": "title", "description": "Matches a title field where supported by the indexed data", "example": 'title:"Dashboard"'}
        ]
    },
    {
        "category": "SSL/TLS & Certificate",
        "description": "Certificate authorities, fingerprints, TLS versions, and JA3/JARM",
        "filters": [
            {"name": "ssl", "description": "Matches SSL/TLS-related banner information", "example": 'ssl:"Let\'s Encrypt"'},
            {"name": "ssl.alpn", "description": "Matches the negotiated or advertised application protocol metadata", "example": "ssl.alpn:h2"},
            {"name": "ssl.cert.fingerprint", "description": "Matches a certificate fingerprint", "example": "ssl.cert.fingerprint:fb:77"},
            {"name": "ssl.cert.issuer.cn", "description": "Matches the certificate issuer's common name", "example": 'ssl.cert.issuer.cn:"R3"'},
            {"name": "ssl.cert.serial", "description": "Matches the certificate serial number", "example": "ssl.cert.serial:12345"},
            {"name": "ssl.cert.subject.cn", "description": "Matches the certificate subject's common name", "example": 'ssl.cert.subject.cn:"*.netart.com"'},
            {"name": "ssl.ja3s", "description": "Matches a JA3S TLS server fingerprint", "example": "ssl.ja3s:12345"},
            {"name": "ssl.jarm", "description": "Matches a JARM TLS fingerprint", "example": "ssl.jarm:12345"},
            {"name": "ssl.version", "description": "Matches SSL/TLS version metadata", "example": "ssl.version:TLSv1.2"}
        ]
    },
    {
        "category": "SSH",
        "description": "Secure Shell fingerprints and host-key configurations",
        "filters": [
            {"name": "ssh.fingerprint", "description": "Matches an SSH host-key fingerprint", "example": "ssh.fingerprint:fb:77:af:03"}
        ]
    }
]


@app.get("/api/search/filters")
async def get_search_filters():
    """Return all available Shodan-style search filters categorized with examples."""
    return {"categories": SEARCH_FILTERS_SCHEMA}


@app.get("/api/search")
async def shodan_search(q: str = "", page: int = 1):
    """
    Shodan-style search across the local PostgreSQL database supporting 40+ filters:
    
    GENERAL & NETWORK:
      - all, ip, net, port, asn, org, isp, hostname, has_ipv6
    GEOGRAPHIC:
      - country, city, state, region
    SOFTWARE & DEVICE:
      - product, version, os, cpe, tag, hash
    VULNERABILITY & SECURITY:
      - vuln, has_vuln, has_ssl, has_screenshot
    HTTP & WEB-SERVER:
      - http.component, http.component_category, http.favicon.hash, http.html_hash,
        http.robots_hash, http.securitytxt, http.status, http.title, http.waf, title
    SSL/TLS & CERTIFICATE:
      - ssl, ssl.alpn, ssl.cert.fingerprint, ssl.cert.issuer.cn, ssl.cert.serial,
        ssl.cert.subject.cn, ssl.ja3s, ssl.jarm, ssl.version
    SSH:
      - ssh.fingerprint
    
    Returns paginated IP results with facets (top countries, ports, orgs).
    """
    if not q.strip():
        return {
            "total": 0, "page": page, "per_page": 20,
            "results": [], "facets": {"countries": [], "ports": [], "orgs": []}
        }

    filters, terms = _parse_shodan_query(q)

    try:
        db = DBManager()
        conditions = []
        params = []

        base_query = """
            SELECT DISTINCT h.id, h.ip, h.country, h.city, h.organization, h.isp, h.asn, h.os, h.tags,
                   h.first_seen, h.last_updated
            FROM hosts h
        """

        # ── 1. GENERAL AND NETWORK FILTERS ────────────────────────────────────
        if "all" in filters:
            like = f"%{filters['all']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s
                    JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.banner ILIKE %s OR p.http_title ILIKE %s OR p.service ILIKE %s
                        OR p.version ILIKE %s OR h.organization ILIKE %s OR h.isp ILIKE %s OR h.os ILIKE %s
                    )
                )
            """)
            params.extend([like, like, like, like, like, like, like])

        if "ip" in filters:
            val = filters["ip"].strip()
            try:
                ipaddress.ip_address(val)
                conditions.append("h.ip = %s::inet")
                params.append(val)
            except ValueError:
                conditions.append("CAST(h.ip AS TEXT) ILIKE %s")
                params.append(f"%{val}%")

        if "net" in filters:
            val = filters["net"].strip()
            try:
                net_obj = ipaddress.ip_network(val, strict=False)
                conditions.append("h.ip <<= %s::inet")
                params.append(str(net_obj))
            except ValueError:
                conditions.append("CAST(h.ip AS TEXT) ILIKE %s")
                params.append(f"%{val}%")

        if "port" in filters:
            try:
                port_num = int(filters["port"])
                conditions.append("""
                    EXISTS (
                        SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                        WHERE s.host_id = h.id AND p.port_number = %s
                    )
                """)
                params.append(port_num)
            except ValueError:
                pass

        if "asn" in filters:
            conditions.append("h.asn ILIKE %s")
            params.append(f"%{filters['asn']}%")

        if "org" in filters:
            conditions.append("h.organization ILIKE %s")
            params.append(f"%{filters['org']}%")

        if "isp" in filters:
            conditions.append("h.isp ILIKE %s")
            params.append(f"%{filters['isp']}%")

        if "hostname" in filters:
            like = f"%{filters['hostname']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s
                    WHERE s.host_id = h.id AND (
                        s.metadata::text ILIKE %s
                        OR s.raw_data->'general_info'->>'Hostnames' ILIKE %s
                        OR s.raw_data->'general_info'->>'Domains' ILIKE %s
                    )
                )
            """)
            params.extend([like, like, like])

        if "has_ipv6" in filters:
            is_true = filters["has_ipv6"].lower() in ("true", "1", "yes")
            if is_true:
                conditions.append("""
                    (family(h.ip) = 6 OR EXISTS (
                        SELECT 1 FROM scans s WHERE s.host_id = h.id AND s.raw_data::text ILIKE '%%ipv6%%'
                    ))
                """)
            else:
                conditions.append("""
                    (family(h.ip) = 4 AND NOT EXISTS (
                        SELECT 1 FROM scans s WHERE s.host_id = h.id AND s.raw_data::text ILIKE '%%ipv6%%'
                    ))
                """)

        # ── 2. GEOGRAPHIC FILTERS ─────────────────────────────────────────────
        if "country" in filters:
            c_val = filters["country"].strip()
            upper = c_val.upper()
            full_name = _COUNTRY_CODE_MAP.get(upper, c_val)
            conditions.append("(h.country ILIKE %s OR h.country ILIKE %s)")
            params.extend([f"%{c_val}%", f"%{full_name}%"])

        if "city" in filters:
            conditions.append("h.city ILIKE %s")
            params.append(f"%{filters['city']}%")

        if "state" in filters:
            like = f"%{filters['state']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s
                    WHERE s.host_id = h.id AND (
                        s.raw_data->'general_info'->>'Region' ILIKE %s
                        OR s.raw_data->'general_info'->>'State' ILIKE %s
                        OR s.raw_data->'general_info'->>'Cloud Region' ILIKE %s
                        OR s.raw_data::text ILIKE %s
                    )
                )
            """)
            params.extend([like, like, like, like])

        if "region" in filters:
            like = f"%{filters['region']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s
                    WHERE s.host_id = h.id AND (
                        s.raw_data->'general_info'->>'Cloud Region' ILIKE %s
                        OR s.raw_data->'general_info'->>'Region' ILIKE %s
                        OR s.raw_data::text ILIKE %s
                    )
                )
            """)
            params.extend([like, like, like])

        # ── 3. SOFTWARE AND DEVICE FILTERS ────────────────────────────────────
        if "product" in filters or "service" in filters:
            prod_val = filters.get("product") or filters.get("service")
            like = f"%{prod_val}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.service ILIKE %s
                        OR p.extra->>'product' ILIKE %s
                        OR p.banner ILIKE %s
                    )
                )
            """)
            params.extend([like, like, like])

        if "version" in filters:
            like = f"%{filters['version']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.version ILIKE %s
                        OR p.extra->>'service_version' ILIKE %s
                        OR p.banner ILIKE %s
                    )
                )
            """)
            params.extend([like, like, like])

        if "os" in filters:
            like = f"%{filters['os']}%"
            conditions.append("""
                (h.os ILIKE %s OR EXISTS (
                    SELECT 1 FROM scans s
                    WHERE s.host_id = h.id AND s.raw_data->'general_info'->>'Operating System' ILIKE %s
                ))
            """)
            params.extend([like, like])

        if "cpe" in filters:
            like = f"%{filters['cpe']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.extra->>'cpe' ILIKE %s
                        OR p.extra::text ILIKE %s
                    )
                )
            """)
            params.extend([like, like])

        if "tag" in filters:
            like = f"%{filters['tag']}%"
            conditions.append("""
                (CAST(h.tags AS TEXT) ILIKE %s OR EXISTS (
                    SELECT 1 FROM scans s
                    WHERE s.host_id = h.id AND CAST(s.raw_data->'general_info'->'tags' AS TEXT) ILIKE %s
                ))
            """)
            params.extend([like, like])

        if "hash" in filters:
            like = f"%{filters['hash']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.extra::text ILIKE %s
                        OR s.raw_data::text ILIKE %s
                    )
                )
            """)
            params.extend([like, like])

        # ── 4. VULNERABILITY AND SECURITY FILTERS ─────────────────────────────
        if "vuln" in filters:
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s
                    JOIN ports p ON p.scan_id = s.id
                    JOIN vulnerabilities v ON v.port_id = p.id
                    WHERE s.host_id = h.id AND v.cve_id ILIKE %s
                )
            """)
            params.append(f"%{filters['vuln']}%")

        if "has_vuln" in filters:
            is_true = filters["has_vuln"].lower() in ("true", "1", "yes")
            prefix = "EXISTS" if is_true else "NOT EXISTS"
            conditions.append(f"""
                {prefix} (
                    SELECT 1 FROM scans s
                    JOIN ports p ON p.scan_id = s.id
                    JOIN vulnerabilities v ON v.port_id = p.id
                    WHERE s.host_id = h.id
                )
            """)

        if "has_ssl" in filters:
            is_true = filters["has_ssl"].lower() in ("true", "1", "yes")
            prefix = "EXISTS" if is_true else "NOT EXISTS"
            conditions.append(f"""
                {prefix} (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.port_number IN (443, 8443, 993, 995, 465)
                        OR p.extra->'scripts' ? 'ssl-cert'
                        OR p.extra->'scripts' ? 'ssl-enum-ciphers'
                        OR p.banner ILIKE '%%ssl%%'
                        OR p.banner ILIKE '%%tls%%'
                    )
                )
            """)

        if "has_screenshot" in filters:
            is_true = filters["has_screenshot"].lower() in ("true", "1", "yes")
            prefix = "EXISTS" if is_true else "NOT EXISTS"
            conditions.append(f"""
                {prefix} (
                    SELECT 1 FROM scans s
                    WHERE s.host_id = h.id AND (
                        s.raw_data::text ILIKE '%%screenshot%%'
                        OR s.metadata::text ILIKE '%%screenshot%%'
                    )
                )
            """)

        # ── 5. HTTP AND WEB-SERVER FILTERS ────────────────────────────────────
        if "http.component" in filters:
            like = f"%{filters['http.component']}%"
            conditions.append("""
                (
                    EXISTS (
                        SELECT 1 FROM scans s JOIN technologies t ON t.scan_id = s.id
                        WHERE s.host_id = h.id AND t.name ILIKE %s
                    )
                    OR EXISTS (
                        SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                        WHERE s.host_id = h.id AND (
                            p.service ILIKE %s
                            OR p.extra->>'product' ILIKE %s
                        )
                    )
                )
            """)
            params.extend([like, like, like])

        if "http.component_category" in filters:
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN technologies t ON t.scan_id = s.id
                    WHERE s.host_id = h.id AND t.category ILIKE %s
                )
            """)
            params.append(f"%{filters['http.component_category']}%")

        if "http.favicon.hash" in filters:
            like = f"%{filters['http.favicon.hash']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.extra::text ILIKE %s
                        OR s.raw_data::text ILIKE %s
                    )
                )
            """)
            params.extend([like, like])

        if "http.html_hash" in filters:
            like = f"%{filters['http.html_hash']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.extra::text ILIKE %s
                        OR s.raw_data::text ILIKE %s
                    )
                )
            """)
            params.extend([like, like])

        if "http.robots_hash" in filters:
            like = f"%{filters['http.robots_hash']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.extra::text ILIKE %s
                        OR s.raw_data::text ILIKE %s
                    )
                )
            """)
            params.extend([like, like])

        if "http.securitytxt" in filters:
            like = f"%{filters['http.securitytxt']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.extra::text ILIKE %s
                        OR p.banner ILIKE %s
                        OR s.raw_data::text ILIKE %s
                    )
                )
            """)
            params.extend([like, like, like])

        if "http.status" in filters:
            s_val = filters["http.status"].strip()
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.banner ILIKE %s
                        OR p.extra->'scripts'->>'http-headers' ILIKE %s
                        OR p.extra::text ILIKE %s
                    )
                )
            """)
            params.extend([f"%HTTP/% {s_val}%", f"%{s_val}%", f"%{s_val}%"])

        if "http.title" in filters or "title" in filters:
            t_val = filters.get("http.title") or filters.get("title")
            like = f"%{t_val}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.http_title ILIKE %s
                        OR p.extra->'scripts'->>'http-title' ILIKE %s
                        OR p.banner ILIKE %s
                    )
                )
            """)
            params.extend([like, like, like])

        if "http.waf" in filters:
            like = f"%{filters['http.waf']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.extra::text ILIKE %s
                        OR p.banner ILIKE %s
                        OR s.raw_data::text ILIKE %s
                    )
                )
            """)
            params.extend([like, like, like])

        # ── 6. SSL/TLS AND CERTIFICATE FILTERS ────────────────────────────────
        if "ssl" in filters:
            like = f"%{filters['ssl']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.extra->'scripts'->>'ssl-cert' ILIKE %s
                        OR p.banner ILIKE %s
                        OR p.extra::text ILIKE %s
                    )
                )
            """)
            params.extend([like, like, like])

        if "ssl.alpn" in filters:
            like = f"%{filters['ssl.alpn']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.extra::text ILIKE %s
                        OR p.banner ILIKE %s
                    )
                )
            """)
            params.extend([like, like])

        if "ssl.cert.fingerprint" in filters:
            like = f"%{filters['ssl.cert.fingerprint']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.extra->'scripts'->>'ssl-cert' ILIKE %s
                        OR p.extra::text ILIKE %s
                    )
                )
            """)
            params.extend([like, like])

        if "ssl.cert.issuer.cn" in filters:
            like = f"%{filters['ssl.cert.issuer.cn']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.extra->'scripts'->>'ssl-cert' ILIKE %s
                        OR p.banner ILIKE %s
                    )
                )
            """)
            params.extend([like, like])

        if "ssl.cert.serial" in filters:
            like = f"%{filters['ssl.cert.serial']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.extra->'scripts'->>'ssl-cert' ILIKE %s
                        OR p.extra::text ILIKE %s
                    )
                )
            """)
            params.extend([like, like])

        if "ssl.cert.subject.cn" in filters:
            like = f"%{filters['ssl.cert.subject.cn']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.extra->'scripts'->>'ssl-cert' ILIKE %s
                        OR p.banner ILIKE %s
                    )
                )
            """)
            params.extend([like, like])

        if "ssl.ja3s" in filters:
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND p.extra::text ILIKE %s
                )
            """)
            params.append(f"%{filters['ssl.ja3s']}%")

        if "ssl.jarm" in filters:
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND p.extra::text ILIKE %s
                )
            """)
            params.append(f"%{filters['ssl.jarm']}%")

        if "ssl.version" in filters:
            like = f"%{filters['ssl.version']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.extra->'scripts'->>'ssl-enum-ciphers' ILIKE %s
                        OR p.banner ILIKE %s
                        OR p.extra::text ILIKE %s
                    )
                )
            """)
            params.extend([like, like, like])

        # ── 7. SSH FILTERS ────────────────────────────────────────────────────
        if "ssh.fingerprint" in filters:
            like = f"%{filters['ssh.fingerprint']}%"
            conditions.append("""
                EXISTS (
                    SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                    WHERE s.host_id = h.id AND (
                        p.banner ILIKE %s
                        OR p.extra::text ILIKE %s
                    )
                )
            """)
            params.extend([like, like])

        # ── 8. FREE-TEXT SEARCH (multi-term) ──────────────────────────────────
        for term in terms:
            like = f"%{term}%"
            conditions.append("""
                (
                    h.organization ILIKE %s OR h.isp ILIKE %s OR h.os ILIKE %s
                    OR h.country ILIKE %s OR h.city ILIKE %s OR CAST(h.ip AS TEXT) ILIKE %s
                    OR EXISTS (
                        SELECT 1 FROM scans s JOIN ports p ON p.scan_id = s.id
                        WHERE s.host_id = h.id AND (
                            p.banner ILIKE %s OR p.service ILIKE %s OR p.version ILIKE %s
                            OR p.http_title ILIKE %s
                        )
                    )
                )
            """)
            params.extend([like, like, like, like, like, like, like, like, like, like])

        if conditions:
            base_query += " WHERE " + " AND ".join(conditions)

        base_query += " ORDER BY h.last_updated DESC"

        with db.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(base_query, params)
            all_rows = cur.fetchall()

        total = len(all_rows)
        per_page = 20
        start = (page - 1) * per_page
        page_rows = all_rows[start:start + per_page]

        # Build result objects with port/vuln summary for each host
        results = []
        for row in page_rows:
            host = dict(row)
            host_id = host["id"]
            ip_str = str(host["ip"])
            host["ip"] = ip_str

            # Serialize dates
            for k, v in host.items():
                if hasattr(v, 'isoformat'):
                    host[k] = v.isoformat()
                elif not isinstance(v, (str, int, float, bool, list, dict, type(None))):
                    host[k] = str(v)

            # Get open ports for this host (from latest scan)
            with db.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT p.port_number, p.service, p.version, p.http_title
                    FROM ports p
                    JOIN scans s ON s.id = p.scan_id
                    WHERE s.host_id = %s
                    ORDER BY p.port_number
                """, (host_id,))
                ports = [dict(r) for r in cur.fetchall()]

            # Get CVE count for this host
            with db.conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(DISTINCT v.cve_id) 
                    FROM vulnerabilities v
                    JOIN ports p ON p.id = v.port_id
                    JOIN scans s ON s.id = p.scan_id
                    WHERE s.host_id = %s
                """, (host_id,))
                cve_count = cur.fetchone()[0]

            host["open_ports"] = ports
            host["port_count"] = len(ports)
            host["cve_count"] = cve_count
            del host["id"]  # Don't expose internal DB id
            results.append(host)

        # Build facets from ALL results (not just current page)
        country_counts = {}
        org_counts = {}
        port_counts = {}

        host_ids = [r["id"] for r in all_rows]
        
        # Country facets
        for row in all_rows:
            c = row.get("country")
            if c:
                country_counts[c] = country_counts.get(c, 0) + 1
            o = row.get("organization")
            if o:
                org_counts[o] = org_counts.get(o, 0) + 1

        # Port facets (batched query)
        if host_ids:
            # Process in chunks to avoid overly large IN clauses
            chunk_size = 500
            for i in range(0, len(host_ids), chunk_size):
                chunk = host_ids[i:i + chunk_size]
                placeholders = ",".join(["%s"] * len(chunk))
                with db.conn.cursor() as cur:
                    cur.execute(f"""
                        SELECT p.port_number, COUNT(DISTINCT s.host_id) as cnt
                        FROM ports p
                        JOIN scans s ON s.id = p.scan_id
                        WHERE s.host_id IN ({placeholders})
                        GROUP BY p.port_number
                    """, chunk)
                    for port_num, cnt in cur.fetchall():
                        port_counts[port_num] = port_counts.get(port_num, 0) + cnt

        db.close()

        facets = {
            "countries": sorted(
                [{"name": k, "count": v} for k, v in country_counts.items()],
                key=lambda x: x["count"], reverse=True
            )[:10],
            "ports": sorted(
                [{"name": str(k), "count": v} for k, v in port_counts.items()],
                key=lambda x: x["count"], reverse=True
            )[:10],
            "orgs": sorted(
                [{"name": k, "count": v} for k, v in org_counts.items()],
                key=lambda x: x["count"], reverse=True
            )[:5],
        }

        return {
            "total": total,
            "page": page,
            "per_page": per_page,
            "results": results,
            "facets": facets,
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Search error: {str(e)}")


@app.get("/api/search/ip/{ip_address}")
async def search_ip(ip_address: str):
    """Get all data for an IP address — host info, all scans with ports, vulns, and technologies."""
    try:
        db = DBManager()
        
        host = db.get_host_by_ip(ip_address)
        if not host:
            db.close()
            return {"found": False, "data": None}
        
        host_id = host["id"]
        
        # Get full scan timeline with ports, vulns, technologies, metadata, and raw_data
        scans = []
        with db.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT s.id, s.source, s.source_last_seen, s.scraped_at, s.metadata, s.raw_data
                FROM scans s
                WHERE s.host_id = %s
                ORDER BY s.scraped_at DESC
            """, (host_id,))
            scan_rows = cur.fetchall()

        for scan_row in scan_rows:
            scan = dict(scan_row)
            scan_id = scan["id"]

            # Get ports for this scan
            with db.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT p.id as port_id, p.port_number, p.protocol, p.state, p.service,
                           p.version, p.http_title, p.banner, p.timestamp, p.extra
                    FROM ports p WHERE p.scan_id = %s ORDER BY p.port_number
                """, (scan_id,))
                ports = []
                for port_row in cur.fetchall():
                    port = dict(port_row)
                    port_id = port["port_id"]

                    # Get vulnerabilities for this port
                    cur.execute("""
                        SELECT cve_id, cvss, cvss_vector, summary
                        FROM vulnerabilities WHERE port_id = %s ORDER BY cvss DESC NULLS LAST
                    """, (port_id,))
                    port["vulnerabilities"] = [dict(v) for v in cur.fetchall()]
                    del port["port_id"]
                    ports.append(port)

            # Get technologies for this scan
            with db.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT category, name, version
                    FROM technologies WHERE scan_id = %s ORDER BY category, name
                """, (scan_id,))
                technologies = [dict(t) for t in cur.fetchall()]

            scan["ports"] = ports
            scan["technologies"] = technologies
            scans.append(scan)

        # Get all unique CVEs for this host with source information
        all_cves = []
        with db.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT v.cve_id, v.cvss, v.cvss_vector, v.summary,
                       p.port_number, p.protocol, s.source
                FROM vulnerabilities v
                JOIN ports p ON p.id = v.port_id
                JOIN scans s ON s.id = p.scan_id
                WHERE s.host_id = %s
                ORDER BY v.cvss DESC NULLS LAST
            """, (host_id,))
            cve_rows = cur.fetchall()

        # Deduplicate all_cves while aggregating found_on ports and sources
        cve_map = {}
        for r in cve_rows:
            cid = r["cve_id"]
            if cid not in cve_map:
                cve_map[cid] = {
                    "cve_id": cid,
                    "cvss": r["cvss"],
                    "cvss_vector": r["cvss_vector"],
                    "summary": r["summary"],
                    "sources": set(),
                    "ports": set()
                }
            if r.get("source"):
                cve_map[cid]["sources"].add(r["source"])
            if r.get("port_number"):
                cve_map[cid]["ports"].add(f"{r['port_number']}/{r.get('protocol', 'tcp')}")

        all_cves = []
        for item in cve_map.values():
            item["sources"] = sorted(list(item["sources"]))
            item["ports"] = sorted(list(item["ports"]))
            all_cves.append(item)
        all_cves.sort(key=lambda x: (x["cvss"] is not None, x["cvss"] or 0), reverse=True)

        scan_count = db.get_scan_count(ip_address)
        db.close()

        # Latest scans for quick access
        latest_shodan = next((s for s in scans if s.get("source") == "shodan"), None)
        latest_nmap = next((s for s in scans if s.get("source") == "nmap"), None)

        # Merge extended host properties from scans (e.g. Domains, Hostnames, Cloud Info)
        extended_host = dict(host)
        if latest_shodan and latest_shodan.get("raw_data", {}).get("general_info"):
            for k, v in latest_shodan["raw_data"]["general_info"].items():
                if k not in extended_host or not extended_host[k]:
                    extended_host[k] = v
        if latest_nmap and latest_nmap.get("raw_data", {}).get("general_info"):
            for k, v in latest_nmap["raw_data"]["general_info"].items():
                if k not in extended_host or not extended_host[k]:
                    extended_host[k] = v

        if "ip" in extended_host and extended_host["ip"]:
            ip_val = str(extended_host["ip"])
            extended_host["ip"] = ip_val.split("/")[0] if "/" in ip_val else ip_val

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

        response_data = {
            "host": extended_host,
            "scans": scans,
            "latest_shodan": latest_shodan,
            "latest_nmap": latest_nmap,
            "all_cves": all_cves,
            "scan_count": scan_count,
        }

        return {
            "found": True,
            "data": serialize(response_data)
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/api/search/cve/{cve_id}")
async def search_cve(cve_id: str):
    """Search the local database for full CVE details + ChatGPT analysis + affected local hosts."""
    try:
        db = DBManager()
        cve_upper = cve_id.strip().upper()
        
        result = db.get_cve_full(cve_upper)
        
        # Always find affected hosts in the local database for this CVE
        with db.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT h.ip::text as host_ip, p.port_number, p.protocol, s.source,
                       v.cvss, v.cvss_vector, v.summary
                FROM vulnerabilities v
                JOIN ports p ON p.id = v.port_id
                JOIN scans s ON s.id = p.scan_id
                JOIN hosts h ON h.id = s.host_id
                WHERE v.cve_id = %s
            """, (cve_upper,))
            vuln_rows = cur.fetchall()

        affected_hosts = []
        seen = set()
        for r in vuln_rows:
            key = (r["host_ip"], r["port_number"])
            if key not in seen:
                seen.add(key)
                affected_hosts.append({
                    "ip": r["host_ip"],
                    "port": f"{r['port_number']}/{r.get('protocol', 'tcp')}",
                    "source": r["source"]
                })

        if not result:
            if vuln_rows:
                # Construct fallback record from vulnerabilities scan findings
                first = vuln_rows[0]
                cvss_score = first["cvss"]
                severity = "UNKNOWN"
                if cvss_score is not None:
                    if cvss_score >= 9.0: severity = "CRITICAL"
                    elif cvss_score >= 7.0: severity = "HIGH"
                    elif cvss_score >= 4.0: severity = "MEDIUM"
                    else: severity = "LOW"

                result = {
                    "cve_id": cve_upper,
                    "description": first["summary"] or "Detected in network and port vulnerability scans on local hosts.",
                    "base_score": cvss_score,
                    "severity": severity,
                    "cvss_vector": first["cvss_vector"],
                    "affected_products": [],
                    "affected_hosts": affected_hosts,
                    "reference_urls": [
                        {"url": f"https://nvd.nist.gov/vuln/detail/{cve_upper}", "tags": ["NVD NIST Official Advisory"]}
                    ],
                    "analysis": None,
                    "from_scans_only": True
                }
            else:
                db.close()
                return {"found": False, "data": None}
        else:
            result["affected_hosts"] = affected_hosts

        db.close()
        
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
        import traceback
        traceback.print_exc()
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
