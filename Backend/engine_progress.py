"""
Engine Progress — Shared Progress & Cancellation System
=========================================================
Provides thread-safe communication between engine tools (running in
background threads) and the SSE stream (running in the API server).

The system uses:
  - threading.local() for per-thread context (engine_id, tool_name)
  - Thread-safe queues for progress events (keyed by chat thread_id)
  - Threading events for cancellation signals

Usage:
    # In api_server.py — register before starting the agent
    from engine_progress import register_chat, unregister_chat, get_progress_queue, cancel_engine

    progress_q = register_chat(thread_id)
    # ... drain progress_q in a polling loop ...
    unregister_chat(thread_id)

    # In main_agent.py tools — set context before running engine
    from engine_progress import set_context, clear_context

    set_context(chat_thread_id, engine_id, tool_name)
    run_engine(...)
    clear_context()

    # In engine nodes — emit progress updates
    from engine_progress import emit_progress, is_cancelled

    emit_progress("query_gen", "running", "3/5 queries generated")
    if is_cancelled():
        raise InterruptedError("Engine cancelled by user")
"""

import threading
import queue as queue_module

# ─── Thread-local storage for engine context ─────────────────────────────────
_local = threading.local()

# ─── Global registries (thread-safe via GIL for simple dict ops) ─────────────
_progress_queues: dict[str, queue_module.Queue] = {}
_cancel_events: dict[str, threading.Event] = {}
_cancel_events_by_engine: dict[str, threading.Event] = {}


# ═════════════════════════════════════════════════════════════════════════════
# Chat-level registration (called by api_server.py)
# ═════════════════════════════════════════════════════════════════════════════

def register_chat(chat_thread_id: str) -> queue_module.Queue:
    """Register a progress queue + cancel event for a chat session."""
    q = queue_module.Queue()
    _progress_queues[chat_thread_id] = q
    _cancel_events[chat_thread_id] = threading.Event()
    return q


def unregister_chat(chat_thread_id: str):
    """Clean up progress queue + cancel event for a chat session."""
    _progress_queues.pop(chat_thread_id, None)
    _cancel_events.pop(chat_thread_id, None)


def get_progress_queue(chat_thread_id: str) -> queue_module.Queue | None:
    return _progress_queues.get(chat_thread_id)


def register_engine_cancel(engine_thread_id: str, event: threading.Event = None) -> threading.Event:
    """Register or get a cancellation event for a specific engine run."""
    evt = event or threading.Event()
    _cancel_events_by_engine[engine_thread_id] = evt
    return evt


def cancel_engine(chat_thread_id: str = None, engine_thread_id: str = None):
    """Signal cancellation for an engine running in this chat or by engine ID."""
    if chat_thread_id:
        evt = _cancel_events.get(chat_thread_id)
        if evt:
            evt.set()
        else:
            evt = threading.Event()
            evt.set()
            _cancel_events[chat_thread_id] = evt

    if engine_thread_id:
        evt = _cancel_events_by_engine.get(engine_thread_id)
        if evt:
            evt.set()
        else:
            evt = threading.Event()
            evt.set()
            _cancel_events_by_engine[engine_thread_id] = evt

    # Directly terminate running subprocesses / browser scrapers
    try:
        from def_nmap.nmap_scanner import cancel_nmap_scanners
        cancel_nmap_scanners(engine_thread_id)
    except Exception:
        pass

    try:
        from def_Shodan.get_ip_info import cancel_shodan_scraper
        cancel_shodan_scraper(engine_thread_id)
    except Exception:
        pass


# ═════════════════════════════════════════════════════════════════════════════
# Engine-level context (called by tools in main_agent.py)
# ═════════════════════════════════════════════════════════════════════════════

def set_context(chat_thread_id: str, engine_id: str, tool_name: str, tool_call_id: str = None):
    """Set the engine context for the current thread.
    
    This must be called in the same thread that will run the engine nodes,
    because the nodes use threading.local() to find the context.
    """
    _local.chat_thread_id = chat_thread_id
    _local.engine_id = engine_id
    _local.tool_name = tool_name
    _local.tool_call_id = tool_call_id

    # If this engine does not yet have an event in _cancel_events_by_engine,
    # but the chat has one, link them so checks by either work.
    if engine_id and chat_thread_id:
        chat_evt = _cancel_events.get(chat_thread_id)
        if chat_evt and engine_id not in _cancel_events_by_engine:
            _cancel_events_by_engine[engine_id] = chat_evt


def clear_context():
    """Clear the engine context for the current thread."""
    _local.chat_thread_id = None
    _local.engine_id = None
    _local.tool_name = None
    _local.tool_call_id = None


def get_context() -> tuple[str | None, str | None, str | None, str | None]:
    """Get (chat_thread_id, engine_id, tool_name, tool_call_id) for the current thread."""
    return (
        getattr(_local, 'chat_thread_id', None),
        getattr(_local, 'engine_id', None),
        getattr(_local, 'tool_name', None),
        getattr(_local, 'tool_call_id', None),
    )


# ═════════════════════════════════════════════════════════════════════════════
# Progress emission (called by engine nodes)
# ═════════════════════════════════════════════════════════════════════════════

def emit_progress(node_name: str, status: str, detail: str = ""):
    """Emit a progress event from inside an engine node.
    
    Pushes to:
      1. The SSE queue (for real-time frontend updates)
      2. The tool_calls DB table (for persistence/reload)
    
    Args:
        node_name: The current node (e.g. "query_gen", "process_all_ips")
        status:    "running" | "done"
        detail:    Human-readable progress string (e.g. "2/5 IPs scanned")
    """
    chat_tid, engine_id, tool_name, tool_call_id = get_context()
    if not chat_tid:
        return  # No context set, probably running in CLI mode

    # 1. Push to SSE queue (real-time)
    q = _progress_queues.get(chat_tid)
    if q:
        q.put({
            "type": "engine_progress",
            "engine_id": engine_id or "",
            "tool_name": tool_name or "",
            "tool_call_id": tool_call_id or "",
            "node": node_name,
            "status": status,
            "detail": detail,
        })

    # 2. Persist to DB (survives page reload)
    if tool_call_id:
        try:
            from chat_persistence import ChatDB
            db = ChatDB()
            db.update_tool_progress(tool_call_id, node_name, status, detail)
            db.close()
        except Exception:
            pass  # Don't let DB errors break engine execution


def is_cancelled(engine_thread_id: str = None, chat_thread_id: str = None) -> bool:
    """Check if the current engine has been cancelled by the user.
    
    Supports:
      1. Explicit engine_thread_id
      2. Explicit chat_thread_id
      3. Thread-local engine_id
      4. Thread-local chat_thread_id
      5. Fallback inspection of EngineManager in-memory record
    """
    # 1. Direct engine_thread_id check
    if engine_thread_id:
        evt = _cancel_events_by_engine.get(engine_thread_id)
        if evt and evt.is_set():
            return True

    # 2. Direct chat_thread_id check
    if chat_thread_id:
        evt = _cancel_events.get(chat_thread_id)
        if evt and evt.is_set():
            return True

    # 3. Thread-local engine_id check
    local_engine = getattr(_local, 'engine_id', None)
    if local_engine:
        evt = _cancel_events_by_engine.get(local_engine)
        if evt and evt.is_set():
            return True

    # 4. Thread-local chat_thread_id check
    local_chat = getattr(_local, 'chat_thread_id', None)
    if local_chat:
        evt = _cancel_events.get(local_chat)
        if evt and evt.is_set():
            return True

    # 5. Fallback inspection via EngineManager
    try:
        from engine_manager import EngineManager
        mgr = EngineManager()
        target_eid = engine_thread_id or local_engine
        if target_eid:
            rec = mgr.get_record(target_eid)
            if rec and (rec.cancel_event.is_set() or rec.status in ("paused", "stopped")):
                return True
        if local_chat:
            rec = mgr.get_running_engine(local_chat)
            if rec and (rec.cancel_event.is_set() or rec.status in ("paused", "stopped")):
                return True
    except Exception:
        pass

    return False
