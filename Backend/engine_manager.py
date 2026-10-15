"""
Engine Manager — Background Engine Lifecycle Manager
======================================================
Manages background engine threads, one per chat. Handles:
  - Starting engines in background threads (fire-and-forget)
  - Tracking which engines are running per chat
  - Pausing/resuming engines via cancellation events
  - Providing SSE-compatible progress queues per engine
  - Getting engine status from LangGraph checkpoints

Usage:
    from engine_manager import EngineManager

    mgr = EngineManager()

    # Start an engine in the background
    mgr.start_engine("query", {"query": "apache servers"}, "query_abc", "chat_123")

    # Get the progress queue for SSE streaming
    q = mgr.get_progress_queue("query_abc")

    # Pause
    mgr.pause_engine("query_abc")

    # Resume
    mgr.resume_engine("query_abc", "chat_123")

    # Check status
    mgr.is_engine_running("chat_123")  # True/False
"""

import os
import sys
import threading
import queue as queue_module
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

# ─── Paths ───────────────────────────────────────────────────────────────────
BACKEND_DIR = Path(r"c:\Users\jassi\OneDrive\Documents\CTI_V2\Backend")
ENV_PATH = BACKEND_DIR.parent / ".env"
load_dotenv(ENV_PATH)

PG_CONN_STRING = (
    f"postgresql://{os.getenv('PG_USER', 'postgres')}:"
    f"{os.getenv('PG_PASSWORD', '')}@"
    f"{os.getenv('PG_HOST', 'localhost')}:"
    f"{os.getenv('PG_PORT', '5432')}/"
    f"{os.getenv('PG_DATABASE', 'cti_db')}"
)


# ═════════════════════════════════════════════════════════════════════════════
# Engine Record
# ═════════════════════════════════════════════════════════════════════════════

class EngineRecord:
    """Tracks a single background engine run."""

    def __init__(self, engine_type: str, engine_thread_id: str, chat_thread_id: str,
                 input_data: dict, tool_call_id: str = None):
        self.engine_type = engine_type           # "query" | "ip" | "cve"
        self.engine_thread_id = engine_thread_id # LangGraph thread for the engine
        self.chat_thread_id = chat_thread_id     # Chat session this belongs to
        self.input_data = input_data             # Original input (query, ips, cves)
        self.tool_call_id = tool_call_id         # Tool call ID from agent

        self.progress_queue = queue_module.Queue()
        self.cancel_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.status = "running"                  # running | paused | done | error
        self.result: dict | None = None
        self.error: str | None = None


# ═════════════════════════════════════════════════════════════════════════════
# Singleton Engine Manager
# ═════════════════════════════════════════════════════════════════════════════

class EngineManager:
    """Manages all background engine threads."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._engines: dict[str, EngineRecord] = {}  # engine_thread_id -> EngineRecord
            cls._instance._chat_engines: dict[str, str] = {}       # chat_thread_id -> engine_thread_id
            cls._instance._lock = threading.Lock()
        return cls._instance

    # ─────────────────────────────────────────────────────────────────────────
    # Start Engine
    # ─────────────────────────────────────────────────────────────────────────

    def start_engine(
        self,
        engine_type: str,
        input_data: dict,
        engine_thread_id: str,
        chat_thread_id: str,
        tool_call_id: str = None,
    ) -> EngineRecord:
        """Start an engine in a background thread.
        
        Args:
            engine_type: "query" | "ip" | "cve"
            input_data: {"query": "..."} or {"ip_addresses": [...]} or {"cve_ids": [...]}
            engine_thread_id: Unique ID for this engine run (LangGraph thread_id)
            chat_thread_id: The chat this engine belongs to
            tool_call_id: Optional tool call ID from the agent
        
        Returns:
            EngineRecord with the progress queue for SSE streaming.
        
        Raises:
            RuntimeError: If an engine is already running for this chat.
        """
        with self._lock:
            # Check if any engine is already running for this chat
            for eid, rec in self._engines.items():
                if rec.chat_thread_id == chat_thread_id and rec.status == "running":
                    raise RuntimeError(
                        f"An engine is already running in this chat ('{eid}'). "
                        "Pause it first before starting a new one."
                    )

            record = EngineRecord(
                engine_type=engine_type,
                engine_thread_id=engine_thread_id,
                chat_thread_id=chat_thread_id,
                input_data=input_data,
                tool_call_id=tool_call_id,
            )

            self._engines[engine_thread_id] = record
            self._chat_engines[chat_thread_id] = engine_thread_id

        # Start the engine in a background thread
        t = threading.Thread(
            target=self._run_engine_thread,
            args=(record,),
            daemon=True,
        )
        record.thread = t
        t.start()

        return record

    def _run_engine_thread(self, record: EngineRecord):
        """Background thread that executes the engine."""
        from engine_progress import set_context, clear_context
        from engine_progress import _progress_queues, _cancel_events, _cancel_events_by_engine
        from chat_persistence import ChatDB

        engine_tid = record.engine_thread_id
        chat_tid = record.chat_thread_id

        # Set context so emit_progress() can find the right queue
        set_context(chat_tid, engine_tid, record.engine_type, record.tool_call_id)

        # Override the progress queue in engine_progress to use
        # the engine-specific queue instead of the chat-level queue
        _progress_queues[chat_tid] = record.progress_queue
        _cancel_events[chat_tid] = record.cancel_event
        _cancel_events_by_engine[engine_tid] = record.cancel_event

        try:
            if record.engine_type == "query":
                from Engine_query_input import run_engine as run_query_engine
                query = record.input_data.get("query", "")
                result = run_query_engine(query, thread_id=engine_tid)

            elif record.engine_type == "ip":
                from Engine_ip_input import run_engine as run_ip_engine
                ips = record.input_data.get("ip_addresses", [])
                result = run_ip_engine(ips, thread_id=engine_tid)

            elif record.engine_type == "cve":
                from Engine_cve_input import run_engine as run_cve_engine
                cves = record.input_data.get("cve_ids", [])
                result = run_cve_engine(cves, thread_id=engine_tid)

            else:
                raise ValueError(f"Unknown engine type: {record.engine_type}")

            record.result = result
            record.status = "done"

            # Push completion event to the progress queue
            record.progress_queue.put({
                "type": "engine_done",
                "engine_thread_id": engine_tid,
                "result": {
                    "engine_status": result.get("engine_status", "unknown"),
                    "ips": result.get("ips", []),
                    "cve": result.get("cve", []),
                    "queries": result.get("queries", []),
                },
            })

            # Update DB
            try:
                db = ChatDB()
                if record.tool_call_id:
                    summary = self._build_summary(record.engine_type, result)
                    db.complete_tool_call(record.tool_call_id, summary)
                db.close()
            except Exception:
                pass

        except InterruptedError:
            if record.status != "stopped":
                record.status = "paused"
            record.progress_queue.put({
                "type": "engine_paused",
                "engine_thread_id": engine_tid,
            })

            # Update DB
            try:
                db = ChatDB()
                if record.tool_call_id:
                    db.pause_tool_call(record.tool_call_id)
                db.close()
            except Exception:
                pass

        except Exception as e:
            record.status = "error"
            record.error = str(e)
            record.progress_queue.put({
                "type": "engine_error",
                "engine_thread_id": engine_tid,
                "error": str(e),
            })

            # Update DB
            try:
                db = ChatDB()
                if record.tool_call_id:
                    db.error_tool_call(record.tool_call_id, str(e))
                db.close()
            except Exception:
                pass

        finally:
            clear_context()
            # Clean up the override only if not paused or stopped
            _progress_queues.pop(chat_tid, None)
            if record.status not in ("paused", "stopped"):
                _cancel_events.pop(chat_tid, None)
                _cancel_events_by_engine.pop(engine_tid, None)

    def _build_summary(self, engine_type: str, result: dict) -> str:
        """Build a human-readable summary from engine results."""
        ips = result.get("ips", [])
        cves = result.get("cve", [])
        status = result.get("engine_status", "unknown")

        if engine_type == "query":
            return (
                f"Status: {status}\n"
                f"Shodan Queries: {len(result.get('queries', []))}\n"
                f"IPs Discovered: {len(ips)}\n"
                f"CVEs Extracted: {len(cves)}"
            )
        elif engine_type == "ip":
            return (
                f"Status: {status}\n"
                f"IPs Scanned: {len(ips)}\n"
                f"CVEs Extracted: {len(cves)}"
            )
        elif engine_type == "cve":
            return (
                f"Status: {status}\n"
                f"CVEs Processed: {len(cves)}"
            )
        return f"Status: {status}"

    # ─────────────────────────────────────────────────────────────────────────
    # Pause / Resume
    # ─────────────────────────────────────────────────────────────────────────

    def pause_engine(self, engine_thread_id: str):
        """Signal an engine to pause (sets the cancel event)."""
        record = self._engines.get(engine_thread_id)
        if record:
            record.cancel_event.set()
        try:
            from engine_progress import cancel_engine
            cancel_engine(
                chat_thread_id=record.chat_thread_id if record else None,
                engine_thread_id=engine_thread_id,
            )
        except Exception:
            pass
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

    def resume_engine(self, engine_thread_id: str, chat_thread_id: str) -> EngineRecord | None:
        """Resume a paused engine by starting a new background thread.
        
        The LangGraph checkpointer will pick up from the last completed node.
        """
        record = self._engines.get(engine_thread_id)
        if not record:
            # Try to reconstruct from DB
            try:
                from chat_persistence import ChatDB
                db = ChatDB()
                all_tools = db.get_tool_calls(chat_thread_id)
                db.close()
                
                for tc in all_tools:
                    if tc.get("engine_thread_id") == engine_thread_id:
                        record = EngineRecord(
                            engine_type=self._infer_engine_type(tc["tool_name"]),
                            engine_thread_id=engine_thread_id,
                            chat_thread_id=chat_thread_id,
                            input_data=tc.get("input_data", {}),
                            tool_call_id=tc.get("tool_call_id"),
                        )
                        break
            except Exception:
                pass
        
        if not record:
            return None

        with self._lock:
            # Check if any other engine is already running for this chat
            for eid, rec in self._engines.items():
                if rec.chat_thread_id == chat_thread_id and eid != engine_thread_id and rec.status == "running":
                    raise RuntimeError(
                        f"An engine is already running in this chat ('{eid}'). "
                        "Pause it first before resuming another engine."
                    )

            # Reset the record for a fresh run
            record.cancel_event = threading.Event()
            record.progress_queue = queue_module.Queue()
            record.status = "running"
            record.error = None

            try:
                from engine_progress import _cancel_events, _cancel_events_by_engine
                _cancel_events_by_engine[engine_thread_id] = record.cancel_event
                _cancel_events[chat_thread_id] = record.cancel_event
            except Exception:
                pass

            self._engines[engine_thread_id] = record
            self._chat_engines[chat_thread_id] = engine_thread_id

        # Update DB: mark this engine as running, and any other running tool as paused
        try:
            from chat_persistence import ChatDB
            db = ChatDB()
            with db.conn.cursor() as cur:
                cur.execute(
                    """UPDATE tool_calls SET status = 'paused', updated_at = NOW()
                       WHERE thread_id = %s AND engine_thread_id != %s AND status = 'running'""",
                    (chat_thread_id, engine_thread_id),
                )
                cur.execute(
                    """UPDATE tool_calls SET status = 'running', updated_at = NOW()
                       WHERE engine_thread_id = %s""",
                    (engine_thread_id,),
                )
            db.close()
        except Exception:
            pass

        # Start the engine again — LangGraph will resume from last checkpoint
        t = threading.Thread(
            target=self._run_engine_thread,
            args=(record,),
            daemon=True,
        )
        record.thread = t
        t.start()

        return record

    def _infer_engine_type(self, tool_name: str) -> str:
        """Infer engine type from tool name."""
        if "query" in tool_name.lower() or "natural_language" in tool_name.lower():
            return "query"
        elif "ip" in tool_name.lower():
            return "ip"
        elif "cve" in tool_name.lower():
            return "cve"
        return "query"

    # ─────────────────────────────────────────────────────────────────────────
    # Query Methods
    # ─────────────────────────────────────────────────────────────────────────

    def get_progress_queue(self, engine_thread_id: str) -> queue_module.Queue | None:
        """Get the progress queue for an engine (for SSE streaming)."""
        record = self._engines.get(engine_thread_id)
        return record.progress_queue if record else None

    def get_record(self, engine_thread_id: str) -> EngineRecord | None:
        """Get the full engine record."""
        return self._engines.get(engine_thread_id)

    def is_engine_running(self, chat_thread_id: str) -> bool:
        """Check if any engine is currently running for a chat."""
        with self._lock:
            for eid, rec in self._engines.items():
                if rec.chat_thread_id == chat_thread_id and rec.status == "running":
                    return True
        return False

    def get_running_engine(self, chat_thread_id: str) -> EngineRecord | None:
        """Get the currently running engine for a chat, if any."""
        with self._lock:
            for eid, rec in self._engines.items():
                if rec.chat_thread_id == chat_thread_id and rec.status == "running":
                    return rec
        return None

    def list_engines_for_chat(self, chat_thread_id: str) -> list[dict]:
        """List all engines (from DB) for a chat, with their status."""
        try:
            from chat_persistence import ChatDB
            db = ChatDB()
            tool_calls = db.get_tool_calls(chat_thread_id)
            db.close()

            results = []
            for tc in tool_calls:
                engine_tid = tc.get("engine_thread_id")
                # Check if it's currently running in memory
                in_memory = self._engines.get(engine_tid) if engine_tid else None
                
                if in_memory and in_memory.status == "running":
                    tc["status"] = "running"
                elif tc.get("status") == "running":
                    # DB says running, but it's not in memory -> server restart/crash
                    tc["status"] = "paused"
                    try:
                        db2 = ChatDB()
                        db2.pause_tool_call(tc.get("tool_call_id"))
                        db2.close()
                    except Exception:
                        pass
                        
                results.append(tc)
            return results
        except Exception:
            return []

    def stop_all_engines_for_chat(self, chat_thread_id: str) -> list[str]:
        """Stop and cancel all engines associated with a chat session.
        
        Returns the list of engine_thread_ids that were stopped.
        """
        from engine_progress import cancel_engine

        # Signal cancellation for chat-level events
        cancel_engine(chat_thread_id=chat_thread_id)

        stopped_ids = []
        with self._lock:
            # Find all engine records matching this chat
            target_eids = [
                eid for eid, rec in self._engines.items()
                if rec.chat_thread_id == chat_thread_id
            ]
            # Also include the mapped engine in _chat_engines if any
            mapped_eid = self._chat_engines.pop(chat_thread_id, None)
            if mapped_eid and mapped_eid not in target_eids:
                target_eids.append(mapped_eid)

            for eid in target_eids:
                stopped_ids.append(eid)
                rec = self._engines.get(eid)
                if rec:
                    rec.cancel_event.set()
                    rec.status = "stopped"
                    cancel_engine(chat_thread_id=chat_thread_id, engine_thread_id=eid)
                    try:
                        rec.progress_queue.put({
                            "type": "engine_paused",
                            "engine_thread_id": eid,
                            "error": "Engine stopped because chat was deleted",
                        })
                    except Exception:
                        pass
                else:
                    cancel_engine(engine_thread_id=eid)

        return stopped_ids

    def stop_engine_for_chat(self, chat_thread_id: str):
        """Stop whatever engine is running for a chat."""
        return self.stop_all_engines_for_chat(chat_thread_id)
