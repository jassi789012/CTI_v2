"""
Chat Persistence — Custom PostgreSQL Tables for Chat & Tool Tracking
=====================================================================
Two custom tables that work alongside LangGraph's internal checkpoints:

  1. chat_messages  — Full chat history with token-level streaming persistence
  2. tool_calls     — Engine invocation tracking with live progress JSONB

Usage:
    from chat_persistence import ChatDB

    db = ChatDB()
    db.init_tables()

    # Save a user message
    db.insert_user_message("chat_abc", "Scan 1.2.3.4", message_index=0)

    # Start streaming assistant response
    row_id = db.insert_assistant_message("chat_abc", message_index=1)
    db.append_token(row_id, "Hello")
    db.append_token(row_id, " world")
    db.complete_message(row_id)

    # Track a tool call
    db.insert_tool_call("chat_abc", "call_123", "scan_ip_list", "ips_call_123", {"ip_addresses": ["1.2.3.4"]})
    db.update_tool_progress("call_123", "init_ips", "done", "3 IPs loaded")
    db.complete_tool_call("call_123", "Engine completed successfully")

    db.close()
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
from psycopg2.extras import Json, RealDictCursor
from dotenv import load_dotenv

# ─── Load environment ────────────────────────────────────────────────────────
ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(dotenv_path=ENV_PATH)


def _get_conn_string() -> str:
    return (
        f"postgresql://{os.getenv('PG_USER', 'postgres')}:"
        f"{os.getenv('PG_PASSWORD', '')}@"
        f"{os.getenv('PG_HOST', 'localhost')}:"
        f"{os.getenv('PG_PORT', '5432')}/"
        f"{os.getenv('PG_DATABASE', 'cti_db')}"
    )


def _get_connection():
    return psycopg2.connect(
        host=os.getenv("PG_HOST", "localhost"),
        port=int(os.getenv("PG_PORT", "5432")),
        dbname=os.getenv("PG_DATABASE", "cti_db"),
        user=os.getenv("PG_USER", "postgres"),
        password=os.getenv("PG_PASSWORD", "postgres"),
    )


# ═════════════════════════════════════════════════════════════════════════════
# Schema DDL
# ═════════════════════════════════════════════════════════════════════════════

CHAT_SCHEMA_SQL = """
-- Chat messages: full conversation history with streaming support
CREATE TABLE IF NOT EXISTS chat_messages (
    id              SERIAL PRIMARY KEY,
    thread_id       VARCHAR(64) NOT NULL,
    role            VARCHAR(16) NOT NULL,
    content         TEXT NOT NULL DEFAULT '',
    message_index   INTEGER NOT NULL,
    is_complete     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_thread
    ON chat_messages(thread_id, message_index);

-- Tool calls: engine invocation tracking with live progress
CREATE TABLE IF NOT EXISTS tool_calls (
    id               SERIAL PRIMARY KEY,
    thread_id        VARCHAR(64) NOT NULL,
    tool_call_id     VARCHAR(128) NOT NULL,
    tool_name        VARCHAR(64) NOT NULL,
    engine_thread_id VARCHAR(128),
    input_data       JSONB NOT NULL DEFAULT '{}',
    status           VARCHAR(16) NOT NULL DEFAULT 'running',
    progress         JSONB NOT NULL DEFAULT '{}',
    result_summary   TEXT,
    message_index    INTEGER,
    created_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tool_calls_thread
    ON tool_calls(thread_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tool_calls_id
    ON tool_calls(tool_call_id);
"""


# ═════════════════════════════════════════════════════════════════════════════
# ChatDB Class
# ═════════════════════════════════════════════════════════════════════════════

class ChatDB:
    """Database manager for chat messages and tool call tracking."""

    def __init__(self):
        self.conn = _get_connection()
        self.conn.autocommit = True

    def close(self):
        if self.conn and not self.conn.closed:
            self.conn.close()

    def init_tables(self):
        """Create the chat_messages and tool_calls tables if they don't exist."""
        with self.conn.cursor() as cur:
            cur.execute(CHAT_SCHEMA_SQL)

    # ─────────────────────────────────────────────────────────────────────────
    # Chat Messages
    # ─────────────────────────────────────────────────────────────────────────

    def insert_user_message(self, thread_id: str, content: str, message_index: int) -> int:
        """Insert a user message (always complete immediately)."""
        with self.conn.cursor() as cur:
            cur.execute(
                """INSERT INTO chat_messages (thread_id, role, content, message_index, is_complete)
                   VALUES (%s, 'user', %s, %s, TRUE)
                   RETURNING id""",
                (thread_id, content, message_index),
            )
            return cur.fetchone()[0]

    def insert_assistant_message(self, thread_id: str, message_index: int) -> int:
        """Insert an empty assistant message placeholder for streaming."""
        with self.conn.cursor() as cur:
            cur.execute(
                """INSERT INTO chat_messages (thread_id, role, content, message_index, is_complete)
                   VALUES (%s, 'assistant', '', %s, FALSE)
                   RETURNING id""",
                (thread_id, message_index),
            )
            return cur.fetchone()[0]

    def append_token(self, row_id: int, token: str):
        """Append a streamed token to an assistant message."""
        with self.conn.cursor() as cur:
            cur.execute(
                """UPDATE chat_messages
                   SET content = content || %s, updated_at = NOW()
                   WHERE id = %s""",
                (token, row_id),
            )

    def complete_message(self, row_id: int, extra_content: str = ""):
        """Mark a message as complete (optionally append final content)."""
        with self.conn.cursor() as cur:
            if extra_content:
                cur.execute(
                    """UPDATE chat_messages
                       SET content = content || %s, is_complete = TRUE, updated_at = NOW()
                       WHERE id = %s""",
                    (extra_content, row_id),
                )
            else:
                cur.execute(
                    """UPDATE chat_messages
                       SET is_complete = TRUE, updated_at = NOW()
                       WHERE id = %s""",
                    (row_id,),
                )

    def get_next_message_index(self, thread_id: str) -> int:
        """Get the next message index for a thread."""
        with self.conn.cursor() as cur:
            cur.execute(
                """SELECT COALESCE(MAX(message_index), -1) + 1
                   FROM chat_messages WHERE thread_id = %s""",
                (thread_id,),
            )
            return cur.fetchone()[0]

    def get_chat_history(self, thread_id: str) -> list[dict]:
        """Get the full chat history for a thread (for frontend reload)."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT role, content, message_index, is_complete, created_at
                   FROM chat_messages
                   WHERE thread_id = %s
                   ORDER BY message_index ASC""",
                (thread_id,),
            )
            rows = cur.fetchall()
            return [dict(row) for row in rows]

    def list_chat_threads(self) -> list[dict]:
        """List all chat threads with their creation times."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT thread_id, MIN(created_at) as created_at, COUNT(*) as message_count
                   FROM chat_messages
                   GROUP BY thread_id
                   ORDER BY MIN(created_at) DESC"""
            )
            rows = cur.fetchall()
            return [dict(row) for row in rows]

    def delete_thread(self, thread_id: str):
        """Delete all messages and tool calls for a thread."""
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM chat_messages WHERE thread_id = %s", (thread_id,))
            cur.execute("DELETE FROM tool_calls WHERE thread_id = %s", (thread_id,))

    # ─────────────────────────────────────────────────────────────────────────
    # Tool Calls
    # ─────────────────────────────────────────────────────────────────────────

    def insert_tool_call(
        self,
        thread_id: str,
        tool_call_id: str,
        tool_name: str,
        engine_thread_id: str,
        input_data: dict,
        message_index: int = None,
    ) -> int:
        """Insert a new tool call record when the agent invokes a tool."""
        with self.conn.cursor() as cur:
            cur.execute(
                """INSERT INTO tool_calls
                   (thread_id, tool_call_id, tool_name, engine_thread_id, input_data, status, progress, message_index)
                   VALUES (%s, %s, %s, %s, %s, 'running', '{}', %s)
                   RETURNING id""",
                (thread_id, tool_call_id, tool_name, engine_thread_id, Json(input_data), message_index),
            )
            return cur.fetchone()[0]

    def update_tool_progress(self, tool_call_id: str, node: str, status: str, detail: str = ""):
        """Update the progress JSONB for a specific node in a tool call."""
        node_data = json.dumps({"status": status, "detail": detail})
        with self.conn.cursor() as cur:
            cur.execute(
                """UPDATE tool_calls
                   SET progress = jsonb_set(progress, %s, %s::jsonb),
                       updated_at = NOW()
                   WHERE tool_call_id = %s AND status = 'running'""",
                ([node], node_data, tool_call_id),
            )

    def complete_tool_call(self, tool_call_id: str, result_summary: str):
        """Mark a tool call as completed with its result summary."""
        with self.conn.cursor() as cur:
            cur.execute(
                """UPDATE tool_calls
                   SET status = 'done', result_summary = %s, updated_at = NOW()
                   WHERE tool_call_id = %s""",
                (result_summary, tool_call_id),
            )

    def pause_tool_call(self, tool_call_id: str):
        """Mark a running tool call as paused."""
        with self.conn.cursor() as cur:
            cur.execute(
                """UPDATE tool_calls
                   SET status = 'paused', updated_at = NOW()
                   WHERE tool_call_id = %s AND status = 'running'""",
                (tool_call_id,),
            )

    def error_tool_call(self, tool_call_id: str, error_message: str):
        """Mark a tool call as errored."""
        with self.conn.cursor() as cur:
            cur.execute(
                """UPDATE tool_calls
                   SET status = 'error', result_summary = %s, updated_at = NOW()
                   WHERE tool_call_id = %s""",
                (error_message, tool_call_id),
            )

    def get_tool_calls(self, thread_id: str) -> list[dict]:
        """Get all tool calls for a chat thread."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT tool_call_id, tool_name, engine_thread_id, input_data,
                          status, progress, result_summary, message_index, created_at
                   FROM tool_calls
                   WHERE thread_id = %s
                   ORDER BY created_at ASC""",
                (thread_id,),
            )
            rows = cur.fetchall()
            return [dict(row) for row in rows]

    def get_paused_tools(self, thread_id: str) -> list[dict]:
        """Get all paused tool calls for a chat (for 'continue' logic)."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT tool_call_id, tool_name, engine_thread_id, input_data,
                          progress, created_at
                   FROM tool_calls
                   WHERE thread_id = %s AND status = 'paused'
                   ORDER BY created_at DESC""",
                (thread_id,),
            )
            rows = cur.fetchall()
            return [dict(row) for row in rows]

    def get_latest_paused_tool(self, thread_id: str) -> dict | None:
        """Get the most recently paused tool call for a chat."""
        paused = self.get_paused_tools(thread_id)
        return paused[0] if paused else None

    def get_running_tool_call_ids(self, thread_id: str) -> list[str]:
        """Get tool_call_ids of all currently running tools for a chat."""
        with self.conn.cursor() as cur:
            cur.execute(
                """SELECT tool_call_id FROM tool_calls
                   WHERE thread_id = %s AND status = 'running'""",
                (thread_id,),
            )
            return [row[0] for row in cur.fetchall()]

    def pause_all_running(self, thread_id: str):
        """Pause all running tool calls for a chat (used when user hits stop)."""
        with self.conn.cursor() as cur:
            cur.execute(
                """UPDATE tool_calls
                   SET status = 'paused', updated_at = NOW()
                   WHERE thread_id = %s AND status = 'running'""",
                (thread_id,),
            )
