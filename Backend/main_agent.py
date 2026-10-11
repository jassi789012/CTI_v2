"""
CTI Main Agent — LangGraph ReAct Agent with Groq LLM
======================================================
The central AI agent for the CTI platform. It receives user messages,
reasons about the best course of action, and uses enumeration engine
tools to scan targets and gather cyber threat intelligence.

Tools Available:
  1. scan_natural_language_query — Runs the full pipeline from a user query
  2. scan_ip_list               — Scans a list of known IP addresses
  3. scan_cve_list              — Fetches NVD data + ChatGPT analysis for CVE IDs

Architecture:
  - LLM:          Groq API  (openai/gpt-oss-120b)
  - Agent:        LangGraph create_react_agent (tool-calling ReAct loop)
  - Checkpoints:  PostgreSQL (same cti_db as the engines)
  - Engine Tools: Each tool runs a LangGraph sub-workflow and returns
                  real-time progress + final results via generators.

Usage:
    # CLI mode (interactive chat)
    python main_agent.py

    # Programmatic mode
    from main_agent import run_agent, build_agent
    response = run_agent("Scan 1.2.3.4 for vulnerabilities", thread_id="chat_001")
"""

import os
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, AIMessageChunk
from langchain_core.tools import tool, InjectedToolCallId
from langchain_groq import ChatGroq
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.prebuilt import create_react_agent
from langgraph.types import interrupt, Command
from langchain_core.runnables import RunnableConfig

from engine_manager import EngineManager

# Thread-local to pass the chat thread_id down to tools
_chat_thread_local = threading.local()

# ─── Paths ───────────────────────────────────────────────────────────────────
BACKEND_DIR = Path(r"c:\Users\jassi\OneDrive\Documents\CTI_V2\Backend")
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(BACKEND_DIR / "def_Shodan"))
sys.path.insert(0, str(BACKEND_DIR / "def_nmap"))
sys.path.insert(0, str(BACKEND_DIR / "query_gen"))
sys.path.insert(0, str(BACKEND_DIR / "cve_maper"))

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

# ─── LLM Config ──────────────────────────────────────────────────────────────
GROQ_MODEL = "openai/gpt-oss-120b"


# ═════════════════════════════════════════════════════════════════════════════
# System Prompt
# ═════════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are a Cyber Threat Intelligence (CTI) analyst agent. You help security researchers and analysts discover, scan, and analyze cyber threats.

You have access to three enumeration engine tools. Each engine runs a multi-step LangGraph workflow that scans targets, collects data, and stores everything in a PostgreSQL database.

## Your Tools

### 1. scan_natural_language_query
Use this when the user describes what they want to find in natural language.
- Example user input: "Find Apache servers in India with known vulnerabilities"
- What it does: Converts the query into Shodan search dorks → fetches IPs → runs Nmap + Shodan scans on each IP → extracts CVEs → fetches NVD data → enriches with ChatGPT analysis
- This is the FULL pipeline. Use it when the user doesn't have specific IPs or CVEs yet.

### 2. scan_ip_list
Use this when the user provides specific IP addresses to scan.
- Example user input: "Scan 1.2.3.4 and 5.6.7.8"
- What it does: Runs Nmap (8-phase full-spectrum scan) + Shodan scraping on each IP → extracts CVEs → fetches NVD data → enriches with ChatGPT analysis
- Skips query generation and IP discovery since the user already has the IPs.

### 3. scan_cve_list
Use this when the user provides specific CVE IDs to look up.
- Example user input: "Give me details about CVE-2024-1234 and CVE-2023-5678"
- What it does: Fetches full NVD data for each CVE → enriches with ChatGPT MITRE ATT&CK mapping and vulnerability walkthrough
- Skips all IP-related scanning. Use this for pure CVE research.

## Important Behavior Rules

1. **Choose the right tool.** If the user gives you IPs, use scan_ip_list. If they give you CVEs, use scan_cve_list. If they describe what they want in plain English, use scan_natural_language_query. Never use the wrong tool.

2. **Engine IDs.** Each tool returns an Engine ID (thread_id). Always tell the user this ID so they can resume the scan later if needed. Example: "I've started your scan. The Engine ID is ips_a1b2c3d4."

3. **Report results clearly.** After an engine finishes, summarize what was found: how many IPs were scanned, how many ports were open, how many CVEs were discovered, etc.

4. **Be honest about limitations.** If a scan finds no results, say so. If an error occurs, report the error clearly.

5. **Long scans.** Full Nmap scans with all 65535 ports can take 5-20 minutes per IP. Warn the user about expected duration for large scans.

6. **Resume capability.** If the user asks to resume a previous scan, ask for the Engine ID. If they don't have it, tell them you cannot resume without the ID.
"""


# ═════════════════════════════════════════════════════════════════════════════
# Tool Definitions
# ═════════════════════════════════════════════════════════════════════════════

@tool
def scan_natural_language_query(
    query: Annotated[str, "The natural language query describing the target"],
    tool_call_id: Annotated[str, InjectedToolCallId],
    config: RunnableConfig,
) -> str:
    """Run the full CTI enumeration pipeline from a natural language query.
    
    This is the most comprehensive tool. It converts a natural language 
    description into Shodan search queries, discovers IPs, then runs 
    parallel Nmap (8-phase full-spectrum) and Shodan scans on every IP found.
    After scanning, it extracts all CVEs from the scan data, fetches NVD 
    details, and enriches each CVE with ChatGPT MITRE ATT&CK analysis.
    
    Use this when the user describes what they want to find in plain English,
    for example: "Find vulnerable Apache servers in Germany" or 
    "Search for exposed MongoDB databases".
    
    The entire pipeline can take 10-60+ minutes depending on how many IPs 
    are discovered. All data is automatically saved to the PostgreSQL database.
    
    Args:
        query: A natural language description of what to scan/find.
               Example: "Find Apache 2.4.49 servers with path traversal vulnerabilities"
    
    Returns:
        Confirmation that the engine has been started with its thread ID.
    """
    from chat_persistence import ChatDB

    # Step 1: Ask for human approval via LangGraph interrupt
    human_response = interrupt({
        "tool": "scan_natural_language_query",
        "engine_name": "Query Engine",
        "query": query,
        "message": f'Run Query Engine for "{query}"?',
    })

    # If human declined, return without running
    if human_response and human_response.get("action") == "decline":
        return f"User declined to run Query Engine for: {query}"

    # Step 2: Start engine in background (fire-and-forget)
    engine_thread_id = f"query_{tool_call_id}"
    
    configurable = config.get("configurable", {})
    chat_tid = configurable.get("thread_id")
    msg_idx = configurable.get("assistant_msg_idx")
    if chat_tid:
        try:
            db = ChatDB()
            db.insert_tool_call(
                chat_tid, tool_call_id, "scan_natural_language_query",
                engine_thread_id, {"query": query}, message_index=msg_idx,
            )
            db.close()
        except Exception:
            pass

    # Start engine in background thread via EngineManager
    try:
        mgr = EngineManager()
        mgr.start_engine(
            engine_type="query",
            input_data={"query": query},
            engine_thread_id=engine_thread_id,
            chat_thread_id=chat_tid or "",
            tool_call_id=tool_call_id,
        )
    except RuntimeError as e:
        return f"Cannot start engine: {str(e)}"

    # Step 3: Return immediately — don't wait for engine
    return (
        f"Query Engine started in background.\n"
        f"Engine Thread ID: {engine_thread_id}\n"
        f"Query: {query}\n"
        f"The user can track live progress via the engine stream."
    )


@tool
def scan_ip_list(
    ip_addresses: Annotated[list[str], "List of IPv4 addresses"],
    tool_call_id: Annotated[str, InjectedToolCallId],
    config: RunnableConfig,
) -> str:
    """Scan a list of IP addresses using Nmap (8-phase full-spectrum) and Shodan.
    
    Use this when the user provides specific IP addresses they want scanned.
    This skips query generation and IP discovery — it goes directly to scanning.
    
    The scan runs an 8-phase Nmap scan on each IP:
      Phase 1: All 65535 TCP ports + service/version detection + OS fingerprinting
      Phase 2: Top 500 UDP ports
      Phase 3: Vulnerability scripts (vuln + vulners CVE database)
      Phase 4: 64 NSE enumeration scripts (SSL, HTTP, DNS, SSH, SMB, SNMP, etc.)
      Phase 5: GeoIP + WHOIS + Reverse DNS
      Phase 6: Firewall detection (ACK scan)
      Phase 7: IP Protocol scan (non-TCP/UDP protocols)
      Phase 8: SCTP Init scan
    
    Additionally, Shodan data is scraped in parallel for each IP.
    After scanning, CVEs are extracted and enriched via NVD + ChatGPT.
    
    Expected duration: 5-20 minutes per IP address.
    
    Args:
        ip_addresses: List of IPv4 addresses to scan.
                      Example: ["1.2.3.4", "5.6.7.8", "10.0.0.1"]
    
    Returns:
        Confirmation that the engine has been started with its thread ID.
    """
    from chat_persistence import ChatDB

    # Step 1: Ask for human approval
    human_response = interrupt({
        "tool": "scan_ip_list",
        "engine_name": "IP Scanner Engine",
        "query": f"Scan IPs: {', '.join(ip_addresses[:5])}" + (" ..." if len(ip_addresses) > 5 else ""),
        "message": f'Run IP Scanner Engine for {len(ip_addresses)} IP(s)?',
    })

    if human_response and human_response.get("action") == "decline":
        return f"User declined to run IP Scanner for: {', '.join(ip_addresses)}"

    # Step 2: Start engine in background
    engine_thread_id = f"ips_{tool_call_id}"
    
    configurable = config.get("configurable", {})
    chat_tid = configurable.get("thread_id")
    msg_idx = configurable.get("assistant_msg_idx")
    if chat_tid:
        try:
            db = ChatDB()
            db.insert_tool_call(
                chat_tid, tool_call_id, "scan_ip_list",
                engine_thread_id, {"ip_addresses": ip_addresses}, message_index=msg_idx,
            )
            db.close()
        except Exception:
            pass

    try:
        mgr = EngineManager()
        mgr.start_engine(
            engine_type="ip",
            input_data={"ip_addresses": ip_addresses},
            engine_thread_id=engine_thread_id,
            chat_thread_id=chat_tid or "",
            tool_call_id=tool_call_id,
        )
    except RuntimeError as e:
        return f"Cannot start engine: {str(e)}"

    return (
        f"IP Scanner Engine started in background.\n"
        f"Engine Thread ID: {engine_thread_id}\n"
        f"IPs: {', '.join(ip_addresses)}\n"
        f"The user can track live progress via the engine stream."
    )


@tool
def scan_cve_list(
    cve_ids: Annotated[list[str], "List of CVE identifiers"],
    tool_call_id: Annotated[str, InjectedToolCallId],
    config: RunnableConfig,
) -> str:
    """Fetch NVD data and run ChatGPT MITRE ATT&CK analysis for a list of CVE IDs.
    
    Use this when the user provides specific CVE identifiers they want researched.
    This skips all IP scanning — it goes directly to CVE data enrichment.
    
    For each CVE, the tool:
      1. Fetches full vulnerability data from the NIST NVD REST API
         (description, CVSS scores, attack vectors, affected products, etc.)
      2. Sends the CVE to ChatGPT for enrichment:
         - MITRE ATT&CK technique mapping
         - Detailed vulnerability walkthrough
         - Exploitation analysis
    
    NVD API rate: ~1,800 CVEs/hour with API key, ~553/hour without.
    ChatGPT enrichment: ~1-2 minutes per CVE.
    
    Args:
        cve_ids: List of CVE identifiers to research.
                 Example: ["CVE-2024-1234", "CVE-2023-5678"]
    
    Returns:
        Confirmation that the engine has been started with its thread ID.
    """
    from chat_persistence import ChatDB

    # Step 1: Ask for human approval
    human_response = interrupt({
        "tool": "scan_cve_list",
        "engine_name": "CVE Research Engine",
        "query": f"Research CVEs: {', '.join(cve_ids[:5])}" + (" ..." if len(cve_ids) > 5 else ""),
        "message": f'Run CVE Research Engine for {len(cve_ids)} CVE(s)?',
    })

    if human_response and human_response.get("action") == "decline":
        return f"User declined to run CVE Research for: {', '.join(cve_ids)}"

    # Step 2: Start engine in background
    engine_thread_id = f"cves_{tool_call_id}"
    
    configurable = config.get("configurable", {})
    chat_tid = configurable.get("thread_id")
    msg_idx = configurable.get("assistant_msg_idx")
    if chat_tid:
        try:
            db = ChatDB()
            db.insert_tool_call(
                chat_tid, tool_call_id, "scan_cve_list",
                engine_thread_id, {"cve_ids": cve_ids}, message_index=msg_idx,
            )
            db.close()
        except Exception:
            pass

    try:
        mgr = EngineManager()
        mgr.start_engine(
            engine_type="cve",
            input_data={"cve_ids": cve_ids},
            engine_thread_id=engine_thread_id,
            chat_thread_id=chat_tid or "",
            tool_call_id=tool_call_id,
        )
    except RuntimeError as e:
        return f"Cannot start engine: {str(e)}"

    return (
        f"CVE Research Engine started in background.\n"
        f"Engine Thread ID: {engine_thread_id}\n"
        f"CVEs: {', '.join(cve_ids)}\n"
        f"The user can track live progress via the engine stream."
    )


# ═════════════════════════════════════════════════════════════════════════════
# Agent Builder
# ═════════════════════════════════════════════════════════════════════════════

TOOLS = [scan_natural_language_query, scan_ip_list, scan_cve_list]


def build_agent(checkpointer=None):
    """Build the main CTI agent with Groq LLM and enumeration tools."""
    llm = ChatGroq(
        model=GROQ_MODEL,
        temperature=0,
    )

    agent = create_react_agent(
        model=llm,
        tools=TOOLS,
        prompt=SYSTEM_PROMPT,
        checkpointer=checkpointer,
    )

    return agent


# ═════════════════════════════════════════════════════════════════════════════
# Agent Runner
# ═════════════════════════════════════════════════════════════════════════════

def run_agent(
    user_message: str,
    thread_id: str = None,
) -> str:
    """
    Send a message to the main CTI agent and get a response.
    
    Args:
        user_message: The user's text message.
        thread_id:    Chat session ID for memory persistence.
                      Pass the same ID to continue a conversation.
    
    Returns:
        The agent's text response.
    """
    if not thread_id:
        thread_id = f"chat_{uuid.uuid4().hex[:8]}"

    with PostgresSaver.from_conn_string(PG_CONN_STRING) as checkpointer:
        checkpointer.setup()
        agent = build_agent(checkpointer=checkpointer)
        config = {"configurable": {"thread_id": thread_id}}

        response = agent.invoke(
            {"messages": [HumanMessage(content=user_message)]},
            config=config,
        )

        # Extract the last AI message from the response
        ai_messages = [
            msg for msg in response["messages"]
            if isinstance(msg, AIMessage) and msg.content
        ]
        if ai_messages:
            return ai_messages[-1].content
        return "(No response generated)"


def stream_agent(
    user_message: str,
    thread_id: str = None,
):
    """
    Stream the agent's response token-by-token and tool events.
    
    Yields dicts with:
        {"type": "token",            "content": "partial text..."}
        {"type": "tool_approval",    "tool": "...", "engine_name": "...", "query": "..."}
        {"type": "tool_end",         "tool": "...", "output": "..."}
        {"type": "engine_started",   "engine_thread_id": "...", "engine_name": "..."}
        {"type": "done",             "thread_id": "chat_abc123"}
    
    Args:
        user_message: The user's text message.
        thread_id:    Chat session ID for memory persistence.
    """
    if not thread_id:
        thread_id = f"chat_{uuid.uuid4().hex[:8]}"

    with PostgresSaver.from_conn_string(PG_CONN_STRING) as checkpointer:
        checkpointer.setup()
        agent = build_agent(checkpointer=checkpointer)
        
        # Get next msg_index for tool linkage
        from chat_persistence import ChatDB
        try:
            db = ChatDB()
            msg_idx = db.get_next_message_index(thread_id)
            db.close()
        except Exception:
            msg_idx = 0

        config = {
            "configurable": {
                "thread_id": thread_id,
                "assistant_msg_idx": msg_idx,
            }
        }

        caught_interrupt = False

        for event_type, payload in agent.stream(
            {"messages": [HumanMessage(content=user_message)]},
            config=config,
            stream_mode=["messages", "updates"],
        ):
            # 1. Handle real-time token streaming from the LLM
            if event_type == "messages":
                chunk, metadata = payload
                if isinstance(chunk, AIMessageChunk):
                    if chunk.content:
                        yield {"type": "token", "content": chunk.content}

            # 2. Handle state updates (when a node finishes)
            elif event_type == "updates":
                # Agent node finished (check if it decided to call tools)
                if "agent" in payload:
                    for msg in payload["agent"].get("messages", []):
                        if isinstance(msg, AIMessage):
                            for tc in (msg.tool_calls or []):
                                yield {
                                    "type": "tool_start",
                                    "tool": tc["name"],
                                    "input": tc["args"],
                                }

                # Tools node finished (returns the tool execution result)
                if "tools" in payload:
                    for msg in payload["tools"].get("messages", []):
                        output = msg.content if hasattr(msg, "content") else str(msg)
                        tool_name = getattr(msg, "name", "unknown")
                        
                        engine_tid = None
                        engine_name = None
                        if "Engine Thread ID:" in output:
                            for line in output.split("\n"):
                                if line.startswith("Engine Thread ID:"):
                                    engine_tid = line.split(":", 1)[1].strip()
                            engine_name = _get_engine_display_name(tool_name)
                        
                        yield {
                            "type": "tool_end",
                            "tool": tool_name,
                            "output": output,
                        }
                        
                        if engine_tid:
                            yield {
                                "type": "engine_started",
                                "engine_thread_id": engine_tid,
                                "engine_name": engine_name or tool_name,
                                "tool": tool_name,
                            }

                # Handle interrupt (human-in-the-loop approval) — in-stream detection
                if "__interrupt" in payload:
                    for intr in payload["__interrupt"]:
                        interrupt_value = intr.value if hasattr(intr, "value") else intr
                        yield {
                            "type": "tool_approval",
                            "tool": interrupt_value.get("tool", ""),
                            "engine_name": interrupt_value.get("engine_name", ""),
                            "query": interrupt_value.get("query", ""),
                            "message": interrupt_value.get("message", ""),
                        }
                        caught_interrupt = True
                    if caught_interrupt:
                        return

        # ── Fallback: check graph state for pending interrupts ──────────
        # Some LangGraph versions don't emit __interrupt in the stream.
        # We check the actual graph state after the stream ends.
        if not caught_interrupt:
            try:
                state = agent.get_state(config)
                if state and state.next:  # Graph has pending nodes → interrupted
                    for task in (state.tasks or []):
                        if hasattr(task, 'interrupts') and task.interrupts:
                            for intr in task.interrupts:
                                interrupt_value = intr.value if hasattr(intr, 'value') else {}
                                yield {
                                    "type": "tool_approval",
                                    "tool": interrupt_value.get("tool", ""),
                                    "engine_name": interrupt_value.get("engine_name", ""),
                                    "query": interrupt_value.get("query", ""),
                                    "message": interrupt_value.get("message", ""),
                                }
                            return
            except Exception as e:
                print(f"[Agent] Error checking state for interrupts: {e}")

        yield {"type": "done", "thread_id": thread_id}


def resume_agent(thread_id: str, human_response: dict):
    """
    Resume the agent after human-in-the-loop approval/decline.
    
    Args:
        thread_id: The chat thread ID.
        human_response: {"action": "accept"} or {"action": "decline"}
    
    Yields the same event dicts as stream_agent.
    """
    with PostgresSaver.from_conn_string(PG_CONN_STRING) as checkpointer:
        checkpointer.setup()
        agent = build_agent(checkpointer=checkpointer)
        
        # Get next msg_index for tool linkage (assume current msg is the last inserted)
        from chat_persistence import ChatDB
        try:
            db = ChatDB()
            msg_idx = db.get_next_message_index(thread_id) - 1
            db.close()
        except Exception:
            msg_idx = 0
            
        config = {
            "configurable": {
                "thread_id": thread_id,
                "assistant_msg_idx": msg_idx,
            }
        }

        caught_interrupt = False

        for event_type, payload in agent.stream(
            Command(resume=human_response),
            config=config,
            stream_mode=["messages", "updates"],
        ):
            if event_type == "messages":
                chunk, metadata = payload
                if isinstance(chunk, AIMessageChunk):
                    if chunk.content:
                        yield {"type": "token", "content": chunk.content}

            elif event_type == "updates":
                if "agent" in payload:
                    for msg in payload["agent"].get("messages", []):
                        if isinstance(msg, AIMessage):
                            for tc in (msg.tool_calls or []):
                                yield {
                                    "type": "tool_start",
                                    "tool": tc["name"],
                                    "input": tc["args"],
                                }

                if "tools" in payload:
                    for msg in payload["tools"].get("messages", []):
                        output = msg.content if hasattr(msg, "content") else str(msg)
                        tool_name = getattr(msg, "name", "unknown")
                        
                        engine_tid = None
                        engine_name = None
                        if "Engine Thread ID:" in output:
                            for line in output.split("\n"):
                                if line.startswith("Engine Thread ID:"):
                                    engine_tid = line.split(":", 1)[1].strip()
                            engine_name = _get_engine_display_name(tool_name)
                        
                        yield {
                            "type": "tool_end",
                            "tool": tool_name,
                            "output": output,
                        }
                        
                        if engine_tid:
                            yield {
                                "type": "engine_started",
                                "engine_thread_id": engine_tid,
                                "engine_name": engine_name or tool_name,
                                "tool": tool_name,
                            }

                if "__interrupt" in payload:
                    for intr in payload["__interrupt"]:
                        interrupt_value = intr.value if hasattr(intr, "value") else intr
                        yield {
                            "type": "tool_approval",
                            "tool": interrupt_value.get("tool", ""),
                            "engine_name": interrupt_value.get("engine_name", ""),
                            "query": interrupt_value.get("query", ""),
                            "message": interrupt_value.get("message", ""),
                        }
                        caught_interrupt = True
                    if caught_interrupt:
                        return

        # Fallback interrupt check
        if not caught_interrupt:
            try:
                state = agent.get_state(config)
                if state and state.next:
                    for task in (state.tasks or []):
                        if hasattr(task, 'interrupts') and task.interrupts:
                            for intr in task.interrupts:
                                interrupt_value = intr.value if hasattr(intr, 'value') else {}
                                yield {
                                    "type": "tool_approval",
                                    "tool": interrupt_value.get("tool", ""),
                                    "engine_name": interrupt_value.get("engine_name", ""),
                                    "query": interrupt_value.get("query", ""),
                                    "message": interrupt_value.get("message", ""),
                                }
                            return
            except Exception as e:
                print(f"[Agent] Error checking state for interrupts: {e}")

        yield {"type": "done", "thread_id": thread_id}


def get_pending_approval(thread_id: str) -> dict | None:
    """
    Check if a chat thread has a pending interrupt (tool awaiting approval).
    Used when frontend reloads a chat after server restart.
    
    Returns:
        dict with tool/engine_name/query/message if pending, else None.
    """
    try:
        with PostgresSaver.from_conn_string(PG_CONN_STRING) as checkpointer:
            checkpointer.setup()
            agent = build_agent(checkpointer=checkpointer)
            config = {"configurable": {"thread_id": thread_id}}
            state = agent.get_state(config)
            if state and state.next:
                for task in (state.tasks or []):
                    if hasattr(task, 'interrupts') and task.interrupts:
                        for intr in task.interrupts:
                            val = intr.value if hasattr(intr, 'value') else {}
                            return {
                                "tool": val.get("tool", ""),
                                "engine_name": val.get("engine_name", ""),
                                "query": val.get("query", ""),
                                "message": val.get("message", ""),
                            }
    except Exception as e:
        print(f"[Agent] Error checking pending approval: {e}")
    return None


def _get_engine_display_name(tool_name: str) -> str:
    """Map tool name to a user-friendly engine display name."""
    mapping = {
        "scan_natural_language_query": "Query Engine",
        "scan_ip_list": "IP Scanner Engine",
        "scan_cve_list": "CVE Research Engine",
    }
    return mapping.get(tool_name, tool_name)


# ═════════════════════════════════════════════════════════════════════════════
# Chat History Retrieval (for Frontend)
# ═════════════════════════════════════════════════════════════════════════════

def get_chat_history(thread_id: str) -> list[dict]:
    """
    Retrieve the full chat history for a given thread_id.
    Returns a list of {"role": "user"|"assistant", "content": "..."} dicts.
    Used by the frontend to restore a previous conversation.
    """
    with PostgresSaver.from_conn_string(PG_CONN_STRING) as checkpointer:
        checkpointer.setup()
        agent = build_agent(checkpointer=checkpointer)
        config = {"configurable": {"thread_id": thread_id}}

        state = agent.get_state(config)
        if not state or not state.values:
            return []

        messages = state.values.get("messages", [])
        history = []
        for msg in messages:
            if isinstance(msg, HumanMessage):
                history.append({"role": "user", "content": msg.content})
            elif isinstance(msg, AIMessage) and msg.content:
                history.append({"role": "assistant", "content": msg.content})
        return history


def get_pending_approval(thread_id: str) -> dict | None:
    """
    Check if the LangGraph state is currently interrupted waiting for user approval.
    Returns the interrupt payload if waiting, else None.
    """
    with PostgresSaver.from_conn_string(PG_CONN_STRING) as checkpointer:
        checkpointer.setup()
        agent = build_agent(checkpointer=checkpointer)
        config = {"configurable": {"thread_id": thread_id}}
        
        state = agent.get_state(config)
        if state and state.tasks:
            for task in state.tasks:
                if task.interrupts:
                    for interrupt_payload in task.interrupts:
                        # Assuming the payload is our dict with "tool", "engine_name", etc.
                        if isinstance(interrupt_payload.value, dict) and "engine_name" in interrupt_payload.value:
                            return interrupt_payload.value
    return None


def list_chat_sessions() -> list[str]:
    """
    List all chat thread_ids from the checkpoints table.
    Returns a list of thread_id strings that start with 'chat_'.
    """
    import psycopg2
    try:
        conn = psycopg2.connect(PG_CONN_STRING)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT thread_id FROM checkpoints
                WHERE thread_id LIKE 'chat_%'
                ORDER BY thread_id DESC
            """)
            ids = [row[0] for row in cur.fetchall()]
        conn.close()
        return ids
    except Exception:
        return []


# ═════════════════════════════════════════════════════════════════════════════
# CLI Entry Point (Interactive Chat)
# ═════════════════════════════════════════════════════════════════════════════

def main():
    print(f"\n{'=' * 60}")
    print(f"  CTI AGENT — Interactive Chat")
    print(f"  Model: {GROQ_MODEL} (via Groq)")
    print(f"  Tools: {len(TOOLS)} enumeration engines")
    print(f"{'=' * 60}")

    # Check for past chat sessions
    past_sessions = list_chat_sessions()
    thread_id = None

    if past_sessions:
        print(f"\n  [*] Found {len(past_sessions)} past chat session(s).")
        while True:
            ans = input("  Resume a past session? (y/n): ").strip().lower()
            if ans in ("y", "yes", "n", "no"):
                break
            print("  Please enter 'y' or 'n'.")

        if ans in ("y", "yes"):
            print(f"\n  Past sessions:\n")
            for i, sid in enumerate(past_sessions[:10], 1):
                print(f"    [{i}] {sid}")

            while True:
                choice = input(f"\n  Select (1-{min(len(past_sessions), 10)}, or 0 for new): ").strip()
                if choice == "0":
                    break
                if choice.isdigit() and 1 <= int(choice) <= min(len(past_sessions), 10):
                    thread_id = past_sessions[int(choice) - 1]
                    break
                print("  Invalid choice.")

    if not thread_id:
        thread_id = f"chat_{uuid.uuid4().hex[:8]}"

    print(f"\n  Thread ID: {thread_id}")
    print(f"  Type 'quit' or 'exit' to end the chat.\n")
    print(f"{'─' * 60}")

    # Load existing history if resuming
    if thread_id in (past_sessions or []):
        history = get_chat_history(thread_id)
        if history:
            print(f"\n  [*] Loaded {len(history)} previous messages.\n")
            for msg in history[-6:]:  # Show last 6 messages
                role = "You" if msg["role"] == "user" else "Agent"
                content = msg["content"][:100] + "..." if len(msg["content"]) > 100 else msg["content"]
                print(f"  [{role}] {content}")
            print(f"\n{'─' * 60}")

    # Interactive chat loop
    while True:
        try:
            user_input = input("\n  You > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\n  [*] Chat ended.")
            break

        if not user_input:
            continue
        if user_input.lower() in ("quit", "exit", "q"):
            print("\n  [*] Chat ended. Your conversation is saved.")
            print(f"  Thread ID: {thread_id}")
            break

        print(f"\n  Agent > ", end="", flush=True)

        # Stream the response
        full_response = ""
        for event in stream_agent(user_input, thread_id=thread_id):
            if event["type"] == "token":
                print(event["content"], end="", flush=True)
                full_response += event["content"]
            elif event["type"] == "tool_start":
                tool_name = event["tool"]
                print(f"\n  [🔧 Using tool: {tool_name}]", flush=True)
                print(f"  [⏳ Engine running... this may take several minutes]", flush=True)
            elif event["type"] == "tool_end":
                tool_name = event["tool"]
                output_preview = event["output"][:200]
                print(f"\n  [✅ Tool {tool_name} finished]", flush=True)
                print(f"  [📊 Result preview: {output_preview}]", flush=True)
                print(f"\n  Agent > ", end="", flush=True)
            elif event["type"] == "done":
                pass

        print()  # newline after streaming


if __name__ == "__main__":
    main()
