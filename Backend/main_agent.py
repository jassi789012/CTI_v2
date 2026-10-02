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
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_core.tools import tool
from langchain_groq import ChatGroq
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.prebuilt import create_react_agent

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
def scan_natural_language_query(query: str) -> str:
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
        A summary of the scan results including the Engine ID for resuming,
        number of IPs found, CVEs extracted, and the final engine status.
    """
    from Engine_query_input import run_engine as run_query_engine

    engine_id = f"query_{uuid.uuid4().hex[:8]}"

    try:
        result = run_query_engine(query, thread_id=engine_id)

        ips = result.get("ips", [])
        cves = result.get("cve", [])
        status = result.get("engine_status", "unknown")

        summary = (
            f"Engine ID: {engine_id}\n"
            f"Status: {status}\n"
            f"Query: {query}\n"
            f"Shodan Queries Generated: {len(result.get('queries', []))}\n"
            f"IPs Discovered: {len(ips)}\n"
            f"IPs: {', '.join(ips[:20])}" + (" ..." if len(ips) > 20 else "") + "\n"
            f"CVEs Extracted: {len(cves)}\n"
            f"CVEs: {', '.join(cves[:30])}" + (" ..." if len(cves) > 30 else "")
        )
        return summary

    except Exception as e:
        return f"Engine ID: {engine_id}\nStatus: error\nError: {str(e)}"


@tool
def scan_ip_list(ip_addresses: list[str]) -> str:
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
        A summary including Engine ID, number of IPs scanned, and CVEs found.
    """
    from Engine_ip_input import run_engine as run_ip_engine

    engine_id = f"ips_{uuid.uuid4().hex[:8]}"

    try:
        result = run_ip_engine(ip_addresses, thread_id=engine_id)

        ips = result.get("ips", [])
        cves = result.get("cve", [])
        status = result.get("engine_status", "unknown")

        summary = (
            f"Engine ID: {engine_id}\n"
            f"Status: {status}\n"
            f"IPs Scanned: {len(ips)}\n"
            f"IPs: {', '.join(ips)}\n"
            f"CVEs Extracted: {len(cves)}\n"
            f"CVEs: {', '.join(cves[:30])}" + (" ..." if len(cves) > 30 else "")
        )
        return summary

    except Exception as e:
        return f"Engine ID: {engine_id}\nStatus: error\nError: {str(e)}"


@tool
def scan_cve_list(cve_ids: list[str]) -> str:
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
        A summary including Engine ID and number of CVEs processed.
    """
    from Engine_cve_input import run_engine as run_cve_engine

    engine_id = f"cves_{uuid.uuid4().hex[:8]}"

    try:
        result = run_cve_engine(cve_ids, thread_id=engine_id)

        cves = result.get("cve", [])
        status = result.get("engine_status", "unknown")

        summary = (
            f"Engine ID: {engine_id}\n"
            f"Status: {status}\n"
            f"CVEs Processed: {len(cves)}\n"
            f"CVEs: {', '.join(cves)}"
        )
        return summary

    except Exception as e:
        return f"Engine ID: {engine_id}\nStatus: error\nError: {str(e)}"


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
        {"type": "token",      "content": "partial text..."}
        {"type": "tool_start", "tool": "scan_ip_list", "input": {...}}
        {"type": "tool_end",   "tool": "scan_ip_list", "output": "..."}
        {"type": "done",       "thread_id": "chat_abc123"}
    
    Args:
        user_message: The user's text message.
        thread_id:    Chat session ID for memory persistence.
    """
    if not thread_id:
        thread_id = f"chat_{uuid.uuid4().hex[:8]}"

    with PostgresSaver.from_conn_string(PG_CONN_STRING) as checkpointer:
        checkpointer.setup()
        agent = build_agent(checkpointer=checkpointer)
        config = {"configurable": {"thread_id": thread_id}}

        for event in agent.stream(
            {"messages": [HumanMessage(content=user_message)]},
            config=config,
            stream_mode="updates",
        ):
            # Agent node emits AI messages (text + tool calls)
            if "agent" in event:
                for msg in event["agent"].get("messages", []):
                    if isinstance(msg, AIMessage):
                        if msg.content:
                            yield {"type": "token", "content": msg.content}
                        # If the AI is calling a tool, emit tool_start
                        for tc in (msg.tool_calls or []):
                            yield {
                                "type": "tool_start",
                                "tool": tc["name"],
                                "input": tc["args"],
                            }

            # Tools node emits tool results
            if "tools" in event:
                for msg in event["tools"].get("messages", []):
                    yield {
                        "type": "tool_end",
                        "tool": getattr(msg, "name", "unknown"),
                        "output": msg.content if hasattr(msg, "content") else str(msg),
                    }

        yield {"type": "done", "thread_id": thread_id}


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
