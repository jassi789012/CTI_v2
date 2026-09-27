"""
CTI Engine — Query Input Pipeline (LangGraph)
===============================================
Full pipeline: Natural language query → Shodan queries → IPs → parallel
data collection (Shodan scraping + Nmap scanning).

State is persisted in PostgreSQL via LangGraph checkpointing. If the engine
crashes mid-run, re-invoke with the same thread_id to resume.

Graph: query_gen → get_ips → process_all_ips (Shodan + Nmap parallel) → summary

Shodan opens browser ONCE, processes all IPs by navigating between pages.
Nmap uses its thread pool to scan all IPs with workers.
Both run in parallel via asyncio.gather.

Usage:
    from Engine_query_input import run_engine
    result = run_engine("find apache servers in India", thread_id="run_001")
"""

import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, TypedDict

from dotenv import load_dotenv
from langgraph.graph import END, StateGraph
from langgraph.checkpoint.postgres import PostgresSaver

# ─── Setup paths ─────────────────────────────────────────────────────────────
BACKEND_DIR = Path(__file__).parent
sys.path.insert(0, str(BACKEND_DIR / "def_Shodan"))
sys.path.insert(0, str(BACKEND_DIR / "def_nmap"))
sys.path.insert(0, str(BACKEND_DIR / "query_gen"))

from query_gen_ai import generate_queries
from get_ip import get_ip_query_ip
from get_ip_info import get_ip_info_json
from nmap_scanner import nmap_scan_ips
from db_manager import DBManager

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


# ═════════════════════════════════════════════════════════════════════════════
# State Schema
# ═════════════════════════════════════════════════════════════════════════════

class EngineState(TypedDict):
    """Full state of the CTI engine, checkpointed after every node."""

    # ── Input ────────────────────────────────────────────
    user_query: str
    query_count: int

    # ── Stage 1: Query Generation ────────────────────────
    generated_queries: list[str]

    # ── Stage 2: IP Discovery ────────────────────────────
    discovered_ips: list[str]

    # ── Stage 3: Batch Processing Results ────────────────
    shodan_results: list[dict]
    nmap_results: list[dict]
    shodan_errors: list[dict]
    nmap_errors: list[dict]

    # ── Live Status ──────────────────────────────────────
    current_step: str
    status_message: str
    started_at: str
    finished_at: str


# ═════════════════════════════════════════════════════════════════════════════
# Node Functions
# ═════════════════════════════════════════════════════════════════════════════

def query_gen_node(state: EngineState) -> dict:
    """Node 1: Generate Shodan queries from natural language input."""
    user_query = state["user_query"]
    count = state.get("query_count", 10)

    print(f"\n{'='*60}")
    print(f"  NODE: Query Generation")
    print(f"  Input: \"{user_query}\"")
    print(f"{'='*60}")

    queries = generate_queries(user_query, count)

    if not queries:
        return {
            "generated_queries": [],
            "current_step": "error",
            "status_message": "Failed to generate queries from LLM",
        }

    return {
        "generated_queries": queries,
        "current_step": "query_gen_done",
        "status_message": f"Generated {len(queries)} Shodan queries",
    }


def get_ip_node(state: EngineState) -> dict:
    """Node 2: Scrape IPs from Shodan search results."""
    queries = state["generated_queries"]

    print(f"\n{'='*60}")
    print(f"  NODE: IP Discovery")
    print(f"  Queries: {len(queries)}")
    print(f"{'='*60}")

    if not queries:
        return {
            "discovered_ips": [],
            "current_step": "error",
            "status_message": "No queries to search",
        }

    ips = get_ip_query_ip(queries)

    return {
        "discovered_ips": ips,
        "current_step": "ip_discovery_done",
        "status_message": f"Discovered {len(ips)} unique IPs from {len(queries)} queries",
    }


def process_all_ips_node(state: EngineState) -> dict:
    """
    Node 3: Run Shodan + Nmap in parallel on ALL IPs.

    Shodan: Opens browser ONCE → navigates to each IP → closes when done.
    Nmap:   Uses thread pool with workers → scans all IPs concurrently.
    Both run in parallel via asyncio.gather.

    This is exactly how try.py worked — same pattern, now inside LangGraph.
    """
    ips = state["discovered_ips"]

    if not ips:
        return {
            "shodan_results": [],
            "nmap_results": [],
            "shodan_errors": [],
            "nmap_errors": [],
            "current_step": "no_ips",
            "status_message": "No IPs to process",
        }

    print(f"\n{'='*60}")
    print(f"  NODE: Process All IPs ({len(ips)} targets)")
    print(f"  Running Shodan scraping + Nmap scanning in parallel...")
    print(f"{'='*60}")

    # ── Run both in parallel (same as try.py) ────────────────────────────
    async def _parallel():
        shodan_task = asyncio.to_thread(get_ip_info_json, ips)
        nmap_task = asyncio.to_thread(nmap_scan_ips, ips)
        return await asyncio.gather(shodan_task, nmap_task, return_exceptions=True)

    results = asyncio.run(_parallel())
    shodan_raw, nmap_raw = results

    # ── Parse Shodan results ─────────────────────────────────────────────
    shodan_results = []
    shodan_errors = []
    if isinstance(shodan_raw, Exception):
        shodan_errors.append({"source": "shodan", "error": str(shodan_raw)})
    elif isinstance(shodan_raw, list):
        for r in shodan_raw:
            if isinstance(r, dict) and "error" in r:
                shodan_errors.append({"ip": r.get("ip"), "source": "shodan", "error": r["error"]})
            elif r is not None:
                shodan_results.append(r)

    # ── Parse Nmap results ───────────────────────────────────────────────
    nmap_results = []
    nmap_errors = []
    if isinstance(nmap_raw, Exception):
        nmap_errors.append({"source": "nmap", "error": str(nmap_raw)})
    elif isinstance(nmap_raw, list):
        for r in nmap_raw:
            if isinstance(r, dict) and "error" in r:
                nmap_errors.append({"ip": r.get("ip"), "source": "nmap", "error": r["error"]})
            elif r is not None:
                nmap_results.append(r)

    msg = (
        f"Processed {len(ips)} IPs: "
        f"Shodan={len(shodan_results)} ok/{len(shodan_errors)} err, "
        f"Nmap={len(nmap_results)} ok/{len(nmap_errors)} err"
    )
    print(f"\n[+] {msg}")

    return {
        "shodan_results": shodan_results,
        "nmap_results": nmap_results,
        "shodan_errors": shodan_errors,
        "nmap_errors": nmap_errors,
        "current_step": "processing_done",
        "status_message": msg,
    }


def summary_node(state: EngineState) -> dict:
    """Node 4: Compile final summary."""
    total_ips = len(state.get("discovered_ips", []))
    shodan_count = len(state.get("shodan_results", []))
    nmap_count = len(state.get("nmap_results", []))
    s_errors = len(state.get("shodan_errors", []))
    n_errors = len(state.get("nmap_errors", []))

    print(f"\n{'='*60}")
    print(f"  ENGINE COMPLETE")
    print(f"{'='*60}")
    print(f"  Query:           {state.get('user_query', 'N/A')}")
    print(f"  Queries gen:     {len(state.get('generated_queries', []))}")
    print(f"  IPs discovered:  {total_ips}")
    print(f"  Shodan scraped:  {shodan_count} ({s_errors} errors)")
    print(f"  Nmap scanned:    {nmap_count} ({n_errors} errors)")
    print(f"{'='*60}")

    return {
        "current_step": "complete",
        "status_message": (
            f"Complete: {total_ips} IPs, "
            f"{shodan_count} Shodan + {nmap_count} Nmap results, "
            f"{s_errors + n_errors} errors"
        ),
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }


# ═════════════════════════════════════════════════════════════════════════════
# Graph Construction
# ═════════════════════════════════════════════════════════════════════════════

def _route_after_ip_discovery(state: EngineState) -> str:
    """Conditional edge: after IP discovery, check if we have any IPs."""
    if state.get("discovered_ips"):
        return "process_all_ips"
    return "summary"


def build_graph():
    """Build the LangGraph state graph for the query-input engine."""
    workflow = StateGraph(EngineState)

    # Add nodes
    workflow.add_node("query_gen", query_gen_node)
    workflow.add_node("get_ips", get_ip_node)
    workflow.add_node("process_all_ips", process_all_ips_node)
    workflow.add_node("summary", summary_node)

    # Wire edges: query_gen → get_ips → process_all_ips → summary
    workflow.set_entry_point("query_gen")
    workflow.add_edge("query_gen", "get_ips")
    workflow.add_conditional_edges("get_ips", _route_after_ip_discovery)
    workflow.add_edge("process_all_ips", "summary")
    workflow.add_edge("summary", END)

    return workflow


# ═════════════════════════════════════════════════════════════════════════════
# Engine Runner
# ═════════════════════════════════════════════════════════════════════════════

def run_engine(
    user_query: str,
    thread_id: str = None,
    query_count: int = 10,
) -> dict:
    """
    Run the full CTI engine pipeline.

    Args:
        user_query:   Natural language description of what to find.
        thread_id:    Unique ID for this run (for checkpoint resume).
                      If None, generates one from timestamp.
        query_count:  Number of Shodan queries to generate.

    Returns:
        Final EngineState dict with all results.
    """
    if not thread_id:
        thread_id = f"query_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    print(f"\n{'='*60}")
    print(f"  CTI ENGINE — Query Input Pipeline")
    print(f"  Thread ID: {thread_id}")
    print(f"{'='*60}")

    # Build graph with PostgreSQL checkpointing
    workflow = build_graph()

    with PostgresSaver.from_conn_string(PG_CONN_STRING) as checkpointer:
        checkpointer.setup()

        graph = workflow.compile(checkpointer=checkpointer)

        config = {"configurable": {"thread_id": thread_id}}

        # Check if there's an existing checkpoint to resume from
        existing_state = graph.get_state(config)
        if existing_state and existing_state.values:
            step = existing_state.values.get("current_step", "")
            if step == "complete":
                print(f"[*] Run '{thread_id}' already completed. Returning cached results.")
                return existing_state.values
            else:
                print(f"[*] Resuming run '{thread_id}' from step: {step}")
                final_state = graph.invoke(None, config)
                return final_state

        # Fresh run
        initial_state = {
            "user_query": user_query,
            "query_count": query_count,
            "generated_queries": [],
            "discovered_ips": [],
            "shodan_results": [],
            "nmap_results": [],
            "shodan_errors": [],
            "nmap_errors": [],
            "current_step": "starting",
            "status_message": "Engine starting...",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": "",
        }

        final_state = graph.invoke(initial_state, config)
        return final_state


def get_engine_status(thread_id: str) -> dict:
    """
    Read the current state of an engine run without invoking it.
    The agent can call this anytime to check progress.
    """
    workflow = build_graph()

    with PostgresSaver.from_conn_string(PG_CONN_STRING) as checkpointer:
        checkpointer.setup()
        graph = workflow.compile(checkpointer=checkpointer)
        config = {"configurable": {"thread_id": thread_id}}

        state = graph.get_state(config)
        if state and state.values:
            return state.values
        return {}


# ═════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═════════════════════════════════════════════════════════════════════════════

def main():
    """
    CLI for the query-input engine.

    Usage:
        python Engine_query_input.py                     # Interactive new run
        python Engine_query_input.py --resume <thread_id> # Resume a crashed run
        python Engine_query_input.py --status <thread_id> # Check run status
    """
    # ── --status: check run status ───────────────────────────────────────
    if len(sys.argv) >= 3 and sys.argv[1] == "--status":
        thread_id = sys.argv[2]
        state = get_engine_status(thread_id)
        if not state:
            print(f"[-] No checkpoint found for thread_id: {thread_id}")
        else:
            print(f"\n{'='*60}")
            print(f"  Engine Status: {thread_id}")
            print(f"{'='*60}")
            print(f"  Step:      {state.get('current_step')}")
            print(f"  Status:    {state.get('status_message')}")
            print(f"  Query:     {state.get('user_query', 'N/A')}")
            print(f"  Queries:   {len(state.get('generated_queries', []))}")
            print(f"  IPs:       {len(state.get('discovered_ips', []))}")
            print(f"  Shodan:    {len(state.get('shodan_results', []))} results")
            print(f"  Nmap:      {len(state.get('nmap_results', []))} results")
            print(f"  Started:   {state.get('started_at', 'N/A')}")
            print(f"  Finished:  {state.get('finished_at') or 'still running'}")
            print(f"{'='*60}")
        return

    # ── --resume: resume a crashed run ───────────────────────────────────
    if len(sys.argv) >= 3 and sys.argv[1] == "--resume":
        thread_id = sys.argv[2]
        print(f"[*] Resuming run: {thread_id}")
        # run_engine with a dummy query — it will load state from checkpoint
        result = run_engine("", thread_id=thread_id)
        print(f"\n\nFinal Status: {result.get('status_message')}")
        return

    # ── Interactive new run ──────────────────────────────────────────────
    print("=" * 60)
    print("  CTI ENGINE — Query Input Pipeline")
    print("=" * 60)

    query = input("\n  Describe what you want to find:\n  > ").strip()
    if not query:
        print("[-] No query provided. Exiting.")
        sys.exit(1)

    count_input = input("  How many Shodan queries? (default 10): ").strip()
    count = int(count_input) if count_input.isdigit() else 10

    thread_input = input("  Thread ID (leave blank for auto): ").strip()
    thread_id = thread_input if thread_input else None

    result = run_engine(query, thread_id=thread_id, query_count=count)

    print(f"\n\nFinal Status: {result.get('status_message')}")


if __name__ == "__main__":
    main()