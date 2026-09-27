"""
CTI Engine — IP Input Pipeline (LangGraph)
============================================
Partial pipeline: Takes a list of IPs directly and runs parallel
data collection (Shodan scraping + Nmap scanning).

Skips query generation and IP discovery — use this when you already
have the target IPs.

Usage:
    from Engine_ip_input import run_engine
    result = run_engine(["1.2.3.4", "5.6.7.8"], thread_id="ips_001")
"""

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from langgraph.graph import END, StateGraph
from langgraph.checkpoint.postgres import PostgresSaver

# ─── Reuse from the query-input engine ───────────────────────────────────────
BACKEND_DIR = Path(__file__).parent
sys.path.insert(0, str(BACKEND_DIR))

from Engine_query_input import (
    EngineState,
    process_all_ips_node,
    summary_node,
)

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
# Init Node (replaces query_gen + get_ip for IP-input mode)
# ═════════════════════════════════════════════════════════════════════════════

def init_ips_node(state: EngineState) -> dict:
    """Initialize state from the provided IP list."""
    ips = state.get("discovered_ips", [])

    # Deduplicate while preserving order
    seen = set()
    unique_ips = []
    for ip in ips:
        ip = str(ip).strip()
        if ip and ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)

    print(f"\n{'='*60}")
    print(f"  NODE: Initialize IPs")
    print(f"  IPs provided: {len(unique_ips)}")
    print(f"{'='*60}")

    if not unique_ips:
        return {
            "discovered_ips": [],
            "current_step": "error",
            "status_message": "No valid IPs provided",
        }

    return {
        "discovered_ips": unique_ips,
        "current_step": "ips_initialized",
        "status_message": f"Ready to process {len(unique_ips)} IPs",
    }


# ═════════════════════════════════════════════════════════════════════════════
# Graph Construction
# ═════════════════════════════════════════════════════════════════════════════

def _route_after_init(state: EngineState) -> str:
    """Conditional edge: after init, check if we have IPs."""
    if state.get("discovered_ips"):
        return "process_all_ips"
    return "summary"


def build_graph():
    """Build the LangGraph state graph for the IP-input engine."""
    workflow = StateGraph(EngineState)

    # Add nodes (reuses process + summary from query-input engine)
    workflow.add_node("init_ips", init_ips_node)
    workflow.add_node("process_all_ips", process_all_ips_node)
    workflow.add_node("summary", summary_node)

    # Wire edges: init_ips → process_all_ips → summary
    workflow.set_entry_point("init_ips")
    workflow.add_conditional_edges("init_ips", _route_after_init)
    workflow.add_edge("process_all_ips", "summary")
    workflow.add_edge("summary", END)

    return workflow


# ═════════════════════════════════════════════════════════════════════════════
# Engine Runner
# ═════════════════════════════════════════════════════════════════════════════

def run_engine(
    ips: list[str],
    thread_id: str = None,
) -> dict:
    """
    Run the IP-input CTI engine pipeline.

    Args:
        ips:          List of IP addresses to process.
        thread_id:    Unique ID for this run (for checkpoint resume).

    Returns:
        Final EngineState dict with all results.
    """
    if not thread_id:
        thread_id = f"ips_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    print(f"\n{'='*60}")
    print(f"  CTI ENGINE — IP Input Pipeline")
    print(f"  Thread ID: {thread_id}")
    print(f"  IPs: {len(ips)}")
    print(f"{'='*60}")

    workflow = build_graph()

    with PostgresSaver.from_conn_string(PG_CONN_STRING) as checkpointer:
        checkpointer.setup()
        graph = workflow.compile(checkpointer=checkpointer)
        config = {"configurable": {"thread_id": thread_id}}

        # Check for existing checkpoint
        existing_state = graph.get_state(config)
        if existing_state and existing_state.values:
            step = existing_state.values.get("current_step", "")
            if step == "complete":
                print(f"[*] Run '{thread_id}' already completed.")
                return existing_state.values
            else:
                print(f"[*] Resuming run '{thread_id}' from step: {step}")
                final_state = graph.invoke(None, config)
                return final_state

        # Fresh run
        initial_state = {
            "user_query": "",
            "query_count": 0,
            "generated_queries": [],
            "discovered_ips": ips,
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
    """Read the current state of an engine run without invoking it."""
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
    """CLI — pass IP addresses as arguments."""
    if len(sys.argv) < 2:
        print("Usage: python Engine_ip_input.py <ip1> [ip2] [ip3] ...")
        sys.exit(1)

    target_ips = sys.argv[1:]

    thread_input = input("  Thread ID (leave blank for auto): ").strip()
    thread_id = thread_input if thread_input else None

    result = run_engine(target_ips, thread_id=thread_id)

    print(f"\n\nFinal Status: {result.get('status_message')}")


if __name__ == "__main__":
    main()
