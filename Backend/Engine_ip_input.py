"""
CTI Engine — IP Input Pipeline (LangGraph)
===========================================
Partial pipeline: Takes a list of IPs directly and runs parallel
data collection (Shodan scraping + Nmap scanning).

Skips query generation and IP discovery — use this when you already
have the target IPs.
"""

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from langgraph.graph import END, StateGraph
from langgraph.checkpoint.postgres import PostgresSaver

# ─── Reuse from the query-input engine ───────────────────────────────────────
BACKEND_DIR = Path(r"c:\Users\jassi\OneDrive\Documents\CTI_V2\Backend")
sys.path.insert(0, str(BACKEND_DIR))

from Engine_query_input import (
    EngineState,
    process_all_ips_node,
    extract_cves_node,
    cve_mapper_node,
    summary_node,
    _list_thread_ids,
    _get_threads_with_state,
)
from engine_progress import emit_progress

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
    ips = state.get("ips", [])

    # Deduplicate while preserving order
    seen = set()
    unique_ips = []
    for ip in ips:
        ip = str(ip).strip()
        if ip and ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)

    emit_progress("init_ips", "running", f"Loading {len(unique_ips)} IPs")
    print(f"\n{'='*60}")
    print(f"  NODE: Initialize IPs")
    print(f"  IPs provided: {len(unique_ips)}")
    print(f"{'='*60}")

    if not unique_ips:
        emit_progress("init_ips", "done", "No IPs provided")
        return {
            "ips": [],
            "engine_status": "error",
        }

    emit_progress("init_ips", "done", f"{len(unique_ips)} IPs loaded")
    return {
        "ips": unique_ips,
        "engine_status": "running",
    }


# ═════════════════════════════════════════════════════════════════════════════
# Graph Construction
# ═════════════════════════════════════════════════════════════════════════════

def _route_after_init(state: EngineState) -> str:
    if state.get("ips"):
        return "process_all_ips"
    return "summary"


def build_graph():
    workflow = StateGraph(EngineState)

    workflow.add_node("init_ips", init_ips_node)
    workflow.add_node("process_all_ips", process_all_ips_node)
    workflow.add_node("extract_cves", extract_cves_node)
    workflow.add_node("cve_mapper", cve_mapper_node)
    workflow.add_node("summary", summary_node)

    workflow.set_entry_point("init_ips")
    workflow.add_conditional_edges("init_ips", _route_after_init)
    workflow.add_edge("process_all_ips", "extract_cves")
    workflow.add_edge("extract_cves", "cve_mapper")
    workflow.add_edge("cve_mapper", "summary")
    workflow.add_edge("summary", END)

    return workflow


# ═════════════════════════════════════════════════════════════════════════════
# Engine Runner
# ═════════════════════════════════════════════════════════════════════════════

def run_engine(
    ips: list[str],
    thread_id: str = None,
) -> dict:
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

        existing_state = graph.get_state(config)
        if existing_state and existing_state.values:
            if existing_state.values.get("engine_status") == "complete":
                print(f"[*] Run '{thread_id}' already completed.")
                return existing_state.values
            else:
                print(f"[*] Resuming run '{thread_id}'")
                return graph.invoke(None, config)

        initial_state = {
            "query": "",
            "queries": [],
            "ips": ips,
            "cve": [],
            "engine_status": "running",
            "query_genrater": "skipped",
            "ip_number_fetcher": "skipped",
            "ip_number_fetcher_done": "0/0",
            "ip_data_fetcher_shodan": "waiting for ips",
            "ip_data_fetcher_shodan_done": "0/0",
            "ip_data_fetcher_nmap": "waiting for ips",
            "ip_data_fetcher_nmap_done": "0/0",
            "cve_extractor": "waiting for ips",
            "cve_extractor_done": "0/0",
            "cve_enrichment": "waiting for cves",
            "cve_enrichment_done": "0/0",
        }

        return graph.invoke(initial_state, config)

def get_engine_status(thread_id: str) -> dict:
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
    print(f"\n{'=' * 60}")
    print(f"  CTI ENGINE — IP Input Pipeline")
    print(f"{'=' * 60}")

    workflow = build_graph()
    threads = []
    try:
        with PostgresSaver.from_conn_string(PG_CONN_STRING) as checkpointer:
            checkpointer.setup()
            graph = workflow.compile(checkpointer=checkpointer)
            threads = _get_threads_with_state("ips_", graph)
    except Exception:
        pass

    chosen_thread = None

    if threads:
        print(f"\n  [*] Found {len(threads)} past thread(s).")
        while True:
            ans = input("  Do you want to run any past thread? (y/n): ").strip().lower()
            if ans in ("y", "yes", "n", "no"):
                break
            print("  Please enter 'y' or 'n'.")

        if ans in ("y", "yes"):
            print(f"\n  Available past threads:\n")
            for i, t in enumerate(threads, 1):
                ips_count = t["ips"]
                print(f"    [{i}] IPs: {ips_count}")
                print(f"        Thread: {t['thread_id']}")
                print(f"        Status: [{t['status']}] | CVEs: {t['cves']}\n")

            while True:
                choice = input(f"  Select a thread to run (1-{len(threads)}, or 0 to start a new run): ").strip()
                if choice == "0":
                    break
                if choice.isdigit() and 1 <= int(choice) <= len(threads):
                    chosen_thread = threads[int(choice) - 1]
                    break
                print(f"  Invalid choice. Enter 1 to {len(threads)} (or 0 for new run).")

            if chosen_thread:
                tid = chosen_thread["thread_id"]
                if chosen_thread["status"] == "complete":
                    print(f"\n  [*] Thread '{tid}' already completed.")
                    state = get_engine_status(tid)
                    print(f"  Target IPs ({len(state.get('ips', []))}): {state.get('ips', [])}")
                    print(f"  Extracted CVEs ({len(state.get('cve', []))}): {state.get('cve', [])}")
                    return
                print(f"\n  [*] Resuming past thread: {tid}")
                run_engine([], thread_id=tid)
                return

    print(f"\n{'─' * 60}")
    print("  NEW IP SCAN RUN")
    print(f"{'─' * 60}")
    raw = input("\n  Enter IP addresses (space or comma separated):\n  > ").strip()
    if not raw:
        print("[-] No IPs provided. Exiting.")
        sys.exit(1)

    target_ips = [ip.strip() for ip in raw.replace(",", " ").split()
                  if ip.strip()]

    run_engine(target_ips)


if __name__ == "__main__":
    main()
