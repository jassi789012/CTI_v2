"""
CTI Engine — CVE Input Pipeline (LangGraph)
=============================================
Partial pipeline: Takes a list of CVE IDs directly and runs
multi-source OSINT enrichment (NVD, CVE.org, EPSS, CISA KEV,
OSV.dev, Exploit-DB, CWE, MITRE ATT&CK) in parallel.

Skips query generation, IP discovery, Shodan/Nmap scanning, and
CVE extraction — use this when you already have CVE numbers.
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
# Init Node (validates and deduplicates the CVE list)
# ═════════════════════════════════════════════════════════════════════════════

def init_cves_node(state: EngineState) -> dict:
    """Initialize state from the provided CVE list."""
    cves = state.get("cve", [])

    # Deduplicate while preserving order, normalize to uppercase
    seen = set()
    unique_cves = []
    for cve_id in cves:
        cve_id = str(cve_id).strip().upper()
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            unique_cves.append(cve_id)

    emit_progress("init_cves", "running", f"Loading {len(unique_cves)} CVEs")
    print(f"\n{'='*60}")
    print(f"  NODE: Initialize CVEs")
    print(f"  CVEs provided: {len(unique_cves)}")
    print(f"{'='*60}")

    if not unique_cves:
        emit_progress("init_cves", "done", "No CVEs provided")
        return {
            "cve": [],
            "engine_status": "error",
        }

    emit_progress("init_cves", "done", f"{len(unique_cves)} CVEs loaded")
    return {
        "cve": unique_cves,
        "engine_status": "running",
    }


# ═════════════════════════════════════════════════════════════════════════════
# Graph Construction
# ═════════════════════════════════════════════════════════════════════════════

def _route_after_init(state: EngineState) -> str:
    if state.get("cve"):
        return "cve_mapper"
    return "summary"


def build_graph():
    workflow = StateGraph(EngineState)

    workflow.add_node("init_cves", init_cves_node)
    workflow.add_node("cve_mapper", cve_mapper_node)
    workflow.add_node("summary", summary_node)

    workflow.set_entry_point("init_cves")
    workflow.add_conditional_edges("init_cves", _route_after_init)
    workflow.add_edge("cve_mapper", "summary")
    workflow.add_edge("summary", END)

    return workflow


# ═════════════════════════════════════════════════════════════════════════════
# Engine Runner
# ═════════════════════════════════════════════════════════════════════════════

def run_engine(
    cves: list[str],
    thread_id: str = None,
) -> dict:
    if not thread_id:
        thread_id = f"cves_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    print(f"\n{'='*60}")
    print(f"  CTI ENGINE — CVE Input Pipeline")
    print(f"  Thread ID: {thread_id}")
    print(f"  CVEs: {len(cves)}")
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
            "ips": [],
            "cve": cves,
            "engine_status": "running",
            "query_genrater": "skipped",
            "ip_number_fetcher": "skipped",
            "ip_number_fetcher_done": "0/0",
            "ip_data_fetcher_shodan": "skipped",
            "ip_data_fetcher_shodan_done": "0/0",
            "ip_data_fetcher_nmap": "skipped",
            "ip_data_fetcher_nmap_done": "0/0",
            "cve_extractor": "skipped",
            "cve_extractor_done": "0/0",
            "cve_enrichment": "running",
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
    print(f"  CTI ENGINE — CVE Input Pipeline")
    print(f"{'=' * 60}")

    workflow = build_graph()
    threads = []
    try:
        with PostgresSaver.from_conn_string(PG_CONN_STRING) as checkpointer:
            checkpointer.setup()
            graph = workflow.compile(checkpointer=checkpointer)
            threads = _get_threads_with_state("cves_", graph)
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
                cve_count = t["cves"]
                print(f"    [{i}] CVEs: {cve_count}")
                print(f"        Thread: {t['thread_id']}")
                print(f"        Status: [{t['status']}]\n")

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
                    print(f"  CVEs mapped ({len(state.get('cve', []))}): {state.get('cve', [])}")
                    return
                print(f"\n  [*] Resuming past thread: {tid}")
                run_engine([], thread_id=tid)
                return

    print(f"\n{'─' * 60}")
    print("  NEW CVE MAPPING RUN")
    print(f"{'─' * 60}")
    raw = input("\n  Enter CVE IDs (space or comma separated):\n  > ").strip()
    if not raw:
        print("[-] No CVEs provided. Exiting.")
        sys.exit(1)

    target_cves = [cve.strip().upper() for cve in raw.replace(",", " ").split()
                   if cve.strip()]

    run_engine(target_cves)


if __name__ == "__main__":
    main()
