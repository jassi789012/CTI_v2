"""
CTI Engine — Query Input Pipeline (LangGraph)
===============================================
Full pipeline: Natural language query → Shodan queries → IPs → parallel
data collection (Shodan scraping + Nmap scanning).

State is persisted in PostgreSQL via LangGraph checkpointing. If the engine
crashes mid-run, re-invoke with the same thread_id to resume.
"""

import os
import sys
import threading
import queue
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, TypedDict

from dotenv import load_dotenv
from langgraph.graph import END, StateGraph
from langgraph.checkpoint.postgres import PostgresSaver
from langchain_core.runnables import RunnableConfig

# ─── Setup paths ─────────────────────────────────────────────────────────────
BACKEND_DIR = Path(r"c:\Users\jassi\OneDrive\Documents\CTI_V2\Backend")
sys.path.insert(0, str(BACKEND_DIR / "def_Shodan"))
sys.path.insert(0, str(BACKEND_DIR / "def_nmap"))
sys.path.insert(0, str(BACKEND_DIR / "query_gen"))
sys.path.insert(0, str(BACKEND_DIR / "cve_maper"))

from query_gen_ai import generate_queries_gen
from get_ip import get_ip_query_ip_gen
from get_ip_info import get_ip_info_gen
from nmap_scanner import nmap_scan_ips_gen
from db_manager import DBManager
from cve_extractor import extract_cves_gen
from cve_mapper import fetch_nvd_gen, enrich_gpt_gen
from engine_progress import emit_progress, is_cancelled

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
    # Data State
    query: str
    queries: list[str]
    ips: list[str]
    cve: list[str]
    
    # Logs State
    engine_status: str
    query_genrater: str
    ip_number_fetcher: str
    ip_number_fetcher_done: str
    ip_data_fetcher_shodan: str
    ip_data_fetcher_shodan_done: str
    ip_data_fetcher_nmap: str
    ip_data_fetcher_nmap_done: str
    cve_extractor: str
    cve_extractor_done: str
    cve_mapper_nvd: str
    cve_mapper_nvd_done: str
    cve_mapper_gpt: str
    cve_mapper_gpt_done: str


# ═════════════════════════════════════════════════════════════════════════════
# Node Functions
# ═════════════════════════════════════════════════════════════════════════════

def query_gen_node(state: EngineState) -> dict:
    user_query = state["query"]
    queries = []
    
    emit_progress("query_gen", "running", "Starting query generation")
    for progress in generate_queries_gen(user_query):
        if is_cancelled():
            raise InterruptedError("Engine cancelled by user")
        status = progress.get("query_genrater", "running")
        queries = progress.get("queries", queries)
        emit_progress("query_gen", "running", f"{len(queries)} queries generated")
        print(f"\r[Query Gen] Status: {status} | Generated: {len(queries)}", end="")
    print()

    emit_progress("query_gen", "done", f"{len(queries)} queries")
    return {
        "queries": queries,
        "query_genrater": "completed",
    }


def get_ip_node(state: EngineState) -> dict:
    queries = state.get("queries", [])
    ips = []
    
    emit_progress("get_ips", "running", "Starting IP discovery")
    for progress in get_ip_query_ip_gen(queries):
        if is_cancelled():
            raise InterruptedError("Engine cancelled by user")
        status = progress.get("ip_number_fetcher", "running")
        done = progress.get("ip_number_fetcher_done", "0/0")
        ips = progress.get("ips", ips)
        emit_progress("get_ips", "running", f"{done} queries | {len(ips)} IPs found")
        print(f"\r[IP Fetch] Status: {status} | Progress: {done} | IPs: {len(ips)}", end="")
    print()
    
    emit_progress("get_ips", "done", f"{len(ips)} IPs discovered")
    return {
        "ips": ips,
        "ip_number_fetcher": "completed",
        "ip_number_fetcher_done": f"{len(queries)}/{len(queries)}" if queries else "0/0"
    }


def process_all_ips_node(state: EngineState, config: RunnableConfig) -> dict:
    ips = state.get("ips", [])
    thread_id = config.get("configurable", {}).get("thread_id")
    
    if not ips:
        emit_progress("process_all_ips", "done", "No IPs to process")
        return {
            "ip_data_fetcher_shodan": "completed",
            "ip_data_fetcher_shodan_done": "0/0",
            "ip_data_fetcher_nmap": "completed",
            "ip_data_fetcher_nmap_done": "0/0",
        }
        
    q = queue.Queue()
    
    def run_shodan():
        for progress in get_ip_info_gen(ips):
            q.put(progress)
        q.put(None)
        
    def run_nmap():
        for progress in nmap_scan_ips_gen(ips, engine_thread_id=thread_id):
            q.put(progress)
        q.put(None)
        
    t1 = threading.Thread(target=run_shodan)
    t2 = threading.Thread(target=run_nmap)
    t1.start()
    t2.start()
    
    finished_threads = 0
    final_shodan_done = "0/0"
    final_nmap_done = "0/0"
    
    emit_progress("process_all_ips", "running", f"Shodan: 0/{len(ips)} | Nmap: 0/{len(ips)}")
    
    while finished_threads < 2:
        if is_cancelled():
            raise InterruptedError("Engine cancelled by user")
            
        try:
            item = q.get(timeout=1.0)
        except queue.Empty:
            continue
            
        if item is None:
            finished_threads += 1
            continue
            
        if "ip_data_fetcher_shodan" in item:
            status = item["ip_data_fetcher_shodan"]
            final_shodan_done = item["ip_data_fetcher_shodan_done"]
            emit_progress("process_all_ips", "running", f"Shodan: {final_shodan_done} | Nmap: {final_nmap_done}")
            print(f"\r[Shodan] {status} {final_shodan_done} | [Nmap] {final_nmap_done}", end="")
            
        elif "ip_data_fetcher_nmap" in item:
            status = item["ip_data_fetcher_nmap"]
            final_nmap_done = item["ip_data_fetcher_nmap_done"]
            emit_progress("process_all_ips", "running", f"Shodan: {final_shodan_done} | Nmap: {final_nmap_done}")
            print(f"\r[Shodan] {final_shodan_done} | [Nmap] {status} {final_nmap_done}", end="")

    t1.join()
    t2.join()
    print()
    
    emit_progress("process_all_ips", "done", f"{len(ips)}/{len(ips)} IPs scanned")
    return {
        "ip_data_fetcher_shodan": "completed",
        "ip_data_fetcher_shodan_done": f"{len(ips)}/{len(ips)}",
        "ip_data_fetcher_nmap": "completed",
        "ip_data_fetcher_nmap_done": f"{len(ips)}/{len(ips)}",
    }


def extract_cves_node(state: EngineState) -> dict:
    ips = state.get("ips", [])
    cves = []
    
    emit_progress("extract_cves", "running", "Starting CVE extraction")
    for progress in extract_cves_gen(ips):
        if is_cancelled():
            raise InterruptedError("Engine cancelled by user")
        status = progress.get("cve_extractor", "running")
        done = progress.get("cve_extractor_done", "0/0")
        cves = progress.get("cves", cves)
        emit_progress("extract_cves", "running", f"{done} | {len(cves)} CVEs found")
        print(f"\r[CVE Extractor] Status: {status} | Progress: {done} | CVEs: {len(cves)}", end="")
    print()
    print()
    
    emit_progress("extract_cves", "done", f"{len(cves)} CVEs extracted")
    return {
        "cve": cves,
        "cve_extractor": "completed",
        "cve_extractor_done": f"{len(ips)}/{len(ips)}" if ips else "0/0"
    }


def cve_mapper_node(state: EngineState) -> dict:
    cves = state.get("cve", [])
    
    nvd_results = {}
    emit_progress("cve_mapper", "running", "Fetching NVD data")
    for progress in fetch_nvd_gen(cves):
        if is_cancelled():
            raise InterruptedError("Engine cancelled by user")
        status = progress.get("nvd_data_fetcher", "running")
        done = progress.get("nvd_data_fetcher_done", "0/0")
        nvd_results = progress.get("nvd_results", nvd_results)
        emit_progress("cve_mapper", "running", f"NVD: {done}")
        print(f"\r[Mapper NVD] Status: {status} | Progress: {done}", end="")
    print()
        
    db = DBManager()
    db.init_tables()
    cves_needing_analysis = []
    for cve_id in nvd_results:
        if not db.check_cve_analysis_exists(cve_id):
            cves_needing_analysis.append(cve_id)
    db.close()
    
    emit_progress("cve_mapper", "running", f"GPT enriching {len(cves_needing_analysis)} CVEs")
    for progress in enrich_gpt_gen(cves_needing_analysis, nvd_results):
        if is_cancelled():
            raise InterruptedError("Engine cancelled by user")
        status = progress.get("cve_mapper_gpt", "running")
        done = progress.get("cve_mapper_gpt_done", "0/0")
        emit_progress("cve_mapper", "running", f"GPT: {done}")
        print(f"\r[Mapper GPT] Status: {status} | Progress: {done}", end="")
    print()
    
    emit_progress("cve_mapper", "done", f"{len(cves)} CVEs mapped")
    return {
        "cve_mapper_nvd": "completed",
        "cve_mapper_nvd_done": f"{len(cves)}/{len(cves)}" if cves else "0/0",
        "cve_mapper_gpt": "completed",
        "cve_mapper_gpt_done": f"{len(cves_needing_analysis)}/{len(cves_needing_analysis)}" if cves_needing_analysis else "0/0"
    }


def summary_node(state: EngineState) -> dict:
    emit_progress("summary", "running", "Generating summary")
    print(f"\n{'='*60}")
    print(f"  ENGINE COMPLETE")
    print(f"{'='*60}")
    print(f"  Query:           {state.get('query', 'N/A')}")
    print(f"  Queries gen:     {len(state.get('queries', []))}")
    print(f"  IPs discovered:  {len(state.get('ips', []))}")
    print(f"  CVEs extracted:  {len(state.get('cve', []))}")
    print(f"{'='*60}")

    emit_progress("summary", "done", "Engine complete")
    return {
        "engine_status": "complete"
    }


# ═════════════════════════════════════════════════════════════════════════════
# Graph Construction
# ═════════════════════════════════════════════════════════════════════════════

def _route_after_ip_discovery(state: EngineState) -> str:
    if state.get("ips"):
        return "process_all_ips"
    return "summary"

def build_graph():
    workflow = StateGraph(EngineState)

    workflow.add_node("query_gen", query_gen_node)
    workflow.add_node("get_ips", get_ip_node)
    workflow.add_node("process_all_ips", process_all_ips_node)
    workflow.add_node("extract_cves", extract_cves_node)
    workflow.add_node("cve_mapper", cve_mapper_node)
    workflow.add_node("summary", summary_node)

    workflow.set_entry_point("query_gen")
    workflow.add_edge("query_gen", "get_ips")
    workflow.add_conditional_edges("get_ips", _route_after_ip_discovery)
    workflow.add_edge("process_all_ips", "extract_cves")
    workflow.add_edge("extract_cves", "cve_mapper")
    workflow.add_edge("cve_mapper", "summary")
    workflow.add_edge("summary", END)

    return workflow


# ═════════════════════════════════════════════════════════════════════════════
# Engine Runner
# ═════════════════════════════════════════════════════════════════════════════

def run_engine(
    user_query: str,
    thread_id: str = None,
) -> dict:
    if not thread_id:
        thread_id = f"query_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    print(f"\n{'='*60}")
    print(f"  CTI ENGINE — Query Input Pipeline")
    print(f"  Thread ID: {thread_id}")
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
            "query": user_query,
            "queries": [],
            "ips": [],
            "cve": [],
            "engine_status": "running",
            "query_genrater": "running",
            "ip_number_fetcher": "waiting for queries",
            "ip_number_fetcher_done": "0/0",
            "ip_data_fetcher_shodan": "waiting for ips",
            "ip_data_fetcher_shodan_done": "0/0",
            "ip_data_fetcher_nmap": "waiting for ips",
            "ip_data_fetcher_nmap_done": "0/0",
            "cve_extractor": "waiting for ips",
            "cve_extractor_done": "0/0",
            "cve_mapper_nvd": "waiting for cves",
            "cve_mapper_nvd_done": "0/0",
            "cve_mapper_gpt": "waiting for cves",
            "cve_mapper_gpt_done": "0/0",
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
# Thread Discovery & CLI
# ═════════════════════════════════════════════════════════════════════════════

def _list_thread_ids(prefix: str = "") -> list[str]:
    import psycopg2
    try:
        conn = psycopg2.connect(PG_CONN_STRING)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT thread_id FROM checkpoints
                WHERE thread_id LIKE %s
                ORDER BY thread_id DESC
            """, (f"{prefix}%",))
            ids = [row[0] for row in cur.fetchall()]
        conn.close()
        return ids
    except Exception:
        return []

def _get_threads_with_state(prefix: str, graph) -> list[dict]:
    thread_ids = _list_thread_ids(prefix)
    threads = []
    for tid in thread_ids:
        try:
            state = graph.get_state({"configurable": {"thread_id": tid}})
            if state and state.values:
                threads.append({
                    "thread_id": tid,
                    "query": state.values.get("query", ""),
                    "ips": len(state.values.get("ips") or []),
                    "status": state.values.get("engine_status", "unknown"),
                    "cves": len(state.values.get("cve") or []),
                })
        except Exception:
            continue
    return threads

def main():
    print(f"\n{'=' * 60}")
    print(f"  CTI ENGINE — Query Input Pipeline")
    print(f"{'=' * 60}")

    workflow = build_graph()
    threads = []
    try:
        with PostgresSaver.from_conn_string(PG_CONN_STRING) as checkpointer:
            checkpointer.setup()
            graph = workflow.compile(checkpointer=checkpointer)
            threads = _get_threads_with_state("query_", graph)
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
                query_display = t["query"].strip() if t["query"].strip() else "(no query text)"
                if len(query_display) > 60:
                    query_display = query_display[:57] + "..."
                print(f"    [{i}] Query : \"{query_display}\"")
                print(f"        Thread: {t['thread_id']}")
                print(f"        Status: [{t['status']}] | Discovered IPs: {t['ips']} | CVEs: {t['cves']}\n")

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
                    print(f"  Discovered IPs ({len(state.get('ips', []))}): {state.get('ips', [])}")
                    print(f"  Extracted CVEs ({len(state.get('cve', []))}): {state.get('cve', [])}")
                    return
                print(f"\n  [*] Resuming past thread: {tid}")
                run_engine("", thread_id=tid)
                return

    print(f"\n{'─' * 60}")
    print("  NEW QUERY RUN")
    print(f"{'─' * 60}")
    query = input("\n  Describe what you want to find:\n  > ").strip()
    if not query:
        print("[-] No query provided. Exiting.")
        sys.exit(1)

    run_engine(query)


if __name__ == "__main__":
    main()