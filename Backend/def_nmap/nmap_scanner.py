"""
CTI_V2 — Nmap Scanner Module
=============================
Scans a list of IPs with Nmap (via python-nmap SDK) and stores all results
in PostgreSQL.

Usage:
    from nmap_scanner import nmap_scan_ips

    results = nmap_scan_ips(["1.2.3.4", "5.6.7.8"])

Or run directly:
    python nmap_scanner.py 1.2.3.4 5.6.7.8

Requirements:
    - Nmap installed and in PATH (https://nmap.org/download.html)
    - python-nmap (`uv add python-nmap`)
    - Admin/root privileges for SYN scan (-sS) and OS detection (-O)
"""

import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import nmap

# Add Backend/ to path so we can import db_manager
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from db_manager import DBManager


# ═════════════════════════════════════════════════════════════════════════════
# Default Scan Arguments
# ═════════════════════════════════════════════════════════════════════════════

# Comprehensive scan: SYN + versions + OS + useful scripts
DEFAULT_SCAN_ARGS = (
    "-sS "                     # TCP SYN scan (fast, stealthy)
    "-sV "                     # Service/version detection
    "-O "                      # OS detection
    "--script default,vuln,ssl-enum-ciphers,http-title,http-headers,banner "
    "-T4 "                     # Aggressive timing
    "-p- "        # Top 1000 ports
    "--open "                  # Only show open ports
    "--reason"                 # Show reason port is open
)


# ═════════════════════════════════════════════════════════════════════════════
# Parse Nmap Results → Structured Dict
# ═════════════════════════════════════════════════════════════════════════════

def parse_scan_result(nm: nmap.PortScanner, host: str) -> dict:
    """
    Convert python-nmap's result for a single host into a structured dict
    matching the shape expected by db_manager.save_nmap_scan().

    Returns:
        {
            "ip": "1.2.3.4",
            "general_info": { "OS": ..., "hostnames": [...], ... },
            "open_ports": [22, 80, 443],
            "port_banners": [ { port, service, version, cve_details, ... } ],
            "os_detection": [ { "name": ..., "accuracy": ... } ],
            "scan_info": { "command_line": ..., "elapsed": ... },
            "scraped_at": "2026-09-24T..."
        }
    """
    host_data = nm[host]

    # ─── OS Detection ────────────────────────────────────────────────────
    os_matches = []
    best_os = None
    for osmatch in host_data.get("osmatch", []):
        os_entry = {
            "name": osmatch.get("name", ""),
            "accuracy": int(osmatch.get("accuracy", 0)),
            "os_classes": [],
        }
        for osclass in osmatch.get("osclass", []):
            os_entry["os_classes"].append({
                "type": osclass.get("type", ""),
                "vendor": osclass.get("vendor", ""),
                "os_family": osclass.get("osfamily", ""),
                "os_gen": osclass.get("osgen", ""),
                "accuracy": int(osclass.get("accuracy", 0)),
            })
        os_matches.append(os_entry)

    if os_matches:
        best_os = os_matches[0]["name"]

    # ─── Hostnames ───────────────────────────────────────────────────────
    hostnames = []
    for hn in host_data.get("hostnames", []):
        if hn.get("name"):
            hostnames.append({
                "name": hn.get("name", ""),
                "type": hn.get("type", ""),
            })

    # ─── Host status ─────────────────────────────────────────────────────
    host_state = host_data.get("status", {}).get("state", "")
    host_reason = host_data.get("status", {}).get("reason", "")

    # ─── MAC Address ─────────────────────────────────────────────────────
    mac_address = None
    mac_vendor = None
    for addr in host_data.get("addresses", {}).values() if isinstance(host_data.get("addresses"), dict) else []:
        pass  # python-nmap stores addresses differently
    # python-nmap stores MAC in vendor key or addresses
    if "mac" in host_data.get("addresses", {}):
        mac_address = host_data["addresses"]["mac"]
    vendor_dict = host_data.get("vendor", {})
    if vendor_dict and mac_address:
        mac_vendor = vendor_dict.get(mac_address, "")

    # ─── Uptime ──────────────────────────────────────────────────────────
    uptime = None
    if host_data.get("uptime"):
        uptime = {
            "seconds": host_data["uptime"].get("seconds", ""),
            "lastboot": host_data["uptime"].get("lastboot", ""),
        }

    # ─── TCP Sequence ────────────────────────────────────────────────────
    tcp_sequence = None
    if host_data.get("tcp_sequence"):
        tcp_sequence = host_data["tcp_sequence"]

    # ─── Ports ───────────────────────────────────────────────────────────
    open_ports = []
    port_banners = []

    for proto in host_data.all_protocols():
        port_list = sorted(host_data[proto].keys())
        for port_num in port_list:
            port_info = host_data[proto][port_num]

            # Skip if not open
            state = port_info.get("state", "")
            if state not in ("open", "open|filtered", "filtered"):
                continue

            open_ports.append(port_num)

            # Build version string
            product = port_info.get("product", "")
            version = port_info.get("version", "")
            extrainfo = port_info.get("extrainfo", "")
            version_parts = []
            if product:
                version_parts.append(product)
            if version:
                version_parts.append(version)
            if extrainfo:
                version_parts.append(f"({extrainfo})")
            version_str = " ".join(version_parts) if version_parts else None

            # Scripts output
            scripts = port_info.get("script", {})
            http_title = None
            banner_text = None
            cve_details = []

            for script_id, script_output in scripts.items():
                if script_id == "http-title":
                    http_title = script_output.strip()
                if script_id == "banner":
                    banner_text = script_output.strip()
                # Extract CVEs from vulnerability scripts
                if "vuln" in script_id or "vulners" in script_id:
                    cve_details.extend(_extract_cves(script_id, script_output))

            port_banners.append({
                "port": port_num,
                "protocol": proto,
                "state": state,
                "service": port_info.get("name", ""),
                "version": version_str,
                "http_title": http_title,
                "banner": banner_text,
                "cve_details": cve_details,
                "extra": {
                    "reason": port_info.get("reason", ""),
                    "product": product,
                    "service_version": version,
                    "extra_info": extrainfo,
                    "conf": port_info.get("conf", ""),
                    "cpe": port_info.get("cpe", ""),
                    "scripts": scripts,
                },
            })

    # ─── Scan info ───────────────────────────────────────────────────────
    scan_info = {
        "command_line": nm.command_line(),
        "nmap_version": nm.nmap_version(),
        "scan_method": nm.scaninfo(),
    }

    # ─── general_info (matching db_manager's expected shape) ─────────────
    general_info = {
        "OS": best_os,
        "hostnames": hostnames,
        "host_state": host_state,
        "host_reason": host_reason,
        "mac_address": mac_address,
        "mac_vendor": mac_vendor,
    }

    return {
        "ip": host,
        "general_info": general_info,
        "open_ports": open_ports,
        "port_banners": port_banners,
        "os_detection": os_matches,
        "uptime": uptime,
        "tcp_sequence": tcp_sequence,
        "scan_info": scan_info,
        "scraped_at": datetime.now(timezone.utc).isoformat(),
    }


def _extract_cves(script_id: str, output: str) -> list:
    """Extract CVE entries from Nmap script output."""
    cves = []
    if not output:
        return cves

    cve_pattern = re.compile(
        r'(CVE-\d{4}-\d{4,})\s+'
        r'(\d+\.?\d*)?',
        re.IGNORECASE
    )

    seen = set()
    for match in cve_pattern.finditer(output):
        cve_id = match.group(1).upper()
        if cve_id in seen:
            continue
        seen.add(cve_id)

        cvss_raw = match.group(2)
        cvss = float(cvss_raw) if cvss_raw else None

        cves.append({
            "cve": cve_id,
            "cvss": cvss,
            "cvss_vector": None,
            "summary": f"Detected by Nmap script: {script_id}",
        })

    return cves


# ═════════════════════════════════════════════════════════════════════════════
# Main: Scan IPs and Save to Database
# ═════════════════════════════════════════════════════════════════════════════

def nmap_scan_ips_gen(
    ips: list,
    scan_args: str = None,
    skip_db: bool = False,
    workers: int = 5,
):
    """
    Generator that scans a list of IPs with Nmap and yields structured
    progress dicts for each worker/IP at each step.

    Uses a thread-safe queue so worker threads can post progress that
    the generator yields from the main thread.

    Yields:
        {"status": "init", "total": int, "workers": int}
        {"status": "nmap_check", "success": bool, "error": str|None}
        {"status": "db_init", "success": bool, "error": str|None}
        {"status": "ip_start", "ip": str, "current": int, "total": int, "worker": int}
        {"status": "ip_done", "ip": str, "current": int, "total": int, "worker": int, "ports": int, "cves": int, "os": str}
        {"status": "ip_error", "ip": str, "current": int, "total": int, "worker": int, "error": str}
        {"status": "complete", "total": int, "succeeded": int, "failed": int, "total_ports": int, "total_cves": int, "results": list}
    """
    import queue

    if not ips:
        yield {"status": "complete", "total": 0, "succeeded": 0, "failed": 0,
               "total_ports": 0, "total_cves": 0, "results": []}
        return

    args = scan_args or DEFAULT_SCAN_ARGS
    unique_ips = list(dict.fromkeys(ips))
    total = len(unique_ips)
    num_workers = min(workers, total)

    yield {"status": "init", "total": total, "workers": num_workers}

    # Verify nmap is installed
    try:
        nmap.PortScanner()
        yield {"status": "nmap_check", "success": True, "error": None}
    except nmap.PortScannerError as e:
        yield {"status": "nmap_check", "success": False, "error": str(e)}
        return

    # Connect to database
    db = None
    db_lock = threading.Lock()
    if not skip_db:
        try:
            db = DBManager()
            db.init_tables()
            yield {"status": "db_init", "success": True, "error": None}
        except Exception as e:
            yield {"status": "db_init", "success": False, "error": str(e)}
            # Continue without DB — results still returned

    # ─── Thread-safe progress queue ──────────────────────────────────────
    progress_queue = queue.Queue()

    # Map thread IDs to worker numbers
    thread_worker_map = {}
    worker_counter = [0]
    map_lock = threading.Lock()

    def get_worker_id():
        tid = threading.current_thread().ident
        with map_lock:
            if tid not in thread_worker_map:
                worker_counter[0] += 1
                thread_worker_map[tid] = worker_counter[0]
            return thread_worker_map[tid]

    # ─── Worker function (runs per IP in its own thread) ─────────────────
    def scan_single_ip(ip_index_tuple):
        i, ip = ip_index_tuple
        worker_id = get_worker_id()
        nm = nmap.PortScanner()

        progress_queue.put({
            "status": "ip_start",
            "ip": ip,
            "current": i,
            "total": total,
            "worker": worker_id,
        })

        try:
            nm.scan(hosts=ip, arguments=args)
        except nmap.PortScannerError as e:
            progress_queue.put({
                "status": "ip_error",
                "ip": ip, "current": i, "total": total,
                "worker": worker_id, "error": str(e),
            })
            return {"ip": ip, "error": str(e)}
        except Exception as e:
            progress_queue.put({
                "status": "ip_error",
                "ip": ip, "current": i, "total": total,
                "worker": worker_id, "error": str(e),
            })
            return {"ip": ip, "error": str(e)}

        scanned_hosts = nm.all_hosts()
        if not scanned_hosts:
            progress_queue.put({
                "status": "ip_error",
                "ip": ip, "current": i, "total": total,
                "worker": worker_id, "error": "Host down or no response",
            })
            return {"ip": ip, "error": "Host down or no response"}

        host = scanned_hosts[0]
        try:
            parsed = parse_scan_result(nm, host)
            port_count = len(parsed.get("open_ports", []))
            cve_count = sum(len(p.get("cve_details", [])) for p in parsed.get("port_banners", []))
            os_guess = parsed.get("general_info", {}).get("OS") or "Unknown"

            if db:
                with db_lock:
                    try:
                        db.save_nmap_scan(parsed)
                    except Exception:
                        pass

            progress_queue.put({
                "status": "ip_done",
                "ip": host, "current": i, "total": total,
                "worker": worker_id,
                "ports": port_count, "cves": cve_count, "os": os_guess,
            })
            return parsed

        except Exception as e:
            progress_queue.put({
                "status": "ip_error",
                "ip": host, "current": i, "total": total,
                "worker": worker_id, "error": str(e),
            })
            return {"ip": host, "error": str(e)}

    # ─── Run workers and yield progress ──────────────────────────────────
    indexed_ips = list(enumerate(unique_ips, 1))
    all_results = []

    # Submit all tasks, drain the queue while waiting
    pool = ThreadPoolExecutor(max_workers=num_workers)
    futures = [pool.submit(scan_single_ip, item) for item in indexed_ips]

    # Yield progress as workers report in
    completed = 0
    while completed < len(futures):
        try:
            msg = progress_queue.get(timeout=0.5)
            yield msg
        except queue.Empty:
            pass

        # Check how many futures are done
        newly_done = sum(1 for f in futures if f.done()) - completed
        if newly_done > 0:
            completed += newly_done

    # Drain any remaining messages
    while not progress_queue.empty():
        yield progress_queue.get_nowait()

    # Collect results
    all_results = [f.result() for f in futures]
    pool.shutdown(wait=False)

    # ─── Summary ─────────────────────────────────────────────────────────
    success = [r for r in all_results if "error" not in r]
    failed = [r for r in all_results if "error" in r]
    total_ports = sum(len(r.get("open_ports", [])) for r in success)
    total_cves = sum(
        sum(len(p.get("cve_details", [])) for p in r.get("port_banners", []))
        for r in success
    )

    if db:
        db.close()

    yield {
        "status": "complete",
        "total": total,
        "succeeded": len(success),
        "failed": len(failed),
        "total_ports": total_ports,
        "total_cves": total_cves,
        "results": all_results,
    }


# ─── Convenience wrapper (backward compatible) ──────────────────────────────
def nmap_scan_ips(
    ips: list,
    scan_args: str = None,
    skip_db: bool = False,
    workers: int = 5,
) -> list:
    """
    Non-generator wrapper: scans IPs and returns the results list.
    Consumes nmap_scan_ips_gen() internally, printing progress.
    """
    results = []
    for update in nmap_scan_ips_gen(ips, scan_args, skip_db, workers):
        status = update["status"]
        if status == "init":
            print(f"\n{'='*70}")
            print(f"  Nmap Scanner — {update['total']} target(s), {update['workers']} workers")
            print(f"{'='*70}")
        elif status == "nmap_check":
            if not update["success"]:
                print(f"[-] Nmap not found: {update['error']}")
                print("    Install from: https://nmap.org/download.html")
                return []
        elif status == "db_init":
            if not update["success"]:
                print(f"[-] Could not connect to database: {update['error']}")
        elif status == "ip_start":
            print(f"\n[Worker {update['worker']}] [{update['current']}/{update['total']}] "
                  f"Scanning: {update['ip']}")
        elif status == "ip_done":
            print(f"  [Worker {update['worker']}] {update['ip']}: "
                  f"{update['ports']} open ports, {update['cves']} CVEs, OS: {update['os']}")
        elif status == "ip_error":
            print(f"  [Worker {update['worker']}] {update['ip']}: ERROR — {update['error']}")
        elif status == "complete":
            results = update["results"]
            print(f"\n{'='*70}")
            print(f"  Scan Complete: {update['succeeded']} succeeded, {update['failed']} failed")
            print(f"  Total: {update['total_ports']} open ports, {update['total_cves']} CVEs detected")
            print(f"{'='*70}\n")
    return results


# ═════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nmap_scanner.py <ip1> [ip2] [ip3] ...")
        print("       python nmap_scanner.py 192.168.1.1 10.0.0.1")
        sys.exit(1)

    target_ips = sys.argv[1:]
    results = nmap_scan_ips(target_ips)

    for r in results:
        if "error" in r:
            print(f"  {r['ip']}: ERROR — {r['error']}")
        else:
            ports = r.get("open_ports", [])
            os_name = r.get("general_info", {}).get("OS") or "Unknown"
            print(f"  {r['ip']}: {len(ports)} ports, OS: {os_name}")


