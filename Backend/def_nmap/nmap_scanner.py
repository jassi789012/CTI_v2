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
    "-p- "        
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

# ═════════════════════════════════════════════════════════════════════════════
# Generator Function
# ═════════════════════════════════════════════════════════════════════════════

def nmap_scan_ips_gen(
    ips: list,
    scan_args: str = None,
    workers: int = 5,
):
    """
    Generator that scans a list of IPs with Nmap and stores results in PostgreSQL.

    Yields progress dicts as each IP scan completes:
        {
            "ip_data_fetcher_nmap": "running" | "completed",
            "ip_data_fetcher_nmap_done": "n/m",
        }

    Data goes directly to the database — not returned in the yields.

    Args:
        ips:         List of IP addresses to scan
        scan_args:   Custom Nmap arguments (default: comprehensive scan)
        workers:     Number of parallel Nmap processes (default: 5)
    """
    if not ips:
        print("[-] No IPs provided.")
        yield {
            "ip_data_fetcher_nmap": "completed",
            "ip_data_fetcher_nmap_done": "0/0",
        }
        return

    args = scan_args or DEFAULT_SCAN_ARGS
    unique_ips = list(dict.fromkeys(ips))
    total = len(unique_ips)
    num_workers = min(workers, total)

    yield {
        "ip_data_fetcher_nmap": "running",
        "ip_data_fetcher_nmap_done": f"0/{total}",
    }

    # Verify nmap is installed
    try:
        nmap.PortScanner()
    except nmap.PortScannerError as e:
        print(f"[-] Nmap not found: {e}")
        print("    Install from: https://nmap.org/download.html")
        yield {
            "ip_data_fetcher_nmap": "completed",
            "ip_data_fetcher_nmap_done": f"0/{total}",
        }
        return

    print(f"\n{'='*70}")
    print(f"  Nmap Scanner — {total} target(s), {num_workers} workers")
    print(f"{'='*70}")

    # Connect to database
    db = None
    db_lock = threading.Lock()
    try:
        db = DBManager()
        db.init_tables()
    except Exception as e:
        print(f"[-] Could not connect to database: {e}")
        print("    Results will NOT be saved to PostgreSQL.")

    # ─── Worker function (runs per IP in its own thread) ─────────────────
    def _scan_worker(ip_index_tuple):
        i, ip = ip_index_tuple
        # Each thread gets its own scanner instance
        nm = nmap.PortScanner()

        print(f"\n[{i}/{total}] Scanning: {ip}")

        try:
            nm.scan(hosts=ip, arguments=args)
        except nmap.PortScannerError as e:
            print(f"[-] Nmap error for {ip}: {e}")
            return {"ip": ip, "error": str(e)}
        except Exception as e:
            print(f"[-] Unexpected error scanning {ip}: {e}")
            return {"ip": ip, "error": str(e)}

        scanned_hosts = nm.all_hosts()
        if not scanned_hosts:
            print(f"[-] No results for {ip} (host might be down).")
            return {"ip": ip, "error": "Host down or no response"}

        # Parse first host result
        host = scanned_hosts[0]
        try:
            parsed = parse_scan_result(nm, host)

            port_count = len(parsed.get("open_ports", []))
            cve_count = sum(
                len(p.get("cve_details", []))
                for p in parsed.get("port_banners", [])
            )
            os_guess = parsed.get("general_info", {}).get("OS") or "Unknown"
            print(f"    [+] {host}: {port_count} open ports, "
                  f"{cve_count} CVEs, OS: {os_guess}")

            # Save to database (thread-safe with lock)
            if db:
                with db_lock:
                    try:
                        db.save_nmap_scan(parsed)
                    except Exception as e:
                        print(f"    [-] DB save error: {e}")

            return parsed

        except Exception as e:
            print(f"    [-] Parse error for {host}: {e}")
            return {"ip": host, "error": str(e)}

    # ─── Run workers and yield progress ──────────────────────────────────
    indexed_ips = list(enumerate(unique_ips, 1))
    completed_count = 0
    all_results = []

    with ThreadPoolExecutor(max_workers=num_workers) as pool:
        from concurrent.futures import as_completed
        futures = {pool.submit(_scan_worker, item): item for item in indexed_ips}
        for future in as_completed(futures):
            result = future.result()
            all_results.append(result)
            completed_count += 1
            yield {
                "ip_data_fetcher_nmap": "running",
                "ip_data_fetcher_nmap_done": f"{completed_count}/{total}",
            }

    # ─── Summary ─────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    success = [r for r in all_results if "error" not in r]
    failed = [r for r in all_results if "error" in r]
    total_ports = sum(len(r.get("open_ports", [])) for r in success)
    total_cves = sum(
        sum(len(p.get("cve_details", [])) for p in r.get("port_banners", []))
        for r in success
    )
    print(f"  Scan Complete: {len(success)} succeeded, {len(failed)} failed")
    print(f"  Total: {total_ports} open ports, {total_cves} CVEs detected")
    print(f"{'='*70}\n")

    if db:
        db.close()

    yield {
        "ip_data_fetcher_nmap": "completed",
        "ip_data_fetcher_nmap_done": f"{total}/{total}",
    }


# ═════════════════════════════════════════════════════════════════════════════
# Synchronous Wrapper
# ═════════════════════════════════════════════════════════════════════════════

def nmap_scan_ips(
    ips: list,
    scan_args: str = None,
    skip_db: bool = False,
    workers: int = 5,
) -> list:
    """
    Synchronous wrapper — scans IPs and returns results list.

    Internally consumes nmap_scan_ips_gen() for progress tracking.

    Args:
        ips:         List of IP addresses to scan
        scan_args:   Custom Nmap arguments (default: comprehensive scan)
        skip_db:     If True, return parsed data without saving to DB
        workers:     Number of parallel Nmap processes (default: 5)

    Returns:
        List of parsed host dictionaries
    """
    for progress in nmap_scan_ips_gen(ips, scan_args, workers):
        pass


# ═════════════════════════════════════════════════════════════════════════════
# Single-IP function (for Engine / LangGraph use)
# ═════════════════════════════════════════════════════════════════════════════

def scan_single_ip(ip: str, scan_args: str = None, db=None) -> dict:
    """
    Scan a single IP with Nmap and optionally save to database.

    This is designed for the LangGraph engine which loops over IPs one
    at a time. Unlike nmap_scan_ips(), this does NOT manage DB lifecycle.

    Args:
        ip:         Single IP address to scan.
        scan_args:  Custom Nmap arguments (default: DEFAULT_SCAN_ARGS).
        db:         An already-connected DBManager instance (optional).
                    If provided, results are saved to DB.

    Returns:
        dict with keys:
            - "status": "scanned" | "error"
            - "ip": the target IP
            - "data": parsed scan result dict (if scanned)
            - "reason": error message (if error)
    """
    ip = ip.strip()
    if not ip:
        return {"status": "error", "ip": ip, "reason": "Empty IP"}

    args = scan_args or DEFAULT_SCAN_ARGS

    # Each call gets its own scanner instance
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError as e:
        return {"status": "error", "ip": ip, "reason": f"Nmap not found: {e}"}

    print(f"[*] Nmap scanning: {ip}")

    try:
        nm.scan(hosts=ip, arguments=args)
    except nmap.PortScannerError as e:
        return {"status": "error", "ip": ip, "reason": f"Nmap error: {e}"}
    except Exception as e:
        return {"status": "error", "ip": ip, "reason": f"Unexpected error: {e}"}

    scanned_hosts = nm.all_hosts()
    if not scanned_hosts:
        return {"status": "error", "ip": ip, "reason": "Host down or no response"}

    host = scanned_hosts[0]
    try:
        parsed = parse_scan_result(nm, host)

        port_count = len(parsed.get("open_ports", []))
        cve_count = sum(len(p.get("cve_details", [])) for p in parsed.get("port_banners", []))
        os_guess = parsed.get("general_info", {}).get("OS") or "Unknown"
        print(f"[+] Nmap {host}: {port_count} open ports, {cve_count} CVEs, OS: {os_guess}")

        # Save to database if connection provided
        if db:
            try:
                db.save_nmap_scan(parsed)
            except Exception as e:
                print(f"[-] DB save error for {ip}: {e}")

        return {"status": "scanned", "ip": ip, "data": parsed}

    except Exception as e:
        return {"status": "error", "ip": ip, "reason": f"Parse error: {e}"}


# ═════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═════════════════════════════════════════════════════════════════════════════


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nmap_scanner.py <ip1> [ip2] [ip3] ...")
        print("       python nmap_scanner.py 192.168.1.1 10.0.0.1")
        sys.exit(1)

    target_ips = sys.argv[1:]

    progress = None
    for progress in nmap_scan_ips_gen(target_ips):
        status = progress["ip_data_fetcher_nmap"]
        done = progress["ip_data_fetcher_nmap_done"]
        print(f"  [{status}] {done}")

    print("\nScan complete.")
