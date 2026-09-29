"""
CVE Extractor
=============
Extract CVE IDs from the local database for a list of IP addresses.

Queries the vulnerabilities table (linked through hosts -> scans -> ports)
to collect all CVEs found in both Shodan and Nmap scan data.

Usage:
    from cve_extractor import extract_cves_for_ips, extract_cves_gen

    # Synchronous (returns list)
    results = extract_cves_for_ips(["1.2.3.4", "5.6.7.8"])

    # Generator (yields progress)
    for progress in extract_cves_gen(["1.2.3.4", "5.6.7.8"]):
        print(progress["cve_extractor"], progress["cve_extractor_done"])
    cves = progress["cves"]
"""

import sys
from pathlib import Path

# Add Backend to sys.path so we can import db_manager
sys.path.insert(0, str(Path(__file__).resolve().parent))

from db_manager import DBManager


# ═════════════════════════════════════════════════════════════════════════════
# Generator Function
# ═════════════════════════════════════════════════════════════════════════════

def extract_cves_gen(ip_list: list):
    """
    Generator that extracts CVE IDs from the database for a list of IPs.

    Yields progress dicts after each IP is queried:
        {
            "cve_extractor": "running" | "completed",
            "cve_extractor_done": "n/m",
            "cves": [sorted list of unique CVE IDs found so far],
        }

    The last yielded dict contains the final result in "cves".

    Args:
        ip_list: List of IP address strings.
    """
    if not ip_list:
        yield {
            "cve_extractor": "completed",
            "cve_extractor_done": "0/0",
            "cves": [],
        }
        return

    total = len(ip_list)
    yield {
        "cve_extractor": "running",
        "cve_extractor_done": f"0/{total}",
        "cves": [],
    }

    db = DBManager()
    all_cves = set()

    try:
        with db.conn.cursor() as cur:
            for i, ip in enumerate(ip_list, 1):
                ip = ip.strip()
                cur.execute("""
                    SELECT DISTINCT v.cve_id
                    FROM vulnerabilities v
                    JOIN ports p ON p.id = v.port_id
                    JOIN scans s ON s.id = p.scan_id
                    JOIN hosts h ON h.id = s.host_id
                    WHERE h.ip = %s::inet
                    ORDER BY v.cve_id
                """, (ip,))

                for row in cur.fetchall():
                    all_cves.add(row[0])

                yield {
                    "cve_extractor": "running",
                    "cve_extractor_done": f"{i}/{total}",
                    "cves": sorted(all_cves),
                }
    finally:
        db.close()

    yield {
        "cve_extractor": "completed",
        "cve_extractor_done": f"{total}/{total}",
        "cves": sorted(all_cves),
    }


# ═════════════════════════════════════════════════════════════════════════════
# Synchronous Wrapper
# ═════════════════════════════════════════════════════════════════════════════

def extract_cves_for_ips(ip_list: list) -> list:
    """
    Synchronous wrapper — returns sorted list of unique CVE IDs.

    Internally consumes extract_cves_gen() and returns the final result.

    Args:
        ip_list: List of IP address strings.

    Returns:
        Sorted list of unique CVE IDs found across all provided IPs.
        Example: ["CVE-2020-1472", "CVE-2021-44228", "CVE-2023-4966"]
    """
    progress = None
    for progress in extract_cves_gen(ip_list):
        pass
    return progress.get("cves", []) if progress else []


# ═════════════════════════════════════════════════════════════════════════════
# CLI - quick test / standalone usage
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        ips = [ip.strip() for ip in sys.argv[1].replace(",", " ").split()
               if ip.strip()]
    else:
        print("\n  CVE Extractor - Enter IP addresses")
        print("  Separate with spaces or commas.\n")
        raw = input("  > ").strip()
        if not raw:
            print("[-] No IPs provided.")
            sys.exit(1)
        ips = [ip.strip() for ip in raw.replace(",", " ").split()
               if ip.strip()]

    progress = None
    for progress in extract_cves_gen(ips):
        status = progress["cve_extractor"]
        done = progress["cve_extractor_done"]
        print(f"  [{status}] {done}")

    cves = progress.get("cves", []) if progress else []

    if cves:
        print(f"\n  Found {len(cves)} unique CVEs across {len(ips)} IPs:\n")
        for cve in cves:
            print(f"    - {cve}")
    else:
        print(f"\n  No CVEs found for the provided IPs.")
