import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from bs4 import BeautifulSoup

# Re-use the login logic and cookie handling from get_ip.py
from get_ip import shodan_login, save_cookies

# Add Backend/ to path so we can import db_manager
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from db_manager import DBManager

# ─── Configuration ───────────────────────────────────────────────────────────
HOST_DELAY_SECONDS = 2.0   # Courtesy delay between host page requests
SCRIPT_DIR = Path(__file__).parent
DEFAULT_OUTPUT_FILE = "shodan_results.json"


# ═════════════════════════════════════════════════════════════════════════════
# Legacy JSON File I/O (kept for backward compatibility / offline fallback)
# ═════════════════════════════════════════════════════════════════════════════

def load_results_file(filepath: str) -> dict:
    """[LEGACY] Load timeline-based results from a JSON file."""
    path = Path(filepath)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        return {}


def get_stored_last_seen(results: dict, ip: str):
    """[LEGACY] Get last_seen from JSON results dict."""
    entries = results.get(ip)
    if not entries or not isinstance(entries, list) or len(entries) == 0:
        return None
    return entries[-1].get("last_seen")


def save_ip_to_results(filepath: str, ip: str, ip_data: dict, results: dict) -> bool:
    """[LEGACY] Save IP data to JSON file."""
    stored_last_seen = get_stored_last_seen(results, ip)
    new_last_seen = ip_data.get("last_seen")
    if stored_last_seen == new_last_seen and ip in results:
        return False
    if ip not in results:
        results[ip] = []
    results[ip].append(ip_data)
    try:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    except (OSError, PermissionError) as e:
        print(f"[-] WARNING: Could not write results file ({e}).")
    return True


# ═════════════════════════════════════════════════════════════════════════════
# Quick last_seen extraction (for crash recovery check)
# ═════════════════════════════════════════════════════════════════════════════

def quick_extract_last_seen(page) -> str:
    """
    Quickly extract just the 'Last Seen' date from the currently loaded Shodan
    host page without doing a full HTML parse. Returns None if not found.
    """
    try:
        # Use Playwright locator for speed instead of full BeautifulSoup parse
        headings = page.locator(".top-info .grid-heading").all()
        for h in headings:
            text = h.inner_text()
            if "Last Seen:" in text:
                return text.replace("Last Seen:", "").strip()
    except Exception:
        pass

    # Fallback: parse a small chunk of the page
    try:
        html = page.content()
        match = re.search(r"Last Seen:\s*(\d{4}-\d{2}-\d{2})", html)
        if match:
            return match.group(1)
    except Exception:
        pass

    return None


# ═════════════════════════════════════════════════════════════════════════════
# HTML Parser (static — extracts everything except port-specific CVEs)
# ═════════════════════════════════════════════════════════════════════════════

def parse_shodan_host_html(html_content: str, ip: str = "") -> dict:
    """
    Parse a Shodan host details HTML page and extract all available sections:
      - general info (Hostnames, Domains, Country, City, Organization, ISP, ASN, OS, Tags)
      - open ports
      - each port banner (protocol, service, version, http_title, raw banner, timestamp)
      - web technologies (grouped by category with names & versions)
      - security contact (from security.txt / security contact cards)
      - timeline (last seen, history URL, and per-port timestamps)

    Port-specific CVEs are NOT extracted here — they require live Playwright
    interaction with the filter dropdown (see extract_port_cves).

    Gracefully handles missing sections if an IP does not contain them.
    """
    soup = BeautifulSoup(html_content, "html.parser")

    # Determine IP
    extracted_ip = ""
    host_title = soup.find("h2", class_="host-title")
    if host_title:
        extracted_ip = host_title.get_text(strip=True)
    elif soup.title:
        title_text = soup.title.get_text(strip=True)
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", title_text)
        if ip_match:
            extracted_ip = ip_match.group(0)

    target_ip = ip or extracted_ip

    # Check for "No information available" or 404
    page_text = soup.get_text()
    if "No information available" in page_text or "No results found" in page_text:
        return {
            "ip": target_ip,
            "error": "No information available on Shodan for this host",
            "general_info": {},
            "open_ports": [],
            "web_technologies": {},
            "security_contact": {},
            "last_seen": None,
            "scraped_at": datetime.now(timezone.utc).isoformat(),
            "timeline": {},
            "port_banners": []
        }

    data = {
        "ip": target_ip,
        "last_seen": None,
        "scraped_at": datetime.now(timezone.utc).isoformat(),
        "general_info": {},
        "open_ports": [],
        "web_technologies": {},
        "security_contact": {},
        "timeline": {
            "history_url": None,
            "port_timestamps": {}
        },
        "port_banners": []
    }

    # ── 1. Last Seen, Tags ───────────────────────────────────────────────────
    top_info = soup.find(class_="top-info")
    if top_info:
        for heading in top_info.find_all(class_="grid-heading"):
            text = heading.get_text(strip=True)
            if "Last Seen:" in text:
                data["last_seen"] = text.replace("Last Seen:", "").strip()

    tags_div = soup.find(id="tags")
    if tags_div:
        data["general_info"]["tags"] = [a.get_text(strip=True) for a in tags_div.find_all("a", class_="tag")]
    else:
        data["general_info"]["tags"] = []

    # History link
    history_link = soup.find("a", href=lambda h: h and "/history" in h)
    if history_link and history_link.get("href"):
        href = history_link["href"]
        if href.startswith("/"):
            href = f"https://www.shodan.io{href}"
        data["timeline"]["history_url"] = href
    elif target_ip:
        data["timeline"]["history_url"] = f"https://www.shodan.io/host/{target_ip}/history"

    # ── 2. General Information ──────────────────────────────────────────────
    gen_heading = soup.find(id="general")
    if gen_heading:
        gen_card = gen_heading.find_parent("div", class_="card")
        if gen_card:
            grid_table = gen_card.find("div", class_="grid-table")
            if grid_table:
                for lbl in grid_table.find_all("label"):
                    key = lbl.get_text(strip=True)
                    val_div = lbl.find_next_sibling("div")
                    if val_div and "grid-border" not in val_div.get("class", []):
                        data["general_info"][key] = val_div.get_text(" ", strip=True)

    # ── 3. Open Ports ───────────────────────────────────────────────────────
    ports_div = soup.find(id="ports")
    if ports_div:
        for a in ports_div.find_all("a"):
            p_text = a.get_text(strip=True)
            if p_text.isdigit():
                port_num = int(p_text)
                if port_num not in data["open_ports"]:
                    data["open_ports"].append(port_num)

    # ── 4. Web Technologies ─────────────────────────────────────────────────
    webtech_heading = soup.find(id="webtech")
    if webtech_heading:
        webtech_card = webtech_heading.find_parent("div", class_="card")
        if webtech_card:
            for cat in webtech_card.find_all(class_="category"):
                cat_heading = cat.find(class_="category-heading")
                cat_name = cat_heading.get_text(strip=True) if cat_heading else "General"
                tech_list = []
                for tech_el in cat.find_all(class_="technologies"):
                    name_span = tech_el.find(class_="technology-name")
                    ver_span = tech_el.find(class_="technology-versions")
                    name = name_span.get_text(strip=True) if name_span else tech_el.get_text(strip=True)
                    ver = ver_span.get_text(strip=True) if ver_span else None
                    tech_list.append({"name": name, "version": ver})
                data["web_technologies"][cat_name] = tech_list

    # ── 5. Security Contact ─────────────────────────────────────────────────
    sec_candidates = soup.find_all(["h1", "h2", "h3", "a"], attrs={"name": re.compile(r"security|contact", re.I)})
    sec_candidates += [h for h in soup.find_all(["h1", "h2", "h3"]) if re.search(r"security\s*contact|security\.txt", h.get_text(), re.I)]
    for cand in sec_candidates:
        card = cand.find_parent("div", class_="card")
        if card:
            grid = card.find("div", class_="grid-table")
            if grid:
                for lbl in grid.find_all("label"):
                    k = lbl.get_text(strip=True)
                    v_div = lbl.find_next_sibling("div")
                    if v_div and "grid-border" not in v_div.get("class", []):
                        data["security_contact"][k] = v_div.get_text(strip=True)
            else:
                data["security_contact"]["details"] = card.get_text("\n", strip=True)
            break

    # ── 6. Port Banners & Timestamps ─────────────────────────────────────────
    for port_h in soup.find_all("h6", class_="grid-heading"):
        port_id = port_h.get("id")
        if not port_id or not port_id.isdigit():
            continue

        port_num = int(port_id)
        if port_num not in data["open_ports"]:
            data["open_ports"].append(port_num)

        # Protocol
        tooltip = port_h.find(class_="tooltip")
        proto_text = tooltip.get_text(strip=True) if tooltip else f"{port_num}/tcp"
        protocol = "tcp"
        if "/" in proto_text:
            protocol = proto_text.split("/")[-1].strip()

        # Timestamp from .text-secondary
        sec_div = port_h.find(class_="text-secondary")
        timestamp = None
        if sec_div:
            sec_text = sec_div.get_text(" ", strip=True)
            parts = [p.strip() for p in sec_text.split("|") if p.strip()]
            for p in parts:
                if re.match(r"\d{4}-\d{2}-\d{2}", p):
                    timestamp = p

        if timestamp:
            data["timeline"]["port_timestamps"][str(port_num)] = timestamp

        # Sibling banner card
        banner_card = port_h.find_next_sibling("div", class_="banner")
        service_title = None
        service_version = None
        http_title = None
        banner_text = ""

        if banner_card:
            # Banner title / Service
            bt = banner_card.find(class_="banner-title")
            if bt:
                em = bt.find("em")
                sp = bt.find("span")
                service_title = em.get_text(strip=True) if em else None
                service_version = sp.get_text(strip=True) if sp else None
                if not service_title:
                    service_title = bt.get_text(strip=True)

            # HTTP Title
            ht = banner_card.find(class_="http-title")
            if ht:
                http_title = ht.get_text(strip=True)

            # Raw banner text from <pre>
            pre = banner_card.find("pre")
            if pre:
                banner_text = pre.get_text()

        data["port_banners"].append({
            "port": port_num,
            "protocol": protocol,
            "service": service_title,
            "version": service_version,
            "http_title": http_title,
            "timestamp": timestamp,
            "cve_details": [],   # Filled later by extract_port_cves()
            "banner": banner_text
        })

    return data


# ═════════════════════════════════════════════════════════════════════════════
# Port-Specific CVE Extraction (requires live Playwright page)
# ═════════════════════════════════════════════════════════════════════════════

def _parse_visible_vuln_rows(page) -> list:
    """
    Parse all currently visible vuln-row elements on the page and return
    a list of CVE detail dicts.
    """
    cves = []
    rows = page.locator("#vulns-table .vuln-row").all()
    for row in rows:
        # Skip rows hidden by the JS filter
        if not row.is_visible():
            continue

        cve_id = row.get_attribute("id")
        if not cve_id:
            link = row.locator("a").first
            cve_id = link.inner_text().strip() if link.count() > 0 else None

        # CVSS score badge
        tag_el = row.locator(".tag").first
        cvss_text = tag_el.inner_text().strip() if tag_el.count() > 0 else None
        cvss = None
        if cvss_text and cvss_text.replace(".", "", 1).isdigit():
            cvss = float(cvss_text)

        # Summary text (the long <span> that isn't the CVSS badge)
        summary = ""
        spans = row.locator("span").all()
        for sp in spans:
            text = sp.inner_text().strip()
            if len(text) > 20:
                summary = text
                break

        # CVSS Vector from summary
        cvss_vector = None
        vector_match = re.search(r"CVSS Vector:\s*\(([^)]+)\)", summary)
        if vector_match:
            cvss_vector = vector_match.group(1)

        cves.append({
            "cve": cve_id,
            "cvss": cvss,
            "cvss_vector": cvss_vector,
            "summary": summary
        })

    return cves


def extract_port_cves(page, open_ports: list) -> dict:
    """
    Extract CVE details per port by interacting with the Shodan vulnerability
    filter dropdown (#vulns-filter-by).

    The dropdown uses JavaScript to show/hide vuln-row elements based on the
    selected port. We select each port option, wait for the DOM to update,
    then scrape the visible rows.

    Returns: { port_number: [ {cve, cvss, cvss_vector, summary}, ... ], ... }
    """
    port_cves = {}

    # Check if the vulns filter dropdown exists
    filter_select = page.locator("#vulns-filter-by")
    if filter_select.count() == 0:
        print("    [.] No vulnerability filter dropdown found.")
        return port_cves

    # Get available port options from the dropdown
    options = filter_select.locator("option").all()
    port_options = []
    for opt in options:
        val = opt.get_attribute("value")
        text = opt.inner_text().strip()
        # Skip "All ports" or non-port options
        if val and val.isdigit():
            port_options.append(int(val))

    if not port_options:
        # No per-port options — try to get all CVEs as generic
        print("    [.] No per-port CVE filter options found.")
        # Fall back: scrape all visible CVEs and assign to no specific port
        all_cves = _parse_visible_vuln_rows(page)
        if all_cves:
            port_cves["all"] = all_cves
        return port_cves

    print(f"    [*] Extracting CVEs for ports: {port_options}")

    for port in port_options:
        try:
            # Select the port in the dropdown
            filter_select.select_option(value=str(port))
            # Wait for JavaScript to show/hide rows
            page.wait_for_timeout(600)

            # Scrape visible CVE rows
            cves = _parse_visible_vuln_rows(page)
            if cves:
                port_cves[port] = cves
                print(f"    [+] Port {port}: {len(cves)} CVE(s)")
            else:
                print(f"    [.] Port {port}: 0 CVEs")

        except Exception as e:
            print(f"    [-] Port {port}: Error extracting CVEs: {e}")

    # Reset dropdown back to "All ports"
    try:
        filter_select.select_option(value="all")
        page.wait_for_timeout(300)
    except Exception:
        pass

    return port_cves


# ═════════════════════════════════════════════════════════════════════════════
# Main scraper orchestrator
# ═════════════════════════════════════════════════════════════════════════════

def scrape_host_info(page, ip: str) -> dict:
    """
    Navigate to a host's Shodan page, parse static HTML, then use Playwright
    to extract port-specific CVEs via the vulnerability filter dropdown.

    Returns the complete data dict for this IP, or a dict with 'error' key on failure.
    """
    url = f"https://www.shodan.io/host/{ip}"
    print(f"\n[*] Fetching host info for: {ip}")
    print(f"    URL: {url}")

    try:
        page.goto(url, wait_until="domcontentloaded", timeout=120000)
        page.wait_for_timeout(2000)  # Wait for dynamic DOM elements to render

        # Handle potential login redirect if session expired
        if "account.shodan.io/login" in page.url:
            print("[-] Session expired or redirected to login.")
            return {
                "ip": ip,
                "error": "Redirected to login. Session may have expired."
            }

        # 1) Parse static HTML for all sections except port-specific CVEs
        html_content = page.content()
        parsed_data = parse_shodan_host_html(html_content, ip=ip)

        # 2) Extract port-specific CVEs via live Playwright interaction
        port_cve_map = extract_port_cves(page, parsed_data.get("open_ports", []))

        # 3) Merge port-specific CVEs into port_banners
        for banner in parsed_data.get("port_banners", []):
            port_num = banner["port"]
            if port_num in port_cve_map:
                banner["cve_details"] = port_cve_map[port_num]

        # Summary
        total_cves = sum(len(b.get("cve_details", [])) for b in parsed_data.get("port_banners", []))
        print(f"[+] Successfully extracted data for {ip}:")
        print(f"    - Open Ports: {len(parsed_data.get('open_ports', []))} ({parsed_data.get('open_ports', [])})")
        print(f"    - Total CVEs: {total_cves} (across {len(port_cve_map)} port(s))")
        print(f"    - Tech Categories: {len(parsed_data.get('web_technologies', {}))}")
        return parsed_data

    except Exception as e:
        print(f"[-] Error scraping host {ip}: {e}")
        return {
            "ip": ip,
            "error": str(e)
        }


def get_ip_info_gen(ip, output_file: str = DEFAULT_OUTPUT_FILE):
    """
    Generator that fetches and parses Shodan host details for one or more IPs,
    yielding structured progress dicts at each step.

    Yields:
        {"status": "db_init", "success": bool, "error": str|None}
        {"status": "login", "success": bool}
        {"status": "ip_start", "ip": str, "current": int, "total": int}
        {"status": "ip_skip", "ip": str, "current": int, "total": int, "reason": str}
        {"status": "ip_done", "ip": str, "current": int, "total": int, "ports": int, "cves": int}
        {"status": "ip_error", "ip": str, "current": int, "total": int, "error": str}
        {"status": "complete", "total": int, "scraped": int, "skipped": int, "results": list}
    """
    is_single = isinstance(ip, str)
    if is_single:
        stripped = ip.strip()
        ip_list = [stripped] if stripped else []
    else:
        ip_list = [str(item).strip() for item in ip if str(item).strip()]

    if not ip_list:
        yield {"status": "complete", "total": 0, "scraped": 0, "skipped": 0, "results": []}
        return

    # ── Connect to PostgreSQL ────────────────────────────────────────────
    try:
        db = DBManager()
        db.init_tables()
        yield {"status": "db_init", "success": True, "error": None}
    except Exception as e:
        yield {"status": "db_init", "success": False, "error": str(e)}
        return

    # Log in to Shodan
    result = shodan_login()
    if not result:
        yield {"status": "login", "success": False}
        db.close()
        return
    yield {"status": "login", "success": True}

    pw, browser, context, page = result
    scraped_results = []
    skipped_count = 0
    total = len(ip_list)

    try:
        for idx, target_ip in enumerate(ip_list, start=1):
            yield {
                "status": "ip_start",
                "ip": target_ip,
                "current": idx,
                "total": total,
            }

            # ── Crash Recovery Check (from database) ─────────────────────
            stored_last_seen = db.get_latest_last_seen(target_ip, source="shodan")

            if stored_last_seen is not None:
                # IP exists in database — load page briefly to compare last_seen
                try:
                    page.goto(f"https://www.shodan.io/host/{target_ip}",
                              wait_until="domcontentloaded", timeout=120000)
                    page.wait_for_timeout(2000)

                    if "account.shodan.io/login" in page.url:
                        yield {
                            "status": "ip_error",
                            "ip": target_ip,
                            "current": idx,
                            "total": total,
                            "error": "Session expired",
                        }
                        break

                    live_last_seen = quick_extract_last_seen(page)

                    if live_last_seen and live_last_seen == stored_last_seen:
                        skipped_count += 1
                        yield {
                            "status": "ip_skip",
                            "ip": target_ip,
                            "current": idx,
                            "total": total,
                            "reason": f"unchanged (last_seen={stored_last_seen})",
                        }
                        if idx < total:
                            time.sleep(HOST_DELAY_SECONDS)
                        continue
                    else:
                        # Data changed — re-scrape from already loaded page
                        html_content = page.content()
                        parsed_data = parse_shodan_host_html(html_content, ip=target_ip)

                        port_cve_map = extract_port_cves(page, parsed_data.get("open_ports", []))
                        for banner in parsed_data.get("port_banners", []):
                            if banner["port"] in port_cve_map:
                                banner["cve_details"] = port_cve_map[banner["port"]]

                        db.save_shodan_scan(parsed_data)
                        scraped_results.append(parsed_data)

                        total_cves = sum(len(b.get("cve_details", [])) for b in parsed_data.get("port_banners", []))
                        yield {
                            "status": "ip_done",
                            "ip": target_ip,
                            "current": idx,
                            "total": total,
                            "ports": len(parsed_data.get("open_ports", [])),
                            "cves": total_cves,
                        }

                except Exception as e:
                    # Update check failed — try full scrape
                    host_info = scrape_host_info(page, target_ip)
                    if "error" not in host_info:
                        db.save_shodan_scan(host_info)
                        scraped_results.append(host_info)
                        total_cves = sum(len(b.get("cve_details", [])) for b in host_info.get("port_banners", []))
                        yield {
                            "status": "ip_done",
                            "ip": target_ip,
                            "current": idx,
                            "total": total,
                            "ports": len(host_info.get("open_ports", [])),
                            "cves": total_cves,
                        }
                    else:
                        yield {
                            "status": "ip_error",
                            "ip": target_ip,
                            "current": idx,
                            "total": total,
                            "error": str(e),
                        }
            else:
                # ── New IP — full scrape ─────────────────────────────────
                host_info = scrape_host_info(page, target_ip)
                if "error" not in host_info:
                    db.save_shodan_scan(host_info)
                    scraped_results.append(host_info)
                    total_cves = sum(len(b.get("cve_details", [])) for b in host_info.get("port_banners", []))
                    yield {
                        "status": "ip_done",
                        "ip": target_ip,
                        "current": idx,
                        "total": total,
                        "ports": len(host_info.get("open_ports", [])),
                        "cves": total_cves,
                    }
                else:
                    yield {
                        "status": "ip_error",
                        "ip": target_ip,
                        "current": idx,
                        "total": total,
                        "error": host_info.get("error", "Unknown error"),
                    }

            # Polite delay between IPs
            if idx < total:
                time.sleep(HOST_DELAY_SECONDS)

    finally:
        save_cookies(context)
        browser.close()
        pw.stop()
        db.close()

    yield {
        "status": "complete",
        "total": total,
        "scraped": len(scraped_results),
        "skipped": skipped_count,
        "results": scraped_results,
    }


# ─── Convenience wrapper (backward compatible) ──────────────────────────────
def get_ip_info_json(ip, output_file: str = DEFAULT_OUTPUT_FILE):
    """
    Non-generator wrapper: fetches host info and returns the results list.
    Consumes get_ip_info_gen() internally, printing progress.
    """
    is_single = isinstance(ip, str)
    results = []

    for update in get_ip_info_gen(ip, output_file):
        status = update["status"]
        if status == "db_init":
            if not update["success"]:
                print(f"[-] Database connection failed: {update['error']}")
                return {} if is_single else []
        elif status == "login":
            if not update["success"]:
                print("[-] Login failed. Cannot proceed.")
                return {} if is_single else []
        elif status == "ip_start":
            print(f"\n{'='*60}")
            print(f"[{update['current']}/{update['total']}] Processing IP: {update['ip']}")
            print(f"{'='*60}")
        elif status == "ip_skip":
            print(f"[=] Skipping {update['ip']} -- {update['reason']}")
        elif status == "ip_done":
            print(f"[+] {update['ip']}: {update['ports']} ports, {update['cves']} CVEs")
        elif status == "ip_error":
            print(f"[-] {update['ip']}: {update['error']}")
        elif status == "complete":
            results = update["results"]
            print(f"\n{'='*60}")
            print(f"[DONE] Total: {update['total']}, "
                  f"Scraped: {update['scraped']}, Skipped: {update['skipped']}")
            print(f"{'='*60}")

    if is_single:
        return results[0] if results else None
    return results


# ═════════════════════════════════════════════════════════════════════════════
# Self-test / Demo
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Offline verification with example.html (parser test — no DB needed)
    example_file = Path(__file__).parent / "example.html"
    if example_file.exists():
        print("[*] Testing parser against example.html...")
        html = example_file.read_text(encoding="utf-8", errors="ignore")
        parsed = parse_shodan_host_html(html, ip="115.190.54.238")
        print("\n--- Extracted Summary from example.html ---")
        print(f"IP: {parsed['ip']}")
        print(f"Last Seen: {parsed['last_seen']}")
        print(f"Scraped At: {parsed['scraped_at']}")
        print(f"Country: {parsed['general_info'].get('Country')}")
        print(f"City: {parsed['general_info'].get('City')}")
        print(f"Organization: {parsed['general_info'].get('Organization')}")
        print(f"Open Ports: {parsed['open_ports']}")
        print(f"Port Banners: {len(parsed['port_banners'])} entries")
        for b in parsed["port_banners"]:
            print(f"  Port {b['port']}: service={b['service']}, version={b['version']}, cve_details={len(b.get('cve_details',[]))}")
        print(f"Web Tech: {list(parsed['web_technologies'].keys())}")
        print(f"Timeline: {parsed['timeline']}")

        # Verify no hashes anywhere
        assert "hashes" not in parsed, "FAIL: top-level 'hashes' key should be removed"
        for b in parsed["port_banners"]:
            assert "hashes" not in b, f"FAIL: 'hashes' found in port {b['port']} banner"
        # Verify cve_details is per-port (empty list since static parse can't interact with dropdown)
        for b in parsed["port_banners"]:
            assert "cve_details" in b, f"FAIL: 'cve_details' missing from port {b['port']} banner"
        # Verify no top-level cve_details
        assert "cve_details" not in parsed, "FAIL: top-level 'cve_details' should be removed"

        print("\n[OK] All parser assertions passed.\n")

    # Database connection test
    print("[*] Testing database connection...")
    try:
        db = DBManager()
        db.init_tables()
        print("[OK] Database connected and tables verified.")

        # If parser test ran, try saving parsed data to DB
        if example_file.exists() and parsed:
            saved = db.save_shodan_scan(parsed)
            if saved:
                print(f"[OK] Example data saved to database.")
                # Verify deduplication
                saved_again = db.save_shodan_scan(parsed)
                assert saved_again is False, "FAIL: duplicate save should return False"
                print("[OK] Deduplication verified.")

                # Verify query
                host = db.get_host_by_ip(parsed["ip"])
                assert host is not None, "FAIL: host should exist in DB"
                print(f"[OK] Host query verified: {host['ip']}")

                timeline = db.get_host_timeline(parsed["ip"])
                print(f"[OK] Timeline has {len(timeline)} entry(s).")

        db.close()
        print("\n[OK] All tests passed!\n")

    except Exception as e:
        print(f"\n[!] Database test failed: {e}")
        print("    Make sure PostgreSQL is running and .env has PG_* variables.")
        print("    Parser tests still passed — only DB connectivity failed.\n")