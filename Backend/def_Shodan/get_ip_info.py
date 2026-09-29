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


def get_ip_info_gen(ip_list):
    """
    Generator that scrapes Shodan host details for a list of IPs.

    Yields progress dicts after each IP is processed:
        {
            "ip_data_fetcher_shodan": "running" | "completed",
            "ip_data_fetcher_shodan_done": "n/m",
        }

    Data goes directly to the database — not returned in the yields.

    Args:
        ip_list: List of IP address strings.
    """
    if not ip_list:
        yield {
            "ip_data_fetcher_shodan": "completed",
            "ip_data_fetcher_shodan_done": "0/0",
        }
        return

    # Normalize the IP list
    clean_ips = [str(ip).strip() for ip in ip_list if str(ip).strip()]
    total = len(clean_ips)

    if not clean_ips:
        yield {
            "ip_data_fetcher_shodan": "completed",
            "ip_data_fetcher_shodan_done": "0/0",
        }
        return

    yield {
        "ip_data_fetcher_shodan": "running",
        "ip_data_fetcher_shodan_done": f"0/{total}",
    }

    # ── Connect to PostgreSQL ────────────────────────────────────────────
    try:
        db = DBManager()
        db.init_tables()
    except Exception as e:
        print(f"[-] Database connection failed: {e}")
        print("[-] Cannot proceed without database.")
        yield {
            "ip_data_fetcher_shodan": "completed",
            "ip_data_fetcher_shodan_done": f"0/{total}",
        }
        return

    print(f"[*] Starting Shodan host information scraper for {total} IP(s)...")
    print(f"    Storage: PostgreSQL ({db.conn.info.dbname}@{db.conn.info.host})")

    # Log in to Shodan
    result = shodan_login()
    if not result:
        print("[-] Login failed. Cannot proceed with host scraping.")
        db.close()
        yield {
            "ip_data_fetcher_shodan": "completed",
            "ip_data_fetcher_shodan_done": f"0/{total}",
        }
        return

    pw, browser, context, page = result

    try:
        for idx, target_ip in enumerate(clean_ips, start=1):
            print(f"\n{'='*60}")
            print(f"[{idx}/{total}] Processing IP: {target_ip}")
            print(f"{'='*60}")

            # ── Crash Recovery Check (from database) ─────────────────────
            stored_last_seen = db.get_latest_last_seen(target_ip, source="shodan")

            if stored_last_seen is not None:
                # IP exists in database — load page briefly to compare last_seen
                print(f"[*] IP found in database (last_seen={stored_last_seen}). Checking for updates...")
                try:
                    page.goto(f"https://www.shodan.io/host/{target_ip}",
                              wait_until="domcontentloaded", timeout=120000)
                    page.wait_for_timeout(2000)

                    # Handle login redirect
                    if "account.shodan.io/login" in page.url:
                        print("[-] Session expired during check. Stopping.")
                        break

                    live_last_seen = quick_extract_last_seen(page)
                    print(f"    Shodan last_seen: {live_last_seen}")

                    if live_last_seen and live_last_seen == stored_last_seen:
                        print(f"[=] Skipping {target_ip} -- data unchanged (last_seen={stored_last_seen}).")
                        yield {
                            "ip_data_fetcher_shodan": "running",
                            "ip_data_fetcher_shodan_done": f"{idx}/{total}",
                        }
                        if idx < total:
                            time.sleep(HOST_DELAY_SECONDS)
                        continue
                    else:
                        print(f"[!] Data has changed (db={stored_last_seen}, shodan={live_last_seen}). Re-scraping...")
                        # Page is already loaded, parse it directly
                        html_content = page.content()
                        parsed_data = parse_shodan_host_html(html_content, ip=target_ip)

                        # Extract port-specific CVEs
                        port_cve_map = extract_port_cves(page, parsed_data.get("open_ports", []))
                        for banner in parsed_data.get("port_banners", []):
                            if banner["port"] in port_cve_map:
                                banner["cve_details"] = port_cve_map[banner["port"]]

                        total_cves = sum(len(b.get("cve_details", [])) for b in parsed_data.get("port_banners", []))
                        print(f"[+] Re-scraped {target_ip}: {len(parsed_data.get('open_ports',[]))} ports, {total_cves} CVEs")

                        db.save_shodan_scan(parsed_data)

                except Exception as e:
                    print(f"[-] Error during update check for {target_ip}: {e}")
                    print("    Will attempt full scrape...")
                    host_info = scrape_host_info(page, target_ip)
                    if "error" not in host_info:
                        db.save_shodan_scan(host_info)
            else:
                # ── New IP — full scrape ─────────────────────────────────
                host_info = scrape_host_info(page, target_ip)
                if "error" not in host_info:
                    db.save_shodan_scan(host_info)
                else:
                    print(f"[-] Could not scrape {target_ip}: {host_info.get('error')}")

            yield {
                "ip_data_fetcher_shodan": "running",
                "ip_data_fetcher_shodan_done": f"{idx}/{total}",
            }

            # Polite delay between IPs
            if idx < total:
                time.sleep(HOST_DELAY_SECONDS)

        print(f"\n{'='*60}")
        print(f"[DONE] Scraping complete. Total IPs processed: {total}")
        print(f"{'='*60}")

    finally:
        save_cookies(context)
        browser.close()
        pw.stop()
        db.close()

    yield {
        "ip_data_fetcher_shodan": "completed",
        "ip_data_fetcher_shodan_done": f"{total}/{total}",
    }


# ═════════════════════════════════════════════════════════════════════════════
# Synchronous Wrapper
# ═════════════════════════════════════════════════════════════════════════════

def get_ip_info_json(ip, output_file: str = DEFAULT_OUTPUT_FILE):
    """
    Main entry point to fetch and parse Shodan host details for one or more IPs.

    Internally consumes get_ip_info_gen() for progress tracking.

    Features:
      - PostgreSQL storage: data is split across hosts, scans, ports,
        vulnerabilities, and technologies tables.
      - Deduplication: if an IP's last_seen date hasn't changed in the DB, it's skipped.
      - Crash recovery: results are committed after each IP. On restart, IPs already
        in the database with matching last_seen are skipped (page is still loaded
        briefly to compare last_seen dates).
      - Port-specific CVEs via live Playwright dropdown interaction.

    Parameters:
      ip: A single IP string or a list/iterable of IP strings.
      output_file: (Legacy) Path to JSON results file. No longer used for primary
                   storage but kept for API compatibility.

    Returns:
      None — data is saved directly to the database.
    """
    is_single = isinstance(ip, str)
    if is_single:
        stripped = ip.strip()
        ip_list = [stripped] if stripped else []
    else:
        ip_list = [str(item).strip() for item in ip if str(item).strip()]

    if not ip_list:
        print("[-] No valid IP addresses provided.")
        return

    for progress in get_ip_info_gen(ip_list):
        pass


# ═════════════════════════════════════════════════════════════════════════════
# Single-IP function (for Engine / LangGraph use)
# ═════════════════════════════════════════════════════════════════════════════

def scrape_single_ip(page, db, target_ip: str) -> dict:
    """
    Scrape a single IP using an existing Playwright page and DB connection.

    This is designed for the LangGraph engine which manages its own browser
    session and loops over IPs one at a time. Unlike get_ip_info_json(),
    this function does NOT manage login/browser lifecycle.

    Args:
        page:       An already-logged-in Playwright page object.
        db:         An already-connected DBManager instance.
        target_ip:  The IP address to scrape.

    Returns:
        dict with keys:
            - "status": "scraped" | "skipped" | "error"
            - "ip": the target IP
            - "data": parsed data dict (if scraped)
            - "reason": skip/error reason string (if skipped/error)
    """
    target_ip = target_ip.strip()
    if not target_ip:
        return {"status": "error", "ip": target_ip, "reason": "Empty IP"}

    # ── Deduplication Check ──────────────────────────────────────────────
    stored_last_seen = db.get_latest_last_seen(target_ip, source="shodan")

    if stored_last_seen is not None:
        print(f"[*] IP found in database (last_seen={stored_last_seen}). Checking for updates...")
        try:
            page.goto(f"https://www.shodan.io/host/{target_ip}",
                      wait_until="domcontentloaded", timeout=120000)
            page.wait_for_timeout(2000)

            if "account.shodan.io/login" in page.url:
                return {"status": "error", "ip": target_ip, "reason": "Session expired"}

            live_last_seen = quick_extract_last_seen(page)
            print(f"    Shodan last_seen: {live_last_seen}")

            if live_last_seen and live_last_seen == stored_last_seen:
                print(f"[=] Skipping {target_ip} -- data unchanged.")
                return {"status": "skipped", "ip": target_ip, "reason": f"unchanged (last_seen={stored_last_seen})"}

            # Data changed — parse from already loaded page
            print(f"[!] Data changed (db={stored_last_seen}, shodan={live_last_seen}). Re-scraping...")
            html_content = page.content()
            parsed_data = parse_shodan_host_html(html_content, ip=target_ip)

            port_cve_map = extract_port_cves(page, parsed_data.get("open_ports", []))
            for banner in parsed_data.get("port_banners", []):
                if banner["port"] in port_cve_map:
                    banner["cve_details"] = port_cve_map[banner["port"]]

            total_cves = sum(len(b.get("cve_details", [])) for b in parsed_data.get("port_banners", []))
            print(f"[+] Re-scraped {target_ip}: {len(parsed_data.get('open_ports', []))} ports, {total_cves} CVEs")

            db.save_shodan_scan(parsed_data)
            return {"status": "scraped", "ip": target_ip, "data": parsed_data}

        except Exception as e:
            print(f"[-] Update check failed for {target_ip}: {e}. Attempting full scrape...")
            # Fall through to full scrape below

    # ── Full scrape (new IP or fallback) ─────────────────────────────────
    host_info = scrape_host_info(page, target_ip)

    if "error" in host_info:
        return {"status": "error", "ip": target_ip, "reason": host_info["error"]}

    db.save_shodan_scan(host_info)
    total_cves = sum(len(b.get("cve_details", [])) for b in host_info.get("port_banners", []))
    print(f"[+] Scraped {target_ip}: {len(host_info.get('open_ports', []))} ports, {total_cves} CVEs")
    return {"status": "scraped", "ip": target_ip, "data": host_info}


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
