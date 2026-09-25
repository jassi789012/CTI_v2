# shodan login link :- https://account.shodan.io/login

import os
import re
import json
import time
from pathlib import Path
from urllib.parse import quote
from playwright.sync_api import sync_playwright
from dotenv import load_dotenv

# ─── Paths ───────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent
COOKIES_FILE = SCRIPT_DIR / "shodan_cookies.json"
ENV_PATH = Path(__file__).resolve().parents[2] / ".env"  # CTI_V2/.env

load_dotenv(dotenv_path=ENV_PATH)


# ─── Cookie helpers ──────────────────────────────────────────────────────────
def save_cookies(context):
    """Persist browser cookies to a JSON file."""
    cookies = context.cookies()
    COOKIES_FILE.write_text(json.dumps(cookies, indent=2), encoding="utf-8")
    print(f"[+] Cookies saved to {COOKIES_FILE}")


def load_cookies(context):
    """Load cookies from file into the browser context. Returns True on success."""
    if not COOKIES_FILE.exists():
        print("[-] No saved cookies found.")
        return False
    try:
        cookies = json.loads(COOKIES_FILE.read_text(encoding="utf-8"))
        context.add_cookies(cookies)
        print("[+] Cookies loaded from file.")
        return True
    except json.JSONDecodeError as e:
        print(f"[-] Cookie file is corrupted: {e}")
        return False
    except Exception as e:
        print(f"[-] Failed to load cookies: {e}")
        return False


# ─── Login verification ─────────────────────────────────────────────────────
DASHBOARD_URL = "https://www.shodan.io/dashboard"

def _has_logout_link(page):
    """Safe check for logout link — won't crash on blank or unloaded pages."""
    try:
        return page.locator("a[href*='logout']").count() > 0 and page.locator("a[href*='logout']").first.is_visible()
    except Exception:
        return False


def is_logged_in(page):
    """
    Check whether the user is logged in on Shodan:
      1. Checks current page for logout link or dashboard URL (no navigation).
      2. If not confirmed, navigates to account.shodan.io and inspects again.
    """
    try:
        # Check current page state first without navigation
        if _has_logout_link(page):
            return True

        if DASHBOARD_URL in page.url:
            return True

        # Navigate to account page to verify session validity
        page.goto("https://account.shodan.io/", wait_until="domcontentloaded", timeout=10000)
        page.wait_for_timeout(1500)

        # If redirected to login page -> not logged in
        if "login" in page.url:
            return False

        # Primary check: presence of logout link
        if _has_logout_link(page):
            return True

        # Secondary checks: presence of account-only elements
        for text in ["Account Overview", "API Key"]:
            loc = page.locator(f"text={text}")
            if loc.count() > 0 and loc.first.is_visible():
                return True

        return "account.shodan.io" in page.url and "login" not in page.url

    except Exception as e:
        print(f"[-] Session check encountered an issue: {e}")
        return False


# ─── Login strategies ───────────────────────────────────────────────────────
def try_login_with_cookies(context, page):
    """Strategy 1: Attempt login using saved cookies."""
    print("\n[*] Strategy 1: Trying saved cookies...")

    if not load_cookies(context):
        return False

    if is_logged_in(page):
        print("[+] Successfully logged in via cookies!")
        return True

    print("[-] Cookies are expired or invalid.")
    return False


def try_login_with_credentials(page):
    """
    Strategy 2: Attempt login using credentials from .env file.
    Selectors will be provided later — currently uses placeholders.
    """
    print("\n[*] Strategy 2: Trying credentials from .env...")

    username = os.getenv("shodan_user")
    password = os.getenv("shodan_password")

    if not username or not password:
        print("[-] Credentials not found or empty in .env file.")
        return False

    print(f"[*] Logging in as: {username}")
    page.goto("https://account.shodan.io/login", wait_until="domcontentloaded")
    page.wait_for_timeout(1500)

    # ── Login form selectors from Shodan HTML ────────────────────────────
    USERNAME_SELECTOR = "#username"
    PASSWORD_SELECTOR = "#password"
    LOGIN_BTN_SELECTOR = "input[type='submit']"

    try:
        page.fill(USERNAME_SELECTOR, username)
        page.fill(PASSWORD_SELECTOR, password)
        page.click(LOGIN_BTN_SELECTOR)

        # Wait for redirect to dashboard
        try:
            page.wait_for_url("**/dashboard**", timeout=7000)
        except Exception:
            page.wait_for_timeout(2000)

        if is_logged_in(page):
            print("[+] Successfully logged in via credentials!")
            return True

        print("[-] Credential login failed (wrong creds, 2FA, or captcha).")
        return False
    except Exception as e:
        print(f"[-] Error during credential login: {e}")
        return False


def try_manual_login(page):
    """Strategy 3: Ask the user to log in manually in the browser."""
    print("\n[*] Strategy 3: Manual login required.")
    print("[!] A browser window is open at the Shodan login page.")
    print("[!] Please log in manually in the browser, then return here.")

    if "login" not in page.url:
        page.goto("https://account.shodan.io/login", wait_until="domcontentloaded")

    # Wait for user confirmation in console
    input("\n>>> Press ENTER here after you have logged in successfully in the browser...")

    if is_logged_in(page):
        print("[+] Manual login successful!")
        return True

    print("[-] Could not confirm login. Please try again.")
    return False


# ─── Main orchestrator ──────────────────────────────────────────────────────
def shodan_login():
    """
    Launch Chromium and log in to Shodan using a 3-tier strategy:
      1. Saved cookies
      2. Credentials from .env
      3. Manual login by the user

    Returns the (pw, browser, context, page) tuple on success so callers
    can continue using the authenticated session.
    Returns None on failure.
    """
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch(headless=False)
    except Exception as e:
        print(f"[-] Failed to launch browser: {e}")
        print("    Run 'playwright install chromium' if browsers are not installed.")
        pw.stop()
        return None
    context = browser.new_context()
    page = context.new_page()

    logged_in = False

    # ── Strategy 1: Cookies ──────────────────────────────────────────────
    if try_login_with_cookies(context, page):
        logged_in = True

    # ── Strategy 2: Credentials ──────────────────────────────────────────
    if not logged_in and try_login_with_credentials(page):
        save_cookies(context)
        logged_in = True

    # ── Strategy 3: Manual ───────────────────────────────────────────────
    if not logged_in and try_manual_login(page):
        save_cookies(context)
        logged_in = True

    if not logged_in:
        print("\n[-] All login methods failed. Exiting.")
        browser.close()
        pw.stop()
        return None

    print("\n[+] Logged in to Shodan successfully.\n")
    return pw, browser, context, page


# ─── IP extraction ───────────────────────────────────────────────────────────
# IPv4: standard dotted-decimal notation
IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'

# IPv6: matches full, compressed, and mixed (::ffff:192.168.1.1) formats
IPV6_PATTERN = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b'

IP_REGEX = re.compile(f'({IPV4_PATTERN}|{IPV6_PATTERN})')

MAX_PAGES_PER_QUERY = 2
PAGE_DELAY_SECONDS = 1.5  # Delay between page loads to avoid rate limiting


def extract_ips_from_page(page):
    """Extract all IPv4 and IPv6 addresses from the current page's HTML."""
    html_content = page.content()
    matches = IP_REGEX.findall(html_content)
    return matches


def scrape_query(page, query):
    """
    Scrape IPs for a single query across up to MAX_PAGES_PER_QUERY pages.
    Returns a set of unique IPs found.
    """
    all_ips = set()
    encoded_query = quote(query)

    for page_num in range(1, MAX_PAGES_PER_QUERY + 1):
        if page_num == 1:
            url = f"https://www.shodan.io/search?query={encoded_query}"
        else:
            url = f"https://www.shodan.io/search?query={encoded_query}&page={page_num}"

        print(f"  [*] Page {page_num}/{MAX_PAGES_PER_QUERY}: {url}")

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(1500)  # Let results render
        except Exception as e:
            print(f"  [-] Failed to load page {page_num}: {e}")
            break

        # Check if Shodan returned a "no results" or error page
        if page.locator("text=No results found").count() > 0:
            print(f"  [*] No results on page {page_num}, stopping pagination.")
            break

        # Extract IPs
        ips = extract_ips_from_page(page)
        print(f"  [+] Found {len(ips)} IP(s) on page {page_num}")
        all_ips.update(ips)

        # Delay before loading next page
        if page_num < MAX_PAGES_PER_QUERY:
            time.sleep(PAGE_DELAY_SECONDS)

    return all_ips


# ─── Generator: yields structured progress dicts ────────────────────────────
def get_ip_query_ip_gen(queries):
    """
    Generator that authenticates with Shodan and scrapes IPs for a list of
    search queries, yielding structured progress dicts at each step.

    Yields:
        {"status": "login", "success": bool}
        {"status": "query_start", "query": int, "total_queries": int, "query_text": str}
        {"status": "page_done", "query": int, "total_queries": int, "page": int, "total_pages": int, "ips_found": int, "total_ips": int}
        {"status": "query_done", "query": int, "total_queries": int, "query_text": str, "query_ips": int, "total_ips": int}
        {"status": "complete", "total_ips": int, "ips": list[str]}
    """
    result = shodan_login()
    if result is None:
        yield {"status": "login", "success": False}
        return
    yield {"status": "login", "success": True}

    pw, browser, context, page = result
    all_ips = set()
    total_queries = len(queries)

    try:
        for idx, query in enumerate(queries, start=1):
            yield {
                "status": "query_start",
                "query": idx,
                "total_queries": total_queries,
                "query_text": query,
            }

            # ── Inline scrape_query logic so we can yield per-page progress ──
            encoded_query = quote(query)
            query_ips = set()

            for page_num in range(1, MAX_PAGES_PER_QUERY + 1):
                if page_num == 1:
                    url = f"https://www.shodan.io/search?query={encoded_query}"
                else:
                    url = f"https://www.shodan.io/search?query={encoded_query}&page={page_num}"

                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    page.wait_for_timeout(1500)
                except Exception:
                    break

                if page.locator("text=No results found").count() > 0:
                    break

                ips_on_page = extract_ips_from_page(page)
                query_ips.update(ips_on_page)
                all_ips.update(ips_on_page)

                yield {
                    "status": "page_done",
                    "query": idx,
                    "total_queries": total_queries,
                    "page": page_num,
                    "total_pages": MAX_PAGES_PER_QUERY,
                    "ips_found": len(ips_on_page),
                    "total_ips": len(all_ips),
                }

                if page_num < MAX_PAGES_PER_QUERY:
                    time.sleep(PAGE_DELAY_SECONDS)

            yield {
                "status": "query_done",
                "query": idx,
                "total_queries": total_queries,
                "query_text": query,
                "query_ips": len(query_ips),
                "total_ips": len(all_ips),
            }

            if idx < total_queries:
                time.sleep(PAGE_DELAY_SECONDS)

    finally:
        save_cookies(context)
        browser.close()
        pw.stop()

    yield {
        "status": "complete",
        "total_ips": len(all_ips),
        "ips": list(all_ips),
    }


# ─── Convenience wrapper (backward compatible) ──────────────────────────────
def get_ip_query_ip(queries):
    """
    Non-generator wrapper: scrapes IPs and returns the final list.
    Consumes get_ip_query_ip_gen() internally, printing progress.
    """
    ips = []
    for update in get_ip_query_ip_gen(queries):
        status = update["status"]
        if status == "login":
            if not update["success"]:
                print("[-] Login failed.")
                return []
        elif status == "query_start":
            print(f"\n[*] Query {update['query']}/{update['total_queries']}: \"{update['query_text']}\"")
        elif status == "page_done":
            print(f"  [*] Page {update['page']}/{update['total_pages']}: "
                  f"{update['ips_found']} IPs (total: {update['total_ips']})")
        elif status == "query_done":
            print(f"[+] Query done — {update['query_ips']} IPs this query, "
                  f"{update['total_ips']} total unique")
        elif status == "complete":
            ips = update["ips"]
            print(f"\n[+] Scraping complete. Total unique IPs: {update['total_ips']}")
    return ips
                                                        

# ─── Entry point ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_queries = [
        "port:80",
        "apache country:IN",
    ]
    ips = get_ip_query_ip(test_queries)
    print(f"\nExtracted IPs ({len(ips)}):")
    for ip in ips:
        print(f"  {ip}")