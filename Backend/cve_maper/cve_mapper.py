"""
CVE Mapper — NVD Fetch + ChatGPT Enrichment
=============================================
Fetches CVE data from NVD REST API, then enriches each CVE with
MITRE ATT&CK mapping and vulnerability walkthrough via ChatGPT
(browser automation using saved account cookies).

Usage:
    python cve_mapper.py CVE-2024-1234,CVE-2024-5678,CVE-2023-9999

Requires:
    - NIST_API_KEY in .env
    - ChatGPT account cookies (run add_chatgpt_account.py first)
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv
from playwright.sync_api import sync_playwright

# ─── Paths ───────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent        # Backend/cve_maper/
BACKEND_DIR = SCRIPT_DIR.parent                     # Backend/
ENV_PATH = BACKEND_DIR.parent / ".env"              # CTI_V2/.env
ERROR_JSON_DIR = SCRIPT_DIR / "error_json"          # debug files for failed parses

# Add Backend to sys.path so we can import db_manager
sys.path.insert(0, str(BACKEND_DIR))

load_dotenv(dotenv_path=ENV_PATH)
from db_manager import DBManager

# ─── Config ──────────────────────────────────────────────────────────────────
NVD_API_KEY = os.getenv("NIST_API_KEY", "")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CHATGPT_URL = "https://chatgpt.com/"
MAX_ACCOUNT_ROUNDS = 3      # circulate all accounts this many times before giving up
RESPONSE_TIMEOUT = 180      # seconds to wait for ChatGPT response
COPY_BUTTON_POLL = 3        # seconds between checks for copy button


# ═════════════════════════════════════════════════════════════════════════════
# NVD Rate Limiter
# ═════════════════════════════════════════════════════════════════════════════

class NVDRateLimiter:
    """
    Rolling-window rate limiter for NVD API.

    NVD limits:
      - Without API key:  5 requests per 30-second rolling window
      - With API key:    50 requests per 30-second rolling window

    NIST recommends sleeping several seconds between requests
    even with an API key to avoid firewall blocks.
    """

    def __init__(self, has_api_key: bool = False):
        self.window = 30  # rolling window in seconds
        if has_api_key:
            self.max_requests = 50
            self.min_gap = 2.0    # NIST recommended minimum gap
        else:
            self.max_requests = 5
            self.min_gap = 6.5    # ~5 req / 30s = 6s gap, + buffer
        self.timestamps = []      # timestamps of recent requests

    def wait(self):
        """Block until it's safe to make the next request."""
        now = time.time()

        # Purge timestamps outside the rolling window
        self.timestamps = [t for t in self.timestamps if now - t < self.window]

        # If we've hit the max, wait until the oldest request exits the window
        if len(self.timestamps) >= self.max_requests:
            wait_until = self.timestamps[0] + self.window
            sleep_time = wait_until - now + 0.5  # 0.5s safety buffer
            if sleep_time > 0:
                print(f"  [NVD] Rate limit: waiting {sleep_time:.1f}s "
                      f"({len(self.timestamps)}/{self.max_requests} requests in window)")
                time.sleep(sleep_time)

        # Enforce minimum gap between consecutive requests
        if self.timestamps:
            gap = now - self.timestamps[-1]
            if gap < self.min_gap:
                sleep_time = self.min_gap - gap
                time.sleep(sleep_time)

        # Record this request
        self.timestamps.append(time.time())

    def backoff(self, seconds: float = 30.0):
        """Called when NVD returns 403 — wait and clear the window."""
        print(f"  [NVD] 403 Forbidden — backing off {seconds:.0f}s...")
        time.sleep(seconds)
        self.timestamps.clear()


# Global rate limiter instance
_nvd_limiter = NVDRateLimiter(has_api_key=bool(NVD_API_KEY))


# ═════════════════════════════════════════════════════════════════════════════
# NVD Data Fetcher
# ═════════════════════════════════════════════════════════════════════════════

def fetch_nvd_data(cve_id: str, max_retries: int = 3) -> dict:
    """
    Fetch CVE data from NVD REST API and parse into a flat dict.
    Respects NVD rate limits using the global rolling-window limiter.

    Returns a dict with all the fields needed by db_manager.save_cve_nvd_data()
    or None on failure.
    """
    url = f"{NVD_BASE_URL}?cveId={cve_id}"
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    for attempt in range(1, max_retries + 1):
        # Wait for rate limiter before making the request
        _nvd_limiter.wait()

        print(f"  [NVD] Fetching {cve_id}...", end=" ")

        try:
            resp = requests.get(url, headers=headers, timeout=30)

            if resp.status_code == 403:
                print(f"403 Forbidden (attempt {attempt}/{max_retries})")
                _nvd_limiter.backoff(30.0)
                continue

            if resp.status_code == 429:
                print(f"429 Too Many Requests (attempt {attempt}/{max_retries})")
                _nvd_limiter.backoff(35.0)
                continue

            resp.raise_for_status()
            data = resp.json()
            break

        except requests.RequestException as e:
            print(f"FAILED ({e})")
            if attempt < max_retries:
                time.sleep(5)
                continue
            return None
    else:
        print(f"  [NVD] All {max_retries} attempts failed for {cve_id}")
        return None

    # Parse the NVD 2.0 response
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        print("NOT FOUND")
        return None

    cve_item = vulns[0].get("cve", {})
    print("OK")

    return _parse_nvd_cve(cve_id, cve_item, data)


def _parse_nvd_cve(cve_id: str, cve_item: dict, raw_response: dict) -> dict:
    """Extract all needed fields from NVD 2.0 CVE item."""

    # ── Description ──────────────────────────────────────────────────────
    descriptions = cve_item.get("descriptions", [])
    description = ""
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    # ── CWE ──────────────────────────────────────────────────────────────
    cwe_id = None
    cwe_name = None
    weaknesses = cve_item.get("weaknesses", [])
    for w in weaknesses:
        for desc in w.get("description", []):
            if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                cwe_id = desc["value"]
                # CWE name isn't in NVD response; we store just the ID
                # ChatGPT will fill in the name
                break
        if cwe_id:
            break

    # ── CVSS Metrics ─────────────────────────────────────────────────────
    metrics = cve_item.get("metrics", {})
    cvss_data = _extract_cvss(metrics)

    # ── Dates ────────────────────────────────────────────────────────────
    published = cve_item.get("published", "")
    last_modified = cve_item.get("lastModified", "")

    # ── References ───────────────────────────────────────────────────────
    references = cve_item.get("references", [])
    ref_list = []
    for ref in references:
        ref_list.append({
            "url": ref.get("url", ""),
            "tags": ref.get("tags", []),
        })

    # ── Affected Products (CPE) ──────────────────────────────────────────
    affected_products = _extract_affected_products(cve_item)

    return {
        "description": description,
        "cwe_id": cwe_id,
        "cwe_name": cwe_name,
        "cvss_version": cvss_data.get("version"),
        "cvss_vector": cvss_data.get("vector_string"),
        "attack_vector": cvss_data.get("attack_vector"),
        "attack_complexity": cvss_data.get("attack_complexity"),
        "privileges_required": cvss_data.get("privileges_required"),
        "user_interaction": cvss_data.get("user_interaction"),
        "scope": cvss_data.get("scope"),
        "confidentiality_impact": cvss_data.get("confidentiality_impact"),
        "integrity_impact": cvss_data.get("integrity_impact"),
        "availability_impact": cvss_data.get("availability_impact"),
        "base_score": cvss_data.get("base_score"),
        "severity": cvss_data.get("severity"),
        "published_date": published,
        "last_modified_date": last_modified,
        "reference_urls": ref_list,
        "affected_products": affected_products,
        "nvd_raw": raw_response,
    }


def _extract_cvss(metrics: dict) -> dict:
    """Extract CVSS data, preferring v3.1 > v3.0 > v2.0."""
    result = {
        "version": None, "vector_string": None, "attack_vector": None,
        "attack_complexity": None, "privileges_required": None,
        "user_interaction": None, "scope": None,
        "confidentiality_impact": None, "integrity_impact": None,
        "availability_impact": None, "base_score": None, "severity": None,
    }

    # Try CVSS v3.1 first, then v3.0
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            cvss = entries[0].get("cvssData", {})
            result["version"] = cvss.get("version")
            result["vector_string"] = cvss.get("vectorString")
            result["attack_vector"] = cvss.get("attackVector")
            result["attack_complexity"] = cvss.get("attackComplexity")
            result["privileges_required"] = cvss.get("privilegesRequired")
            result["user_interaction"] = cvss.get("userInteraction")
            result["scope"] = cvss.get("scope")
            result["confidentiality_impact"] = cvss.get("confidentialityImpact")
            result["integrity_impact"] = cvss.get("integrityImpact")
            result["availability_impact"] = cvss.get("availabilityImpact")
            result["base_score"] = cvss.get("baseScore")
            result["severity"] = entries[0].get("exploitabilityScore") and \
                cvss.get("baseSeverity")
            # baseSeverity is directly in cvssData for v3
            if not result["severity"]:
                result["severity"] = cvss.get("baseSeverity")
            return result

    # Fallback to CVSS v2
    v2_entries = metrics.get("cvssMetricV2", [])
    if v2_entries:
        cvss = v2_entries[0].get("cvssData", {})
        result["version"] = cvss.get("version")
        result["vector_string"] = cvss.get("vectorString")
        result["attack_vector"] = cvss.get("accessVector")
        result["attack_complexity"] = cvss.get("accessComplexity")
        result["base_score"] = cvss.get("baseScore")
        result["severity"] = v2_entries[0].get("baseSeverity")
        result["confidentiality_impact"] = cvss.get("confidentialityImpact")
        result["integrity_impact"] = cvss.get("integrityImpact")
        result["availability_impact"] = cvss.get("availabilityImpact")

    return result


def _extract_affected_products(cve_item: dict) -> list:
    """Extract affected products from CPE configurations."""
    products = []
    configurations = cve_item.get("configurations", [])

    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                cpe_uri = match.get("criteria", "")
                parts = cpe_uri.split(":")
                # CPE 2.3 format: cpe:2.3:a:vendor:product:version:...
                if len(parts) >= 6:
                    vendor = parts[3] if parts[3] != "*" else None
                    product = parts[4] if parts[4] != "*" else None
                    version = parts[5] if parts[5] != "*" else None

                    # Build version range string if available
                    ver_start = match.get("versionStartIncluding") or \
                                match.get("versionStartExcluding")
                    ver_end = match.get("versionEndIncluding") or \
                              match.get("versionEndExcluding")
                    if ver_start or ver_end:
                        version = f"{ver_start or '*'} - {ver_end or '*'}"

                    platform = parts[10] if len(parts) > 10 and parts[10] != "*" else None

                    products.append({
                        "vendor": vendor,
                        "product": product,
                        "version": version,
                        "affected_platform": platform,
                    })

    return products


# ═════════════════════════════════════════════════════════════════════════════
# ChatGPT Prompt Builder
# ═════════════════════════════════════════════════════════════════════════════

def build_chatgpt_prompt(cve_id: str, nvd_data: dict) -> str:
    """
    Build a focused prompt that asks ChatGPT for only what NVD can't provide:
    - MITRE ATT&CK mapping with justification
    - Step-by-step vulnerability walkthrough
    """

    # Build the NVD context block
    products_str = ""
    for p in nvd_data.get("affected_products", []):
        v = p.get("vendor") or "unknown"
        pr = p.get("product") or "unknown"
        ver = p.get("version") or "all"
        products_str += f"  - {v} / {pr} (version: {ver})\n"
    if not products_str:
        products_str = "  - Not available from NVD\n"

    refs_str = ""
    for r in nvd_data.get("reference_urls", [])[:5]:
        refs_str += f"  - {r.get('url', '')}\n"
    if not refs_str:
        refs_str = "  - None\n"

    nist_context = f"""
CVE ID: {cve_id}
Description: {nvd_data.get('description', 'N/A')}
CWE: {nvd_data.get('cwe_id', 'N/A')}
CVSS: {nvd_data.get('base_score', 'N/A')} ({nvd_data.get('severity', 'N/A')})
Vector: {nvd_data.get('cvss_vector', 'N/A')}
Attack Vector: {nvd_data.get('attack_vector', 'N/A')}
Attack Complexity: {nvd_data.get('attack_complexity', 'N/A')}
Privileges Required: {nvd_data.get('privileges_required', 'N/A')}
User Interaction: {nvd_data.get('user_interaction', 'N/A')}
Scope: {nvd_data.get('scope', 'N/A')}
C/I/A Impact: {nvd_data.get('confidentiality_impact', 'N/A')} / {nvd_data.get('integrity_impact', 'N/A')} / {nvd_data.get('availability_impact', 'N/A')}
Published: {nvd_data.get('published_date', 'N/A')}
Affected Products:
{products_str}
References:
{refs_str}""".strip()

    prompt = f"""You are a cybersecurity vulnerability analyst. Analyze the following CVE and return ONLY valid JSON inside a ```json code block.

CRITICAL JSON RULES:
- Output MUST be inside a ```json code block
- Output MUST be valid, parseable JSON — no trailing commas, no comments
- All string values must use proper JSON escaping (backslashes must be \\\\, quotes must be \\")
- URLs must be plain strings, no markdown links
- Do NOT include any text outside the JSON code block

{nist_context}

I need TWO things from you:

1. MITRE ATT&CK MAPPING: Map this vulnerability to relevant ATT&CK tactics and techniques. For each mapping, explain why this CVE maps to that technique.

2. VULNERABILITY WALKTHROUGH: Provide a clear, step-by-step technical explanation of how this vulnerability works — from initial conditions through exploitation to impact. Be specific and technical.

Additionally, include:
- A concise title for this vulnerability
- Whether known exploits exist (check your knowledge)
- Mitigation recommendations
- Detection recommendations

Return JSON in exactly this structure inside a ```json code block:

```json
{{
  "cve_id": "{cve_id}",
  "title": "",
  "exploitation": {{
    "known_exploited": false,
    "exploit_available": false,
    "exploit_sources": []
  }},
  "mitre_attack_mapping": [
    {{
      "tactic_id": "",
      "tactic_name": "",
      "technique_id": "",
      "technique_name": "",
      "justification": ""
    }}
  ],
  "vulnerability_walkthrough": [
    "Step 1: ...",
    "Step 2: ...",
    "Step 3: ..."
  ],
  "mitigations": [
    ""
  ],
  "detection_recommendations": [
    ""
  ],
  "references": [
    {{
      "source": "",
      "url": ""
    }}
  ]
}}
```"""
    return prompt


# ═════════════════════════════════════════════════════════════════════════════
# ChatGPT Browser Automation (Persistent Profile Based)
# ═════════════════════════════════════════════════════════════════════════════

# ─── Selectors (updated for 2026 ChatGPT DOM) ────────────────────────────────
# ChatGPT frequently changes its DOM. We use multiple fallback selectors
# and prefer role/placeholder-based selectors over brittle IDs.

# Prompt input: ChatGPT may use a <textarea>, a contenteditable <div>, or
# a ProseMirror editor. We try the known ID first, then fall back to
# role-based and placeholder-based selectors.
_PROMPT_SELECTORS = [
    "#prompt-textarea",                              # Classic textarea ID
    'div[contenteditable="true"][id="prompt-textarea"]',  # Contenteditable variant
    'div.ProseMirror[contenteditable="true"]',        # ProseMirror editor
    '[data-testid="composer-input"]',                # Test ID variant
]
_PROMPT_SELECTOR = "#prompt-textarea"  # Legacy compat — used in some places

# Send button: multiple fallback selectors
_SEND_BUTTON_SELECTORS = [
    '#composer-submit-button',
    'button[data-testid="send-button"]',
    'button[aria-label="Send prompt"]',
    'button[aria-label="Send"]',
]
_SEND_BUTTON_SELECTOR = ', '.join(_SEND_BUTTON_SELECTORS)

# Assistant message containers
_ASSISTANT_SELECTORS = [
    '[data-message-author-role="assistant"]',
    'div[data-message-author-role="assistant"]',
    'article[data-testid*="conversation-turn"] div.agent-turn',
]
_ASSISTANT_SELECTOR = '[data-message-author-role="assistant"]'

# Stop / streaming buttons
_STOP_BUTTON_SELECTOR = (
    'button[data-testid="stop-button"], '
    'button[aria-label="Stop generating"], '
    'button[aria-label="Stop streaming"]'
)

# Login/signup buttons — ONLY the ones in the TOP HEADER area.
# ChatGPT now shows a "Log in" prompt in the sidebar even to non-logged-in
# users, alongside the prompt textarea. We must NOT match that sidebar CTA.
# The header buttons are the reliable signal for "not logged in".
_HEADER_LOGIN_SELECTORS = [
    # Top-right header buttons (the primary login/signup action area)
    'nav button:has-text("Log in")',
    'header button:has-text("Log in")',
    'div[class*="header"] button:has-text("Log in")',
    # The "Sign up for free" button is always in the header
    'button:has-text("Sign up for free")',
    'a:has-text("Sign up for free")',
]
# Keeping old names for backward compat but they now check the header
_LOGIN_BUTTON_SELECTOR = 'button:has-text("Log in")'
_SIGNUP_BUTTON_SELECTOR = 'button:has-text("Sign up for free")'

# Indicators that the user IS authenticated (these never appear when logged out)
_LOGGED_IN_INDICATORS = [
    'button[data-testid="profile-button"]',       # User avatar / profile button
    'nav button[aria-label*="menu" i]',            # User menu
    'button[aria-label="Open sidebar"]',           # Sidebar toggle (only for logged-in)
    'img[alt="User"]',                              # User avatar image
    'div[data-testid="user-menu"]',                # User menu container
    '[data-testid="history"]',                     # Chat history panel
]

# Placeholder texts ChatGPT shows while thinking
_PLACEHOLDER_TEXTS = {
    "thinking", "searching", "analyzing", "looking",
    "reasoning", "browsing", "generating",
}

# Rate-limit phrases
_RATE_LIMIT_TEXTS = [
    "you've reached the current usage cap",
    "you've reached the limit",
    "rate limit",
    "too many requests",
    "usage cap",
    "temporarily unavailable",
]

# Response stabilisation settings
_POLL_INTERVAL = 1.0    # seconds between stability checks
_STABLE_CHECKS = 5      # consecutive identical polls = "done"

# Accounts directory
_ACCOUNTS_DIR = Path(__file__).resolve().parent / ".accounts"
_ACCOUNTS_FILE = _ACCOUNTS_DIR / "accounts.json"


def _find_prompt_element(page, timeout_ms: int = 5000):
    """Find the prompt input element using multiple fallback selectors.

    Returns the element handle, or None if not found.
    """
    for sel in _PROMPT_SELECTORS:
        try:
            el = page.wait_for_selector(sel, timeout=timeout_ms)
            if el and el.is_visible():
                return el
        except Exception:
            continue

    # Last resort: find by placeholder text
    try:
        el = page.locator('[placeholder*="ChatGPT" i], [placeholder*="Message" i]').first
        if el.count() > 0 and el.is_visible():
            return el.element_handle()
    except Exception:
        pass

    return None


def _has_header_login_buttons(page) -> bool:
    """Return True if the TOP HEADER 'Log in' or 'Sign up' buttons are visible.

    This specifically avoids matching the sidebar "Log in" CTA that ChatGPT
    now shows to everyone (even on the logged-out home page alongside the
    prompt textarea).
    """
    try:
        for sel in _HEADER_LOGIN_SELECTORS:
            try:
                loc = page.locator(sel)
                if loc.count() > 0 and loc.first.is_visible():
                    return True
            except Exception:
                continue
    except Exception:
        pass
    return False


# Keep old name for backward compat
def _has_login_buttons(page) -> bool:
    """Return True if login/signup buttons are visible (= NOT logged in).

    Updated to check HEADER buttons, not sidebar CTAs.
    """
    return _has_header_login_buttons(page)


def _has_logged_in_indicators(page) -> bool:
    """Return True if any logged-in-only UI elements are present."""
    for sel in _LOGGED_IN_INDICATORS:
        try:
            loc = page.locator(sel)
            if loc.count() > 0 and loc.first.is_visible():
                return True
        except Exception:
            continue
    return False


def _is_logged_in(page, timeout_ms: int = 8000) -> bool:
    """Return True if the user is genuinely authenticated.

    Uses a multi-signal approach:
      1. If header 'Log in' / 'Sign up' buttons are visible → NOT logged in
      2. If logged-in-only indicators (profile button, history) exist → logged in
      3. If the prompt textarea is found AND no header login buttons → logged in
      4. Extra wait + re-check for slow page loads

    ChatGPT now shows the prompt textarea to EVERYONE (even logged-out users),
    so we can't rely on the textarea alone as proof of authentication.
    """
    try:
        if "chatgpt.com" not in page.url.lower():
            return False

        # Wait for page to settle
        page.wait_for_load_state("domcontentloaded", timeout=10000)
        page.wait_for_timeout(2000)  # Extra settle time for SPAs

        # Signal 1: Header login/signup buttons visible = definitely NOT logged in
        if _has_header_login_buttons(page):
            print("[login-check] Header login buttons found → not logged in")
            return False

        # Signal 2: Logged-in indicators present = definitely logged in
        if _has_logged_in_indicators(page):
            print("[login-check] Logged-in indicators found → authenticated")
            return True

        # Signal 3: Prompt textarea visible + no header login buttons
        prompt = _find_prompt_element(page, timeout_ms=timeout_ms)
        if prompt:
            # Double-check that login buttons didn't just appear
            if not _has_header_login_buttons(page):
                # Check if there's a sidebar login CTA (the "Get responses
                # tailored to you... Log in" section). If that's the ONLY
                # login indicator, we're NOT logged in.
                try:
                    sidebar_login = page.locator(
                        'text="Get responses tailored to you"'
                    )
                    if sidebar_login.count() > 0 and sidebar_login.first.is_visible():
                        print("[login-check] Sidebar login CTA found → not logged in")
                        return False
                except Exception:
                    pass

                print("[login-check] Prompt found, no login buttons → authenticated")
                return True

        # Signal 4: Last resort — wait a bit more and re-check
        page.wait_for_timeout(3000)
        if _has_logged_in_indicators(page):
            print("[login-check] (retry) Logged-in indicators found → authenticated")
            return True
        if _has_header_login_buttons(page):
            print("[login-check] (retry) Header login buttons found → not logged in")
            return False

    except Exception as e:
        print(f"[login-check] Error: {e}")

    return False


def _detect_rate_limit(page) -> bool:
    """Check whether the page shows a rate-limit or usage-cap message."""
    try:
        body_text = page.inner_text("body").lower()
        for phrase in _RATE_LIMIT_TEXTS:
            if phrase in body_text:
                print(f"    [ChatGPT] Rate limit detected: '{phrase}'")
                return True
    except Exception:
        pass
    return False


class ChatGPTSession:
    """
    Persistent browser session for ChatGPT using launch_persistent_context.
    Keeps the browser open across multiple prompts for batch processing.
    """

    def __init__(self, playwright):
        self.pw = playwright
        self._context = None
        self._page = None
        self._is_open = False
        self.current_account_id = None
        self.current_account_label = None

    def open(self, profile_dir: str, account_id: str = "", label: str = "") -> bool:
        """Launch browser with a persistent profile and verify login."""
        self.close()  # clean up any previous session

        self.current_account_id = account_id
        self.current_account_label = label or account_id

        print(f"  [ChatGPT] Opening session: {self.current_account_label}...", end=" ")

        try:
            self._context = self.pw.chromium.launch_persistent_context(
                user_data_dir=profile_dir,
                headless=False,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                ],
                viewport={"width": 1280, "height": 900},
            )

            # Anti-detection
            self._context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => false});
            """)

            self._page = (
                self._context.pages[0]
                if self._context.pages
                else self._context.new_page()
            )

            self._page.goto(CHATGPT_URL, wait_until="domcontentloaded", timeout=60000)

            if _is_logged_in(self._page):
                print("OK (logged in)")
                self._is_open = True
                return True
            else:
                print("FAILED (not logged in — re-register this account)")
                self.close()
                return False

        except Exception as e:
            print(f"FAILED ({e})")
            self.close()
            return False

    def send_prompt(self, prompt: str) -> str:
        """
        Send a prompt in a new chat and return the full response text.
        Returns 'RATE_LIMITED' on rate limit, None on error.
        """
        if not self._is_open or not self._page:
            return None

        page = self._page

        try:
            # ── Ensure fresh chat ─────────────────────────────────────────
            # If we are already on a conversation URL (/c/...) or messages exist in the view,
            # navigate to the fresh chat root so messages don't accumulate.
            needs_nav = "/c/" in page.url or len(self._find_assistant_messages()) > 0
            if needs_nav:
                print(f"    [ChatGPT] Opening fresh chat...")
                navigated = False
                try:
                    new_btn = page.locator(
                        'a[href="/"], button[aria-label="New chat"], '
                        'a[data-testid="create-new-chat-button"]'
                    ).first
                    if new_btn.count() > 0 and new_btn.is_visible():
                        new_btn.click()
                        page.wait_for_timeout(1500)
                        if "/c/" not in page.url and len(self._find_assistant_messages()) == 0:
                            navigated = True
                except Exception:
                    pass

                if not navigated:
                    try:
                        page.goto(CHATGPT_URL, wait_until="domcontentloaded", timeout=30000)
                        page.wait_for_timeout(2000)
                    except Exception as e:
                        print(f"    [ChatGPT] Navigation notice: {e}")

            # Wait for prompt input
            prompt_el = _find_prompt_element(page, timeout_ms=8000)
            if not prompt_el:
                if _has_login_buttons(page):
                    print(f"    [ChatGPT] Session expired!")
                    return "RATE_LIMITED"
                if _detect_rate_limit(page):
                    return "RATE_LIMITED"
                print(f"    [ChatGPT] Prompt input not found!")
                return None

            # Count existing assistant messages (to detect NEW ones later)
            existing_msgs = self._find_assistant_messages()
            pre_count = len(existing_msgs)

            # ── Paste the prompt ─────────────────────────────────────────
            CHUNK_SIZE = 3000
            print(f"    [ChatGPT] Pasting prompt ({len(prompt)} chars"
                  f"{', chunked' if len(prompt) > CHUNK_SIZE else ''})...")

            # Focus the prompt input
            try:
                prompt_el.click(force=True)
            except Exception:
                try:
                    prompt_el.focus()
                except Exception:
                    pass
            page.wait_for_timeout(300)

            if len(prompt) <= CHUNK_SIZE:
                page.evaluate("text => navigator.clipboard.writeText(text)", prompt)
                page.keyboard.press("Control+v")
                page.wait_for_timeout(500)
            else:
                chunks = [prompt[i:i + CHUNK_SIZE]
                          for i in range(0, len(prompt), CHUNK_SIZE)]
                for idx, chunk in enumerate(chunks):
                    page.evaluate(
                        "text => navigator.clipboard.writeText(text)", chunk
                    )
                    page.keyboard.press("Control+v")
                    page.wait_for_timeout(300)
                print(f"    [ChatGPT] Pasted in {len(chunks)} chunks.")

            # Give UI a moment to register input and enable send button
            page.wait_for_timeout(1500)

            # ── Click Send ───────────────────────────────────────────────
            send_btn = self._find_send_button()
            if not send_btn:
                if _detect_rate_limit(page):
                    return "RATE_LIMITED"
                print(f"    [ChatGPT] Send button not found!")
                return "RATE_LIMITED"

            # Check if send button is disabled (= message limit reached)
            try:
                is_disabled = send_btn.get_attribute("disabled") is not None
                aria_disabled = send_btn.get_attribute("aria-disabled")
                if is_disabled or aria_disabled == "true":
                    print(f"    [ChatGPT] Send button is DISABLED — message limit reached!")
                    return "RATE_LIMITED"
            except Exception:
                pass

            sent = False
            try:
                send_btn.click(force=True)
                sent = True
                print(f"    [ChatGPT] Send button clicked.")
            except Exception:
                pass

            if not sent:
                try:
                    page.keyboard.press("Enter")
                    sent = True
                    print(f"    [ChatGPT] Sent via Enter key.")
                except Exception:
                    pass

            if not sent:
                if _detect_rate_limit(page):
                    return "RATE_LIMITED"
                print(f"    [ChatGPT] Could not send prompt!")
                return "RATE_LIMITED"

            # Wait briefly for ChatGPT to register the prompt and begin generation
            page.wait_for_timeout(2000)

            # ── Wait for full response ───────────────────────────────────
            response_text = self._wait_for_new_response(pre_count)
            return response_text

        except Exception as e:
            print(f"    [ChatGPT] Error: {e}")
            import traceback
            traceback.print_exc()
            return None

    def _find_send_button(self):
        """Find the send button using multiple fallback selectors."""
        page = self._page
        for sel in _SEND_BUTTON_SELECTORS:
            try:
                loc = page.locator(sel)
                if loc.count() > 0 and loc.first.is_visible():
                    return loc.first.element_handle()
            except Exception:
                continue

        # Last resort: find by aria-label containing 'send' (case-insensitive)
        try:
            loc = page.locator('button[aria-label*="end" i]')
            if loc.count() > 0 and loc.first.is_visible():
                return loc.first.element_handle()
        except Exception:
            pass

        return None

    def _find_assistant_messages(self) -> list:
        """Find all assistant message elements using multiple selectors.

        Ensures user message turns are excluded.
        """
        page = self._page

        # 1. Primary selectors — attribute-based (most reliable historically)
        primary_selectors = [
            '[data-message-author-role="assistant"]',
            'div[data-message-author-role="assistant"]',
            'article[data-message-author-role="assistant"]',
        ]
        for sel in primary_selectors:
            try:
                elements = page.query_selector_all(sel)
                if elements:
                    return elements
            except Exception:
                continue

        # 2. Secondary selectors — structure/button-based
        # (Only assistant messages have Copy response/code buttons or agent-turn class)
        secondary_selectors = [
            'article:has(button[aria-label*="Copy" i])',
            'div.agent-turn',
            'div[class*="agent-turn"]',
        ]
        for sel in secondary_selectors:
            try:
                elements = page.query_selector_all(sel)
                if elements:
                    return elements
            except Exception:
                continue

        # 3. Filtered turns: check turns that are NOT user messages
        try:
            turns = page.query_selector_all('article[data-testid*="conversation-turn"]')
            assistant_turns = []
            for turn in turns:
                try:
                    if turn.query_selector('[data-message-author-role="user"]'):
                        continue
                    if (turn.query_selector('.markdown, pre, div.prose, button[aria-label*="Copy" i]')
                            or turn.query_selector('[data-message-author-role="assistant"]')):
                        assistant_turns.append(turn)
                except Exception:
                    continue
            if assistant_turns:
                return assistant_turns
        except Exception:
            pass

        return []

    def _is_generating(self) -> bool:
        """Check if ChatGPT is actively generating/streaming a response."""
        page = self._page
        stop_selectors = [
            'button[data-testid="stop-button"]',
            'button[aria-label="Stop generating"]',
            'button[aria-label="Stop streaming"]',
        ]
        for sel in stop_selectors:
            try:
                loc = page.locator(sel)
                if loc.count() > 0 and loc.first.is_visible():
                    return True
            except Exception:
                continue
        return False

    def _has_copy_button(self) -> bool:
        """Check if a Copy button is visible (indicates response completion)."""
        page = self._page
        copy_selectors = [
            'button[aria-label="Copy response"]',
            'button[aria-label="Copy code"]',
            'button[data-testid*="copy" i]',
            'button[aria-label="Copy"]',
        ]
        for sel in copy_selectors:
            try:
                loc = page.locator(sel)
                if loc.count() > 0 and loc.first.is_visible():
                    return True
            except Exception:
                continue
        return False

    def _dump_dom_debug(self):
        """Log diagnostic information about the page DOM."""
        page = self._page
        print("    [DEBUG] === DOM Diagnostic Dump ===")
        checks = [
            ('[data-message-author-role]', 'data-message-author-role elements'),
            ('[data-message-id]', 'data-message-id elements'),
            ('article', 'article elements'),
            ('div.agent-turn', 'agent-turn divs'),
            ('div[class*="agent"]', 'agent class divs'),
            ('div.markdown', 'markdown divs'),
            ('div.prose', 'prose divs'),
            ('pre code', 'code blocks'),
            ('pre', 'pre blocks'),
            ('button[aria-label*="Copy" i]', 'Copy buttons'),
            ('button[data-testid="stop-button"]', 'Stop testid button'),
            ('button[aria-label="Stop generating"]', 'Stop generating button'),
        ]
        for selector, label in checks:
            try:
                count = len(page.query_selector_all(selector))
                if count > 0:
                    print(f"    [DEBUG]   ✓ {label}: {count}")
            except Exception:
                pass
        print("    [DEBUG] === End Diagnostic Dump ===")

    def _wait_for_new_response(self, prev_count: int) -> str:
        """
        Wait for a NEW assistant message and for it to fully complete.
        Extracts clean JSON as soon as generation finishes or valid JSON is stable.
        """
        page = self._page
        print(f"    [ChatGPT] Waiting for response to start (prev msgs: {prev_count})...")

        # Step 1: Wait for response element to appear OR stop button to indicate generating
        deadline = time.time() + 60
        found = False
        while time.time() < deadline:
            try:
                from engine_progress import is_cancelled
                if is_cancelled():
                    raise InterruptedError("Engine cancelled by user")
            except ImportError:
                pass

            elements = self._find_assistant_messages()
            if elements and len(elements) > prev_count:
                found = True
                print(f"    [ChatGPT] Response element appeared ({len(elements)} msgs)...")
                break

            # If stop button is visible, generation has definitely started!
            if self._is_generating():
                found = True
                print(f"    [ChatGPT] Response generation in progress (stop button active)...")
                break

            # Fallback: check if any code block appeared on page
            try:
                if page.locator("pre code, pre").count() > 0:
                    found = True
                    print(f"    [ChatGPT] Code block detected on page...")
                    break
            except Exception:
                pass

            time.sleep(1)

        if not found:
            if _detect_rate_limit(page):
                return "RATE_LIMITED"

            print(f"    [ChatGPT] No response element detected in 60s. Trying fallback extraction...")
            fallback_text = self._extract_response_fallback()
            if fallback_text and len(fallback_text) > 100:
                print(f"    [ChatGPT] Fallback extraction got {len(fallback_text)} chars")
                return fallback_text

            print(f"    [ChatGPT] No response appeared after 60s!")
            return None

        # Step 2: Poll until generation stops AND JSON is extracted
        max_time = time.time() + 180  # Max 3 minutes generation
        stable_count = 0
        prev_len = 0
        poll_num = 0

        while time.time() < max_time:
            try:
                from engine_progress import is_cancelled
                if is_cancelled():
                    raise InterruptedError("Engine cancelled by user")
            except ImportError:
                pass

            time.sleep(2)
            poll_num += 1

            # 1. Extract current text
            current_text = self._extract_response_text(prev_count)
            if not current_text:
                current_text = self._extract_response_fallback()

            # 2. Track text length stability
            curr_len = len(current_text) if current_text else 0
            if curr_len > 0 and curr_len == prev_len:
                stable_count += 1
            else:
                stable_count = 0
                prev_len = curr_len
                if poll_num % 5 == 0 and curr_len > 0:
                    print(f"    [ChatGPT] Poll #{poll_num}: text streaming ({curr_len} chars)...")

            # 3. Check for "Continue generating" button
            try:
                continue_btn = page.locator("button:has-text('Continue generating')")
                if continue_btn.count() > 0 and continue_btn.first.is_visible():
                    print(f"    [ChatGPT] Clicking 'Continue generating'...")
                    continue_btn.first.click()
                    stable_count = 0
                    time.sleep(2)
                    continue
            except Exception:
                pass

            # 4. Check status indicators
            is_generating = self._is_generating()
            has_copy = self._has_copy_button()

            # 5. Quick validation: if we already have valid parseable JSON
            if current_text and curr_len > 150:
                parsed = parse_chatgpt_response(current_text)
                if parsed and validate_chatgpt_response(parsed):
                    # If stop button is gone OR copy button is present OR text is stable:
                    if not is_generating or has_copy or stable_count >= 2:
                        print(f"    [ChatGPT] Valid complete JSON captured ({curr_len} chars)!")
                        return current_text

            # 6. If generation finished (stop button gone) and text is stable
            if not is_generating and stable_count >= 2 and current_text and curr_len > 50:
                print(f"    [ChatGPT] Generation finished & text stable ({curr_len} chars)")
                return current_text

            # 7. If Copy button appeared and text is stable
            if has_copy and stable_count >= 1 and current_text and curr_len > 50:
                print(f"    [ChatGPT] Copy button visible & text stable ({curr_len} chars)")
                return current_text

            # 8. Hard escape: stable for 16 seconds (8 polls) even if stop button is somehow stuck
            if stable_count >= 8 and current_text and curr_len > 100:
                print(f"    [ChatGPT] Text stable for 16s. Capturing output ({curr_len} chars)")
                return current_text

        # If loop finishes without returning, try one last extract
        final_text = self._extract_response_text(prev_count) or self._extract_response_fallback()
        if final_text and len(final_text) >= 50:
            print(f"    [ChatGPT] Captured response at timeout ({len(final_text)} chars)")
            return final_text

        print(f"    [ChatGPT] Failed to capture response within timeout.")
        return None

    def _extract_response_text(self, prev_count: int = 0) -> str:
        """
        Extract the latest assistant response text.
        Prioritizes complete JSON objects from <pre> code blocks or message text.
        """
        page = self._page
        elements = self._find_assistant_messages()
        if not elements or len(elements) <= prev_count:
            return None

        last_msg = elements[-1]

        # Strategy 1: Code blocks inside the assistant message
        try:
            pre_blocks = last_msg.query_selector_all("pre")
            for pre in pre_blocks:
                try:
                    text = pre.text_content().strip()
                    json_obj = extract_json_object(text)
                    if json_obj and len(json_obj) > 100:
                        return json_obj
                    if text and '{' in text and len(text) > 100:
                        return text
                except Exception:
                    continue
        except Exception:
            pass

        # Strategy 2: Entire message inner text
        try:
            text = last_msg.inner_text().strip()
            if text:
                json_obj = extract_json_object(text)
                if json_obj and len(json_obj) > 100:
                    return json_obj

                fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
                if fence_match and len(fence_match.group(1).strip()) > 100:
                    return fence_match.group(1).strip()

                return text
        except Exception:
            pass

        return None

    def _extract_response_fallback(self) -> str:
        """
        Find JSON anywhere on the page if assistant container matching failed.
        """
        page = self._page

        # Strategy 1: All <pre> elements anywhere on page
        try:
            pre_blocks = page.query_selector_all("pre")
            candidates = []
            for pre in pre_blocks:
                try:
                    text = pre.text_content().strip()
                    json_obj = extract_json_object(text)
                    if json_obj and len(json_obj) > 100:
                        candidates.append(json_obj)
                    elif text and '{' in text and len(text) > 100:
                        candidates.append(text)
                except Exception:
                    continue
            if candidates:
                return max(candidates, key=len)
        except Exception:
            pass

        # Strategy 2: All markdown / prose blocks
        try:
            blocks = page.query_selector_all(".markdown, div.prose")
            candidates = []
            for b in blocks:
                try:
                    text = b.inner_text().strip()
                    json_obj = extract_json_object(text)
                    if json_obj and len(json_obj) > 100:
                        candidates.append(json_obj)
                    elif text and '{' in text and len(text) > 100:
                        candidates.append(text)
                except Exception:
                    continue
            if candidates:
                return max(candidates, key=len)
        except Exception:
            pass

        # Strategy 3: Page body text
        try:
            body_text = page.inner_text("body")
            json_obj = extract_json_object(body_text)
            if json_obj and len(json_obj) > 150:
                return json_obj
        except Exception:
            pass

        return None

    def is_rate_limited(self, response: str) -> bool:
        """Check if the response indicates a rate limit."""
        return response == "RATE_LIMITED" if response else False

    def close(self):
        """Close the browser and clean up."""
        if self._context:
            try:
                self._context.close()
            except Exception:
                pass
            self._context = None
            self._page = None
        self._is_open = False



# ═════════════════════════════════════════════════════════════════════════════
# Response Parser
# ═════════════════════════════════════════════════════════════════════════════

def extract_json_object(text: str) -> str:
    """
    Extract the first complete, balanced JSON object { ... } from text.
    Correctly handles nested braces, strings, and escaped characters.
    Returns None if no complete object is found.
    """
    if not text:
        return None

    start = text.find('{')
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape = False

    for i in range(start, len(text)):
        char = text[i]

        if escape:
            escape = False
            continue

        if char == '\\':
            escape = True
            continue

        if char == '"':
            in_string = not in_string
            continue

        if not in_string:
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]

    return None


def _looks_like_json(text: str) -> bool:
    """Return True if text appears to contain JSON."""
    if not text:
        return False
    stripped = text.lstrip()
    if stripped.startswith('{'):
        return True
    if stripped.startswith('```'):
        rest = re.sub(r'^```(?:json)?\s*', '', stripped)
        return rest.lstrip().startswith('{')
    return '{' in text and '}' in text


def _json_looks_complete(text: str) -> bool:
    """Return True if the JSON response looks structurally complete."""
    extracted = extract_json_object(text)
    return extracted is not None


def parse_chatgpt_response(response_text: str) -> dict:
    """
    Parse ChatGPT's response text into a JSON dict.

    Handles:
      - Raw JSON text
      - Markdown code fences (```json ... ``` or ``` ... ```)
      - Intro/outro text around the JSON object (via balanced bracket extraction)
      - Common LLM syntax quirks (trailing commas before } or ])
    Returns None if parsing fails.
    """
    if not response_text:
        return None

    text = response_text.strip()

    # Attempt 1: Direct parse
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    # Attempt 2: Strip outer markdown code fences
    cleaned = re.sub(r'^```(?:json)?\s*', '', text)
    cleaned = re.sub(r'\s*```$', '', cleaned.strip())
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    # Attempt 3: Balanced-bracket JSON extraction (handles surrounding prose)
    extracted = extract_json_object(text)
    if extracted:
        try:
            parsed = json.loads(extracted)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            # Try fixing trailing commas: e.g. ", }" -> " }" or ", ]" -> " ]"
            fixed = re.sub(r',\s*([\]}])', r'\1', extracted)
            try:
                parsed = json.loads(fixed)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass

    # Attempt 4: Extract from regex markdown code block
    json_block = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if json_block:
        block_text = json_block.group(1).strip()
        try:
            parsed = json.loads(block_text)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            block_extracted = extract_json_object(block_text)
            if block_extracted:
                fixed_block = re.sub(r',\s*([\]}])', r'\1', block_extracted)
                try:
                    parsed = json.loads(fixed_block)
                    if isinstance(parsed, dict):
                        return parsed
                except Exception:
                    pass

    # All attempts failed
    print(f"    [!] JSON parse failed. Response preview: "
          f"{response_text[:200]}...")
    return None


def validate_chatgpt_response(parsed: dict) -> bool:
    """
    Validate that the parsed response has useful structure.
    Accept if it has EITHER mitre_attack_mapping OR vulnerability_walkthrough,
    since partial data is still valuable.
    """
    if not parsed:
        return False

    has_mitre = (
        "mitre_attack_mapping" in parsed
        and isinstance(parsed["mitre_attack_mapping"], list)
        and len(parsed["mitre_attack_mapping"]) > 0
    )

    has_walkthrough = (
        "vulnerability_walkthrough" in parsed
        and isinstance(parsed["vulnerability_walkthrough"], list)
        and len(parsed["vulnerability_walkthrough"]) > 0
    )

    # Accept if we have at least one useful section
    return has_mitre or has_walkthrough


# ═════════════════════════════════════════════════════════════════════════════
# Account Manager (Persistent Profile Based)
# ═════════════════════════════════════════════════════════════════════════════

def _load_accounts() -> list:
    """Load accounts from the registry file."""
    if not _ACCOUNTS_FILE.exists():
        return []
    try:
        with open(_ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []


class AccountRotator:
    """
    Manages rotation through ChatGPT accounts with retry logic.

    Circulates through all accounts MAX_ACCOUNT_ROUNDS times.
    If all accounts fail across all rounds, stops the pipeline.
    """

    def __init__(self, accounts: list):
        self.accounts = accounts
        self.current_index = 0
        self.current_round = 0
        self.max_rounds = MAX_ACCOUNT_ROUNDS
        self._failure_counts = {}

    def get_current(self) -> dict:
        """Get the current account dict."""
        return self.accounts[self.current_index]

    def rotate(self) -> bool:
        """
        Move to the next account. Returns False if all rounds exhausted.
        """
        self.current_index = (self.current_index + 1) % len(self.accounts)
        if self.current_index == 0:
            self.current_round += 1
            print(f"\n  [Rotation] Starting round {self.current_round + 1}/{self.max_rounds}")

        if self.current_round >= self.max_rounds:
            return False  # All rounds exhausted

        return True

    def mark_failed(self, account_id: str):
        count = self._failure_counts.get(account_id, 0) + 1
        self._failure_counts[account_id] = count

    def mark_success(self, account_id: str):
        self._failure_counts[account_id] = 0

    def is_exhausted(self) -> bool:
        return self.current_round >= self.max_rounds

    def status(self) -> str:
        acct = self.get_current()
        label = acct.get("label", acct["id"])
        return f"Account: {label} (round {self.current_round + 1}/{self.max_rounds})"


# ═════════════════════════════════════════════════════════════════════════════
# Main Pipeline
# ═════════════════════════════════════════════════════════════════════════════

# ═════════════════════════════════════════════════════════════════════════════
# Generator Functions
# ═════════════════════════════════════════════════════════════════════════════

def fetch_nvd_gen(cve_list: list):
    """
    Generator for NVD data fetching phase.

    Yields progress dicts after each CVE is processed:
        {
            "nvd_data_fetcher": "running" | "completed",
            "nvd_data_fetcher_done": "n/m",
            "nvd_results": {cve_id: parsed_data, ...},
        }

    The last yielded dict contains the final nvd_results.

    Args:
        cve_list: List of CVE ID strings.
    """
    if not cve_list:
        yield {
            "nvd_data_fetcher": "completed",
            "nvd_data_fetcher_done": "0/0",
            "nvd_results": {},
        }
        return

    total = len(cve_list)
    yield {
        "nvd_data_fetcher": "running",
        "nvd_data_fetcher_done": f"0/{total}",
        "nvd_results": {},
    }

    db = DBManager()
    db.init_tables()
    nvd_results = {}

    print(f"\n{'─' * 60}")
    print(f"  Phase 1: Fetching NVD Data")
    print(f"{'─' * 60}")

    for i, cve_id in enumerate(cve_list, 1):
        try:
            from engine_progress import is_cancelled
            if is_cancelled():
                raise InterruptedError("Engine cancelled by user")
        except ImportError:
            pass

        cve_id = cve_id.strip().upper()
        print(f"\n  [{i}/{total}] {cve_id}")

        # Check if already in DB
        if db.check_cve_exists(cve_id):
            print(f"  [=] Already in database, fetching stored data...")
            existing = db.get_cve_detail(cve_id)
            if existing:
                nvd_results[cve_id] = existing
                yield {
                    "nvd_data_fetcher": "running",
                    "nvd_data_fetcher_done": f"{i}/{total}",
                    "nvd_results": nvd_results,
                }
                continue

        # Fetch from NVD
        nvd_data = fetch_nvd_data(cve_id)
        if nvd_data:
            db.save_cve_nvd_data(cve_id, nvd_data)
            nvd_results[cve_id] = nvd_data
        else:
            print(f"  [!] Could not fetch NVD data for {cve_id}, skipping.")

        yield {
            "nvd_data_fetcher": "running",
            "nvd_data_fetcher_done": f"{i}/{total}",
            "nvd_results": nvd_results,
        }

    print(f"\n  NVD: {len(nvd_results)}/{total} CVEs fetched successfully.")
    db.close()

    yield {
        "nvd_data_fetcher": "completed",
        "nvd_data_fetcher_done": f"{total}/{total}",
        "nvd_results": nvd_results,
    }


def enrich_gpt_gen(cve_list: list, nvd_results: dict):
    """
    Generator for ChatGPT enrichment phase.

    Yields progress dicts after each CVE is processed:
        {
            "cve_mapper_gpt": "running" | "completed",
            "cve_mapper_gpt_done": "n/m",
        }

    All data goes directly to the database.

    Args:
        cve_list: List of CVE IDs needing GPT analysis.
        nvd_results: Dict of {cve_id: nvd_data} from fetch_nvd_gen.
    """
    if not cve_list:
        yield {
            "cve_mapper_gpt": "completed",
            "cve_mapper_gpt_done": "0/0",
        }
        return

    # ── Validate accounts ────────────────────────────────────────────────
    accounts = _load_accounts()
    if not accounts:
        print("\n[!] No ChatGPT accounts found.")
        print("    Run 'python add_chatgpt_account.py' first to register accounts.")
        yield {
            "cve_mapper_gpt": "completed",
            "cve_mapper_gpt_done": f"0/{len(cve_list)}",
        }
        return

    total = len(cve_list)
    yield {
        "cve_mapper_gpt": "running",
        "cve_mapper_gpt_done": f"0/{total}",
    }

    print(f"\n{'─' * 60}")
    print(f"  Phase 2: ChatGPT Enrichment")
    print(f"{'─' * 60}")
    print(f"\n  CVEs needing ChatGPT analysis: {total}")

    db = DBManager()
    db.init_tables()

    # Set up account rotation
    rotator = AccountRotator(accounts)
    retry_queue = []
    completed = 0
    failed = 0

    with sync_playwright() as pw:
        session = ChatGPTSession(pw)

        # Login with first account
        first = rotator.get_current()
        if not session.open(first["profile_dir"], first["id"], first.get("label", "")):
            print(f"  [!] Failed to open session for {first.get('label', first['id'])}")
            if not _try_next_account(session, rotator):
                print("\n[!] All accounts failed to login. Exiting.")
                session.close()
                db.close()
                yield {
                    "cve_mapper_gpt": "completed",
                    "cve_mapper_gpt_done": f"0/{total}",
                }
                return

        # Process each CVE
        for i, cve_id in enumerate(cve_list, 1):
            try:
                from engine_progress import is_cancelled
                if is_cancelled():
                    raise InterruptedError("Engine cancelled by user")
            except ImportError:
                pass

            print(f"\n  [{i}/{total}] {cve_id}  ({rotator.status()})")

            nvd_data = nvd_results.get(cve_id)
            if not nvd_data:
                retry_queue.append(cve_id)
                yield {
                    "cve_mapper_gpt": "running",
                    "cve_mapper_gpt_done": f"{i}/{total}",
                }
                continue

            prompt = build_chatgpt_prompt(cve_id, nvd_data)

            # Send to ChatGPT
            print(f"    Sending prompt to ChatGPT...")
            response = session.send_prompt(prompt)

            # Handle rate limit
            if session.is_rate_limited(response):
                print(f"    [!] Rate limited on {rotator.get_current().get('label', '')}")
                if not _try_next_account(session, rotator):
                    print("\n[!] All accounts exhausted. Stopping.")
                    retry_queue.append(cve_id)
                    yield {
                        "cve_mapper_gpt": "running",
                        "cve_mapper_gpt_done": f"{i}/{total}",
                    }
                    break

                # Retry this CVE with the new account
                response = session.send_prompt(prompt)
                if session.is_rate_limited(response):
                    print(f"    [!] Still rate limited. Adding to retry queue.")
                    retry_queue.append(cve_id)
                    yield {
                        "cve_mapper_gpt": "running",
                        "cve_mapper_gpt_done": f"{i}/{total}",
                    }
                    continue

            if not response or response == "RATE_LIMITED":
                print(f"    [!] No response received. Adding to retry queue.")
                retry_queue.append(cve_id)
                yield {
                    "cve_mapper_gpt": "running",
                    "cve_mapper_gpt_done": f"{i}/{total}",
                }
                continue

            # Parse response
            print(f"    Response length: {len(response)} chars")
            parsed = parse_chatgpt_response(response)
            if parsed and validate_chatgpt_response(parsed):
                db.save_cve_analysis(cve_id, parsed)
                _cleanup_debug_file(cve_id)
                completed += 1
                mitre_count = len(parsed.get("mitre_attack_mapping", []))
                walk_count = len(parsed.get("vulnerability_walkthrough", []))
                print(f"    [+] Saved: {mitre_count} MITRE mappings, "
                      f"{walk_count} walkthrough steps")
            elif parsed:
                print(f"    [~] Response parsed but incomplete. "
                      f"Keys: {list(parsed.keys())}")
                db.save_cve_analysis(cve_id, parsed)
                _cleanup_debug_file(cve_id)
                completed += 1
                print(f"    [~] Saved partial analysis anyway.")
            else:
                print(f"    [!] Failed to parse JSON response.")
                print(f"    [!] Response starts with: {response[:150]}")
                ERROR_JSON_DIR.mkdir(exist_ok=True)
                debug_file = ERROR_JSON_DIR / f"debug_{cve_id}.txt"
                with open(debug_file, "w", encoding="utf-8") as f:
                    f.write(response)
                print(f"    [!] Raw response saved to: error_json/{debug_file.name}")
                retry_queue.append(cve_id)
                failed += 1

            yield {
                "cve_mapper_gpt": "running",
                "cve_mapper_gpt_done": f"{i}/{total}",
            }

        # ── Retry queue ──────────────────────────────────────────────────
        if retry_queue and not rotator.is_exhausted():
            print(f"\n{'─' * 60}")
            print(f"  Retry Queue: {len(retry_queue)} CVEs")
            print(f"{'─' * 60}")

            still_failed = []
            for cve_id in retry_queue:
                print(f"\n  [RETRY] {cve_id}  ({rotator.status()})")
                nvd_data = nvd_results.get(cve_id)
                if not nvd_data:
                    still_failed.append(cve_id)
                    continue

                prompt = build_chatgpt_prompt(cve_id, nvd_data)
                response = session.send_prompt(prompt)

                if session.is_rate_limited(response):
                    if not _try_next_account(session, rotator):
                        still_failed.append(cve_id)
                        still_failed.extend(
                            [c for c in retry_queue if c not in still_failed and c != cve_id]
                        )
                        break
                    response = session.send_prompt(prompt)

                if response and response != "RATE_LIMITED":
                    print(f"    Response length: {len(response)} chars")
                    parsed = parse_chatgpt_response(response)
                    if parsed and validate_chatgpt_response(parsed):
                        db.save_cve_analysis(cve_id, parsed)
                        completed += 1
                        print(f"    [+] Retry succeeded!")
                        _cleanup_debug_file(cve_id)
                    elif parsed:
                        db.save_cve_analysis(cve_id, parsed)
                        completed += 1
                        print(f"    [~] Retry partial save (keys: {list(parsed.keys())})")
                        _cleanup_debug_file(cve_id)
                    else:
                        still_failed.append(cve_id)
                        print(f"    [!] Retry failed (bad JSON).")
                        ERROR_JSON_DIR.mkdir(exist_ok=True)
                        debug_file = ERROR_JSON_DIR / f"debug_{cve_id}.txt"
                        with open(debug_file, "w", encoding="utf-8") as f:
                            f.write(response)
                else:
                    still_failed.append(cve_id)
                    print(f"    [!] Retry failed (no response).")

            retry_queue = still_failed

        session.close()

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n  GPT Enrichment: {completed} completed, {len(retry_queue)} failed")
    if retry_queue:
        print(f"  Failed CVEs: {', '.join(retry_queue)}")

    db.close()

    yield {
        "cve_mapper_gpt": "completed",
        "cve_mapper_gpt_done": f"{total}/{total}",
    }


# ═════════════════════════════════════════════════════════════════════════════
# Pipeline (uses both generators)
# ═════════════════════════════════════════════════════════════════════════════

def run_pipeline(cve_list: list):
    """
    Main CVE mapping pipeline:
    1. Fetch NVD data for each CVE (via fetch_nvd_gen)
    2. Enrich with ChatGPT (via enrich_gpt_gen)
    3. Save everything to database

    Internally consumes both generators for progress tracking.
    """
    print(f"\n{'=' * 60}")
    print(f"  CVE Mapper Pipeline")
    print(f"{'=' * 60}")
    print(f"  CVEs to process:  {len(cve_list)}")
    print(f"  NVD API key:      {'configured' if NVD_API_KEY else 'NOT SET (slower)'}")
    print(f"{'=' * 60}\n")

    # Phase 1: NVD fetch
    nvd_progress = None
    for nvd_progress in fetch_nvd_gen(cve_list):
        pass
    nvd_results = nvd_progress.get("nvd_results", {}) if nvd_progress else {}

    if not nvd_results:
        print("\n[!] No NVD data fetched. Nothing to enrich.")
        return

    # Filter out CVEs that already have analysis
    db = DBManager()
    db.init_tables()
    cves_needing_analysis = []
    for cve_id in nvd_results:
        if db.check_cve_analysis_exists(cve_id):
            print(f"  [=] {cve_id}: Analysis already exists, skipping.")
        else:
            cves_needing_analysis.append(cve_id)
    db.close()

    if not cves_needing_analysis:
        print("\n  All CVEs already have ChatGPT analysis. Nothing to do.")
        return

    # Phase 2: GPT enrichment
    for gpt_progress in enrich_gpt_gen(cves_needing_analysis, nvd_results):
        pass

    # Final summary
    print(f"\n{'=' * 60}")
    print(f"  CVE Mapper — Complete")
    print(f"{'=' * 60}")


def _cleanup_debug_file(cve_id: str):
    """Delete the debug file for a CVE after successful parse."""
    # Check both old location (SCRIPT_DIR) and new location (error_json/)
    for parent in (ERROR_JSON_DIR, SCRIPT_DIR):
        debug_file = parent / f"debug_{cve_id}.txt"
        if debug_file.exists():
            try:
                debug_file.unlink()
                print(f"    [cleanup] Deleted {debug_file.relative_to(SCRIPT_DIR)}")
            except OSError as e:
                print(f"    [cleanup] Could not delete {debug_file.name}: {e}")


def _try_next_account(session: ChatGPTSession, rotator: AccountRotator) -> bool:
    """Try to rotate to the next account. Returns False if all exhausted."""
    while True:
        can_rotate = rotator.rotate()
        if not can_rotate:
            return False

        acct = rotator.get_current()
        label = acct.get("label", acct["id"])
        print(f"  [Rotation] Switching to {label}...")
        if session.open(acct["profile_dir"], acct["id"], label):
            return True
        else:
            print(f"  [!] {label} session failed, trying next...")


# ═════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═════════════════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) >= 2:
        # CLI mode: python cve_mapper.py CVE-2024-1234,CVE-2024-5678
        raw = sys.argv[1]
    else:
        # Interactive mode: prompt user for CVE list
        print("\n" + "=" * 60)
        print("  CVE Mapper — Enter CVE IDs")
        print("=" * 60)
        print("  Separate with spaces or commas.")
        print("  Example: CVE-2020-17144 CVE-2021-45046\n")
        raw = input("  > ").strip()
        if not raw:
            print("[-] No CVEs provided. Exiting.")
            sys.exit(1)

    # Parse CVE list — support both comma and space separators
    cve_list = [c.strip() for c in raw.replace(",", " ").split() if c.strip()]

    if not cve_list:
        print("[-] No CVEs provided. Exiting.")
        sys.exit(1)

    # Validate CVE format
    cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
    invalid = [c for c in cve_list if not cve_pattern.match(c)]
    if invalid:
        print(f"[!] Invalid CVE format: {', '.join(invalid)}")
        print("    Expected format: CVE-YYYY-NNNNN")
        sys.exit(1)

    # Normalize to uppercase
    cve_list = [c.upper() for c in cve_list]

    # Remove duplicates while preserving order
    seen = set()
    unique_cves = []
    for c in cve_list:
        if c not in seen:
            seen.add(c)
            unique_cves.append(c)

    run_pipeline(unique_cves)


if __name__ == "__main__":
    main()

