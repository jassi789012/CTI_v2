"""
ChatGPT Account Manager — Persistent Browser Profiles
======================================================
Creates persistent Chromium browser profiles for ChatGPT accounts.
Uses launch_persistent_context to store full auth state (cookies,
localStorage, indexedDB) — much more reliable than cookie-only storage.

Usage:
    python add_chatgpt_account.py
"""

import json
import time
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

# ─── Config ──────────────────────────────────────────────────────────────────
CHATGPT_URL = "https://chatgpt.com"
ACCOUNTS_DIR = Path(__file__).resolve().parent / ".accounts"
ACCOUNTS_FILE = ACCOUNTS_DIR / "accounts.json"

# Prompt textarea selector (the "logged in" indicator)
PROMPT_SELECTOR = "#prompt-textarea"
# Login/signup buttons (the "NOT logged in" indicator)
LOGIN_BUTTON_SELECTOR = 'button:has-text("Log in")'
SIGNUP_BUTTON_SELECTOR = 'button:has-text("Sign up for free")'


def _load_accounts() -> list:
    """Load existing accounts registry."""
    if not ACCOUNTS_FILE.exists():
        return []
    try:
        with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []


def _save_accounts(accounts: list):
    """Save accounts registry."""
    ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
        json.dump(accounts, f, indent=2)


def _get_next_account_id(accounts: list) -> str:
    """Generate the next account ID."""
    n = 1
    existing_ids = {a["id"] for a in accounts}
    while f"account{n}" in existing_ids:
        n += 1
    return f"account{n}"


def _has_login_buttons(page) -> bool:
    """Return True if login/signup buttons are visible (= NOT logged in)."""
    try:
        for selector in [LOGIN_BUTTON_SELECTOR, SIGNUP_BUTTON_SELECTOR]:
            loc = page.locator(selector)
            if loc.count() > 0 and loc.first.is_visible():
                return True
    except Exception:
        pass
    return False


def _is_logged_in(page) -> bool:
    """Check if the user is logged in to ChatGPT."""
    try:
        if "chatgpt.com" not in page.url.lower():
            return False
        if _has_login_buttons(page):
            return False
        try:
            prompt = page.wait_for_selector(PROMPT_SELECTOR, timeout=5000)
            if prompt and prompt.is_visible() and not _has_login_buttons(page):
                return True
        except PlaywrightTimeout:
            pass
    except Exception:
        pass
    return False


def _wait_for_login(page) -> bool:
    """Wait for user to complete login in the browser window."""
    print("\n" + "=" * 60)
    print("  ACTION REQUIRED: Log in to ChatGPT in the browser window")
    print("  The script will detect login automatically and continue.")
    print("  (You have up to 10 minutes)")
    print("=" * 60 + "\n")

    max_wait = 600  # 10 minutes
    elapsed = 0

    while elapsed < max_wait:
        try:
            on_chatgpt = "chatgpt.com" in page.url.lower()
            no_login_btns = not _has_login_buttons(page)
            has_prompt = False
            try:
                prompt_el = page.query_selector(PROMPT_SELECTOR)
                has_prompt = prompt_el is not None and prompt_el.is_visible()
            except Exception:
                pass

            if on_chatgpt and no_login_btns and has_prompt:
                time.sleep(2)  # double check
                if _is_logged_in(page):
                    print("\n  [+] Login detected! Continuing...\n")
                    return True
        except Exception:
            pass

        time.sleep(5)
        elapsed += 5

        if elapsed % 30 == 0:
            url = "unknown"
            try:
                url = page.url
            except Exception:
                pass
            print(f"    Still waiting... ({elapsed}s, URL: {url})")

    print("\n  [!] Login timed out (10 minutes).")
    return False


def _list_accounts(accounts: list):
    """Print existing accounts."""
    if accounts:
        print(f"\n  Existing accounts ({len(accounts)}):")
        for acc in accounts:
            label = acc.get("label", acc["id"])
            profile = acc["profile_dir"]
            print(f"    • {label}  ({profile})")
    else:
        print("\n  No existing accounts found.")


def main():
    print("\n" + "=" * 60)
    print("  ChatGPT Account Manager — Persistent Profiles")
    print("=" * 60)

    accounts = _load_accounts()
    _list_accounts(accounts)

    with sync_playwright() as p:
        while True:
            account_id = _get_next_account_id(accounts)
            profile_dir = str(ACCOUNTS_DIR / account_id)

            print(f"\n{'─' * 60}")
            print(f"  Adding Account: {account_id}")
            print(f"  Profile: {profile_dir}")
            print(f"{'─' * 60}")

            # Launch browser with persistent context (stores full auth state)
            context = p.chromium.launch_persistent_context(
                user_data_dir=profile_dir,
                headless=False,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                ],
                viewport={"width": 1280, "height": 900},
            )

            # Anti-detection
            context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => false});
            """)

            page = context.pages[0] if context.pages else context.new_page()

            # Navigate to ChatGPT
            print(f"\n  Opening {CHATGPT_URL}")
            page.goto(CHATGPT_URL, wait_until="domcontentloaded", timeout=60000)
            time.sleep(3)

            # Check if already logged in (from a previous interrupted attempt)
            if _is_logged_in(page):
                print(f"  [+] Already logged in!")
            else:
                print(f"  Please log in to your ChatGPT account in the browser window.")
                logged_in = _wait_for_login(page)
                if not logged_in:
                    context.close()
                    continue

            # Give a label
            label = input(f"  Give this account a label (or Enter for '{account_id}'): ").strip()
            if not label:
                label = account_id

            # Save to registry
            accounts.append({
                "id": account_id,
                "label": label,
                "profile_dir": profile_dir,
            })
            _save_accounts(accounts)

            # Close browser (profile is saved on disk)
            context.close()

            print(f"\n  [+] Account '{label}' saved!")
            print(f"      Profile stored at: {profile_dir}")

            # Ask to add another
            answer = input("\n  Add another account? (y/n): ").strip().lower()
            if answer not in ("y", "yes"):
                break

    # Final summary
    print(f"\n{'=' * 60}")
    print("  Done!")
    _list_accounts(accounts)
    print("=" * 60)


if __name__ == "__main__":
    main()
