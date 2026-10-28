"""
CVE Mapper — Multi-Source OSINT Enrichment (Per-Source Queue Architecture)
==========================================================================
Fetches and enriches CVE data from 8 public intelligence sources.

Architecture:
    Each source runs as a dedicated worker thread with its own queue,
    processing CVEs at its own rate limit independently. This ensures
    fast sources (EPSS, KEV) are never blocked by slow sources (NVD,
    Exploit-DB), and each source's rate limit is properly respected.

    ┌─────────────────────────────────────────────────────────────────┐
    │                    CVE List Input                                │
    │              [CVE-1, CVE-2, CVE-3, ...]                        │
    └────────────────────────┬────────────────────────────────────────┘
                             │ enqueue all CVEs to each source
                             ▼
    ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
    │ NVD      │ │ CVE.org  │ │ EPSS     │ │ KEV      │ │ OSV      │
    │ Worker   │ │ Worker   │ │ (batch)  │ │ (cached) │ │ (no lim) │
    │ 50/30s   │ │ 8/10s    │ │ 50/req   │ │          │ │          │
    └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘
         │            │            │            │            │
         ▼            │            │            │            │
    ┌──────────┐      │            │            │            │
    │ NVD done │──────┼────────────┼────────────┼────────────┤
    │ signals  │      │            │            │            │
    │ Event    │      │            │            │            │
    └────┬─────┘      │            │            │            │
         │            │            │            │            │
    ┌────▼─────┐ ┌────▼─────┐ ┌────▼─────┐    │            │
    │ExploitDB │ │ CWE      │ │ ATT&CK   │    │            │
    │ Worker   │ │ Worker   │ │ Worker   │    │            │
    │ 3/10s    │ │ (API)    │ │ (cached) │    │            │
    └────┬─────┘ └────┬─────┘ └────┬─────┘    │            │
         │            │            │            │            │
         └────────────┴────────────┴────────────┴────────────┘
                             │
                    Per-CVE result merge
                             │
                    Save to DB + yield progress

Sources:
    1. NVD         — CVSS scores, CWE, CPE, severity, description
    2. CVE.org     — CNA record, additional references, timeline
    3. FIRST EPSS  — Exploit probability score + percentile (batch query)
    4. CISA KEV    — Known exploited status, remediation deadline
    5. OSV.dev     — Affected open-source packages + fix versions
    6. Exploit-DB  — Public exploit/PoC links (via NVD/CVE.org refs)
    7. CWE Catalog — Weakness details, mitigations
    8. MITRE ATT&CK — CWE→CAPEC→Technique→Tactic mappings (STIX)
    9. VulnCheck   — Enhanced KEV + exploit index (optional, free API key)

Usage:
    python cve_mapper.py CVE-2024-1234,CVE-2024-5678

Requires:
    - NIST_API_KEY in .env (optional but recommended — 10x faster NVD queries)
    - VULNCHECK_API_KEY in .env (optional — adds VulnCheck KEV + exploit data)
"""

import json
import os
import re
import sys
import time
import threading
import queue
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

# ─── Paths ───────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent        # Backend/cve_maper/
BACKEND_DIR = SCRIPT_DIR.parent                     # Backend/
ENV_PATH = BACKEND_DIR.parent / ".env"              # CTI_V2/.env

# Add Backend to sys.path so we can import db_manager
sys.path.insert(0, str(BACKEND_DIR))

load_dotenv(dotenv_path=ENV_PATH)
from db_manager import DBManager

# ─── Config ──────────────────────────────────────────────────────────────────
NVD_API_KEY = os.getenv("NIST_API_KEY", "")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# VulnCheck Community API (free tier — 1000 req/min)
# Sign up at https://console.vulncheck.com for a free token.
# Provides enhanced KEV data (~80% more exploited CVEs than CISA) and
# an exploit index (XDB) with validated PoC links.
VULNCHECK_API_KEY = os.getenv("VULNCHECK_API_KEY", "")
VULNCHECK_BASE_URL = "https://api.vulncheck.com/v3"

MAX_RETRIES = 3

# EPSS batch size (max ~50 CVEs per request due to 2000-char URL limit)
EPSS_BATCH_SIZE = 50


# ═════════════════════════════════════════════════════════════════════════════
# Generic Rate Limiter (thread-safe)
# ═════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    """
    Thread-safe rolling-window rate limiter.
    
    Each source gets its own instance to independently control
    request rates without blocking other sources.
    """

    def __init__(self, max_per_window: int, window_seconds: float,
                 min_gap: float = 0.0, name: str = ""):
        self.max_per_window = max_per_window
        self.window = window_seconds
        self.min_gap = min_gap
        self.name = name
        self.timestamps: list[float] = []
        self.lock = threading.Lock()

    def wait(self):
        """Block until it's safe to make the next request."""
        with self.lock:
            now = time.time()

            # Purge timestamps outside the rolling window
            self.timestamps = [t for t in self.timestamps if now - t < self.window]

            # Enforce minimum gap between consecutive requests
            if self.timestamps and self.min_gap > 0:
                gap = now - self.timestamps[-1]
                if gap < self.min_gap:
                    time.sleep(self.min_gap - gap)

            # If we've hit the max, wait until the oldest request exits the window
            if len(self.timestamps) >= self.max_per_window:
                wait_until = self.timestamps[0] + self.window
                sleep_time = wait_until - time.time() + 0.5
                if sleep_time > 0:
                    if self.name:
                        print(f"  [{self.name}] Rate limit: waiting {sleep_time:.1f}s")
                    time.sleep(sleep_time)

            self.timestamps.append(time.time())

    def backoff(self, seconds: float = 30.0):
        """Called on 403/429 — wait and clear the window."""
        with self.lock:
            if self.name:
                print(f"  [{self.name}] Rate limited — backing off {seconds:.0f}s...")
            time.sleep(seconds)
            self.timestamps.clear()


# ─── Per-Source Rate Limiters (module-level singletons) ──────────────────────

_nvd_limiter = RateLimiter(
    max_per_window=50 if NVD_API_KEY else 5,
    window_seconds=30,
    min_gap=0.6 if NVD_API_KEY else 6.5,
    name="NVD"
)
_cveorg_limiter = RateLimiter(
    max_per_window=8, window_seconds=10, min_gap=1.0, name="CVE.org"
)
_epss_limiter = RateLimiter(
    max_per_window=100, window_seconds=60, min_gap=0.1, name="EPSS"
)
_osv_limiter = RateLimiter(
    max_per_window=50, window_seconds=10, min_gap=0.1, name="OSV"
)
_exploitdb_limiter = RateLimiter(
    max_per_window=3, window_seconds=10, min_gap=3.0, name="Exploit-DB"
)
_cwe_limiter = RateLimiter(
    max_per_window=10, window_seconds=10, min_gap=0.5, name="CWE"
)
_vulncheck_limiter = RateLimiter(
    max_per_window=100, window_seconds=60, min_gap=0.3, name="VulnCheck"
)


# ═════════════════════════════════════════════════════════════════════════════
# Cached Catalogs (downloaded once, refreshed every 24h)
# ═════════════════════════════════════════════════════════════════════════════

class CachedCatalog:
    """
    Thread-safe catalog with TTL-based auto-refresh.
    
    Used for large static datasets (CISA KEV, CWE, MITRE ATT&CK)
    that don't need per-CVE API calls — just in-memory dict lookups.
    """

    def __init__(self, url: str, ttl_hours: int = 24, name: str = ""):
        self.url = url
        self.ttl = ttl_hours * 3600
        self.name = name
        self._data = None
        self._fetched_at: float = 0
        self._lock = threading.Lock()

    def get(self) -> dict | list:
        """Return cached data, refreshing if stale."""
        with self._lock:
            now = time.time()
            if self._data is None or (now - self._fetched_at) > self.ttl:
                print(f"  [{self.name}] Downloading catalog from {self.url[:60]}...")
                try:
                    resp = requests.get(self.url, timeout=120)
                    resp.raise_for_status()
                    self._data = resp.json()
                    self._fetched_at = time.time()
                    print(f"  [{self.name}] Catalog loaded successfully.")
                except Exception as e:
                    print(f"  [{self.name}] Failed to download catalog: {e}")
                    if self._data is None:
                        self._data = {}
            return self._data

    @property
    def is_loaded(self) -> bool:
        return self._data is not None


# Module-level catalog singletons
_kev_catalog = CachedCatalog(
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ttl_hours=24, name="CISA-KEV"
)
_attack_stix = CachedCatalog(
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    ttl_hours=24, name="ATT&CK-STIX"
)

# Prebuilt KEV lookup dict (CVE ID → entry)
_kev_lookup: dict = {}
_kev_lookup_lock = threading.Lock()

# Prebuilt ATT&CK CWE→Techniques mapping
_attack_cwe_map: dict = {}
_attack_cwe_map_lock = threading.Lock()


def _get_kev_lookup() -> dict:
    """Build/return CVE→KEV entry lookup dict from cached catalog."""
    global _kev_lookup
    with _kev_lookup_lock:
        catalog = _kev_catalog.get()
        if not _kev_lookup and catalog:
            vulns = catalog.get("vulnerabilities", [])
            _kev_lookup = {v["cveID"]: v for v in vulns if "cveID" in v}
            print(f"  [CISA-KEV] Index built: {len(_kev_lookup)} entries")
        return _kev_lookup


# ═════════════════════════════════════════════════════════════════════════════
# Source 1: NVD Data Fetcher
# ═════════════════════════════════════════════════════════════════════════════

def fetch_nvd(cve_id: str) -> dict:
    """
    Fetch CVE data from NVD REST API and parse into a flat dict.
    Respects NVD rate limits using the global rolling-window limiter.
    Retries up to MAX_RETRIES times on failure.

    Returns a dict with all the fields needed by db_manager.save_cve_nvd_data()
    or None on failure.
    """
    url = f"{NVD_BASE_URL}?cveId={cve_id}"
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    for attempt in range(1, MAX_RETRIES + 1):
        _nvd_limiter.wait()

        try:
            resp = requests.get(url, headers=headers, timeout=30)

            if resp.status_code == 403:
                print(f"  [NVD] {cve_id}: 403 (attempt {attempt}/{MAX_RETRIES})")
                _nvd_limiter.backoff(30.0)
                continue

            if resp.status_code == 429:
                print(f"  [NVD] {cve_id}: 429 (attempt {attempt}/{MAX_RETRIES})")
                _nvd_limiter.backoff(35.0)
                continue

            resp.raise_for_status()
            data = resp.json()
            break

        except requests.RequestException as e:
            print(f"  [NVD] {cve_id}: FAILED attempt {attempt}/{MAX_RETRIES} ({e})")
            if attempt < MAX_RETRIES:
                time.sleep(5)
                continue
            return None
    else:
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        print(f"  [NVD] {cve_id}: NOT FOUND")
        return None

    cve_item = vulns[0].get("cve", {})
    print(f"  [NVD] {cve_id}: OK")
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
                if len(parts) >= 6:
                    vendor = parts[3] if parts[3] != "*" else None
                    product = parts[4] if parts[4] != "*" else None
                    version = parts[5] if parts[5] != "*" else None

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
# Source 2: CVE.org Record Fetcher
# ═════════════════════════════════════════════════════════════════════════════

def fetch_cve_org(cve_id: str) -> dict | None:
    """
    Fetch CVE record from CVE.org (MITRE CVE Services API).
    Returns parsed dict with CNA descriptions, references, timeline.
    Retries up to MAX_RETRIES times on failure.
    """
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

    for attempt in range(1, MAX_RETRIES + 1):
        _cveorg_limiter.wait()
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code == 404:
                print(f"  [CVE.org] {cve_id}: NOT FOUND")
                return None
            if resp.status_code == 429:
                print(f"  [CVE.org] {cve_id}: 429 (attempt {attempt}/{MAX_RETRIES})")
                _cveorg_limiter.backoff(15.0)
                continue
            resp.raise_for_status()
            data = resp.json()

            # Extract from CNA container
            cna = data.get("containers", {}).get("cna", {})
            
            # Additional references from CNA
            refs = []
            for ref in cna.get("references", []):
                refs.append({
                    "url": ref.get("url", ""),
                    "tags": ref.get("tags", []),
                    "name": ref.get("name", ""),
                })
            
            # Timeline
            timeline = []
            for entry in cna.get("timeline", []):
                timeline.append({
                    "time": entry.get("time", ""),
                    "lang": entry.get("lang", "en"),
                    "value": entry.get("value", ""),
                })
            
            # Descriptions from CNA
            descriptions = []
            for desc in cna.get("descriptions", []):
                descriptions.append({
                    "lang": desc.get("lang", "en"),
                    "value": desc.get("value", ""),
                })
            
            # Problem types / CWE from CNA
            cwe_ids = []
            for pt in cna.get("problemTypes", []):
                for desc in pt.get("descriptions", []):
                    cwe_id = desc.get("cweId", "")
                    if cwe_id:
                        cwe_ids.append(cwe_id)
            
            print(f"  [CVE.org] {cve_id}: OK ({len(refs)} refs)")
            return {
                "references": refs,
                "timeline": timeline,
                "descriptions": descriptions,
                "cwe_ids": cwe_ids,
                "date_published": data.get("cveMetadata", {}).get("datePublished"),
                "assigner_org": data.get("cveMetadata", {}).get("assignerShortName"),
            }
            
        except Exception as e:
            print(f"  [CVE.org] {cve_id}: FAILED attempt {attempt}/{MAX_RETRIES} ({e})")
            if attempt < MAX_RETRIES:
                time.sleep(3)
                continue
            return None
    
    return None


# ═════════════════════════════════════════════════════════════════════════════
# Source 3: FIRST EPSS Score Fetcher (supports batch queries)
# ═════════════════════════════════════════════════════════════════════════════

# Module-level EPSS batch cache: pre-fetched scores for all CVEs
_epss_batch_cache: dict[str, dict] = {}
_epss_batch_lock = threading.Lock()


def _prefetch_epss_batch(cve_list: list[str]):
    """
    Pre-fetch EPSS scores for all CVEs using batch queries.
    
    The FIRST EPSS API supports comma-separated CVE IDs (max 2000 chars
    in the cve parameter → ~50 CVEs per request). This is ~50x faster
    than individual queries.
    
    Rate limit: 1000 req/min (public, no API key needed).
    """
    global _epss_batch_cache

    # Split into batches of EPSS_BATCH_SIZE
    batches = []
    for i in range(0, len(cve_list), EPSS_BATCH_SIZE):
        batches.append(cve_list[i:i + EPSS_BATCH_SIZE])

    results = {}
    for batch_num, batch in enumerate(batches, 1):
        cve_param = ",".join(batch)
        url = f"https://api.first.org/data/v1/epss?cve={cve_param}"

        for attempt in range(1, MAX_RETRIES + 1):
            _epss_limiter.wait()
            try:
                resp = requests.get(url, timeout=30)
                if resp.status_code == 429:
                    print(f"  [EPSS] Batch {batch_num}/{len(batches)}: 429 (attempt {attempt}/{MAX_RETRIES})")
                    _epss_limiter.backoff(10.0)
                    continue
                resp.raise_for_status()
                data = resp.json()

                for entry in data.get("data", []):
                    cve_id = entry.get("cve", "")
                    if cve_id:
                        results[cve_id] = {
                            "epss_score": float(entry.get("epss", 0)),
                            "epss_percentile": float(entry.get("percentile", 0)),
                            "epss_date": entry.get("date"),
                        }

                print(f"  [EPSS] Batch {batch_num}/{len(batches)}: {len(data.get('data', []))} scores fetched")
                break  # Success, move to next batch

            except Exception as e:
                print(f"  [EPSS] Batch {batch_num}/{len(batches)}: FAILED attempt {attempt}/{MAX_RETRIES} ({e})")
                if attempt < MAX_RETRIES:
                    time.sleep(2)
                    continue

    with _epss_batch_lock:
        _epss_batch_cache.update(results)

    print(f"  [EPSS] Pre-fetched {len(results)}/{len(cve_list)} EPSS scores via batch API")


def fetch_epss(cve_id: str) -> dict | None:
    """
    Fetch EPSS exploit probability score from FIRST.
    Returns dict with epss_score (0-1) and epss_percentile (0-1).
    
    Uses pre-fetched batch cache if available (populated by
    _prefetch_epss_batch before workers start). Falls back to
    individual query if cache misses.
    """
    # Check batch cache first (instant lookup, no API call)
    with _epss_batch_lock:
        cached = _epss_batch_cache.get(cve_id)
        if cached is not None:
            print(f"  [EPSS] {cve_id}: score={cached['epss_score']:.4f} (from batch cache)")
            return cached

    # Fallback: individual query (shouldn't normally happen after prefetch)
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"

    for attempt in range(1, MAX_RETRIES + 1):
        _epss_limiter.wait()
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 429:
                print(f"  [EPSS] {cve_id}: 429 (attempt {attempt}/{MAX_RETRIES})")
                _epss_limiter.backoff(10.0)
                continue
            resp.raise_for_status()
            data = resp.json()
            
            entries = data.get("data", [])
            if not entries:
                print(f"  [EPSS] {cve_id}: No data")
                return None
            
            entry = entries[0]
            score = float(entry.get("epss", 0))
            percentile = float(entry.get("percentile", 0))
            
            print(f"  [EPSS] {cve_id}: score={score:.4f}, percentile={percentile:.4f}")
            return {
                "epss_score": score,
                "epss_percentile": percentile,
                "epss_date": entry.get("date"),
            }
            
        except Exception as e:
            print(f"  [EPSS] {cve_id}: FAILED attempt {attempt}/{MAX_RETRIES} ({e})")
            if attempt < MAX_RETRIES:
                time.sleep(2)
                continue
            return None

    return None


# ═════════════════════════════════════════════════════════════════════════════
# Source 4: CISA KEV Lookup (cached catalog)
# ═════════════════════════════════════════════════════════════════════════════

def fetch_kev_status(cve_id: str) -> dict | None:
    """
    Look up CVE in the CISA Known Exploited Vulnerabilities catalog.
    Uses in-memory cached catalog (downloaded once, refreshed every 24h).
    """
    kev = _get_kev_lookup()
    entry = kev.get(cve_id)
    
    if entry:
        print(f"  [KEV] {cve_id}: LISTED (due {entry.get('dueDate', 'N/A')})")
        return {
            "kev_listed": True,
            "kev_vendor": entry.get("vendorProject"),
            "kev_product": entry.get("product"),
            "kev_vuln_name": entry.get("vulnerabilityName"),
            "kev_date_added": entry.get("dateAdded"),
            "kev_due_date": entry.get("dueDate"),
            "kev_ransomware": entry.get("knownRansomwareCampaignUse", "Unknown"),
            "kev_notes": entry.get("notes", ""),
            "kev_required_action": entry.get("requiredAction", ""),
        }
    else:
        print(f"  [KEV] {cve_id}: Not listed")
        return {
            "kev_listed": False,
        }


# ═════════════════════════════════════════════════════════════════════════════
# Source 5: OSV.dev Open-Source Vulnerability Data
# ═════════════════════════════════════════════════════════════════════════════

def fetch_osv(cve_id: str) -> dict | None:
    """
    Fetch open-source vulnerability data from OSV.dev.
    Returns affected packages, ecosystems, and fix versions.
    Retries up to MAX_RETRIES times on failure.
    """
    url = f"https://api.osv.dev/v1/vulns/{cve_id}"

    for attempt in range(1, MAX_RETRIES + 1):
        _osv_limiter.wait()
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 404:
                print(f"  [OSV] {cve_id}: Not in OSV")
                return None
            if resp.status_code == 429:
                print(f"  [OSV] {cve_id}: 429 (attempt {attempt}/{MAX_RETRIES})")
                _osv_limiter.backoff(10.0)
                continue
            resp.raise_for_status()
            data = resp.json()
            
            # Extract affected packages
            packages = []
            for affected in data.get("affected", []):
                pkg = affected.get("package", {})
                
                # Get fix versions
                fix_versions = []
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            fix_versions.append(event["fixed"])
                
                # Get affected versions list
                versions = affected.get("versions", [])
                
                packages.append({
                    "ecosystem": pkg.get("ecosystem", ""),
                    "name": pkg.get("name", ""),
                    "purl": pkg.get("purl", ""),
                    "fix_versions": fix_versions,
                    "affected_version_count": len(versions),
                })
            
            print(f"  [OSV] {cve_id}: {len(packages)} affected packages")
            return {
                "osv_id": data.get("id"),
                "osv_summary": data.get("summary", ""),
                "osv_severity": data.get("database_specific", {}).get("severity", ""),
                "packages": packages,
                "aliases": data.get("aliases", []),
            }
            
        except Exception as e:
            print(f"  [OSV] {cve_id}: FAILED attempt {attempt}/{MAX_RETRIES} ({e})")
            if attempt < MAX_RETRIES:
                time.sleep(2)
                continue
            return None
    
    return None


# ═════════════════════════════════════════════════════════════════════════════
# Source 6: Exploit-DB References (via NVD/CVE.org reference URLs)
# ═════════════════════════════════════════════════════════════════════════════

def fetch_exploitdb(cve_id: str, reference_urls: list = None) -> dict | None:
    """
    Find Exploit-DB references for a CVE.
    
    Strategy:
      1. Check NVD/CVE.org reference URLs for exploit-db.com links
      2. Check for GitHub PoC links in references
      3. Optionally query Exploit-DB search (rate-limited)

    Retries the Exploit-DB search up to MAX_RETRIES times on failure.
    """
    exploit_refs = []
    github_pocs = []
    
    # Parse reference URLs from NVD/CVE.org
    if reference_urls:
        for ref in reference_urls:
            url = ref.get("url", "") if isinstance(ref, dict) else str(ref)
            tags = ref.get("tags", []) if isinstance(ref, dict) else []
            
            # Exploit-DB links
            if "exploit-db.com" in url:
                edb_match = re.search(r'exploit-db\.com/exploits/(\d+)', url)
                edb_id = edb_match.group(1) if edb_match else None
                exploit_refs.append({
                    "source": "exploit-db",
                    "url": url,
                    "edb_id": edb_id,
                })
            
            # GitHub PoC repositories
            elif "github.com" in url and any(t in tags for t in ["Exploit", "Third Party Advisory"]):
                github_pocs.append({
                    "source": "github",
                    "url": url,
                })
            
            # PacketStorm
            elif "packetstormsecurity.com" in url:
                exploit_refs.append({
                    "source": "packetstorm",
                    "url": url,
                })
    
    # Try Exploit-DB search as fallback (with retries)
    if not exploit_refs:
        for attempt in range(1, MAX_RETRIES + 1):
            _exploitdb_limiter.wait()
            try:
                search_url = f"https://exploit-db.com/search?cve={cve_id.replace('CVE-', '')}"
                resp = requests.get(
                    search_url,
                    headers={"User-Agent": "Mozilla/5.0 CTI_V2 Research Bot"},
                    timeout=15,
                    allow_redirects=True
                )
                if resp.status_code == 429:
                    print(f"  [Exploit-DB] {cve_id}: 429 (attempt {attempt}/{MAX_RETRIES})")
                    _exploitdb_limiter.backoff(15.0)
                    continue
                if resp.status_code == 200 and "exploit-db.com/exploits/" in resp.text:
                    # Extract EDB IDs from response
                    for match in re.finditer(r'/exploits/(\d+)', resp.text):
                        edb_id = match.group(1)
                        exploit_refs.append({
                            "source": "exploit-db",
                            "url": f"https://www.exploit-db.com/exploits/{edb_id}",
                            "edb_id": edb_id,
                        })
                    # Deduplicate
                    seen = set()
                    deduped = []
                    for ref in exploit_refs:
                        if ref["url"] not in seen:
                            seen.add(ref["url"])
                            deduped.append(ref)
                    exploit_refs = deduped
                break  # Success or non-retryable status
            except Exception as e:
                print(f"  [Exploit-DB] {cve_id}: FAILED attempt {attempt}/{MAX_RETRIES} ({e})")
                if attempt < MAX_RETRIES:
                    time.sleep(3)
                    continue
    
    total = len(exploit_refs) + len(github_pocs)
    print(f"  [Exploit-DB] {cve_id}: {len(exploit_refs)} exploits, {len(github_pocs)} PoCs")
    
    return {
        "exploit_available": total > 0,
        "exploit_refs": exploit_refs,
        "github_pocs": github_pocs,
        "exploit_count": total,
    }


# ═════════════════════════════════════════════════════════════════════════════
# Source 7: CWE Weakness Details (from CWE API)
# ═════════════════════════════════════════════════════════════════════════════

def fetch_cwe_details(cwe_id: str) -> dict | None:
    """
    Get CWE weakness details from the MITRE CWE API.
    Retries up to MAX_RETRIES times on failure.
    """
    if not cwe_id or not cwe_id.startswith("CWE-"):
        return None
    
    cwe_number = cwe_id.replace("CWE-", "")
    url = f"https://cweapi.mitre.org/api/v1/cwe/{cwe_number}"
    
    for attempt in range(1, MAX_RETRIES + 1):
        _cwe_limiter.wait()
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 429:
                print(f"  [CWE] {cwe_id}: 429 (attempt {attempt}/{MAX_RETRIES})")
                _cwe_limiter.backoff(10.0)
                continue
            if resp.status_code == 200:
                data = resp.json()
                weakness = data.get("Weakness", data.get("Category", {}))
                
                # Extract mitigations
                mitigations = []
                potential_mitigations = weakness.get("Potential_Mitigations", {})
                if isinstance(potential_mitigations, dict):
                    for m in potential_mitigations.get("Mitigation", []):
                        mit_text = m.get("Description", "")
                        if isinstance(mit_text, dict):
                            mit_text = mit_text.get("text", str(mit_text))
                        mitigations.append({
                            "phase": m.get("Phase", ""),
                            "description": str(mit_text)[:500],
                        })
                
                # Extract detection methods
                detections = []
                detection_methods = weakness.get("Detection_Methods", {})
                if isinstance(detection_methods, dict):
                    for d in detection_methods.get("Detection_Method", []):
                        det_desc = d.get("Description", "")
                        if isinstance(det_desc, dict):
                            det_desc = det_desc.get("text", str(det_desc))
                        detections.append({
                            "method": d.get("Method", ""),
                            "description": str(det_desc)[:500],
                        })
                
                cwe_name = weakness.get("Name", "")
                cwe_desc = weakness.get("Description", "")
                if isinstance(cwe_desc, dict):
                    cwe_desc = cwe_desc.get("text", str(cwe_desc))
                
                print(f"  [CWE] {cwe_id}: {cwe_name}")
                return {
                    "cwe_id": cwe_id,
                    "cwe_name": cwe_name,
                    "cwe_description": str(cwe_desc)[:1000],
                    "cwe_mitigations": mitigations,
                    "cwe_detections": detections,
                }
            else:
                print(f"  [CWE] {cwe_id}: API returned {resp.status_code}")
                return None
                
        except Exception as e:
            print(f"  [CWE] {cwe_id}: FAILED attempt {attempt}/{MAX_RETRIES} ({e})")
            if attempt < MAX_RETRIES:
                time.sleep(2)
                continue
            return None
    
    return None


# ═════════════════════════════════════════════════════════════════════════════
# Source 8: MITRE ATT&CK Mapping (cached STIX)
# ═════════════════════════════════════════════════════════════════════════════

def fetch_attack_mappings(cwe_id: str) -> list:
    """
    Map a CWE ID to MITRE ATT&CK techniques/tactics via STIX data.
    Returns list of {tactic_id, tactic_name, technique_id, technique_name}.
    """
    if not cwe_id or not cwe_id.startswith("CWE-"):
        return []
    
    attack_map = _get_attack_cwe_map()
    mappings = attack_map.get(cwe_id, [])
    
    if mappings:
        print(f"  [ATT&CK] {cwe_id}: {len(mappings)} technique mappings")
    else:
        print(f"  [ATT&CK] {cwe_id}: No direct mappings found")
    
    return mappings


# ═════════════════════════════════════════════════════════════════════════════
# Source 9 (optional): VulnCheck Community API (free API key)
# ═════════════════════════════════════════════════════════════════════════════
#
# VulnCheck provides three valuable free-tier endpoints:
#   1. VulnCheck KEV — 80% more "exploited in the wild" CVEs than CISA KEV
#   2. NVD++ (nist-nvd2) — faster NVD data with enriched CPE
#   3. XDB Exploit Index — validated PoC/exploit links
#
# Sign up free at https://console.vulncheck.com
# Rate limit: 1000 req/min (community tier)

# Module-level VulnCheck batch cache
_vulncheck_kev_cache: dict[str, dict] = {}
_vulncheck_kev_lock = threading.Lock()
_vulncheck_kev_loaded = False


def _prefetch_vulncheck_kev():
    """
    Pre-fetch the VulnCheck KEV index (all entries) into memory.
    
    VulnCheck KEV contains ~80% more exploited CVEs than CISA KEV,
    including additional references, ransomware associations, and
    exploit timeline data.
    
    Only called if VULNCHECK_API_KEY is set. Uses the v3 index API.
    """
    global _vulncheck_kev_cache, _vulncheck_kev_loaded

    if not VULNCHECK_API_KEY:
        return

    headers = {"Authorization": f"Bearer {VULNCHECK_API_KEY}"}
    url = f"{VULNCHECK_BASE_URL}/index/vulncheck-kev"

    print(f"  [VulnCheck] Downloading VulnCheck KEV index...")

    try:
        _vulncheck_limiter.wait()
        resp = requests.get(url, headers=headers, timeout=60)

        if resp.status_code == 401:
            print(f"  [VulnCheck] Invalid API key — skipping VulnCheck enrichment")
            return
        if resp.status_code == 429:
            print(f"  [VulnCheck] Rate limited — skipping KEV prefetch")
            return

        resp.raise_for_status()
        data = resp.json()

        entries = data.get("data", [])
        kev_map = {}
        for entry in entries:
            cve_id = entry.get("cve", [None])
            if isinstance(cve_id, list):
                for c in cve_id:
                    if c:
                        kev_map[c] = entry
            elif cve_id:
                kev_map[cve_id] = entry

        with _vulncheck_kev_lock:
            _vulncheck_kev_cache.update(kev_map)
            _vulncheck_kev_loaded = True

        print(f"  [VulnCheck] KEV index loaded: {len(kev_map)} entries (vs CISA KEV)")

    except Exception as e:
        print(f"  [VulnCheck] Failed to download KEV index: {e}")


def fetch_vulncheck(cve_id: str) -> dict | None:
    """
    Look up CVE in VulnCheck's enriched data (KEV + exploit index).
    
    Returns dict with:
      - vulncheck_kev_listed: True if VulnCheck considers it exploited
      - vulncheck_xdb_exploits: list of validated exploit/PoC URLs
      - vulncheck_ransomware: ransomware association info
    
    Only available if VULNCHECK_API_KEY is set in .env.
    Falls back to None if key is not configured.
    """
    if not VULNCHECK_API_KEY:
        return None

    result = {}
    headers = {"Authorization": f"Bearer {VULNCHECK_API_KEY}"}

    # 1. Check VulnCheck KEV (from pre-fetched cache)
    with _vulncheck_kev_lock:
        kev_entry = _vulncheck_kev_cache.get(cve_id)

    if kev_entry:
        result["vulncheck_kev_listed"] = True
        result["vulncheck_ransomware"] = kev_entry.get("ransomware", {})
        result["vulncheck_kev_date_added"] = kev_entry.get("date_added", "")
        print(f"  [VulnCheck] {cve_id}: Found in VulnCheck KEV")
    else:
        result["vulncheck_kev_listed"] = False

    # 2. Query XDB exploit index for validated PoC links
    try:
        _vulncheck_limiter.wait()
        xdb_url = f"{VULNCHECK_BASE_URL}/index/vulncheck-xdb?cve={cve_id}"
        resp = requests.get(xdb_url, headers=headers, timeout=15)

        if resp.status_code == 200:
            data = resp.json()
            exploits = data.get("data", [])
            if exploits:
                xdb_links = []
                for exp in exploits:
                    clone_url = exp.get("clone_ssh_url") or exp.get("clone_url", "")
                    if clone_url:
                        xdb_links.append({
                            "url": clone_url,
                            "name": exp.get("repo_name", ""),
                            "date_added": exp.get("date_added", ""),
                        })
                result["vulncheck_xdb_exploits"] = xdb_links
                print(f"  [VulnCheck] {cve_id}: {len(xdb_links)} exploit repos found")
            else:
                result["vulncheck_xdb_exploits"] = []
        elif resp.status_code == 429:
            _vulncheck_limiter.backoff(10.0)
            result["vulncheck_xdb_exploits"] = []
        else:
            result["vulncheck_xdb_exploits"] = []

    except Exception as e:
        print(f"  [VulnCheck] {cve_id}: XDB query failed ({e})")
        result["vulncheck_xdb_exploits"] = []

    return result if any(v for v in result.values()) else None


# ═════════════════════════════════════════════════════════════════════════════
# Per-CVE Result Collector (thread-safe)
# ═════════════════════════════════════════════════════════════════════════════

class CVEResultCollector:
    """
    Thread-safe collector that tracks per-CVE results from all sources.
    
    Each source worker stores its result here. When all sources for a CVE
    are done (or the dependent sources have fired), the CVE is marked ready
    for DB save.
    
    Sources are split into two tiers:
      - Tier 1 (independent):  nvd, cve_org, epss, kev, osv [, vulncheck]
      - Tier 2 (depend on NVD): exploitdb, cwe, attack
    
    Tier 2 sources wait for NVD to finish (via per-CVE Event) to get
    the cwe_id and reference_urls.
    """

    TIER1_SOURCES = {"nvd", "cve_org", "epss", "kev", "osv", "vulncheck"}
    # Tier-1 sources that tier-2 waits for (only NVD and CVE.org, since
    # exploitdb needs reference URLs from both, and CWE/ATT&CK need cwe_id)
    TIER1_GATE_SOURCES = {"nvd", "cve_org"}

    def __init__(self, cve_list: list[str], total_sources: int = 8):
        self.cve_list = cve_list
        self.lock = threading.Lock()
        self.total_sources = total_sources
        
        # Per-CVE results: {cve_id: {source_name: result_dict}}
        self._results: dict[str, dict] = {cve: {} for cve in cve_list}
        
        # Per-CVE events signaling NVD+CVE.org are done (tier-2 can proceed)
        self._tier1_done_events: dict[str, threading.Event] = {
            cve: threading.Event() for cve in cve_list
        }
        
        # Track which tier-1 sources have reported per CVE
        self._tier1_reported: dict[str, set] = {cve: set() for cve in cve_list}
        
        # Per-CVE completion event (all sources done)
        self._all_done_events: dict[str, threading.Event] = {
            cve: threading.Event() for cve in cve_list
        }
        
        # Track total sources reported per CVE
        self._source_counts: dict[str, int] = {cve: 0 for cve in cve_list}
        
        # Per-source completion counters (for frontend progress display)
        self._source_completed: dict[str, int] = {}
        
        # Ordered queue of CVEs that are fully enriched and ready for save
        self.completed_queue: queue.Queue = queue.Queue()

    def store_result(self, cve_id: str, source_name: str, result):
        """Store a source result for a CVE and check completion."""
        with self.lock:
            self._results[cve_id][source_name] = result
            self._source_counts[cve_id] += 1
            
            # Track per-source completion count
            self._source_completed[source_name] = self._source_completed.get(source_name, 0) + 1
            
            # If this is a tier-1 gate source, check if all gate sources are done
            if source_name in self.TIER1_GATE_SOURCES:
                self._tier1_reported[cve_id].add(source_name)
                if self.TIER1_GATE_SOURCES.issubset(self._tier1_reported[cve_id]):
                    self._tier1_done_events[cve_id].set()
            
            # If all sources are done, mark CVE as complete
            if self._source_counts[cve_id] >= self.total_sources:
                self._all_done_events[cve_id].set()
                self.completed_queue.put(cve_id)

    def wait_for_tier1(self, cve_id: str, timeout: float = 300) -> bool:
        """Block until NVD + CVE.org results are available for this CVE."""
        return self._tier1_done_events[cve_id].wait(timeout=timeout)

    def get_nvd_data(self, cve_id: str) -> dict | None:
        """Get NVD result for a CVE (call after wait_for_tier1)."""
        with self.lock:
            return self._results.get(cve_id, {}).get("nvd")

    def get_cve_org_data(self, cve_id: str) -> dict | None:
        """Get CVE.org result for a CVE (call after wait_for_tier1)."""
        with self.lock:
            return self._results.get(cve_id, {}).get("cve_org")

    def get_all_results(self, cve_id: str) -> dict:
        """Get all results for a CVE."""
        with self.lock:
            return dict(self._results.get(cve_id, {}))

    def wait_for_completion(self, cve_id: str, timeout: float = 600) -> bool:
        """Block until all sources are done for this CVE."""
        return self._all_done_events[cve_id].wait(timeout=timeout)

    def get_source_progress(self) -> dict[str, int]:
        """Get {source_name: completed_count} snapshot for frontend progress."""
        with self.lock:
            return dict(self._source_completed)


# ═════════════════════════════════════════════════════════════════════════════
# Source Worker Threads
# ═════════════════════════════════════════════════════════════════════════════

def _source_worker(
    source_name: str,
    cve_queue: queue.Queue,
    collector: CVEResultCollector,
    fetch_fn,
    cancel_event: threading.Event | None = None,
    depends_on_tier1: bool = False,
):
    """
    Generic source worker that processes CVEs from its queue.
    
    Args:
        source_name:       Name of the source (e.g., 'nvd', 'epss')
        cve_queue:         Queue of CVE IDs to process
        collector:         Shared result collector
        fetch_fn:          Function(cve_id, ...) → result dict
        cancel_event:      Optional event to signal cancellation
        depends_on_tier1:  If True, wait for NVD+CVE.org before processing
    """
    while True:
        # Check for cancellation
        if cancel_event and cancel_event.is_set():
            return

        try:
            cve_id = cve_queue.get(timeout=1.0)
        except queue.Empty:
            return  # Queue exhausted, worker exits

        try:
            # If this source depends on tier-1 results, wait for them
            if depends_on_tier1:
                if not collector.wait_for_tier1(cve_id, timeout=300):
                    print(f"  [{source_name}] {cve_id}: Timeout waiting for NVD/CVE.org")
                    collector.store_result(cve_id, source_name, None)
                    cve_queue.task_done()
                    continue

            # Call the fetch function with appropriate arguments
            if source_name == "exploitdb":
                # Needs reference URLs from NVD + CVE.org
                nvd_data = collector.get_nvd_data(cve_id)
                cve_org_data = collector.get_cve_org_data(cve_id)
                ref_urls = (nvd_data.get("reference_urls", []) if nvd_data else [])
                if cve_org_data and cve_org_data.get("references"):
                    ref_urls = ref_urls + cve_org_data["references"]
                result = fetch_fn(cve_id, ref_urls)
            
            elif source_name in ("cwe", "attack"):
                # Needs cwe_id from NVD
                nvd_data = collector.get_nvd_data(cve_id)
                cwe_id = nvd_data.get("cwe_id") if nvd_data else None
                result = fetch_fn(cwe_id)
            
            else:
                # Independent sources (nvd, cve_org, epss, kev, osv)
                result = fetch_fn(cve_id)

            collector.store_result(cve_id, source_name, result)

        except InterruptedError:
            return
        except Exception as e:
            print(f"  [{source_name}] {cve_id}: WORKER ERROR ({e})")
            collector.store_result(cve_id, source_name, None)

        cve_queue.task_done()


# ═════════════════════════════════════════════════════════════════════════════
# Unified Per-Source Queue Enrichment Generator
# ═════════════════════════════════════════════════════════════════════════════

def enrich_all_sources_gen(cve_list: list):
    """
    Generator for unified CVE enrichment using per-source worker queues.

    Architecture:
        - 8-9 dedicated worker threads (one per source; +1 if VulnCheck key set)
        - Each source has its own queue and rate limiter
        - Independent sources (NVD, CVE.org, EPSS, KEV, OSV [, VulnCheck]) start immediately
        - Dependent sources (Exploit-DB, CWE, ATT&CK) wait for NVD+CVE.org
        - 3 retries per source per CVE on failure
        - EPSS uses batch pre-fetch (~50x fewer requests)
        - Results are merged and saved as each CVE completes all sources

    Yields:
        {
            "cve_enrichment": "running" | "completed",
            "cve_enrichment_done": "n/m",
            "source_progress": {source_name: completed_count, ...},
            "source_total": int,
        }
    """
    if not cve_list:
        yield {
            "cve_enrichment": "completed",
            "cve_enrichment_done": "0/0",
        }
        return

    total = len(cve_list)
    yield {
        "cve_enrichment": "running",
        "cve_enrichment_done": f"0/{total}",
    }

    db = DBManager()
    db.init_tables()

    # Filter out already-enriched CVEs
    cves_to_process = []
    skipped = 0
    for cve_id in cve_list:
        cve_id = cve_id.strip().upper()
        if db.check_cve_exists(cve_id) and db.check_cve_analysis_exists(cve_id):
            print(f"  [=] {cve_id}: Already enriched, skipping.")
            skipped += 1
        else:
            cves_to_process.append(cve_id)

    if not cves_to_process:
        print(f"\n  All {total} CVEs already enriched.")
        db.close()
        yield {
            "cve_enrichment": "completed",
            "cve_enrichment_done": f"{total}/{total}",
        }
        return

    # Determine active sources
    use_vulncheck = bool(VULNCHECK_API_KEY)
    num_sources = 9 if use_vulncheck else 8

    print(f"\n{'─' * 60}")
    print(f"  CVE Enrichment: {len(cves_to_process)} CVEs × {num_sources} sources (per-source queues)")
    if use_vulncheck:
        print(f"  VulnCheck API: ✓ enabled (free community tier)")
    else:
        print(f"  VulnCheck API: ✗ not configured (set VULNCHECK_API_KEY in .env for extra data)")
    if skipped:
        print(f"  Skipped: {skipped} already enriched")
    print(f"{'─' * 60}")

    # Pre-warm cached catalogs (download before starting workers)
    print(f"\n  Pre-warming cached catalogs...")
    _get_kev_lookup()
    _get_attack_cwe_map()

    # Pre-fetch EPSS scores in batch (50 CVEs per request instead of 1-by-1)
    print(f"  Pre-fetching EPSS scores via batch API...")
    _prefetch_epss_batch(cves_to_process)

    # Pre-fetch VulnCheck KEV index if API key is configured
    if use_vulncheck:
        _prefetch_vulncheck_kev()

    print(f"  Catalogs ready.\n")

    # Cancel event for cooperative shutdown
    cancel_event = threading.Event()

    # Create collector and per-source queues
    collector = CVEResultCollector(cves_to_process, total_sources=num_sources)

    # ── Define source configurations ─────────────────────────────────────
    # (source_name, fetch_function, depends_on_tier1)
    source_configs = [
        # Tier 1: Independent sources (start immediately)
        ("nvd",     fetch_nvd,             False),
        ("cve_org", fetch_cve_org,         False),
        ("epss",    fetch_epss,            False),
        ("kev",     fetch_kev_status,      False),
        ("osv",     fetch_osv,             False),
        # Tier 2: Dependent sources (wait for NVD + CVE.org)
        ("exploitdb", fetch_exploitdb,     True),
        ("cwe",       fetch_cwe_details,   True),
        ("attack",    fetch_attack_mappings, True),
    ]

    # Conditionally add VulnCheck if API key is present
    if use_vulncheck:
        source_configs.append(("vulncheck", fetch_vulncheck, False))

    # Create per-source queues and fill them with CVE IDs
    source_queues: dict[str, queue.Queue] = {}
    for source_name, _, _ in source_configs:
        q = queue.Queue()
        for cve_id in cves_to_process:
            q.put(cve_id)
        source_queues[source_name] = q

    # Launch worker threads (one per source)
    workers = []
    for source_name, fetch_fn, depends_on_tier1 in source_configs:
        t = threading.Thread(
            target=_source_worker,
            args=(
                source_name,
                source_queues[source_name],
                collector,
                fetch_fn,
                cancel_event,
                depends_on_tier1,
            ),
            name=f"worker-{source_name}",
            daemon=True,
        )
        t.start()
        workers.append(t)

    # ── Collect results and yield progress as CVEs complete ───────────────
    completed_count = skipped
    try:
        while completed_count < total:
            # Check for engine cancellation
            try:
                from engine_progress import is_cancelled
                if is_cancelled():
                    cancel_event.set()
                    raise InterruptedError("Engine cancelled by user")
            except ImportError:
                pass

            try:
                cve_id = collector.completed_queue.get(timeout=2.0)
            except queue.Empty:
                # Even if no CVE completed yet, yield current source progress
                yield {
                    "cve_enrichment": "running",
                    "cve_enrichment_done": f"{completed_count}/{total}",
                    "source_progress": collector.get_source_progress(),
                    "source_total": len(cves_to_process),
                }
                continue

            # All sources done for this CVE — save to DB
            results = collector.get_all_results(cve_id)
            _save_enrichment(db, cve_id, results)
            completed_count += 1

            print(f"\n  ✓ {cve_id} saved ({completed_count}/{total})")

            yield {
                "cve_enrichment": "running",
                "cve_enrichment_done": f"{completed_count}/{total}",
                "source_progress": collector.get_source_progress(),
                "source_total": len(cves_to_process),
            }

    except InterruptedError:
        cancel_event.set()
        raise
    finally:
        # Signal workers to stop and wait for them
        cancel_event.set()
        for t in workers:
            t.join(timeout=5)
        db.close()

    print(f"\n  Enrichment complete: {total} CVEs processed.")

    yield {
        "cve_enrichment": "completed",
        "cve_enrichment_done": f"{total}/{total}",
        "source_progress": collector.get_source_progress(),
        "source_total": len(cves_to_process),
    }


def _save_enrichment(db: DBManager, cve_id: str, results: dict):
    """Save merged enrichment results to database."""
    
    nvd_data = results.get("nvd")
    epss_data = results.get("epss")
    kev_data = results.get("kev")
    cwe_data = results.get("cwe")
    exploitdb_data = results.get("exploitdb")
    osv_data = results.get("osv")
    attack_data = results.get("attack")
    vulncheck_data = results.get("vulncheck")
    
    # ── Save NVD core data ───────────────────────────────────────────────
    if nvd_data:
        # Merge CWE name from CWE catalog
        if cwe_data and cwe_data.get("cwe_name"):
            nvd_data["cwe_name"] = cwe_data["cwe_name"]
        
        # Merge EPSS data
        if epss_data:
            nvd_data["epss_score"] = epss_data.get("epss_score")
            nvd_data["epss_percentile"] = epss_data.get("epss_percentile")
        
        # Merge KEV status (prefer VulnCheck KEV if available, as it has more coverage)
        if vulncheck_data and vulncheck_data.get("vulncheck_kev_listed"):
            nvd_data["kev_listed"] = True
        elif kev_data:
            nvd_data["kev_listed"] = kev_data.get("kev_listed", False)
        
        # Merge exploit availability (combine ExploitDB + VulnCheck XDB)
        has_exploitdb = exploitdb_data and exploitdb_data.get("exploit_available", False)
        has_vulncheck_xdb = (vulncheck_data and 
                             vulncheck_data.get("vulncheck_xdb_exploits") and
                             len(vulncheck_data["vulncheck_xdb_exploits"]) > 0)
        if has_exploitdb or has_vulncheck_xdb:
            nvd_data["exploit_available"] = True
        elif exploitdb_data:
            nvd_data["exploit_available"] = exploitdb_data.get("exploit_available", False)
        
        db.save_cve_nvd_data(cve_id, nvd_data)
    
    # ── Save enrichment analysis ─────────────────────────────────────────
    analysis = {
        "title": nvd_data.get("description", "")[:200] if nvd_data else cve_id,
        "exploitation": {},
        "mitigations": [],
        "detection_recommendations": [],
        "vulnerability_walkthrough": [],
        "mitre_attack_mapping": [],
        "references": [],
    }
    
    # EPSS exploitation info
    if epss_data:
        analysis["exploitation"]["epss_score"] = epss_data.get("epss_score")
        analysis["exploitation"]["epss_percentile"] = epss_data.get("epss_percentile")
        analysis["exploitation"]["epss_date"] = epss_data.get("epss_date")
    
    # KEV exploitation info
    if kev_data:
        analysis["exploitation"]["kev_listed"] = kev_data.get("kev_listed", False)
        if kev_data.get("kev_listed"):
            analysis["exploitation"]["kev_date_added"] = kev_data.get("kev_date_added")
            analysis["exploitation"]["kev_due_date"] = kev_data.get("kev_due_date")
            analysis["exploitation"]["kev_ransomware"] = kev_data.get("kev_ransomware")
            analysis["exploitation"]["kev_required_action"] = kev_data.get("kev_required_action")
            analysis["exploitation"]["kev_vuln_name"] = kev_data.get("kev_vuln_name")
    
    # Exploit-DB and PoC references
    if exploitdb_data:
        analysis["exploitation"]["exploit_available"] = exploitdb_data.get("exploit_available", False)
        analysis["exploitation"]["exploit_count"] = exploitdb_data.get("exploit_count", 0)
        analysis["exploitation"]["exploit_refs"] = exploitdb_data.get("exploit_refs", [])
        analysis["exploitation"]["github_pocs"] = exploitdb_data.get("github_pocs", [])
    
    # VulnCheck enhanced data (if API key configured)
    if vulncheck_data:
        if vulncheck_data.get("vulncheck_kev_listed"):
            analysis["exploitation"]["vulncheck_kev_listed"] = True
            analysis["exploitation"]["vulncheck_kev_date_added"] = vulncheck_data.get("vulncheck_kev_date_added", "")
            analysis["exploitation"]["vulncheck_ransomware"] = vulncheck_data.get("vulncheck_ransomware", {})
        if vulncheck_data.get("vulncheck_xdb_exploits"):
            # Add VulnCheck exploit repos alongside ExploitDB refs
            xdb_refs = []
            for xdb in vulncheck_data["vulncheck_xdb_exploits"]:
                xdb_refs.append({
                    "source": "vulncheck-xdb",
                    "url": xdb.get("url", ""),
                    "name": xdb.get("name", ""),
                    "date_added": xdb.get("date_added", ""),
                })
            analysis["exploitation"]["vulncheck_xdb_exploits"] = xdb_refs
            # Combine with ExploitDB count for total exploit availability
            existing_count = analysis["exploitation"].get("exploit_count", 0)
            analysis["exploitation"]["exploit_count"] = existing_count + len(xdb_refs)
            analysis["exploitation"]["exploit_available"] = True
    
    # CWE-based mitigations and detection
    if cwe_data:
        analysis["mitigations"] = cwe_data.get("cwe_mitigations", [])
        analysis["detection_recommendations"] = cwe_data.get("cwe_detections", [])
        analysis["vulnerability_walkthrough"] = [{
            "step": "Weakness Overview",
            "description": cwe_data.get("cwe_description", ""),
        }]
    
    # MITRE ATT&CK mappings
    if attack_data:
        analysis["mitre_attack_mapping"] = attack_data
    
    # OSV affected packages as references
    if osv_data and osv_data.get("packages"):
        for pkg in osv_data["packages"]:
            analysis["references"].append({
                "source": "osv.dev",
                "ecosystem": pkg.get("ecosystem"),
                "package": pkg.get("name"),
                "fix_versions": pkg.get("fix_versions", []),
            })
    
    # Save analysis (reuses existing DB method)
    db.save_cve_analysis(cve_id, analysis)


# ═════════════════════════════════════════════════════════════════════════════
# CLI Pipeline (standalone execution)
# ═════════════════════════════════════════════════════════════════════════════

def run_pipeline(cve_list: list):
    """Run the full enrichment pipeline from CLI."""
    print(f"\n{'═' * 60}")
    print(f"  CVE Multi-Source Enrichment Pipeline")
    print(f"  Architecture: Per-source worker queues")
    print(f"  Sources: NVD, CVE.org, EPSS, CISA KEV, OSV.dev,")
    print(f"           Exploit-DB, CWE, MITRE ATT&CK")
    if VULNCHECK_API_KEY:
        print(f"           + VulnCheck (community API key)")
    print(f"{'═' * 60}")
    print(f"  CVEs to process: {len(cve_list)}")

    for progress in enrich_all_sources_gen(cve_list):
        status = progress.get("cve_enrichment", "running")
        done = progress.get("cve_enrichment_done", "0/0")
        print(f"\r  Overall: {status} | {done}", end="")
    
    print(f"\n\n{'═' * 60}")
    print(f"  Pipeline complete!")
    print(f"{'═' * 60}\n")


# ═════════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═════════════════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print("Usage: python cve_mapper.py CVE-2024-1234,CVE-2024-5678")
        print("\nEnriches CVEs from 8 public intelligence sources:")
        print("  NVD, CVE.org, FIRST EPSS, CISA KEV, OSV.dev,")
        print("  Exploit-DB, CWE Catalog, MITRE ATT&CK STIX")
        sys.exit(1)

    cve_input = sys.argv[1]
    cve_list = [c.strip() for c in cve_input.split(",") if c.strip()]

    if not cve_list:
        print("Error: No valid CVE IDs provided.")
        sys.exit(1)

    run_pipeline(cve_list)


if __name__ == "__main__":
    main()
