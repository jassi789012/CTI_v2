"""
CTI_V2 Database Manager
=======================
Central module for PostgreSQL database operations.
Handles connection, schema creation, and CRUD for:
  - hosts, scans, ports, vulnerabilities, technologies

Usage:
    from db_manager import DBManager

    db = DBManager()           # connects using .env credentials
    db.init_tables()           # creates tables if they don't exist
    db.save_shodan_scan(data)  # inserts a full Shodan scan result
    db.close()
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
from psycopg2.extras import Json, RealDictCursor
from dotenv import load_dotenv

# ─── Load environment ────────────────────────────────────────────────────────
ENV_PATH = Path(__file__).resolve().parents[1] / ".env"  # CTI_V2/.env
load_dotenv(dotenv_path=ENV_PATH)


def _get_connection_params() -> dict:
    """Build connection params from environment variables."""
    return {
        "host": os.getenv("PG_HOST", "localhost"),
        "port": int(os.getenv("PG_PORT", "5432")),
        "dbname": os.getenv("PG_DATABASE", "cti_db"),
        "user": os.getenv("PG_USER", "postgres"),
        "password": os.getenv("PG_PASSWORD", "postgres"),
    }


# ═════════════════════════════════════════════════════════════════════════════
# Schema DDL
# ═════════════════════════════════════════════════════════════════════════════

SCHEMA_SQL = """
-- 1. Hosts — central registry of every IP
CREATE TABLE IF NOT EXISTS hosts (
    id           SERIAL PRIMARY KEY,
    ip           INET NOT NULL UNIQUE,
    country      TEXT,
    city         TEXT,
    organization TEXT,
    isp          TEXT,
    asn          TEXT,
    os           TEXT,
    tags         JSONB DEFAULT '[]'::jsonb,
    first_seen   TIMESTAMPTZ DEFAULT NOW(),
    last_updated TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hosts_ip       ON hosts (ip);
CREATE INDEX IF NOT EXISTS idx_hosts_country  ON hosts (country);
CREATE INDEX IF NOT EXISTS idx_hosts_asn      ON hosts (asn);
CREATE INDEX IF NOT EXISTS idx_hosts_org      ON hosts (organization);
CREATE INDEX IF NOT EXISTS idx_hosts_tags     ON hosts USING GIN (tags);

-- 2. Scans — every scan snapshot (timeline)
CREATE TABLE IF NOT EXISTS scans (
    id               SERIAL PRIMARY KEY,
    host_id          INT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    source           TEXT NOT NULL,
    source_last_seen DATE,
    scraped_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    raw_data         JSONB,
    metadata         JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_scans_host_id          ON scans (host_id);
CREATE INDEX IF NOT EXISTS idx_scans_source           ON scans (source);
CREATE INDEX IF NOT EXISTS idx_scans_scraped_at       ON scans (scraped_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_dedup            ON scans (host_id, source, source_last_seen);

-- 3. Ports — discovered ports & banners
CREATE TABLE IF NOT EXISTS ports (
    id          SERIAL PRIMARY KEY,
    scan_id     INT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    port_number INT NOT NULL,
    protocol    TEXT DEFAULT 'tcp',
    state       TEXT DEFAULT 'open',
    service     TEXT,
    version     TEXT,
    http_title  TEXT,
    banner      TEXT,
    timestamp   DATE,
    extra       JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_ports_scan_id     ON ports (scan_id);
CREATE INDEX IF NOT EXISTS idx_ports_port_number ON ports (port_number);
CREATE INDEX IF NOT EXISTS idx_ports_service     ON ports (service);

-- 4. Vulnerabilities — CVEs per port
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          SERIAL PRIMARY KEY,
    port_id     INT NOT NULL REFERENCES ports(id) ON DELETE CASCADE,
    cve_id      TEXT NOT NULL,
    cvss        FLOAT,
    cvss_vector TEXT,
    summary     TEXT
);

CREATE INDEX IF NOT EXISTS idx_vulns_port_id ON vulnerabilities (port_id);
CREATE INDEX IF NOT EXISTS idx_vulns_cve_id  ON vulnerabilities (cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_cvss    ON vulnerabilities (cvss DESC);

-- 5. Technologies — web technologies detected
CREATE TABLE IF NOT EXISTS technologies (
    id       SERIAL PRIMARY KEY,
    scan_id  INT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    category TEXT,
    name     TEXT NOT NULL,
    version  TEXT
);

CREATE INDEX IF NOT EXISTS idx_tech_scan_id ON technologies (scan_id);
CREATE INDEX IF NOT EXISTS idx_tech_name    ON technologies (name);

-- 6. CVE Details — enriched CVE data from NVD
CREATE TABLE IF NOT EXISTS cve_details (
    id                     SERIAL PRIMARY KEY,
    cve_id                 TEXT NOT NULL UNIQUE,
    description            TEXT,
    cwe_id                 TEXT,
    cwe_name               TEXT,
    cvss_version           TEXT,
    cvss_vector            TEXT,
    attack_vector          TEXT,
    attack_complexity      TEXT,
    privileges_required    TEXT,
    user_interaction       TEXT,
    scope                  TEXT,
    confidentiality_impact TEXT,
    integrity_impact       TEXT,
    availability_impact    TEXT,
    base_score             FLOAT,
    severity               TEXT,
    published_date         TEXT,
    last_modified_date     TEXT,
    reference_urls         JSONB DEFAULT '[]'::jsonb,
    nvd_raw                JSONB,
    fetched_at             TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cve_details_cve_id   ON cve_details (cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_details_severity ON cve_details (severity);
CREATE INDEX IF NOT EXISTS idx_cve_details_score    ON cve_details (base_score DESC);

-- 7. CVE Affected Products — CPE data from NVD
CREATE TABLE IF NOT EXISTS cve_affected_products (
    id              SERIAL PRIMARY KEY,
    cve_detail_id   INT NOT NULL REFERENCES cve_details(id) ON DELETE CASCADE,
    vendor          TEXT,
    product         TEXT,
    version         TEXT,
    affected_platform TEXT
);

CREATE INDEX IF NOT EXISTS idx_cve_ap_detail_id ON cve_affected_products (cve_detail_id);
CREATE INDEX IF NOT EXISTS idx_cve_ap_vendor    ON cve_affected_products (vendor);
CREATE INDEX IF NOT EXISTS idx_cve_ap_product   ON cve_affected_products (product);

-- 8. CVE Analysis — ChatGPT enrichment
CREATE TABLE IF NOT EXISTS cve_analysis (
    id                        SERIAL PRIMARY KEY,
    cve_detail_id             INT NOT NULL UNIQUE REFERENCES cve_details(id) ON DELETE CASCADE,
    title                     TEXT,
    exploitation_info         JSONB,
    mitigations               JSONB,
    detection_recommendations JSONB,
    vulnerability_walkthrough JSONB,
    chatgpt_references        JSONB,
    chatgpt_raw               JSONB,
    analyzed_at               TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cve_analysis_detail_id ON cve_analysis (cve_detail_id);

-- 9. CVE MITRE ATT&CK Mappings — from ChatGPT
CREATE TABLE IF NOT EXISTS cve_mitre_mappings (
    id               SERIAL PRIMARY KEY,
    cve_analysis_id  INT NOT NULL REFERENCES cve_analysis(id) ON DELETE CASCADE,
    tactic_id        TEXT,
    tactic_name      TEXT,
    technique_id     TEXT,
    technique_name   TEXT,
    justification    TEXT
);

CREATE INDEX IF NOT EXISTS idx_cve_mitre_analysis_id  ON cve_mitre_mappings (cve_analysis_id);
CREATE INDEX IF NOT EXISTS idx_cve_mitre_technique_id ON cve_mitre_mappings (technique_id);

-- 10. Nmap scan phase checkpoints (for resume support)
CREATE TABLE IF NOT EXISTS nmap_scan_checkpoints (
    id               SERIAL PRIMARY KEY,
    ip               INET NOT NULL,
    engine_thread_id TEXT NOT NULL,
    last_phase       INT NOT NULL,
    state_data       JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at       TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(ip, engine_thread_id)
);

CREATE INDEX IF NOT EXISTS idx_nmap_cp_ip ON nmap_scan_checkpoints (ip);
"""


# ═════════════════════════════════════════════════════════════════════════════
# DBManager Class
# ═════════════════════════════════════════════════════════════════════════════

class DBManager:
    """
    Manages all PostgreSQL operations for CTI_V2.

    Usage:
        db = DBManager()
        db.init_tables()
        db.save_shodan_scan(parsed_data)
        db.close()
    """

    def __init__(self, conn_params: dict = None):
        """
        Connect to PostgreSQL.
        If conn_params is not provided, reads from .env / environment variables.
        """
        params = conn_params or _get_connection_params()
        try:
            self.conn = psycopg2.connect(**params)
            self.conn.autocommit = False
            print(f"[+] Connected to PostgreSQL: {params['host']}:{params['port']}/{params['dbname']}")
        except psycopg2.OperationalError as e:
            print(f"[-] Failed to connect to PostgreSQL: {e}")
            raise

    def close(self):
        """Close the database connection."""
        if self.conn and not self.conn.closed:
            self.conn.close()
            print("[+] Database connection closed.")

    def init_tables(self):
        """Create all tables and indexes if they don't exist."""
        try:
            with self.conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)
            self.conn.commit()
            print("[+] Database tables initialized successfully.")
        except Exception as e:
            self.conn.rollback()
            print(f"[-] Failed to initialize tables: {e}")
            raise

    # ─── Host Operations ─────────────────────────────────────────────────────

    def upsert_host(self, ip: str, general_info: dict) -> int:
        """
        Insert or update a host record. Returns the host ID.

        If the IP already exists, updates the general info fields
        and bumps last_updated.
        """
        tags = general_info.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]

        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO hosts (ip, country, city, organization, isp, asn, os, tags)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (ip) DO UPDATE SET
                    country      = COALESCE(EXCLUDED.country, hosts.country),
                    city         = COALESCE(EXCLUDED.city, hosts.city),
                    organization = COALESCE(EXCLUDED.organization, hosts.organization),
                    isp          = COALESCE(EXCLUDED.isp, hosts.isp),
                    asn          = COALESCE(EXCLUDED.asn, hosts.asn),
                    os           = COALESCE(EXCLUDED.os, hosts.os),
                    tags         = EXCLUDED.tags,
                    last_updated = NOW()
                RETURNING id
            """, (
                ip,
                general_info.get("Country"),
                general_info.get("City"),
                general_info.get("Organization"),
                general_info.get("ISP"),
                general_info.get("ASN"),
                general_info.get("OS"),
                Json(tags),
            ))
            host_id = cur.fetchone()[0]
        return host_id

    # ─── Scan Operations ─────────────────────────────────────────────────────

    def check_scan_exists(self, host_id: int, source: str, source_last_seen) -> bool:
        """
        Check if a scan with the same host_id, source, and source_last_seen
        already exists (deduplication check).
        """
        with self.conn.cursor() as cur:
            if source_last_seen is None:
                cur.execute("""
                    SELECT id FROM scans
                    WHERE host_id = %s AND source = %s AND source_last_seen IS NULL
                    LIMIT 1
                """, (host_id, source))
            else:
                cur.execute("""
                    SELECT id FROM scans
                    WHERE host_id = %s AND source = %s AND source_last_seen = %s
                    LIMIT 1
                """, (host_id, source, source_last_seen))
            return cur.fetchone() is not None

    def get_latest_last_seen(self, ip: str, source: str = "shodan"):
        """
        Get the most recent source_last_seen date for an IP from a given source.
        Returns None if IP has never been scanned by this source.
        """
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT s.source_last_seen
                FROM scans s
                JOIN hosts h ON h.id = s.host_id
                WHERE h.ip = %s::inet AND s.source = %s
                ORDER BY s.scraped_at DESC
                LIMIT 1
            """, (ip, source))
            row = cur.fetchone()
            if row and row[0]:
                return str(row[0])
            return None

    def insert_scan(self, host_id: int, source: str, source_last_seen,
                    scraped_at: str, raw_data: dict, metadata: dict) -> int:
        """Insert a new scan record. Returns the scan ID."""
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO scans (host_id, source, source_last_seen, scraped_at, raw_data, metadata)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                host_id, source, source_last_seen, scraped_at,
                Json(raw_data), Json(metadata),
            ))
            return cur.fetchone()[0]

    # ─── Port Operations ─────────────────────────────────────────────────────

    def insert_port(self, scan_id: int, port_data: dict) -> int:
        """Insert a port record. Returns the port ID."""
        # Parse timestamp safely
        ts = port_data.get("timestamp")

        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO ports (scan_id, port_number, protocol, state, service,
                                   version, http_title, banner, timestamp, extra)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                scan_id,
                port_data.get("port"),
                port_data.get("protocol", "tcp"),
                port_data.get("state", "open"),
                port_data.get("service"),
                port_data.get("version"),
                port_data.get("http_title"),
                port_data.get("banner"),
                ts,
                Json(port_data.get("extra", {})),
            ))
            return cur.fetchone()[0]

    # ─── Vulnerability Operations ─────────────────────────────────────────────

    def insert_vulnerabilities(self, port_id: int, cve_list: list):
        """Insert multiple CVE records for a port."""
        if not cve_list:
            return

        with self.conn.cursor() as cur:
            for cve in cve_list:
                cur.execute("""
                    INSERT INTO vulnerabilities (port_id, cve_id, cvss, cvss_vector, summary)
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    port_id,
                    cve.get("cve"),
                    cve.get("cvss"),
                    cve.get("cvss_vector"),
                    cve.get("summary"),
                ))

    # ─── Technology Operations ────────────────────────────────────────────────

    def insert_technologies(self, scan_id: int, web_technologies: dict):
        """Insert web technology records from the Shodan web_technologies dict."""
        if not web_technologies:
            return

        with self.conn.cursor() as cur:
            for category, tech_list in web_technologies.items():
                for tech in tech_list:
                    cur.execute("""
                        INSERT INTO technologies (scan_id, category, name, version)
                        VALUES (%s, %s, %s, %s)
                    """, (
                        scan_id,
                        category,
                        tech.get("name"),
                        tech.get("version"),
                    ))

    # ═════════════════════════════════════════════════════════════════════════
    # High-Level: Save a Complete Shodan Scan
    # ═════════════════════════════════════════════════════════════════════════

    def save_shodan_scan(self, parsed_data: dict) -> bool:
        """
        Save a complete Shodan scan result into the database.

        This is the main method called by get_ip_info.py. It:
          1. Upserts the host record
          2. Checks for deduplication (same last_seen = skip)
          3. Inserts scan, ports, vulnerabilities, and technologies
          4. Commits the transaction

        Returns True if data was saved, False if skipped (duplicate).
        """
        ip = parsed_data.get("ip")
        if not ip:
            print("[-] Cannot save scan: no IP in parsed data.")
            return False

        # Skip error-only results
        if "error" in parsed_data and len(parsed_data) <= 2:
            print(f"[-] Skipping {ip}: error result only.")
            return False

        try:
            # 1. Upsert host
            general_info = parsed_data.get("general_info", {})
            host_id = self.upsert_host(ip, general_info)

            # 2. Deduplication check
            source_last_seen = parsed_data.get("last_seen")
            if self.check_scan_exists(host_id, "shodan", source_last_seen):
                print(f"[=] IP {ip}: last_seen unchanged ({source_last_seen}). Skipping save.")
                self.conn.commit()  # commit the host upsert at least
                return False

            # 3. Build metadata (source-specific extras)
            metadata = {}
            if parsed_data.get("security_contact"):
                metadata["security_contact"] = parsed_data["security_contact"]
            if parsed_data.get("timeline"):
                metadata["timeline"] = parsed_data["timeline"]

            # 4. Insert scan
            scan_id = self.insert_scan(
                host_id=host_id,
                source="shodan",
                source_last_seen=source_last_seen,
                scraped_at=parsed_data.get("scraped_at", datetime.now(timezone.utc).isoformat()),
                raw_data=parsed_data,
                metadata=metadata,
            )

            # 5. Insert ports + vulnerabilities
            total_cves = 0
            for banner in parsed_data.get("port_banners", []):
                port_id = self.insert_port(scan_id, banner)
                cve_list = banner.get("cve_details", [])
                if cve_list:
                    self.insert_vulnerabilities(port_id, cve_list)
                    total_cves += len(cve_list)

            # 6. Insert technologies
            self.insert_technologies(scan_id, parsed_data.get("web_technologies", {}))

            # 7. Commit the whole transaction
            self.conn.commit()

            port_count = len(parsed_data.get("port_banners", []))
            tech_count = sum(len(v) for v in parsed_data.get("web_technologies", {}).values())
            print(f"[+] IP {ip}: Saved to database (scan_id={scan_id}, "
                  f"{port_count} ports, {total_cves} CVEs, {tech_count} technologies).")
            return True

        except Exception as e:
            self.conn.rollback()
            print(f"[-] Error saving {ip} to database: {e}")
            return False

    # ═════════════════════════════════════════════════════════════════════════
    # High-Level: Save a Complete Nmap Scan
    # ═════════════════════════════════════════════════════════════════════════

    def save_nmap_scan(self, parsed_data: dict) -> bool:
        """
        Save a complete Nmap scan result into the database.

        This mirrors save_shodan_scan() but for Nmap data. It:
          1. Upserts the host record (shares the hosts table with Shodan)
          2. Inserts a scan with source='nmap'
          3. Inserts ports, vulnerabilities
          4. Commits the transaction

        Returns True if data was saved, False if skipped/failed.
        """
        ip = parsed_data.get("ip")
        if not ip:
            print("[-] Cannot save nmap scan: no IP in parsed data.")
            return False

        if "error" in parsed_data:
            print(f"[-] Skipping {ip}: error result.")
            return False

        try:
            # 1. Upsert host
            general_info = parsed_data.get("general_info", {})
            host_id = self.upsert_host(ip, general_info)

            # 2. Build metadata (nmap-specific extras)
            metadata = {}
            if parsed_data.get("os_detection"):
                metadata["os_detection"] = parsed_data["os_detection"]
            if parsed_data.get("uptime"):
                metadata["uptime"] = parsed_data["uptime"]
            if parsed_data.get("tcp_sequence"):
                metadata["tcp_sequence"] = parsed_data["tcp_sequence"]
            if parsed_data.get("traceroute"):
                metadata["traceroute"] = parsed_data["traceroute"]
            if parsed_data.get("scan_info"):
                metadata["scan_info"] = parsed_data["scan_info"]
            if parsed_data.get("geolocation"):
                metadata["geolocation"] = parsed_data["geolocation"]
            if parsed_data.get("firewall_detection"):
                metadata["firewall_detection"] = parsed_data["firewall_detection"]
            if parsed_data.get("ssh_info"):
                metadata["ssh_info"] = parsed_data["ssh_info"]
            if parsed_data.get("dns_info"):
                metadata["dns_info"] = parsed_data["dns_info"]
            if parsed_data.get("scan_duration_seconds"):
                metadata["scan_duration_seconds"] = parsed_data["scan_duration_seconds"]
            if parsed_data.get("whois"):
                metadata["whois"] = parsed_data["whois"]
            if parsed_data.get("ip_protocols"):
                metadata["ip_protocols"] = parsed_data["ip_protocols"]
            if parsed_data.get("hostscripts"):
                metadata["hostscripts"] = parsed_data["hostscripts"]
            if parsed_data.get("smb_info"):
                metadata["smb_info"] = parsed_data["smb_info"]

            hostnames = general_info.get("hostnames", [])
            if hostnames:
                metadata["hostnames"] = hostnames

            mac = general_info.get("mac_address")
            if mac:
                metadata["mac_address"] = mac
                metadata["mac_vendor"] = general_info.get("mac_vendor")

            # 3. Insert scan — use current time as source_last_seen since Nmap is live
            scraped_at = parsed_data.get("scraped_at", datetime.now(timezone.utc).isoformat())
            today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

            scan_id = self.insert_scan(
                host_id=host_id,
                source="nmap",
                source_last_seen=today_str,
                scraped_at=scraped_at,
                raw_data=parsed_data,
                metadata=metadata,
            )

            # 4. Insert ports + vulnerabilities
            total_cves = 0
            for banner in parsed_data.get("port_banners", []):
                port_id = self.insert_port(scan_id, banner)
                cve_list = banner.get("cve_details", [])
                if cve_list:
                    self.insert_vulnerabilities(port_id, cve_list)
                    total_cves += len(cve_list)

            # 5. Commit the whole transaction
            self.conn.commit()

            port_count = len(parsed_data.get("port_banners", []))
            os_name = general_info.get("OS", "Unknown")
            print(f"[+] IP {ip}: Nmap scan saved (scan_id={scan_id}, "
                  f"{port_count} ports, {total_cves} CVEs, OS: {os_name}).")
            return True

        except Exception as e:
            self.conn.rollback()
            print(f"[-] Error saving nmap scan for {ip}: {e}")
            return False

    # ─── Nmap Scan Checkpoints (resume support) ──────────────────────────────

    def save_nmap_checkpoint(self, ip: str, engine_thread_id: str, last_phase: int, state_data: dict):
        """Save or update a scan checkpoint so the scan can resume after a crash."""
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO nmap_scan_checkpoints (ip, engine_thread_id, last_phase, state_data)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (ip, engine_thread_id) DO UPDATE
                SET last_phase = EXCLUDED.last_phase,
                    state_data = EXCLUDED.state_data,
                    updated_at = NOW()
            """, (ip, engine_thread_id, last_phase, Json(state_data)))
        self.conn.commit()

    def load_nmap_checkpoint(self, ip: str, engine_thread_id: str) -> dict | None:
        """Load the most recent checkpoint for an IP scan. Returns None if no checkpoint."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT last_phase, state_data FROM nmap_scan_checkpoints
                WHERE ip = %s AND engine_thread_id = %s
            """, (ip, engine_thread_id))
            row = cur.fetchone()
        if row:
            return dict(row)
        return None

    def delete_nmap_checkpoint(self, ip: str, engine_thread_id: str):
        """Remove checkpoint after scan completes successfully."""
        with self.conn.cursor() as cur:
            cur.execute("""
                DELETE FROM nmap_scan_checkpoints
                WHERE ip = %s AND engine_thread_id = %s
            """, (ip, engine_thread_id))
        self.conn.commit()

    # ─── Staleness Check ─────────────────────────────────────────────────

    def get_last_scan_date(self, ip: str, source: str = None):
        """
        Get the most recent scraped_at timestamp for an IP, optionally filtered by source.

        Used by the 2-week staleness check: if the most recent scan is less than
        14 days old, the IP can be skipped to avoid redundant scanning.

        Args:
            ip:     Target IP address string.
            source: Optional filter by scan source ('shodan', 'nmap'). If None,
                    returns the most recent scan across all sources.

        Returns:
            datetime object of the most recent scraped_at, or None if never scanned.
        """
        try:
            with self.conn.cursor() as cur:
                if source:
                    cur.execute("""
                        SELECT s.scraped_at
                        FROM scans s
                        JOIN hosts h ON h.id = s.host_id
                        WHERE h.ip = %s::inet AND s.source = %s
                        ORDER BY s.scraped_at DESC
                        LIMIT 1
                    """, (ip.strip(), source))
                else:
                    cur.execute("""
                        SELECT s.scraped_at
                        FROM scans s
                        JOIN hosts h ON h.id = s.host_id
                        WHERE h.ip = %s::inet
                        ORDER BY s.scraped_at DESC
                        LIMIT 1
                    """, (ip.strip(),))
                row = cur.fetchone()
                return row[0] if row else None
        except Exception:
            self.conn.rollback()
            return None

    def is_scan_stale(self, ip: str, source: str = None, max_age_days: int = 14) -> bool:
        """
        Check whether an IP needs re-scanning based on scan age.

        Returns True if:
          - The IP has never been scanned by the given source, OR
          - The most recent scan is older than max_age_days (default 14 days).

        Returns False if:
          - A scan exists and is within the freshness window.

        Args:
            ip:           Target IP address.
            source:       Optional source filter ('shodan', 'nmap').
            max_age_days: Maximum age in days before a scan is considered stale.

        Returns:
            True if the IP should be (re-)scanned, False if data is fresh enough.
        """
        last_scan = self.get_last_scan_date(ip, source=source)
        if last_scan is None:
            return True  # Never scanned — needs scanning

        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)

        # Ensure last_scan is timezone-aware
        if last_scan.tzinfo is None:
            last_scan = last_scan.replace(tzinfo=timezone.utc)

        age = now - last_scan
        is_stale = age > timedelta(days=max_age_days)

        if is_stale:
            print(f"[*] Scan for {ip} (source={source}) is {age.days} days old — stale (>{max_age_days}d). Will re-scan.")
        else:
            print(f"[=] Scan for {ip} (source={source}) is {age.days} days old — fresh (<={max_age_days}d). Skipping.")

        return is_stale


    # Query Helpers (for agent and scripts)
    # ═════════════════════════════════════════════════════════════════════════

    def get_host_by_ip(self, ip: str) -> dict:
        """Get host info by IP address. Returns None if not found or invalid."""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM hosts WHERE ip = %s::inet", (ip.strip(),))
                row = cur.fetchone()
                return dict(row) if row else None
        except Exception:
            self.conn.rollback()
            return None

    def get_scan_count(self, ip: str, source: str = None) -> int:
        """Get the number of scans for an IP, optionally filtered by source."""
        try:
            with self.conn.cursor() as cur:
                if source:
                    cur.execute("""
                        SELECT COUNT(*) FROM scans s
                        JOIN hosts h ON h.id = s.host_id
                        WHERE h.ip = %s::inet AND s.source = %s
                    """, (ip.strip(), source))
                else:
                    cur.execute("""
                        SELECT COUNT(*) FROM scans s
                        JOIN hosts h ON h.id = s.host_id
                        WHERE h.ip = %s::inet
                    """, (ip.strip(),))
                row = cur.fetchone()
                return row[0] if row else 0
        except Exception:
            self.conn.rollback()
            return 0

    def get_host_timeline(self, ip: str) -> list:
        """Get all scan snapshots for an IP, ordered by date (newest first)."""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT s.id, s.source, s.source_last_seen, s.scraped_at, s.metadata
                    FROM scans s
                    JOIN hosts h ON h.id = s.host_id
                    WHERE h.ip = %s::inet
                    ORDER BY s.scraped_at DESC
                """, (ip.strip(),))
                return [dict(row) for row in cur.fetchall()]
        except Exception:
            self.conn.rollback()
            return []

    # ═════════════════════════════════════════════════════════════════════════
    # CVE Operations (for cve_mapper)
    # ═════════════════════════════════════════════════════════════════════════

    def check_cve_exists(self, cve_id: str) -> bool:
        """Check if a CVE already has NVD data stored."""
        with self.conn.cursor() as cur:
            cur.execute("SELECT id FROM cve_details WHERE cve_id = %s", (cve_id,))
            return cur.fetchone() is not None

    def check_cve_analysis_exists(self, cve_id: str) -> bool:
        """Check if a CVE already has ChatGPT analysis stored."""
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT ca.id FROM cve_analysis ca
                JOIN cve_details cd ON cd.id = ca.cve_detail_id
                WHERE cd.cve_id = %s
            """, (cve_id,))
            return cur.fetchone() is not None

    def save_cve_nvd_data(self, cve_id: str, nvd_parsed: dict) -> int:
        """
        Upsert NVD data for a CVE. Returns the cve_detail_id.

        nvd_parsed should contain:
            description, cwe_id, cwe_name, cvss_version, cvss_vector,
            attack_vector, attack_complexity, privileges_required,
            user_interaction, scope, confidentiality_impact,
            integrity_impact, availability_impact, base_score, severity,
            published_date, last_modified_date, reference_urls,
            affected_products: [{vendor, product, version, affected_platform}],
            nvd_raw: full NVD API response
        """
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO cve_details (
                        cve_id, description, cwe_id, cwe_name,
                        cvss_version, cvss_vector, attack_vector,
                        attack_complexity, privileges_required,
                        user_interaction, scope, confidentiality_impact,
                        integrity_impact, availability_impact,
                        base_score, severity, published_date,
                        last_modified_date, reference_urls, nvd_raw
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (cve_id) DO UPDATE SET
                        description            = EXCLUDED.description,
                        cwe_id                 = EXCLUDED.cwe_id,
                        cwe_name               = EXCLUDED.cwe_name,
                        cvss_version           = EXCLUDED.cvss_version,
                        cvss_vector            = EXCLUDED.cvss_vector,
                        attack_vector          = EXCLUDED.attack_vector,
                        attack_complexity      = EXCLUDED.attack_complexity,
                        privileges_required    = EXCLUDED.privileges_required,
                        user_interaction       = EXCLUDED.user_interaction,
                        scope                  = EXCLUDED.scope,
                        confidentiality_impact = EXCLUDED.confidentiality_impact,
                        integrity_impact       = EXCLUDED.integrity_impact,
                        availability_impact    = EXCLUDED.availability_impact,
                        base_score             = EXCLUDED.base_score,
                        severity               = EXCLUDED.severity,
                        published_date         = EXCLUDED.published_date,
                        last_modified_date     = EXCLUDED.last_modified_date,
                        reference_urls         = EXCLUDED.reference_urls,
                        nvd_raw                = EXCLUDED.nvd_raw,
                        fetched_at             = NOW()
                    RETURNING id
                """, (
                    cve_id,
                    nvd_parsed.get("description"),
                    nvd_parsed.get("cwe_id"),
                    nvd_parsed.get("cwe_name"),
                    nvd_parsed.get("cvss_version"),
                    nvd_parsed.get("cvss_vector"),
                    nvd_parsed.get("attack_vector"),
                    nvd_parsed.get("attack_complexity"),
                    nvd_parsed.get("privileges_required"),
                    nvd_parsed.get("user_interaction"),
                    nvd_parsed.get("scope"),
                    nvd_parsed.get("confidentiality_impact"),
                    nvd_parsed.get("integrity_impact"),
                    nvd_parsed.get("availability_impact"),
                    nvd_parsed.get("base_score"),
                    nvd_parsed.get("severity"),
                    nvd_parsed.get("published_date"),
                    nvd_parsed.get("last_modified_date"),
                    Json(nvd_parsed.get("reference_urls", [])),
                    Json(nvd_parsed.get("nvd_raw", {})),
                ))
                cve_detail_id = cur.fetchone()[0]

            # Insert affected products (delete old ones first for upsert)
            with self.conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM cve_affected_products WHERE cve_detail_id = %s",
                    (cve_detail_id,)
                )
                for product in nvd_parsed.get("affected_products", []):
                    cur.execute("""
                        INSERT INTO cve_affected_products
                            (cve_detail_id, vendor, product, version, affected_platform)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (
                        cve_detail_id,
                        product.get("vendor"),
                        product.get("product"),
                        product.get("version"),
                        product.get("affected_platform"),
                    ))

            self.conn.commit()
            print(f"[+] CVE {cve_id}: NVD data saved (id={cve_detail_id}).")
            return cve_detail_id

        except Exception as e:
            self.conn.rollback()
            print(f"[-] Error saving NVD data for {cve_id}: {e}")
            raise

    def save_cve_analysis(self, cve_id: str, chatgpt_parsed: dict) -> int:
        """
        Save ChatGPT analysis for a CVE. Returns the cve_analysis_id.

        chatgpt_parsed is the parsed JSON from ChatGPT containing:
            title, exploitation, mitigations, detection_recommendations,
            vulnerability_walkthrough, mitre_attack_mapping, references
        """
        try:
            # Get the cve_detail_id
            with self.conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM cve_details WHERE cve_id = %s", (cve_id,)
                )
                row = cur.fetchone()
                if not row:
                    print(f"[-] CVE {cve_id}: No NVD data found. Save NVD data first.")
                    return -1
                cve_detail_id = row[0]

            # Upsert analysis
            with self.conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO cve_analysis (
                        cve_detail_id, title, exploitation_info,
                        mitigations, detection_recommendations,
                        vulnerability_walkthrough, chatgpt_references,
                        chatgpt_raw
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve_detail_id) DO UPDATE SET
                        title                     = EXCLUDED.title,
                        exploitation_info         = EXCLUDED.exploitation_info,
                        mitigations               = EXCLUDED.mitigations,
                        detection_recommendations = EXCLUDED.detection_recommendations,
                        vulnerability_walkthrough = EXCLUDED.vulnerability_walkthrough,
                        chatgpt_references        = EXCLUDED.chatgpt_references,
                        chatgpt_raw               = EXCLUDED.chatgpt_raw,
                        analyzed_at               = NOW()
                    RETURNING id
                """, (
                    cve_detail_id,
                    chatgpt_parsed.get("title"),
                    Json(chatgpt_parsed.get("exploitation", {})),
                    Json(chatgpt_parsed.get("mitigations", [])),
                    Json(chatgpt_parsed.get("detection_recommendations", [])),
                    Json(chatgpt_parsed.get("vulnerability_walkthrough", [])),
                    Json(chatgpt_parsed.get("references", [])),
                    Json(chatgpt_parsed),
                ))
                analysis_id = cur.fetchone()[0]

            # Delete old MITRE mappings and insert new ones
            with self.conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM cve_mitre_mappings WHERE cve_analysis_id = %s",
                    (analysis_id,)
                )
                for mapping in chatgpt_parsed.get("mitre_attack_mapping", []):
                    cur.execute("""
                        INSERT INTO cve_mitre_mappings (
                            cve_analysis_id, tactic_id, tactic_name,
                            technique_id, technique_name, justification
                        ) VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        analysis_id,
                        mapping.get("tactic_id"),
                        mapping.get("tactic_name"),
                        mapping.get("technique_id"),
                        mapping.get("technique_name"),
                        mapping.get("justification"),
                    ))

            self.conn.commit()
            mitre_count = len(chatgpt_parsed.get("mitre_attack_mapping", []))
            print(f"[+] CVE {cve_id}: ChatGPT analysis saved "
                  f"(id={analysis_id}, {mitre_count} MITRE mappings).")
            return analysis_id

        except Exception as e:
            self.conn.rollback()
            print(f"[-] Error saving analysis for {cve_id}: {e}")
            raise

    def get_cve_detail(self, cve_id: str) -> dict:
        """Get full CVE details including affected products."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM cve_details WHERE cve_id = %s", (cve_id,)
            )
            detail = cur.fetchone()
            if not detail:
                return None
            detail = dict(detail)

            cur.execute(
                "SELECT * FROM cve_affected_products WHERE cve_detail_id = %s",
                (detail["id"],)
            )
            detail["affected_products"] = [dict(r) for r in cur.fetchall()]
            return detail

    def get_cve_full(self, cve_id: str) -> dict:
        """Get CVE details + ChatGPT analysis + MITRE mappings."""
        detail = self.get_cve_detail(cve_id)
        if not detail:
            return None

        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM cve_analysis WHERE cve_detail_id = %s",
                (detail["id"],)
            )
            analysis = cur.fetchone()
            if analysis:
                analysis = dict(analysis)
                cur.execute(
                    "SELECT * FROM cve_mitre_mappings WHERE cve_analysis_id = %s",
                    (analysis["id"],)
                )
                analysis["mitre_mappings"] = [dict(r) for r in cur.fetchall()]
                detail["analysis"] = analysis

        return detail


# ═════════════════════════════════════════════════════════════════════════════
# Self-test
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("[*] Testing DBManager...")
    try:
        db = DBManager()
        db.init_tables()
        print("[OK] Tables created/verified.")

        # Quick test with dummy data
        test_data = {
            "ip": "127.0.0.1",
            "last_seen": "2026-09-24",
            "scraped_at": datetime.now(timezone.utc).isoformat(),
            "general_info": {
                "Country": "Test Country",
                "City": "Test City",
                "Organization": "Test Org",
                "ISP": "Test ISP",
                "ASN": "AS12345",
                "OS": "Linux",
                "tags": ["test"],
            },
            "open_ports": [80],
            "port_banners": [{
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "version": "test/1.0",
                "http_title": "Test Page",
                "banner": "HTTP/1.1 200 OK",
                "timestamp": "2026-09-24",
                "cve_details": [{
                    "cve": "CVE-2099-0001",
                    "cvss": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N",
                    "summary": "Test vulnerability",
                }],
            }],
            "web_technologies": {
                "Web servers": [{"name": "TestServer", "version": "1.0"}],
            },
            "security_contact": {"email": "test@test.com"},
            "timeline": {
                "history_url": "https://test.com/history",
                "port_timestamps": {"80": "2026-09-24"},
            },
        }

        # First insert should succeed
        result1 = db.save_shodan_scan(test_data)
        assert result1 is True, "First insert should return True"

        # Second insert (same last_seen) should be skipped
        result2 = db.save_shodan_scan(test_data)
        assert result2 is False, "Duplicate insert should return False"

        # Verify data
        host = db.get_host_by_ip("127.0.0.1")
        assert host is not None, "Host should exist"
        print(f"[OK] Host: {host['ip']}, country={host['country']}")

        count = db.get_scan_count("127.0.0.1")
        assert count == 1, f"Expected 1 scan, got {count}"
        print(f"[OK] Scan count: {count}")

        timeline = db.get_host_timeline("127.0.0.1")
        assert len(timeline) == 1, f"Expected 1 timeline entry, got {len(timeline)}"
        print(f"[OK] Timeline entries: {len(timeline)}")

        # Clean up test data
        with db.conn.cursor() as cur:
            cur.execute("DELETE FROM hosts WHERE ip = '127.0.0.1'::inet")
        db.conn.commit()
        print("[OK] Test data cleaned up.")

        db.close()
        print("\n[OK] All DBManager tests passed!")

    except psycopg2.OperationalError as e:
        print(f"\n[!] Could not connect to PostgreSQL: {e}")
        print("    Make sure PostgreSQL is running and .env has the correct credentials:")
        print("    PG_HOST=localhost")
        print("    PG_PORT=5432")
        print("    PG_DATABASE=cti_db")
        print("    PG_USER=postgres")
        print("    PG_PASSWORD=your_password")
