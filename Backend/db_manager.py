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
    # Query Helpers (for agent and scripts)
    # ═════════════════════════════════════════════════════════════════════════

    def get_host_by_ip(self, ip: str) -> dict:
        """Get host info by IP address. Returns None if not found."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM hosts WHERE ip = %s::inet", (ip,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_scan_count(self, ip: str, source: str = None) -> int:
        """Get the number of scans for an IP, optionally filtered by source."""
        with self.conn.cursor() as cur:
            if source:
                cur.execute("""
                    SELECT COUNT(*) FROM scans s
                    JOIN hosts h ON h.id = s.host_id
                    WHERE h.ip = %s::inet AND s.source = %s
                """, (ip, source))
            else:
                cur.execute("""
                    SELECT COUNT(*) FROM scans s
                    JOIN hosts h ON h.id = s.host_id
                    WHERE h.ip = %s::inet
                """, (ip,))
            return cur.fetchone()[0]

    def get_host_timeline(self, ip: str) -> list:
        """Get all scan snapshots for an IP, ordered by date (newest first)."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT s.id, s.source, s.source_last_seen, s.scraped_at, s.metadata
                FROM scans s
                JOIN hosts h ON h.id = s.host_id
                WHERE h.ip = %s::inet
                ORDER BY s.scraped_at DESC
            """, (ip,))
            return [dict(row) for row in cur.fetchall()]


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
