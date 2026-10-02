"""
CTI_V2 — Nmap Scanner Module (Full-Spectrum Multi-Phase)
=========================================================
Scans a list of IPs with Nmap using 8 scan phases to extract
the maximum possible data, then stores everything in PostgreSQL.

Scan Phases:
  Phase 1: TCP port discovery + service/version (intensity 9) + OS + traceroute
  Phase 2: UDP top 500 ports
  Phase 3: Targeted vulnerability scripts on discovered ports (vuln + vulners)
  Phase 4: Comprehensive NSE enumeration (60+ scripts, 14 categories)
  Phase 5: GeoIP & DNS reverse lookup
  Phase 6: Firewall detection (ACK scan)
  Phase 7: IP Protocol scan (non-TCP/UDP protocols)
  Phase 8: SCTP Init scan (top 100 SCTP ports)

Script categories covered:
  SSL/TLS, HTTP, DNS, SSH, SMB/NetBIOS, SNMP, Databases,
  Mail, FTP, RDP, VNC, NTP, LDAP, Telnet, SIP, MQTT,
  Docker, Kubernetes, Broadcast, Banner

Usage:
    from nmap_scanner import nmap_scan_ips, nmap_scan_ips_gen

    # Synchronous
    results = nmap_scan_ips(["1.2.3.4", "5.6.7.8"])

    # Generator (yields progress)
    for progress in nmap_scan_ips_gen(["1.2.3.4"]):
        print(progress)

Requirements:
    - Nmap installed and in PATH (https://nmap.org/download.html)
    - python-nmap (pip install python-nmap)
    - Run as Administrator for SYN scan (-sS) and OS detection (-O)
"""

import re
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import nmap

# Add Backend/ to path so we can import db_manager
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from db_manager import DBManager


# ═════════════════════════════════════════════════════════════════════════════
# Configuration
# ═════════════════════════════════════════════════════════════════════════════

# TCP port discovery — scan ALL 65535 ports
TCP_PORT_ARGS = "-p-"

# Maximum parallel IP scans
MAX_WORKERS = 4


# ═════════════════════════════════════════════════════════════════════════════
# Phase 1–8: Individual Scan Functions
# ═════════════════════════════════════════════════════════════════════════════

def _phase1_tcp_discovery(scanner, ip):
    """
    Phase 1: TCP port discovery + service/version (max intensity) + OS +
    traceroute. This is the core scan that discovers what's running.
    """
    print(f"    [1/8] TCP port discovery + service detection + OS fingerprint...")
    try:
        scanner.scan(
            hosts=ip,
            arguments=(
                f"-sS -sV --version-intensity 9 -sC -O -T4 "
                f"{TCP_PORT_ARGS} --traceroute --open --reason"
            ),
        )
    except Exception as e:
        print(f"    [!] Phase 1 error: {e}")


def _phase2_udp(scanner, ip):
    """
    Phase 2: UDP scan on top 500 ports.
    Catches DNS, SNMP, NTP, TFTP, LDAP, DHCP, SIP, mDNS, etc.
    """
    print(f"    [2/8] UDP top 500 ports...")
    try:
        scanner.scan(
            hosts=ip,
            arguments="-sU -sV -T4 --top-ports 500 --version-intensity 0 --open",
        )
    except Exception as e:
        print(f"    [!] Phase 2 (UDP) error: {e}")


def _phase3_vuln_scripts(scanner, ip, open_ports):
    """
    Phase 3: Vulnerability scripts on discovered open ports.
    Includes both 'vuln' category and 'vulners' (CVE cross-reference via CPE).
    """
    if not open_ports:
        print(f"    [3/8] Vuln scripts skipped (no open ports)")
        return
    port_str = ",".join(str(p) for p in open_ports)
    print(f"    [3/8] Vulnerability scripts on {len(open_ports)} open ports...")
    try:
        scanner.scan(
            hosts=ip,
            arguments=f"-sV -T4 -p {port_str} --script vuln,vulners",
        )
    except Exception as e:
        print(f"    [!] Phase 3 (vuln) error: {e}")


def _phase4_comprehensive_enum(scanner, ip, open_ports):
    """
    Phase 4: Comprehensive NSE enumeration — 60+ scripts across 14 categories.
    """
    if not open_ports:
        print(f"    [4/8] Enumeration scripts skipped (no open ports)")
        return
    port_str = ",".join(str(p) for p in open_ports)

    scripts = [
        # ── SSL/TLS (7) ──
        "ssl-enum-ciphers", "ssl-cert", "ssl-dh-params",
        "ssl-heartbleed", "ssl-poodle", "ssl-ccs-injection",
        "ssl-known-key",

        # ── HTTP (17) ──
        "http-title", "http-headers", "http-methods",
        "http-robots.txt", "http-server-header", "http-enum",
        "http-auth-finder", "http-waf-detect", "http-waf-fingerprint",
        "http-sitemap-generator", "http-security-headers",
        "http-cors", "http-cookie-flags", "http-php-version",
        "http-generator", "http-open-proxy", "http-open-redirect",

        # ── DNS (6) ──
        "dns-nsid", "dns-brute", "dns-zone-transfer",
        "dns-srv-enum", "dns-recursion", "dns-cache-snoop",

        # ── SSH (3) ──
        "ssh-hostkey", "ssh2-enum-algos", "ssh-auth-methods",

        # ── SMB / NetBIOS (8) ──
        "smb-os-discovery", "smb-enum-shares", "smb-security-mode",
        "smb2-capabilities", "smb2-security-mode", "smb-enum-users",
        "smb-enum-sessions", "nbstat",

        # ── SNMP (4) ──
        "snmp-info", "snmp-sysdescr", "snmp-interfaces",
        "snmp-processes",

        # ── Databases (7) ──
        "mysql-info", "mysql-enum", "mongodb-info",
        "redis-info", "pgsql-info", "ms-sql-info",
        "couchdb-stats",

        # ── Mail (4) ──
        "smtp-commands", "smtp-enum-users",
        "pop3-capabilities", "imap-capabilities",

        # ── FTP (2) ──
        "ftp-anon", "ftp-syst",

        # ── RDP (2) ──
        "rdp-enum-encryption", "rdp-ntlm-info",

        # ── VNC (2) ──
        "vnc-info", "vnc-title",

        # ── NTP (2) ──
        "ntp-info", "ntp-monlist",

        # ── LDAP (2) ──
        "ldap-rootdse", "ldap-search",

        # ── Telnet (2) ──
        "telnet-encryption", "telnet-ntlm-info",

        # ── SIP / VoIP (2) ──
        "sip-methods", "sip-enum-users",

        # ── MQTT / IoT (1) ──
        "mqtt-subscribe",

        # ── Docker / Kubernetes (2) ──
        "docker-version", "kubernetes-info",

        # ── XMPP (1) ──
        "xmpp-info",

        # ── Banner (1) ──
        "banner",
    ]
    script_str = ",".join(scripts)
    print(f"    [4/8] Comprehensive enumeration ({len(scripts)} scripts)...")
    try:
        scanner.scan(
            hosts=ip,
            arguments=f"-sV -T4 -p {port_str} --script {script_str}",
        )
    except Exception as e:
        print(f"    [!] Phase 4 (enum) error: {e}")


def _phase5_geoip_dns(scanner, ip):
    """
    Phase 5: GeoIP lookup + DNS reverse resolution + whois.
    """
    print(f"    [5/8] GeoIP & DNS reverse lookup...")
    try:
        scanner.scan(
            hosts=ip,
            arguments="-sn --script ip-geolocation-geoplugin,whois-ip,dns-brute,fcrdns",
        )
    except Exception as e:
        print(f"    [!] Phase 5 (GeoIP) error: {e}")


def _phase6_firewall_detection(scanner, ip, open_ports):
    """
    Phase 6: Firewall/filtering detection via ACK scan + Window scan.
    """
    if not open_ports:
        print(f"    [6/8] Firewall detection skipped (no open ports)")
        return
    test_ports = open_ports[:10]
    port_str = ",".join(str(p) for p in test_ports)
    print(f"    [6/8] Firewall detection on {len(test_ports)} ports...")
    try:
        # ACK scan for filtered port analysis
        scanner.scan(
            hosts=ip,
            arguments=f"-sA -T4 -p {port_str}",
        )
    except Exception as e:
        print(f"    [!] Phase 6 (firewall) error: {e}")


def _phase7_ip_protocol_scan(scanner, ip):
    """
    Phase 7: IP Protocol scan — discovers which IP protocols
    (TCP, UDP, ICMP, IGMP, GRE, ESP, etc.) the host responds to.
    """
    print(f"    [7/8] IP Protocol scan...")
    try:
        scanner.scan(
            hosts=ip,
            arguments="-sO -T4",
        )
    except Exception as e:
        print(f"    [!] Phase 7 (protocol) error: {e}")


def _phase8_sctp_scan(scanner, ip):
    """
    Phase 8: SCTP Init scan — discovers SCTP services (telecom, VoIP,
    diameter, SS7 signaling, etc.)
    """
    print(f"    [8/8] SCTP Init scan (top 100)...")
    try:
        scanner.scan(
            hosts=ip,
            arguments="-sY -T4 --top-ports 100 --open",
        )
    except Exception as e:
        print(f"    [!] Phase 8 (SCTP) error: {e}")


# ═════════════════════════════════════════════════════════════════════════════
# Phase Result Parser (raw nmap dict → intermediate dict)
# ═════════════════════════════════════════════════════════════════════════════

def _parse_phase_host(scanner, ip):
    """
    Parse a single phase's scanner result into a dict of ports, OS,
    traceroute, and host-level scripts.
    """
    data = {
        "status": None, "os_detection": [], "ports": {},
        "traceroute": [], "hostscripts": {},
    }

    if ip not in scanner.all_hosts():
        return data

    host = scanner[ip]
    data["status"] = host.state()

    # OS detection
    for osmatch in host.get("osmatch", []):
        os_entry = {
            "name": osmatch.get("name", ""),
            "accuracy": int(osmatch.get("accuracy", 0)),
            "os_classes": [],
        }
        for oc in osmatch.get("osclass", []):
            os_entry["os_classes"].append({
                "type": oc.get("type", ""),
                "vendor": oc.get("vendor", ""),
                "os_family": oc.get("osfamily", ""),
                "os_gen": oc.get("osgen", ""),
                "accuracy": int(oc.get("accuracy", 0)),
            })
        data["os_detection"].append(os_entry)

    # Traceroute
    try:
        trace = host.get("trace", {})
        if trace:
            for hop in trace.get("hops", []):
                data["traceroute"].append({
                    "ttl": hop.get("ttl"),
                    "ip": hop.get("ipaddr"),
                    "hostname": hop.get("host"),
                    "rtt": hop.get("rtt"),
                })
    except Exception:
        pass

    # Host-level scripts (not associated with a specific port)
    try:
        if "hostscript" in host:
            for script in host["hostscript"]:
                script_id = script.get("id", "unknown")
                script_output = script.get("output", "")
                data["hostscripts"][script_id] = script_output
    except Exception:
        pass

    # Ports
    for proto in host.all_protocols():
        for port_num in sorted(host[proto].keys()):
            port_info = host[proto][port_num]
            port_key = f"{port_num}/{proto}"

            port_entry = data["ports"].get(port_key, {
                "port": port_num,
                "protocol": proto,
                "state": None,
                "service": None,
                "product": None,
                "version": None,
                "extra_info": None,
                "cpe": None,
                "reason": None,
                "conf": None,
                "scripts": {},
            })

            port_entry["state"] = port_info.get("state") or port_entry["state"]
            port_entry["service"] = port_info.get("name") or port_entry["service"]
            port_entry["product"] = port_info.get("product") or port_entry["product"]
            port_entry["version"] = port_info.get("version") or port_entry["version"]
            port_entry["extra_info"] = port_info.get("extrainfo") or port_entry["extra_info"]
            port_entry["cpe"] = port_info.get("cpe") or port_entry["cpe"]
            port_entry["reason"] = port_info.get("reason") or port_entry["reason"]
            port_entry["conf"] = port_info.get("conf") or port_entry["conf"]

            if "script" in port_info:
                for script_name, output in port_info["script"].items():
                    port_entry["scripts"][script_name] = output

            data["ports"][port_key] = port_entry

    return data


def _parse_ip_protocol_scan(scanner, ip):
    """
    Parse IP Protocol scan results into a list of supported protocols.
    """
    protocols = []
    if ip not in scanner.all_hosts():
        return protocols
    host = scanner[ip]

    # IP protocol scan results are in the 'ip' protocol
    try:
        if "ip" in host.all_protocols():
            for proto_num in sorted(host["ip"].keys()):
                proto_info = host["ip"][proto_num]
                protocols.append({
                    "protocol_number": proto_num,
                    "state": proto_info.get("state", ""),
                    "name": proto_info.get("name", ""),
                    "reason": proto_info.get("reason", ""),
                })
    except Exception:
        pass

    return protocols


# ═════════════════════════════════════════════════════════════════════════════
# Structured Script Parsers
# ═════════════════════════════════════════════════════════════════════════════

def _parse_ssl_cert(raw_output):
    """Parse ssl-cert script output into structured certificate data."""
    cert = {
        "subject": {}, "issuer": {},
        "validity": {"not_before": None, "not_after": None},
        "san": [],
        "public_key": {"algorithm": None, "bits": None},
        "signature_algorithm": None, "serial": None,
        "md5": None, "sha1": None,
    }
    if not raw_output:
        return None
    text = str(raw_output)

    for field in ["commonName", "organizationName", "countryName",
                  "stateOrProvinceName", "localityName"]:
        m = re.search(rf'{field}:\s*(.+?)(?:\n|$)', text)
        if m:
            cert["subject"][field] = m.group(1).strip()

    issuer_section = re.search(r'Issuer:\s*(.*?)(?:Validity|Public Key|$)', text, re.DOTALL)
    if issuer_section:
        for field in ["commonName", "organizationName", "countryName"]:
            m = re.search(rf'{field}:\s*(.+?)(?:\n|$)', issuer_section.group(1))
            if m:
                cert["issuer"][field] = m.group(1).strip()

    m = re.search(r'Not valid before:\s*(.+?)(?:\n|$)', text)
    if m:
        cert["validity"]["not_before"] = m.group(1).strip()
    m = re.search(r'Not valid after:\s*(.+?)(?:\n|$)', text)
    if m:
        cert["validity"]["not_after"] = m.group(1).strip()

    cert["san"] = re.findall(r'DNS:([^\s,]+)', text)

    m = re.search(r'Public Key type:\s*(.+?)(?:\n|$)', text)
    if m:
        cert["public_key"]["algorithm"] = m.group(1).strip()
    m = re.search(r'Public Key bits:\s*(\d+)', text)
    if m:
        cert["public_key"]["bits"] = int(m.group(1))

    m = re.search(r'Sign(?:ature)?\s*[Aa]lgorithm:\s*(.+?)(?:\n|$)', text)
    if m:
        cert["signature_algorithm"] = m.group(1).strip()

    m = re.search(r'MD5:\s*([a-fA-F0-9\s]+)', text)
    if m:
        cert["md5"] = m.group(1).strip()
    m = re.search(r'SHA-?1:\s*([a-fA-F0-9\s]+)', text)
    if m:
        cert["sha1"] = m.group(1).strip()

    if cert["subject"] or cert["issuer"] or cert["san"]:
        return cert
    return None


def _parse_ssh_hostkey(raw_output):
    """Parse ssh-hostkey script output into structured key data."""
    keys = []
    if not raw_output:
        return None
    text = str(raw_output)
    for m in re.finditer(r'(\d+)\s+([\w:+/=]+)\s+.*?\((\w+)\)', text):
        keys.append({
            "bits": int(m.group(1)),
            "fingerprint": m.group(2).strip(),
            "key_type": m.group(3).strip(),
        })
    return keys if keys else None


def _parse_ssh2_enum_algos(raw_output):
    """Parse ssh2-enum-algos into structured algorithm lists."""
    algos = {
        "kex_algorithms": [], "server_host_key_algorithms": [],
        "encryption_algorithms": [], "mac_algorithms": [],
        "compression_algorithms": [],
    }
    if not raw_output:
        return None
    text = str(raw_output)
    current_section = None
    for line in text.split('\n'):
        line = line.strip()
        if 'kex_algorithms' in line:
            current_section = "kex_algorithms"
        elif 'server_host_key_algorithms' in line:
            current_section = "server_host_key_algorithms"
        elif 'encryption_algorithms' in line:
            current_section = "encryption_algorithms"
        elif 'mac_algorithms' in line:
            current_section = "mac_algorithms"
        elif 'compression_algorithms' in line:
            current_section = "compression_algorithms"
        elif current_section and line and not line.startswith('|'):
            algos[current_section].append(line)
    return algos if any(v for v in algos.values()) else None


def _parse_ssh_auth_methods(raw_output):
    """Parse ssh-auth-methods output."""
    if not raw_output:
        return None
    text = str(raw_output)
    methods = re.findall(
        r'(publickey|password|keyboard-interactive|gssapi-with-mic|hostbased|none)',
        text.lower()
    )
    return list(set(methods)) if methods else None


def _parse_http_security_headers(raw_output):
    """Parse http-security-headers output into present/missing header lists."""
    result = {"present": [], "missing": []}
    if not raw_output:
        return None
    text = str(raw_output)
    for line in text.split('\n'):
        line = line.strip()
        if not line:
            continue
        if 'MISSING' in line.upper() or 'NOT SET' in line.upper():
            m = re.match(r'[\s|_]*(.+?)[\s]*(?:is not set|MISSING|not found)', line, re.IGNORECASE)
            if m:
                result["missing"].append(m.group(1).strip())
            else:
                result["missing"].append(line)
        elif 'SET' in line.upper() or ':' in line:
            m = re.match(r'[\s|_]*(.+?)[\s]*(?:is set|SET TO|:)', line, re.IGNORECASE)
            if m:
                result["present"].append(m.group(1).strip())
    return result if (result["present"] or result["missing"]) else None


def _parse_dns_brute(raw_output):
    """Parse dns-brute output into a list of discovered subdomains."""
    if not raw_output:
        return None
    text = str(raw_output)
    subdomains = []
    for m in re.finditer(r'([a-zA-Z0-9][\w.-]+\.[a-zA-Z]{2,})\s*-\s*([\d.]+)', text):
        subdomains.append({
            "hostname": m.group(1).strip(),
            "ip": m.group(2).strip(),
        })
    return subdomains if subdomains else None


def _parse_geoip(scanner, ip):
    """Parse GeoIP data from ip-geolocation-geoplugin script."""
    geo = {
        "country": None, "city": None,
        "latitude": None, "longitude": None,
        "region": None, "source": "geoplugin",
    }
    if ip not in scanner.all_hosts():
        return None
    host = scanner[ip]

    try:
        if hasattr(host, 'get') and 'hostscript' in host:
            for script in host['hostscript']:
                output = script.get('output', '')
                sid = script.get('id', '').lower()
                if 'geolocation' in sid or 'geoplugin' in sid:
                    m = re.search(r'coordinates:\s*([-\d.]+),\s*([-\d.]+)', output)
                    if m:
                        geo["latitude"] = m.group(1)
                        geo["longitude"] = m.group(2)
                    m = re.search(r'Country:\s*(.+?)(?:\n|$)', output, re.IGNORECASE)
                    if m:
                        geo["country"] = m.group(1).strip()
                    m = re.search(r'City:\s*(.+?)(?:\n|$)', output, re.IGNORECASE)
                    if m:
                        geo["city"] = m.group(1).strip()
                    m = re.search(r'Region:\s*(.+?)(?:\n|$)', output, re.IGNORECASE)
                    if m:
                        geo["region"] = m.group(1).strip()
    except Exception:
        pass

    if not geo["country"]:
        try:
            raw_output = scanner.get_nmap_last_output()
            if raw_output:
                m = re.search(r'ip-geolocation.*?coordinates:\s*([-\d.]+),\s*([-\d.]+)',
                              raw_output, re.DOTALL)
                if m:
                    geo["latitude"] = m.group(1)
                    geo["longitude"] = m.group(2)
        except Exception:
            pass

    if geo["country"] or geo["city"] or geo["latitude"]:
        return geo
    return None


def _parse_whois(hostscripts):
    """Parse whois-ip hostscript output into structured data."""
    raw = hostscripts.get("whois-ip")
    if not raw:
        return None
    text = str(raw)
    whois = {}
    for key in ["inetnum", "netname", "descr", "country", "org-name",
                 "NetRange", "OrgName", "OrgId", "Organization",
                 "Address", "City", "StateProv", "PostalCode"]:
        m = re.search(rf'{key}:\s*(.+?)(?:\n|$)', text, re.IGNORECASE)
        if m:
            whois[key.lower().replace("-", "_")] = m.group(1).strip()
    return whois if whois else None


def _parse_smb_os_discovery(raw_output):
    """Parse smb-os-discovery output into structured data."""
    if not raw_output:
        return None
    text = str(raw_output)
    smb = {}
    for key, label in [("os", "OS:"), ("computer_name", "Computer name:"),
                        ("domain", "Domain name:"), ("forest", "Forest name:"),
                        ("fqdn", "FQDN:"), ("workgroup", "Workgroup:"),
                        ("system_time", "System time:")]:
        m = re.search(rf'{re.escape(label)}\s*(.+?)(?:\n|$)', text, re.IGNORECASE)
        if m:
            smb[key] = m.group(1).strip()
    return smb if smb else None


# ═════════════════════════════════════════════════════════════════════════════
# CVE Extraction from Script Output
# ═════════════════════════════════════════════════════════════════════════════

def _extract_cves(script_id: str, output: str) -> list:
    """Extract CVE entries from Nmap script output (vuln + vulners)."""
    cves = []
    if not output:
        return cves

    cve_pattern = re.compile(
        r'(CVE-\d{4}-\d{4,})\s*'
        r'(\d+\.?\d*)?',
        re.IGNORECASE,
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
# Post-Processing: Extract Structured Data from Merged Scripts
# ═════════════════════════════════════════════════════════════════════════════

def _extract_structured_data(result):
    """
    Post-process the merged result to extract structured data from
    key NSE script outputs into dedicated fields.
    """
    ssh_info = {"host_keys": None, "algorithms": None, "auth_methods": None}
    dns_info = {
        "reverse_dns": None, "brute_subdomains": None,
        "zone_transfer": None, "recursion": None,
    }
    smb_info = None

    for port_key, port_data in result.get("_merged_ports", {}).items():
        all_scripts = port_data.get("scripts", {})
        service = (port_data.get("service") or "").lower()

        # SSL cert
        if "ssl-cert" in all_scripts:
            parsed = _parse_ssl_cert(all_scripts["ssl-cert"])
            if parsed:
                port_data["ssl_certificate_parsed"] = parsed

        # SSH
        if service == "ssh" or port_data.get("port") == 22:
            if "ssh-hostkey" in all_scripts:
                parsed = _parse_ssh_hostkey(all_scripts["ssh-hostkey"])
                if parsed:
                    ssh_info["host_keys"] = parsed
            if "ssh2-enum-algos" in all_scripts:
                parsed = _parse_ssh2_enum_algos(all_scripts["ssh2-enum-algos"])
                if parsed:
                    ssh_info["algorithms"] = parsed
            if "ssh-auth-methods" in all_scripts:
                parsed = _parse_ssh_auth_methods(all_scripts["ssh-auth-methods"])
                if parsed:
                    ssh_info["auth_methods"] = parsed

        # HTTP security headers
        if "http-security-headers" in all_scripts:
            parsed = _parse_http_security_headers(all_scripts["http-security-headers"])
            if parsed:
                port_data["http_security_headers_parsed"] = parsed

        # DNS
        if "dns-brute" in all_scripts:
            parsed = _parse_dns_brute(all_scripts["dns-brute"])
            if parsed:
                dns_info["brute_subdomains"] = parsed
        if "dns-zone-transfer" in all_scripts:
            output = str(all_scripts["dns-zone-transfer"])
            if "failed" not in output.lower() and len(output) > 20:
                dns_info["zone_transfer"] = output
        if "dns-recursion" in all_scripts:
            output = str(all_scripts["dns-recursion"])
            dns_info["recursion"] = "enabled" if "recursion" in output.lower() else "disabled"

        # SMB OS Discovery
        if "smb-os-discovery" in all_scripts:
            parsed = _parse_smb_os_discovery(all_scripts["smb-os-discovery"])
            if parsed:
                smb_info = parsed

    if any(v for v in ssh_info.values()):
        result["ssh_info"] = ssh_info
    if any(v for v in dns_info.values()):
        result["dns_info"] = dns_info
    if smb_info:
        result["smb_info"] = smb_info


# ═════════════════════════════════════════════════════════════════════════════
# Full-Spectrum Multi-Phase Scan (single IP)
# ═════════════════════════════════════════════════════════════════════════════

def _scan_ip_multiphase(ip: str) -> dict:
    """
    Run a full-spectrum 8-phase Nmap scan on a single IP.

    Returns a structured dict matching the shape expected by
    db_manager.save_nmap_scan().
    """
    print(f"\n  [*] Starting FULL-SPECTRUM scan on {ip}")
    start_time = time.time()

    scanner = nmap.PortScanner()

    # Accumulators — merged across all phases
    merged_ports = {}      # key: "port/proto"
    merged_hostscripts = {}
    os_detection = []
    traceroute = []
    geolocation = None
    firewall_detection = None
    ip_protocols = []
    whois_info = None
    host_status = None

    # ── Phase 1: TCP Discovery ───────────────────────────────────────────
    _phase1_tcp_discovery(scanner, ip)
    p1 = _parse_phase_host(scanner, ip)

    if p1["status"] is None:
        elapsed = round(time.time() - start_time, 1)
        print(f"  [-] {ip}: Host seems down ({elapsed}s)")
        return {"ip": ip, "error": "Host down or not responding"}

    host_status = p1["status"]
    os_detection = p1["os_detection"]
    traceroute = p1["traceroute"]
    merged_ports.update(p1["ports"])
    merged_hostscripts.update(p1.get("hostscripts", {}))

    open_tcp_ports = [
        v["port"] for v in merged_ports.values()
        if v.get("state") == "open" and v.get("protocol") == "tcp"
    ]
    print(f"    → Found {len(open_tcp_ports)} open TCP ports")

    # ── Phase 2: UDP ─────────────────────────────────────────────────────
    _phase2_udp(scanner, ip)
    p2 = _parse_phase_host(scanner, ip)
    for pk, pv in p2["ports"].items():
        if pk not in merged_ports:
            merged_ports[pk] = pv
    merged_hostscripts.update(p2.get("hostscripts", {}))

    open_udp_ports = [
        v["port"] for v in merged_ports.values()
        if v.get("state") == "open" and v.get("protocol") == "udp"
    ]
    if open_udp_ports:
        print(f"    → Found {len(open_udp_ports)} open UDP ports")

    # All open ports for targeted scans
    all_open_ports = open_tcp_ports + open_udp_ports

    # ── Phase 3: Targeted Vulnerability Scripts ──────────────────────────
    _phase3_vuln_scripts(scanner, ip, all_open_ports)
    p3 = _parse_phase_host(scanner, ip)
    for pk, pv in p3["ports"].items():
        if pk in merged_ports:
            merged_ports[pk]["scripts"].update(pv.get("scripts", {}))
            merged_ports[pk]["product"] = pv.get("product") or merged_ports[pk]["product"]
            merged_ports[pk]["version"] = pv.get("version") or merged_ports[pk]["version"]
        else:
            merged_ports[pk] = pv
    merged_hostscripts.update(p3.get("hostscripts", {}))

    # ── Phase 4: Comprehensive Enumeration ───────────────────────────────
    _phase4_comprehensive_enum(scanner, ip, all_open_ports)
    p4 = _parse_phase_host(scanner, ip)
    for pk, pv in p4["ports"].items():
        if pk in merged_ports:
            merged_ports[pk]["scripts"].update(pv.get("scripts", {}))
        else:
            merged_ports[pk] = pv
    merged_hostscripts.update(p4.get("hostscripts", {}))

    # ── Phase 5: GeoIP & DNS ────────────────────────────────────────────
    _phase5_geoip_dns(scanner, ip)
    geo_data = _parse_geoip(scanner, ip)
    if geo_data:
        geolocation = geo_data
        print(f"    → GeoIP: {geo_data.get('country', '?')}, {geo_data.get('city', '?')}")

    # Capture hostscripts from phase 5 (whois, fcrdns, etc.)
    p5 = _parse_phase_host(scanner, ip)
    merged_hostscripts.update(p5.get("hostscripts", {}))

    # Parse whois from hostscripts
    whois_info = _parse_whois(merged_hostscripts)

    # ── Phase 6: Firewall Detection ──────────────────────────────────────
    _phase6_firewall_detection(scanner, ip, open_tcp_ports)
    p6 = _parse_phase_host(scanner, ip)

    filtered_count = sum(
        1 for p in merged_ports.values() if p.get("state") == "filtered"
    )
    ack_filtered = sum(
        1 for p in p6["ports"].values()
        if p.get("state") in ("filtered", "unfiltered")
    )
    if filtered_count > 0 or ack_filtered > 0:
        firewall_detection = {
            "filtered_ports_count": filtered_count,
            "ack_scan_results": {
                pk: pv.get("state") for pk, pv in p6["ports"].items()
            },
            "likely_firewalled": filtered_count > 10,
        }

    # ── Phase 7: IP Protocol Scan ────────────────────────────────────────
    _phase7_ip_protocol_scan(scanner, ip)
    ip_protocols = _parse_ip_protocol_scan(scanner, ip)
    if ip_protocols:
        print(f"    → IP protocols: {len(ip_protocols)} discovered")

    # ── Phase 8: SCTP Scan ───────────────────────────────────────────────
    _phase8_sctp_scan(scanner, ip)
    p8 = _parse_phase_host(scanner, ip)
    for pk, pv in p8["ports"].items():
        if pk not in merged_ports:
            merged_ports[pk] = pv
    sctp_ports = [
        v["port"] for v in p8["ports"].values()
        if v.get("state") == "open"
    ]
    if sctp_ports:
        print(f"    → SCTP: {len(sctp_ports)} open ports")

    # ── Post-process: extract structured data from scripts ───────────────
    result_for_parsing = {"_merged_ports": merged_ports}
    _extract_structured_data(result_for_parsing)

    # ── Build final output matching save_nmap_scan() shape ───────────────

    # Hostnames
    hostnames = []
    try:
        if ip in scanner.all_hosts():
            for hn in scanner[ip].get("hostnames", []):
                if hn.get("name"):
                    hostnames.append({
                        "name": hn.get("name", ""),
                        "type": hn.get("type", ""),
                    })
    except Exception:
        pass

    # MAC address
    mac_address = None
    mac_vendor = None
    try:
        if ip in scanner.all_hosts():
            host_data = scanner[ip]
            if "mac" in host_data.get("addresses", {}):
                mac_address = host_data["addresses"]["mac"]
            vendor_dict = host_data.get("vendor", {})
            if vendor_dict and mac_address:
                mac_vendor = vendor_dict.get(mac_address, "")
    except Exception:
        pass

    # Uptime
    uptime = None
    try:
        if ip in scanner.all_hosts():
            host_data = scanner[ip]
            if host_data.get("uptime"):
                uptime = {
                    "seconds": host_data["uptime"].get("seconds", ""),
                    "lastboot": host_data["uptime"].get("lastboot", ""),
                }
    except Exception:
        pass

    # TCP sequence
    tcp_sequence = None
    try:
        if ip in scanner.all_hosts():
            host_data = scanner[ip]
            if host_data.get("tcp_sequence"):
                tcp_sequence = host_data["tcp_sequence"]
    except Exception:
        pass

    best_os = os_detection[0]["name"] if os_detection else None

    # ── Convert merged_ports → port_banners (DB-compatible format) ───────
    open_ports_list = []
    port_banners = []

    for port_key, port_data in sorted(merged_ports.items()):
        state = port_data.get("state", "")
        if state not in ("open", "open|filtered", "filtered"):
            continue

        port_num = port_data["port"]
        proto = port_data["protocol"]
        open_ports_list.append(port_num)

        # Build version string
        product = port_data.get("product", "")
        version = port_data.get("version", "")
        extrainfo = port_data.get("extra_info", "")
        version_parts = []
        if product:
            version_parts.append(product)
        if version:
            version_parts.append(version)
        if extrainfo:
            version_parts.append(f"({extrainfo})")
        version_str = " ".join(version_parts) if version_parts else None

        # Separate scripts into vuln vs enumeration
        all_scripts = port_data.get("scripts", {})
        vuln_scripts = {}
        enum_scripts = {}
        http_title = None
        banner_text = None
        cve_details = []

        for script_id, script_output in all_scripts.items():
            if script_id == "http-title":
                http_title = str(script_output).strip()
            if script_id == "banner":
                banner_text = str(script_output).strip()

            # Extract CVEs from vuln scripts
            if "vuln" in script_id or "vulners" in script_id:
                vuln_scripts[script_id] = script_output
                cve_details.extend(_extract_cves(script_id, str(script_output)))
            else:
                enum_scripts[script_id] = script_output

        # Build extra dict with all enriched data
        extra = {
            "reason": port_data.get("reason", ""),
            "product": product,
            "service_version": version,
            "extra_info": extrainfo,
            "conf": port_data.get("conf", ""),
            "cpe": port_data.get("cpe", ""),
            "vulnerability_scripts": vuln_scripts,
            "enumeration_scripts": enum_scripts,
        }

        # Add structured parsed data if available
        if port_data.get("ssl_certificate_parsed"):
            extra["ssl_certificate"] = port_data["ssl_certificate_parsed"]
        if port_data.get("http_security_headers_parsed"):
            extra["http_security_headers"] = port_data["http_security_headers_parsed"]

        port_banners.append({
            "port": port_num,
            "protocol": proto,
            "state": state,
            "service": port_data.get("service", ""),
            "version": version_str,
            "http_title": http_title,
            "banner": banner_text,
            "cve_details": cve_details,
            "extra": extra,
        })

    # ── Scan info ────────────────────────────────────────────────────────
    scan_info = {
        "command_line": scanner.command_line() if hasattr(scanner, 'command_line') else "",
        "nmap_version": scanner.nmap_version() if hasattr(scanner, 'nmap_version') else "",
        "scan_phases": 8,
        "tcp_port_args": TCP_PORT_ARGS,
    }

    # ── Summary stats ────────────────────────────────────────────────────
    total_cves = sum(len(pb.get("cve_details", [])) for pb in port_banners)
    total_vuln_scripts = sum(
        len(pb.get("extra", {}).get("vulnerability_scripts", {}))
        for pb in port_banners
    )
    total_enum_scripts = sum(
        len(pb.get("extra", {}).get("enumeration_scripts", {}))
        for pb in port_banners
    )
    elapsed = round(time.time() - start_time, 1)

    print(f"  [+] {ip}: {host_status}, "
          f"{len(open_ports_list)} open ports, "
          f"{len(os_detection)} OS matches, "
          f"{total_cves} CVEs, "
          f"{total_vuln_scripts} vuln scripts, "
          f"{total_enum_scripts} enum scripts, "
          f"{len(ip_protocols)} IP protocols, "
          f"{elapsed}s elapsed")

    # ── general_info ─────────────────────────────────────────────────────
    general_info = {
        "OS": best_os,
        "hostnames": hostnames,
        "host_state": host_status,
        "host_reason": "",
        "mac_address": mac_address,
        "mac_vendor": mac_vendor,
    }

    result = {
        "ip": ip,
        "general_info": general_info,
        "open_ports": open_ports_list,
        "port_banners": port_banners,
        "os_detection": os_detection,
        "uptime": uptime,
        "tcp_sequence": tcp_sequence,
        "traceroute": traceroute,
        "geolocation": geolocation,
        "whois": whois_info,
        "firewall_detection": firewall_detection,
        "ip_protocols": ip_protocols,
        "hostscripts": merged_hostscripts if merged_hostscripts else None,
        "scan_info": scan_info,
        "scan_duration_seconds": elapsed,
        "scraped_at": datetime.now(timezone.utc).isoformat(),
    }

    # Add enrichments at top level
    if result_for_parsing.get("ssh_info"):
        result["ssh_info"] = result_for_parsing["ssh_info"]
    if result_for_parsing.get("dns_info"):
        result["dns_info"] = result_for_parsing["dns_info"]
    if result_for_parsing.get("smb_info"):
        result["smb_info"] = result_for_parsing["smb_info"]

    return result


# ═════════════════════════════════════════════════════════════════════════════
# Parse single-pass scan result (kept for backward compat)
# ═════════════════════════════════════════════════════════════════════════════

def parse_scan_result(nm: nmap.PortScanner, host: str) -> dict:
    """
    Convert python-nmap's result for a single host into a structured dict
    matching the shape expected by db_manager.save_nmap_scan().

    This is used by the single-pass scan path. The multi-phase scanner
    uses _scan_ip_multiphase() instead.
    """
    host_data = nm[host]

    # OS Detection
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

    # Hostnames
    hostnames = []
    for hn in host_data.get("hostnames", []):
        if hn.get("name"):
            hostnames.append({
                "name": hn.get("name", ""),
                "type": hn.get("type", ""),
            })

    host_state = host_data.get("status", {}).get("state", "")
    host_reason = host_data.get("status", {}).get("reason", "")

    # MAC Address
    mac_address = None
    mac_vendor = None
    if "mac" in host_data.get("addresses", {}):
        mac_address = host_data["addresses"]["mac"]
    vendor_dict = host_data.get("vendor", {})
    if vendor_dict and mac_address:
        mac_vendor = vendor_dict.get(mac_address, "")

    # Uptime
    uptime = None
    if host_data.get("uptime"):
        uptime = {
            "seconds": host_data["uptime"].get("seconds", ""),
            "lastboot": host_data["uptime"].get("lastboot", ""),
        }

    # TCP Sequence
    tcp_sequence = None
    if host_data.get("tcp_sequence"):
        tcp_sequence = host_data["tcp_sequence"]

    # Ports
    open_ports = []
    port_banners = []
    for proto in host_data.all_protocols():
        port_list = sorted(host_data[proto].keys())
        for port_num in port_list:
            port_info = host_data[proto][port_num]
            state = port_info.get("state", "")
            if state not in ("open", "open|filtered", "filtered"):
                continue
            open_ports.append(port_num)

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

            scripts = port_info.get("script", {})
            http_title = None
            banner_text = None
            cve_details = []
            for script_id, script_output in scripts.items():
                if script_id == "http-title":
                    http_title = script_output.strip()
                if script_id == "banner":
                    banner_text = script_output.strip()
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

    scan_info = {
        "command_line": nm.command_line(),
        "nmap_version": nm.nmap_version(),
        "scan_method": nm.scaninfo(),
    }

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


# ═════════════════════════════════════════════════════════════════════════════
# Generator Function
# ═════════════════════════════════════════════════════════════════════════════

def nmap_scan_ips_gen(
    ips: list,
    workers: int = None,
    multiphase: bool = True,
):
    """
    Generator that scans a list of IPs with Nmap and stores results in PostgreSQL.

    Yields progress dicts as each IP scan completes:
        {
            "ip_data_fetcher_nmap": "running" | "completed",
            "ip_data_fetcher_nmap_done": "n/m",
        }

    Args:
        ips:         List of IP addresses to scan
        workers:     Number of parallel Nmap processes (default: MAX_WORKERS)
        multiphase:  If True, run full 8-phase scan. If False, single-pass.
    """
    if not ips:
        print("[-] No IPs provided.")
        yield {
            "ip_data_fetcher_nmap": "completed",
            "ip_data_fetcher_nmap_done": "0/0",
        }
        return

    unique_ips = list(dict.fromkeys(ips))
    total = len(unique_ips)
    num_workers = min(workers or MAX_WORKERS, total)

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

    mode = "FULL-SPECTRUM (8-phase)" if multiphase else "SINGLE-PASS"
    print(f"\n{'='*70}")
    print(f"  Nmap Scanner — {total} target(s), {num_workers} workers, {mode}")
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

    # ─── Worker function ─────────────────────────────────────────────────
    def _scan_worker(ip_index_tuple):
        i, ip = ip_index_tuple
        print(f"\n[{i}/{total}] Scanning: {ip}")

        if multiphase:
            parsed = _scan_ip_multiphase(ip)
        else:
            nm = nmap.PortScanner()
            try:
                nm.scan(
                    hosts=ip,
                    arguments=(
                        f"-sS -sV -O --script default,vuln,ssl-enum-ciphers,"
                        f"http-title,http-headers,banner -T4 "
                        f"{TCP_PORT_ARGS} --open --reason"
                    ),
                )
            except Exception as e:
                print(f"[-] Nmap error for {ip}: {e}")
                return {"ip": ip, "error": str(e)}

            scanned = nm.all_hosts()
            if not scanned:
                print(f"[-] No results for {ip}")
                return {"ip": ip, "error": "Host down or no response"}

            try:
                parsed = parse_scan_result(nm, scanned[0])
            except Exception as e:
                print(f"[-] Parse error for {ip}: {e}")
                return {"ip": ip, "error": str(e)}

        if "error" in parsed:
            return parsed

        # Save to database
        if db:
            with db_lock:
                try:
                    db.save_nmap_scan(parsed)
                except Exception as e:
                    print(f"    [-] DB save error: {e}")

        return parsed

    # ─── Run workers and yield progress ──────────────────────────────────
    indexed_ips = list(enumerate(unique_ips, 1))
    completed_count = 0
    all_results = []

    with ThreadPoolExecutor(max_workers=num_workers) as pool:
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
    skip_db: bool = False,
    workers: int = None,
    multiphase: bool = True,
) -> list:
    """
    Synchronous wrapper — scans IPs and returns results list.
    Internally consumes nmap_scan_ips_gen() for progress tracking.
    """
    for progress in nmap_scan_ips_gen(ips, workers, multiphase):
        pass


# ═════════════════════════════════════════════════════════════════════════════
# Single-IP function (for Engine / LangGraph use)
# ═════════════════════════════════════════════════════════════════════════════

def scan_single_ip(ip: str, db=None, multiphase: bool = True) -> dict:
    """
    Scan a single IP with Nmap and optionally save to database.

    Args:
        ip:         Single IP address to scan.
        db:         An already-connected DBManager instance (optional).
        multiphase: If True, run full 8-phase scan.

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

    try:
        nmap.PortScanner()
    except nmap.PortScannerError as e:
        return {"status": "error", "ip": ip, "reason": f"Nmap not found: {e}"}

    if multiphase:
        parsed = _scan_ip_multiphase(ip)
    else:
        nm = nmap.PortScanner()
        print(f"[*] Nmap scanning: {ip}")
        try:
            nm.scan(
                hosts=ip,
                arguments=(
                    f"-sS -sV -O --script default,vuln,ssl-enum-ciphers,"
                    f"http-title,http-headers,banner -T4 "
                    f"{TCP_PORT_ARGS} --open --reason"
                ),
            )
        except Exception as e:
            return {"status": "error", "ip": ip, "reason": f"Nmap error: {e}"}

        scanned = nm.all_hosts()
        if not scanned:
            return {"status": "error", "ip": ip, "reason": "Host down or no response"}

        try:
            parsed = parse_scan_result(nm, scanned[0])
        except Exception as e:
            return {"status": "error", "ip": ip, "reason": f"Parse error: {e}"}

    if "error" in parsed:
        return {"status": "error", "ip": ip, "reason": parsed["error"]}

    port_count = len(parsed.get("open_ports", []))
    cve_count = sum(len(p.get("cve_details", [])) for p in parsed.get("port_banners", []))
    os_guess = parsed.get("general_info", {}).get("OS") or "Unknown"
    print(f"[+] Nmap {ip}: {port_count} open ports, {cve_count} CVEs, OS: {os_guess}")

    if db:
        try:
            db.save_nmap_scan(parsed)
        except Exception as e:
            print(f"[-] DB save error for {ip}: {e}")

    return {"status": "scanned", "ip": ip, "data": parsed}


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
