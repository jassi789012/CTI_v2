# CTI_V2 — Backend Architecture & Engine Documentation

[![Python Version](https://img.shields.io/badge/python-3.14%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![LangGraph](https://img.shields.io/badge/LangGraph-1.2%2B-orange.svg)](https://langchain-ai.github.io/langgraph/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16%2B-336791.svg)](https://www.postgresql.org/)
[![Playwright](https://img.shields.io/badge/Playwright-1.63%2B-45ba4b.svg)](https://playwright.dev/)

The **CTI_V2 Backend** is a high-performance Cyber Threat Intelligence platform built on FastAPI, LangGraph, and PostgreSQL. It delivers automated OSINT discovery, a 9-phase full-spectrum Nmap scanner, zero-cost AI threat modeling with account-rotated ChatGPT automation, NIST NVD API v2 enrichment, and a ReAct security analyst agent with Human-in-the-Loop (HITL) authorization gates.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [FastAPI Server & 17 Endpoints](#fastapi-server--17-endpoints)
  - [Chat & Agent Endpoints (7)](#chat--agent-endpoints-7)
  - [Engine Lifecycle & Streaming Endpoints (4)](#engine-lifecycle--streaming-endpoints-4)
  - [Threat Search & OSINT Endpoints (4)](#threat-search--osint-endpoints-4)
  - [Platform Health & Statistics (2)](#platform-health--statistics-2)
  - [Server-Sent Events (SSE) Streaming Protocol](#server-sent-events-sse-streaming-protocol)
- [LangGraph Reconnaissance Engines](#langgraph-reconnaissance-engines)
  - [1. Natural Language Query Engine (`Engine_query_input.py`)](#1-natural-language-query-engine-engine_query_inputpy)
  - [2. Direct IP Scanner Engine (`Engine_ip_input.py`)](#2-direct-ip-scanner-engine-engine_ip_inputpy)
  - [3. CVE Research Engine (`Engine_cve_input.py`)](#3-cve-research-engine-engine_cve_inputpy)
- [ReAct Agent & Human-in-the-Loop (`main_agent.py`)](#react-agent--human-in-the-loop-main_agentpy)
- [9-Phase Nmap Engine (`def_nmap/nmap_scanner.py`)](#9-phase-nmap-engine-def_nmapnmap_scannerpy)
  - [Phase Execution Matrix](#phase-execution-matrix)
  - [Checkpointing & Resumption](#checkpointing--resumption)
  - [Advanced NSE Analyzers & Posture Assessment](#advanced-nse-analyzers--posture-assessment)
- [Shodan Scraping Module (`def_Shodan/`)](#shodan-scraping-module-def_shodan)
- [Dual-Source CVE Enrichment & Multi-Account Rotator (`cve_maper/`)](#dual-source-cve-enrichment--multi-account-rotator-cve_maper)
  - [NIST NVD API Client](#nist-nvd-api-client)
  - [ChatGPT Browser Automation & Account Rotator](#chatgpt-browser-automation--account-rotator)
- [Engine Lifecycle Coordinator (`engine_manager.py`)](#engine-lifecycle-coordinator-engine_managerpy)
- [Database Schema & Persistence (`db_manager.py`)](#database-schema--persistence-db_managerpy)
  - [Reconnaissance Schema (10 Tables)](#reconnaissance-schema-10-tables)
  - [Chat & Agent Persistence (3 Tables)](#chat--agent-persistence-3-tables)
- [Configuration & Environment Variables](#configuration--environment-variables)
- [Local Development & CLI Execution](#local-development--cli-execution)

---

## Architecture Overview

```
                      ┌─────────────────────────────────────────┐
                      │            FastAPI HTTP Server          │
                      │            (Backend/api_server.py)      │
                      └────────────────────┬────────────────────┘
                                           │
                ┌──────────────────────────┴──────────────────────────┐
                ▼                                                     ▼
┌───────────────────────────────┐                     ┌───────────────────────────────┐
│       Main ReAct Agent        │                     │         Engine Manager        │
│     (Backend/main_agent.py)   │                     │   (Backend/engine_manager.py) │
├───────────────────────────────┤                     ├───────────────────────────────┤
│ • Groq LLM (gpt-oss-120b)     │                     │ • Background Worker Threads   │
│ • LangGraph State Machine     │                     │ • Cooperative Cancellation    │
│ • HITL Interrupt Mechanism    │                     │ • Thread-Safe Event Queues    │
│ • PostgresSaver Checkpointing │                     │ • Per-Phase Checkpoints       │
└───────────────┬───────────────┘                     └───────────────┬───────────────┘
                │                                                     │
                └──────────────────────────┬──────────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                            LANGGRAPH RECONNAISSANCE PIPELINES                       │
│                                                                                     │
│   ┌────────────────────────┐  ┌───────────────────────┐  ┌──────────────────────┐   │
│   │   Engine_query_input   │  │    Engine_ip_input    │  │   Engine_cve_input   │   │
│   │  NLP Query -> Shodan   │  │ Direct IP Scanning    │  │ Direct CVE Research  │   │
│   └───────────┬────────────┘  └───────────┬───────────┘  └──────────┬───────────┘   │
└───────────────┼───────────────────────────┼─────────────────────────┼───────────────┘
                ▼                           ▼                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                               COLLECTION & ENRICHMENT                               │
│                                                                                     │
│  • query_gen: Groq LLM converts natural language into Shodan search dorks           │
│  • def_Shodan: Playwright Chromium scraper, session cookies, host diff engine       │
│  • def_nmap: 9-Phase full-spectrum scanner (TCP, UDP, OS, Vuln, NSE, ACK, SCTP)     │
│  • cve_extractor: Service banner normalization and CVE regex extraction             │
│  • cve_mapper: NIST NVD API v2 + Playwright Headless ChatGPT account rotator        │
└──────────────────────────────────────────┬──────────────────────────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                             POSTGRESQL DATABASE (cti_db)                            │
│                                                                                     │
│  hosts • scans • ports • vulnerabilities • technologies • cve_details               │
│  cve_affected_products • cve_analysis • cve_mitre_mappings • nmap_scan_checkpoints  │
│  chat_messages • tool_calls • checkpoints • checkpoint_blobs • checkpoint_writes    │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

---

## FastAPI Server & 17 Endpoints

Located in [`Backend/api_server.py`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/api_server.py), the FastAPI server coordinates chat sessions, human authorization gates, background scanning threads, and threat intelligence queries.

### Chat & Agent Endpoints (7)

| Method | Endpoint | Description | Request Body / Params |
|---|---|---|---|
| `POST` | `/api/chats/new` | Creates a new chat investigation thread | `None` |
| `GET` | `/api/chats` | Lists all chat sessions with preview and timestamp | `None` |
| `GET` | `/api/chats/{thread_id}` | Retrieves all messages and tool states for a conversation | Path: `thread_id` |
| `DELETE` | `/api/chats/{thread_id}` | Deletes a conversation and associated tool calls | Path: `thread_id` |
| `POST` | `/api/chats/{thread_id}/message` | Sends user prompt and streams reasoning tokens via SSE | Body: `{"message": "string"}` |
| `POST` | `/api/chats/{thread_id}/approve` | Submits Human-in-the-Loop decision to resume or abort | Body: `{"action": "accept" \| "decline"}` |
| `POST` | `/api/chats/{thread_id}/stop` | Immediately cancels an ongoing agent reasoning stream | Path: `thread_id` |

### Engine Lifecycle & Streaming Endpoints (4)

| Method | Endpoint | Description | Request Body / Params |
|---|---|---|---|
| `GET` | `/api/engine/{engine_thread_id}/stream` | Server-Sent Events (SSE) stream for real-time engine progress | Path: `engine_thread_id` |
| `POST` | `/api/engine/{engine_thread_id}/stop` | Pauses/stops a running background engine cooperatively | Path: `engine_thread_id` |
| `POST` | `/api/engine/{engine_thread_id}/resume` | Resumes a paused engine from its latest checkpoint | Path: `engine_thread_id` |
| `GET` | `/api/chats/{thread_id}/engines` | Returns all active or paused engines tied to a chat | Path: `thread_id` |

### Threat Search & OSINT Endpoints (4)

| Method | Endpoint | Description | Query Parameters |
|---|---|---|---|
| `GET` | `/api/search/filters` | Returns all 43 supported Shodan search filters grouped by category | None |
| `GET` | `/api/search` | Queries local database using Shodan filter syntax with pagination | `q` (string), `page` (int), `page_size` (int) |
| `GET` | `/api/search/ip/{ip_address}` | Retrieves full host profile, Nmap active data, Shodan passive data, ACK firewall posture, and CVEs | Path: `ip_address` |
| `GET` | `/api/search/cve/{cve_id}` | Retrieves full NVD metrics, CPEs, ChatGPT ATT&CK analysis, and **affected local scanned assets** | Path: `cve_id` |

### Platform Health & Statistics (2)

| Method | Endpoint | Description | Response Format |
|---|---|---|---|
| `GET` | `/api/stats` | Aggregated count of hosts, scans, ports, and CVEs | `{"total_hosts": int, "total_scans": int, "total_ports": int, "total_cves": int}` |
| `GET` | `/api/health` | Health check verifying API status and database connectivity | `{"status": "ok", "database": "connected"}` |

### Server-Sent Events (SSE) Streaming Protocol

FastAPI streams events using `text/event-stream`. Two dedicated event streams are maintained:

#### 1. Chat Reasoning Stream (`POST /api/chats/{thread_id}/message`)
- `token`: Partial text token from Groq LLM reasoning (`data: {"token": "..."}`).
- `tool_approval`: HITL interrupt card requiring user authorization (`data: {"tool_name": "...", "tool_args": {...}}`).
- `tool_start`: Emitted when an approved engine starts execution (`data: {"tool_call_id": "...", "engine_thread_id": "..."}`).
- `tool_end`: Emitted upon engine completion with summary metrics (`data: {"tool_call_id": "...", "result": "..."}`).
- `done`: Final marker indicating the message stream is complete.
- `error`: Emitted if an unhandled exception occurs.

#### 2. Engine Progress Stream (`GET /api/engine/{engine_thread_id}/stream`)
- `phase`: Nmap phase transition event (`data: {"phase": 2, "phase_name": "Service & OS Detection", "status": "running"}`).
- `tool_node`: LangGraph pipeline node event (`data: {"node": "process_all_ips", "status": "running"}`).
- `log`: Console message or intermediate scanner output (`data: {"message": "Phase 1 complete: 4 open ports found."}`).
- `done`: Emitted when all pipeline steps finish successfully.
- `error`: Emitted if an engine error occurs.

---

## LangGraph Reconnaissance Engines

The platform includes three specialized execution graphs compiled with LangGraph:

### 1. Natural Language Query Engine (`Engine_query_input.py`)

Executes an end-to-end reconnaissance lifecycle starting from a natural language user prompt:

```
[query_gen] ──► [get_ip] ──► [process_all_ips] ──► [extract_cves] ──► [cve_mapper] ──► [summary]
```

1. **`query_gen`**: Sends the prompt to Groq (`openai/gpt-oss-120b`) with a specialized system prompt to generate a validated Shodan dork (e.g. `"Apache country:IN"`).
2. **`get_ip`**: Launches Playwright Chromium with cached cookies (`shodan_cookies.json`) and extracts up to `max_ips` (default 5) target IP addresses.
3. **`process_all_ips`**: Concurrently initiates Shodan host extraction (`def_Shodan/get_ip_info.py`) and the 9-phase Nmap scanner (`def_nmap/nmap_scanner.py`) across all discovered IPs.
4. **`extract_cves`**: Normalizes all discovered service banners, raw outputs, and NSE script results with regular expressions to identify mentioned CVE IDs.
5. **`cve_mapper`**: Enriches all extracted CVEs via the NIST NVD API v2 and the headless ChatGPT browser session.
6. **`summary`**: Aggregates all discovered hosts, ports, and vulnerabilities into an executive analytical briefing.

### 2. Direct IP Scanner Engine (`Engine_ip_input.py`)

Bypasses Shodan query generation when an analyst provides specific IP addresses:

```
[ip_input] ──► [process_all_ips] ──► [extract_cves] ──► [cve_mapper] ──► [summary]
```

- Deduplicates IPv4 addresses.
- Executes parallel Shodan passive scraping and 9-phase Nmap active scanning.
- Extracts and enriches vulnerabilities via NVD and ChatGPT.

### 3. CVE Research Engine (`Engine_cve_input.py`)

Dedicated vulnerability intelligence pipeline for analyzing specific CVE identifiers:

```
[cve_input] ──► [cve_mapper] ──► [summary]
```

- Accepts a list of CVE IDs (e.g., `CVE-2024-21626`).
- Queries NIST NVD for CVSS scores, CWE classification, and CPE configurations.
- Prompts ChatGPT to build step-by-step root cause walkthroughs, MITRE ATT&CK tactical mappings, and defensive recommendations.

---

## ReAct Agent & Human-in-the-Loop (`main_agent.py`)

Located in [`Backend/main_agent.py`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/main_agent.py):

- **Model**: Powered by Groq's high-speed inference engine running `openai/gpt-oss-120b`.
- **Tools Available to Agent**:
  1. `query_database`: Executes read-only SQL queries against PostgreSQL `cti_db` to answer questions about previously scanned hosts, ports, and CVEs.
  2. `scan_natural_language_query`: Spawns `Engine_query_input.py`.
  3. `scan_ip_list`: Spawns `Engine_ip_input.py`.
  4. `scan_cve_list`: Spawns `Engine_cve_input.py`.
- **HITL Safeguard**:
  Scanning is an active operation that carries legal and operational implications. Before executing any scanning tool, the agent invokes `interrupt(...)`:
  ```python
  # Interrupt execution and request authorization
  decision = interrupt({
      "tool_name": tool_name,
      "tool_args": tool_args,
      "message": f"Authorization required to launch scan on target: {tool_args}"
  })
  ```
  Execution halts until the user approves via `POST /api/chats/{thread_id}/approve`. The state is resumed from PostgreSQL via `PostgresSaver`.

---

## 9-Phase Nmap Engine (`def_nmap/nmap_scanner.py`)

Located in [`Backend/def_nmap/nmap_scanner.py`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/def_nmap/nmap_scanner.py), this module executes an extensive, sequential multi-phase assessment.

### Phase Execution Matrix

| Phase | Name | Target Ports | Nmap Flags & Scripts | Checkpointed Output |
|---|---|---|---|---|
| **Phase 1** | Fast TCP Discovery | `1-65535` | `-sS -T4 -p 1-65535 --open --reason` | Discovered open TCP ports and response reasons |
| **Phase 2** | Service & OS Detection | Discovered Ports | `-sV --version-intensity 5 -sC -O -T4 --traceroute` | Service names, versions, OS guesses, uptime, network hops |
| **Phase 3** | UDP Scanning | Top 500 UDP | `-sU -sV -T4 --top-ports 500 --version-intensity 0 --open` | Open UDP services (DNS, SNMP, NTP, DHCP) |
| **Phase 4** | Vulnerability Scripts | Open Ports | `-sV -T4 --script vuln,vulners` | Known vulnerability script outputs and CVE references |
| **Phase 5** | NSE Deep Enumeration | Open Ports | 64 targeted NSE scripts (SSL, HTTP headers, SMB, SSH, WAF) | Detailed protocol metadata, SSL certificates, headers |
| **Phase 6** | GeoIP & WHOIS | Host IP | `-sn --script ip-geolocation-geoplugin,whois-ip,dns-brute,fcrdns` | Autonomous system, network whois, brute-forced subdomains |
| **Phase 7** | Firewall Detection | Top 1000 Ports | `-sA -T4` (TCP ACK scan) | Stateful packet filter posture (`Likely Firewalled` vs `Unfiltered`) |
| **Phase 8** | IP Protocol Scan | Layer 4 | `-sO -T4` | Supported IP protocols: ICMP (1), IGMP (2), TCP (6), UDP (17), GRE (47), ESP (50) |
| **Phase 9** | SCTP Scan | Top 100 Ports | `-sY -T4 --top-ports 100 --open` | SCTP associations (telecom, SS7/SIGTRAN, WebRTC) |

### Checkpointing & Resumption

Every phase writes its intermediate JSON state to the `nmap_scan_checkpoints` table in PostgreSQL:
```sql
INSERT INTO nmap_scan_checkpoints (ip, engine_thread_id, last_phase, state_data, updated_at)
VALUES (%s, %s, %s, %s, NOW())
ON CONFLICT (ip, engine_thread_id) DO UPDATE SET last_phase = EXCLUDED.last_phase, state_data = EXCLUDED.state_data;
```
If an analyst pauses the scan (or the system restarts), calling `POST /api/engine/{engine_thread_id}/resume` reads the latest `last_phase` and skips all previously executed phases, preserving bandwidth and time.

### Advanced NSE Analyzers & Posture Assessment

- **ACK Firewall Posture Assessment**: Analyzes Phase 7 TCP ACK probe responses. If most ports respond with `filtered` (no RST packet returned), the system evaluates the host as **Likely Firewalled**; if ports return `unfiltered` (RST returned), it classifies the host as directly exposed.
- **SSL/TLS Certificate Inspection**: Extracts Subject Common Name, Issuer, Validity Not Before/After, Public Key Algorithm & bit strength, Subject Alternative Names (SANs), and SHA-1 fingerprint. Highlights expired certificates.
- **HTTP Security Headers Audit**: Verifies presence of defensive headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`) and explicitly reports missing headers.
- **SSH Key & Cipher Telemetry**: Catalogs host keys (RSA, ECDSA, ED25519), allowed authentication methods (`publickey`, `password`), and client-to-server cipher/MAC algorithms.
- **SMB Discovery**: Identifies exact Windows OS build, Domain Name, NetBIOS computer name, Forest Name, and remote system clock.

---

## Shodan Scraping Module (`def_Shodan/`)

Located in [`Backend/def_Shodan/`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/def_Shodan/):

1. **`get_ip.py`**:
   - Automates Shodan query searches using Playwright Chromium in headless mode.
   - Utilizes persistent cookies stored in `shodan_cookies.json` to maintain authenticated sessions without triggering CAPTCHAs.
   - Extracts target IP lists directly from search result pages.
2. **`get_ip_info.py`**:
   - Scrapes individual host detail pages (`https://www.shodan.io/host/{ip}`).
   - Checks the target host's `last_seen` timestamp against the local database. If unchanged, skips scraping to avoid redundant requests.
   - Extracts ISP, Organization, ASN, physical geolocation (`lat/lon`, postal, city, country), open ports, banners, HTTP response headers, SSL certificate data, and `security.txt` contact information.

---

## Dual-Source CVE Enrichment & Multi-Account Rotator (`cve_maper/`)

Located in [`Backend/cve_maper/`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/cve_maper/):

### NIST NVD API Client
- Queries official NIST NVD API v2 endpoints (`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}`).
- Normalizes CVSS base scores and vectors (CVSS v3.1, v3.0, and v2.0).
- Extracts CWE taxonomies, official references, and Common Platform Enumeration (CPE) configurations.

### ChatGPT Browser Automation & Account Rotator
To perform in-depth threat intelligence without enterprise LLM costs, CTI_V2 automates free ChatGPT sessions using Playwright persistent browser contexts:
- **Account Profiles**: Stored in `Backend/cve_maper/.accounts/`.
- **Account Rotator CLI (`add_chatgpt_account.py`)**:
  ```bash
  cd Backend/cve_maper
  python add_chatgpt_account.py
  ```
  Prompts the user to log in manually via an interactive browser window once. The session cookies and storage state are saved to disk.
- **Automatic Session Switching**:
  When ChatGPT returns an hourly message limit warning, the system automatically rotates to the next available browser profile in `.accounts/`.
- **Structured JSON Extraction**:
  Enforces a strict JSON response schema containing:
  - Technical vulnerability root-cause walkthrough.
  - Active in-the-wild exploitation status (CISA KEV, PoC availability).
  - MITRE ATT&CK Matrix mapping: Tactical stages (TA0001–TA0043) and Techniques (T1190, T1059, etc.) with technical justification.
  - Actionable mitigation checklists and threat-hunting detection queries.

---

## Engine Lifecycle Coordinator (`engine_manager.py`)

Located in [`Backend/engine_manager.py`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/engine_manager.py) and [`Backend/engine_progress.py`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/engine_progress.py):

- **Thread Tracking**: Spawns each scanning engine in a dedicated `threading.Thread` with an isolated `engine_thread_id`.
- **Real-Time Event Queues**: Each running engine writes progress events to an in-memory `queue.Queue`. The FastAPI SSE endpoint (`/api/engine/{engine_thread_id}/stream`) yields events directly from this queue.
- **Cooperative Cancellation**:
  - `EngineManager.stop_engine(engine_thread_id)` sets an internal `threading.Event` stop flag.
  - Both the LangGraph nodes and the 9-phase Nmap runner check this event at every loop iteration, halting execution immediately and cleanly recording checkpoint state.
- **Resumption**:
  - `EngineManager.resume_engine(engine_thread_id)` spins up a new worker thread starting from the checkpointed state.

---

## Database Schema & Persistence (`db_manager.py`)

CTI_V2 uses PostgreSQL (`cti_db`). Tables are initialized automatically on startup by [`db_manager.py`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/db_manager.py) and [`chat_persistence.py`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/chat_persistence.py).

### Reconnaissance Schema (10 Tables)

```
┌──────────────────┐       ┌──────────────────┐       ┌────────────────────────┐
│      hosts       │◄──────┤      scans       │◄──────┤         ports          │
│ (ip, geo, org,   │  1:N  │ (source, raw,    │  1:N  │ (port, protocol,       │
│  asn, os, tags)  │       │  scraped_at)     │       │  service, banner)      │
└──────────────────┘       └──────────────────┘       └───────────┬────────────┘
                                    │                             │
                                    ▼ 1:N                         ▼ 1:N
                           ┌──────────────────┐       ┌────────────────────────┐
                           │   technologies   │       │    vulnerabilities     │
                           │ (category, name, │       │ (cve_id, cvss, vector, │
                           │  version)        │       │  port_id FK)           │
                           └──────────────────┘       └───────────┬────────────┘
                                                                  │
                                   ┌──────────────────────────────┘
                                   ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                                     cve_details                                      │
│  (cve_id PRIMARY KEY, description, cwe_id, base_score, severity, published_date)     │
└──────────────┬───────────────────────────────────────────────────────┬───────────────┘
               │ 1:N                                                   │ 1:1
               ▼                                                       ▼
┌──────────────────────────────┐                              ┌────────────────────────┐
│    cve_affected_products     │                              │      cve_analysis      │
│ (vendor, product, version,   │                              │ (walkthrough, PoC info,│
│  cve_detail_id FK)           │                              │  mitigations, hunting) │
└──────────────────────────────┘                              └───────────┬────────────┘
                                                                          │ 1:N
                                                                          ▼
                                                              ┌────────────────────────┐
                                                              │   cve_mitre_mappings   │
                                                              │ (tactic_id, tech_id,   │
                                                              │  justification)        │
                                                              └────────────────────────┘
```

1. **`hosts`**: Central inventory of scanned target IPs, reverse hostnames, geolocations, ASN, and OS tags.
2. **`scans`**: Historical scan instances per host, recording scan source (`nmap` / `shodan`), timestamps, and raw JSON payloads.
3. **`ports`**: Discovered ports per scan, storing transport protocol, service name, version, raw banner, and HTTP titles.
4. **`vulnerabilities`**: Maps specific CVEs to individual open ports and scans.
5. **`technologies`**: Detected web server components, frameworks, and programming languages.
6. **`cve_details`**: Normalized NIST NVD intelligence (CVSS base scores, CWE IDs, descriptions, reference URLs).
7. **`cve_affected_products`**: Common Platform Enumeration (CPE) software and hardware matrices.
8. **`cve_analysis`**: ChatGPT threat analyses, including technical walkthroughs, mitigation checklists, and threat-hunting rules.
9. **`cve_mitre_mappings`**: MITRE ATT&CK tactics (TA0001–TA0043) and techniques (T1190, T1059, etc.) linked to threat analyses.
10. **`nmap_scan_checkpoints`**: Per-phase state checkpoints (`ip`, `engine_thread_id`, `last_phase`, `state_data`).

### Chat & Agent Persistence (3 Tables)

11. **`chat_messages`**: Conversation history (`thread_id`, `role`, `content`, `message_index`, `is_complete`).
12. **`tool_calls`**: In-progress and completed engine executions (`thread_id`, `tool_call_id`, `tool_name`, `engine_thread_id`, `status`, `progress`, `result_summary`).
13. **`checkpoints` / `checkpoint_blobs` / `checkpoint_writes`**: LangGraph internal state tables managed by `PostgresSaver`.

---

## Configuration & Environment Variables

Create a `.env` file in the project root:

```env
# ─── Shodan Credentials ──────────────────────────────────────────────────────
shodan_user=your_shodan_username
shodan_password=your_shodan_password

# ─── PostgreSQL Database ─────────────────────────────────────────────────────
PG_HOST=localhost
PG_PORT=5432
PG_DATABASE=cti_db
PG_USER=postgres
PG_PASSWORD=your_postgres_password

# ─── Groq API (Agent & Query Generation) ─────────────────────────────────────
GROQ_API_KEY=your_groq_api_key_here

# ─── NIST NVD API (Optional, for higher rate limits) ─────────────────────────
NIST_API_KEY=your_nist_api_key_here
```

---

## Local Development & CLI Execution

### Starting the FastAPI Server

```bash
cd Backend
python api_server.py
```
- API Server: `http://localhost:8000`
- Swagger UI Documentation: `http://localhost:8000/docs`
- Redoc Documentation: `http://localhost:8000/redoc`

### CLI Direct Execution

Any engine or agent module can be tested or executed directly from the terminal:

```bash
# Run the Interactive ReAct CTI Agent:
python Backend/main_agent.py

# Run Natural Language Query Engine:
python Backend/Engine_query_input.py

# Run Direct IP Scanning Engine:
python Backend/Engine_ip_input.py

# Run CVE Research Engine:
python Backend/Engine_cve_input.py

# Verify Database Connection & Tables:
python Backend/db_manager.py

# Register a new ChatGPT Account profile:
cd Backend/cve_maper
python add_chatgpt_account.py
```
