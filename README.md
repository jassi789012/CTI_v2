# CTI_V2 — Autonomous Cyber Threat Intelligence Platform

[![Python Version](https://img.shields.io/badge/python-3.14%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![LangGraph](https://img.shields.io/badge/LangGraph-1.2%2B-orange.svg)](https://langchain-ai.github.io/langgraph/)
[![React](https://img.shields.io/badge/React-19.2-61dafb.svg)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-8.3-646cff.svg)](https://vitejs.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16%2B-336791.svg)](https://www.postgresql.org/)
[![Playwright](https://img.shields.io/badge/Playwright-1.63%2B-45ba4b.svg)](https://playwright.dev/)

**CTI_V2** is a modular, AI-powered Cyber Threat Intelligence (CTI) and automated reconnaissance platform. It combines automated OSINT discovery, full-spectrum 9-phase port scanning, dual-source vulnerability enrichment, and an autonomous AI ReAct agent with Human-in-the-Loop verification—all managed through a responsive, cyberpunk-inspired web interface with live streaming progress, checkpointing, and pause/resume execution controls.

---

## Table of Contents

- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Core Engines & Pipelines](#core-engines--pipelines)
- [AI Agent & Human-in-the-Loop](#ai-agent--human-in-the-loop)
- [Deep Reconnaissance & Scanning](#deep-reconnaissance--scanning)
  - [9-Phase Nmap Engine](#9-phase-nmap-engine)
  - [Shodan Web Scraping Automation](#shodan-web-scraping-automation)
  - [Dual-Source CVE Mapping (NVD + ChatGPT)](#dual-source-cve-mapping-nvd--chatgpt)
- [Web Applications & UI](#web-applications--ui)
  - [1. AI Threat Analyst Chat (`/` & `/chat`)](#1-ai-threat-analyst-chat---chat)
  - [2. Threat Search Engine (`/search`)](#2-threat-search-engine-search)
  - [3. Host Intelligence Page (`/ip/:ip`)](#3-host-intelligence-page-ipip)
  - [4. Vulnerability Intelligence Page (`/cve/:cveId`)](#4-vulnerability-intelligence-page-cvecveid)
  - [5. Cyberpunk 404 Error Page (`*`)](#5-cyberpunk-404-error-page-)
- [API Reference](#api-reference)
  - [Chat & AI Agent Endpoints (7)](#chat--ai-agent-endpoints-7)
  - [Engine Lifecycle & Streaming Endpoints (4)](#engine-lifecycle--streaming-endpoints-4)
  - [Threat Search & OSINT Intelligence Endpoints (4)](#threat-search--osint-intelligence-endpoints-4)
  - [System & Health Endpoints (2)](#system--health-endpoints-2)
- [Database Architecture](#database-architecture)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
  - [1. Clone Repository](#1-clone-repository)
  - [2. Environment & Python Dependencies](#2-environment--python-dependencies)
  - [3. Playwright Browser Installation](#3-playwright-browser-installation)
  - [4. PostgreSQL Configuration](#4-postgresql-configuration)
  - [5. Environment Variables (`.env`)](#5-environment-variables-env)
  - [6. ChatGPT Accounts Setup](#6-chatgpt-accounts-setup)
- [Running the Platform](#running-the-platform)
  - [Starting the API Server](#starting-the-api-server)
  - [Starting the Frontend UI](#starting-the-frontend-ui)
  - [CLI Interactive Mode](#cli-interactive-mode)
- [Project Directory Structure](#project-directory-structure)
- [Ethics & Disclaimer](#ethics--disclaimer)
- [License & Author](#license--author)

---

## Key Features

- **Autonomous AI Security Analyst**: LangGraph ReAct agent powered by Groq (`openai/gpt-oss-120b`) that reasons over threat queries, queries the local PostgreSQL database, and coordinates background scanning engines.
- **Human-in-the-Loop (HITL) Safeguards**: LangGraph interrupt mechanisms pause execution before launching active scans, requesting user authorization via interactive approval cards.
- **Three Specialized Recon Engines**:
  - **Natural Language Query Engine**: Converts conversational queries (e.g. *"Find vulnerable Apache servers in Germany"*) into Shodan search dorks, discovers IPs, runs deep scans, and maps CVEs.
  - **Direct IP Scanner Engine**: Performs 9-phase deep scans and Shodan reconnaissance directly on target IP lists.
  - **CVE Research Engine**: Directly fetches NVD metrics and runs automated ChatGPT MITRE ATT&CK mapping and exploit walkthroughs on specific CVE IDs.
- **9-Phase Full-Spectrum Nmap Scanner**: Sequential multi-phase scanner with automated TCP, UDP, Service detection, OS fingerprinting, 64 NSE enumeration scripts, SSL ciphers, WHOIS/DNS/GeoIP, ACK firewall detection, IP protocols, and SCTP scans.
- **Per-Phase Checkpointing & Resumption**: Every Nmap phase and LangGraph engine step writes state to PostgreSQL, allowing immediate pause and resume without losing prior progress.
- **Zero-Cost LLM Enrichment**: Headless Playwright ChatGPT browser automation with persistent session profiles, multi-account rotation, anti-bot mitigation, and robust JSON schema extraction.
- **Live SSE Streaming**: FastAPI server streams agent reasoning tokens and engine step-by-step execution metrics over Server-Sent Events (SSE).
- **Interactive Cyberpunk Frontend**: Built with React 19, Vite, and Lucide icons, featuring real-time node progress trackers, pause/resume/stop controls, and GFM markdown rendering.

---

## System Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                          REACT 19 FRONTEND (Vite)                                      │
│  ┌─────────────────────────┐  ┌──────────────────────────┐  ┌───────────────────┐  ┌────────────────┐  │
│  │ AI Chatbot (/ & /chat)  │  │ Threat Search (/search)  │  │ Host Intel (/ip)  │  │ Vuln Intel     │  │
│  │ Live SSE Engine Tracker │  │ 43-Filter Shodan Dorks   │  │ Nmap+Shodan Tabs  │  │ Local Assets & │  │
│  │ HITL Approval Cards     │  │ Dynamic Aggregations     │  │ ACK Firewall/SSL  │  │ ATT&CK Mapping │  │
│  └─────────────────────────┘  └──────────────────────────┘  └───────────────────┘  └────────────────┘  │
└───────────────────────────────────────────────────┬────────────────────────────────────────────────────┘
                                                    │ HTTP REST / SSE Event Streams
                                                    ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     FASTAPI BACKEND (api_server.py)                                    │
│  • 17 REST & SSE Endpoints             • Server-Sent Events (SSE) Streaming • 43-Filter Dork Search   │
│  • Human-in-the-Loop Interruption      • Background Engine Thread Manager   • Local CTI Data APIs      │
└───────────────────────────┬───────────────────────────────────────────┬────────────────────────────────┘
                            │                                           │
                            ▼                                           ▼
┌──────────────────────────────────────────────┐       ┌─────────────────────────────────────────────────┐
│          MAIN AGENT (main_agent.py)          │       │         ENGINE MANAGER (engine_manager.py)      │
│  • LangGraph ReAct Agent Loop                │       │  • Background Thread Coordination & Execution   │
│  • Groq LLM (openai/gpt-oss-120b)            │       │  • Real-time SSE Event Queues (engine_progress) │
│  • HITL Tool Interruption & Approval Gate    │       │  • Cooperative Thread Interruption & Pause/Stop │
└───────────────────────────┬──────────────────┘       └────────────────────────┬────────────────────────┘
                            │                                                   │
                            ▼                                                   ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                      LANGGRAPH RECON PIPELINES                                         │
│  ┌───────────────────────────────────┐ ┌────────────────────────────────┐ ┌───────────────────────────┐  │
│  │     Engine_query_input.py         │ │      Engine_ip_input.py        │ │    Engine_cve_input.py    │  │
│  │ Natural Language Target Discovery │ │ Direct IP Reconnaissance       │ │ Pure Vulnerability        │  │
│  │ Shodan Dorking -> Active Scans    │ │ Shodan Passive + 9-Phase Nmap  │ │ Research & ATT&CK Mapping │  │
│  └─────────────────┬─────────────────┘ └───────────────┬────────────────┘ └─────────────┬─────────────┘  │
└────────────────────┼───────────────────────────────────┼────────────────────────────────┼────────────────┘
                     ▼                                   ▼                                ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                        COLLECTION & ENRICHMENT                                         │
│  • query_gen_ai: Groq-powered natural language to Shodan search query generator                       │
│  • def_Shodan: Playwright Chromium authenticated scraper, cookie session pool, and diffing engine      │
│  • def_nmap: 9-Phase full-spectrum Nmap engine with per-phase state checkpointing & ACK firewall audit │
│  • cve_extractor: Regex and banner normalization for multi-port CVE extraction                        │
│  • cve_mapper: Dual-source enrichment via NIST NVD API v2 + Playwright Headless ChatGPT account rotator│
└───────────────────────────────────────────────────┬────────────────────────────────────────────────────┘
                                                    │
                                                    ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       POSTGRESQL DATABASE (cti_db)                                     │
│  • CTI Intelligence: hosts, scans, ports, vulnerabilities, technologies, cve_details, affected_products│
│  • AI & ATT&CK: cve_analysis (walkthroughs, mitigations, detection), cve_mitre_mappings (tactics, tech)│
│  • Checkpoints: nmap_scan_checkpoints, checkpoints, checkpoint_blobs, checkpoint_writes                │
│  • Chat & Session State: chat_messages, tool_calls                                                     │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Core Engines & Pipelines

### 1. Natural Language Query Engine (`Engine_query_input.py`)
Executes the full reconnaissance lifecycle starting from an analytical query:
1. **Query Generation (`query_gen`)**: Groq LLM parses the user prompt into valid Shodan search dorks (e.g., `product:Apache country:IN`).
2. **IP Discovery (`get_ip`)**: Playwright navigates Shodan search results to extract target IP addresses.
3. **Parallel Scanning (`process_all_ips`)**: Concurrently launches Shodan host page data fetching and the 9-phase Nmap scanner.
4. **CVE Extraction (`extract_cves`)**: Aggregates service banners and outputs to identify mentioned CVE IDs.
5. **Vulnerability Enrichment (`cve_mapper`)**: Fetches NVD CVSS scores and generates ChatGPT MITRE ATT&CK mappings and vulnerability walkthroughs.
6. **Summary Generation (`summary`)**: Compiles intelligence into structured database records and returns a concise executive summary.

### 2. Direct IP Scanner Engine (`Engine_ip_input.py`)
Bypasses query generation when the analyst already has target IP addresses:
- Deduplicates and normalizes target IPv4 addresses.
- Executes parallel Shodan host extraction and the 9-phase Nmap scanner.
- Performs CVE extraction, NVD querying, and ChatGPT threat enrichment.

### 3. CVE Research Engine (`Engine_cve_input.py`)
Used for targeted vulnerability research:
- Accepts a list of CVE IDs (e.g., `CVE-2024-21626`, `CVE-2023-38606`).
- Queries the NIST NVD API for CVSS base scores, CWE categorization, and CPE affected products.
- Uses the ChatGPT Playwright session to build exploitation walkthroughs, attack vector analyses, and defensive recommendations.

---

## AI Agent & Human-in-the-Loop

The agent is implemented using **LangGraph ReAct** architecture in [`Backend/main_agent.py`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/main_agent.py):

- **Tool Selection**: When an analyst sends a prompt, the agent decides whether to answer from internal knowledge, query the local PostgreSQL CTI database, or launch an active enumeration engine.
- **Human-in-the-Loop Interrupts**: Starting a network scan is an active operation. The agent raises an `interrupt(...)` before executing `scan_natural_language_query`, `scan_ip_list`, or `scan_cve_list`.
- **Approval Cards**: The frontend receives a `tool_approval` SSE event and presents the user with an authorization card displaying the tool name and exact parameters.
- **Resume & Execution**: Clicking **Accept** issues a `POST /api/chats/{thread_id}/approve`, resuming LangGraph state via `PostgresSaver` checkpointer and launching the engine in a background thread.

---

## Deep Reconnaissance & Scanning

### 9-Phase Nmap Engine
Located in [`Backend/def_nmap/nmap_scanner.py`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/def_nmap/nmap_scanner.py):

| Phase | Name | Arguments / Description |
|---|---|---|
| **1** | Fast TCP Discovery | `-sS -T4 -p 1-65535 --open --reason` (all 65535 ports) |
| **2** | Service & OS Detection | `-sV --version-intensity 5 -sC -O -T4 --traceroute` on open ports |
| **3** | UDP Scan | `-sU -sV -T4 --top-ports 500 --version-intensity 0 --open` |
| **4** | Vulnerability Scripts | `-sV -T4 --script vuln,vulners` on discovered ports |
| **5** | NSE Enumeration | 64 targeted NSE scripts (SSL ciphers, heartbleed, HTTP headers, WAF, robots, SMB, SSH) |
| **6** | GeoIP & WHOIS | `-sn --script ip-geolocation-geoplugin,whois-ip,dns-brute,fcrdns` |
| **7** | Firewall Detection | `-sA -T4` (TCP ACK scan to identify stateful firewalls & filtered ports) |
| **8** | IP Protocol Scan | `-sO -T4` (discovers supported layer-4 protocols: ICMP, IGMP, TCP, UDP, GRE, ESP) |
| **9** | SCTP Scan | `-sY -T4 --top-ports 100 --open` (identifies telecom & signaling interfaces) |

Every phase writes its progress to `nmap_scan_checkpoints`. If a scan is stopped or interrupted, resumption automatically skips already completed phases.

### Shodan Web Scraping Automation
Located in [`Backend/def_Shodan/`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/def_Shodan/):
- Uses Playwright Chromium automation to interact with Shodan web interfaces.
- Stores authenticated sessions in `shodan_cookies.json` to eliminate repeated logins.
- Detects database `last_seen` timestamps and performs lightweight diff checks to avoid redundant scraping.

### Dual-Source CVE Mapping (NVD + ChatGPT)
Located in [`Backend/cve_maper/`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/cve_maper/):
- **NIST NVD API**: Queries official CVSS metrics (v2/v3.1/v4), CWE taxonomies, severity vectors, and CPE configurations.
- **ChatGPT Browser Automation**:
  - Automates free web ChatGPT accounts using Playwright persistent browser contexts.
  - Features an **Account Rotator** (`add_chatgpt_account.py`) that stores multiple profiles in `Backend/cve_maper/.accounts/`.
  - Automatically switches accounts when rate limits or hourly message caps are encountered.
  - Extracts structured JSON containing:
    - Root-cause vulnerability walkthrough.
    - MITRE ATT&CK Tactics (TA0001–TA0043) and Techniques (T1190, T1059, etc.) with technical justification.
    - Detection strategies and actionable mitigation guidelines.

---

## Web Applications & UI

The frontend is located in [`Frontend/Chatbot/`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/) (see [Frontend Documentation](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/README.md) for full design guide):

### 1. AI Threat Analyst Chat (`/` & `/chat`)
- **Real-Time Token Streaming**: Agent thoughts and execution steps stream via Server-Sent Events (SSE) with GFM Markdown formatting.
- **Human-in-the-Loop Cards**: Interactive authorization cards when the agent proposes active scans (`scan_natural_language_query`, `scan_ip_list`, `scan_cve_list`).
- **Live Recon Engine Panel**: Visualizes pipeline stages (`Query Gen`, `IP Discovery`, `Parallel Scanning`, `CVE Extraction`, `NVD + AI Enrichment`, `Summary`) with per-phase Nmap status badges and pause/resume/stop buttons.
- **Chat History Sidebar**: Persistent conversation switcher with thread creation, deletion, and local storage synchronization.

### 2. Threat Search Engine (`/search`)
- **43-Filter Shodan Search Engine**: Full query parser matching Shodan filter syntax across local PostgreSQL data:
  - **General & Network**: `ip`, `net`, `port`, `asn`, `org`, `isp`, `hostname`, `has_ipv6`, `all`
  - **Geographic**: `country`, `city`, `state`, `region`
  - **Software & Device**: `product`, `version`, `os`, `cpe`, `tag`, `hash`
  - **Vulnerability & Security**: `vuln`, `has_vuln`, `has_ssl`, `has_screenshot`
  - **HTTP & Web-Server**: `http.component`, `http.component_category`, `http.title`, `http.status`, `http.waf`
  - **SSL/TLS & Certificate**: `ssl`, `ssl.version`, `ssl.cert.subject.cn`, `ssl.cert.issuer.cn`, `ssl.ja3s`
  - **SSH**: `ssh.fingerprint`
- **Dynamic Facets Sidebar**: Real-time aggregations for Top Countries, Top Open Ports, and Top Organizations.
- **Interactive Preset Chips**: Quick one-click filters for common searches (`port:22`, `port:80`, `port:443`, `has_vuln:true`, `has_ssl:true`, `product:openssh`).
- **Host Intelligence Cards**: Clean result cards displaying IP address, geographic location, ASN/ISP, open port chips with service names, CVE count badges, and pagination.

### 3. Host Intelligence Page (`/ip/:ip`)
- **Hero Host Header**: IP address with copy button, reverse PTR hostnames, source presence badges (`Shodan` / `Nmap`), scan count, total CVEs, physical coordinates (`lat/lon`, postal, region), organization, ASN, OS, and Shodan tags.
- **Tabbed Inspection Framework** (`?tab=all|shodan|nmap|vulns|timeline`):
  - **Shodan Passive Recon**: Observation dates, `security.txt` responsible disclosure contact card, categorized web technology badges (frameworks, web servers), and banners.
  - **Nmap Active Scanner**: Execution CLI command, uptime & TCP predictability, OS detection accuracy bars, traceroute network hops, and advanced NSE scripts:
    - **ACK Firewall Posture (Phase 6)**: Evaluates whether the host is behind a stateful packet-filtering firewall (`Likely Firewalled` vs `Unfiltered`) with filtered ports count and ACK probe response breakdown.
    - **DNS Reconnaissance**: Subdomain brute-forcing, PTR reverse lookup, and DNS zone transfer test results.
    - **SSH Intelligence**: Host key fingerprints, allowed authentication methods, and supported ciphers/KEX/MAC algorithms.
    - **SMB & Active Directory**: Domain name, forest, workgroup, exact OS build, and target system clock.
    - **Layer-3/4 IP Protocols**: Discovered protocol support (ICMP, IGMP, GRE, ESP, AH).
    - **Network Whois**: Registrant organization, CIDR blocks, and ASN records.
    - **SSL/TLS Certificate Inspector**: Subject CN, Issuer, validity range (with EXPIRED tags), SAN domains, and SHA-1 fingerprint.
    - **HTTP Security Headers Audit**: Validated headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) and flagged missing defensive headers.
  - **Aggregated Vulnerabilities Tab**: Severity filterable (Critical, High, Medium, Low) CVE list with CVSS vectors, summaries, affected port badges, and discovery source tags.
  - **Scan Timeline Tab**: Historical snapshots showing each scan date, source engine, and per-port observation timestamps.

### 4. Vulnerability Intelligence Page (`/cve/:cveId`)
- **Comprehensive CVE Overview**: Executive title, CVSS v2/v3.1 base score, severity badge, attack vector metrics grid, and full CVSS vector string with copy button.
- **Affected Local Assets & Scanned Hosts Card**:
  - Automatically correlates the vulnerability with your local scanned hosts in PostgreSQL.
  - Displays host IP (clickable link to `/ip/:ip`), vulnerable port/protocol, discovery source (`nmap` / `shodan`), and direct action button *"View Host Intelligence →"*.
  - Displays a clean green reassurance badge when no local assets are affected.
- **Weakness Taxonomy (CWE)**: Official MITRE CWE identifier, title, and link.
- **Threat & Exploit Telemetry**: CISA KEV exploitation status, public exploit/PoC availability, and Exploit-DB/GitHub references.
- **Adversary MITRE ATT&CK Matrix**: Tactical mapping (TA0001–TA0043) and techniques (T1190, T1059, etc.) with technical justification.
- **Technical Walkthrough & Mitigations**: Step-by-step vulnerability walkthrough, verified remediation checklist, and threat hunting Snort/Suricata rules.
- **Affected Products (CPE)**: Filterable table of affected vendor software and versions from NIST NVD.
- **Raw Payloads Viewer**: Collapsible JSON inspector for underlying NVD and AI response payloads.

### 5. Cyberpunk 404 Error Page (`*`)
- Terminal-inspired route fallback with automated redirection controls.

---

## API Reference

The FastAPI backend runs at `http://localhost:8000` ([`Backend/api_server.py`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/api_server.py)). Interactive OpenAPI documentation is available at `http://localhost:8000/docs`.

### Chat & AI Agent Endpoints (7)
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/chats/new` | Creates a new chat session thread. |
| `GET` | `/api/chats` | Lists all chat session histories with preview messages. |
| `GET` | `/api/chats/{thread_id}` | Retrieves all messages, message indices, and tool states for a conversation. |
| `DELETE` | `/api/chats/{thread_id}` | Deletes a conversation and clears associated tool calls. |
| `POST` | `/api/chats/{thread_id}/message` | Sends user prompt and streams LLM tokens and tool calls via SSE. |
| `POST` | `/api/chats/{thread_id}/approve` | Submits Human-in-the-Loop authorization decision (`{"action": "accept"|"decline"}`). |
| `POST` | `/api/chats/{thread_id}/stop` | Cancels an ongoing agent reasoning stream. |

### Engine Lifecycle & Streaming Endpoints (4)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/engine/{engine_thread_id}/stream` | Server-Sent Events (SSE) stream for real-time progress events of a running engine. |
| `POST` | `/api/engine/{engine_thread_id}/stop` | Pauses/stops a running background engine cooperatively. |
| `POST` | `/api/engine/{engine_thread_id}/resume` | Resumes a paused engine from its latest phase checkpoint. |
| `GET` | `/api/chats/{thread_id}/engines` | Lists running and paused scanning engines associated with a chat. |

### Threat Search & OSINT Intelligence Endpoints (4)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/search/filters` | Returns all 43 supported Shodan search filters grouped by category. |
| `GET` | `/api/search` | Queries local database using Shodan filter syntax (`?q=...&page=1&page_size=20`). |
| `GET` | `/api/search/ip/{ip_address}` | Retrieves full host intelligence (Shodan passive, Nmap active, ACK firewall, SSL, CVEs). |
| `GET` | `/api/search/cve/{cve_id}` | Retrieves full NVD metrics, CPEs, ChatGPT ATT&CK analysis, and **affected local assets**. |

### System & Health Endpoints (2)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/stats` | Returns database statistics (total hosts, scans, ports, CVEs). |
| `GET` | `/api/health` | Health check endpoint returning system status and database connectivity. |

---

## Database Architecture

Data is stored in PostgreSQL (`cti_db`). Tables are initialized automatically on startup by [`db_manager.py`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/db_manager.py) and [`chat_persistence.py`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/chat_persistence.py):

### CTI Reconnaissance Tables
1. **`hosts`**: Central inventory of scanned IPs (`ip`, `country`, `city`, `organization`, `isp`, `asn`, `os`, `tags`, `first_seen`, `last_updated`).
2. **`scans`**: Historical scan snapshots per host (`host_id`, `source`, `source_last_seen`, `scraped_at`, `raw_data`, `metadata`).
3. **`ports`**: Discovered ports, services, and banners (`scan_id`, `port_number`, `protocol`, `state`, `service`, `version`, `banner`, `http_title`, `extra`).
4. **`vulnerabilities`**: CVEs discovered on specific ports (`port_id`, `cve_id`, `cvss`, `cvss_vector`, `summary`).
5. **`technologies`**: Detected web technologies and libraries (`scan_id`, `category`, `name`, `version`).
6. **`cve_details`**: Normalized NIST NVD intelligence (`cve_id`, `description`, `cwe_id`, `base_score`, `severity`, `published_date`, `reference_urls`, `nvd_raw`).
7. **`cve_affected_products`**: CPE hardware/software configurations (`cve_detail_id`, `vendor`, `product`, `version`, `affected_platform`).
8. **`cve_analysis`**: ChatGPT threat analyses (`cve_detail_id`, `title`, `exploitation_info`, `mitigations`, `detection_recommendations`, `vulnerability_walkthrough`).
9. **`cve_mitre_mappings`**: MITRE ATT&CK framework mapping (`cve_analysis_id`, `tactic_id`, `tactic_name`, `technique_id`, `technique_name`, `justification`).
10. **`nmap_scan_checkpoints`**: Per-phase state checkpoints (`ip`, `engine_thread_id`, `last_phase`, `state_data`).

### Chat & Agent Persistence Tables
11. **`chat_messages`**: Chat conversation history and streaming states (`thread_id`, `role`, `content`, `message_index`, `is_complete`).
12. **`tool_calls`**: In-progress and completed engine executions (`thread_id`, `tool_call_id`, `tool_name`, `engine_thread_id`, `status`, `progress`, `result_summary`).
13. **`checkpoints` / `checkpoint_blobs` / `checkpoint_writes`**: LangGraph internal state tables managed by `PostgresSaver`.

---

## Prerequisites

| Software | Version | Purpose |
|---|---|---|
| **Python** | ≥ 3.14 | Core backend runtime |
| **uv** | Latest | High-performance Python package and venv manager |
| **Node.js** | ≥ 18.0 | React / Vite frontend runtime |
| **PostgreSQL** | ≥ 16 | Relational CTI data store & LangGraph checkpointer |
| **Nmap** | Latest | Network port scanner (must be available in system `PATH`) |
| **Playwright** | Latest | Browser automation for Shodan and ChatGPT |
| **Groq API Key** | — | High-speed LLM inference for ReAct agent & query generation |
| **NVD API Key** | — | Optional but recommended for NIST NVD API rate limits |

---

## Installation & Setup

### 1. Clone Repository
```bash
git clone https://github.com/jassi789012/CTI_v2.git
cd CTI_v2
```

### 2. Environment & Python Dependencies
Using [uv](https://docs.astral.sh/uv/):
```bash
uv sync
```
*Alternatively, using standard virtualenv:*
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -e .
```

### 3. Playwright Browser Installation
Install the required Chromium binaries for browser scraping:
```bash
playwright install chromium
```

### 4. PostgreSQL Configuration
1. Ensure PostgreSQL service is running on `localhost:5432`.
2. Connect to PostgreSQL and create the database:
```sql
CREATE DATABASE cti_db;
```

### 5. Environment Variables (`.env`)
Create a `.env` file in the project root directory:
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

# ─── Groq API (AI Agent & Query Generation) ──────────────────────────────────
# Free API key: https://console.groq.com
GROQ_API_KEY=your_groq_api_key_here

# ─── NIST NVD API (CVE Enrichment) ──────────────────────────────────────────
# Free API key: https://nvd.nist.gov/developers/request-an-api-key
NIST_API_KEY=your_nist_api_key_here
```

### 6. ChatGPT Accounts Setup
To enable zero-cost ChatGPT vulnerability analysis, register at least one free ChatGPT account:
```bash
cd Backend/cve_maper
python add_chatgpt_account.py
```
Follow the interactive prompt:
- Enter an account label (e.g., `account1`).
- Playwright opens a browser window.
- Manually log in to your ChatGPT account.
- Press Enter in the terminal to save the persistent session profile to `Backend/cve_maper/.accounts/`.
- *(Optional)* Add multiple accounts to automatically bypass hourly rate limits.

---

## Running the Platform

### Starting the API Server
From the `Backend` directory:
```bash
cd Backend
python api_server.py
```
- API Server: `http://localhost:8000`
- Interactive OpenAPI Docs: `http://localhost:8000/docs`

### Starting the Frontend UI
From the `Frontend/Chatbot` directory:
```bash
cd Frontend/Chatbot
npm install
npm run dev
```
- Access the web application at `http://localhost:5173`.

### CLI Interactive Mode
You can also run any of the engines or agent directly from the command line:

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
```

---

## Project Directory Structure

```
CTI_V2/
├── .env                              # Environment configuration (credentials, DB)
├── .env.example                      # Sample configuration template
├── pyproject.toml                    # Python project configuration & dependencies
├── uv.lock                           # Locked dependency resolution
├── README.md                         # Platform root documentation
│
├── Backend/                          # Python FastAPI & LangGraph backend
│   ├── README.md                     # Backend modular documentation
│   ├── api_server.py                 # FastAPI REST (17 endpoints) and SSE streaming server
│   ├── main_agent.py                 # LangGraph ReAct agent with HITL approval
│   ├── engine_manager.py             # Background engine lifecycle manager
│   ├── engine_progress.py            # Real-time progress queues & cancel events
│   ├── db_manager.py                 # Core CTI PostgreSQL schema (10 tables) & query logic
│   ├── chat_persistence.py           # Chat history & tool call tracking (3 tables)
│   ├── cve_extractor.py              # Service banner & output CVE extractor
│   │
│   ├── Engine_query_input.py         # Full Natural Language Query LangGraph engine
│   ├── Engine_ip_input.py            # Targeted IP List LangGraph engine
│   ├── Engine_cve_input.py           # CVE Research & Enrichment LangGraph engine
│   │
│   ├── def_Shodan/                   # Shodan automation module
│   │   ├── get_ip.py                 # Shodan query search & IP discovery
│   │   ├── get_ip_info.py            # Shodan host page scraper & diff engine
│   │   └── shodan_cookies.json       # Cached authenticated browser cookies
│   │
│   ├── def_nmap/                     # Nmap reconnaissance module
│   │   └── nmap_scanner.py           # 9-Phase full-spectrum scanner with checkpoints
│   │
│   ├── cve_maper/                    # Dual-source vulnerability enrichment
│   │   ├── cve_mapper.py             # NVD API v2 client + Playwright ChatGPT engine
│   │   ├── add_chatgpt_account.py    # Multi-account registration CLI utility
│   │   └── .accounts/                # Persistent Playwright browser profiles
│   │
│   └── query_gen/                    # AI query generation module
│       └── query_gen_ai.py           # Groq LLM Shodan dork generator
│
└── Frontend/
    └── Chatbot/                      # React 19 + Vite Frontend Application
        ├── README.md                 # Frontend design system & routes documentation
        ├── src/
        │   ├── App.jsx               # AI Chat interface, live engine panel, HITL modal
        │   ├── App.css               # Chat styling, animations, cyberpunk theme
        │   ├── SearchPage.css        # Scoped stylesheet for search & intelligence views
        │   ├── index.css             # Base styles & CSS design tokens
        │   ├── main.jsx              # React DOM entry point & Router configuration
        │   │
        │   └── pages/                # Modular page views
        │       ├── SearchPage.jsx    # 43-Filter Shodan threat search & facet aggregations
        │       ├── IpDetailPage.jsx  # Deep host inspection (Nmap + Shodan + ACK firewall)
        │       ├── CveDetailPage.jsx # CVE telemetry, ATT&CK mapping & local affected assets
        │       └── NotFoundPage.jsx  # Cyberpunk-styled 404 error page
        │
        ├── package.json              # Frontend dependencies & scripts
        └── vite.config.js            # Vite configuration & proxy settings
```

---

## Ethics & Disclaimer

> [!WARNING]
> **CTI_V2** is developed strictly for **authorized penetration testing, defensive threat intelligence, academic research, and educational purposes**.
> Scanning networks, hosts, or systems without explicit prior authorization from the system owners may violate national and international computer fraud laws. The authors and contributors assume no liability for misuse or damage caused by this software. Always act in compliance with applicable laws and rules of engagement.

---

## License & Author

- **Author**: **jassi789012** ([jassi789012singh@gmail.com](mailto:jassi789012singh@gmail.com))
- **Repository**: [https://github.com/jassi789012/CTI_v2](https://github.com/jassi789012/CTI_v2)
- **License**: Educational & Authorized Security Research License.