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
- [API Reference](#api-reference)
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
┌─────────────────────────────────────────────────────────────────────────────┐
│                             REACT FRONTEND (Vite)                           │
│  Chatbot UI  │  Live Engine Panel  │  Approval Cards  │  Pause/Resume UI    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ HTTP / SSE Stream
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          FASTAPI BACKEND (api_server.py)                    │
│  • Chat History Management          • Server-Sent Events (SSE) Stream       │
│  • HITL Approval Endpoints          • Engine Lifecycle Manager              │
│  • Local DB Search API              • Background Thread Coordinator         │
└──────────────────────┬───────────────────────────────┬──────────────────────┘
                       │                               │
                       ▼                               ▼
┌─────────────────────────────────────────┐  ┌────────────────────────────────┐
│       MAIN AGENT (main_agent.py)        │  │       ENGINE MANAGER           │
│  • LangGraph ReAct Agent Loop           │  │  • Thread Lifecycle Tracking  │
│  • Groq LLM (gpt-oss-120b)              │  │  • Real-time Progress Queues   │
│  • HITL Tool Interruption Mechanism     │  │  • Engine Cancellation Events │
└──────────────────────┬──────────────────┘  └────────────────┬───────────────┘
                       │                                      │
                       ▼                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LANGGRAPH EXECUTION PIPELINES                       │
│  ┌─────────────────────────┐ ┌──────────────────────┐ ┌──────────────────┐  │
│  │   Engine_query_input    │ │    Engine_ip_input   │ │ Engine_cve_input │  │
│  │ Natural Language Target │ │ Targeted IP Scanning │ │ Pure CVE Research│  │
│  └───────────┬─────────────┘ └──────────┬───────────┘ └─────────┬────────┘  │
└──────────────┼──────────────────────────┼───────────────────────┼───────────┘
               ▼                          ▼                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                             COLLECTION & ENRICHMENT                         │
│  • query_gen_ai: Groq-powered Shodan search query generation                │
│  • def_Shodan: Automated browser login & IP discovery / host scraper        │
│  • def_nmap: 9-Phase full-spectrum Nmap scanner with phase checkpoints      │
│  • cve_extractor: Regex and banner normalization for CVE discovery          │
│  • cve_mapper: NIST NVD API v2 + Headless ChatGPT Playwright automation     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          POSTGRESQL DATABASE (cti_db)                       │
│  • CTI Data: hosts, scans, ports, vulnerabilities, technologies, cve_details│
│  • Checkpoints: nmap_scan_checkpoints, checkpoints, checkpoint_blobs        │
│  • Chat: chat_messages, tool_calls                                          │
└─────────────────────────────────────────────────────────────────────────────┘
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

The frontend is located in [`Frontend/Chatbot/`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/):

- **Cyberpunk Dark Interface**: High-contrast, sleek interface with glassmorphism panels, custom glowing indicators, and clean typography.
- **Live Engine Progress Panel**:
  - Displays each pipeline step: `Query Generation`, `IP Discovery`, `Shodan + Nmap Scanning`, `CVE Extraction`, `NVD + ChatGPT Enrichment`, and `Summary`.
  - Shows dynamic per-phase Nmap status badges in real-time.
- **Pause & Resume Controls**:
  - Clicking **Stop** immediately signals backend threads and updates UI to *Pausing...*.
  - When paused, an in-panel **Resume** button allows continuing execution from the last checkpoint.
- **Human-in-the-Loop Dialog**: Modal approval cards for granting or declining tool execution.
- **Chat Management**: Sidebar session manager with history persistence, creation of new investigations, and deletion.

---

## API Reference

The FastAPI backend runs at `http://localhost:8000` ([`Backend/api_server.py`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Backend/api_server.py)):

### Chat & Agent
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/chats/new` | Creates a new chat session thread. |
| `GET` | `/api/chats` | Lists all chat session histories. |
| `GET` | `/api/chats/{thread_id}` | Retrieves messages for a specific conversation. |
| `DELETE` | `/api/chats/{thread_id}` | Deletes a chat session and clears related tool calls. |
| `POST` | `/api/chats/{thread_id}/message` | Sends user prompt and streams tokens and tool events via SSE. |
| `POST` | `/api/chats/{thread_id}/approve` | Submits Human-in-the-Loop decision (`{"action": "accept"|"decline"}`). |
| `POST` | `/api/chats/{thread_id}/stop` | Cancels an ongoing agent reasoning stream. |

### Engine Lifecycle & Streaming
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/engine/{engine_thread_id}/stream` | SSE stream for real-time progress events of a running engine. |
| `POST` | `/api/engine/{engine_thread_id}/stop` | Pauses/stops a running background engine. |
| `POST` | `/api/engine/{engine_thread_id}/resume` | Resumes a paused engine from its latest checkpoint. |
| `GET` | `/api/chats/{thread_id}/engines` | Lists running and paused engines associated with a chat. |

### Local Intelligence Search
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/search/ip/{ip}` | Retrieves all host details, scan history, ports, and CVEs for an IP. |
| `GET` | `/api/search/cve/{cve_id}` | Retrieves full NVD metrics, CPEs, and ChatGPT MITRE analysis for a CVE. |
| `GET` | `/api/stats` | Returns database statistics (total hosts, scans, ports, CVEs). |

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
├── README.md                         # Platform documentation
│
├── Backend/
│   ├── api_server.py                 # FastAPI REST and SSE streaming server
│   ├── main_agent.py                 # LangGraph ReAct agent with HITL approval
│   ├── engine_manager.py             # Background engine lifecycle manager
│   ├── engine_progress.py            # Real-time progress queues & cancel events
│   ├── db_manager.py                 # Core CTI PostgreSQL schema & query logic
│   ├── chat_persistence.py           # Chat history & tool call tracking tables
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
        ├── src/
        │   ├── App.jsx               # Chat interface, live engine panel, HITL modal
        │   ├── App.css               # Styling, animations, cyberpunk theme
        │   ├── main.jsx              # Application entry point
        │   └── index.css             # Base styles & CSS variables
        ├── package.json              # Frontend dependencies & scripts
        └── vite.config.js            # Vite configuration
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