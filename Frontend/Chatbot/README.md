# CTI_V2 — Cyber Threat Intelligence Frontend

[![React](https://img.shields.io/badge/React-19.2-61dafb.svg)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-8.3-646cff.svg)](https://vitejs.dev/)
[![React Router](https://img.shields.io/badge/React_Router-7.18-ca4245.svg)](https://reactrouter.com/)
[![Lucide Icons](https://img.shields.io/badge/Lucide_React-1.51-f56565.svg)](https://lucide.dev/)

A modern, high-contrast, cyberpunk-themed web application built for the **CTI_V2 Autonomous Threat Intelligence Platform**. It provides security analysts with interactive AI chat investigations, live pipeline engine visualization, multi-filter OSINT searching, deep host inspection, and comprehensive vulnerability research.

---

## Table of Contents

- [Features & Capabilities](#features--capabilities)
- [Application Architecture & Routes](#application-architecture--routes)
- [Pages Deep-Dive](#pages-deep-dive)
  - [1. AI Threat Analyst Chat (`/` & `/chat`)](#1-ai-threat-analyst-chat----chat)
  - [2. Threat Search Engine (`/search`)](#2-threat-search-engine-search)
  - [3. Host Intelligence Page (`/ip/:ip`)](#3-host-intelligence-page-ipip)
  - [4. Vulnerability Intelligence Page (`/cve/:cveId`)](#4-vulnerability-intelligence-page-cvecveid)
  - [5. 404 Not Found Page (`*`)](#5-404-not-found-page-)
- [Design System & Aesthetics](#design-system--aesthetics)
- [Technology Stack](#technology-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Development Server](#development-server)
  - [Production Build](#production-build)
- [Backend API Integration](#backend-api-integration)

---

## Features & Capabilities

- **Interactive AI Chat & Streaming Reasoning:** Real-time token streaming from LangGraph ReAct agent via Server-Sent Events (SSE) with GFM Markdown rendering.
- **Live Reconnaissance Engine Panel:** Real-time step-by-step pipeline tracker showing engine execution states, current nodes, per-phase Nmap status badges, and pause/resume/stop controls.
- **Human-in-the-Loop (HITL) Approval Modals:** Interactive authorization cards when the agent requests permission to run active network scans or deep CVE mappers.
- **43-Filter Shodan Search Engine:** Search local intelligence using Shodan dork syntax across 7 categories (Network, Geographic, Software, Security, HTTP, SSL/TLS, SSH) with dynamic facets and pagination.
- **Deep Host Inspection:** Side-by-side tabs for Shodan passive intelligence and Nmap active reconnaissance, including ACK firewall detection, DNS brute-forcing, SSH keys & cipher suites, SMB domain discovery, layer 3/4 IP protocols, SSL certificate inspector, and HTTP security headers audit.
- **Vulnerability Telemetry & Affected Assets:** Displays full CVSS v2/v3.1 breakdowns, MITRE ATT&CK matrix mappings, step-by-step walkthroughs, actionable mitigations, NVD CPE product tables, and an **Affected Local Scanned Assets table** showing which internal hosts are vulnerable.

---

## Application Architecture & Routes

The application uses **React Router DOM v7** configured in [`src/main.jsx`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/src/main.jsx):

| Route | Component | Description |
|---|---|---|
| `/` | [`App.jsx`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/src/App.jsx) | Primary AI Analyst chat interface, engine runner, and session manager |
| `/chat` | [`App.jsx`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/src/App.jsx) | Alias for AI Analyst chat interface |
| `/search` | [`SearchPage.jsx`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/src/pages/SearchPage.jsx) | Shodan-style threat search engine across local PostgreSQL database |
| `/ip/:ip` | [`IpDetailPage.jsx`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/src/pages/IpDetailPage.jsx) | Deep host intelligence inspection page for a specific IP |
| `/cve/:cveId` | [`CveDetailPage.jsx`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/src/pages/CveDetailPage.jsx) | Full CVE intelligence, ATT&CK mapping, and affected local assets |
| `*` | [`NotFoundPage.jsx`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/src/pages/NotFoundPage.jsx) | Cyberpunk-themed 404 error page |

---

## Pages Deep-Dive

### 1. AI Threat Analyst Chat (`/` & `/chat`)

Located in [`src/App.jsx`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/src/App.jsx):
- **Chat History & Sidebar:** Displays previous investigations stored in PostgreSQL, with ability to create new chats, switch threads, or delete sessions.
- **Real-Time Token Streaming:** Renders assistant reasoning and final answers token-by-token with syntax-highlighted code blocks, tables, and clickable entity links.
- **HITL Tool Approval Card:** Renders when LangGraph hits an `interrupt(...)`. Allows the user to inspect the tool name, target parameters, and click **Accept** or **Decline**.
- **Engine Progress Tracker:**
  - Dynamic nodes showing pipeline stages: `Query Generation`, `IP Discovery`, `Parallel Scanning`, `CVE Extraction`, `NVD + AI Enrichment`, and `Executive Summary`.
  - Live timer, status badges (`running`, `paused`, `done`, `error`), and real-time execution log messages.
  - Interactive **Pause**, **Resume**, and **Stop** buttons synchronized with backend threads.

### 2. Threat Search Engine (`/search`)

Located in [`src/pages/SearchPage.jsx`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/src/pages/SearchPage.jsx):
- **43 Shodan-Style Filters:** Built-in filter catalog panel categorized into:
  - `General & Network`: `ip`, `net`, `port`, `asn`, `org`, `isp`, `hostname`, `has_ipv6`, `all`
  - `Geographic`: `country`, `city`, `state`, `region`
  - `Software & Device`: `product`, `version`, `os`, `cpe`, `tag`, `hash`
  - `Vulnerability & Security`: `vuln`, `has_vuln`, `has_ssl`, `has_screenshot`
  - `HTTP & Web-Server`: `http.component`, `http.component_category`, `http.title`, `http.status`, `http.waf`
  - `SSL/TLS & Certificate`: `ssl`, `ssl.version`, `ssl.cert.subject.cn`, `ssl.cert.issuer.cn`, `ssl.ja3s`
  - `SSH`: `ssh.fingerprint`
- **Interactive Quick Presets:** One-click chips for common searches (`port:22`, `port:80`, `port:443`, `has_vuln:true`, `has_ssl:true`, `product:openssh`).
- **Dynamic Facets Sidebar:** Instant aggregations for Top Countries, Top Open Ports, and Top Organizations.
- **Search Result Cards:** Clickable host cards showing IP, location, organization, OS, ASN, open port chips with service names, CVE counts, and pagination controls.

### 3. Host Intelligence Page (`/ip/:ip`)

Located in [`src/pages/IpDetailPage.jsx`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/src/pages/IpDetailPage.jsx):
- **Hero Overview Card:** Host IP with copy button, PTR hostnames/domains, source presence badges (Shodan / Nmap), scan count, total CVEs, physical location, GeoIP coordinates (`lat, long`, postal code, region), organization, ISP, ASN, OS, and Shodan tags.
- **Section Switcher Tabs:** Synchronized with URL query params (`?tab=all|shodan|nmap|vulns|timeline`).
- **Shodan Intelligence Section:**
  - Last Seen date, Scraped At date, link to Shodan Host History.
  - Security Contact & Responsible Disclosure card (`security.txt`).
  - Detected Web Technologies categorized badges (web servers, frameworks, programming languages).
  - Open ports & services: port number, protocol, service, version, HTTP title, observation timestamp, raw banner viewer with copy button, and associated CVE chips.
- **Nmap Live Scanner Section:**
  - Host status (UP/DOWN with response reason) and scan duration.
  - Execution command line viewer with copy button.
  - System Last Boot, uptime hours/seconds, and TCP sequence predictability difficulty & class.
  - OS Detection Matches with accuracy percentage bars, vendor, family, gen, and CPEs.
  - Traceroute Network Hops table (TTL, RTT in ms, IP, and Hostname).
  - **Firewall & Filtering Analysis (Phase 6 ACK Scan):** Posture badge (`Likely Firewalled` vs `Unfiltered`), filtered ports count, and port-by-port ACK probe response breakdown.
  - **DNS Reconnaissance:** Reverse DNS (PTR), recursion status, zone transfer test result, and brute-forced subdomains with IPs.
  - **SSH Protocol & Key Intelligence:** Table of SSH host keys (type, bits, fingerprint), allowed authentication methods, and supported SSH2 ciphers/KEX/MAC algorithms.
  - **SMB & Active Directory Discovery:** Exact OS build, computer name, domain name, forest, workgroup, and target system time.
  - **Layer-3/4 IP Protocol Scan:** List of supported protocols (ICMP, IGMP, GRE, ESP, AH).
  - **Network Whois Record:** Registrant and ASN network allocation record viewer.
  - **Port Probing & NSE Scripts:**
    - Service confidence rating (`Match Confidence: X/10`) and state reason.
    - **SSL/TLS Certificate Inspection Card:** Subject CN, Issuer, validity range (with EXPIRED indicator), public key algorithm/bits, SAN domains, and SHA-1 fingerprint.
    - **HTTP Defensive Security Headers Card:** Verified headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) and highlighted missing recommended headers.
    - Associated CVE chips with CVSS scores and vector tooltips.
    - Collapsible NSE script output boxes with copy buttons.
- **Aggregated Vulnerabilities Tab:** Filterable by severity (Critical, High, Medium, Low) showing CVE ID, CVSS score badge, summary text, discovery source tags (`shodan`, `nmap`), affected port tags, and full CVSS vector strings.
- **Scan Timeline Tab:** Historical snapshot cards showing each scan date, engine source, and a port table with individual observation timestamps.

### 4. Vulnerability Intelligence Page (`/cve/:cveId`)

Located in [`src/pages/CveDetailPage.jsx`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/src/pages/CveDetailPage.jsx):
- **CVE Header Card:** CVE ID, executive summary title, severity badge & base score, NIST description, CVSS metrics grid (version, attack vector, complexity, privileges, user interaction, scope, confidentiality, integrity, availability, published date, modified date, and NVD sync timestamp), and complete CVSS vector string with copy button.
- **Affected Local Assets & Scanned Hosts Card:**
  - Table showing **which of your local scanned hosts in the database have this vulnerability**.
  - Displays Host IP (clickable link to `/ip/:ip`), vulnerable port/protocol, discovery source (`nmap` / `shodan`), and direct action button *"View Host Intelligence →"*.
  - Displays a clean green reassurance badge when no local assets are affected.
- **Weakness Classification (CWE):** CWE ID with direct link to official MITRE definition and CWE title.
- **Exploitation & Threat Intelligence:** Active in-the-wild exploitation status (CISA KEV), public exploit/PoC availability badge, analysis date, and known exploit references/sources (Exploit-DB, GitHub).
- **MITRE ATT&CK Matrix Mapping:** Cards displaying adversary tactic pills, technique pills with direct links to `attack.mitre.org`, and technical adversary justifications.
- **Technical Vulnerability Walkthrough:** Numbered step-by-step breakdown from preconditions to payload delivery and security impact.
- **Actionable Mitigations:** Verified remediation checklist.
- **Detection & Threat Hunting Recommendations:** Actionable hunting queries, Snort/Suricata rules, and SIEM guidance.
- **Affected Software & Products:** Filterable table listing vendor, product name, affected version ranges, and platform configurations from NIST CPE.
- **Advisory & Reference Sources:** Official advisory URLs and tagged references.
- **Raw Technical Payload Viewer:** Collapsible JSON viewer displaying the complete underlying NVD and AI response payloads.

---

## Design System & Aesthetics

- **Color Palette:**
  - Background: Deep Void (`#0a0a0f`, `#0c0c14`)
  - Primary Accent: Neon Violet / Indigo (`#6c63ff`, `#a5b4fc`)
  - Scanner Engine Accent: Electric Cyan (`#22d3ee`, `#06b6d4`)
  - Shodan Engine Accent: Solar Amber (`#f97316`, `#fb923c`)
  - Severity High/Critical: Crimson Red (`#ef4444`, `#f87171`)
  - Success / Safe: Emerald Green (`#10b981`, `#86efac`)
- **Typography:** Inter for user interfaces, JetBrains Mono / Fira Code for technical vectors, IPs, code blocks, and hashes.
- **Glassmorphism:** Subtle semi-transparent card panels with soft radial glows, frosted glass blur (`backdrop-filter: blur(20px)`), and thin border highlights.

---

## Technology Stack

- **Framework:** React 19.2
- **Bundler:** Vite 8.3
- **Routing:** React Router DOM 7.18
- **Icons:** Lucide React 1.51
- **Markdown:** React Markdown 10.1 + Remark GFM 4.0
- **Linter:** Oxlint 1.81
- **CSS:** Vanilla CSS with scoped modular classes ([`SearchPage.css`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/src/SearchPage.css), [`App.css`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/src/App.css), [`index.css`](file:///c:/Users/jassi/OneDrive/Documents/CTI_V2/Frontend/Chatbot/src/index.css))

---

## Getting Started

### Prerequisites

- **Node.js:** `>= 18.0.0`
- **npm:** `>= 9.0.0`
- **Backend API:** The FastAPI backend server should be running at `http://localhost:8000`.

### Installation

Navigate to the frontend directory and install dependencies:

```bash
cd Frontend/Chatbot
npm install
```

### Development Server

Start the local Vite development server with Hot Module Replacement (HMR):

```bash
npm run dev
```

Open your browser at `http://localhost:5173`.

### Production Build

Compile and minify the application for production:

```bash
npm run build
```

To preview the production build locally:

```bash
npm run preview
```

To run the linter:

```bash
npm run lint
```

---

## Backend API Integration

The frontend communicates with the FastAPI backend at `http://localhost:8000/api`:

- **Chat & LangGraph Agent:** `POST /api/chats/{thread_id}/message` (SSE Stream), `POST /api/chats/{thread_id}/approve`
- **Engine Streaming:** `GET /api/engine/{engine_thread_id}/stream` (SSE Stream), `POST /api/engine/{engine_thread_id}/stop`, `POST /api/engine/{engine_thread_id}/resume`
- **Threat Search:** `GET /api/search?q={query}&page={page}&page_size=20`
- **Host Intelligence:** `GET /api/search/ip/{ip_address}`
- **CVE Intelligence:** `GET /api/search/cve/{cve_id}`
- **Platform Stats:** `GET /api/stats`
