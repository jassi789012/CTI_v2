# CTI_V2 — Cyber Threat Intelligence Platform

A modular cyber threat intelligence (CTI) data collection platform that scrapes, parses, and stores reconnaissance data from multiple sources (Shodan, Nmap, etc.) into a PostgreSQL database for analysis.

---

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Install Python Dependencies](#2-install-python-dependencies)
  - [3. Install Playwright Browsers](#3-install-playwright-browsers)
  - [4. Install & Configure PostgreSQL](#4-install--configure-postgresql)
  - [5. Configure Environment Variables](#5-configure-environment-variables)
- [Usage](#usage)
- [Database Schema](#database-schema)
- [Future Roadmap](#future-roadmap)

---

## Overview

CTI_V2 automates the process of gathering threat intelligence data:

1. **IP Discovery** — Scrapes Shodan search results to discover IPs matching custom queries (e.g., `apache country:DE`, `has_vuln:true country:JP`).
2. **Host Reconnaissance** — Visits each discovered IP's Shodan host page to extract detailed info: open ports, services, banners, CVEs, technologies, geolocation, etc.
3. **Structured Storage** — Parses the raw HTML into structured data and stores it in PostgreSQL across normalized tables for efficient querying.

The platform is designed to be **source-agnostic** — while Shodan is the first integration, the database schema supports data from Nmap, Censys, and other tools.

---

## Project Structure

```
CTI_V2/
├── .env                          # Environment variables (credentials, DB config)
├── .gitignore                    # Ignores .env, .venv
├── pyproject.toml                # Project config & dependencies (managed by uv)
├── uv.lock                       # Locked dependency versions
│
├── Backend/
│   ├── db_manager.py             # PostgreSQL database manager (schema, CRUD)
│   │
│   ├── def_Shodan/               # Shodan scraping module
│   │   ├── get_ip.py             # Scrapes IPs from Shodan search results
│   │   ├── get_ip_info.py        # Scrapes detailed host info for each IP
│   │   ├── try.py                # Example runner script
│   │   └── shodan_cookies.json   # Cached Shodan session cookies (auto-generated)
│   │
│   ├── def_nmap/                 # Nmap integration (planned)
│   ├── cve_maper/                # CVE mapping module (planned)
│   └── query_gen/                # Query generation module (planned)
│
└── src/                          # Future: frontend / API layer
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                       try.py (Runner)                    │
│         Defines queries → calls get_ip → get_ip_info     │
└──────────┬──────────────────────────────┬────────────────┘
           │                              │
           ▼                              ▼
┌─────────────────────┐      ┌─────────────────────────────┐
│     get_ip.py       │      │      get_ip_info.py         │
│                     │      │                             │
│ • Logs into Shodan  │      │ • Visits each IP's host page│
│   via Playwright    │      │ • Parses HTML → structured  │
│ • Runs search       │      │   JSON (ports, CVEs, tech)  │
│   queries           │      │ • Saves to PostgreSQL via   │
│ • Extracts IPs from │      │   DBManager                 │
│   search results    │      │                             │
└─────────────────────┘      └──────────────┬──────────────┘
                                            │
                                            ▼
                             ┌──────────────────────────────┐
                             │       db_manager.py          │
                             │                              │
                             │ • Manages PostgreSQL conn    │
                             │ • Creates tables on startup  │
                             │ • Inserts structured data    │
                             │   across 5 normalized tables │
                             └──────────────┬───────────────┘
                                            │
                                            ▼
                             ┌──────────────────────────────┐
                             │     PostgreSQL (cti_db)      │
                             │                              │
                             │  hosts · scans · ports       │
                             │  vulnerabilities · technologies│
                             └──────────────────────────────┘
```

---

## Prerequisites

| Tool         | Version  | Purpose                          |
|--------------|----------|----------------------------------|
| **Python**   | ≥ 3.14   | Runtime                          |
| **uv**       | Latest   | Python package manager           |
| **PostgreSQL**| ≥ 16    | Database                         |
| **Playwright**| ≥ 1.63  | Browser automation (Shodan login)|

---

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/jassi789012/CTI_v2.git
cd CTI_v2
```

### 2. Install Python Dependencies

Using [uv](https://docs.astral.sh/uv/):

```bash
uv sync
```

This installs all dependencies from `pyproject.toml`:
- `bs4` — HTML parsing
- `playwright` — Browser automation for Shodan scraping
- `psycopg2-binary` — PostgreSQL driver
- `python-dotenv` — Load `.env` config

### 3. Install Playwright Browsers

Playwright needs a Chromium browser to automate Shodan login and scraping:

```bash
playwright install chromium
```

### 4. Install & Configure PostgreSQL

#### Install PostgreSQL (Windows)

1. Download the installer from [postgresql.org/download/windows](https://www.postgresql.org/download/windows/)
2. Run the installer — use default settings
3. Set a password for the `postgres` user (remember this!)
4. **Skip** Stack Builder when prompted (not needed)

> **Note:** PostgreSQL installs as a Windows service with `StartType: Automatic`.  
> It will start automatically on every system restart — no manual startup needed.

#### Create the Database

Open a terminal and run:

```bash
psql -U postgres
```

Enter your password when prompted, then:

```sql
CREATE DATABASE cti_db;
\q
```

> **Tip:** You can also create the database via pgAdmin (the GUI tool installed with PostgreSQL), but it's not required. Your scripts connect directly to the PostgreSQL server, not to pgAdmin.

### 5. Configure Environment Variables

Create a `.env` file in the project root (`CTI_V2/.env`):

```env
# Shodan Credentials
shodan_user=your_shodan_username
shodan_password=your_shodan_password

# PostgreSQL Database
PG_HOST=localhost
PG_PORT=5432
PG_DATABASE=cti_db
PG_USER=postgres
PG_PASSWORD=your_postgres_password
```

> **Important:** The `.env` file is listed in `.gitignore` and will **not** be pushed to Git.

---

## Usage

### Quick Start

Navigate to the Shodan module directory and run:

```bash
cd Backend/def_Shodan
python try.py
```

This will:
1. Log into Shodan using your credentials
2. Search for IPs matching the queries defined in `try.py`
3. Visit each discovered IP's host page
4. Parse the HTML and extract structured data
5. Store everything in PostgreSQL (`cti_db`)

### Customize Queries

Edit [`try.py`](Backend/def_Shodan/try.py) to change the Shodan search queries:

```python
queries = [
    "apache country:DE",
    "nginx port:443 country:US",
    "product:OpenSSH port:22",
    "has_vuln:true country:JP",
    # Add your own queries here
]
```

### Verify Database (Optional)

Run the self-test to confirm PostgreSQL is connected and tables are working:

```bash
python Backend/db_manager.py
```

This creates the tables, inserts test data, verifies reads, cleans up, and prints `[OK] All tests passed!`.

---

## Database Schema

All data is stored in **5 normalized tables** in the `cti_db` PostgreSQL database:

### Entity Relationship

```
hosts (1) ──→ (N) scans (1) ──→ (N) ports (1) ──→ (N) vulnerabilities
                    │
                    └──→ (N) technologies
```

### Tables

#### `hosts` — Central IP Registry
| Column       | Type        | Description                    |
|-------------|-------------|--------------------------------|
| id          | SERIAL PK   | Auto-increment ID              |
| ip          | INET UNIQUE | IP address                     |
| country     | TEXT        | Country code                   |
| city        | TEXT        | City name                      |
| organization| TEXT        | Organization name              |
| isp         | TEXT        | Internet Service Provider      |
| asn         | TEXT        | Autonomous System Number       |
| os          | TEXT        | Detected operating system      |
| tags        | JSONB       | Shodan tags (array)            |
| first_seen  | TIMESTAMPTZ | First time this IP was scanned |
| last_updated| TIMESTAMPTZ | Last time this IP was updated  |

#### `scans` — Scan Snapshots (Timeline)
| Column          | Type        | Description                         |
|----------------|-------------|-------------------------------------|
| id             | SERIAL PK   | Auto-increment ID                   |
| host_id        | INT FK      | References `hosts.id`               |
| source         | TEXT        | Data source (e.g., `shodan`)         |
| source_last_seen| DATE       | When the source last saw this host  |
| scraped_at     | TIMESTAMPTZ | When our scraper collected this data|
| raw_data       | JSONB       | Full raw parsed data (JSON)         |
| metadata       | JSONB       | Additional metadata                 |

#### `ports` — Discovered Ports & Services
| Column      | Type      | Description                    |
|------------|-----------|--------------------------------|
| id         | SERIAL PK | Auto-increment ID              |
| scan_id    | INT FK    | References `scans.id`          |
| port_number| INT       | Port number (e.g., 80, 443)    |
| protocol   | TEXT      | Protocol (tcp/udp)             |
| state      | TEXT      | Port state (open/closed)       |
| service    | TEXT      | Service name (e.g., nginx)     |
| version    | TEXT      | Service version                |
| http_title | TEXT      | HTTP page title (if web)       |
| banner     | TEXT      | Service banner                 |
| timestamp  | DATE      | When port was last seen        |
| extra      | JSONB     | Additional port data           |

#### `vulnerabilities` — CVEs Per Port
| Column      | Type      | Description                    |
|------------|-----------|--------------------------------|
| id         | SERIAL PK | Auto-increment ID              |
| port_id    | INT FK    | References `ports.id`          |
| cve_id     | TEXT      | CVE identifier (e.g., CVE-2021-44228) |
| cvss       | FLOAT     | CVSS score (0.0–10.0)         |
| cvss_vector| TEXT      | CVSS vector string             |
| summary    | TEXT      | Vulnerability description      |

#### `technologies` — Detected Web Technologies
| Column   | Type      | Description                    |
|---------|-----------|--------------------------------|
| id      | SERIAL PK | Auto-increment ID              |
| scan_id | INT FK    | References `scans.id`          |
| category| TEXT      | Technology category            |
| name    | TEXT      | Technology name (e.g., jQuery) |
| version | TEXT      | Detected version               |

---

## Future Roadmap

- [ ] **Nmap Integration** — Scan IPs with Nmap and store results in the same database (`def_nmap/`)
- [ ] **CVE Mapper** — Enrich vulnerability data with NVD/MITRE details (`cve_maper/`)
- [ ] **Query Generator** — AI-powered Shodan/Nmap query generation (`query_gen/`)
- [ ] **AI Agent** — Connect an LLM agent to the database for natural language threat analysis
- [ ] **Frontend Dashboard** — Web UI for visualizing collected intelligence (`src/`)
- [ ] **API Layer** — REST API for programmatic access to CTI data

---

## Author

**jassi789012** — [jassi789012singh@gmail.com](mailto:jassi789012singh@gmail.com)

## License

This project is for educational and authorized security research purposes only.