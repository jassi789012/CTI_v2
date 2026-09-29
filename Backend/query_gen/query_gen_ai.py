"""
Shodan Query Generator — LangChain + Groq powered query expansion
==================================================================
Takes a natural language query and uses ChatGroq (LangChain) to generate
multiple Shodan search queries that capture the same intent.

Why: Free Shodan accounts show max 2 pages per query.
By generating multiple equivalent queries with different filters,
we can collect more IPs without changing the search intent.

Stack:
    - LangChain:  Prompt management + LLM chain
    - ChatGroq:   Fast LLM inference (llama-3.3-70b-versatile)
    - Pydantic:   Structured output parsing

Usage:
    from query_gen_ai import generate_queries, generate_queries_gen

    # Synchronous
    queries = generate_queries("find apache servers in India")

    # Generator (yields progress)
    for progress in generate_queries_gen("find apache servers in India"):
        print(progress["query_generator"])
    queries = progress["queries"]
"""

import sys
from pathlib import Path

from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq
from pydantic import BaseModel, Field

# ─── Load .env from project root ─────────────────────────────────────────────
env_path = Path(__file__).resolve().parents[2] / ".env"
load_dotenv(env_path)


# ═════════════════════════════════════════════════════════════════════════════
# Configuration
# ═════════════════════════════════════════════════════════════════════════════

GROQ_MODEL = "openai/gpt-oss-20b"
DEFAULT_QUERY_COUNT = 10

# Filters restricted to paid Shodan accounts
RESTRICTED_FILTERS = ["vuln:", "has_vuln:", "tag:"]


# ═════════════════════════════════════════════════════════════════════════════
# Pydantic Output Schema
# ═════════════════════════════════════════════════════════════════════════════

class ShodanQueries(BaseModel):
    """Structured output: a list of Shodan search queries."""
    queries: list[str] = Field(
        description="List of valid Shodan search query strings"
    )


# ═════════════════════════════════════════════════════════════════════════════
# System Prompt — Shodan Query Syntax Reference
# ═════════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are a Shodan search query expert. Your job is to take a user's 
natural language description and generate multiple Shodan search queries that all 
match the SAME intent but use different filter combinations to get different result sets.

## Shodan Query Syntax Reference (FREE ACCOUNT ONLY)

These filters work on Shodan free accounts:
- port:NUMBER          (e.g. port:80, port:443, port:22)
- country:CODE         (2-letter ISO code, e.g. country:US, country:IN)
- city:"NAME"          (e.g. city:"Mumbai")
- org:"NAME"           (e.g. org:"Google LLC")
- hostname:DOMAIN      (e.g. hostname:example.com)
- product:"NAME"       (e.g. product:"Apache httpd")
- version:"X.Y"        (e.g. version:"2.4.49")
- os:"NAME"            (e.g. os:"Windows 10")
- net:CIDR             (e.g. net:8.8.8.0/24)
- asn:ASNUMBER         (e.g. asn:AS15169)
- ssl:TEXT              (search SSL certificate fields)
- ssl.cert.subject.CN:NAME  (SSL certificate common name)
- http.title:"TEXT"    (HTML page title)
- http.html:"TEXT"     (HTML body content)
- http.status:CODE     (HTTP status code, e.g. http.status:200)
- http.component:"NAME" (web technology, e.g. http.component:"jQuery")
- before:DD/MM/YYYY    (results before date)
- after:DD/MM/YYYY     (results after date)
- "keyword"            (plain text search in banners)

Multiple filters can be combined: product:"Apache" country:US port:80

## RESTRICTED FILTERS — DO NOT USE THESE

The following filters require a PAID Shodan subscription and MUST NOT appear 
in any query you generate:
- vuln:          (e.g. vuln:CVE-2021-44228) — BLOCKED on free accounts
- has_vuln:      (e.g. has_vuln:true) — BLOCKED on free accounts
- tag:           (e.g. tag:ics, tag:honeypot) — BLOCKED on free accounts

NEVER use vuln:, has_vuln:, or tag: in any query. Use alternative filters instead.

## Your Rules

1. ALL generated queries MUST match the user's original intent — do NOT change what 
   they're searching for.
2. Vary the queries by using different but equivalent filters, different port 
   combinations, different geographic breakdowns, version variations, etc.
3. Each query should return DIFFERENT results from the others (not duplicates).
4. Keep queries valid Shodan syntax.
5. NEVER use vuln:, has_vuln:, or tag: filters — they are BLOCKED on free accounts."""


# ═════════════════════════════════════════════════════════════════════════════
# Helpers
# ═════════════════════════════════════════════════════════════════════════════

def _filter_restricted(queries: list[str]) -> tuple[list[str], list[str]]:
    """
    Remove queries containing filters restricted to paid Shodan accounts.

    Returns:
        (valid_queries, removed_queries)
    """
    valid = []
    removed = []

    for q in queries:
        q_lower = q.lower()
        if any(rf.lower() in q_lower for rf in RESTRICTED_FILTERS):
            removed.append(q)
        else:
            valid.append(q)

    return valid, removed


# ═════════════════════════════════════════════════════════════════════════════
# Generator Function
# ═════════════════════════════════════════════════════════════════════════════

def generate_queries_gen(user_query: str, count: int = DEFAULT_QUERY_COUNT):
    """
    Generator that produces Shodan queries from a natural language input.

    Yields progress dicts:
        {
            "query_generator": "running" | "completed",
            "queries": [list of valid Shodan query strings],
        }

    The last yielded dict contains the final result in "queries".

    Args:
        user_query:  Natural language description of what to search.
        count:       Number of queries to generate (default 10).
    """
    if not user_query or not user_query.strip():
        yield {"query_generator": "completed", "queries": []}
        return

    yield {"query_generator": "running", "queries": []}

    # ── 1. Build the LLM with structured output ──────────────────────────
    print("[*] Initializing ChatGroq...")
    llm = ChatGroq(model=GROQ_MODEL, temperature=0.7)
    structured_llm = llm.with_structured_output(ShodanQueries)

    # ── 2. Build the prompt ──────────────────────────────────────────────
    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human",
         "Generate exactly {count} Shodan search queries for this request:\n\n"
         "\"{user_query}\"\n\n"
         "Return exactly {count} unique query strings."),
    ])

    # ── 3. Chain: prompt → LLM → Pydantic parsed output ─────────────────
    chain = prompt | structured_llm

    # ── 4. Invoke the chain ──────────────────────────────────────────────
    print("[*] Generating queries with LLM...")

    try:
        result: ShodanQueries = chain.invoke({
            "user_query": user_query,
            "count": count,
        })
    except Exception as e:
        print(f"[-] LLM call failed: {e}")
        yield {"query_generator": "completed", "queries": []}
        return

    queries = result.queries
    print(f"[*] LLM returned {len(queries)} queries")

    # ── 5. Deduplicate (preserve order) ──────────────────────────────────
    seen = set()
    unique = []
    for q in queries:
        q = q.strip()
        if q and q not in seen:
            seen.add(q)
            unique.append(q)

    # ── 6. Remove queries with restricted (paid-only) filters ────────────
    valid, removed = _filter_restricted(unique)

    if removed:
        print(f"\n[!] Removed {len(removed)} queries with restricted filters:")
        for rq in removed:
            print(f"    BLOCKED: {rq}")

    if not valid:
        print("[-] All generated queries were blocked (used paid-only filters).")
        yield {"query_generator": "completed", "queries": []}
        return

    # ── 7. Final result ──────────────────────────────────────────────────
    print(f"[+] Generated {len(valid)} valid queries")

    yield {"query_generator": "completed", "queries": valid}


# ═════════════════════════════════════════════════════════════════════════════
# Synchronous Wrapper
# ═════════════════════════════════════════════════════════════════════════════

def generate_queries(user_query: str, count: int = DEFAULT_QUERY_COUNT) -> list[str]:
    """
    Synchronous wrapper — returns list of Shodan query strings.

    Internally consumes generate_queries_gen() and returns the final result.

    Args:
        user_query:  Natural language description of what to search.
        count:       Number of queries to generate (default 10).

    Returns:
        list[str] — List of valid Shodan query strings.
    """
    progress = None
    for progress in generate_queries_gen(user_query, count):
        pass
    return progress.get("queries", []) if progress else []


# ═════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═════════════════════════════════════════════════════════════════════════════

def main():
    """Interactive CLI — enter a natural language query."""
    print("=" * 60)
    print("  SHODAN QUERY GENERATOR")
    print("=" * 60)

    query = input("\n  Describe what you want to find on Shodan:\n  > ").strip()
    if not query:
        print("[-] No query provided. Exiting.")
        sys.exit(1)

    count_input = input("  How many queries? (default 10): ").strip()
    count = int(count_input) if count_input.isdigit() else DEFAULT_QUERY_COUNT

    progress = None
    for progress in generate_queries_gen(query, count):
        status = progress["query_generator"]
        print(f"  [{status}]")

    queries = progress.get("queries", []) if progress else []

    if queries:
        print(f"\n[+] {len(queries)} queries generated:")
        for i, q in enumerate(queries, 1):
            print(f"    {i}. {q}")
        print(f"\n[+] Copy these into your scraper:")
        print(f"    {queries}")


if __name__ == "__main__":
    main()
