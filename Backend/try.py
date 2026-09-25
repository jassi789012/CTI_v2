import sys
import asyncio
from pathlib import Path

# Add module directories to path
BACKEND_DIR = Path(__file__).parent
sys.path.insert(0, str(BACKEND_DIR / "def_Shodan"))
sys.path.insert(0, str(BACKEND_DIR / "def_nmap"))

from get_ip import get_ip_query_ip
from get_ip_info import get_ip_info_json
from nmap_scanner import nmap_scan_ips

# 1. Scrape IPs matching queries
queries = [
    "apache country:DE",
    "nginx port:443 country:US",
    # "product:OpenSSH port:22",
    # "product:MySQL port:3306",
    # "product:MongoDB port:27017",
    # 'http.title:"login" country:GB',
    # 'ssl.cert.subject.cn:"example.com"',
    # "has_screenshot:true port:80",
    # "has_vuln:true country:JP",
    # 'os:"Windows Server" port:3389',
]
ips = get_ip_query_ip(queries)

# ips = ['47.115.174.249']


# 2. Run Shodan scraping + Nmap scanning in parallel
async def main():
    shodan_task = asyncio.to_thread(get_ip_info_json, ips)
    nmap_task = asyncio.to_thread(nmap_scan_ips, ips)

    shodan_results, nmap_results = await asyncio.gather(shodan_task, nmap_task)


asyncio.run(main())
