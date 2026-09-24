from get_ip import get_ip_query_ip
from get_ip_info import get_ip_info_json

# 1. Scrape IPs matching query
queries = [
    "apache country:DE",
    "nginx port:443 country:US",
    "product:OpenSSH port:22",
    "product:MySQL port:3306",
    "product:MongoDB port:27017",
    'http.title:"login" country:GB',
    'ssl.cert.subject.cn:"example.com"',
    "has_screenshot:true port:80",
    "has_vuln:true country:JP",
    'os:"Windows Server" port:3389'
]
ips = get_ip_query_ip(queries)

# ips = ['47.115.174.249']

# 2. Extract full host details for each discovered IP
host_details = get_ip_info_json(ips, output_file="results.json")
