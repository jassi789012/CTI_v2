import sys
sys.path.insert(0, "Backend/cve_maper")
import cve_mapper as m
for cwe in ["CWE-287","CWE-79","CWE-20","CWE-798"]:
    d = m.fetch_cwe_details(cwe)
    if not d:
        print(cwe, "NO DATA"); continue
    print("---", cwe, d["cwe_name"])
    print("   mitigations:", len(d["cwe_mitigations"]), "| detections:", len(d["cwe_detections"]), "| capecs:", d["capec_ids"][:6])
    maps = m.fetch_attack_mappings(cwe, d["capec_ids"])
    for x in maps[:3]:
        print("    ->", x["tactic_id"], x["tactic_name"], x["technique_id"], x["technique_name"])
