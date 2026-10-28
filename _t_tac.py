import sys
sys.path.insert(0, "Backend/cve_maper")
import cve_mapper as m
d = m._attack_stix.get()
for o in d.get("objects", []):
    if o.get("type") != "x-mitre-tactic":
        continue
    ext = [r.get("external_id") for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"]
    print(ext, "| name=", repr(o.get("name")), "| shortname=", repr(o.get("x_mitre_shortname")), "| revoked=", o.get("revoked"), o.get("x_mitre_deprecated"))
