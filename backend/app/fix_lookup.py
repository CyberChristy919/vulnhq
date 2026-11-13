"""Each CVE's fix type, from CISA KEV, OSV.dev and NVD. Feeds patch_plan(items, fix_types)."""

from app.fix_type import fix_type, fixed_version
from app.osv import OsvUnavailable


def nvd_fixed_versions(rules, nvd_cache):
    """CVE ID -> first fixed version, from vuln_rules.json and the NVD cache."""
    found = {}
    # Vetted rules: ranges from NVD
    for rule in rules:
        # "through 2.4.49" gives None; "before 2.15.0" gives "2.15.0"
        version = fixed_version(rule["max_version"], rule["max_inclusive"])
        if version:
            # setdefault keeps the first branch's fix and ignores later ones
            found.setdefault(rule["cve"], version)
    # Live NVD lookups: "product|version" -> list of saved matches
    for matches in nvd_cache.get("cves", {}).values():
        for match in matches:
            # Older cache entries don't have fixed_version, so .get() gives None
            if match.get("fixed_version"):
                found.setdefault(match["cve_id"], match["fixed_version"])
    return found


def lookup_fix_types(cve_ids, required_actions, nvd_fixed, osv_record):
    """CVE ID -> fix type. OSV being down never stops the page from loading."""
    types = {}
    osv_up = True
    # dict.fromkeys drops duplicates and keeps the order
    for cve_id in dict.fromkeys(cve_ids):
        record = None
        if osv_up:
            try:
                record = osv_record(cve_id)
            except OsvUnavailable:
                # OSV is down: skip it for this CVE and every one after
                osv_up = False
        # KEV first, then OSV, then NVD; False because these are exclusive ends
        types[cve_id] = fix_type(required_actions.get(cve_id), record, nvd_fixed.get(cve_id), False)
    return types
 