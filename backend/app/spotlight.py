"""Turns a CrowdStrike Falcon Spotlight export into VulnHQ's import format."""

from app.importer import AssetImport, ImportFile

# 1. A dict that maps criticality words (lowercase) to numbers
CRIT = {"critical": 5, "high": 4, "medium": 3, "low": 2}

def spotlight_to_import(data):
    # 2. Get the list of records: data["resources"] if data is a dict, otherwise data itself
    records = data.get("resources", []) if isinstance(data, dict) else data
    assets = {}   # hostname -> AssetImport, keeps the order hosts are first seen
    skipped = []

    for r in records:
        # 3. Skip anything whose status isn't "open" or "reopen" (no message)
        if r.get("status") not in ("open", "reopen"):
            continue
        # 4. Read the CVE ID and the hostname safely. Either part may be missing.
        #    If either is missing, add a message with r's "id" to skipped and move on.
        cve = (r.get("cve") or {}).get("id")
        info = r.get("host_info") or {}
        host = info.get("hostname")
        if not cve or not host:
            skipped.append(f"{r.get('id')}: missing CVE ID or hostname")
            continue
        # 5. First time seeing this hostname: create its AssetImport with
        #    hostname, ip_address, internet_facing and criticality
        if host not in assets:
            assets[host] = AssetImport(
                hostname=host,
                ip_address=info.get("local_ip"),
                internet_facing={"Yes": True, "No": False}.get(info.get("internet_exposure")),
                criticality=CRIT.get((info.get("asset_criticality") or "").lower()),
            )
        # 6. Add the CVE to that host's cves list, unless it's already there
        if cve not in assets[host].cves:
            assets[host].cves.append(cve)
    return ImportFile(assets=list(assets.values())), skipped