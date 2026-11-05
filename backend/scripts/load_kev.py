from datetime import date

import httpx

from app.database import Base, SessionLocal, engine
from app.models import Vulnerability

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def parse_date(value: str | None) -> date | None:
    return date.fromisoformat(value) if value else None


def main():
    # Creates tables if they don't exist yet
    Base.metadata.create_all(bind=engine)

    print("Downloading CISA KEV catalog...")
    resp = httpx.get(KEV_URL, timeout=60, follow_redirects=True)
    resp.raise_for_status()
    data = resp.json()

    added = updated = 0
    with SessionLocal() as db:
        for item in data["vulnerabilities"]:
            # Update the CVE if it already exists, otherwise add it
            vuln = db.get(Vulnerability, item["cveID"])
            if vuln is None:
                vuln = Vulnerability(cve_id=item["cveID"])
                db.add(vuln)
                added += 1
            else:
                updated += 1

            vuln.vendor = item.get("vendorProject")
            vuln.product = item.get("product")
            vuln.name = item.get("vulnerabilityName")
            vuln.description = item.get("shortDescription")
            vuln.required_action = item.get("requiredAction")
            vuln.in_kev = True
            vuln.kev_date_added = parse_date(item.get("dateAdded"))
            vuln.kev_due_date = parse_date(item.get("dueDate"))
            vuln.ransomware_use = item.get("knownRansomwareCampaignUse", "").lower() == "known"

        db.commit()

    print(f"KEV catalog {data.get('catalogVersion')}: {added} added, {updated} updated")


if __name__ == "__main__":
    main()