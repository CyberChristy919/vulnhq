import httpx
from sqlalchemy import select

from app.database import SessionLocal
from app.models import Vulnerability

EPSS_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100  # The EPSS API accepts up to 100 CVEs per request


def fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    # Returns {cve_id: epss_score} for one batch of CVEs
    resp = httpx.get(EPSS_URL, params={"cve": ",".join(cve_ids)}, timeout=60)
    resp.raise_for_status()
    return {row["cve"]: float(row["epss"]) for row in resp.json()["data"]}


def main():
    with SessionLocal() as db:
        vulns = db.scalars(select(Vulnerability)).all()
        print(f"Fetching EPSS scores for {len(vulns)} CVEs...")

        scores: dict[str, float] = {}
        for i in range(0, len(vulns), BATCH_SIZE):
            batch = [v.cve_id for v in vulns[i : i + BATCH_SIZE]]
            scores.update(fetch_epss(batch))

        updated = 0
        for vuln in vulns:
            if vuln.cve_id in scores:
                vuln.epss_score = scores[vuln.cve_id]
                updated += 1

        db.commit()

    print(f"EPSS scores updated for {updated} of {len(vulns)} CVEs")


if __name__ == "__main__":
    main()
