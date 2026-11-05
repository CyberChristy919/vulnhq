import csv
import gzip
import sys
from pathlib import Path

import httpx
from sqlalchemy import select

from app.database import SessionLocal
from app.models import Vulnerability

# Full daily EPSS file (all CVEs) published by the EPSS team
EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def load_scores() -> dict[str, float]:
    # Optional: pass a downloaded file path, e.g. python -m scripts.load_epss epss.csv.gz
    if len(sys.argv) > 1:
        print(f"Reading EPSS file {sys.argv[1]}...")
        raw = Path(sys.argv[1]).read_bytes()
    else:
        print("Downloading daily EPSS file...")
        resp = httpx.get(EPSS_CSV_URL, timeout=120, follow_redirects=True)
        resp.raise_for_status()
        raw = resp.content

    text = gzip.decompress(raw).decode("utf-8")
    # First line is a "#model_version..." comment, skip it
    rows = csv.DictReader(line for line in text.splitlines() if not line.startswith("#"))
    return {row["cve"]: float(row["epss"]) for row in rows}


def main():
    scores = load_scores()
    print(f"Loaded {len(scores)} EPSS scores")

    with SessionLocal() as db:
        vulns = db.scalars(select(Vulnerability)).all()
        updated = 0
        for vuln in vulns:
            if vuln.cve_id in scores:
                vuln.epss_score = scores[vuln.cve_id]
                updated += 1
        db.commit()

    print(f"EPSS scores updated for {updated} of {len(vulns)} CVEs")


if __name__ == "__main__":
    main()