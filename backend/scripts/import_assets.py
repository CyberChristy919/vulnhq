"""Imports applications, assets and CVEs from a JSON file.

Usage (from the backend folder):
    python -m scripts.import_assets ..\\sample-data\\demo-assets.json
"""

import json
import sys
from pathlib import Path

from pydantic import ValidationError

from app.database import Base, SessionLocal, engine
from app.importer import ImportFile, import_data


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m scripts.import_assets <path-to-json-file>")
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)

    try:
        data = ImportFile.model_validate(json.loads(path.read_text(encoding="utf-8-sig")))
    except (json.JSONDecodeError, ValidationError) as exc:
        print(f"The file isn't in the expected format:\n{exc}")
        sys.exit(1)

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        summary = import_data(db, data)

    print(f"Applications: {summary.applications_created} created, {summary.applications_updated} updated")
    print(f"Assets:       {summary.assets_created} created, {summary.assets_updated} updated")
    print(f"Findings:     {summary.findings_created} created")
    if summary.new_cves_added:
        print(f"New CVEs (not in KEV): {', '.join(summary.new_cves_added)}")
        print("Run 'python -m scripts.load_epss' to add EPSS scores for them.")
    for err in summary.errors:
        print(f"Skipped: {err}")


if __name__ == "__main__":
    main()
