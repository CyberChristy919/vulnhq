"""Imports a CrowdStrike Falcon Spotlight export into VulnHQ.

Usage (from the backend folder):
    python -m scripts.import_spotlight ..\\sample-data\\spotlight-demo.json
"""

import json
import sys
from pathlib import Path

from app.database import Base, SessionLocal, engine
from app.importer import import_data
from app.spotlight import spotlight_to_import


def main():
    # 1. If there isn't exactly one file argument, print a usage message and exit with 1
    if len(sys.argv) != 2:
        print("Usage: python -m scripts.import_spotlight <path-to-json-file>")
        sys.exit(1)

    # 2. Make a Path and check the file exists
    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)

    # 3. Read the file as JSON (encoding="utf-8-sig") and convert it with spotlight_to_import.
    try:
        data, skipped = spotlight_to_import(json.loads(path.read_text(encoding="utf-8-sig")))
    except json.JSONDecodeError as exc:
        print(f"The file isn't valid JSON:\n{exc}")
        sys.exit(1)

    # 4, create tables, open a session, import
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        summary = import_data(db, data)

    # 5. Print how many assets were created and updated, and how many findings were created
    print(f"Assets:       {summary.assets_created} created, {summary.assets_updated} updated")
    print(f"Findings:     {summary.findings_created} created")

    # 6. Print each skipped record
    for s in skipped:
        print(f"Skipped: {s}")


if __name__ == "__main__":
    main()