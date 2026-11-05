"""Imports an asset inventory, matches installed software to CVEs, and
optionally applies a business context file.

Usage (from the backend folder):
    python -m scripts.import_inventory <inventory.json>
    python -m scripts.import_inventory <inventory.json> --context <context.json>
"""

import json
import sys
from pathlib import Path

from pydantic import ValidationError

from app.database import Base, SessionLocal, engine
from app.inventory import ContextFile, InventoryFile, apply_context, import_inventory


def read_json(path: Path, model):
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)
    try:
        return model.model_validate(json.loads(path.read_text(encoding="utf-8-sig")))
    except (json.JSONDecodeError, ValidationError) as exc:
        print(f"{path.name} isn't in the expected format:\n{exc}")
        sys.exit(1)


def main():
    args = sys.argv[1:]
    if not args or args[0].startswith("--"):
        print(__doc__)
        sys.exit(1)

    inventory = read_json(Path(args[0]), InventoryFile)
    context = None
    if "--context" in args:
        idx = args.index("--context")
        if idx + 1 >= len(args):
            print("Add the context file path after --context")
            sys.exit(1)
        context = read_json(Path(args[idx + 1]), ContextFile)

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        s = import_inventory(db, inventory)
        print(f"Assets:    {s.assets_created} created, {s.assets_updated} updated")
        print(f"Software:  {s.software_items} items checked")
        print(f"Findings:  {s.findings_created} created on {s.assets_with_findings} assets")
        print(f"           {s.kev_findings} known exploited (KEV), {s.conditional_findings} need a configuration check")
        if s.new_cves_added:
            print(f"New CVEs not in KEV: {len(s.new_cves_added)}. Run 'python -m scripts.load_epss' to score them.")

        if context:
            c = apply_context(db, context)
            print(f"Context:   {c.assets_updated} assets updated")
            for host in c.not_found:
                print(f"           not found: {host}")


if __name__ == "__main__":
    main()
