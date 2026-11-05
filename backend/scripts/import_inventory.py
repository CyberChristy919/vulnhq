"""Imports an asset inventory, matches installed software to CVEs, and
optionally applies a business context file.

Usage (from the backend folder):
    python -m scripts.import_inventory <inventory.json>
    python -m scripts.import_inventory <inventory.json> --context <context.json>

Options:
    --no-nvd          Use only the vetted rules (no internet needed)
    --min-cvss 7.0    Skip NVD matches below this CVSS unless the CVE is in KEV
"""

import json
import sys
from pathlib import Path

from pydantic import ValidationError

from app.database import Base, SessionLocal, engine
from app.inventory import ContextFile, InventoryFile, Options, apply_context, import_inventory


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

    options = Options(use_nvd="--no-nvd" not in args)
    if "--min-cvss" in args:
        options.min_cvss = float(args[args.index("--min-cvss") + 1])

    Base.metadata.create_all(bind=engine)
    if options.use_nvd:
        print("Checking software against the vetted rules, then NVD for anything else...")
    with SessionLocal() as db:
        s = import_inventory(db, inventory, options)
        print(f"Assets:    {s.assets_created} created, {s.assets_updated} updated")
        print(f"Software:  {s.software_items} items checked")
        print(f"Findings:  {s.findings_created} created on {s.assets_with_findings} assets")
        print(f"           {s.kev_findings} known exploited (KEV), {s.conditional_findings} need a configuration check")
        if options.use_nvd:
            print(f"           {s.nvd_findings} from NVD lookups (CVSS {options.min_cvss}+ or KEV), {s.nvd_lookups} NVD requests")
        if s.not_checked:
            # Group by reason so the list stays short
            by_reason: dict[str, list[str]] = {}
            for line in s.not_checked:
                label, reason = line.split(": ", 1)
                by_reason.setdefault(reason, []).append(label)
            print(f"\nNot checked ({len(s.not_checked)} software versions):")
            for reason, labels in by_reason.items():
                print(f"  - {', '.join(labels)}")
                print(f"    Why: {reason}")
        if s.needs_review:
            print(f"\nNeeds review ({len(s.needs_review)}), no match but the product is in CISA KEV:")
            for line in s.needs_review:
                print(f"  - {line.split(': no version match, but ')[0]}: "
                      f"{line.split('but ')[1].split(' known')[0]} KEV CVEs")
        if s.new_cves_added:
            print()
            print(f"New CVEs not in KEV: {len(s.new_cves_added)}. Run 'python -m scripts.load_epss' to score them.")

        if context:
            c = apply_context(db, context)
            print(f"Context:   {c.assets_updated} assets updated")
            for host in c.not_found:
                print(f"           not found: {host}")


if __name__ == "__main__":
    main()
