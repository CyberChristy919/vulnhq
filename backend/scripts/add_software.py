"""Adds one software item to an existing asset and checks it for CVEs right away.

Usage (from the backend folder):
    python -m scripts.add_software <hostname> "<software name>" <version>
    python -m scripts.add_software <hostname> "<software name>" <version> --cpe vendor:product

Example:
    python -m scripts.add_software hr-app01.corp.local "Atlassian Confluence" 8.5.1
"""

import sys

from app.database import SessionLocal
from app.inventory import SoftwareIn, add_software


def main():
    args = sys.argv[1:]
    if len(args) < 3:
        print(__doc__)
        sys.exit(1)
    hostname, name, version = args[:3]
    cpe = args[args.index("--cpe") + 1] if "--cpe" in args else None

    print(f"Checking {name} {version}...")
    with SessionLocal() as db:
        result = add_software(db, hostname, SoftwareIn(name=name, version=version, cpe=cpe))
        if result is None:
            print(f"No asset named {hostname}. Check the spelling or import it first.")
            sys.exit(1)
        summary, findings = result
        findings.sort(key=lambda f: (not f.vulnerability.in_kev, -(f.vulnerability.cvss_score or 0)))
        kev = sum(f.vulnerability.in_kev for f in findings)
        print(f"Findings: {len(findings)} created, {kev} known exploited (KEV)")
        for f in findings[:15]:
            tag = "KEV " if f.vulnerability.in_kev else "    "
            cvss = f.vulnerability.cvss_score if f.vulnerability.cvss_score is not None else "-"
            print(f"  {tag}{f.cve_id:<16} CVSS {cvss:<4} {f.confidence:<11} {(f.vulnerability.name or '')[:60]}")
        if len(findings) > 15:
            print(f"  ...and {len(findings) - 15} more on the fix list")
        for line in summary.not_checked:
            print(f"Not checked: {line}")
        for line in summary.needs_review:
            print(f"Needs review: {line}")
        if summary.new_cves_added:
            print("Run 'python -m scripts.load_epss' to add EPSS scores for the new CVEs.")


if __name__ == "__main__":
    main()
