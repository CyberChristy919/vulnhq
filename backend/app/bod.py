"""CISA BOD 26-04 remediation tiers.

Looks up a finding in Table 1 of the directive (backend/data/bod2604_matrix.json)
using four yes/no values, and works out the fix-by date.
"""

import json
from dataclasses import dataclass, field
from datetime import date, timedelta
from itertools import product
from pathlib import Path

# Load the CISA table once, when the app starts
MATRIX_PATH = Path(__file__).resolve().parents[1] / "data" / "bod2604_matrix.json"
MATRIX = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))

# Tier details, e.g. TIERS["3"] -> {"label": "14 days", "days": 14, ...}
TIERS = MATRIX["tiers"]

# Each row keyed by its four values, e.g. (True, True, False, "total") -> row 3
ROWS = {
    (r["publicly_exposed"], r["in_kev"], r["automatable"], r["technical_impact"]): r
    for r in MATRIX["rows"]
}


# CISA SSVC values per CVE from vuln_rules.json: cve -> (automatable, technical_impact)
RULES_PATH = Path(__file__).resolve().parents[1] / "data" / "vuln_rules.json"
SSVC = {
    r["cve"]: (r.get("automatable"), r.get("technical_impact"))
    for r in json.loads(RULES_PATH.read_text(encoding="utf-8"))["rules"]
}


@dataclass
class BodResult:
    tier: int  # 1 to 5, 1 is most urgent
    label: str  # e.g. "3 days & forensic triage"
    days: int | None  # None means fix on system upgrade
    forensic_triage: bool  # True only for tier 1
    row: int | None  # Table 1 row, or None if a value was assumed
    assumed: list[str] = field(default_factory=list)  # unknown fields


def bod_tier(exposed, in_kev, automatable, impact):
    """Find the BOD 26-04 tier for one finding on one asset."""

    # Accept "Total" or "TOTAL", but nothing except total/partial
    if impact is not None:
        impact = impact.lower()
        if impact not in ("total", "partial"):
            raise ValueError(f"impact must be 'total', 'partial' or None, got {impact!r}")

    # For each unknown value, try both possibilities and note it
    assumed = []
    exposed_options = [exposed]
    if exposed is None:
        exposed_options = [True, False]
        assumed.append("publicly_exposed")

    auto_options = [automatable]
    if automatable is None:
        auto_options = [True, False]
        assumed.append("automatable")

    impact_options = [impact]
    if impact is None:
        impact_options = ["total", "partial"]
        assumed.append("technical_impact")

    # Look up every combination and keep the most urgent (lowest tier number)
    matches = [
        ROWS[(e, in_kev, a, i)]
        for e, a, i in product(exposed_options, auto_options, impact_options)
    ]
    worst = min(matches, key=lambda r: r["tier"])

    details = TIERS[str(worst["tier"])]
    return BodResult(
        tier=worst["tier"],
        label=details["label"],
        days=details["days"],
        forensic_triage=details["forensic_triage"],
        row=None if assumed else worst["row"],
        assumed=assumed,
    )


def bod_due_date(first_seen, kev_date_added, days):
    """Fix-by date: the clock starts at whichever came first."""
    if days is None:
        return None  # fix on system upgrade, no fixed date
    start = first_seen
    if kev_date_added is not None and kev_date_added < first_seen:
        start = kev_date_added
    return start + timedelta(days=days)