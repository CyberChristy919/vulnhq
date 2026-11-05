"""Matches installed software versions to CVEs using data/vuln_rules.json."""

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app.versions import in_range

RULES_PATH = Path(__file__).resolve().parents[1] / "data" / "vuln_rules.json"


@dataclass
class Match:
    cve_id: str
    title: str
    cvss: float | None
    software: str
    condition: str | None
    source: str


@lru_cache
def load_rules() -> list[dict]:
    return json.loads(RULES_PATH.read_text(encoding="utf-8"))["rules"]


@lru_cache
def covered_products() -> frozenset[str]:
    """Software names that have at least one vetted rule."""
    return frozenset(p for rule in load_rules() for p in rule["products"])


def match_software(name: str, version: str) -> list[Match]:
    key = name.strip().lower()
    matches: dict[str, Match] = {}
    for rule in load_rules():
        if key not in rule["products"]:
            continue
        if in_range(
            version,
            rule["min_version"],
            rule["min_inclusive"],
            rule["max_version"],
            rule["max_inclusive"],
        ):
            # A CVE can have several ranges; keep one match per CVE
            matches.setdefault(
                rule["cve"],
                Match(
                    cve_id=rule["cve"],
                    title=rule["title"],
                    cvss=rule["cvss"],
                    software=f"{name} {version}",
                    condition=rule["condition"],
                    source=rule["source"],
                ),
            )
    return list(matches.values())
