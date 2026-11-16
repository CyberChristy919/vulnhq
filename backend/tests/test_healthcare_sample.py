"""Checks for the fictional healthcare sample data set (issue #5).

Files: sample-data/healthcare-inventory.json and sample-data/healthcare-context.json,
in the same formats as the lab files. Runs offline: matches use only the vetted
rules in backend/data/vuln_rules.json, not NVD.
"""

import ipaddress
import json
from datetime import date
from pathlib import Path

import pytest

from app.inventory import ContextFile, InventoryFile
from app.matcher import match_software

SAMPLE = Path(__file__).resolve().parents[2] / "sample-data"
DOC_RANGES = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


@pytest.fixture(scope="module")
def raw_inventory():
    return json.loads((SAMPLE / "healthcare-inventory.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def inventory(raw_inventory):
    return InventoryFile.model_validate(raw_inventory)


@pytest.fixture(scope="module")
def context():
    raw = json.loads((SAMPLE / "healthcare-context.json").read_text(encoding="utf-8"))
    return ContextFile.model_validate(raw)


def test_has_15_to_30_assets(inventory):
    assert 15 <= len(inventory.assets) <= 30


def test_hostnames_are_unique(inventory):
    names = [a.hostname for a in inventory.assets]
    assert len(names) == len(set(names))


def test_ips_are_from_documentation_ranges(inventory):
    for a in inventory.assets:
        assert a.ip_address, f"{a.hostname} has no ip_address"
        ip = ipaddress.ip_address(a.ip_address)
        assert any(ip in net for net in DOC_RANGES), f"{a.hostname}: {ip} isn't a documentation address"


def test_mix_of_criticality(inventory):
    assert len({a.criticality for a in inventory.assets}) >= 3


def test_metadata_has_generated_date(raw_inventory):
    date.fromisoformat(raw_inventory["metadata"]["generated"])


def test_at_least_one_stale_scan(raw_inventory, inventory):
    # More than 90 days before the file's generated date
    generated = date.fromisoformat(raw_inventory["metadata"]["generated"])
    ages = [(generated - date.fromisoformat(str(a.last_scan_date))).days
            for a in inventory.assets if a.last_scan_date]
    assert any(age > 90 for age in ages)


def test_some_assets_match_known_cves(inventory):
    matched = [a.hostname for a in inventory.assets
               if any(match_software(s.name, s.version) for s in a.installed_software)]
    assert len(matched) >= 3


def test_some_software_matches_nothing(inventory):
    unmatched = [s for a in inventory.assets for s in a.installed_software
                 if not match_software(s.name, s.version)]
    assert unmatched


def test_context_hostnames_exist_in_inventory(inventory, context):
    names = {a.hostname for a in inventory.assets}
    for entry in context.assets:
        assert entry.hostname in names, f"{entry.hostname} isn't in the inventory"


def test_context_has_internet_facing_and_sensitive_data(context):
    assert any(e.internet_facing for e in context.assets)
    assert any(e.data_classification in ("restricted", "confidential") for e in context.assets)
