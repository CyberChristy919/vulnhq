"""Tests for matching OSV packages per Patch plan row in the /patch-plan API.

The bug: Google Chrome showed "library update" because OSV lists npm electron
for CVE-2023-5217 and NuGet SkiaSharp for CVE-2023-4863. Those bundle the same
libraries, but they aren't Chrome.

These tests describe the code before it exists. Change get_patch_plan() in app/main.py:
    Look up fix types one row at a time, passing the row's package:
        for row in plan:
            types = lookup_fix_types(row.cves, ..., package=row.package)
            row.fix_type = package_fix_type(list(types.values()))
    Use one OsvClient(timeout=5) for every row, so its cache is shared.
    Fetch the KEV actions and NVD fixed versions once, before the loop.
    Then return the rows in plan as dicts (the order still never changes).

Fixed versions are real NVD ranges from data/vuln_rules.json.
OSV records are trimmed from api.osv.dev (November 2026).

Until lookup_fix_types() takes a package, these tests are skipped.
"""

import inspect

import pytest
from fastapi.testclient import TestClient

from app import fix_lookup, main
from tests.test_ask import ITEMS, Item

if "package" not in inspect.signature(fix_lookup.lookup_fix_types).parameters:
    pytest.skip("lookup_fix_types() doesn't take a package yet", allow_module_level=True)

CHROME_ITEMS = [
    Item("exec-ws-ceo", "EXEC-WS-001", "Google Chrome 114.0.5735.198", "CVE-2023-4863", 8.8, 60.0, "High", True),
    Item("exec-ws-ceo", "EXEC-WS-001", "Google Chrome 114.0.5735.198", "CVE-2023-5217", 8.8, 60.0, "High", True),
    Item("hr-app01", "HR-SRV-002", "log4j-core 2.14.1", "CVE-2021-44228", 10.0, 98.0, "Critical", True),
]

RULES = [
    {"cve": "CVE-2023-4863", "max_version": "116.0.5845.187", "max_inclusive": False},
    {"cve": "CVE-2023-5217", "max_version": "117.0.5938.132", "max_inclusive": False},
    {"cve": "CVE-2021-44228", "max_version": "2.15.0", "max_inclusive": False},
]

OSV = {
    # https://osv.dev/vulnerability/GHSA-j7hp-h8jx-5ppr
    "CVE-2023-4863": {"affected": [{"package": {"ecosystem": "NuGet", "name": "SkiaSharp"}},
                                   {"package": {"ecosystem": "Go", "name": "github.com/chai2010/webp"}}]},
    # https://osv.dev/vulnerability/GHSA-qqvq-6xgj-jw8g
    "CVE-2023-5217": {"affected": [{"package": {"ecosystem": "npm", "name": "electron"}}]},
    # https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q
    "CVE-2021-44228": {"affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"}}]},
}


class FakeOsv:
    made = 0

    def __init__(self, timeout=30, **kwargs):
        FakeOsv.made += 1

    def record(self, cve_id):
        return OSV.get(cve_id)


@pytest.fixture
def client(monkeypatch):
    FakeOsv.made = 0
    monkeypatch.setattr(main, "scored_findings", lambda db, *args, **kwargs: ITEMS + CHROME_ITEMS)
    monkeypatch.setattr(main, "kev_required_actions", lambda db, cves: {})
    monkeypatch.setattr(main, "load_rules", lambda: RULES)
    monkeypatch.setattr(main, "load_nvd_cache", lambda: {})
    monkeypatch.setattr(main, "OsvClient", FakeOsv)
    main.app.dependency_overrides[main.get_db] = lambda: None
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


def fix_types(client):
    return {r["package"]: r["fix_type"] for r in client.get("/patch-plan").json()}


def test_chrome_is_a_vendor_update(client):
    # OSV's electron and SkiaSharp aren't Chrome, so NVD's fixed versions decide
    assert fix_types(client)["Google Chrome"] == "vendor update"


def test_log4j_core_is_a_library_update(client):
    assert fix_types(client)["log4j-core"] == "library update"


def test_one_osv_client_for_all_rows(client):
    client.get("/patch-plan")
    assert FakeOsv.made == 1
