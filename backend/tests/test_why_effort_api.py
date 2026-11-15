"""Tests for showing effort in "Why this order" on the Patch plan page.

GET /patch-plan already fills in fix_type, but GET /patch-plan/why builds its own
plan without it, so every row there is "unknown" and the Effort part never shows.

These tests describe the code before it exists. In app/main.py:

    add_fix_types(db, plan)
        Move the lookup out of get_patch_plan() into this helper, unchanged:
        KEV actions and NVD fixed versions once, one OsvClient(timeout=5),
        then for each row: lookup_fix_types(..., package=row.package) and
        row.fix_type = package_fix_type(...). It changes the rows in place.

    get_patch_plan():     plan = patch_plan(items)[:limit], add_fix_types(db, plan), return the rows
    get_patch_plan_why(): plan = patch_plan(scored_findings(db))[:limit], add_fix_types(db, plan),
                          return {"why": why_this_order(plan, limit)}
        Cut to limit first, so it only looks up the packages it explains.

The findings, NVD fixed versions and OSV records are the same ones as in
test_patch_plan_fix_api_package.py (NVD ranges from data/vuln_rules.json,
OSV records trimmed from api.osv.dev).

Until add_fix_types() is in app/main.py, these tests are skipped.
"""

import pytest
from fastapi.testclient import TestClient

from app import main
from tests.test_patch_plan_fix_api_package import CHROME_ITEMS, OSV, RULES

if not hasattr(main, "add_fix_types"):
    pytest.skip("add_fix_types() isn't in app/main.py yet", allow_module_level=True)


class FakeOsv:
    made = 0
    asked = []

    def __init__(self, timeout=30, **kwargs):
        FakeOsv.made += 1

    def record(self, cve_id):
        FakeOsv.asked.append(cve_id)
        return OSV.get(cve_id)


@pytest.fixture
def client(monkeypatch):
    FakeOsv.made = 0
    FakeOsv.asked = []
    # Google Chrome (2 KEV findings) first, then log4j-core (1)
    monkeypatch.setattr(main, "scored_findings", lambda db, *args, **kwargs: CHROME_ITEMS)
    monkeypatch.setattr(main, "kev_required_actions", lambda db, cves: {})
    monkeypatch.setattr(main, "load_rules", lambda: RULES)
    monkeypatch.setattr(main, "load_nvd_cache", lambda: {})
    monkeypatch.setattr(main, "OsvClient", FakeOsv)
    main.app.dependency_overrides[main.get_db] = lambda: None
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


def why(client, limit=3):
    return client.get(f"/patch-plan/why?limit={limit}").json()["why"]


def test_why_shows_effort_for_each_package(client):
    lines = why(client)
    assert lines[1].startswith("Google Chrome first:")
    assert lines[1].endswith(" Effort: vendor update (install the vendor's update).")
    assert lines[2].startswith("log4j-core next:")
    assert lines[2].endswith(" Effort: library update (rebuild and test every app that bundles it).")


def test_why_uses_one_osv_client(client):
    why(client)
    assert FakeOsv.made == 1


def test_why_only_looks_up_the_packages_it_explains(client):
    # limit=1 explains only Google Chrome, so log4j-core's CVE is never looked up
    why(client, limit=1)
    assert "CVE-2021-44228" not in FakeOsv.asked
    assert set(FakeOsv.asked) == {"CVE-2023-4863", "CVE-2023-5217"}


def test_patch_plan_still_has_fix_types(client):
    rows = {r["package"]: r["fix_type"] for r in client.get("/patch-plan").json()}
    assert rows == {"Google Chrome": "vendor update", "log4j-core": "library update"}
