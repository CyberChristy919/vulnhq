"""Tests for real fix types in the /patch-plan API.

These tests describe the code before it exists. Change app/main.py:

    New imports:
        from app.fix_lookup import lookup_fix_types, nvd_fixed_versions
        from app.matcher import load_rules
        from app.nvd import _load_cache as load_nvd_cache
        from app.osv import OsvClient

    kev_required_actions(db, cve_ids) -> dict[str, str]
        CVE ID -> requiredAction from the vulnerabilities table (filled from the
        CISA KEV feed). Only the CVEs asked for; leave out CVEs with no text.

    GET /patch-plan
        Each row gets "fix_type". Steps:
        1. plan = patch_plan(items)[:limit]  (the order never depends on fix type)
        2. Look up only the CVEs in those rows, so a short list stays fast:
               lookup_fix_types(cves, kev_required_actions(db, cves),
                                nvd_fixed_versions(load_rules(), load_nvd_cache()),
                                OsvClient(timeout=5).record)
           timeout=5 keeps the page from hanging if OSV is slow.
        3. Return patch_plan(items, fix_types)[:limit] as JSON.

The database, KEV, NVD and OSV are all replaced with fakes, so no network calls.
KEV text below is the real requiredAction for each CVE from
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
and fixed versions come from data/vuln_rules.json and NVD
(https://nvd.nist.gov/vuln/detail/CVE-2020-1938).

Until app/main.py has kev_required_actions(), these tests are skipped.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import main
from app.database import Base
from app.models import Vulnerability
from app.osv import OsvUnavailable
from app.patch_plan import patch_plan
from tests.test_ask import ITEMS

if not hasattr(main, "kev_required_actions"):
    pytest.skip("app/main.py has no kev_required_actions() yet", allow_module_level=True)

APPLY_UPDATES = "Apply updates per vendor instructions."
CISCO = ("Verify that instances of Cisco IOS XE Web UI are in compliance with BOD 23-02 "
         "and apply mitigations per vendor instructions.")
KEV = {
    "CVE-2021-41773": APPLY_UPDATES,
    "CVE-2021-42013": APPLY_UPDATES,
    "CVE-2023-20198": CISCO,
    "CVE-2023-20273": CISCO,
    "CVE-2020-1938": APPLY_UPDATES,
}

# Apache's NVD ranges end "through 2.4.49" / "through 2.4.50", so they name no fix
RULES = [
    {"cve": "CVE-2021-41773", "max_version": "2.4.49", "max_inclusive": True},
    {"cve": "CVE-2021-42013", "max_version": "2.4.50", "max_inclusive": True},
    {"cve": "CVE-2022-0778", "max_version": "1.1.1n", "max_inclusive": False},
]
# Tomcat came from a live NVD lookup: before 9.0.31
NVD_CACHE = {"cves": {"a:apache:tomcat|9.0.30": [{"cve_id": "CVE-2020-1938", "fixed_version": "9.0.31"}]}}


class FakeOsv:
    """Stands in for OsvClient. No CVE in ITEMS has a library ecosystem."""
    calls = []
    timeout = None
    down = False

    def __init__(self, timeout=30, **kwargs):
        FakeOsv.timeout = timeout

    def record(self, cve_id):
        FakeOsv.calls.append(cve_id)
        if FakeOsv.down:
            raise OsvUnavailable("OSV returned 503. Try again shortly.")
        return {"id": cve_id, "affected": []}


@pytest.fixture
def client(monkeypatch):
    FakeOsv.calls, FakeOsv.timeout, FakeOsv.down = [], None, False
    monkeypatch.setattr(main, "scored_findings", lambda db, *args, **kwargs: ITEMS)
    monkeypatch.setattr(main, "kev_required_actions", lambda db, cves: {c: KEV[c] for c in cves if c in KEV})
    monkeypatch.setattr(main, "load_rules", lambda: RULES)
    monkeypatch.setattr(main, "load_nvd_cache", lambda: NVD_CACHE)
    monkeypatch.setattr(main, "OsvClient", FakeOsv)
    main.app.dependency_overrides[main.get_db] = lambda: None
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


def rows_by_package(client, url="/patch-plan"):
    return {r["package"]: r["fix_type"] for r in client.get(url).json()}


# ---------- GET /patch-plan ----------

def test_every_row_has_fix_type(client):
    for row in client.get("/patch-plan").json():
        assert row["fix_type"] in {"replace", "library update", "vendor update", "unknown"}


def test_fix_types_come_from_the_sources(client):
    result = rows_by_package(client)
    # NVD rule: OpenSSL is fixed in 1.1.1n
    assert result["OpenSSL"] == "vendor update"
    # Live NVD cache: Tomcat is fixed in 9.0.31
    assert result["Apache Tomcat"] == "vendor update"
    # Inclusive ranges only, and KEV says "Apply updates": no source names a fix
    assert result["Apache HTTP Server"] == "unknown"


def test_kev_end_of_life_means_replace(client, monkeypatch):
    # Pretend KEV marked Cisco IOS XE end-of-life (it hasn't) to check the text reaches fix_type
    eol = "The impacted product is end-of-life and should be disconnected if still in use."
    monkeypatch.setattr(main, "kev_required_actions",
                        lambda db, cves: {c: eol for c in cves if c.startswith("CVE-2023-202")})
    assert rows_by_package(client)["Cisco IOS XE"] == "replace"


def test_order_is_unchanged(client):
    rows = client.get("/patch-plan").json()
    assert [r["package"] for r in rows] == [p.package for p in patch_plan(ITEMS)]


def test_only_returned_rows_are_looked_up(client):
    rows = client.get("/patch-plan?limit=1").json()
    assert len(rows) == 1
    # OSV is only asked about the CVEs in that one row
    assert set(FakeOsv.calls) == set(rows[0]["cves"])


def test_osv_timeout_is_short(client):
    client.get("/patch-plan")
    assert FakeOsv.timeout is not None and FakeOsv.timeout <= 10


def test_osv_outage_still_loads(client):
    FakeOsv.down = True
    resp = client.get("/patch-plan")
    assert resp.status_code == 200
    # NVD still answers without OSV
    assert {r["package"]: r["fix_type"] for r in resp.json()}["OpenSSL"] == "vendor update"


# ---------- kev_required_actions ----------

@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all([
            Vulnerability(cve_id="CVE-2020-1938", in_kev=True, required_action=APPLY_UPDATES),
            Vulnerability(cve_id="CVE-2023-20198", in_kev=True, required_action=CISCO),
            # Not in KEV, so no required action
            Vulnerability(cve_id="CVE-2022-0778", in_kev=False, required_action=None),
        ])
        session.commit()
        yield session


def test_kev_required_actions_only_the_cves_asked_for(db):
    result = main.kev_required_actions(db, ["CVE-2020-1938", "CVE-2022-0778"])
    assert result == {"CVE-2020-1938": APPLY_UPDATES}


def test_kev_required_actions_unknown_cve(db):
    assert main.kev_required_actions(db, ["CVE-2099-0001"]) == {}
