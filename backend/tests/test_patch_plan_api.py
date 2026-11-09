"""Tests for the /patch-plan API (SRS FR-MOB-01, Q3).

The endpoint returns patch_plan() rows as JSON, most KEV findings first, then biggest risk reduction:
    GET /patch-plan?limit=10 -> [{package, findings, cves, hosts, versions,
                                  kev_findings, critical_findings, risk_removed}, ...]
The database is replaced with the sample findings from test_ask, so no real database is needed.
"""

import pytest
from fastapi.testclient import TestClient

from app import main
from tests.test_ask import ITEMS

if not any(getattr(r, "path", "") == "/patch-plan" for r in main.app.routes):
    pytest.skip("GET /patch-plan isn't in app/main.py yet", allow_module_level=True)


@pytest.fixture
def client(monkeypatch):
    # Use the sample findings instead of the database
    monkeypatch.setattr(main, "scored_findings", lambda db, *args, **kwargs: ITEMS)
    main.app.dependency_overrides[main.get_db] = lambda: None
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


def test_patch_plan_kev_then_biggest_risk_first(client):
    rows = client.get("/patch-plan").json()
    # Apache HTTP Server: 3 KEV findings and 95 + 93 + 80 = 268 risk points, the most of any package
    assert rows[0]["package"] == "Apache HTTP Server"
    assert rows[0]["risk_removed"] == 268.0
    assert rows[0]["findings"] == 3
    assert rows[0]["kev_findings"] == 3
    order = [(r["kev_findings"], r["risk_removed"]) for r in rows]
    assert order == sorted(order, reverse=True)


def test_patch_plan_has_every_field(client):
    row = client.get("/patch-plan").json()[0]
    for key in ("package", "findings", "cves", "hosts", "versions",
                "kev_findings", "critical_findings", "risk_removed"):
        assert key in row


def test_patch_plan_limit(client):
    assert len(client.get("/patch-plan?limit=2").json()) == 2
    # The API caps limit at 100
    assert client.get("/patch-plan?limit=101").status_code == 422
