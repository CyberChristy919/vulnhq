"""Tests for wiring "Why this order" into the Ask page and the API.

These tests describe the code before it exists. Build it in two places:

    app/ask.py
        Answer gets a new field, after suggestions:
            why: list[str] = field(default_factory=list)
        The "patch_first" answer (Q3) fills it with why_this_order(plan).
        Its old "Next: ..." notes are removed, because the why lines replace them.
        Every other answer leaves why empty.

    app/main.py
        GET /patch-plan/why?limit=3 -> {"why": [...]}
            The same lines, for the Patch plan. limit defaults to 3 and is capped at 10.

The sample findings come from test_ask, so no real database is needed:
    Apache HTTP Server: 3 KEV findings on 2 hosts, risk 268
    Cisco IOS XE:       2 KEV findings on 1 host,  risk 160
    OpenSSL:            0 KEV, risk 55
    Apache Tomcat:      0 KEV, risk 40

Until the field and the route exist, these tests are skipped.
"""

from datetime import date

import pytest
from fastapi.testclient import TestClient

from app import ask, main

ORDER_RULE = pytest.importorskip("app.explain").ORDER_RULE
from tests.test_ask import ASSETS, ITEMS

if not hasattr(ask.Answer(None, ""), "why"):
    pytest.skip("Answer.why isn't in app/ask.py yet", allow_module_level=True)

EXPECTED = [
    ORDER_RULE,
    "Apache HTTP Server first: 3 actively exploited flaws on 2 hosts.",
    "Cisco IOS XE next: 2 actively exploited flaws, fewer than Apache HTTP Server (3).",
    "OpenSSL next: 0 actively exploited flaws, fewer than Cisco IOS XE (2).",
]


def run(q):
    return ask.answer(q, ITEMS, ASSETS, date(2026, 11, 10))


# ---------- Ask page ----------

def test_patch_first_explains_the_order():
    assert run("Which software package should we patch first?").why == EXPECTED


def test_patch_first_drops_the_old_next_notes():
    notes = run("Which software package should we patch first?").notes
    assert not any(n.startswith("Next:") for n in notes)


def test_other_answers_have_no_why():
    assert run("Which of our assets have critical unpatched CVEs?").why == []


# ---------- API ----------

has_route = any(getattr(r, "path", "") == "/patch-plan/why" for r in main.app.routes)
needs_route = pytest.mark.skipif(not has_route, reason="GET /patch-plan/why isn't in app/main.py yet")


@pytest.fixture
def client(monkeypatch):
    # Use the sample findings instead of the database
    monkeypatch.setattr(main, "scored_findings", lambda db, *args, **kwargs: ITEMS)
    monkeypatch.setattr(main, "list_assets", lambda db, *args, **kwargs: ASSETS)
    main.app.dependency_overrides[main.get_db] = lambda: None
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


@needs_route
def test_api_why_default_is_top_three(client):
    assert client.get("/patch-plan/why").json() == {"why": EXPECTED}


@needs_route
def test_api_why_limit(client):
    assert len(client.get("/patch-plan/why?limit=1").json()["why"]) == 2  # the rule plus 1 package
    assert client.get("/patch-plan/why?limit=11").status_code == 422


@needs_route
def test_ask_api_returns_why(client, monkeypatch):
    # No local AI model in tests; keyword routing handles this question
    monkeypatch.setattr(main, "classify", lambda *args, **kwargs: None)
    body = client.post("/ask", json={"question": "Which software package should we patch first?"}).json()
    assert body["why"] == EXPECTED
