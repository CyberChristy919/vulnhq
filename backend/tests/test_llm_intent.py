"""Tests for the local AI fallback on the Ask page.

The model only picks the question type when keywords don't match; the code still calculates every number.
These tests never call a real model: they use fake classifiers and a fake HTTP reply,
so they pass with Ollama stopped.
"""

import json

import httpx
import pytest

llm = pytest.importorskip("app.llm_intent")
ask = pytest.importorskip("app.ask")

from tests.test_ask import AS_OF, ASSETS, ITEMS  # noqa: E402  (same sample data as test_ask)

DEPTS = ["Finance", "HR", "IT", "Marketing"]
PKGS = ["Apache HTTP Server", "Apache Tomcat", "Cisco IOS XE", "OpenSSL"]


def reply(**fields):
    """A model reply as JSON text, with "none"/0 for anything not given."""
    data = {"intent": "none", "department": "none", "package": "none", "days": 0}
    data.update(fields)
    return json.dumps(data)


# ---------- parse_reply: only trust values that exist ----------

def test_parse_good_reply():
    got = llm.parse_reply(reply(intent="department_kev", department="Finance"), DEPTS, PKGS)
    assert got == {"intent": "department_kev", "department": "Finance", "package": None, "days": None}


def test_parse_not_json():
    assert llm.parse_reply("Sure! The intent is bu_exposure.", DEPTS, PKGS) is None


def test_parse_none_intent():
    assert llm.parse_reply(reply(), DEPTS, PKGS) is None


def test_parse_unknown_intent():
    assert llm.parse_reply(reply(intent="delete_everything"), DEPTS, PKGS) is None


def test_parse_drops_made_up_department_and_package():
    got = llm.parse_reply(reply(intent="patch_first", department="Legal", package="Windows 95"), DEPTS, PKGS)
    assert got["department"] is None and got["package"] is None


def test_parse_department_question_without_department_becomes_fleet_wide():
    assert llm.parse_reply(reply(intent="department_kev"), DEPTS, PKGS)["intent"] == "bu_exposure"


def test_parse_patch_impact_without_package_becomes_patch_first():
    assert llm.parse_reply(reply(intent="patch_impact"), DEPTS, PKGS)["intent"] == "patch_first"


@pytest.mark.parametrize("days, expected", [(45, 45), (0, None), (-5, None), (99999, None), ("30", None)])
def test_parse_days(days, expected):
    assert llm.parse_reply(reply(intent="stale_high", days=days), DEPTS, PKGS)["days"] == expected


# ---------- build_schema and build_prompt ----------

def test_schema_limits_choices_to_real_values():
    schema = llm.build_schema(DEPTS, PKGS)
    props = schema["properties"]
    assert set(props["intent"]["enum"]) == set(llm.INTENTS) | {"none"}
    assert props["department"]["enum"] == DEPTS + ["none"]
    assert props["package"]["enum"] == PKGS + ["none"]
    assert set(schema["required"]) == {"intent", "department", "package", "days"}


def test_ten_intents():
    assert len(llm.INTENTS) == 10


def test_prompt_lists_every_intent():
    prompt = llm.build_prompt()
    assert all(name in prompt for name in llm.INTENTS)


# ---------- classify: talks to Ollama, never crashes ----------

class FakeResponse:
    def __init__(self, content, status=200):
        self.content, self.status = content, status

    def raise_for_status(self):
        if self.status >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=None)

    def json(self):
        return {"message": {"content": self.content}}


def test_classify_sends_schema_and_reads_reply(monkeypatch):
    sent = {}

    def fake_post(url, json, timeout):
        sent.update(url=url, body=json, timeout=timeout)
        return FakeResponse(reply(intent="bu_exposure"))

    monkeypatch.setattr(llm.httpx, "post", fake_post)
    got = llm.classify("which team is in the worst shape on exploited bugs?", DEPTS, PKGS)
    assert got["intent"] == "bu_exposure"
    assert sent["url"].endswith("/api/chat")
    assert sent["body"]["model"] == llm.OLLAMA_MODEL
    assert sent["body"]["stream"] is False
    assert sent["body"]["format"] == llm.build_schema(DEPTS, PKGS)
    assert sent["body"]["messages"][-1]["content"].startswith("which team")


def test_classify_returns_none_when_ollama_is_down(monkeypatch):
    def down(*args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(llm.httpx, "post", down)
    assert llm.classify("anything", DEPTS, PKGS) is None


def test_classify_returns_none_on_server_error(monkeypatch):
    monkeypatch.setattr(llm.httpx, "post", lambda *a, **k: FakeResponse("", status=500))
    assert llm.classify("anything", DEPTS, PKGS) is None


def test_classify_returns_none_on_slow_model(monkeypatch):
    def slow(*args, **kwargs):
        raise httpx.ReadTimeout("too slow")

    monkeypatch.setattr(llm.httpx, "post", slow)
    assert llm.classify("anything", DEPTS, PKGS) is None


# ---------- answer(intent=...): skip keyword detection ----------

def test_answer_accepts_intent():
    result = ask.answer("gibberish words", ITEMS, ASSETS, AS_OF, intent="kev_past_due")
    assert result.intent == "kev_past_due"


# ---------- answer_with_ai: keywords first, model second ----------

def never_called(*args):
    raise AssertionError("the model should not be asked when keywords match")


def fake(**guess):
    """A classifier that always returns the same guess, and records what it was given."""
    calls = []

    def classify(question, departments, packages):
        calls.append((question, departments, packages))
        return {"intent": None, "department": None, "package": None, "days": None, **guess}

    classify.calls = calls
    return classify


def test_keywords_win_without_asking_model():
    result = ask.answer_with_ai("Which business unit has the most critical exposure?",
                                ITEMS, ASSETS, AS_OF, never_called)
    assert result.intent == "bu_exposure"
    assert not any("AI model" in n for n in result.notes)


def test_model_picks_intent_for_new_wording():
    result = ask.answer_with_ai("which team is in the roughest shape on exploited bugs?",
                                ITEMS, ASSETS, AS_OF, fake(intent="bu_exposure"))
    assert result.intent == "bu_exposure"
    assert "AI model" in result.notes[0]
    assert result.evidence  # numbers and evidence still come from the data


def test_model_gets_real_departments_and_packages():
    classify = fake(intent="bu_exposure")
    ask.answer_with_ai("hmm, who is hurting most?", ITEMS, ASSETS, AS_OF, classify)
    _, departments, packages = classify.calls[0]
    assert departments == DEPTS
    assert packages == PKGS


def test_model_department_is_used():
    result = ask.answer_with_ai("how bad are the money people on exploited stuff?",
                                ITEMS, ASSETS, AS_OF, fake(intent="department_kev", department="Finance"))
    assert result.intent == "department_kev"
    assert "Finance" in result.answer


def test_model_package_is_used():
    result = ask.answer_with_ai("if we fixed the web server what would we gain?",
                                ITEMS, ASSETS, AS_OF, fake(intent="patch_impact", package="Apache HTTP Server"))
    assert result.intent == "patch_impact"
    assert "Apache HTTP Server" in result.answer


def test_model_days_are_used():
    result = ask.answer_with_ai("anything gone dark for 45 days with bad bugs?",
                                ITEMS, ASSETS, AS_OF, fake(intent="stale_high", days=45))
    assert result.intent == "stale_high"
    assert "45 days" in result.answer


def test_model_unsure_keeps_honest_answer():
    result = ask.answer_with_ai("what's for lunch?", ITEMS, ASSETS, AS_OF, lambda *a: None)
    assert result.intent is None
    assert result.suggestions == ask.EXAMPLES
