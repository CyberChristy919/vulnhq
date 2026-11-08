"""Tests for the Ask feature (SRS FR-NLQ, FR-TRC, FR-AMB; Q1 to Q10).

These tests describe the code before it exists. Build it in app/ask.py.
Users can type any question; the 10 assignment questions are shortcuts.
No AI model: keywords pick the question type, and every number comes from the data.

    detect_intent(question, departments=(), packages=()) -> str | None
        One of: "critical_assets", "top_asset", "patch_first", "patch_impact",
        "department_kev", "kev_past_due", "posture", "bu_exposure",
        "network_cves", "stale_high". None when the question isn't understood.
        "unpatched" must NOT count as "patch".

    find_department(question, departments) -> str | None   (case-insensitive, whole word)
    find_package(question, packages) -> (package or None, candidates)
        Full package name in the question wins. Otherwise, packages whose first
        word is in the question are candidates; one candidate is the answer,
        several means "ask which one" (package None).
    find_days(question, default=30) -> int   ("last 45 days" -> 45)

    answer(question, items, assets, as_of) -> Answer
        Answer (dataclass): intent, answer (text), evidence (list of dicts),
        notes (list of str), suggestions (list of str)
        Every evidence row has: asset_id, hostname, cve_id, cvss, source,
        kev_due_date, bod_due_date, confidence, nvd_url.

Until app/ask.py exists, these tests are skipped.
"""

from dataclasses import dataclass, field
from datetime import date

import pytest

ask = pytest.importorskip("app.ask")

AS_OF = date(2026, 11, 8)


@dataclass
class Asset:
    hostname: str
    asset_id: str
    asset_type: str
    department: str
    criticality: int = 3
    last_scan_date: date | None = date(2026, 11, 1)


@dataclass
class Item:
    hostname: str
    asset_id: str
    software: str
    cve_id: str
    cvss_score: float | None
    risk_score: float
    tier: str = "Medium"
    in_kev: bool = False
    confidence: str = "confirmed"
    kev_due_date: date | None = None
    kev_past_due: bool = False
    kev_days_overdue: int | None = None
    bod_due_date: date | None = None
    bod_assumed: list = field(default_factory=list)


ASSETS = [
    Asset("fin-app01", "FIN-SRV-001", "server", "Finance", 5),
    Asset("fin-ws01", "FIN-WS-001", "workstation", "Finance", 3, date(2026, 8, 1)),
    Asset("hr-srv01", "HR-SRV-001", "server", "HR", 4),
    Asset("core-rtr01", "NET-RTR-001", "network device", "IT", 5, date(2026, 9, 1)),
    Asset("mkt-ws01", "MKT-WS-001", "workstation", "Marketing", 2, None),
]

ITEMS = [
    Item("fin-app01", "FIN-SRV-001", "Apache HTTP Server 2.4.49", "CVE-2021-41773", 9.8, 95.0, "Critical",
         True, kev_due_date=date(2021, 11, 17), kev_past_due=True, kev_days_overdue=1817),
    Item("fin-app01", "FIN-SRV-001", "Apache HTTP Server 2.4.49", "CVE-2021-42013", 9.8, 93.0, "Critical",
         True, kev_due_date=date(2021, 11, 17), kev_past_due=True, kev_days_overdue=1817),
    Item("hr-srv01", "HR-SRV-001", "Apache HTTP Server 2.4.50", "CVE-2021-42013", 9.8, 80.0, "High",
         True, kev_due_date=date(2021, 11, 17), kev_past_due=True, kev_days_overdue=1817),
    Item("fin-ws01", "FIN-WS-001", "OpenSSL 1.1.1", "CVE-2022-0778", 7.5, 55.0, "Medium",
         confidence="conditional"),
    Item("core-rtr01", "NET-RTR-001", "Cisco IOS XE 16.9", "CVE-2023-20198", 10.0, 90.0, "Critical",
         True, kev_due_date=date(2023, 10, 20), kev_past_due=True, kev_days_overdue=1115),
    Item("core-rtr01", "NET-RTR-001", "Cisco IOS XE 16.9", "CVE-2023-20273", 7.2, 70.0, "High",
         True, confidence="nvd", bod_assumed=["automatable"]),
    Item("mkt-ws01", "MKT-WS-001", "Apache Tomcat 9.0.30", "CVE-2020-1938", None, 40.0, "Low"),
]

DEPTS = [a.department for a in ASSETS]
PKGS = ["Apache HTTP Server", "OpenSSL", "Cisco IOS XE", "Apache Tomcat"]


def run(q):
    return ask.answer(q, ITEMS, ASSETS, AS_OF)


# ---------- The 10 assignment questions pick the right intent ----------

@pytest.mark.parametrize("question, intent", [
    ("Which of our assets have critical unpatched CVEs?", "critical_assets"),
    ("What is our highest-risk server right now and why?", "top_asset"),
    ("Which software package should we patch first to reduce the most exposure across the fleet?", "patch_first"),
    ("How many of our Finance department assets are affected by actively exploited vulnerabilities?", "department_kev"),
    ("Are any of our assets running software with a CISA KEV due date that has already passed?", "kev_past_due"),
    ("Summarise our overall vulnerability posture for the CISO in 3 sentences.", "posture"),
    ("Which business unit has the most critical exposure?", "bu_exposure"),
    ("What would patching Apache HTTP Server on all affected hosts reduce our CVE count by?", "patch_impact"),
    ("List all CVEs affecting our network devices sorted by CVSS score.", "network_cves"),
    ("Are there any assets that have not been scanned in the last 30 days that also have high-severity CVEs?", "stale_high"),
])
def test_assignment_questions(question, intent):
    assert ask.detect_intent(question, DEPTS, PKGS) == intent


# ---------- Users' own wording still works ----------

@pytest.mark.parametrize("question, intent", [
    ("show me critical vulns", "critical_assets"),
    ("riskiest server?", "top_asset"),
    ("what should we patch first", "patch_first"),
    ("how exposed is HR to exploited vulns", "department_kev"),
    ("anything overdue on KEV?", "kev_past_due"),
    ("give me an overview for leadership", "posture"),
    ("which department is worst off", "bu_exposure"),
    ("if we upgrade OpenSSL what changes", "patch_impact"),
    ("what's wrong with our routers", "network_cves"),
    ("stale scans with high CVEs", "stale_high"),
])
def test_own_wording(question, intent):
    assert ask.detect_intent(question, DEPTS, PKGS) == intent


def test_unpatched_is_not_patch():
    assert ask.detect_intent("unpatched critical CVEs", DEPTS, PKGS) == "critical_assets"


def test_not_understood():
    r = run("What's the weather in Raleigh?")
    assert r.intent is None
    assert "can't answer" in r.answer
    assert len(r.suggestions) == 10


# ---------- Extracting details ----------

def test_find_department():
    assert ask.find_department("finance assets", DEPTS) == "Finance"
    assert ask.find_department("assets in HR", DEPTS) == "HR"
    assert ask.find_department("shrimp", DEPTS) is None   # whole words only


def test_find_package_full_name():
    assert ask.find_package("patching apache http server", PKGS) == ("Apache HTTP Server", ["Apache HTTP Server"])


def test_find_package_ambiguous():
    pkg, cands = ask.find_package("patch apache", PKGS)
    assert pkg is None
    assert cands == ["Apache HTTP Server", "Apache Tomcat"]


def test_find_days():
    assert ask.find_days("not scanned in the last 45 days") == 45
    assert ask.find_days("stale scans") == 30


# ---------- Answers: numbers come from the data ----------

def test_q1_critical_assets():
    r = run("Which of our assets have critical unpatched CVEs?")
    assert r.answer.startswith("3 assets")          # CVSS 9.0+: fin-app01, hr-srv01, core-rtr01
    assert [e["cvss"] for e in r.evidence][0] == 10.0


def test_q2_top_server():
    r = run("What is our highest-risk server right now and why?")
    assert r.answer.startswith("fin-app01 (FIN-SRV-001)")
    assert "CVE-2021-41773" in r.answer


def test_q3_patch_first():
    r = run("Which software package should we patch first?")
    assert r.answer.startswith("Patch Apache HTTP Server first")


def test_q4_department_kev():
    r = run("How many of our Finance department assets are affected by actively exploited vulnerabilities?")
    assert r.answer.startswith("1 of 2 Finance assets")


def test_q5_kev_past_due():
    r = run("Any CISA KEV due dates already passed?")
    assert r.answer.startswith("Yes: 4 findings on 3 assets")
    assert "1817 days" in r.answer


def test_q6_posture_is_three_sentences():
    r = run("Summarise our posture for the CISO")
    assert r.answer.count(". ") + 1 == 3


def test_q7_bu_exposure():
    r = run("Which business unit has the most critical exposure?")
    assert r.answer.startswith("Finance")


def test_q8_patch_impact():
    r = run("What would patching Apache HTTP Server on all affected hosts reduce our CVE count by?")
    assert "remove 2 CVEs (6 to 4)" in r.answer


def test_q8_ambiguous_package_asks_which():
    r = run("What would patching Apache reduce?")
    assert "Which one?" in r.answer
    assert len(r.suggestions) == 2


def test_q9_network_sorted_by_cvss():
    r = run("List all CVEs affecting our network devices sorted by CVSS score.")
    assert [e["cve_id"] for e in r.evidence] == ["CVE-2023-20198", "CVE-2023-20273"]


def test_q10_stale_high():
    r = run("Assets not scanned in the last 30 days with high-severity CVEs?")
    assert r.answer.startswith("2 assets")          # fin-ws01 (Aug) and core-rtr01 (Sep)
    assert any("mkt-ws01" in n for n in r.notes)    # no scan date is called out, not dropped


# ---------- Traceability and honesty ----------

def test_evidence_rows_have_citation_fields():
    r = run("List all CVEs affecting our network devices")
    row = r.evidence[0]
    for key in ("asset_id", "hostname", "cve_id", "cvss", "source", "kev_due_date",
                "bod_due_date", "confidence", "nvd_url"):
        assert key in row
    assert row["source"] == "CISA KEV, NVD"
    assert row["nvd_url"] == "https://nvd.nist.gov/vuln/detail/CVE-2023-20198"


def test_notes_show_uncertain_matches():
    r = run("List all CVEs affecting our network devices")
    assert any("1 from NVD only" in n for n in r.notes)
    assert any("assumed worst-case" in n for n in r.notes)


def test_missing_cvss_is_called_out():
    r = run("Which of our assets have critical unpatched CVEs?")
    assert any("1 findings have no CVSS score" in n for n in r.notes)
