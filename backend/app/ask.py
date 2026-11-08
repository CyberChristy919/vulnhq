"""Answer plain-English questions about vulnerability exposure (SRS FR-NLQ, Q1 to Q10).

Users can ask anything; the 10 assignment questions are shortcuts.
No AI model: keywords pick the question type, and every number comes from the data.
"""

import re
from dataclasses import dataclass, field
from datetime import date

from app.patch_plan import package_name, patch_plan, patch_impact

# Shortcut questions shown on the Ask page, and suggested when a question isn't understood
EXAMPLES = [
    "Which of our assets have critical unpatched CVEs?",
    "What is our highest-risk server right now and why?",
    "Which software package should we patch first to reduce the most exposure across the fleet?",
    "How many of our Finance department assets are affected by actively exploited vulnerabilities?",
    "Are any of our assets running software with a CISA KEV due date that has already passed?",
    "Summarise our overall vulnerability posture for the CISO in 3 sentences.",
    "Which business unit has the most critical exposure?",
    "What would patching Apache HTTP Server on all affected hosts reduce our CVE count by?",
    "List all CVEs affecting our network devices sorted by CVSS score.",
    "Are there any assets that have not been scanned in the last 30 days that also have high-severity CVEs?",
]

# NVD severity bands: Critical is 9.0 and up, High is 7.0 and up
CRITICAL_CVSS = 9.0
HIGH_CVSS = 7.0
NETWORK_WORDS = ("network", "router", "switch", "firewall")


@dataclass
class Answer:
    intent: str | None
    answer: str
    # One row per finding behind the answer, so an analyst can check it
    evidence: list[dict] = field(default_factory=list)
    # Caveats: uncertain matches, missing data, assumptions
    notes: list[str] = field(default_factory=list)
    # Questions to try instead, when the question isn't understood or is ambiguous
    suggestions: list[str] = field(default_factory=list)


def has(q, *words):
    """True if any of the words appear anywhere in the question."""
    return any(w in q for w in words)


def find_department(question, departments):
    """The department named in the question, or None. Whole words only."""
    q = question.lower()
    # Longest names first, so "Finance Ops" wins over "Finance"
    for d in sorted({d for d in departments if d}, key=len, reverse=True):
        if re.search(rf"\b{re.escape(d.lower())}\b", q):
            return d
    return None


def find_package(question, packages):
    """(package, candidates). Package is None when the name is ambiguous."""
    q = question.lower()
    names = sorted(set(packages), key=len, reverse=True)
    # A full package name in the question wins
    for p in names:
        if p.lower() in q:
            return p, [p]
    # Otherwise match on the first word, e.g. "apache"
    words = set(re.findall(r"[a-z0-9]+", q))
    cands = [p for p in names if p.split()[0].lower() in words]
    return (cands[0] if len(cands) == 1 else None), sorted(cands)


def find_days(question, default=30):
    """'last 45 days' -> 45; no number -> default."""
    m = re.search(r"(\d+)\s*days?", question.lower())
    return int(m.group(1)) if m else default


def detect_intent(question, departments=(), packages=()):
    """Pick the question type from keywords. Order matters: first match wins."""
    q = question.lower()
    if has(q, "ciso", "posture", "summar", "overview"):
        return "posture"
    # \b means "start of a word", so "unpatched" does not count as "patch"
    patching = re.search(r"\b(patch|upgrad|updat)", q)
    if patching and find_package(q, packages)[1]:
        return "patch_impact"
    if patching or has(q, "package", "which software"):
        return "patch_first"
    if has(q, "past due", "passed", "overdue", "missed"):
        return "kev_past_due"
    if has(q, "scan", "stale"):
        return "stale_high"
    if find_department(q, departments):
        return "department_kev"
    if has(q, "business unit", "department", " bu", "bu "):
        return "bu_exposure"
    if has(q, *NETWORK_WORDS):
        return "network_cves"
    if has(q, "highest-risk", "highest risk", "riskiest", "most at risk", "worst"):
        return "top_asset"
    if has(q, "critical", "unpatched", "at risk", "vulnerable"):
        return "critical_assets"
    return None