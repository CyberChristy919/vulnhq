"""Answer plain-English questions about vulnerability exposure (SRS FR-NLQ, Q1 to Q10).

Users can ask anything; the 10 assignment questions are shortcuts.
Keywords pick the question type first; if they don't match, a local AI model (Ollama) picks it.
Every number comes from the data, not the model.
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
    # \bbu\b is the whole word "bu", so "bugs" does not count
    if has(q, "business unit", "department") or re.search(r"\bbu\b", q):
        return "bu_exposure"
    if has(q, *NETWORK_WORDS):
        return "network_cves"
    if has(q, "highest-risk", "highest risk", "riskiest", "most at risk", "worst"):
        return "top_asset"
    if has(q, "critical", "unpatched", "at risk", "vulnerable"):
        return "critical_assets"
    return None


def evidence_row(i):
    """One finding as a citation row: everything an analyst needs to verify it."""
    return {
        "asset_id": i.asset_id,
        "hostname": i.hostname,
        "cve_id": i.cve_id,
        "cvss": i.cvss_score,
        "source": "CISA KEV, NVD" if i.in_kev else "NVD",
        "kev_due_date": i.kev_due_date,
        "bod_due_date": i.bod_due_date,
        "confidence": i.confidence,
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{i.cve_id}",
    }


def confidence_note(items):
    """'Match confidence: 41 confirmed, 9 conditional (...), 6 from NVD only (...).'"""
    counts = {c: sum(i.confidence == c for i in items) for c in ("confirmed", "conditional", "nvd")}
    parts = []
    if counts["confirmed"]:
        parts.append(f"{counts['confirmed']} confirmed")
    if counts["conditional"]:
        parts.append(f"{counts['conditional']} conditional (needs a configuration check)")
    if counts["nvd"]:
        parts.append(f"{counts['nvd']} from NVD only (not yet reviewed)")
    return "Match confidence: " + ", ".join(parts) + "." if parts else ""


def common_notes(items):
    """Caveats shown under every answer, so nothing uncertain is silently dropped."""
    notes = [n for n in [confidence_note(items)] if n]
    missing = sum(i.cvss_score is None for i in items)
    if missing:
        notes.append(f"{missing} findings have no CVSS score and were not counted by severity.")
    assumed = sum(bool(i.bod_assumed) for i in items)
    if assumed:
        notes.append(f"{assumed} findings use an assumed worst-case CISA tier because CISA has not scored them.")
    return notes


def sev(items, floor):
    """Findings with a CVSS score at or above floor. Missing scores are left out (and noted)."""
    return [i for i in items if i.cvss_score is not None and i.cvss_score >= floor]


def answer(question, items, assets, as_of: date, intent=None) -> Answer:
    """Answer any question. items = open findings, assets = asset summaries.
    intent: skip keyword detection (used when the local AI model picked the question type)."""
    by_host = {a.hostname: a for a in assets}
    departments = [a.department for a in assets]
    packages = [package_name(i.software) for i in items]
    intent = intent or detect_intent(question, departments, packages)
    q = question.lower()

    # Q1: assets with CVSS 9.0+ findings
    if intent == "critical_assets":
        hits = sorted(sev(items, CRITICAL_CVSS), key=lambda i: (-i.cvss_score, i.hostname))
        hosts = sorted({i.hostname for i in hits})
        text = (f"{len(hosts)} assets have critical unpatched CVEs (CVSS {CRITICAL_CVSS} or higher): "
                f"{len(hits)} findings across {len({i.cve_id for i in hits})} CVEs.")
        return Answer(intent, text, [evidence_row(i) for i in hits], common_notes(items))

    # Q2: asset (or server) with the highest single risk score
    if intent == "top_asset":
        want_server = "server" in q
        pool = [i for i in items if not want_server or "server" in (by_host[i.hostname].asset_type or "").lower()]
        if not pool:
            return Answer(intent, "No open findings on matching assets.", notes=common_notes(items))
        top = max(pool, key=lambda i: i.risk_score)
        mine = sorted([i for i in items if i.hostname == top.hostname], key=lambda i: -i.risk_score)
        a = by_host[top.hostname]
        kind = "server" if want_server else "asset"
        text = (f"{a.hostname} ({a.asset_id}) is the highest-risk {kind}: top risk score {top.risk_score} "
                f"from {top.cve_id}, {len(mine)} open findings, {sum(i.in_kev for i in mine)} in CISA KEV, "
                f"criticality {a.criticality} of 5.")
        return Answer(intent, text, [evidence_row(i) for i in mine], common_notes(mine))

    # Q3: package whose patch removes the most risk
    if intent == "patch_first":
        plan = patch_plan(items)
        if not plan:
            return Answer(intent, "No open findings to patch.")
        p = plan[0]
        text = (f"Patch {p.package} first: it removes {p.findings} findings ({p.kev_findings} in CISA KEV) "
                f"across {len(p.hosts)} hosts, risk score total {p.risk_removed}.")
        mine = [i for i in items if package_name(i.software) == p.package]
        notes = [f"Next: {x.package} ({x.findings} findings, risk {x.risk_removed})" for x in plan[1:3]]
        return Answer(intent, text, [evidence_row(i) for i in mine], notes + common_notes(mine))

    # Q8: what patching one package would remove; asks "which one?" if the name is ambiguous
    if intent == "patch_impact":
        pkg, cands = find_package(q, packages)
        if pkg is None:
            return Answer(intent, f"That name matches {len(cands)} packages: {', '.join(cands)}. Which one?",
                          suggestions=[f"What would patching {c} reduce our CVE count by?" for c in cands])
        r = patch_impact(items, pkg)
        mine = [i for i in items if package_name(i.software) == pkg]
        text = (f"Patching {pkg} on {len(r['hosts'])} hosts would remove {r['cves_removed']} CVEs "
                f"({r['cves_before']} to {r['cves_after']}) and {r['findings_before'] - r['findings_after']} findings "
                f"({r['findings_before']} to {r['findings_after']}).")
        return Answer(intent, text, [evidence_row(i) for i in mine], common_notes(mine))

    # Q5: findings past their CISA KEV due date, most overdue first
    if intent == "kev_past_due":
        hits = sorted([i for i in items if i.kev_past_due], key=lambda i: -(i.kev_days_overdue or 0))
        hosts = {i.hostname for i in hits}
        text = (f"Yes: {len(hits)} findings on {len(hosts)} assets are past their CISA KEV due date; "
                f"the oldest is {hits[0].kev_days_overdue} days overdue ({hits[0].cve_id})."
                if hits else "No: no open findings are past their CISA KEV due date.")
        return Answer(intent, text, [evidence_row(i) for i in hits], common_notes(hits))

    # Q10: assets not scanned in N days that have CVSS 7.0+ findings
    if intent == "stale_high":
        days = find_days(q)
        stale = {a.hostname for a in assets if a.last_scan_date and (as_of - a.last_scan_date).days > days}
        unknown = [a.hostname for a in assets if not a.last_scan_date]
        hits = [i for i in sev(items, HIGH_CVSS) if i.hostname in stale]
        hosts = {i.hostname for i in hits}
        text = (f"{len(hosts)} assets have not been scanned in the last {days} days and have high-severity CVEs "
                f"(CVSS {HIGH_CVSS} or higher): {len(hits)} findings.")
        notes = common_notes(hits)
        # Assets with no scan date can't be checked; say so instead of dropping them
        if unknown:
            notes.append(f"{len(unknown)} assets have no scan date and could not be checked: {', '.join(sorted(unknown))}.")
                # Old scans miss newer software changes, so the real count may be higher
        if hosts:
            notes.append("Findings on these assets may be understated, since their last scan is out of date.")
        return Answer(intent, text, [evidence_row(i) for i in hits], notes)

    # Q4: one department's assets with KEV findings
    if intent == "department_kev":
        dept = find_department(q, departments)
        dept_hosts = {a.hostname for a in assets if a.department == dept}
        hits = [i for i in items if i.hostname in dept_hosts and i.in_kev]
        hosts = {i.hostname for i in hits}
        text = (f"{len(hosts)} of {len(dept_hosts)} {dept} assets are affected by actively exploited (CISA KEV) "
                f"vulnerabilities: {len(hits)} findings across {len({i.cve_id for i in hits})} CVEs.")
        return Answer(intent, text, [evidence_row(i) for i in hits], common_notes(hits))

    # Q7: department with the most Critical-tier findings (ties: most KEV)
    if intent == "bu_exposure":
        rows = {}
        for i in items:
            d = by_host[i.hostname].department or "Unknown"
            r = rows.setdefault(d, {"critical": 0, "kev": 0, "findings": 0})
            r["critical"] += i.tier == "Critical"
            r["kev"] += i.in_kev
            r["findings"] += 1
        if not rows:
            return Answer(intent, "No open findings.")
        ranked = sorted(rows.items(), key=lambda kv: (-kv[1]["critical"], -kv[1]["kev"], kv[0]))
        d, r = ranked[0]
        text = (f"{d} has the most critical exposure: {r['critical']} Critical-tier findings, "
                f"{r['kev']} in CISA KEV, {r['findings']} open findings in total.")
        notes = [f"{n}: {x['critical']} Critical, {x['kev']} KEV, {x['findings']} total" for n, x in ranked]
        notes.append("Critical tier is the VulnHQ risk tier, which combines CVSS, KEV, EPSS and asset criticality.")
        top = [i for i in items if (by_host[i.hostname].department or "Unknown") == d and i.tier == "Critical"]
        return Answer(intent, text, [evidence_row(i) for i in top], notes)

    # Q9: findings on network devices, highest CVSS first (missing CVSS last)
    if intent == "network_cves":
        net = {a.hostname for a in assets if has((a.asset_type or "").lower(), *NETWORK_WORDS)}
        hits = sorted([i for i in items if i.hostname in net],
                      key=lambda i: (i.cvss_score is None, -(i.cvss_score or 0), i.cve_id))
        text = (f"{len({i.cve_id for i in hits})} CVEs affect {len({i.hostname for i in hits})} network devices "
                f"({len(hits)} findings), sorted by CVSS score, highest first.")
        return Answer(intent, text, [evidence_row(i) for i in hits], common_notes(hits))

    # Q6: three sentences built from the same numbers as the other answers
    if intent == "posture":
        hosts = {i.hostname for i in items}
        kev = sum(i.in_kev for i in items)
        past = sum(i.kev_past_due for i in items)
        plan = patch_plan(items)
        s1 = (f"We have {len(items)} open findings on {len(hosts)} of {len(assets)} assets; "
              f"{kev} are actively exploited (CISA KEV) and {past} are past their CISA due date.")
        s2 = (f"Patching {plan[0].package} on {len(plan[0].hosts)} hosts is the single biggest reduction, "
              f"removing {plan[0].findings} findings." if plan else "There is no single package to patch.")
        sub = answer("which business unit has the most critical exposure", items, assets, as_of)
        stale = sum(1 for a in assets if a.last_scan_date and (as_of - a.last_scan_date).days > 30)
        s3 = (f"{sub.answer.split(':')[0]}, and {stale} assets have not been scanned in the last 30 days.")
        return Answer(intent, " ".join([s1, s2, s3]), [], common_notes(items))

    # Not understood: say so honestly and offer the shortcut questions
    return Answer(None, "I can't answer that question yet. Try one of these, or reword using words like "
                  "'critical', 'patch first', 'past due', a department name, or 'network devices'.",
                  suggestions=EXAMPLES)


def answer_with_ai(question, items, assets, as_of: date, classify) -> Answer:
    """Keywords first. If they don't match, let the local AI model pick the question type.

    classify(question, departments, packages) returns {"intent", "department", "package", "days"} or None.
    """
    result = answer(question, items, assets, as_of)
    if result.intent is not None:
        return result
    departments = sorted({a.department for a in assets if a.department})
    packages = sorted({package_name(i.software) for i in items})
    guess = classify(question, departments, packages)
    if not guess:
        return result
    # Add the details the model found, so the usual helpers (find_department, find_package, find_days) see them
    hints = [guess.get("department"), guess.get("package")]
    if guess.get("days"):
        hints.append(f"{guess['days']} days")
    reworded = " ".join([question] + [h for h in hints if h])
    ai = answer(reworded, items, assets, as_of, intent=guess["intent"])
    ai.notes.insert(0, f"Question type picked by the local AI model ({guess['intent']}). "
                       "Every number comes from the data, not the model.")
    return ai                 