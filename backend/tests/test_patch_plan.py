"""Tests for the package-level patch plan (SRS FR-MOB-01, Q3 and Q8).

These tests describe the code before it exists. Build it in app/patch_plan.py:

    package_name(label) -> str
        Turns a finding's software label into the package name, so every
        version of the same product lands in one group.
        Keep the words before the first word that starts with a digit.
            "Apache HTTP Server 2.4.49" -> "Apache HTTP Server"
            "OpenSSL 1.0.2k"            -> "OpenSSL"
        A label with no version stays as-is. None or "" -> "Unknown".

    patch_plan(items) -> list[PackagePlan]
        items: open findings; each has .software, .cve_id, .hostname,
               .in_kev, .tier, .risk_score
        One PackagePlan per package. Packages with the most KEV findings come
        first, so an actively exploited flaw (like Log4Shell) is never buried
        under a pile of unreviewed findings. Then biggest risk_removed first
        (ties: package name A to Z).

    PackagePlan (dataclass) fields:
        package:           package name from package_name()
        findings:          number of findings for this package
        cves:              sorted list of distinct CVE IDs
        hosts:             sorted list of distinct hostnames
        versions:          sorted list of distinct software labels
        kev_findings:      findings that are in KEV
        critical_findings: findings whose VulnHQ tier is "Critical"
        risk_removed:      sum of risk_score, rounded to 1 decimal

    patch_impact(items, package) -> dict   (answers Q8, "what would patching X reduce?")
        package matching ignores upper/lower case.
        Returns:
            "package":          the package name as asked
            "hosts":            sorted distinct hostnames that have the package
            "findings_before":  len(items)
            "findings_after":   findings left after removing that package's findings
            "cves_before":      distinct CVE IDs across all items
            "cves_after":       distinct CVE IDs left after the patch
            "cves_removed":     cves_before - cves_after
        An unknown package removes nothing (before == after, hosts == []).

Until app/patch_plan.py exists, these tests are skipped.
"""

from dataclasses import dataclass

import pytest

pp = pytest.importorskip("app.patch_plan")
package_name = pp.package_name
patch_plan = pp.patch_plan
patch_impact = pp.patch_impact


@dataclass
class Item:
    software: str | None
    cve_id: str
    hostname: str
    in_kev: bool = False
    tier: str = "Medium"
    risk_score: float = 50.0


ITEMS = [
    Item("Apache HTTP Server 2.4.49", "CVE-2021-41773", "web01", True, "Critical", 90.0),
    Item("Apache HTTP Server 2.4.49", "CVE-2021-42013", "web01", True, "Critical", 88.0),
    Item("Apache HTTP Server 2.4.50", "CVE-2021-42013", "web02", True, "High", 70.0),
    Item("OpenSSL 1.0.2k", "CVE-2022-0778", "web01", False, "High", 60.0),
    Item("OpenSSL 1.1.1", "CVE-2022-0778", "db01", False, "Medium", 40.0),
    Item("Log4j 2.14.1", "CVE-2021-44228", "app01", True, "Critical", 95.0),
]


# ---------- package_name ----------

@pytest.mark.parametrize("label, expected", [
    ("Apache HTTP Server 2.4.49", "Apache HTTP Server"),
    ("OpenSSL 1.0.2k", "OpenSSL"),
    ("Log4j 2.14.1", "Log4j"),
    ("Microsoft Exchange Server", "Microsoft Exchange Server"),
    (None, "Unknown"),
    ("", "Unknown"),
])
def test_package_name(label, expected):
    assert package_name(label) == expected


# ---------- patch_plan ----------

def test_one_row_per_package():
    plan = patch_plan(ITEMS)
    # Apache (3 KEV), Log4j (1 KEV), then OpenSSL (0 KEV)
    assert [p.package for p in plan] == ["Apache HTTP Server", "Log4j", "OpenSSL"]


def test_most_kev_findings_first():
    plan = patch_plan(ITEMS)
    assert [p.kev_findings for p in plan] == [3, 1, 0]


def test_kev_package_beats_bigger_non_kev_total():
    # Many unreviewed, non-KEV findings must not outrank one KEV flaw
    items = [Item("Python 3.8", f"CVE-P{n}", "h1", False, "High", 60.0) for n in range(10)]
    items.append(Item("Log4j 2.14.1", "CVE-2021-44228", "h2", True, "Critical", 95.0))
    plan = patch_plan(items)
    assert plan[0].package == "Log4j"
    assert plan[1].risk_removed == 600.0   # Python: bigger total, but no KEV


def test_same_kev_count_biggest_risk_removed_first():
    items = [Item("Small 1", "CVE-1", "h1", True, risk_score=40.0),
             Item("Big 1", "CVE-2", "h1", True, risk_score=90.0)]
    assert [p.package for p in patch_plan(items)] == ["Big", "Small"]


def test_package_counts():
    apache = patch_plan(ITEMS)[0]
    assert apache.findings == 3
    assert apache.cves == ["CVE-2021-41773", "CVE-2021-42013"]
    assert apache.hosts == ["web01", "web02"]
    assert apache.versions == ["Apache HTTP Server 2.4.49", "Apache HTTP Server 2.4.50"]
    assert apache.kev_findings == 3
    assert apache.critical_findings == 2


def test_risk_removed_is_rounded():
    items = [Item("Foo 1.0", "CVE-1", "h1", risk_score=10.04),
             Item("Foo 1.0", "CVE-2", "h1", risk_score=10.03)]
    assert patch_plan(items)[0].risk_removed == 20.1


def test_ties_sorted_by_name():
    items = [Item("Zeta 1", "CVE-1", "h1", risk_score=50.0),
             Item("Alpha 1", "CVE-2", "h1", risk_score=50.0)]
    assert [p.package for p in patch_plan(items)] == ["Alpha", "Zeta"]


def test_empty_list():
    assert patch_plan([]) == []


# ---------- patch_impact ----------

def test_patching_apache():
    r = patch_impact(ITEMS, "Apache HTTP Server")
    assert r["hosts"] == ["web01", "web02"]
    assert r["findings_before"] == 6
    assert r["findings_after"] == 3
    assert r["cves_before"] == 4
    assert r["cves_after"] == 2
    assert r["cves_removed"] == 2


def test_case_does_not_matter():
    assert patch_impact(ITEMS, "apache http server")["cves_removed"] == 2


def test_unknown_package_removes_nothing():
    r = patch_impact(ITEMS, "Nginx")
    assert r["hosts"] == []
    assert r["findings_after"] == r["findings_before"] == 6
    assert r["cves_removed"] == 0
