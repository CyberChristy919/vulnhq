"""Tests for the board-level "Why this order" explanation.

These tests describe the code before it exists. Build it in app/explain.py:

    why_this_order(plan, limit=3) -> list[str]
        plan: the list from patch_plan(), already sorted
              (most KEV findings first, then most risk removed, then A to Z)
        Returns plain-language lines a board member can read:
            line 0:  the ordering rule (ORDER_RULE)
            then one line per package, up to `limit` packages
        An empty plan returns [].

    First package:
        KEV > 0:  "{package} first: {kev} actively exploited flaw(s) on {hosts} host(s)."
        KEV = 0:  "{package} first: no actively exploited flaws, so it leads on total risk ({risk})."

    Each later package, compared with the one just before it:
        Fewer KEV:      "{package} next: {kev} actively exploited flaw(s), fewer than {prev} ({prev_kev})."
            ...and if it removes MORE risk than the one before, add the trade-off:
                        " It removes more total risk ({risk} vs {prev_risk}), but exploited flaws come first."
        Same KEV:       "{package} next: tied on actively exploited flaws ({kev}), so total risk decides ({risk} vs {prev_risk})."
        Same KEV, same risk:
                        "{package} next: tied on exploited flaws and total risk, so listed A to Z."

    Numbers: 1 -> "flaw" / "host", anything else -> "flaws" / "hosts".
    Risk prints without a trailing .0: 95.0 -> "95", 95.5 -> "95.5".

Until app/explain.py exists, these tests are skipped.
"""

import pytest

from app.patch_plan import PackagePlan

ex = pytest.importorskip("app.explain")
why_this_order = ex.why_this_order
ORDER_RULE = ex.ORDER_RULE


def pkg(name, kev, risk, hosts=1):
    """A PackagePlan with only the fields the explanation uses filled in."""
    return PackagePlan(
        package=name, findings=kev or 1, cves=[], versions=[],
        hosts=[f"host{n}" for n in range(hosts)],
        kev_findings=kev, critical_findings=0, risk_removed=risk,
    )


# The same order patch_plan() gives for the ITEMS in test_patch_plan.py
PLAN = [
    pkg("Apache HTTP Server", 3, 248.0, hosts=2),
    pkg("Log4j", 1, 95.0),
    pkg("OpenSSL", 0, 100.0, hosts=2),
]


def test_empty_plan_has_no_explanation():
    assert why_this_order([]) == []


def test_first_line_is_the_rule():
    assert why_this_order(PLAN)[0] == ORDER_RULE
    assert ORDER_RULE == ("Order rule: most actively exploited flaws (CISA KEV) first, "
                          "then the most total risk removed.")


def test_first_package_with_kev():
    assert why_this_order(PLAN)[1] == "Apache HTTP Server first: 3 actively exploited flaws on 2 hosts."


def test_first_package_without_kev():
    lines = why_this_order([pkg("OpenSSL", 0, 100.0, hosts=2)])
    assert lines[1] == "OpenSSL first: no actively exploited flaws, so it leads on total risk (100)."


def test_fewer_kev_uses_singular():
    assert why_this_order(PLAN)[2] == "Log4j next: 1 actively exploited flaw, fewer than Apache HTTP Server (3)."


def test_fewer_kev_but_more_risk_shows_the_trade_off():
    assert why_this_order(PLAN)[3] == (
        "OpenSSL next: 0 actively exploited flaws, fewer than Log4j (1). "
        "It removes more total risk (100 vs 95), but exploited flaws come first."
    )


def test_tied_kev_so_risk_decides():
    plan = [pkg("Chrome", 2, 150.5), pkg("Java", 2, 120.0)]
    assert why_this_order(plan)[2] == (
        "Java next: tied on actively exploited flaws (2), so total risk decides (120 vs 150.5)."
    )


def test_tied_on_everything_is_alphabetical():
    plan = [pkg("Chrome", 1, 80.0), pkg("Firefox", 1, 80.0)]
    assert why_this_order(plan)[2] == "Firefox next: tied on exploited flaws and total risk, so listed A to Z."


def test_one_host_is_singular():
    assert why_this_order([pkg("Log4j", 1, 95.0)])[1] == "Log4j first: 1 actively exploited flaw on 1 host."


def test_limit_caps_the_number_of_packages():
    lines = why_this_order(PLAN, limit=2)
    assert len(lines) == 3  # the rule plus 2 packages
    assert why_this_order(PLAN, limit=1)[1].startswith("Apache HTTP Server first")
