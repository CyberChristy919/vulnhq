"""Edge cases for KEV past-due status and BOD 26-04 deadlines (issue #2).

These tests describe the current behavior of app/kev.py and app/bod.py so a
change to deadlines can't break silently. They add boundary, missing-data and
unknown-value cases on top of tests/test_kev.py and tests/test_bod.py.
"""

from dataclasses import dataclass
from datetime import date
from itertools import product

import pytest

from app.bod import bod_due_date, bod_tier
from app.kev import kev_kpi, kev_status
from tests.test_bod import CISA_TABLE_1

AS_OF = date(2026, 11, 9)


@dataclass
class Item:
    hostname: str
    in_kev: bool
    kev_date_added: date | None = None
    kev_due_date: date | None = None


# ---------- kev_status: one day either side of the due date ----------


@pytest.mark.parametrize(
    "due, past_due, days_overdue, days_left",
    [
        (date(2026, 11, 8), True, 1, None),  # due yesterday
        (date(2026, 11, 9), False, None, 0),  # due today
        (date(2026, 11, 10), False, None, 1),  # due tomorrow
    ],
)
def test_one_day_either_side_of_due_date(due, past_due, days_overdue, days_left):
    s = kev_status(True, date(2026, 10, 1), due, AS_OF)
    assert s.past_due is past_due
    assert s.days_overdue == days_overdue
    assert s.days_left == days_left


def test_overdue_across_year_end():
    s = kev_status(True, date(2026, 12, 10), date(2026, 12, 31), date(2027, 1, 1))
    assert s.past_due is True
    assert s.days_overdue == 1


def test_overdue_counts_leap_day():
    # 2028 is a leap year, so Feb 28 to Mar 1 is 2 days
    s = kev_status(True, date(2028, 2, 1), date(2028, 2, 28), date(2028, 3, 1))
    assert s.days_overdue == 2


def test_due_on_leap_day_is_not_past_due_that_day():
    s = kev_status(True, date(2028, 2, 1), date(2028, 2, 29), date(2028, 2, 29))
    assert s.past_due is False
    assert s.days_left == 0
    assert s.label == "Due 2028-02-29"


# ---------- kev_status: missing data ----------


def test_missing_date_added_still_flags_past_due():
    s = kev_status(True, None, date(2026, 10, 1), AS_OF)
    assert s.past_due is True
    assert s.days_overdue == 39
    assert s.due_date_set_under is None


def test_missing_date_added_and_due_date():
    s = kev_status(True, None, None, AS_OF)
    assert s.label == "In KEV (no due date)"
    assert s.past_due is False
    assert s.days_left is None
    assert s.due_date_set_under is None


def test_no_due_date_still_reports_directive():
    s = kev_status(True, date(2026, 11, 1), None, AS_OF)
    assert s.label == "In KEV (no due date)"
    assert s.due_date_set_under == "BOD 26-04"


def test_not_in_kev_ignores_leftover_kev_dates():
    # Stale KEV fields on a CVE that isn't in KEV must not raise a flag
    s = kev_status(False, date(2021, 12, 10), date(2021, 12, 24), AS_OF)
    assert s.label == "Not in KEV"
    assert s.past_due is False
    assert s.days_overdue is None
    assert s.due_date_set_under is None


# ---------- kev_status: BOD 22-01 vs BOD 26-04 ----------


def test_directive_follows_date_added_not_due_date():
    # Added under BOD 22-01, due after BOD 26-04 was issued: still BOD 22-01
    s = kev_status(True, date(2026, 6, 1), date(2026, 6, 22), AS_OF)
    assert s.due_date_set_under == "BOD 22-01"
    assert s.past_due is True


# ---------- kev_kpi ----------


def test_kpi_counts_each_finding_but_each_host_once():
    items = [
        Item("web-01", True, date(2026, 9, 1), date(2026, 9, 22)),  # 48 days over
        Item("web-01", True, date(2026, 10, 1), date(2026, 10, 22)),  # 18 days over
    ]
    assert kev_kpi(items, AS_OF) == {
        "kev_past_due_findings": 2,
        "kev_past_due_assets": 1,
        "oldest_days_overdue": 48,
    }


def test_kpi_skips_not_in_kev_and_missing_due_dates():
    items = [
        Item("db-01", False, date(2021, 12, 10), date(2021, 12, 24)),  # not in KEV
        Item("db-02", True, date(2026, 10, 1), None),  # no due date
        Item("db-03", True, None, date(2026, 11, 8)),  # 1 day over, no date added
    ]
    assert kev_kpi(items, AS_OF) == {
        "kev_past_due_findings": 1,
        "kev_past_due_assets": 1,
        "oldest_days_overdue": 1,
    }


def test_kpi_due_tomorrow_and_today_not_counted():
    items = [
        Item("app-01", True, date(2026, 10, 26), date(2026, 11, 9)),
        Item("app-02", True, date(2026, 10, 27), date(2026, 11, 10)),
    ]
    assert kev_kpi(items, AS_OF)["kev_past_due_findings"] == 0


# ---------- bod_due_date ----------


def test_due_date_same_start_day():
    assert bod_due_date(date(2026, 11, 1), date(2026, 11, 1), 3) == date(2026, 11, 4)


def test_due_date_ignores_later_kev_date():
    # Seen first, added to KEV later: the clock still starts at first_seen
    assert bod_due_date(date(2026, 11, 1), date(2026, 11, 5), 14) == date(2026, 11, 15)


def test_due_date_across_leap_day():
    assert bod_due_date(date(2028, 2, 27), None, 3) == date(2028, 3, 1)


def test_due_date_60_days_across_year_end():
    assert bod_due_date(date(2026, 11, 15), None, 60) == date(2027, 1, 14)


def test_fix_on_upgrade_without_kev_date():
    assert bod_due_date(date(2026, 11, 1), None, None) is None


# ---------- bod_tier: unknown and unexpected values ----------


@pytest.mark.parametrize("impact", ["", "none", "high", " total"])
def test_unexpected_impact_raises(impact):
    with pytest.raises(ValueError):
        bod_tier(True, True, True, impact)


def test_impact_all_caps_partial():
    assert bod_tier(True, True, True, "PARTIAL").tier == 2


def test_unknown_automatable_keeps_most_urgent():
    # Internal, not in KEV, partial: row 14 (60 days) or row 16 (fix on upgrade)
    r = bod_tier(False, False, None, "partial")
    assert r.tier == 4
    assert r.days == 60
    assert r.row is None
    assert r.assumed == ["automatable"]


def test_unknown_values_listed_in_fixed_order():
    r = bod_tier(None, True, True, None)
    assert r.assumed == ["publicly_exposed", "technical_impact"]


# Tier for every known combination, from the CISA table typed in test_bod.py
KNOWN = {(e, k, a, i): tier for _, e, k, a, i, tier in CISA_TABLE_1}


@pytest.mark.parametrize(
    "exposed, in_kev, automatable, impact",
    list(product([True, False, None], [True, False], [True, False, None], ["total", "partial", None])),
)
def test_unknowns_never_less_urgent_than_any_possibility(exposed, in_kev, automatable, impact):
    # SRS FR-PRI-08: an unknown value takes the most urgent tier it could be
    options = [
        KNOWN[(e, in_kev, a, i)]
        for e in ([exposed] if exposed is not None else [True, False])
        for a in ([automatable] if automatable is not None else [True, False])
        for i in ([impact] if impact is not None else ["total", "partial"])
    ]
    r = bod_tier(exposed, in_kev, automatable, impact)
    assert r.tier == min(options)
    has_unknown = None in (exposed, automatable, impact)
    assert (r.row is None) is has_unknown
