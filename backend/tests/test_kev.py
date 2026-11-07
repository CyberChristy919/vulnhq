"""Tests for the KEV past-due flag and KPI card (SRS FR-PRI-03, Q5).

These tests describe the code before it exists. Build it in app/kev.py:

    kev_status(in_kev, kev_date_added, kev_due_date, as_of) -> KevStatus
        as_of: the date to measure against (pass date.today() in the app)

    KevStatus (dataclass) fields:
        label:         "Not in KEV", "Past due", or "Due <YYYY-MM-DD>"
        past_due:      True only when kev_due_date is earlier than as_of
                       (due today is NOT past due)
        days_overdue:  whole days past the due date, or None if not past due
        days_left:     days until the due date (0 = due today), or None if past due or not in KEV
        due_date_set_under: "BOD 22-01" if CISA added the CVE to KEV before 2026-06-10,
                            "BOD 26-04" on or after that date, None if not in KEV

    kev_kpi(items, as_of) -> dict
        items: open findings; each has .in_kev, .kev_date_added, .kev_due_date, .hostname
        Returns:
            "kev_past_due_findings": count of findings with past_due True
            "kev_past_due_assets":   count of distinct hostnames with a past-due finding
            "oldest_days_overdue":   largest days_overdue, or None if nothing is past due

The KEV past-due flag is separate from the VulnHQ SLA "overdue" flag. A finding
can be KEV past due while still inside its VulnHQ SLA, and the other way around.

Then add kev_due_date, kev_past_due and kev_days_overdue to FixListItem, and add
the three KPI values to /stats.

Until app/kev.py exists, these tests are skipped.
"""

from dataclasses import dataclass
from datetime import date

import pytest

kev = pytest.importorskip("app.kev")
kev_status = kev.kev_status
kev_kpi = kev.kev_kpi

AS_OF = date(2026, 11, 9)  # demo day
BOD_26_04_ISSUED = date(2026, 6, 10)


@dataclass
class Item:
    hostname: str
    in_kev: bool
    kev_date_added: date | None = None
    kev_due_date: date | None = None


# ---------- kev_status: past-due flag ----------


def test_not_in_kev():
    s = kev_status(False, None, None, AS_OF)
    assert s.label == "Not in KEV"
    assert s.past_due is False
    assert s.days_overdue is None
    assert s.days_left is None
    assert s.due_date_set_under is None


def test_past_due():
    s = kev_status(True, date(2026, 10, 1), date(2026, 10, 22), AS_OF)
    assert s.label == "Past due"
    assert s.past_due is True
    assert s.days_overdue == 18
    assert s.days_left is None


def test_due_today_is_not_past_due():
    s = kev_status(True, date(2026, 10, 26), AS_OF, AS_OF)
    assert s.past_due is False
    assert s.days_overdue is None
    assert s.days_left == 0
    assert s.label == "Due 2026-11-09"


def test_due_yesterday_is_one_day_overdue():
    s = kev_status(True, date(2026, 10, 25), date(2026, 11, 8), AS_OF)
    assert s.past_due is True
    assert s.days_overdue == 1


def test_due_in_future():
    s = kev_status(True, date(2026, 11, 5), date(2026, 11, 19), AS_OF)
    assert s.past_due is False
    assert s.days_left == 10
    assert s.label == "Due 2026-11-19"


def test_log4shell_is_years_overdue():
    # Log4Shell: added 2021-12-10, due 2021-12-24 under BOD 22-01
    s = kev_status(True, date(2021, 12, 10), date(2021, 12, 24), AS_OF)
    assert s.past_due is True
    assert s.days_overdue == (AS_OF - date(2021, 12, 24)).days
    assert s.due_date_set_under == "BOD 22-01"


def test_in_kev_without_due_date_is_not_past_due():
    # Bad or partial feed data: don't invent a past-due flag
    s = kev_status(True, date(2026, 11, 1), None, AS_OF)
    assert s.past_due is False
    assert s.days_overdue is None


# ---------- kev_status: which directive set the due date ----------


def test_added_before_bod_26_04_is_bod_22_01():
    s = kev_status(True, date(2026, 6, 9), date(2026, 6, 30), AS_OF)
    assert s.due_date_set_under == "BOD 22-01"


def test_added_on_bod_26_04_issue_date_is_bod_26_04():
    s = kev_status(True, BOD_26_04_ISSUED, date(2026, 6, 24), AS_OF)
    assert s.due_date_set_under == "BOD 26-04"


def test_added_after_bod_26_04_is_bod_26_04():
    s = kev_status(True, date(2026, 11, 1), date(2026, 11, 15), AS_OF)
    assert s.due_date_set_under == "BOD 26-04"


# ---------- kev_kpi: dashboard card ----------


def test_kpi_counts_findings_and_assets():
    items = [
        Item("fin-srv-001", True, date(2021, 12, 10), date(2021, 12, 24)),  # past due
        Item("fin-srv-001", True, date(2021, 10, 1), date(2021, 11, 1)),  # past due, same host
        Item("eng-srv-002", True, date(2026, 10, 1), date(2026, 10, 22)),  # past due
        Item("hr-ws-001", True, date(2026, 11, 5), date(2026, 11, 19)),  # not yet due
        Item("it-net-001", False),  # not in KEV
    ]
    kpi = kev_kpi(items, AS_OF)
    assert kpi["kev_past_due_findings"] == 3
    assert kpi["kev_past_due_assets"] == 2
    assert kpi["oldest_days_overdue"] == (AS_OF - date(2021, 11, 1)).days


def test_kpi_nothing_past_due():
    items = [
        Item("hr-ws-001", True, date(2026, 11, 5), date(2026, 11, 19)),
        Item("it-net-001", False),
    ]
    kpi = kev_kpi(items, AS_OF)
    assert kpi["kev_past_due_findings"] == 0
    assert kpi["kev_past_due_assets"] == 0
    assert kpi["oldest_days_overdue"] is None


def test_kpi_empty_list():
    kpi = kev_kpi([], AS_OF)
    assert kpi == {
        "kev_past_due_findings": 0,
        "kev_past_due_assets": 0,
        "oldest_days_overdue": None,
    }


def test_kpi_due_today_not_counted():
    kpi = kev_kpi([Item("fin-srv-001", True, date(2026, 10, 26), AS_OF)], AS_OF)
    assert kpi["kev_past_due_findings"] == 0


def test_kpi_uses_as_of_date():
    # Same data, different as-of date: past due changes
    items = [Item("fin-srv-001", True, date(2026, 10, 26), date(2026, 11, 9))]
    assert kev_kpi(items, date(2026, 11, 9))["kev_past_due_findings"] == 0
    assert kev_kpi(items, date(2026, 11, 10))["kev_past_due_findings"] == 1


# ---------- Fix list fields ----------


def test_fix_list_item_has_kev_fields():
    from app.schemas import FixListItem

    fields = FixListItem.model_fields
    for name in ("kev_due_date", "kev_past_due", "kev_days_overdue"):
        assert name in fields, f"FixListItem is missing {name}"
    # Keep the VulnHQ SLA flag separate from the KEV flag
    assert "overdue" in fields
