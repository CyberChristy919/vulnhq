"""CISA KEV past-due status and dashboard KPI.

The KEV due date is CISA's published date. It is kept separate from the
VulnHQ SLA due date (SRS FR-PRI-03). No database imports, so it can be
unit tested on its own.
"""

from dataclasses import dataclass
from datetime import date

# BOD 26-04 issue date. KEV entries added before this had due dates set under BOD 22-01.
BOD_26_04_ISSUED = date(2026, 6, 10)

@dataclass
class KevStatus:
    label: str                       # "Not in KEV", "Past due", or "Due YYYY-MM-DD"
    past_due: bool
    days_overdue: int | None         # None unless past due
    days_left: int | None            # None if past due or not in KEV
    due_date_set_under: str | None   # "BOD 22-01", "BOD 26-04", or None

def kev_status(
    in_kev: bool,
    kev_date_added: date | None,
    kev_due_date: date | None,
    as_of: date,
) -> KevStatus:
    """Past-due status for one finding's KEV due date, measured against as_of."""
    # Not in KEV: nothing to flag
    if not in_kev:
        return KevStatus("Not in KEV", False, None, None, None)

    # Which directive set the due date, based on when CISA added the CVE
    if kev_date_added is None:
        set_under = None
    elif kev_date_added < BOD_26_04_ISSUED:
        set_under = "BOD 22-01"
    else:
        set_under = "BOD 26-04"

    # In KEV but the feed has no due date: don't invent a past-due flag
    if kev_due_date is None:
        return KevStatus("In KEV (no due date)", False, None, None, set_under)

    # Past due only when the due date is earlier than as_of; due today is not past due
    if kev_due_date < as_of:
        days_overdue = (as_of - kev_due_date).days
        return KevStatus("Past due", True, days_overdue, None, set_under)

    days_left = (kev_due_date - as_of).days
    return KevStatus(f"Due {kev_due_date.isoformat()}", False, None, days_left, set_under)

def kev_kpi(items, as_of: date) -> dict:
    """KEV past-due numbers for the dashboard card. items are open findings."""
    past_due_hosts = set()
    overdue_days = []

    for item in items:
        status = kev_status(item.in_kev, item.kev_date_added, item.kev_due_date, as_of)
        if status.past_due:
            past_due_hosts.add(item.hostname)
            overdue_days.append(status.days_overdue)

    return {
        "kev_past_due_findings": len(overdue_days),
        "kev_past_due_assets": len(past_due_hosts),
        "oldest_days_overdue": max(overdue_days) if overdue_days else None,
    }