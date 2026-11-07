"""Tests for the CISA BOD 26-04 tier function.

These tests describe the function before it exists. Build it in app/bod.py:

    bod_tier(exposed, in_kev, automatable, impact) -> BodResult
        exposed:     True, False or None (None = unknown)
        in_kev:      True or False
        automatable: True, False or None (None = unknown)
        impact:      "total", "partial" or None (None = unknown); case doesn't matter
        Raises ValueError for any other impact value.

    BodResult (dataclass) fields:
        tier:            1 to 5 (1 is most urgent)
        label:           e.g. "3 days & forensic triage", "Fix on system upgrade"
        days:            3, 14, 60, or None for "Fix on system upgrade"
        forensic_triage: True only for tier 1
        row:             Table 1 row number (1 to 16), or None if any value was assumed
        assumed:         list of unknown fields, in this order:
                         ["publicly_exposed", "automatable", "technical_impact"]

    bod_due_date(first_seen, kev_date_added, days) -> date or None
        Clock starts on the earlier of the two dates (kev_date_added may be None).
        Returns None when days is None (fix on system upgrade).

Rows come from backend/data/bod2604_matrix.json. The CISA_TABLE_1 list below is
typed in separately from the CISA table image, so a bad edit to the JSON file fails a test.
Unknown values follow SRS FR-PRI-08: try every possible value and keep the most urgent tier.

Until app/bod.py exists, these tests are skipped.
"""

import json
from datetime import date
from pathlib import Path

import pytest

bod = pytest.importorskip("app.bod")
bod_tier = bod.bod_tier
bod_due_date = bod.bod_due_date

MATRIX_PATH = Path(__file__).resolve().parents[1] / "data" / "bod2604_matrix.json"

Y, N = True, False

# CISA BOD 26-04, Appendix A, Table 1
# (row, publicly exposed, in KEV, automatable, technical impact, tier)
CISA_TABLE_1 = [
    (1, Y, Y, Y, "total", 1),
    (2, Y, Y, Y, "partial", 2),
    (3, Y, Y, N, "total", 1),
    (4, Y, Y, N, "partial", 3),
    (5, Y, N, Y, "total", 2),
    (6, Y, N, Y, "partial", 3),
    (7, Y, N, N, "total", 3),
    (8, Y, N, N, "partial", 4),
    (9, N, Y, Y, "total", 1),
    (10, N, Y, Y, "partial", 3),
    (11, N, Y, N, "total", 3),
    (12, N, Y, N, "partial", 3),
    (13, N, N, Y, "total", 4),
    (14, N, N, Y, "partial", 4),
    (15, N, N, N, "total", 5),
    (16, N, N, N, "partial", 5),
]

# tier: (label, days, forensic triage)
TIERS = {
    1: ("3 days & forensic triage", 3, True),
    2: ("3 days", 3, False),
    3: ("14 days", 14, False),
    4: ("60 days", 60, False),
    5: ("Fix on system upgrade", None, False),
}


# ---------- Matrix file ----------


def test_matrix_file_matches_cisa_table():
    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    rows = [
        (r["row"], r["publicly_exposed"], r["in_kev"], r["automatable"], r["technical_impact"], r["tier"])
        for r in matrix["rows"]
    ]
    assert rows == CISA_TABLE_1


def test_matrix_file_tier_details():
    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    for tier, (label, days, triage) in TIERS.items():
        t = matrix["tiers"][str(tier)]
        assert (t["label"], t["days"], t["forensic_triage"]) == (label, days, triage)


# ---------- Known values: every row of Table 1 ----------


@pytest.mark.parametrize("row, exposed, kev, auto, impact, tier", CISA_TABLE_1)
def test_every_table_row(row, exposed, kev, auto, impact, tier):
    result = bod_tier(exposed, kev, auto, impact)
    label, days, triage = TIERS[tier]
    assert result.tier == tier
    assert result.label == label
    assert result.days == days
    assert result.forensic_triage is triage
    assert result.row == row
    assert result.assumed == []


# ---------- Rows worth calling out in the demo ----------


def test_row_1_exposed_kev_automatable_total():
    result = bod_tier(True, True, True, "total")
    assert result.tier == 1
    assert result.days == 3
    assert result.forensic_triage is True


def test_row_5_not_in_kev_can_still_be_3_days():
    # Exposed + automatable + total control is 3 days even without KEV
    result = bod_tier(True, False, True, "total")
    assert result.tier == 2
    assert result.days == 3
    assert result.forensic_triage is False


def test_row_11_internal_kev_total_is_14_days():
    # The SRS correction: KEV + total control is NOT always 3 days.
    # Internal and not automatable gets 14 days.
    result = bod_tier(False, True, False, "total")
    assert result.tier == 3
    assert result.days == 14
    assert result.forensic_triage is False


def test_row_16_nothing_met_is_fix_on_upgrade():
    result = bod_tier(False, False, False, "partial")
    assert result.tier == 5
    assert result.label == "Fix on system upgrade"
    assert result.days is None


# ---------- Unknown values (SRS FR-PRI-08) ----------


def test_unknown_exposure_uses_worst_case():
    # Exposed would be row 3 (tier 1); internal would be row 11 (tier 3)
    result = bod_tier(None, True, False, "total")
    assert result.tier == 1
    assert result.forensic_triage is True
    assert result.assumed == ["publicly_exposed"]
    assert result.row is None


def test_unknown_exposure_still_flagged_when_lower_tier():
    # Exposed would be row 8 (60 days); internal would be row 16 (upgrade)
    result = bod_tier(None, False, False, "partial")
    assert result.tier == 4
    assert result.days == 60
    assert result.assumed == ["publicly_exposed"]


def test_unknown_automatable():
    # Automatable would be row 10 (tier 3); not automatable would be row 12 (tier 3)
    result = bod_tier(False, True, None, "partial")
    assert result.tier == 3
    assert result.assumed == ["automatable"]
    assert result.row is None


def test_unknown_impact():
    # Total would be row 9 (tier 1); partial would be row 10 (tier 3)
    result = bod_tier(False, True, True, None)
    assert result.tier == 1
    assert result.assumed == ["technical_impact"]


def test_all_unknown_not_in_kev():
    # Worst case is row 5: exposed + automatable + total
    result = bod_tier(None, False, None, None)
    assert result.tier == 2
    assert result.days == 3
    assert result.assumed == ["publicly_exposed", "automatable", "technical_impact"]


def test_all_unknown_in_kev():
    result = bod_tier(None, True, None, None)
    assert result.tier == 1
    assert result.forensic_triage is True


# ---------- Input handling ----------


def test_impact_is_case_insensitive():
    assert bod_tier(True, True, True, "Total").tier == 1
    assert bod_tier(True, True, True, "PARTIAL").tier == 2


def test_invalid_impact_raises():
    with pytest.raises(ValueError):
        bod_tier(True, True, True, "high")


# ---------- Due dates ----------


def test_due_date_starts_at_kev_date_when_earlier():
    # CVE added to KEV before we found it on the asset
    assert bod_due_date(date(2026, 11, 10), date(2026, 11, 1), 14) == date(2026, 11, 15)


def test_due_date_starts_at_first_seen_when_earlier():
    # Found on the asset before CISA added it to KEV
    assert bod_due_date(date(2026, 11, 1), date(2026, 11, 10), 3) == date(2026, 11, 4)


def test_due_date_without_kev():
    assert bod_due_date(date(2026, 11, 1), None, 60) == date(2026, 12, 31)


def test_fix_on_upgrade_has_no_due_date():
    assert bod_due_date(date(2026, 11, 1), None, None) is None
