"""VulnHQ Risk Score: weights, tiers and scoring logic.

All tunable values live at the top of this file. See docs/scoring.md.
This module has no database imports so it can be unit tested on its own.
"""

from dataclasses import dataclass
from datetime import date, timedelta

# ---------- Weights (must total 100) ----------
WEIGHTS = {
    "kev": 25,
    "epss": 20,
    "ransomware": 10,
    "criticality": 20,
    "internet_facing": 10,
    "money_movement": 10,
    "sensitive_data": 5,
}

MONEY_MOVEMENT_POINTS = {
    "none": 0,
    "internal_transfers": 5,
    "outbound_payments": 10,
}

SENSITIVE_CLASSIFICATIONS = {"confidential", "restricted"}

# ---------- Tiers: (minimum score, tier name, days to fix) ----------
TIERS = [
    (80, "Critical", 7),
    (60, "High", 30),
    (40, "Medium", 60),
    (0, "Low", 90),
]


@dataclass
class ScoreInput:
    in_kev: bool = False
    epss: float | None = None
    ransomware: bool = False
    criticality: int = 3
    internet_facing: bool = False
    money_movement: str = "none"
    data_classification: str | None = None


@dataclass
class ScoreResult:
    score: float
    tier: str
    sla_days: int
    breakdown: dict[str, float]


def calculate_score(item: ScoreInput) -> ScoreResult:
    # Each factor's points, so the UI can show why a finding ranks high
    criticality = max(1, min(5, item.criticality))
    breakdown = {
        "kev": WEIGHTS["kev"] if item.in_kev else 0,
        "epss": round((item.epss or 0) * WEIGHTS["epss"], 1),
        "ransomware": WEIGHTS["ransomware"] if item.ransomware else 0,
        "criticality": criticality / 5 * WEIGHTS["criticality"],
        "internet_facing": WEIGHTS["internet_facing"] if item.internet_facing else 0,
        "money_movement": MONEY_MOVEMENT_POINTS.get(item.money_movement, 0),
        "sensitive_data": WEIGHTS["sensitive_data"]
        if (item.data_classification or "").lower() in SENSITIVE_CLASSIFICATIONS
        else 0,
    }
    score = round(min(100, sum(breakdown.values())), 1)
    tier, sla_days = get_tier(score)
    return ScoreResult(score=score, tier=tier, sla_days=sla_days, breakdown=breakdown)


def get_tier(score: float) -> tuple[str, int]:
    for minimum, name, days in TIERS:
        if score >= minimum:
            return name, days
    return TIERS[-1][1], TIERS[-1][2]


def due_date(first_seen: date, sla_days: int) -> date:
    return first_seen + timedelta(days=sla_days)
