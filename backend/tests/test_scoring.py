from datetime import date

from app.scoring import WEIGHTS, ScoreInput, calculate_score, due_date, get_tier


def test_weights_total_100():
    assert sum(WEIGHTS.values()) == 100


def test_worked_example_from_docs():
    # docs/scoring.md example: KEV, ransomware, EPSS 0.94, crit 5, internet, outbound, confidential
    result = calculate_score(
        ScoreInput(
            in_kev=True,
            epss=0.94,
            ransomware=True,
            criticality=5,
            internet_facing=True,
            money_movement="outbound_payments",
            data_classification="confidential",
        )
    )
    assert result.score == 98.8
    assert result.tier == "Critical"
    assert result.sla_days == 7


def test_minimum_score_is_low():
    result = calculate_score(ScoreInput(criticality=1))
    assert result.score == 4.0
    assert result.tier == "Low"
    assert result.sla_days == 90


def test_money_movement_levels():
    base = dict(criticality=1)
    none = calculate_score(ScoreInput(**base, money_movement="none")).score
    internal = calculate_score(ScoreInput(**base, money_movement="internal_transfers")).score
    outbound = calculate_score(ScoreInput(**base, money_movement="outbound_payments")).score
    assert internal - none == 5
    assert outbound - none == 10


def test_internet_facing_and_money_movement_are_independent():
    marketing = calculate_score(ScoreInput(internet_facing=True, money_movement="none"))
    wires = calculate_score(ScoreInput(internet_facing=False, money_movement="outbound_payments"))
    assert marketing.breakdown["internet_facing"] == 10
    assert marketing.breakdown["money_movement"] == 0
    assert wires.breakdown["internet_facing"] == 0
    assert wires.breakdown["money_movement"] == 10


def test_missing_epss_counts_as_zero():
    result = calculate_score(ScoreInput(in_kev=True, epss=None))
    assert result.breakdown["epss"] == 0


def test_tier_boundaries():
    assert get_tier(80) == ("Critical", 7)
    assert get_tier(79.9) == ("High", 30)
    assert get_tier(60) == ("High", 30)
    assert get_tier(40) == ("Medium", 60)
    assert get_tier(39.9) == ("Low", 90)


def test_due_date():
    assert due_date(date(2026, 11, 5), 7) == date(2026, 11, 12)
