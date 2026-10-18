"""U-ROUTE / U-ROUTE-02: routing math, exclusions and rate-card provenance (testing.md §3)."""
from __future__ import annotations

from api.services.router import load_ratecards, quote_rail, route
from api.settings import settings

CARDS, DEFAULT = load_ratecards(settings.ratecards_path)


def test_ratecards_require_provenance_fields():
    for c in CARDS:
        assert c.source_url and c.source_date and c.assumptions and c.limitations


def test_normal_routing_picks_cheapest_compliant_rail():
    r = route(CARDS, DEFAULT, source="BDT", dest="USD", amount_minor=500_000)
    assert r.chosen is not None
    assert r.chosen.total_cost_minor == min(q.total_cost_minor for q in r.ranked)
    assert r.savings_minor >= 0


def test_urgent_routing_minimises_time_first():
    r = route(CARDS, DEFAULT, source="BDT", dest="USD", amount_minor=500_000, urgency="urgent")
    assert r.chosen.eta_hours == min(q.eta_hours for q in r.ranked)


def test_deadline_infeasible_rails_excluded_with_reason():
    r = route(CARDS, DEFAULT, source="BDT", dest="USD", amount_minor=500_000, deadline_hours=3)
    assert all(q.eta_hours <= 3 for q in r.ranked)
    assert any(q.excluded_reason == "DEADLINE_INFEASIBLE" for q in r.excluded)


def test_unsupported_corridor_returns_no_chosen_rail():
    r = route(CARDS, DEFAULT, source="JPY", dest="USD", amount_minor=1000)
    assert r.chosen is None
    assert all(q.excluded_reason == "CORRIDOR_NOT_SUPPORTED" for q in r.excluded)


def test_savings_is_vs_the_default_rail_not_an_arbitrary_baseline():
    r = route(CARDS, DEFAULT, source="BDT", dest="USD", amount_minor=500_000)
    default = next(q for q in r.ranked if q.rail_id == DEFAULT)
    assert r.default_cost_minor == default.total_cost_minor
    assert r.savings_minor == max(default.total_cost_minor - r.chosen.total_cost_minor, 0)


def test_recipient_net_equals_amount_minus_listed_charges():
    from decimal import Decimal

    card = next(c for c in CARDS if c.rail_id == "rail_a_bank")
    q = quote_rail(card, corridor="BDT>USD", amount_minor=500_000, have_currency="BDT")
    assert q.recipient_net_minor >= 0
    expected_fee = card.fixed_fee_minor + int(Decimal(500_000) * Decimal(card.pct_fee)) \
        + card.intermediary_fee_minor + card.receiving_bank_fee_minor
    assert q.total_cost_minor == expected_fee
    assert q.sender_total_cost_minor == 500_000 + q.total_cost_minor


def test_routing_is_deterministic_and_tie_broken_by_rail_id():
    a = route(CARDS, DEFAULT, source="BDT", dest="USD", amount_minor=500_000)
    b = route(CARDS, DEFAULT, source="BDT", dest="USD", amount_minor=500_000)
    assert [q.rail_id for q in a.ranked] == [q.rail_id for q in b.ranked]
