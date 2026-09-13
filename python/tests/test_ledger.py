"""
The ledger.

Deliberately dumb -- a set of counters -- but two of its properties are load
bearing: the snapshot must be a copy (the engine is pure and must not be able
to mutate live state through it), and the clock must start at the first
metered event rather than at construction.
"""

from __future__ import annotations

import pytest
from helpers import T0
from toolwrit.budget.ledger import Ledger, TokenPrice


class TestLedger:
    def test_starts_empty(self) -> None:
        usage = Ledger().snapshot()
        assert (usage.calls, usage.tokens, usage.usd, usage.started_at) == (0, 0, 0, None)

    def test_the_snapshot_is_a_copy_the_caller_cannot_mutate_state_through(self) -> None:
        ledger = Ledger()
        snapshot = ledger.snapshot()
        snapshot.calls = 999
        assert ledger.snapshot().calls == 0

    def test_count_call_increments_and_starts_the_clock(self) -> None:
        ledger = Ledger()
        ledger.count_call(T0)
        ledger.count_call(T0 + 5000)
        usage = ledger.snapshot()
        assert usage.calls == 2
        assert usage.started_at == T0, "the clock starts at the FIRST metered event"

    def test_add_tokens_accumulates_tokens_and_cost(self) -> None:
        ledger = Ledger()
        ledger.add_tokens(100, 0.5, T0)
        ledger.add_tokens(50, 0.25, T0 + 1)
        usage = ledger.snapshot()
        assert usage.tokens == 150
        assert usage.usd == 0.75

    def test_add_usage_derives_cost_from_the_price_table(self) -> None:
        ledger = Ledger()
        ledger.add_usage(1000, 500, TokenPrice(input=0.003, output=0.015), T0)
        usage = ledger.snapshot()
        assert usage.tokens == 1500
        assert abs(usage.usd - 0.0105) < 1e-12

    def test_add_usage_without_a_price_table_is_free(self) -> None:
        ledger = Ledger()
        ledger.add_usage(10, 20, None, T0)
        assert (ledger.snapshot().tokens, ledger.snapshot().usd) == (30, 0)

    def test_add_spend_accumulates_non_token_cost(self) -> None:
        ledger = Ledger()
        ledger.add_spend(0.25, T0)
        ledger.add_spend(0.25, T0 + 1)
        assert ledger.snapshot().usd == 0.5

    def test_reset_clears_every_counter_including_the_clock(self) -> None:
        ledger = Ledger()
        ledger.count_call(T0)
        ledger.add_tokens(10, 1, T0)
        ledger.reset()
        usage = ledger.snapshot()
        assert (usage.calls, usage.tokens, usage.usd, usage.started_at) == (0, 0, 0, None)


class TestPriceCoercion:
    """
    The reference docs show a price as an object literal, so a reader porting
    that example passes a dict. Accepting it is the difference between the
    quickstart working and an AttributeError from inside the ledger.
    """

    def test_accepts_a_plain_mapping(self):
        from toolwrit.budget.ledger import Ledger

        ledger = Ledger()
        ledger.add_usage(1000, 500, {"input": 0.003, "output": 0.015}, at=0)
        assert ledger.snapshot().usd == pytest.approx(0.003 + 0.0075)

    def test_mapping_and_dataclass_agree(self):
        from toolwrit.budget.ledger import Ledger, TokenPrice

        a, b = Ledger(), Ledger()
        a.add_usage(1234, 567, {"input": 0.01, "output": 0.02}, at=0)
        b.add_usage(1234, 567, TokenPrice(input=0.01, output=0.02), at=0)
        assert a.snapshot().usd == b.snapshot().usd

    def test_a_partial_mapping_defaults_the_missing_side_to_zero(self):
        from toolwrit.budget.ledger import Ledger

        ledger = Ledger()
        ledger.add_usage(1000, 1000, {"input": 0.005}, at=0)
        assert ledger.snapshot().usd == pytest.approx(0.005)

    def test_rejects_a_misspelled_key_rather_than_pricing_it_at_zero(self):
        from toolwrit.budget.ledger import Ledger

        # Silently pricing a typo at zero would under-report spend, which is
        # the direction that lets a budget ceiling never fire.
        with pytest.raises(TypeError, match="unknown price key"):
            Ledger().add_usage(1000, 0, {"imput": 0.003}, at=0)

    def test_rejects_a_wholly_wrong_type(self):
        from toolwrit.budget.ledger import Ledger

        with pytest.raises(TypeError, match="must be a TokenPrice or a mapping"):
            Ledger().add_usage(1000, 0, 0.003, at=0)  # type: ignore[arg-type]
