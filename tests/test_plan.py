"""
The run plan: a declared envelope, approved once, reported against.

The plan is what makes capacity limits livable, so these tests pin the two
properties an operator actually relies on: that the approved envelope is in
the tamper-evident record before anything can be consumed, and that a
threshold reports exactly once -- an alert that repeats gets muted, and a
muted alert is the same as no alert.
"""

from __future__ import annotations

from typing import Callable

from leash.audit.verify import verify_chain
from leash.leash import Leash
from leash.policy.load import parse_policy
from leash.types import BudgetWarning, Policy

T0 = 1_788_998_400_000  # 2026-09-10T00:00:00Z


def make_policy(plan_yaml: str, budget_yaml: str = "calls: 10") -> Policy:
    return parse_policy(
        f'version: "1"\ndefault: allow\nbudget:\n  {budget_yaml}\n'
        f"plan:\n{plan_yaml}\nrules: []\n"
    )


def collect(
    p: Policy, now: Callable[[], int] | None = None
) -> tuple[Leash, list[BudgetWarning]]:
    warnings: list[BudgetWarning] = []
    leash = Leash(
        p,
        run="test-run",
        now=now or (lambda: T0),
        on_warn=warnings.append,
    )
    return leash, warnings


class TestTheApprovedEnvelopeIsRecordedFirst:
    def test_writes_the_plan_as_entry_one(self) -> None:
        leash, _ = collect(make_policy("  purpose: nightly sync\n  approvedBy: ergin"))
        first = leash.entries()[0]

        assert first.seq == 1
        assert first.tool == "leash:plan"
        assert first.args["purpose"] == "nightly sync"
        assert first.args["approvedBy"] == "ergin"
        assert first.args["budget"] == {"calls": 10}
        # Zero usage at the moment of approval is the point: the envelope is
        # committed before the run can spend against it.
        assert first.usage == {"calls": 0, "tokens": 0, "usd": 0, "bytes": 0}

    def test_records_the_defaults_it_will_actually_use(self) -> None:
        leash, _ = collect(make_policy("  purpose: p"))
        assert leash.entries()[0].args["warnAt"] == [0.8, 0.95]

    def test_records_approved_by_as_null_rather_than_omitting_it(self) -> None:
        leash, _ = collect(make_policy("  purpose: p"))
        assert leash.entries()[0].args["approvedBy"] is None

    def test_writes_no_plan_entry_when_the_policy_declares_no_plan(self) -> None:
        p = parse_policy('version: "1"\ndefault: allow\nrules: []\n')
        assert Leash(p, now=lambda: T0).entries() == []


class TestThresholdReporting:
    def test_fires_each_threshold_exactly_once(self) -> None:
        leash, warnings = collect(make_policy("  purpose: p\n  warnAt: [0.5, 0.9]"))
        for i in range(10):
            leash.guard("t", {}, lambda: i)

        calls = [w for w in warnings if w.dimension == "calls"]
        assert [w.threshold for w in calls] == [0.5, 0.9]
        assert [w.used for w in calls] == [5, 9]
        assert all(w.limit == 10 for w in calls)

    def test_sorts_thresholds_so_they_report_in_ascending_order(self) -> None:
        leash, warnings = collect(make_policy("  purpose: p\n  warnAt: [0.9, 0.2, 0.5]"))
        for i in range(10):
            leash.guard("t", {}, lambda: i)
        assert [w.threshold for w in warnings] == [0.2, 0.5, 0.9]

    def test_reports_each_budget_dimension_independently(self) -> None:
        p = make_policy("  purpose: p\n  warnAt: [0.5]", "calls: 10\n  tokens: 1000\n  usd: 2")
        leash, warnings = collect(p)

        leash.meter(400, 200)  # 600/1000 tokens
        leash.spend(1.5)       # 1.5/2 usd

        assert [(w.dimension, w.used) for w in warnings] == [("tokens", 600), ("usd", 1.5)]

    def test_measures_the_time_dimension_from_the_first_metered_event(self) -> None:
        clock = {"now": T0}
        p = make_policy("  purpose: p\n  warnAt: [0.5]", "seconds: 100")
        leash, warnings = collect(p, now=lambda: clock["now"])

        leash.spend(0)  # starts the clock, 0s elapsed
        assert warnings == []

        clock["now"] = T0 + 60_000  # 60s of a 100s envelope
        leash.spend(0)
        assert warnings[-1].dimension == "seconds"
        assert warnings[-1].used == 60

    def test_stays_silent_when_the_policy_has_a_budget_but_no_plan(self) -> None:
        p = parse_policy('version: "1"\ndefault: allow\nbudget:\n  calls: 10\nrules: []\n')
        warnings: list[BudgetWarning] = []
        leash = Leash(p, now=lambda: T0, on_warn=warnings.append)

        for i in range(9):
            leash.guard("t", {}, lambda: i)
        assert warnings == []

    def test_puts_every_warning_in_the_chain_which_still_verifies(self) -> None:
        leash, _ = collect(make_policy("  purpose: p\n  warnAt: [0.5, 0.9]"))
        for i in range(10):
            leash.guard("t", {}, lambda: i)

        warned = [e for e in leash.entries() if e.tool == "leash:warning"]
        assert len(warned) == 2
        assert warned[0].args["dimension"] == "calls"
        # The log answers "was anyone told" without depending on whether a Slack
        # message was actually delivered.
        assert verify_chain(leash.entries()).ok is True

    def test_does_not_require_an_on_warn_handler_to_record_the_warning(self) -> None:
        p = make_policy("  purpose: p\n  warnAt: [0.5]")
        leash = Leash(p, run="r", now=lambda: T0)
        for i in range(6):
            leash.guard("t", {}, lambda: i)
        assert any(e.tool == "leash:warning" for e in leash.entries())

    def test_the_message_formats_numbers_the_way_the_typescript_does(self) -> None:
        p = make_policy("  purpose: p\n  warnAt: [0.5]", "tokens: 25000")
        leash, warnings = collect(p)
        leash.meter(12500, 0)
        assert warnings[0].message == (
            'run "test-run" (p) has used 12,500/25,000 tokens — '
            "50% of the approved envelope"
        )

    def test_a_fractional_dimension_is_rendered_with_two_decimals(self) -> None:
        p = make_policy("  purpose: p\n  warnAt: [0.5]", "usd: 3")
        leash, warnings = collect(p)
        leash.spend(1.5)
        assert "1.50/3 usd" in warnings[0].message
