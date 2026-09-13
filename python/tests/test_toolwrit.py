"""
End-to-end behaviour of the Toolwrit runtime object.

The contract being pinned here is the one an integrator relies on:
  - an allowed call runs, and is counted;
  - a denied call does NOT run, is NOT counted, but IS recorded;
  - "ask" without a handler is a denial (fail closed);
  - the chain over a whole mixed run verifies, and head() is the receipt.

Every timestamp comes from the injectable ``now``. There are no sleeps, no real
clocks and no timers in this file.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any, Callable

import pytest

from helpers import T0, at, fixed_clock, frozen_clock, policy, rule
from toolwrit.audit.chain import GENESIS
from toolwrit.audit.verify import verify_chain, verify_file
from toolwrit.budget.ledger import TokenPrice
from toolwrit.toolwrit import Toolwrit, ToolwritDenied
from toolwrit.types import ArgConstraint, BudgetLimits, Decision, Policy, RateLimit, ToolCall


def allow_fs() -> Policy:
    return policy(
        rules=[
            rule(
                "fs-read",
                tools=["fs.read"],
                effect="allow",
                when={"path": ArgConstraint(type="string", startsWith=["/tmp/"])},
            ),
            rule("confirm", tools=["fs.write"], effect="ask", description="writes need a human"),
            rule("no-shell", tools=["shell.**"], effect="deny", description="shell is off limits"),
        ]
    )


def denied(fn: Callable[[], Any]) -> ToolwritDenied:
    """Run ``fn``, requiring it to raise ToolwritDenied, and return the exception."""
    with pytest.raises(ToolwritDenied) as info:
        fn()
    return info.value


class TestConstruction:
    def test_generates_a_run_id_when_none_is_given_and_stamps_it_on_entries(self) -> None:
        a = Toolwrit(allow_fs(), now=frozen_clock())
        b = Toolwrit(allow_fs(), now=frozen_clock())
        assert re.fullmatch(r"[0-9a-f-]{36}", a.run)
        assert a.run != b.run

        a.guard("fs.read", {"path": "/tmp/x"}, lambda: 1)
        assert a.entries()[0].run == a.run

    def test_uses_an_explicit_run_id(self) -> None:
        toolwrit = Toolwrit(allow_fs(), run="run-42", now=frozen_clock())
        assert toolwrit.run == "run-42"
        toolwrit.guard("fs.read", {"path": "/tmp/x"}, lambda: 1)
        assert toolwrit.entries()[0].run == "run-42"

    def test_starts_with_empty_usage_no_entries_and_head_at_genesis(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock())
        usage = toolwrit.usage()
        assert (usage.calls, usage.tokens, usage.usd, usage.started_at) == (0, 0, 0, None)
        assert toolwrit.entries() == []
        assert toolwrit.head() == GENESIS


class TestCheck:
    def test_evaluates_without_recording_counting_or_executing(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock())
        assert toolwrit.check("fs.read", {"path": "/tmp/x"}).effect == "allow"
        assert toolwrit.check("shell.exec").effect == "deny"
        assert toolwrit.check("fs.write").effect == "ask", "check reports the raw effect"
        assert toolwrit.entries() == []
        assert toolwrit.usage().calls == 0

    def test_defaults_args_to_an_empty_object(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock())
        assert [v.constraint for v in toolwrit.check("fs.read").violations] == ["required"]


class TestGuardAllow:
    def test_executes_the_function_and_returns_its_value(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock())
        ran = []
        result = toolwrit.guard("fs.read", {"path": "/tmp/x"}, lambda: ran.append(1) or "contents")
        assert result == "contents"
        assert len(ran) == 1

    def test_guard_async_awaits_an_async_function(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock())

        async def body() -> int:
            async def tool() -> int:
                await asyncio.sleep(0)
                return 7

            return await toolwrit.guard_async("fs.read", {"path": "/tmp/x"}, tool)

        assert asyncio.run(body()) == 7

    def test_guard_async_also_accepts_a_plain_function(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock())
        result = asyncio.run(toolwrit.guard_async("fs.read", {"path": "/tmp/x"}, lambda: 7))
        assert result == 7

    def test_increments_calls_and_starts_the_clock_at_the_call_time(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=fixed_clock(at(0), at(5)))
        toolwrit.guard("fs.read", {"path": "/tmp/a"}, lambda: 1)
        assert (toolwrit.usage().calls, toolwrit.usage().started_at) == (1, at(0))
        toolwrit.guard("fs.read", {"path": "/tmp/b"}, lambda: 1)
        assert (toolwrit.usage().calls, toolwrit.usage().started_at) == (2, at(0))

    def test_records_the_decision_before_executing(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock())

        def explode() -> None:
            raise RuntimeError("disk on fire")

        with pytest.raises(RuntimeError, match="disk on fire"):
            toolwrit.guard("fs.read", {"path": "/tmp/x"}, explode)

        assert len(toolwrit.entries()) == 1
        assert toolwrit.entries()[0].decision.effect == "allow"
        assert toolwrit.usage().calls == 1, "authorised and counted before it failed"

    def test_records_the_entry_with_the_tool_args_time_and_decision(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock(at(3)))
        toolwrit.guard("fs.read", {"path": "/tmp/x"}, lambda: 1)
        entry = toolwrit.entries()[0]
        assert entry.tool == "fs.read"
        assert entry.args == {"path": "/tmp/x"}
        assert entry.at == at(3)
        assert entry.decision.rule == "fs-read"
        assert entry.usage == {"calls": 0, "tokens": 0, "usd": 0, "bytes": 0}, "usage as of the decision"


class TestGuardDeny:
    def test_raises_toolwrit_denied_carrying_the_tool_decision_and_audit_hash(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock())
        ran = []
        err = denied(
            lambda: toolwrit.guard("shell.exec", {"cmd": "rm -rf /"}, lambda: ran.append(1))
        )

        assert ran == [], "the guarded function must never run"
        assert err.tool == "shell.exec"
        assert err.decision.effect == "deny"
        assert err.decision.rule == "no-shell"
        assert err.decision.reason == "shell is off limits"
        assert "toolwrit: shell.exec denied — shell is off limits" in str(err)

        assert len(toolwrit.entries()) == 1
        assert err.audit_hash == toolwrit.entries()[0].hash, "the hash quotes the refusal"
        assert err.audit_hash == toolwrit.head()

    def test_does_not_increment_the_call_counter_but_does_record_the_refusal(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock())
        denied(lambda: toolwrit.guard("shell.exec", {}, lambda: 1))
        usage = toolwrit.usage()
        assert (usage.calls, usage.tokens, usage.usd, usage.started_at) == (0, 0, 0, None)
        assert len(toolwrit.entries()) == 1
        assert toolwrit.entries()[0].decision.effect == "deny"

    def test_denies_an_unknown_tool_by_default_and_reports_it(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock())
        err = denied(lambda: toolwrit.guard("mystery.tool", {}, lambda: 1))
        assert err.decision.rule is None
        assert [v.constraint for v in err.decision.violations] == ["default"]

    def test_denies_an_allow_rule_near_miss_and_surfaces_the_failing_argument(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock())
        err = denied(lambda: toolwrit.guard("fs.read", {"path": "/etc/passwd"}, lambda: 1))
        assert [
            f"{v.rule}:{v.path}:{v.constraint}" for v in err.decision.violations
        ] == ["fs-read:path:startsWith"]

    def test_denied_calls_do_not_consume_a_rate_limit(self) -> None:
        p = policy(rules=[rule("limited", tools=["t"], effect="allow", limit=RateLimit(max=1))])
        toolwrit = Toolwrit(p, now=frozen_clock())
        denied(lambda: toolwrit.guard("other", {}, lambda: 1))  # not attributed to `limited`
        toolwrit.guard("t", {}, lambda: 1)
        denied(lambda: toolwrit.guard("t", {}, lambda: 1))
        assert toolwrit.usage().calls == 1


class TestGuardAsk:
    def test_denies_when_no_handler_is_configured_fail_closed(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock())
        ran = []
        err = denied(lambda: toolwrit.guard("fs.write", {"path": "/tmp/x"}, lambda: ran.append(1)))

        assert ran == []
        assert err.decision.effect == "deny"
        assert err.decision.rule == "confirm", "the asking rule is still credited"
        assert "no approval handler configured" in err.decision.reason
        assert [v.constraint for v in err.decision.violations] == ["ask"]
        assert "denying by default" in err.decision.violations[0].message
        assert toolwrit.usage().calls == 0
        assert toolwrit.entries()[0].decision.effect == "deny", "the refusal is recorded"

    def test_allows_when_the_handler_returns_true_and_records_the_upgrade(self) -> None:
        seen: list[tuple[str, str]] = []

        def on_ask(c: ToolCall, d: Decision) -> bool:
            seen.append((c.tool, d.effect))
            return True

        toolwrit = Toolwrit(allow_fs(), now=frozen_clock(), on_ask=on_ask)
        assert toolwrit.guard("fs.write", {"path": "/tmp/x"}, lambda: "written") == "written"
        assert seen == [("fs.write", "ask")]
        assert toolwrit.usage().calls == 1

        entry = toolwrit.entries()[0]
        assert entry.decision.effect == "allow"
        assert entry.decision.rule == "confirm"
        assert entry.decision.reason.endswith("(approved)")

    def test_denies_when_the_handler_returns_false(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock(), on_ask=lambda c, d: False)
        err = denied(lambda: toolwrit.guard("fs.write", {"path": "/tmp/x"}, lambda: 1))
        assert err.decision.effect == "deny"
        assert err.decision.reason.endswith("(approval refused)")
        assert [v.message for v in err.decision.violations] == [
            "approval was refused by the configured handler"
        ]
        assert toolwrit.usage().calls == 0

    def test_guard_async_awaits_an_async_handler(self) -> None:
        order: list[str] = []

        async def on_ask(c: ToolCall, d: Decision) -> bool:
            order.append("asked")
            await asyncio.sleep(0)
            order.append("resolved")
            return True

        toolwrit = Toolwrit(allow_fs(), now=frozen_clock(), on_ask=on_ask)
        asyncio.run(
            toolwrit.guard_async("fs.write", {}, lambda: order.append("executed"))
        )
        assert order == ["asked", "resolved", "executed"]

    def test_sync_guard_refuses_an_async_handler_rather_than_guessing(self) -> None:
        async def on_ask(c: ToolCall, d: Decision) -> bool:
            return True

        toolwrit = Toolwrit(allow_fs(), now=frozen_clock(), on_ask=on_ask)
        with pytest.raises(TypeError, match="use guard_async"):
            toolwrit.guard("fs.write", {}, lambda: 1)

    def test_the_handler_receives_the_exact_call_it_is_asked_about(self) -> None:
        received: list[ToolCall] = []

        def on_ask(c: ToolCall, d: Decision) -> bool:
            received.append(c)
            return False

        toolwrit = Toolwrit(allow_fs(), now=frozen_clock(at(9)), on_ask=on_ask)
        denied(lambda: toolwrit.guard("fs.write", {"path": "/tmp/secret"}, lambda: 1))
        assert received[0].tool == "fs.write"
        assert received[0].args == {"path": "/tmp/secret"}
        assert received[0].at == at(9)

    def test_is_not_consulted_for_allow_or_deny_decisions(self) -> None:
        asked = []
        toolwrit = Toolwrit(
            allow_fs(), now=frozen_clock(), on_ask=lambda c, d: bool(asked.append(1)) or True
        )
        toolwrit.guard("fs.read", {"path": "/tmp/x"}, lambda: 1)
        denied(lambda: toolwrit.guard("shell.exec", {}, lambda: 1))
        assert asked == []

    def test_cannot_upgrade_a_budget_denial(self) -> None:
        p = allow_fs()
        p.budget = BudgetLimits(calls=1)
        toolwrit = Toolwrit(p, now=frozen_clock(), on_ask=lambda c, d: True)
        toolwrit.guard("fs.read", {"path": "/tmp/x"}, lambda: 1)
        err = denied(lambda: toolwrit.guard("fs.write", {"path": "/tmp/x"}, lambda: 1))
        assert err.decision.violations[0].constraint == "calls"


class TestMeteringAndBudgets:
    def test_meter_adds_tokens_and_derives_spend_from_the_price_table(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock(at(2)))
        toolwrit.meter(1000, 500, TokenPrice(input=0.003, output=0.015))
        usage = toolwrit.usage()
        assert usage.tokens == 1500
        assert abs(usage.usd - (0.003 + 0.0075)) < 1e-12
        assert usage.started_at == at(2), "the time budget starts at the first metered event"

    def test_meter_without_a_price_table_records_tokens_at_zero_cost(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock())
        toolwrit.meter(10, 20)
        usage = toolwrit.usage()
        assert (usage.calls, usage.tokens, usage.usd, usage.started_at) == (0, 30, 0, T0)

    def test_spend_adds_usd_and_accumulates(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock())
        toolwrit.spend(0.25)
        toolwrit.spend(0.25)
        assert toolwrit.usage().usd == 0.5

    def test_a_previously_allowed_call_is_denied_once_the_call_budget_trips(self) -> None:
        p = allow_fs()
        p.budget = BudgetLimits(calls=2)
        toolwrit = Toolwrit(p, now=frozen_clock())
        toolwrit.guard("fs.read", {"path": "/tmp/a"}, lambda: 1)
        toolwrit.guard("fs.read", {"path": "/tmp/b"}, lambda: 1)
        err = denied(lambda: toolwrit.guard("fs.read", {"path": "/tmp/c"}, lambda: 1))
        assert err.decision.violations[0].constraint == "calls"
        assert toolwrit.usage().calls == 2, "the refused call is not counted"

    def test_metering_tokens_can_trip_the_budget_mid_run(self) -> None:
        p = allow_fs()
        p.budget = BudgetLimits(tokens=100)
        toolwrit = Toolwrit(p, now=frozen_clock())
        toolwrit.guard("fs.read", {"path": "/tmp/a"}, lambda: 1)
        toolwrit.meter(60, 39)
        toolwrit.guard("fs.read", {"path": "/tmp/b"}, lambda: 1)
        toolwrit.meter(1, 0)
        err = denied(lambda: toolwrit.guard("fs.read", {"path": "/tmp/c"}, lambda: 1))
        assert err.decision.violations[0].constraint == "tokens"
        assert "100/100 tokens used" in err.decision.reason

    def test_spending_trips_the_usd_budget_mid_run(self) -> None:
        p = allow_fs()
        p.budget = BudgetLimits(usd=1)
        toolwrit = Toolwrit(p, now=frozen_clock())
        toolwrit.guard("fs.read", {"path": "/tmp/a"}, lambda: 1)
        toolwrit.spend(0.99)
        toolwrit.guard("fs.read", {"path": "/tmp/b"}, lambda: 1)
        toolwrit.spend(0.01)
        err = denied(lambda: toolwrit.guard("fs.read", {"path": "/tmp/c"}, lambda: 1))
        assert err.decision.violations[0].constraint == "usd"

    def test_the_seconds_budget_trips_on_the_injected_clock_alone(self) -> None:
        p = allow_fs()
        p.budget = BudgetLimits(seconds=30)
        # One clock read per guard: count_call reuses the timestamp from the call.
        toolwrit = Toolwrit(p, now=fixed_clock(at(0), at(29), at(30)))
        toolwrit.guard("fs.read", {"path": "/tmp/a"}, lambda: 1)
        toolwrit.guard("fs.read", {"path": "/tmp/b"}, lambda: 1)
        err = denied(lambda: toolwrit.guard("fs.read", {"path": "/tmp/c"}, lambda: 1))
        assert err.decision.violations[0].constraint == "seconds"
        assert "time budget exhausted: 30.0s/30s elapsed" in err.decision.reason

    def test_rate_limits_are_enforced_across_guarded_calls(self) -> None:
        p = policy(
            rules=[
                rule("burst", tools=["t"], effect="allow", limit=RateLimit(max=2, perSeconds=60))
            ]
        )
        toolwrit = Toolwrit(p, now=fixed_clock(at(0), at(1), at(2), at(120)))
        toolwrit.guard("t", {}, lambda: 1)
        toolwrit.guard("t", {}, lambda: 1)
        err = denied(lambda: toolwrit.guard("t", {}, lambda: 1))
        assert err.decision.violations[0].constraint == "limit"
        toolwrit.guard("t", {}, lambda: 1)  # the window has slid past both entries
        assert toolwrit.usage().calls == 3


class TestAuditChainOverAWholeRun:
    def test_verifies_across_a_mixed_run(self) -> None:
        p = allow_fs()
        p.budget = BudgetLimits(calls=3)
        toolwrit = Toolwrit(
            p,
            run="mixed",
            now=fixed_clock(at(0), at(1), at(2), at(3), at(4), at(5)),
            on_ask=lambda c, d: True,
        )

        toolwrit.guard("fs.read", {"path": "/tmp/a"}, lambda: 1)              # allow
        denied(lambda: toolwrit.guard("shell.exec", {}, lambda: 1))           # deny by rule
        toolwrit.guard("fs.write", {"path": "/tmp/b"}, lambda: 1)             # ask -> approved
        denied(lambda: toolwrit.guard("fs.read", {"path": "/etc/x"}, lambda: 1))  # near miss
        toolwrit.guard("fs.read", {"path": "/tmp/c"}, lambda: 1)              # allow (3rd call)
        denied(lambda: toolwrit.guard("fs.read", {"path": "/tmp/d"}, lambda: 1))  # budget

        entries = toolwrit.entries()
        assert len(entries) == 6
        assert [e.decision.effect for e in entries] == [
            "allow", "deny", "allow", "deny", "allow", "deny",
        ]
        assert [e.seq for e in entries] == [1, 2, 3, 4, 5, 6]
        assert [e.usage["calls"] for e in entries] == [0, 1, 1, 2, 2, 3]

        result = verify_chain(entries)
        assert result.ok is True, result.failure
        assert result.count == 6
        assert result.head == toolwrit.head()

    def test_head_equals_the_last_entrys_hash_after_every_step(self) -> None:
        toolwrit = Toolwrit(allow_fs(), now=frozen_clock())
        assert toolwrit.head() == GENESIS
        for i in range(4):
            toolwrit.guard("fs.read", {"path": f"/tmp/{i}"}, lambda: i)
            assert toolwrit.head() == toolwrit.entries()[-1].hash, f"after {i + 1} calls"
        assert len(toolwrit.entries()) == 4

    def test_writes_and_verifies_a_jsonl_audit_file_with_redaction(self, tmp_path: Path) -> None:
        file = tmp_path / "run.jsonl"
        args = {"path": "/tmp/x", "token": "sk-live-secret"}
        toolwrit = Toolwrit(
            policy(rules=[rule("any", tools=["**"], effect="allow")]),
            run="file-run",
            audit_file=str(file),
            redact=["token"],
            now=fixed_clock(at(0), at(1)),
        )

        toolwrit.guard("api.call", args, lambda: 1)
        toolwrit.guard("api.call", args, lambda: 2)

        result = verify_file(str(file))
        assert result.ok is True, result.failure
        assert result.count == 2
        assert result.head == toolwrit.head()
        assert toolwrit.entries()[0].args["token"] == "[redacted]"
        assert toolwrit.entries()[0].args["path"] == "/tmp/x"
        assert args["token"] == "sk-live-secret", "the caller's object is untouched"
        assert "sk-live-secret" not in file.read_text(encoding="utf-8")

    def test_two_instances_with_the_same_inputs_produce_the_same_chain(self) -> None:
        def build() -> str:
            toolwrit = Toolwrit(allow_fs(), run="same", now=fixed_clock(at(0), at(1)))
            toolwrit.guard("fs.read", {"path": "/tmp/a"}, lambda: 1)
            denied(lambda: toolwrit.guard("shell.exec", {}, lambda: 1))
            return toolwrit.head()

        assert build() == build(), "the chain is a function of the inputs alone"


class TestTheBytesCeilingUnderConcurrency:
    """Concurrent calls must not each be decided against a stale byte total.

    A result's size is unknowable until the tool has produced it, so a bytes
    ceiling always allows the limit plus one call. What it must not do is allow
    the limit plus *however many calls the caller happened to launch at once*:
    without serialisation every one of them evaluates against the same zero and
    every one is permitted.
    """

    @staticmethod
    def policy_with_ceiling() -> Policy:
        return policy(
            default="allow",
            budget=BudgetLimits(bytes=100),
        )

    def test_concurrent_calls_are_decided_one_at_a_time(self) -> None:
        toolwrit = Toolwrit(self.policy_with_ceiling(), now=frozen_clock())
        ran: list[int] = []

        async def big(index: int) -> str:
            await asyncio.sleep(0)
            ran.append(index)
            return "x" * 500

        async def main() -> list[Any]:
            return await asyncio.gather(
                *(
                    toolwrit.guard_async("fs.read", {"i": i}, lambda i=i: big(i))
                    for i in range(4)
                ),
                return_exceptions=True,
            )

        results = asyncio.run(main())

        # The first call is allowed and its result exhausts the ceiling; the
        # other three are refused before their tool is ever invoked.
        assert len(ran) == 1, f"{len(ran)} tools ran, expected 1"
        assert sum(isinstance(r, ToolwritDenied) for r in results) == 3
        assert toolwrit.usage().calls == 1

    def test_a_policy_without_a_bytes_budget_still_runs_calls_concurrently(self) -> None:
        # The serialisation is the price of a bytes ceiling, not a new default.
        toolwrit = Toolwrit(policy(default="allow"), now=frozen_clock())
        order: list[str] = []

        async def slow() -> str:
            order.append("slow-start")
            await asyncio.sleep(0.02)
            order.append("slow-end")
            return "s"

        async def quick() -> str:
            await asyncio.sleep(0)
            order.append("quick")
            return "q"

        async def main() -> None:
            await asyncio.gather(
                toolwrit.guard_async("fs.read", {}, slow),
                toolwrit.guard_async("fs.read", {}, quick),
            )

        asyncio.run(main())
        # The quick call finished while the slow one was still in its tool.
        assert order == ["slow-start", "quick", "slow-end"], order
