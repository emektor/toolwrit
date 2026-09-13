"""
The decision function.

``evaluate`` is the whole product in one pure function. These tests walk the
documented precedence ladder end to end:

  budget > exhausted rate limit > deny > ask > allow > policy default (deny)

and pin the boundary conditions of each rung, because "deterministic" is a
claim that only means something if the boundaries are nailed down.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from helpers import at, call, ctx, hist, plain, policy, rule, shape, usage
from toolwrit.policy.engine import evaluate
from toolwrit.types import ArgConstraint, BudgetLimits, EvalContext, RateLimit


class TestMatchingAndDefaults:
    def test_denies_by_default_when_there_are_no_rules_at_all(self) -> None:
        d = evaluate(call("fs.read"), ctx())
        assert shape(d) == {"effect": "deny", "rule": None, "constraints": ["default"]}
        assert d.violations[0].rule == "policy"
        assert 'no rule allows tool "fs.read"' in d.reason

    def test_denies_by_default_when_no_rule_matches_the_tool_name(self) -> None:
        c = ctx(policy(rules=[rule("r", tools=["net.*"], effect="allow")]))
        assert evaluate(call("fs.read"), c).effect == "deny"

    def test_honours_an_explicit_default_allow(self) -> None:
        d = evaluate(call("anything"), ctx(policy(default="allow")))
        assert shape(d) == {"effect": "allow", "rule": None, "constraints": []}
        assert "policy default is allow" in d.reason

    def test_honours_an_explicit_default_ask(self) -> None:
        d = evaluate(call("anything"), ctx(policy(default="ask")))
        assert d.effect == "ask"
        assert d.rule is None
        assert [v.constraint for v in d.violations] == ["default"]

    def test_allows_via_a_matching_rule_and_names_it(self) -> None:
        c = ctx(policy(rules=[rule("fs-read", tools=["fs.read"])]))
        d = evaluate(call("fs.read"), c)
        assert shape(d) == {"effect": "allow", "rule": "fs-read", "constraints": []}
        assert 'allowed by rule "fs-read"' in d.reason

    def test_matches_on_globs_with_the_same_semantics_as_matches_glob(self) -> None:
        c = ctx(policy(rules=[rule("fs", tools=["fs.*"])]))
        assert evaluate(call("fs.read"), c).effect == "allow"
        assert evaluate(call("fs.read.raw"), c).effect == "deny"

    def test_a_rule_with_a_when_that_holds_matches(self) -> None:
        c = ctx(
            policy(
                rules=[
                    rule(
                        "scoped",
                        tools=["fs.read"],
                        when={"path": ArgConstraint(startsWith=["/tmp/"])},
                    )
                ]
            )
        )
        assert evaluate(call("fs.read", {"path": "/tmp/a"}), c).effect == "allow"


class TestPrecedence:
    rules = [
        rule("allow-all", tools=["**"], effect="allow"),
        rule("ask-fs", tools=["fs.*"], effect="ask"),
        rule("deny-secrets", tools=["fs.read"], effect="deny", description="no secrets"),
    ]

    def test_deny_beats_ask_and_allow_regardless_of_declaration_order(self) -> None:
        for order in (self.rules, list(reversed(self.rules))):
            d = evaluate(call("fs.read"), ctx(policy(rules=list(order))))
            assert shape(d) == {
                "effect": "deny",
                "rule": "deny-secrets",
                "constraints": ["rule"],
            }
            assert d.reason == "no secrets"

    def test_ask_beats_allow(self) -> None:
        d = evaluate(call("fs.write"), ctx(policy(rules=list(self.rules))))
        assert shape(d) == {"effect": "ask", "rule": "ask-fs", "constraints": []}

    def test_allow_wins_when_nothing_stronger_matches(self) -> None:
        d = evaluate(call("net.get"), ctx(policy(rules=list(self.rules))))
        assert shape(d) == {"effect": "allow", "rule": "allow-all", "constraints": []}

    def test_picks_the_first_rule_of_the_winning_effect_when_several_tie(self) -> None:
        c = ctx(
            policy(
                rules=[
                    rule("a1", tools=["t"], effect="allow"),
                    rule("a2", tools=["t"], effect="allow"),
                ]
            )
        )
        assert evaluate(call("t"), c).rule == "a1"

    def test_a_deny_rule_whose_when_fails_does_not_deny(self) -> None:
        c = ctx(
            policy(
                rules=[
                    rule(
                        "deny-etc",
                        tools=["fs.read"],
                        effect="deny",
                        when={"path": ArgConstraint(startsWith=["/etc/"])},
                    ),
                    rule(
                        "allow-tmp",
                        tools=["fs.read"],
                        effect="allow",
                        when={"path": ArgConstraint(startsWith=["/tmp/"])},
                    ),
                ]
            )
        )
        assert evaluate(call("fs.read", {"path": "/tmp/ok"}), c).rule == "allow-tmp"
        assert evaluate(call("fs.read", {"path": "/etc/passwd"}), c).rule == "deny-etc"

    def test_uses_the_description_as_the_denial_reason_with_a_generated_fallback(self) -> None:
        described = evaluate(
            call("t"),
            ctx(policy(rules=[rule("d", tools=["t"], effect="deny", description="because")])),
        )
        assert described.reason == "because"
        assert described.violations[0].message == "because"

        bare = evaluate(call("t"), ctx(policy(rules=[rule("d", tools=["t"], effect="deny")])))
        assert bare.reason == 'denied by rule "d"'
        assert 'tool "t" is denied by rule "d"' in bare.violations[0].message


class TestNearMisses:
    c = ctx(
        policy(
            rules=[
                rule(
                    "allow-tmp",
                    tools=["fs.write"],
                    effect="allow",
                    when={"path": ArgConstraint(type="string", startsWith=["/tmp/"])},
                )
            ]
        )
    )

    def test_an_allow_rule_whose_when_fails_falls_through_to_the_default_deny(self) -> None:
        d = evaluate(call("fs.write", {"path": "/etc/passwd"}), self.c)
        assert d.effect == "deny"
        assert d.rule is None, "the near-miss rule did not decide, so rule stays None"

    def test_surfaces_the_near_miss_violations(self) -> None:
        d = evaluate(call("fs.write", {"path": "/etc/passwd"}), self.c)
        assert [v.constraint for v in d.violations] == ["startsWith"]
        assert d.violations[0].rule == "allow-tmp"
        assert d.violations[0].path == "path"
        assert 'no rule allows "fs.write" with these arguments' in d.reason

    def test_falls_back_to_the_generic_message_when_no_rule_wanted_the_tool(self) -> None:
        d = evaluate(call("net.get", {"path": "/etc/passwd"}), self.c)
        assert [v.constraint for v in d.violations] == ["default"]
        assert 'no rule allows tool "net.get"' in d.reason

    def test_collects_near_misses_from_several_rules(self) -> None:
        many = ctx(
            policy(
                rules=[
                    rule("r1", tools=["t"], effect="allow", when={"a": ArgConstraint(type="string")}),
                    rule("r2", tools=["t"], effect="ask", when={"b": ArgConstraint(type="string")}),
                ]
            )
        )
        d = evaluate(call("t", {}), many)
        assert [f"{v.rule}:{v.constraint}" for v in d.violations] == [
            "r1:required",
            "r2:required",
        ]

    def test_does_not_leak_a_deny_rules_constraint_failures_as_near_misses(self) -> None:
        # A deny rule that did not fire is not a near-miss: reporting it would
        # tell the agent exactly which argument to change to dodge the deny rule.
        with_deny = ctx(
            policy(
                rules=[
                    rule(
                        "deny-etc",
                        tools=["t"],
                        effect="deny",
                        when={"p": ArgConstraint(startsWith=["/etc/"])},
                    )
                ]
            )
        )
        d = evaluate(call("t", {"p": "/tmp/x"}), with_deny)
        assert [v.constraint for v in d.violations] == ["default"]


class TestBudget:
    allow_all = policy(rules=[rule("yes", tools=["**"], effect="allow")])

    def with_budget(self, budget: dict[str, Any], **u: Any) -> EvalContext:
        p = policy(rules=list(self.allow_all.rules), budget=BudgetLimits(**budget))
        return ctx(p, usage(**u))

    def test_no_budget_block_means_no_budget_denial(self) -> None:
        c = ctx(self.allow_all, usage(calls=10**9, tokens=10**9, usd=10**9))
        assert evaluate(call("t"), c).effect == "allow"

    def test_denies_on_calls_at_the_limit(self) -> None:
        assert evaluate(call("t"), self.with_budget({"calls": 3}, calls=2)).effect == "allow"
        d = evaluate(call("t"), self.with_budget({"calls": 3}, calls=3))
        assert shape(d) == {"effect": "deny", "rule": None, "constraints": ["calls"]}
        assert d.violations[0].rule == "budget"
        assert "call budget exhausted: 3/3 calls used" in d.reason
        assert evaluate(call("t"), self.with_budget({"calls": 3}, calls=4)).effect == "deny"

    def test_denies_on_tokens_at_the_limit(self) -> None:
        assert (
            evaluate(call("t"), self.with_budget({"tokens": 1000}, tokens=999)).effect
            == "allow"
        )
        d = evaluate(call("t"), self.with_budget({"tokens": 1000}, tokens=1000))
        assert shape(d) == {"effect": "deny", "rule": None, "constraints": ["tokens"]}
        assert "token budget exhausted: 1000/1000" in d.reason

    def test_denies_on_usd_at_the_limit(self) -> None:
        assert evaluate(call("t"), self.with_budget({"usd": 1}, usd=0.9999)).effect == "allow"
        d = evaluate(call("t"), self.with_budget({"usd": 1}, usd=1))
        assert shape(d) == {"effect": "deny", "rule": None, "constraints": ["usd"]}
        assert "spend budget exhausted: $1.0000/$1.0000" in d.reason

    def test_denies_on_elapsed_seconds_at_the_limit(self) -> None:
        b = {"seconds": 60}
        assert (
            evaluate(call("t", {}, at(59.999)), self.with_budget(b, started_at=at(0))).effect
            == "allow"
        )
        d = evaluate(call("t", {}, at(60)), self.with_budget(b, started_at=at(0)))
        assert shape(d) == {"effect": "deny", "rule": None, "constraints": ["seconds"]}
        assert "time budget exhausted: 60.0s/60s elapsed" in d.reason

    def test_the_seconds_budget_is_a_no_op_while_started_at_is_none(self) -> None:
        # Nothing has been metered yet, so the run has not started; a huge `at`
        # must not retroactively exhaust the clock.
        d = evaluate(call("t", {}, at(10**6)), self.with_budget({"seconds": 1}, started_at=None))
        assert d.effect == "allow"

    def test_a_call_before_started_at_yields_negative_elapsed_and_does_not_deny(self) -> None:
        d = evaluate(call("t", {}, at(-10)), self.with_budget({"seconds": 1}, started_at=at(0)))
        assert d.effect == "allow"

    def test_each_limit_is_checked_independently(self) -> None:
        every = {"calls": 5, "tokens": 5, "usd": 5}
        assert evaluate(call("t"), self.with_budget(every, tokens=5)).effect == "deny"
        assert evaluate(call("t"), self.with_budget(every, usd=5)).effect == "deny"
        assert evaluate(call("t"), self.with_budget(every, calls=5)).effect == "deny"

    def test_reports_limits_in_a_fixed_order_when_several_are_exhausted(self) -> None:
        d = evaluate(
            call("t"),
            self.with_budget({"calls": 1, "tokens": 1, "usd": 1}, calls=9, tokens=9, usd=9),
        )
        assert d.violations[0].constraint == "calls", "calls is checked first"
        assert len(d.violations) == 1

    def test_an_exhausted_budget_denies_even_when_an_allow_rule_matches_cleanly(self) -> None:
        d = evaluate(call("t"), self.with_budget({"calls": 1}, calls=1))
        assert d.effect == "deny"
        assert d.rule is None, "budget denials are engine-level, not rule-level"

    def test_an_exhausted_budget_beats_a_rate_limit_that_would_also_have_denied(self) -> None:
        c = EvalContext(
            policy=policy(
                rules=[rule("lim", tools=["t"], effect="allow", limit=RateLimit(max=1))],
                budget=BudgetLimits(calls=1),
            ),
            usage=usage(calls=1),
            history=[hist("t", "lim", at(0))],
        )
        assert evaluate(call("t", {}, at(1)), c).violations[0].constraint == "calls"


class TestRateLimits:
    @staticmethod
    def limited(max_: int, per_seconds: float | None = None, effect: str = "allow"):
        return policy(
            rules=[
                rule(
                    "lim",
                    tools=["t"],
                    effect=effect,
                    limit=RateLimit(max=max_, perSeconds=per_seconds),
                )
            ]
        )

    def test_allows_while_under_the_per_run_limit_and_denies_at_it(self) -> None:
        p = self.limited(2)
        history = [hist("t", "lim", at(0)), hist("t", "lim", at(1))]
        assert evaluate(call("t", {}, at(2)), ctx(p, history=history[:1])).effect == "allow"

        d = evaluate(call("t", {}, at(2)), ctx(p, history=history))
        assert shape(d) == {"effect": "deny", "rule": "lim", "constraints": ["limit"]}
        assert 'rate limit exhausted for rule "lim"' in d.reason
        assert "allows 2 call(s) per this run; 2 already used" in d.violations[0].message

    def test_a_per_run_limit_ignores_how_long_ago_the_calls_happened(self) -> None:
        history = [hist("t", "lim", at(-(10**6)))]
        assert evaluate(call("t", {}, at(0)), ctx(self.limited(1), history=history)).effect == "deny"

    def test_max_zero_denies_the_very_first_call(self) -> None:
        d = evaluate(call("t", {}, at(0)), ctx(self.limited(0), history=[]))
        assert shape(d) == {"effect": "deny", "rule": "lim", "constraints": ["limit"]}

    def test_only_counts_history_attributed_to_the_same_rule(self) -> None:
        history = [hist("t", "other", at(0)), hist("t", None, at(0))]
        assert evaluate(call("t", {}, at(1)), ctx(self.limited(1), history=history)).effect == "allow"

    def test_a_sliding_window_excludes_entries_older_than_the_window(self) -> None:
        p = self.limited(1, 60)
        inside = [hist("t", "lim", at(0))]
        assert evaluate(call("t", {}, at(59)), ctx(p, history=inside)).effect == "deny"
        assert evaluate(call("t", {}, at(61)), ctx(p, history=inside)).effect == "allow"

    def test_an_entry_exactly_at_the_window_edge_has_expired(self) -> None:
        # floor = now - perSeconds*1000; an entry with at == floor is NOT counted.
        p = self.limited(1, 60)
        edge = [hist("t", "lim", at(0))]
        assert evaluate(call("t", {}, at(60)), ctx(p, history=edge)).effect == "allow"
        assert evaluate(call("t", {}, at(59.999)), ctx(p, history=edge)).effect == "deny"

    def test_counts_several_entries_inside_the_window_and_names_the_window(self) -> None:
        history = [hist("t", "lim", t) for t in (at(0), at(10), at(20))]
        d = evaluate(call("t", {}, at(25)), ctx(self.limited(3, 60), history=history))
        assert d.effect == "deny"
        assert "allows 3 call(s) per 60s; 3 already used" in d.violations[0].message

    def test_an_exhausted_limit_denies_a_rule_whose_effect_is_ask(self) -> None:
        history = [hist("t", "lim", at(0))]
        d = evaluate(call("t", {}, at(1)), ctx(self.limited(1, 60, "ask"), history=history))
        assert shape(d) == {"effect": "deny", "rule": "lim", "constraints": ["limit"]}

    def test_an_exhausted_limit_on_a_deny_rule_is_attributed_to_the_limit(self) -> None:
        history = [hist("t", "lim", at(0))]
        d = evaluate(call("t", {}, at(1)), ctx(self.limited(1, 60, "deny"), history=history))
        assert shape(d) == {"effect": "deny", "rule": "lim", "constraints": ["limit"]}

    def test_a_rate_limit_beats_a_deny_rule_from_a_different_clause(self) -> None:
        p = policy(
            rules=[
                rule("lim", tools=["t"], effect="allow", limit=RateLimit(max=1)),
                rule("nope", tools=["t"], effect="deny"),
            ]
        )
        d = evaluate(call("t", {}, at(1)), ctx(p, history=[hist("t", "lim", at(0))]))
        assert d.rule == "lim", "the rate limit is checked before the deny ladder"
        assert d.violations[0].constraint == "limit"

    def test_a_rate_limit_on_a_rule_that_did_not_match_is_ignored(self) -> None:
        p = policy(
            rules=[
                rule(
                    "lim",
                    tools=["t"],
                    effect="allow",
                    when={"ok": ArgConstraint(type="boolean")},
                    limit=RateLimit(max=0),
                ),
                rule("fallback", tools=["t"], effect="allow"),
            ]
        )
        # `ok` is missing, so `lim` never matches and its max:0 must not fire.
        assert evaluate(call("t", {}, at(0)), ctx(p)).rule == "fallback"


class TestPurity:
    c = EvalContext(
        policy=policy(
            budget=BudgetLimits(calls=10, tokens=100, usd=1, seconds=60),
            rules=[
                rule(
                    "a",
                    tools=["fs.*"],
                    effect="allow",
                    when={"path": ArgConstraint(startsWith=["/tmp/"])},
                    limit=RateLimit(max=5, perSeconds=30),
                ),
                rule("d", tools=["fs.delete"], effect="deny"),
                rule("k", tools=["net.*"], effect="ask"),
            ],
        ),
        usage=usage(calls=2, tokens=20, usd=0.1, started_at=at(0)),
        history=[hist("fs.read", "a", at(1))],
    )

    calls = [
        call("fs.read", {"path": "/tmp/a"}, at(5)),
        call("fs.read", {"path": "/etc/a"}, at(5)),
        call("fs.delete", {"path": "/tmp/a"}, at(5)),
        call("net.get", {}, at(5)),
        call("unknown.tool", {}, at(5)),
    ]

    def test_produces_equal_decisions_on_repeated_evaluation(self) -> None:
        for k in self.calls:
            first = evaluate(k, self.c)
            second = evaluate(k, self.c)
            assert second == first, f"unstable decision for {k.tool}"
            assert second is not first, "each call must return a fresh object"

    def test_does_not_mutate_the_context_the_policy_the_usage_or_the_call(self) -> None:
        before = plain(
            {"policy": self.c.policy, "usage": self.c.usage, "history": list(self.c.history)}
        )
        calls_before = plain(self.calls)
        for k in self.calls:
            evaluate(k, self.c)
        assert (
            plain(
                {
                    "policy": self.c.policy,
                    "usage": self.c.usage,
                    "history": list(self.c.history),
                }
            )
            == before
        )
        assert plain(self.calls) == calls_before

    def test_is_insensitive_to_the_call_id(self) -> None:
        """Only tool, args and time matter."""
        one = replace(self.calls[0], id="id-one")
        two = replace(self.calls[0], id="id-two")
        assert evaluate(one, self.c) == evaluate(two, self.c)

    def test_mutating_a_returned_decision_does_not_affect_the_next_evaluation(self) -> None:
        d = evaluate(self.calls[1], self.c)
        d.violations.clear()
        d.effect = "allow"
        assert evaluate(self.calls[1], self.c).effect == "deny"
        assert len(evaluate(self.calls[1], self.c).violations) == 1
