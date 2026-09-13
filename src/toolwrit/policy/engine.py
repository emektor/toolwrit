"""
The decision function.

``evaluate`` is pure: same policy + same usage + same history + same call
always yields the same Decision. No clock reads, no I/O, no model in the
loop. That property is what makes a Toolwrit audit log replayable, and it is
the difference between this and a guardrail that asks an LLM for permission.

Precedence, in order:
  1. Budget. An exhausted budget denies everything, whatever the rules say.
  2. A matching rule whose rate limit is spent denies.
  3. Among matching rules: deny beats ask beats allow.
  4. No match at all falls through to ``policy.default`` (deny unless set).
"""

from __future__ import annotations

import math

from .._js import js_number, js_to_fixed
from ..types import Decision, EvalContext, PolicyRule, ToolCall, Violation
from .constraints import check_args
from .match import matches_any_glob


def evaluate(call: ToolCall, ctx: EvalContext) -> Decision:
    budget_violation = _check_budget(call, ctx)
    if budget_violation is not None:
        return Decision(
            effect="deny",
            rule=None,
            reason=budget_violation.message,
            violations=[budget_violation],
        )

    matched: list[PolicyRule] = []
    #: Rules that targeted this tool but whose constraints rejected the arguments.
    near_misses: list[Violation] = []

    for rule in ctx.policy.rules:
        if not matches_any_glob(rule.tools, call.tool):
            continue

        violations = check_args(rule.id, rule.when, call.args) if rule.when else []
        if violations:
            if rule.effect != "deny":
                near_misses.extend(violations)
            continue
        matched.append(rule)

    for rule in matched:
        if rule.limit is None:
            continue
        used = _count_recent(ctx, rule.id, call.at, rule.limit.perSeconds)
        if used >= rule.limit.max:
            window = (
                f"{js_number(rule.limit.perSeconds)}s"
                if rule.limit.perSeconds is not None
                else "this run"
            )
            return Decision(
                effect="deny",
                rule=rule.id,
                reason=f'rate limit exhausted for rule "{rule.id}"',
                violations=[
                    Violation(
                        rule=rule.id,
                        constraint="limit",
                        message=(
                            f'rule "{rule.id}" allows {js_number(rule.limit.max)} '
                            f"call(s) per {window}; {js_number(used)} already used"
                        ),
                    )
                ],
            )

    denied = next((r for r in matched if r.effect == "deny"), None)
    if denied is not None:
        return Decision(
            effect="deny",
            rule=denied.id,
            reason=_or(denied.description, f'denied by rule "{denied.id}"'),
            violations=[
                Violation(
                    rule=denied.id,
                    constraint="rule",
                    message=_or(
                        denied.description,
                        f'tool "{call.tool}" is denied by rule "{denied.id}"',
                    ),
                )
            ],
        )

    ask = next((r for r in matched if r.effect == "ask"), None)
    if ask is not None:
        return Decision(
            effect="ask",
            rule=ask.id,
            reason=_or(ask.description, f'rule "{ask.id}" requires approval'),
            violations=[],
        )

    allow = next((r for r in matched if r.effect == "allow"), None)
    if allow is not None:
        return Decision(
            effect="allow",
            rule=allow.id,
            reason=f'allowed by rule "{allow.id}"',
            violations=[],
        )

    fallback = ctx.policy.default if ctx.policy.default is not None else "deny"
    if fallback == "allow":
        return Decision(
            effect="allow",
            rule=None,
            reason="no rule matched; policy default is allow",
            violations=[],
        )

    # Deny-by-default is the common path, so spend the effort on a message the
    # agent can act on: if a rule wanted this tool but rejected the arguments,
    # say which argument rather than the useless "no rule matched".
    return Decision(
        effect=fallback,
        rule=None,
        reason=(
            f'no rule allows "{call.tool}" with these arguments'
            if near_misses
            else f'no rule allows tool "{call.tool}"'
        ),
        violations=(
            near_misses
            if near_misses
            else [
                Violation(
                    rule="policy",
                    constraint="default",
                    message=(
                        f'tool "{call.tool}" is not in the policy; '
                        f"the default effect is {fallback}"
                    ),
                )
            ]
        ),
    )


def _or(value: str | None, fallback: str) -> str:
    """Nullish coalescing: an explicitly empty description is still a description."""
    return fallback if value is None else value


def _check_budget(call: ToolCall, ctx: EvalContext) -> Violation | None:
    limits = ctx.policy.budget
    if limits is None:
        return None
    usage = ctx.usage

    def over(constraint: str, message: str) -> Violation:
        return Violation(rule="budget", constraint=constraint, message=message)

    if limits.calls is not None and usage.calls >= limits.calls:
        return over(
            "calls",
            f"call budget exhausted: {js_number(usage.calls)}/"
            f"{js_number(limits.calls)} calls used",
        )
    if limits.tokens is not None and usage.tokens >= limits.tokens:
        return over(
            "tokens",
            f"token budget exhausted: {js_number(usage.tokens)}/"
            f"{js_number(limits.tokens)} tokens used",
        )
    if limits.usd is not None and usage.usd >= limits.usd:
        return over(
            "usd",
            f"spend budget exhausted: ${js_to_fixed(usage.usd, 4)}/"
            f"${js_to_fixed(limits.usd, 4)} used",
        )
    if limits.bytes is not None and usage.bytes >= limits.bytes:
        return over(
            "bytes",
            f"data budget exhausted: {js_number(usage.bytes)}/"
            f"{js_number(limits.bytes)} bytes returned by tools",
        )
    if limits.seconds is not None and usage.started_at is not None:
        elapsed = (call.at - usage.started_at) / 1000
        if elapsed >= limits.seconds:
            return over(
                "seconds",
                f"time budget exhausted: {js_to_fixed(elapsed, 1)}s/"
                f"{js_number(limits.seconds)}s elapsed",
            )

    return None


def _count_recent(
    ctx: EvalContext,
    rule_id: str,
    now: int,
    per_seconds: float | None,
) -> int:
    """Calls already attributed to ``rule_id``, within the sliding window if one is set."""
    floor = -math.inf if per_seconds is None else now - per_seconds * 1000
    return sum(1 for entry in ctx.history if entry.rule == rule_id and entry.at > floor)
