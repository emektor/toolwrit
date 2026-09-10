"""
Shared fixtures for the Leash test suite.

Everything here is deterministic on purpose: no wall clock, no timers, no
randomness. Every timestamp is an explicit number so a failing assertion can
be reproduced from the test source alone.
"""

from __future__ import annotations

from typing import Any, Callable, Sequence

from leash._js import to_jsonable
from leash.types import (
    BudgetUsage,
    Decision,
    EvalContext,
    HistoryEntry,
    Policy,
    PolicyRule,
    ToolCall,
)

#: Fixed epoch used across the suite: 2024-01-01T00:00:00.000Z.
T0 = 1_704_067_200_000


def at(seconds: float) -> int:
    """T0 plus ``seconds``, for readable window arithmetic."""
    return int(T0 + seconds * 1000)


def fixed_clock(*times: int) -> Callable[[], int]:
    """A clock that hands out a scripted sequence of timestamps."""
    state = {"i": 0}

    def clock() -> int:
        value = times[min(state["i"], len(times) - 1)] if times else T0
        state["i"] += 1
        return value

    return clock


def frozen_clock(t: int = T0) -> Callable[[], int]:
    """A clock that never advances."""
    return lambda: t


def call(tool: str, args: dict[str, Any] | None = None, when: int = T0) -> ToolCall:
    return ToolCall(id=f"call-{tool}-{when}", tool=tool, args=args or {}, at=when)


def usage(**partial: Any) -> BudgetUsage:
    return BudgetUsage(**{"calls": 0, "tokens": 0, "usd": 0, "started_at": None, **partial})


def policy(**partial: Any) -> Policy:
    return Policy(**{"version": "1", "rules": [], **partial})


def rule(id: str, **partial: Any) -> PolicyRule:
    return PolicyRule(id=id, **{"tools": ["*"], "effect": "allow", **partial})


def ctx(
    policy_: Policy | None = None,
    usage_: BudgetUsage | None = None,
    history: Sequence[HistoryEntry] = (),
) -> EvalContext:
    return EvalContext(
        policy=policy_ if policy_ is not None else policy(),
        usage=usage_ if usage_ is not None else usage(),
        history=history,
    )


def hist(tool: str, rule_id: str | None, when: int) -> HistoryEntry:
    return HistoryEntry(tool=tool, rule=rule_id, at=when)


def shape(d: Decision) -> dict[str, Any]:
    """A decision shape without the noisy free-text ``reason``."""
    return {
        "effect": d.effect,
        "rule": d.rule,
        "constraints": [v.constraint for v in d.violations],
    }


def names(violations: Sequence[Any]) -> list[str]:
    """The constraint names that fired, in order."""
    return [v.constraint for v in violations]


def plain(value: Any) -> Any:
    """Dataclasses as plain data, for comparing against literal expectations."""
    return to_jsonable(value)
