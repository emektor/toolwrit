"""
Run-scoped consumption tracking.

The ledger is the "capacity" half of Leash: rules decide *what* an agent may
do, the ledger decides *how much*. It is deliberately dumb -- a set of
counters -- because the interesting logic belongs in the engine, and because
a counter is trivially auditable.
"""

from __future__ import annotations

import math
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace

from ..types import BudgetUsage


@dataclass(frozen=True)
class TokenPrice:
    """Per-thousand-token prices used to turn token counts into dollars."""

    #: USD per 1,000 input tokens.
    input: float = 0
    #: USD per 1,000 output tokens.
    output: float = 0


def _require_consumption(name: str, value: float) -> float:
    """
    Reject a consumption figure that would corrupt the ledger.

    A single NaN is permanent and silent: every ceiling check is
    ``used >= limit``, and ``nan >= n`` is False, so one bad metering call
    disables that budget for the rest of the run with no error anywhere. A
    negative figure is as bad in the other direction -- it walks a spent budget
    back under its ceiling and reopens it. A metering bug has to surface as an
    exception, not as a limit that quietly stops applying.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"leash: {name} must be a finite number, got {value!r}")
    if not math.isfinite(value):
        raise TypeError(f"leash: {name} must be a finite number, got {value!r}")
    if value < 0:
        raise ValueError(f"leash: {name} must not be negative, got {value}")
    return value


def as_token_price(price: "TokenPrice | Mapping[str, float] | None") -> TokenPrice:
    """Coerce a price table given as a mapping, a TokenPrice, or nothing."""
    if price is None:
        return TokenPrice()
    if isinstance(price, TokenPrice):
        return price
    if isinstance(price, Mapping):
        unknown = set(price) - {"input", "output"}
        if unknown:
            raise TypeError(
                f"unknown price key(s) {sorted(unknown)}; expected 'input' and 'output'"
            )
        return TokenPrice(input=price.get("input", 0), output=price.get("output", 0))
    raise TypeError(f"price must be a TokenPrice or a mapping, got {type(price).__name__}")


def now_ms() -> int:
    """Milliseconds since the epoch, matching JavaScript's ``Date.now()``."""
    return int(time.time() * 1000)


class Ledger:
    def __init__(self) -> None:
        self._usage = BudgetUsage()

    def snapshot(self) -> BudgetUsage:
        """Snapshot for the engine. Returned by value so callers cannot mutate state."""
        return replace(self._usage)

    def count_call(self, at: int) -> None:
        """Record that a call was permitted and executed."""
        self._start(at)
        self._usage.calls += 1

    def add_tokens(self, tokens: float, usd: float = 0, at: int | None = None) -> None:
        """Record raw token consumption with a directly known cost."""
        _require_consumption("tokens", tokens)
        _require_consumption("usd", usd)
        self._start(now_ms() if at is None else at)
        self._usage.tokens += tokens
        self._usage.usd += usd

    def add_usage(
        self,
        input_tokens: float,
        output_tokens: float,
        price: TokenPrice | Mapping[str, float] | None = None,
        at: int | None = None,
    ) -> None:
        """
        Record a model turn, deriving cost from a price table.
        Kept separate from add_tokens so the pricing assumption is visible in the
        caller rather than buried in a magic number.

        A plain mapping is accepted as well as a TokenPrice. The reference
        documentation shows an object literal, so a reader porting that example
        reaches for ``{"input": 0.003, "output": 0.015}``; rejecting it with an
        AttributeError deep in the ledger would be a poor welcome.
        """
        price = as_token_price(price)
        _require_consumption("input tokens", input_tokens)
        _require_consumption("output tokens", output_tokens)
        _require_consumption("price.input", price.input)
        _require_consumption("price.output", price.output)
        usd = (input_tokens / 1000) * price.input + (output_tokens / 1000) * price.output
        self.add_tokens(input_tokens + output_tokens, usd, at)

    def add_bytes(self, size: float, at: int | None = None) -> None:
        """
        Record the size of a tool result.

        Called after the tool has run, because the size of what comes back is
        not knowable before it does.
        """
        _require_consumption("bytes", size)
        self._start(at if at is not None else now_ms())
        self._usage.bytes += size

    def add_spend(self, usd: float, at: int | None = None) -> None:
        """Record spend that is not token-denominated, e.g. a paid API call."""
        _require_consumption("usd", usd)
        self._start(now_ms() if at is None else at)
        self._usage.usd += usd

    def reset(self) -> None:
        """Reset every counter. Used between runs when a process is long-lived."""
        self._usage = BudgetUsage()

    def _start(self, at: int) -> None:
        """The time budget starts at the first metered event, not at construction."""
        if self._usage.started_at is None:
            self._usage.started_at = at
