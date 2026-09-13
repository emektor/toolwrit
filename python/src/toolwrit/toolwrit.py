"""
The runtime object an application holds.

Toolwrit ties together the three pieces that have to agree with each other:
the policy engine (may this happen), the ledger (is there capacity left) and
the audit chain (what actually happened). Keeping them behind one object is
what stops an integration from recording a decision it did not enforce.

There are two guard methods rather than one. Python cannot await from a
synchronous frame, so ``guard`` serves callers whose tool and approval handler
are ordinary functions, and ``guard_async`` serves everyone else -- it awaits
whatever it is given and accepts plain functions unchanged. Both run the same
evaluate-record-enforce sequence; only the calling convention differs.
"""

from __future__ import annotations

import asyncio
import inspect
import uuid
from collections.abc import Mapping
from typing import Any, Awaitable, Callable, Sequence, TypeVar

from .audit.chain import AuditEntry, AuditLog, canonicalize
from .budget.ledger import Ledger, TokenPrice, now_ms
from ._js import js_locale_integer, js_number, js_round, js_to_fixed, to_jsonable
from .policy.engine import evaluate
from .types import (
    BudgetUsage,
    BudgetWarning,
    Decision,
    EvalContext,
    Policy,
    ToolCall,
    Violation,
)

T = TypeVar("T")

#: Called when a rule's effect is "ask". Return True to permit the call.
#: Without a handler, "ask" is treated as a denial: an unattended run must not
#: silently upgrade itself to allowed.
ApprovalHandler = Callable[[ToolCall, Decision], "bool | Awaitable[bool]"]

#: Warn thresholds used when a plan does not name its own.
DEFAULT_WARN_AT = [0.8, 0.95]


class ToolwritDenied(Exception):
    """Thrown when a guarded call is refused. Catch this to feed the agent an error."""

    def __init__(self, tool: str, decision: Decision, audit_hash: str) -> None:
        super().__init__(f"toolwrit: {tool} denied — {decision.reason}")
        self.tool = tool
        self.decision = decision
        #: Hash of the audit entry recording the refusal. Quote it in support tickets.
        self.audit_hash = audit_hash


def size_of(result: Any) -> int:
    """
    Size of a tool result, in bytes.

    Deterministic by construction: the same result always measures the same, so
    a replayed audit log reaches the same verdict. Structured results are
    measured by their canonical JSON length, which equals what the TypeScript
    implementation gets from JSON.stringify -- sorting keys reorders bytes but
    does not add or remove any. A result that cannot be serialised falls back to
    its string form and is therefore UNDER-counted: documented rather than
    hidden, because under-counting a volume ceiling fails open.
    """
    if result is None:
        return 0
    if isinstance(result, str):
        return len(result.encode("utf-8"))
    if isinstance(result, (bytes, bytearray, memoryview)):
        return len(bytes(result))

    try:
        return len(canonicalize(result).encode("utf-8"))
    except Exception:
        return len(str(result).encode("utf-8"))


def _format(value: float) -> str:
    """Readable numbers in warning text: 12500 -> "12,500", 1.5 -> "1.50"."""
    return js_locale_integer(value) if float(value).is_integer() else js_to_fixed(value, 2)


class Toolwrit:
    def __init__(
        self,
        policy: Policy,
        *,
        run: str | None = None,
        audit_file: str | None = None,
        redact: Sequence[str] | None = None,
        on_ask: ApprovalHandler | None = None,
        on_warn: Callable[[BudgetWarning], None] | None = None,
        now: Callable[[], int] | None = None,
    ) -> None:
        self._policy = policy
        self._on_ask = on_ask
        self._on_warn = on_warn
        self.run = run or str(uuid.uuid4())
        self._now = now or now_ms
        self._ledger = Ledger()
        self._audit = AuditLog(run=self.run, file=audit_file, redact=redact)
        #: "dimension:threshold" keys already reported, so each fires exactly once.
        self._warned: set[str] = set()
        self._lock: asyncio.Lock | None = None
        self._lock_loop: object | None = None

        # The approved envelope goes into the chain before anything can consume it.
        # Recording it as an ordinary entry keeps the chain uniform -- one shape,
        # one verifier -- and means an operator cannot later claim a different
        # budget was authorised than the one the run actually started under.
        if policy.plan is not None:
            plan = policy.plan
            self._audit.record(
                self._to_call(
                    "toolwrit:plan",
                    {
                        "purpose": plan.purpose,
                        "approvedBy": plan.approvedBy,
                        "budget": to_jsonable(policy.budget)
                        if policy.budget is not None
                        else None,
                        "warnAt": plan.warnAt
                        if plan.warnAt is not None
                        else list(DEFAULT_WARN_AT),
                    },
                ),
                Decision(
                    effect="allow",
                    rule="plan",
                    reason="run plan recorded",
                    violations=[],
                ),
                {"calls": 0, "tokens": 0, "usd": 0, "bytes": 0},
            )

    def check(self, tool: str, args: dict[str, Any] | None = None) -> Decision:
        """
        Evaluate a call without recording or executing anything.
        Use this for dry-runs and for showing an operator what a policy would do.
        """
        return evaluate(self._to_call(tool, args or {}), self._context())

    def guard(
        self,
        tool: str,
        args: dict[str, Any],
        execute: Callable[[], T],
    ) -> T:
        """
        Evaluate, record, and -- if permitted -- run ``execute``.

        The decision is written to the audit chain before ``execute`` is invoked,
        so a crash inside the tool still leaves evidence that the call was
        authorised. A refusal raises ToolwritDenied rather than returning a
        sentinel, because a silently-skipped side effect is the worst possible
        failure mode here.
        """
        call = self._to_call(tool, args)
        decision = evaluate(call, self._context())

        if decision.effect == "ask":
            approved = self._ask(call, decision)
            if inspect.isawaitable(approved):
                # Close it rather than leaking a never-awaited coroutine: the
                # handler has not run any of its body yet, so nothing is lost.
                getattr(approved, "close", lambda: None)()
                raise TypeError(
                    "the configured on_ask handler is asynchronous; use guard_async"
                )
            decision = self._resolve_ask(decision, approved)

        self._enforce(tool, call, decision)
        return self._measure(call, execute())

    async def guard_async(
        self,
        tool: str,
        args: dict[str, Any],
        execute: Callable[[], T | Awaitable[T]],
    ) -> T:
        """``guard`` for async callers: awaits the approval handler and the tool."""
        call = self._to_call(tool, args)

        # Deciding, recording and counting is one critical section. Awaiting an
        # approval handler used to leave it interruptible: concurrent calls all
        # evaluated against the same pre-approval snapshot, so three guards
        # against a budget of one were all approved and all executed. The tool
        # itself still runs outside the lock, and the lock is only ever
        # contended while an approval is genuinely pending.
        async with self._decision_lock():
            decision = evaluate(call, self._context())

            if decision.effect == "ask":
                approved = self._ask(call, decision)
                if inspect.isawaitable(approved):
                    approved = await approved
                decision = self._resolve_ask(decision, approved)

            self._enforce(tool, call, decision)

            # A bytes ceiling is the one budget whose consumption is unknowable
            # until after the tool has run, so concurrent calls would each be
            # decided against a total none of them had contributed to yet. Where
            # a ceiling is declared the tool runs inside the critical section
            # too, bounding a run at the limit plus one call -- the bound the
            # documentation promises. A policy with no bytes budget keeps full
            # concurrency, so the cost falls only on the feature that needs it.
            if self._policy.budget is not None and self._policy.budget.bytes is not None:
                inside = execute()
                if inspect.isawaitable(inside):
                    inside = await inside
                return self._measure(call, inside)  # type: ignore[arg-type]

        result = execute()
        if inspect.isawaitable(result):
            result = await result
        return self._measure(call, result)  # type: ignore[arg-type]

    def meter(
        self,
        input_tokens: float,
        output_tokens: float,
        price: TokenPrice | Mapping[str, float] | None = None,
    ) -> None:
        """
        Record model consumption against the budget. Call after every model turn.

        ``price`` may be a TokenPrice or a plain mapping such as
        ``{"input": 0.003, "output": 0.015}``.
        """
        self._ledger.add_usage(input_tokens, output_tokens, price, self._now())
        self._report_progress()

    def spend(self, usd: float) -> None:
        """Record non-token spend, e.g. a metered third-party API call."""
        self._ledger.add_spend(usd, self._now())
        self._report_progress()

    def usage(self) -> BudgetUsage:
        """Current consumption. Useful for progress bars and for tests."""
        return self._ledger.snapshot()

    def entries(self) -> list[AuditEntry]:
        """The audit chain recorded so far."""
        return self._audit.all()

    def head(self) -> str:
        """Hash of the newest audit entry -- the receipt for this run so far."""
        return self._audit.head()

    # -- internals ---------------------------------------------------------- #

    def _context(self) -> EvalContext:
        return EvalContext(
            policy=self._policy,
            usage=self._ledger.snapshot(),
            history=self._audit.history(),
        )

    def _enforce(self, tool: str, call: ToolCall, decision: Decision) -> None:
        """Record the verdict, then act on it. Recording comes first, always."""
        entry = self._audit.record(call, decision, self._usage_for_audit())
        if decision.effect != "allow":
            raise ToolwritDenied(tool, decision, entry.hash)
        self._ledger.count_call(call.at)

    def _decision_lock(self) -> asyncio.Lock:
        """
        The async critical section's lock, created on the running loop.

        Built lazily because a Toolwrit may be constructed outside any event loop,
        and an asyncio.Lock bound to the wrong loop is worse than none. The
        synchronous ``guard`` does not take it: it has no await point, so it
        cannot interleave with itself on one thread. Mixing ``guard`` and
        ``guard_async`` on one instance is therefore not protected -- pick one.
        """
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is not loop:
            self._lock = asyncio.Lock()
            self._lock_loop = loop
        return self._lock

    def _measure(self, call: ToolCall, result: T) -> T:
        """
        The volume half of containment: record how much the tool returned.

        Attributed to the call's own timestamp rather than a fresh clock read,
        so the ledger does not depend on how long the tool happened to take.
        """
        self._ledger.add_bytes(size_of(result), call.at)
        self._report_progress()
        return result

    def _ask(self, call: ToolCall, decision: Decision) -> Any:
        return None if self._on_ask is None else self._on_ask(call, decision)

    def _resolve_ask(self, decision: Decision, approved: Any) -> Decision:
        if self._on_ask is None:
            return Decision(
                effect="deny",
                rule=decision.rule,
                reason=f"{decision.reason} (no approval handler configured)",
                violations=[
                    Violation(
                        rule=decision.rule if decision.rule is not None else "policy",
                        constraint="ask",
                        message=(
                            "this call requires approval but no onAsk handler was "
                            "configured; denying by default"
                        ),
                    )
                ],
            )

        if approved:
            return Decision(
                effect="allow",
                rule=decision.rule,
                reason=f"{decision.reason} (approved)",
                violations=list(decision.violations),
            )
        return Decision(
            effect="deny",
            rule=decision.rule,
            reason=f"{decision.reason} (approval refused)",
            violations=[
                Violation(
                    rule=decision.rule if decision.rule is not None else "policy",
                    constraint="ask",
                    message="approval was refused by the configured handler",
                )
            ],
        )

    def _report_progress(self) -> None:
        """
        Fire any warn thresholds the latest consumption has crossed.

        Warnings are recorded in the audit chain as well as delivered to on_warn,
        so "nobody told me it was at 95%" is answerable from the log rather than
        from whether a Slack message happened to be delivered.
        """
        plan, budget = self._policy.plan, self._policy.budget
        if plan is None or budget is None:
            return

        thresholds = plan.warnAt if plan.warnAt is not None else DEFAULT_WARN_AT
        usage = self._ledger.snapshot()
        elapsed = (
            0 if usage.started_at is None else (self._now() - usage.started_at) / 1000
        )

        dimensions: list[tuple[str, float, float | None]] = [
            ("calls", usage.calls, budget.calls),
            ("tokens", usage.tokens, budget.tokens),
            ("usd", usage.usd, budget.usd),
            ("bytes", usage.bytes, budget.bytes),
            ("seconds", elapsed, budget.seconds),
        ]

        for dimension, used, limit in dimensions:
            if limit is None or limit <= 0:
                continue
            fraction = used / limit

            for threshold in thresholds:
                key = f"{dimension}:{js_number(threshold)}"
                if fraction < threshold or key in self._warned:
                    continue
                self._warned.add(key)

                warning = BudgetWarning(
                    dimension=dimension,  # type: ignore[arg-type]
                    threshold=threshold,
                    used=used,
                    limit=limit,
                    message=(
                        f'run "{self.run}" ({plan.purpose}) has used '
                        f"{_format(used)}/{_format(limit)} {dimension} — "
                        f"{js_round(fraction * 100)}% of the approved envelope"
                    ),
                )

                self._audit.record(
                    self._to_call(
                        "toolwrit:warning",
                        {
                            "dimension": warning.dimension,
                            "threshold": warning.threshold,
                            "used": warning.used,
                            "limit": warning.limit,
                            "message": warning.message,
                        },
                    ),
                    Decision(
                        effect="allow",
                        rule="plan",
                        reason=warning.message,
                        violations=[],
                    ),
                    {
                        "calls": usage.calls,
                        "tokens": usage.tokens,
                        "usd": usage.usd,
                        "bytes": usage.bytes,
                    },
                )
                if self._on_warn is not None:
                    self._on_warn(warning)

    def _to_call(self, tool: str, args: dict[str, Any]) -> ToolCall:
        return ToolCall(id=str(uuid.uuid4()), tool=tool, args=args, at=self._now())

    def _usage_for_audit(self) -> dict[str, float]:
        usage = self._ledger.snapshot()
        return {
            "calls": usage.calls,
            "tokens": usage.tokens,
            "usd": usage.usd,
            "bytes": usage.bytes,
        }
