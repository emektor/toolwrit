"""
Core contracts for Leash.

Everything in this file is data. The policy engine is a pure function over
these shapes: no network, no model calls, no randomness. That is the whole
point -- an enforcement decision must be reproducible from the policy, the
call and the ledger state alone, so it can be replayed during an audit.

Each dataclass declares ``JSON_OMIT_IF_NONE``: the optional fields that are
simply *absent* from the JSON form rather than present-and-null. The
distinction is load-bearing, because the audit chain hashes that JSON and
``Decision.rule`` -- which is not in any omit set -- must serialise as
``"rule":null`` to match the TypeScript chain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar, Literal, Sequence

Effect = Literal["allow", "deny", "ask"]
ArgType = Literal["string", "number", "boolean", "object", "array"]


@dataclass
class ToolCall:
    """A single tool invocation an agent wants to make."""

    #: Caller-supplied id, unique within a run. Used to correlate audit entries.
    id: str
    #: Tool name as the agent asked for it, e.g. "fs.write" or "github/create_issue".
    tool: str
    #: Arguments the agent proposed. Untrusted: this is model output.
    args: dict[str, Any]
    #: Milliseconds since epoch. Injected so evaluation stays deterministic in tests.
    at: int


@dataclass
class BudgetLimits:
    """What a run is allowed to consume before Leash cuts it off."""

    JSON_OMIT_IF_NONE: ClassVar[frozenset[str]] = frozenset(
        {"calls", "tokens", "usd", "bytes", "seconds"}
    )

    #: Hard ceiling on total tool calls in the run.
    calls: float | None = None
    #: Hard ceiling on input+output tokens attributed to the run.
    tokens: float | None = None
    #: Hard ceiling on estimated spend, in USD.
    usd: float | None = None
    #: Hard ceiling on bytes returned BY tools across the run.
    #: Bulk exfiltration is a permitted action repeated, not a forbidden one,
    #: so only the running total gives it away. A result's size is unknowable
    #: before the tool runs, so the breaching call completes and the NEXT one
    #: is refused: this bounds a run at the limit plus one call.
    bytes: float | None = None
    #: Wall-clock ceiling for the run, in seconds, measured from the first call.
    seconds: float | None = None


@dataclass
class BudgetUsage:
    """Live consumption for a run, compared against BudgetLimits."""

    calls: int = 0
    tokens: float = 0
    usd: float = 0
    #: Bytes returned by tools so far.
    bytes: float = 0
    #: Milliseconds since epoch of the first metered event, or None before it.
    started_at: int | None = None


@dataclass
class ArgConstraint:
    """
    Constraints applied to a single argument, addressed by a dotted path
    (``path``, ``body.recipients.0``). Every constraint present must hold; an
    absent value fails any constraint other than ``optional``.
    """

    JSON_OMIT_IF_NONE: ClassVar[frozenset[str]] = frozenset(
        {
            "optional", "oneOf", "noneOf", "matches", "startsWith", "excludes",
            "min", "max", "maxLength", "minLength", "urlHosts", "type",
        }
    )

    #: Allow the argument to be missing entirely. Default false.
    optional: bool | None = None
    #: Value must be one of these (deep-equality for objects).
    oneOf: list[Any] | None = None
    #: Value must NOT be one of these.
    noneOf: list[Any] | None = None
    #: String must match this regular expression (anchored by the author, not by us).
    matches: str | None = None
    #: String must start with one of these prefixes. Used for filesystem scoping.
    startsWith: list[str] | None = None
    #: String must NOT contain any of these substrings. Cheap traversal guard.
    excludes: list[str] | None = None
    #: Inclusive numeric bounds.
    min: float | None = None
    max: float | None = None
    #: Length bounds for strings and arrays.
    maxLength: float | None = None
    minLength: float | None = None
    #: Value must parse as a URL whose hostname is in this list (exact or ".suffix").
    urlHosts: list[str] | None = None
    #: Runtime type check.
    type: ArgType | None = None


@dataclass
class RateLimit:
    """Per-rule throttle, evaluated against the audit ledger."""

    JSON_OMIT_IF_NONE: ClassVar[frozenset[str]] = frozenset({"perSeconds"})

    #: Maximum matching calls allowed inside the window.
    max: int = 0
    #: Sliding window length in seconds. Omit for "per run".
    perSeconds: float | None = None


@dataclass
class PolicyRule:
    """One clause of a policy document."""

    JSON_OMIT_IF_NONE: ClassVar[frozenset[str]] = frozenset(
        {"description", "when", "limit"}
    )

    #: Stable identifier, surfaced in decisions and audit entries.
    id: str
    #: Tool name globs this rule applies to. ``*`` matches any run of characters
    #: except ``.`` and ``/``; ``**`` matches anything, separators included.
    #:
    #: So ``**`` is the match-every-tool pattern. A bare ``*`` matches only names
    #: with no separator in them -- it does NOT match "fs.read". Reach for ``**``
    #: when you mean "everything", particularly on a deny rule, where a glob
    #: that under-matches leaves a hole rather than failing closed.
    tools: list[str] = field(default_factory=list)
    effect: Effect = "allow"
    #: Human-readable justification. Shows up in denial messages and reports.
    description: str | None = None
    #: Argument constraints, keyed by dotted path. All must hold for the rule to match.
    when: dict[str, ArgConstraint] | None = None
    #: Throttle for calls matching this rule. Exceeding it denies.
    limit: RateLimit | None = None


@dataclass
class RunPlan:
    """
    The envelope a run declares before it starts, and a human approves once.

    This is what makes capacity limits usable rather than annoying. A global
    threshold ("50MB is suspicious") is either too loose to catch anything or
    too tight to live with, because it has to guess at every job at once. A
    declared envelope does not guess: a render job that asked for an hour and
    two gigabytes gets exactly that without interruption, and the signal is not
    "this looks like a lot" but "this run left the envelope its operator
    approved". Approve at the start, hear nothing until a warn threshold.

    The plan is written into the audit chain as its first entry, so what was
    authorised is part of the tamper-evident record, not just what happened.
    """

    JSON_OMIT_IF_NONE: ClassVar[frozenset[str]] = frozenset({"approvedBy", "warnAt"})

    #: What this run is for, in the operator's words. Carried into the audit log.
    purpose: str
    #: Who approved the envelope. Recorded, never verified by Leash itself.
    approvedBy: str | None = None
    #: Fractions of the budget (0-1) at which the run reports to a human.
    #: Each threshold fires at most once. Defaults to [0.8, 0.95].
    warnAt: list[float] | None = None


@dataclass
class BudgetWarning:
    """Emitted when consumption crosses one of the plan's warn thresholds."""

    #: Which budget dimension crossed.
    dimension: Literal["calls", "tokens", "usd", "bytes", "seconds"]
    #: The threshold that fired, as a fraction of the limit.
    threshold: float
    #: Consumption and ceiling for that dimension.
    used: float
    limit: float
    #: Ready-to-send summary, e.g. for a Slack message.
    message: str


@dataclass
class Policy:
    """A complete, self-contained enforcement policy."""

    JSON_OMIT_IF_NONE: ClassVar[frozenset[str]] = frozenset(
        {"name", "default", "budget", "plan"}
    )

    #: Schema version. Only "1" exists today; unknown versions are rejected.
    version: Literal["1"] = "1"
    rules: list[PolicyRule] = field(default_factory=list)
    #: Free-text label carried into audit exports.
    name: str | None = None
    #: Effect when no rule matches. Defaults to "deny" -- Leash is deny-by-default.
    default: Effect | None = None
    budget: BudgetLimits | None = None
    #: The declared, pre-approved envelope for a run. See RunPlan.
    plan: RunPlan | None = None


@dataclass
class Violation:
    """Why a call was refused, or which constraint a rule turned on."""

    JSON_OMIT_IF_NONE: ClassVar[frozenset[str]] = frozenset({"path"})

    #: Rule that produced this violation, or "budget" / "policy" for engine-level ones.
    rule: str
    #: Constraint name that failed, e.g. "startsWith" or "usd".
    constraint: str
    #: Operator-facing explanation. Safe to show to the agent as a tool error.
    message: str
    #: Dotted argument path, when the violation is argument-specific.
    path: str | None = None


@dataclass
class Decision:
    """The engine's verdict on one tool call."""

    effect: Effect
    #: Id of the rule that decided this, or None when the default applied.
    rule: str | None
    #: Short reason, suitable for a log line.
    reason: str
    #: Empty for a clean allow.
    violations: list[Violation] = field(default_factory=list)


@dataclass(frozen=True)
class HistoryEntry:
    """A prior call, in the only shape the engine needs for rate limiting."""

    tool: str
    rule: str | None
    at: int


@dataclass
class EvalContext:
    """State the engine reads but never mutates."""

    policy: Policy
    usage: BudgetUsage = field(default_factory=BudgetUsage)
    #: Prior calls in this run, oldest first. Used only for rate limiting.
    history: Sequence[HistoryEntry] = field(default_factory=tuple)
