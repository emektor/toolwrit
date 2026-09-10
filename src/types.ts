/**
 * Core contracts for Leash.
 *
 * Everything in this file is data. The policy engine is a pure function over
 * these shapes: no network, no model calls, no randomness. That is the whole
 * point — an enforcement decision must be reproducible from the policy, the
 * call and the ledger state alone, so it can be replayed during an audit.
 */

/** A single tool invocation an agent wants to make. */
export interface ToolCall {
  /** Caller-supplied id, unique within a run. Used to correlate audit entries. */
  id: string;
  /** Tool name as the agent asked for it, e.g. "fs.write" or "github/create_issue". */
  tool: string;
  /** Arguments the agent proposed. Untrusted: this is model output. */
  args: Record<string, unknown>;
  /** Milliseconds since epoch. Injected so evaluation stays deterministic in tests. */
  at: number;
}

/** What a run is allowed to consume before Leash cuts it off. */
export interface BudgetLimits {
  /** Hard ceiling on total tool calls in the run. */
  calls?: number;
  /** Hard ceiling on input+output tokens attributed to the run. */
  tokens?: number;
  /** Hard ceiling on estimated spend, in USD. */
  usd?: number;
  /** Wall-clock ceiling for the run, in seconds, measured from the first call. */
  seconds?: number;
}

/** Live consumption for a run, compared against BudgetLimits. */
export interface BudgetUsage {
  calls: number;
  tokens: number;
  usd: number;
  /** Milliseconds since epoch of the first metered event, or null before it. */
  startedAt: number | null;
}

/**
 * Constraints applied to a single argument, addressed by a dotted path
 * (`path`, `body.recipients.0`). Every constraint present must hold; an absent
 * value fails any constraint other than `optional`.
 */
export interface ArgConstraint {
  /** Allow the argument to be missing entirely. Default false. */
  optional?: boolean;
  /** Value must be one of these (deep-equality for objects). */
  oneOf?: unknown[];
  /** Value must NOT be one of these. */
  noneOf?: unknown[];
  /** String must match this regular expression (anchored by the author, not by us). */
  matches?: string;
  /** String must start with one of these prefixes. Used for filesystem scoping. */
  startsWith?: string[];
  /** String must NOT contain any of these substrings. Cheap traversal guard. */
  excludes?: string[];
  /** Inclusive numeric bounds. */
  min?: number;
  max?: number;
  /** Length bounds for strings and arrays. */
  maxLength?: number;
  minLength?: number;
  /** Value must parse as a URL whose hostname is in this list (exact or ".suffix"). */
  urlHosts?: string[];
  /** Runtime type check. */
  type?: 'string' | 'number' | 'boolean' | 'object' | 'array';
}

/** Per-rule throttle, evaluated against the audit ledger. */
export interface RateLimit {
  /** Maximum matching calls allowed inside the window. */
  max: number;
  /** Sliding window length in seconds. Omit for "per run". */
  perSeconds?: number;
}

export type Effect = 'allow' | 'deny' | 'ask';

/** One clause of a policy document. */
export interface PolicyRule {
  /** Stable identifier, surfaced in decisions and audit entries. */
  id: string;
  /** Human-readable justification. Shows up in denial messages and reports. */
  description?: string;
  /**
   * Tool name globs this rule applies to. `*` matches any run of characters
   * except `.` and `/`; `**` matches anything. A bare `*` means "every tool".
   */
  tools: string[];
  effect: Effect;
  /** Argument constraints, keyed by dotted path. All must hold for the rule to match. */
  when?: Record<string, ArgConstraint>;
  /** Throttle for calls matching this rule. Exceeding it denies. */
  limit?: RateLimit;
}

/** A complete, self-contained enforcement policy. */
export interface Policy {
  /** Schema version. Only "1" exists today; unknown versions are rejected. */
  version: '1';
  /** Free-text label carried into audit exports. */
  name?: string;
  /** Effect when no rule matches. Defaults to "deny" — Leash is deny-by-default. */
  default?: Effect;
  budget?: BudgetLimits;
  rules: PolicyRule[];
}

/** Why a call was refused, or which constraint a rule turned on. */
export interface Violation {
  /** Rule that produced this violation, or "budget" / "policy" for engine-level ones. */
  rule: string;
  /** Dotted argument path, when the violation is argument-specific. */
  path?: string;
  /** Constraint name that failed, e.g. "startsWith" or "usd". */
  constraint: string;
  /** Operator-facing explanation. Safe to show to the agent as a tool error. */
  message: string;
}

/** The engine's verdict on one tool call. */
export interface Decision {
  effect: Effect;
  /** Id of the rule that decided this, or null when the default applied. */
  rule: string | null;
  /** Short reason, suitable for a log line. */
  reason: string;
  /** Empty for a clean allow. */
  violations: Violation[];
}

/** State the engine reads but never mutates. */
export interface EvalContext {
  policy: Policy;
  usage: BudgetUsage;
  /** Prior calls in this run, oldest first. Used only for rate limiting. */
  history: readonly { tool: string; rule: string | null; at: number }[];
}
