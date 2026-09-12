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
  /**
   * Hard ceiling on bytes returned BY tools across the run.
   *
   * This is the volume half of containment, and it catches a different attack
   * from the rules. Bulk exfiltration is rarely a forbidden action; it is a
   * permitted action repeated until it has drained something. Every individual
   * read passes the allowlist, and only the total gives it away.
   *
   * Note the ordering this imposes: a result's size cannot be known before the
   * tool runs, so a call that blows the ceiling completes and the NEXT one is
   * refused. A bytes ceiling therefore bounds a run at roughly the limit plus
   * one call's worth, not exactly the limit.
   */
  bytes?: number;
  /** Wall-clock ceiling for the run, in seconds, measured from the first call. */
  seconds?: number;
}

/** Live consumption for a run, compared against BudgetLimits. */
export interface BudgetUsage {
  calls: number;
  tokens: number;
  usd: number;
  /** Bytes returned by tools so far. See BudgetLimits.bytes. */
  bytes: number;
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
   * except `.` and `/`; `**` matches anything, separators included.
   *
   * So `**` is the match-every-tool pattern. A bare `*` matches only names
   * with no separator in them — it does NOT match "fs.read". Reach for `**`
   * when you mean "everything", particularly on a deny rule, where a glob
   * that under-matches leaves a hole rather than failing closed.
   */
  tools: string[];
  effect: Effect;
  /** Argument constraints, keyed by dotted path. All must hold for the rule to match. */
  when?: Record<string, ArgConstraint>;
  /** Throttle for calls matching this rule. Exceeding it denies. */
  limit?: RateLimit;
}

/**
 * The envelope a run declares before it starts, and a human approves once.
 *
 * This is what makes capacity limits usable rather than annoying. A global
 * threshold ("50MB is suspicious") is either too loose to catch anything or
 * too tight to live with, because it has to guess at every job at once. A
 * declared envelope does not guess: a render job that asked for an hour and
 * two gigabytes gets exactly that without interruption, and the signal is not
 * "this looks like a lot" but "this run left the envelope its operator
 * approved". Approve at the start, hear nothing until a warn threshold.
 *
 * The plan is written into the audit chain as its first entry, so what was
 * authorised is part of the tamper-evident record, not just what happened.
 */
export interface RunPlan {
  /** What this run is for, in the operator's words. Carried into the audit log. */
  purpose: string;
  /** Who approved the envelope. Recorded, never verified by Leash itself. */
  approvedBy?: string;
  /**
   * Fractions of the budget (0-1) at which the run reports to a human.
   * Each threshold fires at most once. Defaults to [0.8, 0.95].
   */
  warnAt?: number[];
}

/** Emitted when consumption crosses one of the plan's warn thresholds. */
export interface BudgetWarning {
  /** Which budget dimension crossed. */
  dimension: 'calls' | 'tokens' | 'usd' | 'seconds' | 'bytes';
  /** The threshold that fired, as a fraction of the limit. */
  threshold: number;
  /** Consumption and ceiling for that dimension. */
  used: number;
  limit: number;
  /** Ready-to-send summary, e.g. for a Slack message. */
  message: string;
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
  /** The declared, pre-approved envelope for a run. See RunPlan. */
  plan?: RunPlan;
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
