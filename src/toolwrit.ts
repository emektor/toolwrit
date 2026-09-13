/**
 * The runtime object an application holds.
 *
 * Toolwrit ties together the three pieces that have to agree with each other:
 * the policy engine (may this happen), the ledger (is there capacity left) and
 * the audit chain (what actually happened). Keeping them behind one object is
 * what stops an integration from recording a decision it did not enforce.
 */

import { randomUUID } from 'node:crypto';
import { AuditLog, type AuditEntry } from './audit/chain.js';
import { Ledger, type TokenPrice } from './budget/ledger.js';
import { evaluate } from './policy/engine.js';
import type { BudgetWarning, Decision, Policy, ToolCall } from './types.js';

/** Thrown when a guarded call is refused. Catch this to feed the agent an error. */
export class ToolwritDenied extends Error {
  constructor(
    readonly tool: string,
    readonly decision: Decision,
    /** Hash of the audit entry recording the refusal. Quote it in support tickets. */
    readonly auditHash: string
  ) {
    super(`toolwrit: ${tool} denied — ${decision.reason}`);
    this.name = 'ToolwritDenied';
  }
}

/**
 * Called when a rule's effect is "ask". Return true to permit the call.
 * Without a handler, "ask" is treated as a denial: an unattended run must not
 * silently upgrade itself to allowed.
 */
export type ApprovalHandler = (call: ToolCall, decision: Decision) => boolean | Promise<boolean>;

export interface ToolwritOptions {
  policy: Policy;
  /** Run identifier stamped on audit entries. Generated when omitted. */
  run?: string;
  /** JSONL file to append audit entries to. Entries are buffered either way. */
  auditFile?: string;
  /** Dotted argument paths to redact before an argument is written to the log. */
  redact?: string[];
  /** Approval callback for "ask" rules. */
  onAsk?: ApprovalHandler;
  /**
   * Called when consumption crosses a warn threshold declared in the plan.
   * Fires at most once per threshold per dimension. Keep it non-blocking —
   * it runs inline with metering; queue the Slack post rather than awaiting it.
   */
  onWarn?: (warning: BudgetWarning) => void;
  /** Injectable clock. Tests pass a fixed one; production leaves it alone. */
  now?: () => number;
}

/** Warn thresholds used when a plan does not name its own. */
const DEFAULT_WARN_AT = [0.8, 0.95];

/**
 * Size of a tool result, in bytes.
 *
 * Deterministic by construction: the same result always measures the same, so
 * a replayed audit log reaches the same verdict. A result we cannot serialise
 * (a cycle, a class with a throwing toJSON) falls back to its string form and
 * is therefore UNDER-counted -- documented rather than hidden, because
 * under-counting a volume ceiling fails open.
 */
function sizeOf(result: unknown): number {
  if (result === null || result === undefined) return 0;
  if (typeof result === 'string') return Buffer.byteLength(result, 'utf8');
  if (ArrayBuffer.isView(result)) return result.byteLength;
  if (result instanceof ArrayBuffer) return result.byteLength;

  try {
    const json = JSON.stringify(result);
    // stringify returns undefined for a function or a lone symbol.
    return json === undefined ? 0 : Buffer.byteLength(json, 'utf8');
  } catch {
    return Buffer.byteLength(String(result), 'utf8');
  }
}

/** Readable numbers in warning text: 12500 -> "12,500", 1.5 -> "1.5". */
function format(value: number): string {
  return Number.isInteger(value) ? value.toLocaleString('en-US') : value.toFixed(2);
}

export class Toolwrit {
  readonly run: string;
  private readonly ledger = new Ledger();
  private readonly audit: AuditLog;
  private readonly now: () => number;
  /** "dimension:threshold" keys already reported, so each fires exactly once. */
  private readonly warned = new Set<string>();
  /** Tail of the decision queue; see serialize(). */
  private critical: Promise<unknown> = Promise.resolve();

  /**
   * Run `section` with no other decision section interleaved.
   *
   * Chaining onto the previous tail rather than using a lock library keeps this
   * to five lines and free of dependencies. A section that throws still
   * releases, because the chain is advanced with a settled-either-way promise.
   */
  private serialize<T>(section: () => Promise<T>): Promise<T> {
    const result = this.critical.then(section, section);
    this.critical = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  constructor(private readonly options: ToolwritOptions) {
    this.run = options.run ?? randomUUID();
    this.now = options.now ?? Date.now;
    this.audit = new AuditLog({
      run: this.run,
      ...(options.auditFile ? { file: options.auditFile } : {}),
      ...(options.redact ? { redact: options.redact } : {}),
    });

    // The approved envelope goes into the chain before anything can consume it.
    // Recording it as an ordinary entry keeps the chain uniform -- one shape,
    // one verifier -- and means an operator cannot later claim a different
    // budget was authorised than the one the run actually started under.
    if (options.policy.plan) {
      const plan = options.policy.plan;
      this.audit.record(
        this.toCall('toolwrit:plan', {
          purpose: plan.purpose,
          approvedBy: plan.approvedBy ?? null,
          budget: options.policy.budget ?? null,
          warnAt: plan.warnAt ?? DEFAULT_WARN_AT,
        }),
        { effect: 'allow', rule: 'plan', reason: 'run plan recorded', violations: [] },
        { calls: 0, tokens: 0, usd: 0, bytes: 0 }
      );
    }
  }

  /**
   * Evaluate a call without recording or executing anything.
   * Use this for dry-runs and for showing an operator what a policy would do.
   */
  check(tool: string, args: Record<string, unknown> = {}): Decision {
    return evaluate(this.toCall(tool, args), {
      policy: this.options.policy,
      usage: this.ledger.snapshot(),
      history: this.audit.history(),
    });
  }

  /**
   * Evaluate, record, and — if permitted — run `execute`.
   *
   * The decision is written to the audit chain before `execute` is invoked, so
   * a crash inside the tool still leaves evidence that the call was authorised.
   * A refusal throws ToolwritDenied rather than returning a sentinel, because a
   * silently-skipped side effect is the worst possible failure mode here.
   */
  async guard<T>(
    tool: string,
    args: Record<string, unknown>,
    execute: () => T | Promise<T>
  ): Promise<T> {
    const call = this.toCall(tool, args);

    // Deciding, recording and counting is one critical section. It used to be
    // interruptible: an "ask" rule awaits its approval handler, and concurrent
    // calls all evaluated against the same pre-approval snapshot, so three
    // guards against a budget of one were all approved and all executed. The
    // tool itself still runs outside the lock, and the common path holds it
    // without ever awaiting, so nothing serialises unless an approval is
    // genuinely pending -- which is the one case where serialising is right.
    const { decision, entry } = await this.serialize(async () => {
      let verdict = evaluate(call, {
        policy: this.options.policy,
        usage: this.ledger.snapshot(),
        history: this.audit.history(),
      });

      if (verdict.effect === 'ask') {
        verdict = await this.resolveAsk(call, verdict);
      }

      const recorded = this.audit.record(call, verdict, this.usageForAudit());
      if (verdict.effect === 'allow') this.ledger.countCall(call.at);
      return { decision: verdict, entry: recorded };
    });

    if (decision.effect !== 'allow') {
      throw new ToolwritDenied(tool, decision, entry.hash);
    }

    const result = await execute();
    // The volume half of containment. Measured after the fact because a
    // result's size is not knowable before the tool produces it.
    // Attributed to the call's own timestamp rather than a fresh clock read:
    // the bytes belong to that call, and reading the clock again here would
    // make the ledger depend on how long the tool happened to take.
    this.ledger.addBytes(sizeOf(result), call.at);
    this.reportProgress();
    return result;
  }

  /** Record model consumption against the budget. Call after every model turn. */
  meter(input: number, output: number, price?: TokenPrice): void {
    this.ledger.addUsage(input, output, price, this.now());
    this.reportProgress();
  }

  /** Record non-token spend, e.g. a metered third-party API call. */
  spend(usd: number): void {
    this.ledger.addSpend(usd, this.now());
    this.reportProgress();
  }

  /**
   * Fire any warn thresholds the latest consumption has crossed.
   *
   * Warnings are recorded in the audit chain as well as delivered to onWarn,
   * so "nobody told me it was at 95%" is answerable from the log rather than
   * from whether a Slack message happened to be delivered.
   */
  private reportProgress(): void {
    const { plan, budget } = this.options.policy;
    if (!plan || !budget) return;

    const thresholds = plan.warnAt ?? DEFAULT_WARN_AT;
    const usage = this.ledger.snapshot();
    const elapsed = usage.startedAt === null ? 0 : (this.now() - usage.startedAt) / 1000;

    const dimensions: [BudgetWarning['dimension'], number, number | undefined][] = [
      ['calls', usage.calls, budget.calls],
      ['tokens', usage.tokens, budget.tokens],
      ['usd', usage.usd, budget.usd],
      ['bytes', usage.bytes, budget.bytes],
      ['seconds', elapsed, budget.seconds],
    ];

    for (const [dimension, used, limit] of dimensions) {
      if (limit === undefined || limit <= 0) continue;
      const fraction = used / limit;

      for (const threshold of thresholds) {
        const key = `${dimension}:${threshold}`;
        if (fraction < threshold || this.warned.has(key)) continue;
        this.warned.add(key);

        const warning: BudgetWarning = {
          dimension,
          threshold,
          used,
          limit,
          message:
            `run "${this.run}" (${plan.purpose}) has used ` +
            `${format(used)}/${format(limit)} ${dimension} — ` +
            `${Math.round(fraction * 100)}% of the approved envelope`,
        };

        this.audit.record(
          this.toCall('toolwrit:warning', { ...warning }),
          { effect: 'allow', rule: 'plan', reason: warning.message, violations: [] },
          { calls: usage.calls, tokens: usage.tokens, usd: usage.usd, bytes: usage.bytes }
        );
        this.options.onWarn?.(warning);
      }
    }
  }

  /** Current consumption. Useful for progress bars and for tests. */
  usage() {
    return this.ledger.snapshot();
  }

  /** The audit chain recorded so far. */
  entries(): readonly AuditEntry[] {
    return this.audit.all();
  }

  /** Hash of the newest audit entry — the receipt for this run so far. */
  head(): string {
    return this.audit.head();
  }

  private async resolveAsk(call: ToolCall, decision: Decision): Promise<Decision> {
    if (!this.options.onAsk) {
      return {
        ...decision,
        effect: 'deny',
        reason: `${decision.reason} (no approval handler configured)`,
        violations: [
          {
            rule: decision.rule ?? 'policy',
            constraint: 'ask',
            message:
              'this call requires approval but no onAsk handler was configured; denying by default',
          },
        ],
      };
    }

    const approved = await this.options.onAsk(call, decision);
    return approved
      ? { ...decision, effect: 'allow', reason: `${decision.reason} (approved)` }
      : {
          ...decision,
          effect: 'deny',
          reason: `${decision.reason} (approval refused)`,
          violations: [
            {
              rule: decision.rule ?? 'policy',
              constraint: 'ask',
              message: 'approval was refused by the configured handler',
            },
          ],
        };
  }

  private toCall(tool: string, args: Record<string, unknown>): ToolCall {
    return { id: randomUUID(), tool, args, at: this.now() };
  }

  private usageForAudit() {
    const { calls, tokens, usd, bytes } = this.ledger.snapshot();
    return { calls, tokens, usd, bytes };
  }
}
