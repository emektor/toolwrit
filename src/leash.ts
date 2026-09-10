/**
 * The runtime object an application holds.
 *
 * Leash ties together the three pieces that have to agree with each other:
 * the policy engine (may this happen), the ledger (is there capacity left) and
 * the audit chain (what actually happened). Keeping them behind one object is
 * what stops an integration from recording a decision it did not enforce.
 */

import { randomUUID } from 'node:crypto';
import { AuditLog, type AuditEntry } from './audit/chain.js';
import { Ledger, type TokenPrice } from './budget/ledger.js';
import { evaluate } from './policy/engine.js';
import type { Decision, Policy, ToolCall } from './types.js';

/** Thrown when a guarded call is refused. Catch this to feed the agent an error. */
export class LeashDenied extends Error {
  constructor(
    readonly tool: string,
    readonly decision: Decision,
    /** Hash of the audit entry recording the refusal. Quote it in support tickets. */
    readonly auditHash: string
  ) {
    super(`leash: ${tool} denied — ${decision.reason}`);
    this.name = 'LeashDenied';
  }
}

/**
 * Called when a rule's effect is "ask". Return true to permit the call.
 * Without a handler, "ask" is treated as a denial: an unattended run must not
 * silently upgrade itself to allowed.
 */
export type ApprovalHandler = (call: ToolCall, decision: Decision) => boolean | Promise<boolean>;

export interface LeashOptions {
  policy: Policy;
  /** Run identifier stamped on audit entries. Generated when omitted. */
  run?: string;
  /** JSONL file to append audit entries to. Entries are buffered either way. */
  auditFile?: string;
  /** Dotted argument paths to redact before an argument is written to the log. */
  redact?: string[];
  /** Approval callback for "ask" rules. */
  onAsk?: ApprovalHandler;
  /** Injectable clock. Tests pass a fixed one; production leaves it alone. */
  now?: () => number;
}

export class Leash {
  readonly run: string;
  private readonly ledger = new Ledger();
  private readonly audit: AuditLog;
  private readonly now: () => number;

  constructor(private readonly options: LeashOptions) {
    this.run = options.run ?? randomUUID();
    this.now = options.now ?? Date.now;
    this.audit = new AuditLog({
      run: this.run,
      ...(options.auditFile ? { file: options.auditFile } : {}),
      ...(options.redact ? { redact: options.redact } : {}),
    });
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
   * A refusal throws LeashDenied rather than returning a sentinel, because a
   * silently-skipped side effect is the worst possible failure mode here.
   */
  async guard<T>(
    tool: string,
    args: Record<string, unknown>,
    execute: () => T | Promise<T>
  ): Promise<T> {
    const call = this.toCall(tool, args);
    let decision = evaluate(call, {
      policy: this.options.policy,
      usage: this.ledger.snapshot(),
      history: this.audit.history(),
    });

    if (decision.effect === 'ask') {
      decision = await this.resolveAsk(call, decision);
    }

    const entry = this.audit.record(call, decision, this.usageForAudit());

    if (decision.effect !== 'allow') {
      throw new LeashDenied(tool, decision, entry.hash);
    }

    this.ledger.countCall(call.at);
    return execute();
  }

  /** Record model consumption against the budget. Call after every model turn. */
  meter(input: number, output: number, price?: TokenPrice): void {
    this.ledger.addUsage(input, output, price, this.now());
  }

  /** Record non-token spend, e.g. a metered third-party API call. */
  spend(usd: number): void {
    this.ledger.addSpend(usd, this.now());
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
    const { calls, tokens, usd } = this.ledger.snapshot();
    return { calls, tokens, usd };
  }
}
