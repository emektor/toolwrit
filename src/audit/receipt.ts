/**
 * Run receipts — the fleet-scale unit of review.
 *
 * A hash chain proves what one run did, but nobody reads chains at scale. A
 * fleet of 100,000 agents leaves hundreds of millions of entries behind, and
 * "review the logs" is not an answer anyone can act on. The receipt is the
 * summary that makes that fleet legible: one small object per run, so a console
 * reads 100,000 receipts rather than 100,000,000 entries, and the runs that
 * left their approved envelope — a budget ceiling hit, a tool denied over and
 * over — are already flagged in the summary rather than buried in it.
 *
 * `summarize` is pure: a function of the chain alone, no I/O and no clock, so
 * the same chain always yields the same receipt and a receipt can be recomputed
 * during an audit and compared byte for byte with the one issued at the time.
 */

import type { AuditEntry } from './chain.js';
import { GENESIS } from './chain.js';
import { verifyChain, type VerifyResult } from './verify.js';
import type { BudgetLimits } from '../types.js';

/** The declared envelope, as it was recorded in the chain's `leash:plan` entry. */
export interface ReceiptPlan {
  purpose: string;
  approvedBy: string | null;
  budget: BudgetLimits | null;
  warnAt: number[];
}

/** A threshold that fired during the run, recovered from a `leash:warning` entry. */
export interface ReceiptWarning {
  dimension: string;
  threshold: number;
  used: number;
  limit: number;
}

/** Fraction of each budgeted dimension the run consumed. Absent when unbudgeted. */
export interface ReceiptConsumed {
  calls?: number;
  tokens?: number;
  usd?: number;
  bytes?: number;
}

export interface RunReceipt {
  /** Run identifier the entries carry. Empty string for an empty chain. */
  run: string;
  /** Timestamps of the first and last entry, or null when there are none. */
  from: number | null;
  to: number | null;
  entryCount: number;
  /** Hash of the final entry — the value an anchor commits to. */
  head: string;
  /** Whether the chain verified when this receipt was computed. */
  chainOk: boolean;
  /** The approved envelope, when the run declared one. */
  plan: ReceiptPlan | null;
  /** Consumption as last recorded in the chain. */
  usage: { calls: number; tokens: number; usd: number; bytes: number };
  /** Usage over the plan's budget, per dimension. Null without a declared budget. */
  consumed: ReceiptConsumed | null;
  allowed: number;
  denied: number;
  asked: number;
  warnings: ReceiptWarning[];
  /** Tool name -> number of denials, so an anomalous run is legible at a glance. */
  deniedTools: Record<string, number>;
  /** True when a call was refused because a budget ceiling was reached. */
  exceeded: boolean;
}

/** Entries Leash writes about itself rather than about a guarded tool call. */
const PLAN_TOOL = 'leash:plan';
const WARNING_TOOL = 'leash:warning';

/** Summarize a chain. Pure: same entries in, same receipt out. */
export function summarize(entries: readonly AuditEntry[]): RunReceipt {
  const verified = verifyChain(entries);
  const first = entries[0];
  const last = entries[entries.length - 1];

  const plan = readPlan(entries);
  const warnings: ReceiptWarning[] = [];
  const deniedTools: Record<string, number> = {};
  let allowed = 0;
  let denied = 0;
  let asked = 0;
  let exceeded = false;

  for (const entry of entries) {
    if (entry.tool === WARNING_TOOL) {
      const warning = readWarning(entry);
      if (warning) warnings.push(warning);
      continue;
    }
    // Leash's own bookkeeping entries are not tool calls the agent made, so
    // counting them as "allowed" would overstate every run by one or two.
    if (entry.tool === PLAN_TOOL) continue;

    switch (entry.decision.effect) {
      case 'allow':
        allowed++;
        break;
      case 'ask':
        // A resolved ask is recorded as its outcome, so this counts only calls
        // still awaiting a human at the moment they were written.
        asked++;
        break;
      case 'deny':
        denied++;
        deniedTools[entry.tool] = (deniedTools[entry.tool] ?? 0) + 1;
        if (entry.decision.violations.some((v) => v.rule === 'budget')) exceeded = true;
        break;
    }
  }

  // Each entry records usage as of the DECISION, before the call it authorised
  // is counted, so the final entry's call count always lags reality by the last
  // permitted call. Reporting it raw produced receipts that said "9 allowed, 8
  // calls" -- a contradiction a reviewer notices immediately. The allowed count
  // is the authoritative call total; tokens and spend still come from the last
  // entry, since metering happens between calls and the chain is where it lands.
  const usage = {
    calls: allowed,
    tokens: last?.usage.tokens ?? 0,
    usd: last?.usage.usd ?? 0,
    bytes: last?.usage.bytes ?? 0,
  };

  return {
    run: last?.run ?? '',
    from: first?.at ?? null,
    to: last?.at ?? null,
    entryCount: entries.length,
    // The head is what the final entry claims, even for a chain that failed to
    // verify: a receipt over a broken chain still has to say what it saw.
    head: last?.hash ?? GENESIS,
    chainOk: verified.ok,
    plan,
    usage,
    consumed: plan?.budget ? fractions(usage, plan.budget) : null,
    allowed,
    denied,
    asked,
    warnings,
    deniedTools,
    exceeded,
  };
}

/**
 * Verify a chain AND that it is the chain the receipt was issued for.
 *
 * Verifying a chain in isolation cannot detect that its tail was cut off: a
 * prefix of a valid chain is itself a valid chain, every link intact, so an
 * agent that deletes its last twenty entries hands you a log that passes.
 * Comparing against a receipt issued at the time closes that hole — the head
 * quoted then cannot be reached by any shorter or rewritten chain. That is the
 * whole point of anchoring the receipt somewhere the agent cannot reach.
 */
export function verifyAgainstReceipt(
  entries: readonly AuditEntry[],
  receipt: RunReceipt
): VerifyResult {
  const result = verifyChain(entries);
  if (!result.ok) return result;

  const run = entries[entries.length - 1]?.run ?? '';
  if (receipt.run !== '' && run !== receipt.run) {
    return {
      ok: false,
      count: result.count,
      head: result.head,
      failure: {
        seq: entries.length,
        reason: 'malformed',
        detail: `receipt is for run "${receipt.run}" but the chain is for run "${run}"`,
      },
    };
  }

  if (result.head !== receipt.head) {
    return {
      ok: false,
      count: result.count,
      head: result.head,
      failure: {
        seq: entries.length,
        reason: 'broken-link',
        detail:
          `chain head ${short(result.head)} does not match the receipt's head ` +
          `${short(receipt.head)} (${result.count} entries present, receipt recorded ` +
          `${receipt.entryCount})`,
      },
    };
  }

  return result;
}

function fractions(
  usage: { calls: number; tokens: number; usd: number; bytes: number },
  budget: BudgetLimits
): ReceiptConsumed {
  const consumed: ReceiptConsumed = {};
  for (const dimension of ['calls', 'tokens', 'usd', 'bytes'] as const) {
    const limit = budget[dimension];
    // A zero or absent limit has no meaningful fraction; reporting 0 or
    // Infinity there would read as "plenty of room left".
    if (typeof limit === 'number' && limit > 0) consumed[dimension] = usage[dimension] / limit;
  }
  return consumed;
}

function readPlan(entries: readonly AuditEntry[]): ReceiptPlan | null {
  const entry = entries.find((e) => e.tool === PLAN_TOOL);
  if (!entry) return null;

  const args = entry.args;
  const warnAt = args['warnAt'];
  const budget = args['budget'];
  const approvedBy = args['approvedBy'];

  return {
    purpose: typeof args['purpose'] === 'string' ? args['purpose'] : '',
    approvedBy: typeof approvedBy === 'string' ? approvedBy : null,
    budget: typeof budget === 'object' && budget !== null ? (budget as BudgetLimits) : null,
    warnAt: Array.isArray(warnAt) ? warnAt.filter((v): v is number => typeof v === 'number') : [],
  };
}

function readWarning(entry: AuditEntry): ReceiptWarning | null {
  const { dimension, threshold, used, limit } = entry.args;
  if (
    typeof dimension !== 'string' ||
    typeof threshold !== 'number' ||
    typeof used !== 'number' ||
    typeof limit !== 'number'
  ) {
    return null;
  }
  return { dimension, threshold, used, limit };
}

function short(hash: string): string {
  return hash.slice(0, 12);
}
