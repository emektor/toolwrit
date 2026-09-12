/**
 * Run-scoped consumption tracking.
 *
 * The ledger is the "capacity" half of Leash: rules decide *what* an agent may
 * do, the ledger decides *how much*. It is deliberately dumb — a set of
 * counters — because the interesting logic belongs in the engine, and because
 * a counter is trivially auditable.
 */

import type { BudgetUsage } from '../types.js';

/** Per-thousand-token prices used to turn token counts into dollars. */
export interface TokenPrice {
  /** USD per 1,000 input tokens. */
  input: number;
  /** USD per 1,000 output tokens. */
  output: number;
}

export class Ledger {
  private usage: BudgetUsage = { calls: 0, tokens: 0, usd: 0, bytes: 0, startedAt: null };

  /** Snapshot for the engine. Returned by value so callers cannot mutate state. */
  snapshot(): BudgetUsage {
    return { ...this.usage };
  }

  /** Record that a call was permitted and executed. */
  countCall(at: number): void {
    this.start(at);
    this.usage.calls += 1;
  }

  /** Record raw token consumption with a directly known cost. */
  addTokens(tokens: number, usd = 0, at = Date.now()): void {
    this.start(at);
    this.usage.tokens += tokens;
    this.usage.usd += usd;
  }

  /**
   * Record a model turn, deriving cost from a price table.
   * Kept separate from addTokens so the pricing assumption is visible in the
   * caller rather than buried in a magic number.
   */
  addUsage(
    input: number,
    output: number,
    price: TokenPrice = { input: 0, output: 0 },
    at = Date.now()
  ): void {
    const usd = (input / 1000) * price.input + (output / 1000) * price.output;
    this.addTokens(input + output, usd, at);
  }

  /**
   * Record the size of a tool result.
   *
   * Called after the tool has run, because the size of what comes back is not
   * knowable before it does.
   */
  addBytes(bytes: number, at = Date.now()): void {
    this.start(at);
    this.usage.bytes += bytes;
  }

  /** Record spend that is not token-denominated, e.g. a paid API call. */
  addSpend(usd: number, at = Date.now()): void {
    this.start(at);
    this.usage.usd += usd;
  }

  /** Reset every counter. Used between runs when a process is long-lived. */
  reset(): void {
    this.usage = { calls: 0, tokens: 0, usd: 0, bytes: 0, startedAt: null };
  }

  /** The time budget starts at the first metered event, not at construction. */
  private start(at: number): void {
    if (this.usage.startedAt === null) this.usage.startedAt = at;
  }
}
