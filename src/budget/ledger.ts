/**
 * Run-scoped consumption tracking.
 *
 * The ledger is the "capacity" half of Toolwrit: rules decide *what* an agent may
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

/**
 * Reject a consumption figure that would corrupt the ledger.
 *
 * A single NaN is permanent and silent: every ceiling check is `used >= limit`,
 * and `NaN >= n` is false, so one bad metering call disables that budget for
 * the rest of the run with no error anywhere. `meter(undefined, 300)` — a
 * provider response missing a field — was enough to do it. A negative figure is
 * as bad in the other direction: it walks a spent budget back under its ceiling
 * and reopens it.
 *
 * Failing loudly is the only safe option. A metering bug must surface as an
 * exception the caller can see, not as a limit that quietly stops applying.
 */
function requireConsumption(name: string, value: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new TypeError(`toolwrit: ${name} must be a finite number, got ${JSON.stringify(value)}`);
  }
  if (value < 0) {
    throw new RangeError(`toolwrit: ${name} must not be negative, got ${value}`);
  }
  return value;
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
    requireConsumption('tokens', tokens);
    requireConsumption('usd', usd);
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
    requireConsumption('input tokens', input);
    requireConsumption('output tokens', output);
    requireConsumption('price.input', price.input);
    requireConsumption('price.output', price.output);
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
    requireConsumption('bytes', bytes);
    this.start(at);
    this.usage.bytes += bytes;
  }

  /** Record spend that is not token-denominated, e.g. a paid API call. */
  addSpend(usd: number, at = Date.now()): void {
    requireConsumption('usd', usd);
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
