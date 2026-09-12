/**
 * Shared fixtures for the Leash test suite.
 *
 * Everything here is deterministic on purpose: no `Date.now()`, no timers, no
 * randomness. Every timestamp is an explicit number so a failing assertion can
 * be reproduced from the test source alone.
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type {
  BudgetUsage,
  Decision,
  EvalContext,
  Policy,
  PolicyRule,
  ToolCall,
} from '../src/types.js';

/** Fixed epoch used across the suite: 2024-01-01T00:00:00.000Z. */
export const T0 = 1_704_067_200_000;

/** T0 plus `seconds`, for readable window arithmetic. */
export function at(seconds: number): number {
  return T0 + seconds * 1000;
}

/** A clock that hands out a scripted sequence of timestamps. */
export function fixedClock(...times: number[]): () => number {
  let i = 0;
  return () => {
    const value = times[Math.min(i, times.length - 1)];
    i++;
    return value ?? T0;
  };
}

/** A clock that never advances. */
export function frozenClock(t = T0): () => number {
  return () => t;
}

export function call(
  tool: string,
  args: Record<string, unknown> = {},
  when: number = T0
): ToolCall {
  return { id: `call-${tool}-${when}`, tool, args, at: when };
}

export function usage(partial: Partial<BudgetUsage> = {}): BudgetUsage {
  return { calls: 0, tokens: 0, usd: 0, bytes: 0, startedAt: null, ...partial };
}

export function policy(partial: Partial<Policy> = {}): Policy {
  return { version: '1', rules: [], ...partial };
}

export function rule(partial: Partial<PolicyRule> & Pick<PolicyRule, 'id'>): PolicyRule {
  return { tools: ['*'], effect: 'allow', ...partial };
}

export function ctx(partial: Partial<EvalContext> = {}): EvalContext {
  return {
    policy: policy(),
    usage: usage(),
    history: [],
    ...partial,
  };
}

/** A decision shape without the noisy free-text `reason`. */
export function shape(d: Decision): { effect: string; rule: string | null; constraints: string[] } {
  return {
    effect: d.effect,
    rule: d.rule,
    constraints: d.violations.map((v) => v.constraint),
  };
}

/** Create a temp directory and register cleanup with the caller's `after` hook. */
export function tempDir(): { path: string; cleanup: () => void } {
  const path = mkdtempSync(join(tmpdir(), 'leash-test-'));
  return { path, cleanup: () => rmSync(path, { recursive: true, force: true }) };
}

/** Deep structural clone via JSON — used to snapshot inputs and prove purity. */
export function snapshot<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
