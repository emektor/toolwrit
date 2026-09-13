/**
 * The volume ceiling.
 *
 * Rules govern which calls happen; this governs how much data they drain.
 * Bulk exfiltration is rarely a forbidden action -- it is a permitted action
 * repeated until something is empty -- so every individual call passes the
 * allowlist and only the running total gives it away.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Toolwrit, ToolwritDenied } from '../src/toolwrit.js';
import { parsePolicy } from '../src/policy/load.js';
import { evaluate } from '../src/policy/engine.js';
import { Ledger } from '../src/budget/ledger.js';
import type { BudgetWarning, Policy } from '../src/types.js';
import { T0, call, frozenClock, usage } from './helpers.js';

const ALLOW_ALL = (budget: string): Policy =>
  parsePolicy(`version: "1"\ndefault: allow\nbudget:\n  ${budget}\nrules: []\n`);

describe('bytes: measurement', () => {
  const sizeAfter = async (result: unknown): Promise<number> => {
    const toolwrit = new Toolwrit({ policy: ALLOW_ALL('calls: 100'), now: frozenClock() });
    await toolwrit.guard('t', {}, () => result);
    return toolwrit.usage().bytes;
  };

  it('measures strings as UTF-8, not as code units', async () => {
    assert.equal(await sizeAfter('abc'), 3);
    // A three-byte character must not be counted as one.
    assert.equal(await sizeAfter('€'), 3);
  });

  it('measures binary results by their byte length', async () => {
    assert.equal(await sizeAfter(new Uint8Array(512)), 512);
    assert.equal(await sizeAfter(new ArrayBuffer(64)), 64);
  });

  it('measures structured results by their serialised size', async () => {
    assert.equal(await sizeAfter({ a: 1 }), JSON.stringify({ a: 1 }).length);
    assert.equal(await sizeAfter([1, 2, 3]), 7);
  });

  it('counts an empty result as nothing', async () => {
    assert.equal(await sizeAfter(null), 0);
    assert.equal(await sizeAfter(undefined), 0);
  });

  it('falls back rather than throwing on an unserialisable result', async () => {
    const cyclic: Record<string, unknown> = {};
    cyclic['self'] = cyclic;
    // Under-counted, deliberately and documented: the alternative is an
    // exception from inside the enforcement layer, which is worse.
    assert.equal(typeof (await sizeAfter(cyclic)), 'number');
  });

  it('is deterministic, so a replayed log reaches the same verdict', async () => {
    const value = { customers: [{ id: 1, name: 'a' }, { id: 2, name: 'b' }] };
    assert.equal(await sizeAfter(value), await sizeAfter(structuredClone(value)));
  });
});

describe('bytes: the ceiling', () => {
  it('denies the next call once the ceiling is reached', async () => {
    const toolwrit = new Toolwrit({ policy: ALLOW_ALL('bytes: 20'), now: frozenClock() });

    const page = 'x'.repeat(12);
    await toolwrit.guard('crm.read', {}, () => page);
    assert.equal(toolwrit.usage().bytes, 12);

    // Still under, so this one runs -- and takes the total past the ceiling.
    await toolwrit.guard('crm.read', {}, () => page);
    assert.equal(toolwrit.usage().bytes, 24);

    await assert.rejects(
      () => toolwrit.guard('crm.read', {}, () => page),
      (err: unknown) => {
        assert.ok(err instanceof ToolwritDenied);
        assert.equal(err.decision.violations[0]?.constraint, 'bytes');
        return true;
      }
    );
  });

  it('bounds a run at the limit plus one call, never exactly the limit', async () => {
    // A result's size is unknowable before the tool runs, so the call that
    // breaches the ceiling always completes. Pinned so nobody reads the
    // ceiling as a hard cap on what a single call can return.
    const toolwrit = new Toolwrit({ policy: ALLOW_ALL('bytes: 10'), now: frozenClock() });
    await toolwrit.guard('dump', {}, () => 'y'.repeat(5000));

    assert.equal(toolwrit.usage().bytes, 5000);
    await assert.rejects(() => toolwrit.guard('dump', {}, () => 'z'), ToolwritDenied);
  });

  it('denies before a matching allow rule gets a say', () => {
    const p = parsePolicy(
      `version: "1"\ndefault: deny\nbudget:\n  bytes: 100\n` +
        `rules:\n  - id: r\n    tools: ["read"]\n    effect: allow\n`
    );
    const decision = evaluate(call('read', {}, T0), {
      policy: p,
      usage: usage({ bytes: 100 }),
      history: [],
    });

    assert.equal(decision.effect, 'deny');
    assert.equal(decision.rule, null);
    assert.equal(decision.violations[0]?.rule, 'budget');
  });

  it('is untouched when the policy sets no bytes ceiling', async () => {
    const toolwrit = new Toolwrit({ policy: ALLOW_ALL('calls: 100'), now: frozenClock() });
    await toolwrit.guard('dump', {}, () => 'q'.repeat(100_000));
    assert.equal(toolwrit.usage().bytes, 100_000);
    await toolwrit.guard('dump', {}, () => 'ok');
  });

  it('trips at the ceiling exactly, not one byte past it', () => {
    const p = ALLOW_ALL('bytes: 50');
    const at49 = evaluate(call('t', {}, T0), { policy: p, usage: usage({ bytes: 49 }), history: [] });
    const at50 = evaluate(call('t', {}, T0), { policy: p, usage: usage({ bytes: 50 }), history: [] });

    assert.equal(at49.effect, 'allow');
    assert.equal(at50.effect, 'deny');
  });
});

describe('bytes: reporting', () => {
  it('reports against the plan like every other dimension', async () => {
    const p = parsePolicy(
      `version: "1"\ndefault: allow\nbudget:\n  bytes: 1000\n` +
        `plan:\n  purpose: nightly export\n  warnAt: [0.5]\nrules: []\n`
    );
    const warnings: BudgetWarning[] = [];
    const toolwrit = new Toolwrit({ policy: p, now: frozenClock(), onWarn: (w) => warnings.push(w) });

    await toolwrit.guard('crm.read', {}, () => 'a'.repeat(600));

    assert.equal(warnings.length, 1);
    assert.equal(warnings[0]?.dimension, 'bytes');
    assert.equal(warnings[0]?.used, 600);
    assert.equal(warnings[0]?.limit, 1000);
  });

  it('carries the byte total into the audit entry', async () => {
    const toolwrit = new Toolwrit({ policy: ALLOW_ALL('bytes: 1000'), now: frozenClock() });
    await toolwrit.guard('a', {}, () => 'hello');
    await toolwrit.guard('b', {}, () => 'world');

    // Each entry records usage as of its own decision, so the second entry
    // carries what the first call drained.
    assert.equal(toolwrit.entries()[0]?.usage.bytes, 0);
    assert.equal(toolwrit.entries()[1]?.usage.bytes, 5);
  });
});

describe('bytes: ledger and validation', () => {
  it('accumulates and resets with the rest of the ledger', () => {
    const ledger = new Ledger();
    ledger.addBytes(100, T0);
    ledger.addBytes(50, T0);
    assert.equal(ledger.snapshot().bytes, 150);

    ledger.reset();
    assert.equal(ledger.snapshot().bytes, 0);
  });

  it('starts the run clock, so a bytes-only policy still has a time base', () => {
    const ledger = new Ledger();
    ledger.addBytes(1, T0);
    assert.equal(ledger.snapshot().startedAt, T0);
  });

  it('rejects a non-positive ceiling', () => {
    assert.throws(() => ALLOW_ALL('bytes: 0'), /positive number/);
    assert.throws(() => ALLOW_ALL('bytes: -1'), /positive number/);
  });
});
