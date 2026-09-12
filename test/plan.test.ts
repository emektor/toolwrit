/**
 * The run plan: a declared envelope, approved once, reported against.
 *
 * The plan is what makes capacity limits livable, so these tests pin the two
 * properties an operator actually relies on: that the approved envelope is in
 * the tamper-evident record before anything can be consumed, and that a
 * threshold reports exactly once -- an alert that repeats gets muted, and a
 * muted alert is the same as no alert.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Leash } from '../src/leash.js';
import { parsePolicy, PolicyError } from '../src/policy/load.js';
import { verifyChain } from '../src/audit/verify.js';
import type { BudgetWarning, Policy } from '../src/types.js';

const T0 = Date.parse('2026-09-10T00:00:00Z');

function policy(planYaml: string, budgetYaml = 'calls: 10'): Policy {
  return parsePolicy(
    `version: "1"\ndefault: allow\nbudget:\n  ${budgetYaml}\nplan:\n${planYaml}\nrules: []\n`
  );
}

function collect(p: Policy, opts: { now?: () => number } = {}) {
  const warnings: BudgetWarning[] = [];
  const leash = new Leash({
    policy: p,
    run: 'test-run',
    now: opts.now ?? (() => T0),
    onWarn: (w) => warnings.push(w),
  });
  return { leash, warnings };
}

describe('run plan: the approved envelope is recorded first', () => {
  it('writes the plan as entry 1, before anything can be consumed', () => {
    const { leash } = collect(policy('  purpose: nightly sync\n  approvedBy: ergin'));
    const [first] = leash.entries();

    assert.equal(first?.seq, 1);
    assert.equal(first?.tool, 'leash:plan');
    assert.equal(first?.args['purpose'], 'nightly sync');
    assert.equal(first?.args['approvedBy'], 'ergin');
    assert.deepEqual(first?.args['budget'], { calls: 10 });
    // Zero usage at the moment of approval is the point: the envelope is
    // committed before the run can spend against it.
    assert.deepEqual(first?.usage, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
  });

  it('records the defaults it will actually use, not an empty field', () => {
    const { leash } = collect(policy('  purpose: p'));
    assert.deepEqual(leash.entries()[0]?.args['warnAt'], [0.8, 0.95]);
  });

  it('records approvedBy as null rather than omitting it when unset', () => {
    const { leash } = collect(policy('  purpose: p'));
    assert.equal(leash.entries()[0]?.args['approvedBy'], null);
  });

  it('writes no plan entry when the policy declares no plan', () => {
    const p = parsePolicy('version: "1"\ndefault: allow\nrules: []\n');
    const leash = new Leash({ policy: p, now: () => T0 });
    assert.equal(leash.entries().length, 0);
  });
});

describe('run plan: threshold reporting', () => {
  it('fires each threshold exactly once, even as usage keeps climbing', async () => {
    const { leash, warnings } = collect(policy('  purpose: p\n  warnAt: [0.5, 0.9]'));

    for (let i = 0; i < 10; i++) await leash.guard('t', {}, () => i);

    const calls = warnings.filter((w) => w.dimension === 'calls');
    assert.deepEqual(calls.map((w) => w.threshold), [0.5, 0.9]);
    assert.deepEqual(calls.map((w) => w.used), [5, 9]);
    assert.equal(calls.every((w) => w.limit === 10), true);
  });

  it('sorts thresholds so they report in ascending order however they were written', async () => {
    const { leash, warnings } = collect(policy('  purpose: p\n  warnAt: [0.9, 0.2, 0.5]'));
    for (let i = 0; i < 10; i++) await leash.guard('t', {}, () => i);
    assert.deepEqual(warnings.map((w) => w.threshold), [0.2, 0.5, 0.9]);
  });

  it('reports each budget dimension independently', () => {
    const p = policy('  purpose: p\n  warnAt: [0.5]', 'calls: 10\n  tokens: 1000\n  usd: 2');
    const { leash, warnings } = collect(p);

    leash.meter(400, 200);   // 600/1000 tokens
    leash.spend(1.5);        // 1.5/2 usd

    assert.deepEqual(
      warnings.map((w) => [w.dimension, w.used]),
      [['tokens', 600], ['usd', 1.5]]
    );
  });

  it('measures the time dimension from the first metered event', () => {
    let now = T0;
    const p = policy('  purpose: p\n  warnAt: [0.5]', 'seconds: 100');
    const { leash, warnings } = collect(p, { now: () => now });

    leash.spend(0);            // starts the clock, 0s elapsed
    assert.equal(warnings.length, 0);

    now = T0 + 60_000;         // 60s of a 100s envelope
    leash.spend(0);
    assert.equal(warnings.at(-1)?.dimension, 'seconds');
    assert.equal(warnings.at(-1)?.used, 60);
  });

  it('stays silent when the policy has a budget but no plan', async () => {
    const p = parsePolicy('version: "1"\ndefault: allow\nbudget:\n  calls: 10\nrules: []\n');
    const warnings: BudgetWarning[] = [];
    const leash = new Leash({ policy: p, now: () => T0, onWarn: (w) => warnings.push(w) });

    for (let i = 0; i < 9; i++) await leash.guard('t', {}, () => i);
    assert.deepEqual(warnings, []);
  });

  it('puts every warning in the chain, and the chain still verifies', async () => {
    const { leash } = collect(policy('  purpose: p\n  warnAt: [0.5, 0.9]'));
    for (let i = 0; i < 10; i++) await leash.guard('t', {}, () => i);

    const warned = leash.entries().filter((e) => e.tool === 'leash:warning');
    assert.equal(warned.length, 2);
    assert.equal(warned[0]?.args['dimension'], 'calls');
    // The log answers "was anyone told" without depending on whether a Slack
    // message was actually delivered.
    assert.equal(verifyChain(leash.entries()).ok, true);
  });

  it('does not require an onWarn handler to record the warning', async () => {
    const p = policy('  purpose: p\n  warnAt: [0.5]');
    const leash = new Leash({ policy: p, run: 'r', now: () => T0 });
    for (let i = 0; i < 6; i++) await leash.guard('t', {}, () => i);
    assert.equal(leash.entries().some((e) => e.tool === 'leash:warning'), true);
  });
});

describe('run plan: validation', () => {
  const bad = (yaml: string) => assert.throws(() => parsePolicy(yaml), PolicyError);

  it('rejects a plan with no budget to measure against', () => {
    // A plan that reports nothing reads as "all clear" rather than
    // "not configured", which is the dangerous direction.
    bad('version: "1"\nplan:\n  purpose: p\nrules: []\n');
  });

  it('rejects a missing or empty purpose', () => {
    bad('version: "1"\nbudget:\n  calls: 1\nplan:\n  approvedBy: x\nrules: []\n');
    bad('version: "1"\nbudget:\n  calls: 1\nplan:\n  purpose: "   "\nrules: []\n');
  });

  it('rejects thresholds outside (0, 1]', () => {
    for (const t of ['0', '-0.5', '1.5', '"0.8"']) {
      bad(`version: "1"\nbudget:\n  calls: 1\nplan:\n  purpose: p\n  warnAt: [${t}]\nrules: []\n`);
    }
  });

  it('rejects an empty threshold list rather than silently reporting nothing', () => {
    bad('version: "1"\nbudget:\n  calls: 1\nplan:\n  purpose: p\n  warnAt: []\nrules: []\n');
  });

  it('rejects an unknown plan field so a typo cannot disable reporting', () => {
    bad('version: "1"\nbudget:\n  calls: 1\nplan:\n  purpose: p\n  warn_at: [0.8]\nrules: []\n');
  });

  it('accepts 1.0 as a threshold', () => {
    const p = policy('  purpose: p\n  warnAt: [1]');
    assert.deepEqual(p.plan?.warnAt, [1]);
  });
});
