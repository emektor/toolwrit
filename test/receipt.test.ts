/**
 * Run receipts, and the hole they close.
 *
 * Two properties matter here. The first is that a receipt is a faithful, tiny
 * summary of a run — because at fleet scale the receipt is all anyone reads,
 * and a summary that hides a budget breach is worse than no summary. The
 * second is the one plain verification cannot give you: a truncated chain
 * verifies happily against itself, so the test that a receipt catches it is the
 * test that anchoring is worth doing at all.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Toolwrit, ToolwritDenied } from '../src/toolwrit.js';
import { GENESIS } from '../src/audit/chain.js';
import { summarize, verifyAgainstReceipt } from '../src/audit/receipt.js';
import { verifyChain } from '../src/audit/verify.js';
import type { Policy } from '../src/types.js';
import { frozenClock, policy, rule, T0 } from './helpers.js';

/** A run whose calls are all permitted, so a receipt can be read on its own. */
async function plainRun(): Promise<Toolwrit> {
  const toolwrit = new Toolwrit({
    policy: policy({ default: 'allow' }),
    run: 'plain',
    now: frozenClock(),
  });
  for (let i = 0; i < 3; i++) await toolwrit.guard('fs.read', { path: `/tmp/${i}` }, () => i);
  return toolwrit;
}

/** Guard a call that is expected to be refused, keeping the test readable. */
async function expectDenied(toolwrit: Toolwrit, tool: string, args: Record<string, unknown> = {}) {
  await assert.rejects(() => toolwrit.guard(tool, args, () => 'ran'), ToolwritDenied);
}

describe('summarize: a plain run', () => {
  it('names the run, its span and its outcome', async () => {
    const toolwrit = await plainRun();
    const receipt = summarize(toolwrit.entries());

    assert.equal(receipt.run, 'plain');
    assert.equal(receipt.entryCount, 3);
    assert.equal(receipt.from, T0);
    assert.equal(receipt.to, T0);
    assert.equal(receipt.allowed, 3);
    assert.equal(receipt.denied, 0);
    assert.equal(receipt.asked, 0);
    assert.deepEqual(receipt.deniedTools, {});
    assert.equal(receipt.exceeded, false);
  });

  it('quotes the head of the chain and reports it verified', async () => {
    const toolwrit = await plainRun();
    const receipt = summarize(toolwrit.entries());

    assert.equal(receipt.head, toolwrit.head());
    assert.equal(receipt.chainOk, true);
  });

  it('carries no plan and no budget fractions when none was declared', async () => {
    const receipt = summarize((await plainRun()).entries());
    assert.equal(receipt.plan, null);
    assert.equal(receipt.consumed, null);
  });

  it('is pure — the same entries always summarize identically', async () => {
    const entries = (await plainRun()).entries();
    assert.deepEqual(summarize(entries), summarize(entries));
  });
});

describe('summarize: a run with a plan', () => {
  const planned: Policy = policy({
    default: 'allow',
    budget: { calls: 10, tokens: 1000, usd: 2, bytes: 0 },
    plan: { purpose: 'nightly sync', approvedBy: 'ergin', warnAt: [0.5] },
  });

  function plannedRun(): Toolwrit {
    const toolwrit = new Toolwrit({ policy: planned, run: 'planned', now: frozenClock() });
    toolwrit.meter(400, 200); // 600/1000 tokens — crosses the 50% threshold
    toolwrit.spend(1.5); //      1.5/2 usd     — crosses it in a second dimension
    return toolwrit;
  }

  it('reports the envelope the operator approved', () => {
    const receipt = summarize(plannedRun().entries());
    assert.deepEqual(receipt.plan, {
      purpose: 'nightly sync',
      approvedBy: 'ergin',
      budget: { calls: 10, tokens: 1000, usd: 2, bytes: 0 },
      warnAt: [0.5],
    });
  });

  it('lists the thresholds that fired', () => {
    const receipt = summarize(plannedRun().entries());
    assert.deepEqual(
      receipt.warnings.map((w) => [w.dimension, w.threshold, w.used, w.limit]),
      [
        ['tokens', 0.5, 600, 1000],
        ['usd', 0.5, 1.5, 2],
      ]
    );
  });

  it('reports each dimension as a fraction of its ceiling', () => {
    const receipt = summarize(plannedRun().entries());
    assert.deepEqual(receipt.usage, { calls: 0, tokens: 600, usd: 1.5, bytes: 0 });
    assert.deepEqual(receipt.consumed, { calls: 0, tokens: 0.6, usd: 0.75 });
  });

  it('does not count toolwrit:plan or toolwrit:warning as tool calls the agent made', () => {
    const receipt = summarize(plannedRun().entries());
    // Three bookkeeping entries, none of them an agent action.
    assert.equal(receipt.entryCount, 3);
    assert.equal(receipt.allowed, 0);
  });

  it('omits a fraction for a dimension the budget does not cap', () => {
    const toolwrit = new Toolwrit({
      policy: policy({
        default: 'allow',
        budget: { calls: 4 },
        plan: { purpose: 'p' },
      }),
      run: 'partial',
      now: frozenClock(),
    });
    assert.deepEqual(summarize(toolwrit.entries()).consumed, { calls: 0 });
  });
});

describe('summarize: denials', () => {
  it('tallies denials by tool so an anomalous run is legible at a glance', async () => {
    const toolwrit = new Toolwrit({
      policy: policy({
        default: 'allow',
        rules: [rule({ id: 'no-writes', tools: ['fs.write', 'fs.rm'], effect: 'deny' })],
      }),
      run: 'denials',
      now: frozenClock(),
    });

    await toolwrit.guard('fs.read', {}, () => 'ok');
    await expectDenied(toolwrit, 'fs.write');
    await expectDenied(toolwrit, 'fs.write');
    await expectDenied(toolwrit, 'fs.rm');

    const receipt = summarize(toolwrit.entries());
    assert.equal(receipt.allowed, 1);
    assert.equal(receipt.denied, 3);
    assert.deepEqual(receipt.deniedTools, { 'fs.write': 2, 'fs.rm': 1 });
    // A rule denial is not a budget breach: the run stayed inside its envelope.
    assert.equal(receipt.exceeded, false);
  });

  it('flags exceeded when a call was refused for want of budget', async () => {
    const toolwrit = new Toolwrit({
      policy: policy({ default: 'allow', budget: { calls: 2 } }),
      run: 'over',
      now: frozenClock(),
    });

    await toolwrit.guard('t', {}, () => 1);
    await toolwrit.guard('t', {}, () => 2);
    await expectDenied(toolwrit, 't');

    const receipt = summarize(toolwrit.entries());
    assert.equal(receipt.exceeded, true);
    assert.deepEqual(receipt.deniedTools, { t: 1 });
  });

  it('leaves exceeded false for a run that stayed under its ceiling', async () => {
    const toolwrit = new Toolwrit({
      policy: policy({ default: 'allow', budget: { calls: 5 } }),
      run: 'under',
      now: frozenClock(),
    });
    for (let i = 0; i < 4; i++) await toolwrit.guard('t', {}, () => i);
    assert.equal(summarize(toolwrit.entries()).exceeded, false);
  });
});

describe('verifyAgainstReceipt: catching a truncated tail', () => {
  it('accepts a chain that still reaches the head the receipt quoted', async () => {
    const toolwrit = await plainRun();
    const receipt = summarize(toolwrit.entries());
    assert.equal(verifyAgainstReceipt(toolwrit.entries(), receipt).ok, true);
  });

  it('detects a truncation that plain verifyChain accepts', async () => {
    const toolwrit = await plainRun();
    const receipt = summarize(toolwrit.entries());
    const truncated = toolwrit.entries().slice(0, 1);

    // This is the hole: a prefix of a valid chain is itself a valid chain, so
    // an agent that deletes its last entries hands over a log that verifies.
    assert.equal(verifyChain(truncated).ok, true);

    const checked = verifyAgainstReceipt(truncated, receipt);
    assert.equal(checked.ok, false);
    assert.equal(checked.failure?.reason, 'broken-link');
    assert.match(checked.failure?.detail ?? '', /receipt's head/);
  });

  it('reports the chain failure first when the chain is broken as well', async () => {
    const toolwrit = await plainRun();
    const receipt = summarize(toolwrit.entries());

    const tampered = toolwrit.entries().map((e) => ({ ...e }));
    tampered[1]!.args = { path: '/etc/shadow' };

    const checked = verifyAgainstReceipt(tampered, receipt);
    assert.equal(checked.ok, false);
    assert.equal(checked.failure?.reason, 'bad-hash');
  });

  it('refuses a receipt issued for a different run', async () => {
    const receipt = summarize((await plainRun()).entries());

    const other = new Toolwrit({ policy: policy({ default: 'allow' }), run: 'other', now: frozenClock() });
    await other.guard('fs.read', {}, () => 1);

    const checked = verifyAgainstReceipt(other.entries(), receipt);
    assert.equal(checked.ok, false);
    assert.equal(checked.failure?.reason, 'malformed');
  });
});

describe('summarize: the empty chain', () => {
  it('summarizes to a receipt that says nothing happened, rather than throwing', () => {
    const receipt = summarize([]);
    assert.deepEqual(receipt, {
      run: '',
      from: null,
      to: null,
      entryCount: 0,
      head: GENESIS,
      chainOk: true,
      plan: null,
      usage: { calls: 0, tokens: 0, usd: 0, bytes: 0 },
      consumed: null,
      allowed: 0,
      denied: 0,
      asked: 0,
      warnings: [],
      deniedTools: {},
      exceeded: false,
    });
  });

  it('verifies against its own receipt', () => {
    assert.equal(verifyAgainstReceipt([], summarize([])).ok, true);
  });
});
