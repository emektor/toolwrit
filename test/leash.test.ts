/**
 * End-to-end behaviour of the Leash runtime object.
 *
 * The contract being pinned here is the one an integrator relies on:
 *   - an allowed call runs, and is counted;
 *   - a denied call does NOT run, is NOT counted, but IS recorded;
 *   - "ask" without a handler is a denial (fail closed);
 *   - the chain over a whole mixed run verifies, and head() is the receipt.
 *
 * Every timestamp comes from the injectable `now`. There are no sleeps, no real
 * clocks and no timers in this file.
 */

import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Leash, LeashDenied } from '../src/leash.js';
import { verifyChain, verifyFile } from '../src/audit/verify.js';
import { GENESIS } from '../src/audit/chain.js';
import type { Decision, Policy, ToolCall } from '../src/types.js';
import { T0, at, fixedClock, frozenClock, policy, rule, tempDir } from './helpers.js';

const tmp = tempDir();
after(() => tmp.cleanup());

const ALLOW_FS: Policy = policy({
  rules: [
    rule({ id: 'fs-read', tools: ['fs.read'], effect: 'allow', when: { path: { type: 'string', startsWith: ['/tmp/'] } } }),
    rule({ id: 'confirm', tools: ['fs.write'], effect: 'ask', description: 'writes need a human' }),
    rule({ id: 'no-shell', tools: ['shell.**'], effect: 'deny', description: 'shell is off limits' }),
  ],
});

/** Run `fn`, requiring it to throw LeashDenied, and return it. */
async function denied(fn: () => Promise<unknown>): Promise<LeashDenied> {
  try {
    await fn();
  } catch (err) {
    if (!(err instanceof LeashDenied)) {
      assert.fail(`expected LeashDenied, got ${(err as Error)?.constructor?.name}: ${String(err)}`);
    }
    return err;
  }
  return assert.fail('expected LeashDenied to be thrown, but the call succeeded');
}

describe('Leash: construction', () => {
  it('generates a run id when none is given, and stamps it on entries', async () => {
    const a = new Leash({ policy: ALLOW_FS, now: frozenClock() });
    const b = new Leash({ policy: ALLOW_FS, now: frozenClock() });
    assert.match(a.run, /^[0-9a-f-]{36}$/);
    assert.notEqual(a.run, b.run);

    await a.guard('fs.read', { path: '/tmp/x' }, () => 1);
    assert.equal(a.entries()[0]!.run, a.run);
  });

  it('uses an explicit run id', async () => {
    const l = new Leash({ policy: ALLOW_FS, run: 'run-42', now: frozenClock() });
    assert.equal(l.run, 'run-42');
    await l.guard('fs.read', { path: '/tmp/x' }, () => 1);
    assert.equal(l.entries()[0]!.run, 'run-42');
  });

  it('starts with empty usage, no entries and head() at GENESIS', () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock() });
    assert.deepEqual(l.usage(), { calls: 0, tokens: 0, usd: 0, bytes: 0, startedAt: null });
    assert.deepEqual(l.entries(), []);
    assert.equal(l.head(), GENESIS);
  });
});

describe('Leash.check', () => {
  it('evaluates without recording, counting or executing', () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock() });
    assert.equal(l.check('fs.read', { path: '/tmp/x' }).effect, 'allow');
    assert.equal(l.check('shell.exec').effect, 'deny');
    assert.equal(l.check('fs.write').effect, 'ask', 'check reports the raw effect, it does not ask');
    assert.deepEqual(l.entries(), []);
    assert.equal(l.usage().calls, 0);
  });

  it('defaults args to an empty object', () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock() });
    assert.deepEqual(l.check('fs.read').violations.map((v) => v.constraint), ['required']);
  });
});

describe('Leash.guard: allow', () => {
  it('executes the function and returns its value', async () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock() });
    let ran = 0;
    const result = await l.guard('fs.read', { path: '/tmp/x' }, () => {
      ran++;
      return 'contents';
    });
    assert.equal(result, 'contents');
    assert.equal(ran, 1);
  });

  it('awaits an async function', async () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock() });
    const result = await l.guard('fs.read', { path: '/tmp/x' }, async () => 7);
    assert.equal(result, 7);
  });

  it('increments usage().calls and starts the clock at the call time', async () => {
    const l = new Leash({ policy: ALLOW_FS, now: fixedClock(at(0), at(5)) });
    await l.guard('fs.read', { path: '/tmp/a' }, () => 1);
    assert.deepEqual(l.usage(), { calls: 1, tokens: 0, usd: 0, bytes: 1, startedAt: at(0) });
    await l.guard('fs.read', { path: '/tmp/b' }, () => 1);
    assert.deepEqual(l.usage(), { calls: 2, tokens: 0, usd: 0, bytes: 2, startedAt: at(0) });
  });

  it('records the decision before executing, so a thrown tool still leaves evidence', async () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock() });
    await assert.rejects(
      l.guard('fs.read', { path: '/tmp/x' }, () => {
        throw new Error('disk on fire');
      }),
      /disk on fire/
    );
    assert.equal(l.entries().length, 1);
    assert.equal(l.entries()[0]!.decision.effect, 'allow');
    assert.equal(l.usage().calls, 1, 'the call was authorised and counted before it failed');
  });

  it('records the entry with the tool, args, time and decision', async () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock(at(3)) });
    await l.guard('fs.read', { path: '/tmp/x' }, () => 1);
    const [entry] = l.entries();
    assert.equal(entry!.tool, 'fs.read');
    assert.deepEqual(entry!.args, { path: '/tmp/x' });
    assert.equal(entry!.at, at(3));
    assert.equal(entry!.decision.rule, 'fs-read');
    assert.deepEqual(entry!.usage, { calls: 0, tokens: 0, usd: 0, bytes: 0 }, 'usage is captured as of the decision');
  });
});

describe('Leash.guard: deny', () => {
  it('throws LeashDenied carrying the tool, the decision and the audit hash', async () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock() });
    let ran = false;
    const err = await denied(() => l.guard('shell.exec', { cmd: 'rm -rf /' }, () => { ran = true; }));

    assert.equal(ran, false, 'the guarded function must never run');
    assert.equal(err.name, 'LeashDenied');
    assert.equal(err.tool, 'shell.exec');
    assert.equal(err.decision.effect, 'deny');
    assert.equal(err.decision.rule, 'no-shell');
    assert.equal(err.decision.reason, 'shell is off limits');
    assert.match(err.message, /leash: shell\.exec denied — shell is off limits/);

    assert.equal(l.entries().length, 1);
    assert.equal(err.auditHash, l.entries()[0]!.hash, 'the hash quotes the recorded refusal');
    assert.equal(err.auditHash, l.head());
  });

  it('does NOT increment the call counter but DOES record the refusal', async () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock() });
    await denied(() => l.guard('shell.exec', {}, () => 1));
    assert.deepEqual(l.usage(), { calls: 0, tokens: 0, usd: 0, bytes: 0, startedAt: null });
    assert.equal(l.entries().length, 1);
    assert.equal(l.entries()[0]!.decision.effect, 'deny');
  });

  it('denies an unknown tool by default and reports it', async () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock() });
    const err = await denied(() => l.guard('mystery.tool', {}, () => 1));
    assert.equal(err.decision.rule, null);
    assert.deepEqual(err.decision.violations.map((v) => v.constraint), ['default']);
  });

  it('denies an allow-rule near miss and surfaces the failing argument', async () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock() });
    const err = await denied(() => l.guard('fs.read', { path: '/etc/passwd' }, () => 1));
    assert.deepEqual(err.decision.violations.map((v) => `${v.rule}:${v.path}:${v.constraint}`), [
      'fs-read:path:startsWith',
    ]);
  });

  it('denied calls do not consume a rate limit', async () => {
    const p = policy({
      rules: [rule({ id: 'limited', tools: ['t'], effect: 'allow', limit: { max: 1 } })],
    });
    const l = new Leash({ policy: p, now: frozenClock() });
    await denied(() => l.guard('other', {}, () => 1)); // denied, not attributed to `limited`
    await l.guard('t', {}, () => 1);
    await denied(() => l.guard('t', {}, () => 1));
    assert.equal(l.usage().calls, 1);
  });
});

describe('Leash.guard: ask', () => {
  it('denies when no onAsk handler is configured (fail closed)', async () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock() });
    let ran = false;
    const err = await denied(() => l.guard('fs.write', { path: '/tmp/x' }, () => { ran = true; }));

    assert.equal(ran, false);
    assert.equal(err.decision.effect, 'deny');
    assert.equal(err.decision.rule, 'confirm', 'the asking rule is still credited');
    assert.match(err.decision.reason, /no approval handler configured/);
    assert.deepEqual(err.decision.violations.map((v) => v.constraint), ['ask']);
    assert.match(
      err.decision.violations[0]!.message,
      /requires approval but no onAsk handler was configured; denying by default/
    );
    assert.equal(l.usage().calls, 0);
    assert.equal(l.entries()[0]!.decision.effect, 'deny', 'the refusal is what gets recorded');
  });

  it('allows when the handler returns true, and records the upgraded decision', async () => {
    const seen: { tool: string; effect: string }[] = [];
    const l = new Leash({
      policy: ALLOW_FS,
      now: frozenClock(),
      onAsk: (c: ToolCall, d: Decision) => {
        seen.push({ tool: c.tool, effect: d.effect });
        return true;
      },
    });
    const result = await l.guard('fs.write', { path: '/tmp/x' }, () => 'written');
    assert.equal(result, 'written');
    assert.deepEqual(seen, [{ tool: 'fs.write', effect: 'ask' }]);
    assert.equal(l.usage().calls, 1);

    const [entry] = l.entries();
    assert.equal(entry!.decision.effect, 'allow');
    assert.equal(entry!.decision.rule, 'confirm');
    assert.match(entry!.decision.reason, /\(approved\)$/);
  });

  it('denies when the handler returns false', async () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock(), onAsk: () => false });
    const err = await denied(() => l.guard('fs.write', { path: '/tmp/x' }, () => 1));
    assert.equal(err.decision.effect, 'deny');
    assert.match(err.decision.reason, /\(approval refused\)$/);
    assert.deepEqual(err.decision.violations.map((v) => v.message), [
      'approval was refused by the configured handler',
    ]);
    assert.equal(l.usage().calls, 0);
  });

  it('awaits an async handler', async () => {
    const order: string[] = [];
    const l = new Leash({
      policy: ALLOW_FS,
      now: frozenClock(),
      onAsk: async () => {
        order.push('asked');
        await Promise.resolve();
        order.push('resolved');
        return true;
      },
    });
    await l.guard('fs.write', {}, () => order.push('executed'));
    assert.deepEqual(order, ['asked', 'resolved', 'executed']);
  });

  it('receives the exact call it is being asked about', async () => {
    let received: ToolCall | null = null;
    const l = new Leash({
      policy: ALLOW_FS,
      now: frozenClock(at(9)),
      onAsk: (c) => {
        received = c;
        return false;
      },
    });
    await denied(() => l.guard('fs.write', { path: '/tmp/secret' }, () => 1));
    const call = received as ToolCall | null;
    assert.equal(call?.tool, 'fs.write');
    assert.deepEqual(call?.args, { path: '/tmp/secret' });
    assert.equal(call?.at, at(9));
  });

  it('is not consulted for allow or deny decisions', async () => {
    let asked = 0;
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock(), onAsk: () => { asked++; return true; } });
    await l.guard('fs.read', { path: '/tmp/x' }, () => 1);
    await denied(() => l.guard('shell.exec', {}, () => 1));
    assert.equal(asked, 0);
  });

  it('cannot upgrade a budget denial — the budget is checked before the ask', async () => {
    const p: Policy = { ...ALLOW_FS, budget: { calls: 1 } };
    const l = new Leash({ policy: p, now: frozenClock(), onAsk: () => true });
    await l.guard('fs.read', { path: '/tmp/x' }, () => 1);
    const err = await denied(() => l.guard('fs.write', { path: '/tmp/x' }, () => 1));
    assert.equal(err.decision.violations[0]!.constraint, 'calls');
  });
});

describe('Leash: metering and budgets', () => {
  it('meter() adds tokens and derives spend from the price table', () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock(at(2)) });
    l.meter(1000, 500, { input: 0.003, output: 0.015 });
    const u = l.usage();
    assert.equal(u.tokens, 1500);
    assert.ok(Math.abs(u.usd - (0.003 + 0.0075)) < 1e-12, `unexpected usd ${u.usd}`);
    assert.equal(u.startedAt, at(2), 'the time budget starts at the first metered event');
  });

  it('meter() without a price table records tokens at zero cost', () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock() });
    l.meter(10, 20);
    assert.deepEqual(l.usage(), { calls: 0, tokens: 30, usd: 0, bytes: 0, startedAt: T0 });
  });

  it('spend() adds usd and accumulates', () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock() });
    l.spend(0.25);
    l.spend(0.25);
    assert.equal(l.usage().usd, 0.5);
  });

  it('a previously-allowed call starts being denied once the call budget trips', async () => {
    const p: Policy = { ...ALLOW_FS, budget: { calls: 2 } };
    const l = new Leash({ policy: p, now: frozenClock() });
    await l.guard('fs.read', { path: '/tmp/a' }, () => 1);
    await l.guard('fs.read', { path: '/tmp/b' }, () => 1);
    const err = await denied(() => l.guard('fs.read', { path: '/tmp/c' }, () => 1));
    assert.equal(err.decision.violations[0]!.constraint, 'calls');
    assert.equal(l.usage().calls, 2, 'the refused call is not counted');
  });

  it('metering tokens can trip the budget mid-run', async () => {
    const p: Policy = { ...ALLOW_FS, budget: { tokens: 100 } };
    const l = new Leash({ policy: p, now: frozenClock() });
    await l.guard('fs.read', { path: '/tmp/a' }, () => 1);
    l.meter(60, 39);
    await l.guard('fs.read', { path: '/tmp/b' }, () => 1);
    l.meter(1, 0);
    const err = await denied(() => l.guard('fs.read', { path: '/tmp/c' }, () => 1));
    assert.equal(err.decision.violations[0]!.constraint, 'tokens');
    assert.match(err.decision.reason, /100\/100 tokens used/);
  });

  it('spending trips the usd budget mid-run', async () => {
    const p: Policy = { ...ALLOW_FS, budget: { usd: 1 } };
    const l = new Leash({ policy: p, now: frozenClock() });
    await l.guard('fs.read', { path: '/tmp/a' }, () => 1);
    l.spend(0.99);
    await l.guard('fs.read', { path: '/tmp/b' }, () => 1);
    l.spend(0.01);
    const err = await denied(() => l.guard('fs.read', { path: '/tmp/c' }, () => 1));
    assert.equal(err.decision.violations[0]!.constraint, 'usd');
  });

  it('the seconds budget trips on the injected clock alone', async () => {
    const p: Policy = { ...ALLOW_FS, budget: { seconds: 30 } };
    // One clock read per guard: countCall reuses the timestamp from the call.
    const l = new Leash({ policy: p, now: fixedClock(at(0), at(29), at(30)) });
    await l.guard('fs.read', { path: '/tmp/a' }, () => 1);
    await l.guard('fs.read', { path: '/tmp/b' }, () => 1);
    const err = await denied(() => l.guard('fs.read', { path: '/tmp/c' }, () => 1));
    assert.equal(err.decision.violations[0]!.constraint, 'seconds');
    assert.match(err.decision.reason, /time budget exhausted: 30\.0s\/30s elapsed/);
  });

  it('rate limits are enforced across guarded calls using the injected clock', async () => {
    const p = policy({
      rules: [rule({ id: 'burst', tools: ['t'], effect: 'allow', limit: { max: 2, perSeconds: 60 } })],
    });
    const l = new Leash({ policy: p, now: fixedClock(at(0), at(1), at(2), at(120)) });
    await l.guard('t', {}, () => 1);
    await l.guard('t', {}, () => 1);
    const err = await denied(() => l.guard('t', {}, () => 1));
    assert.equal(err.decision.violations[0]!.constraint, 'limit');
    await l.guard('t', {}, () => 1); // the window has slid past both entries
    assert.equal(l.usage().calls, 3);
  });
});

describe('Leash: audit chain over a whole run', () => {
  it('verifies across a mixed run of allows, denies, asks and budget refusals', async () => {
    const p: Policy = { ...ALLOW_FS, budget: { calls: 3 } };
    const l = new Leash({ policy: p, run: 'mixed', now: fixedClock(at(0), at(1), at(2), at(3), at(4), at(5)), onAsk: () => true });

    await l.guard('fs.read', { path: '/tmp/a' }, () => 1);         // allow
    await denied(() => l.guard('shell.exec', {}, () => 1));        // deny by rule
    await l.guard('fs.write', { path: '/tmp/b' }, () => 1);        // ask -> approved
    await denied(() => l.guard('fs.read', { path: '/etc/x' }, () => 1)); // near miss
    await l.guard('fs.read', { path: '/tmp/c' }, () => 1);         // allow (3rd call)
    await denied(() => l.guard('fs.read', { path: '/tmp/d' }, () => 1)); // budget

    const entries = l.entries();
    assert.equal(entries.length, 6);
    assert.deepEqual(entries.map((e) => e.decision.effect), ['allow', 'deny', 'allow', 'deny', 'allow', 'deny']);
    assert.deepEqual(entries.map((e) => e.seq), [1, 2, 3, 4, 5, 6]);
    assert.deepEqual(entries.map((e) => e.usage.calls), [0, 1, 1, 2, 2, 3]);

    const result = verifyChain(entries);
    assert.equal(result.ok, true, JSON.stringify(result.failure));
    assert.equal(result.count, 6);
    assert.equal(result.head, l.head());
  });

  it('head() equals the last entry\'s hash after every step', async () => {
    const l = new Leash({ policy: ALLOW_FS, now: frozenClock() });
    assert.equal(l.head(), GENESIS);
    for (let i = 0; i < 4; i++) {
      await l.guard('fs.read', { path: `/tmp/${i}` }, () => i);
      const entries = l.entries();
      assert.equal(l.head(), entries[entries.length - 1]!.hash, `after ${i + 1} calls`);
    }
    assert.equal(l.entries().length, 4);
  });

  it('writes and verifies a JSONL audit file, with redaction applied', async () => {
    const file = join(tmp.path, 'run.jsonl');
    const args = { path: '/tmp/x', token: 'sk-live-secret' };
    const l = new Leash({
      policy: policy({ rules: [rule({ id: 'any', tools: ['**'], effect: 'allow' })] }),
      run: 'file-run',
      auditFile: file,
      redact: ['token'],
      now: fixedClock(at(0), at(1)),
    });

    await l.guard('api.call', args, () => 1);
    await l.guard('api.call', args, () => 2);

    const result = verifyFile(file);
    assert.equal(result.ok, true, JSON.stringify(result.failure));
    assert.equal(result.count, 2);
    assert.equal(result.head, l.head());
    assert.equal(l.entries()[0]!.args['token'], '[redacted]');
    assert.equal(l.entries()[0]!.args['path'], '/tmp/x');
    assert.equal(args.token, 'sk-live-secret', 'the caller\'s object is untouched');
    assert.ok(!readFileSync(file, 'utf8').includes('sk-live-secret'), 'the secret never reaches disk');
  });

  it('two Leash instances with the same inputs produce the same chain', async () => {
    const build = async () => {
      const l = new Leash({ policy: ALLOW_FS, run: 'same', now: fixedClock(at(0), at(1)) });
      await l.guard('fs.read', { path: '/tmp/a' }, () => 1);
      await denied(() => l.guard('shell.exec', {}, () => 1));
      return l.head();
    };
    assert.equal(await build(), await build(), 'the chain is a function of the inputs alone');
  });
});
