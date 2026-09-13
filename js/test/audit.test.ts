/**
 * The tamper-evident audit chain.
 *
 * This is the half of Toolwrit an auditor actually reads. The tests below prove
 * two things: that the canonical form is stable (so a log written by one
 * process verifies in another), and that every realistic edit to a written log
 * is detected, with the right entry and the right reason named.
 */

import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { AuditLog, GENESIS, canonicalize, hashEntry, type AuditEntry } from '../src/audit/chain.js';
import { verifyChain, verifyFile } from '../src/audit/verify.js';
import type { Decision } from '../src/types.js';
import { T0, call, tempDir } from './helpers.js';

const tmp = tempDir();
after(() => tmp.cleanup());

const ALLOW: Decision = { effect: 'allow', rule: 'r1', reason: 'allowed by rule "r1"', violations: [] };
const DENY: Decision = {
  effect: 'deny',
  rule: null,
  reason: 'no rule allows tool "fs.write"',
  violations: [{ rule: 'policy', constraint: 'default', message: 'nope' }],
};

/** Three-entry chain used by most of the tampering tests. */
function buildChain(): AuditEntry[] {
  const log = new AuditLog({ run: 'run-1' });
  log.record(call('fs.read', { path: '/tmp/a' }, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
  log.record(call('fs.write', { path: '/etc/x' }, T0 + 1), DENY, { calls: 1, tokens: 10, usd: 0.01, bytes: 0 });
  log.record(call('fs.read', { path: '/tmp/b' }, T0 + 2), ALLOW, { calls: 1, tokens: 10, usd: 0.01, bytes: 0 });
  return log.all().map((e) => structuredClone(e));
}

describe('canonicalize', () => {
  it('serialises primitives like JSON.stringify', () => {
    assert.equal(canonicalize(1), '1');
    assert.equal(canonicalize('a'), '"a"');
    assert.equal(canonicalize(true), 'true');
    assert.equal(canonicalize(null), 'null');
    assert.equal(canonicalize(undefined), 'null');
    assert.equal(canonicalize('a"b\\c'), '"a\\"b\\\\c"');
  });

  it('sorts object keys', () => {
    assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
  });

  it('honours toJSON, because the file is written with JSON.stringify', () => {
    // Hashing a Date structurally gives {}, while the JSONL line holds the ISO
    // string -- so an entirely honest entry fails to verify against its own
    // file. The canonical form has to be what JSON.stringify will write.
    const when = new Date('2026-09-13T08:00:00Z');
    assert.equal(canonicalize(when), JSON.stringify(when));
    assert.equal(canonicalize({ when }), '{"when":"2026-09-13T08:00:00.000Z"}');
    assert.equal(canonicalize([when]), '["2026-09-13T08:00:00.000Z"]');
    // Any library object carrying a toJSON, not only Date.
    const decimal = { value: '1.10', toJSON(): string { return this.value; } };
    assert.equal(canonicalize({ amount: decimal }), '{"amount":"1.10"}');
    // A "toJSON" that is not callable is an ordinary field.
    assert.equal(canonicalize({ toJSON: 1 }), '{"toJSON":1}');
  });

  it('sorts keys recursively, at every depth', () => {
    assert.equal(
      canonicalize({ z: { d: 1, c: { b: 1, a: 2 } }, y: 3 }),
      '{"y":3,"z":{"c":{"a":2,"b":1},"d":1}}'
    );
  });

  it('is stable across differently-ordered but equal objects', () => {
    const a = { tool: 't', args: { b: 2, a: 1 }, seq: 1 };
    const b = { seq: 1, args: { a: 1, b: 2 }, tool: 't' };
    assert.equal(canonicalize(a), canonicalize(b));
  });

  it('hashEntry inherits that stability, so key order cannot change a hash', () => {
    const common = { at: T0, run: 'r', decision: ALLOW, usage: { calls: 0, tokens: 0, usd: 0, bytes: 0 }, prev: GENESIS };
    const a = { seq: 1, tool: 't', args: { b: 2, a: 1 }, ...common };
    const b = { ...common, args: { a: 1, b: 2 }, tool: 't', seq: 1 };
    assert.equal(hashEntry(a), hashEntry(b));
  });

  it('preserves array order — arrays are sequences, not sets', () => {
    assert.equal(canonicalize([3, 1, 2]), '[3,1,2]');
    assert.notEqual(canonicalize([1, 2]), canonicalize([2, 1]));
  });

  it('handles nested arrays of objects', () => {
    assert.equal(canonicalize([{ b: 1, a: 2 }, []]), '[{"a":2,"b":1},[]]');
  });

  it('drops undefined object values, matching JSON.stringify', () => {
    assert.equal(canonicalize({ a: 1, b: undefined }), '{"a":1}');
    assert.equal(canonicalize({ a: 1, b: undefined }), canonicalize({ a: 1 }));
  });

  it('renders undefined array elements as null, matching JSON.stringify', () => {
    assert.equal(canonicalize([1, undefined, 2]), '[1,null,2]');
  });

  it('distinguishes null from a missing key', () => {
    assert.notEqual(canonicalize({ a: null }), canonicalize({}));
  });

  it('emits no incidental whitespace', () => {
    assert.equal(canonicalize({ a: [1, { b: 2 }] }), '{"a":[1,{"b":2}]}');
  });

  it('does not confuse an empty object with an empty array', () => {
    assert.notEqual(canonicalize({}), canonicalize([]));
  });
});

describe('hashEntry', () => {
  it('is sha256 over the canonical form', () => {
    const body = { seq: 1, at: T0, run: 'r', tool: 't', args: {}, decision: ALLOW, usage: { calls: 0, tokens: 0, usd: 0, bytes: 0 }, prev: GENESIS };
    const expected = createHash('sha256').update(canonicalize(body)).digest('hex');
    assert.equal(hashEntry(body), expected);
    assert.match(hashEntry(body), /^[0-9a-f]{64}$/);
  });

  it('changes when any field changes', () => {
    const body = { seq: 1, at: T0, run: 'r', tool: 't', args: { a: 1 }, decision: ALLOW, usage: { calls: 0, tokens: 0, usd: 0, bytes: 0 }, prev: GENESIS };
    const base = hashEntry(body);
    assert.notEqual(hashEntry({ ...body, tool: 'u' }), base);
    assert.notEqual(hashEntry({ ...body, at: T0 + 1 }), base);
    assert.notEqual(hashEntry({ ...body, args: { a: 2 } }), base);
    assert.notEqual(hashEntry({ ...body, decision: { ...ALLOW, effect: 'deny' } }), base);
    assert.notEqual(hashEntry({ ...body, usage: { calls: 1, tokens: 0, usd: 0, bytes: 0 } }), base);
    assert.notEqual(hashEntry({ ...body, prev: 'f'.repeat(64) }), base);
    assert.notEqual(hashEntry({ ...body, run: 'other' }), base);
  });
});

describe('AuditLog', () => {
  it('links the chain: first prev is GENESIS, each later prev is its predecessor\'s hash', () => {
    const entries = buildChain();
    assert.equal(entries.length, 3);
    assert.equal(entries[0]!.prev, GENESIS);
    assert.equal(entries[1]!.prev, entries[0]!.hash);
    assert.equal(entries[2]!.prev, entries[1]!.hash);
    assert.deepEqual(entries.map((e) => e.seq), [1, 2, 3]);
  });

  it('records the call, run, timestamp, decision and usage verbatim', () => {
    const [first] = buildChain();
    assert.equal(first!.run, 'run-1');
    assert.equal(first!.tool, 'fs.read');
    assert.equal(first!.at, T0);
    assert.deepEqual(first!.args, { path: '/tmp/a' });
    assert.deepEqual(first!.decision, ALLOW);
    assert.deepEqual(first!.usage, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
  });

  it('head() equals the last entry\'s hash, and GENESIS when empty', () => {
    const log = new AuditLog({ run: 'r' });
    assert.equal(log.head(), GENESIS);
    const e1 = log.record(call('t', {}, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
    assert.equal(log.head(), e1.hash);
    const e2 = log.record(call('t', {}, T0 + 1), ALLOW, { calls: 1, tokens: 0, usd: 0, bytes: 0 });
    assert.equal(log.head(), e2.hash);
  });

  it('is deterministic: identical inputs produce identical hashes', () => {
    assert.deepEqual(buildChain().map((e) => e.hash), buildChain().map((e) => e.hash));
  });

  it('a different run id produces a different chain', () => {
    const other = new AuditLog({ run: 'run-2' });
    const e = other.record(call('fs.read', { path: '/tmp/a' }, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
    assert.notEqual(e.hash, buildChain()[0]!.hash);
  });

  it('history() exposes only non-denied calls, in the engine\'s shape', () => {
    const log = new AuditLog({ run: 'r' });
    log.record(call('fs.read', {}, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
    log.record(call('fs.write', {}, T0 + 1), DENY, { calls: 1, tokens: 0, usd: 0, bytes: 0 });
    log.record(call('fs.read', {}, T0 + 2), { ...ALLOW, effect: 'ask' }, { calls: 1, tokens: 0, usd: 0, bytes: 0 });
    assert.deepEqual(log.history(), [
      { tool: 'fs.read', rule: 'r1', at: T0 },
      { tool: 'fs.read', rule: 'r1', at: T0 + 2 },
    ]);
  });

  it('all() reports entries oldest first', () => {
    const entries = buildChain();
    assert.deepEqual(entries.map((e) => e.tool), ['fs.read', 'fs.write', 'fs.read']);
  });
});

describe('verifyChain: the honest cases', () => {
  it('accepts an empty chain with head GENESIS', () => {
    assert.deepEqual(verifyChain([]), { ok: true, count: 0, head: GENESIS });
  });

  it('accepts a good chain and reports its head', () => {
    const entries = buildChain();
    const result = verifyChain(entries);
    assert.equal(result.ok, true);
    assert.equal(result.count, 3);
    assert.equal(result.head, entries[2]!.hash);
    assert.equal(result.failure, undefined);
  });

  it('accepts a chain that is one legitimate entry longer', () => {
    const log = new AuditLog({ run: 'r' });
    for (let i = 0; i < 10; i++) {
      log.record(call('t', { i }, T0 + i), ALLOW, { calls: i, tokens: 0, usd: 0, bytes: 0 });
      assert.equal(verifyChain(log.all()).ok, true, `after ${i + 1} entries`);
    }
  });
});

describe('verifyChain: tampering', () => {
  it('rejects a mutated argument', () => {
    const entries = buildChain();
    (entries[1]!.args as Record<string, unknown>)['path'] = '/tmp/harmless';
    const r = verifyChain(entries);
    assert.equal(r.ok, false);
    assert.equal(r.failure!.seq, 2);
    assert.equal(r.failure!.reason, 'bad-hash');
    assert.match(r.failure!.detail, /hashes to [0-9a-f]{12} but claims [0-9a-f]{12}/);
  });

  it('rejects a mutated decision — a deny rewritten as an allow', () => {
    const entries = buildChain();
    entries[1]!.decision.effect = 'allow';
    entries[1]!.decision.violations = [];
    const r = verifyChain(entries);
    assert.equal(r.ok, false);
    assert.equal(r.failure!.seq, 2);
    assert.equal(r.failure!.reason, 'bad-hash');
  });

  it('rejects a mutated usage figure', () => {
    const entries = buildChain();
    entries[2]!.usage.usd = 0;
    const r = verifyChain(entries);
    assert.deepEqual([r.ok, r.failure!.seq, r.failure!.reason], [false, 3, 'bad-hash']);
  });

  it('rejects a deleted middle entry', () => {
    const entries = buildChain();
    entries.splice(1, 1);
    const r = verifyChain(entries);
    assert.equal(r.ok, false);
    assert.equal(r.failure!.seq, 2, 'the gap shows at the position the deleted entry vacated');
    assert.equal(r.failure!.reason, 'bad-sequence');
    assert.match(r.failure!.detail, /declares seq 3 but sits at position 2/);
  });

  it('rejects a deleted final entry only via the head it reports', () => {
    // Truncation cannot break a hash link, so it is detected by comparing the
    // reported head against the receipt the run handed out.
    const entries = buildChain();
    const fullHead = verifyChain(entries).head;
    entries.pop();
    const r = verifyChain(entries);
    assert.equal(r.ok, true, 'a truncated prefix is internally consistent by construction');
    assert.notEqual(r.head, fullHead, 'but the head no longer matches the receipt');
    assert.equal(r.count, 2);
  });

  it('rejects two reordered entries', () => {
    const entries = buildChain();
    const [a, b] = [entries[1]!, entries[2]!];
    entries[1] = b;
    entries[2] = a;
    const r = verifyChain(entries);
    assert.equal(r.ok, false);
    assert.equal(r.failure!.seq, 2);
    assert.equal(r.failure!.reason, 'bad-sequence');
  });

  it('rejects a forged entry spliced into the middle', () => {
    const entries = buildChain();
    const forgedBody = {
      seq: 2,
      at: T0 + 1,
      run: 'run-1',
      tool: 'fs.write',
      args: { path: '/etc/x' },
      decision: ALLOW, // the attacker's goal: make the denial look authorised
      usage: { calls: 1, tokens: 10, usd: 0.01, bytes: 0 },
      prev: entries[0]!.hash,
    };
    // A well-formed forgery: correct seq, correct prev, correctly recomputed hash.
    entries[1] = { ...forgedBody, hash: hashEntry(forgedBody) };

    const r = verifyChain(entries);
    assert.equal(r.ok, false);
    assert.equal(r.failure!.seq, 3, 'the successor is what exposes the splice');
    assert.equal(r.failure!.reason, 'broken-link');
    assert.match(r.failure!.detail, /links to [0-9a-f]{12} but predecessor hashes to [0-9a-f]{12}/);
  });

  it('rejects an entry whose hash was rewritten to any other value', () => {
    const entries = buildChain();
    entries[0]!.hash = 'f'.repeat(64);
    const r = verifyChain(entries);
    assert.equal(r.ok, false);
    assert.equal(r.failure!.seq, 1);
    assert.equal(r.failure!.reason, 'bad-hash');
  });

  it('rejects a rewritten prev link', () => {
    const entries = buildChain();
    entries[1]!.prev = GENESIS;
    const r = verifyChain(entries);
    assert.equal(r.ok, false);
    assert.equal(r.failure!.seq, 2);
    assert.equal(r.failure!.reason, 'broken-link');
  });

  it('rejects a renumbered first entry', () => {
    const entries = buildChain();
    entries[0]!.seq = 0;
    const r = verifyChain(entries);
    assert.deepEqual([r.failure!.seq, r.failure!.reason], [1, 'bad-sequence']);
  });

  it('stops at the FIRST inconsistency', () => {
    const entries = buildChain();
    (entries[1]!.args as Record<string, unknown>)['path'] = 'tampered';
    (entries[2]!.args as Record<string, unknown>)['path'] = 'tampered';
    assert.equal(verifyChain(entries).failure!.seq, 2);
  });

  it('reports the last verified head alongside a failure', () => {
    const entries = buildChain();
    (entries[2]!.args as Record<string, unknown>)['path'] = 'tampered';
    const r = verifyChain(entries);
    assert.equal(r.head, entries[1]!.hash, 'everything up to seq 2 is still provably intact');
    assert.equal(r.count, 3);
  });
});

describe('verifyFile', () => {
  it('verifies a JSONL log written by AuditLog', () => {
    const file = join(tmp.path, 'good.jsonl');
    const log = new AuditLog({ run: 'file-run', file });
    log.record(call('fs.read', { path: '/tmp/a' }, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
    log.record(call('fs.write', { path: '/etc/x' }, T0 + 1), DENY, { calls: 1, tokens: 0, usd: 0, bytes: 0 });

    const r = verifyFile(file);
    assert.equal(r.ok, true);
    assert.equal(r.count, 2);
    assert.equal(r.head, log.head());
  });

  it('verifies a log whose arguments carried a Date', () => {
    // The regression this pins: a run that did nothing wrong reported
    // "bad-hash" against its own file, because the Date was hashed as {} and
    // written as a string. A false tamper alarm is not a lesser bug here.
    const file = join(tmp.path, 'dated.jsonl');
    const log = new AuditLog({ run: 'dated', file });
    const args = { when: new Date('2026-09-13T08:00:00Z'), nested: [new Date(0)] };
    log.record(call('api.schedule', args, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });

    const r = verifyFile(file);
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.head, log.head());
  });

  it('creates the parent directory for the log file', () => {
    const file = join(tmp.path, 'nested', 'deeper', 'log.jsonl');
    const log = new AuditLog({ run: 'r', file });
    log.record(call('t', {}, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
    assert.equal(verifyFile(file).ok, true);
  });

  it('detects an edit made directly to the file on disk', () => {
    const file = join(tmp.path, 'edited.jsonl');
    const log = new AuditLog({ run: 'r', file });
    log.record(call('fs.read', { path: '/tmp/a' }, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
    log.record(call('fs.write', { path: '/etc/shadow' }, T0 + 1), DENY, { calls: 1, tokens: 0, usd: 0, bytes: 0 });

    const lines = readFileSync(file, 'utf8').trimEnd().split('\n');
    const second = JSON.parse(lines[1]!) as AuditEntry;
    second.args['path'] = '/tmp/innocent';
    writeFileSync(file, `${lines[0]}\n${JSON.stringify(second)}\n`, 'utf8');

    const r = verifyFile(file);
    assert.equal(r.ok, false);
    assert.equal(r.failure!.seq, 2);
    assert.equal(r.failure!.reason, 'bad-hash');
  });

  it('detects a deleted line', () => {
    const file = join(tmp.path, 'truncated.jsonl');
    const log = new AuditLog({ run: 'r', file });
    for (let i = 0; i < 3; i++) {
      log.record(call('t', { i }, T0 + i), ALLOW, { calls: i, tokens: 0, usd: 0, bytes: 0 });
    }
    const lines = readFileSync(file, 'utf8').trimEnd().split('\n');
    writeFileSync(file, `${lines[0]}\n${lines[2]}\n`, 'utf8');
    const r = verifyFile(file);
    assert.deepEqual([r.ok, r.failure!.seq, r.failure!.reason], [false, 2, 'bad-sequence']);
  });

  it('reports malformed JSON with the offending line number', () => {
    const file = join(tmp.path, 'malformed.jsonl');
    const log = new AuditLog({ run: 'r', file });
    log.record(call('t', {}, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
    writeFileSync(file, `${readFileSync(file, 'utf8')}{not json}\n`, 'utf8');
    const r = verifyFile(file);
    assert.equal(r.ok, false);
    assert.equal(r.failure!.reason, 'malformed');
    assert.equal(r.failure!.seq, 2);
    assert.match(r.failure!.detail, /line 2 is not valid JSON/);
  });

  it('ignores blank and whitespace-only lines', () => {
    const file = join(tmp.path, 'blanks.jsonl');
    const log = new AuditLog({ run: 'r', file });
    log.record(call('t', {}, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
    writeFileSync(file, `\n${readFileSync(file, 'utf8')}\n   \n`, 'utf8');
    assert.equal(verifyFile(file).ok, true);
  });

  it('verifies an empty file as an empty chain', () => {
    const file = join(tmp.path, 'empty.jsonl');
    writeFileSync(file, '', 'utf8');
    assert.deepEqual(verifyFile(file), { ok: true, count: 0, head: GENESIS });
  });

  it('two runs appended to one file each verify only as a whole-file chain', () => {
    // Documented format property: several runs may share a file. The chain is
    // per-AuditLog, so a second log restarts at GENESIS and the combined file
    // fails — worth pinning so nobody assumes shared-file chaining works.
    const file = join(tmp.path, 'two-runs.jsonl');
    new AuditLog({ run: 'a', file }).record(call('t', {}, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
    new AuditLog({ run: 'b', file }).record(call('t', {}, T0 + 1), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
    const r = verifyFile(file);
    assert.equal(r.ok, false);
    assert.equal(r.failure!.seq, 2);
    assert.equal(r.failure!.reason, 'bad-sequence');
  });
});

describe('AuditLog: redaction', () => {
  it('replaces a redacted path with "[redacted]" in the entry', () => {
    const log = new AuditLog({ run: 'r', redact: ['token'] });
    const entry = log.record(call('api.call', { token: 'sk-live-secret', url: 'https://x/' }, T0), ALLOW, {
      calls: 0, tokens: 0, usd: 0, bytes: 0,
    });
    assert.equal(entry.args['token'], '[redacted]');
    assert.equal(entry.args['url'], 'https://x/');
  });

  it('redacts a nested path and an array element', () => {
    const log = new AuditLog({ run: 'r', redact: ['auth.headers.authorization', 'keys.1'] });
    const entry = log.record(
      call('api.call', { auth: { headers: { authorization: 'Bearer x', accept: '*/*' } }, keys: ['pub', 'priv'] }, T0),
      ALLOW,
      { calls: 0, tokens: 0, usd: 0, bytes: 0 }
    );
    const auth = entry.args['auth'] as { headers: Record<string, unknown> };
    assert.equal(auth.headers['authorization'], '[redacted]');
    assert.equal(auth.headers['accept'], '*/*');
    assert.deepEqual(entry.args['keys'], ['pub', '[redacted]']);
  });

  it('does NOT mutate the caller\'s args object', () => {
    const args = { token: 'sk-live-secret', nested: { pw: 'hunter2' } };
    const log = new AuditLog({ run: 'r', redact: ['token', 'nested.pw'] });
    log.record(call('api.call', args, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
    assert.equal(args.token, 'sk-live-secret', 'the agent still needs the real value');
    assert.equal(args.nested.pw, 'hunter2');
  });

  it('a redaction path that does not exist is a harmless no-op', () => {
    const log = new AuditLog({ run: 'r', redact: ['nope', 'a.b.c.d', 'list.9', ''] });
    const entry = log.record(call('t', { a: { b: 1 }, list: [] }, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
    assert.deepEqual(entry.args, { a: { b: 1 }, list: [] });
    assert.equal(verifyChain([entry]).ok, true);
  });

  it('the chain still verifies over redacted entries', () => {
    const log = new AuditLog({ run: 'r', redact: ['token'] });
    log.record(call('a', { token: 's1' }, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
    log.record(call('b', { token: 's2' }, T0 + 1), ALLOW, { calls: 1, tokens: 0, usd: 0, bytes: 0 });
    assert.equal(verifyChain(log.all()).ok, true);
  });

  it('the hash commits to the redacted shape, so two different secrets hash alike', () => {
    // This is the point of redacting *before* hashing: the log proves what the
    // shape of the call was without ever containing the secret.
    const mk = (secret: string) => {
      const log = new AuditLog({ run: 'r', redact: ['token'] });
      return log.record(call('a', { token: secret }, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 }).hash;
    };
    assert.equal(mk('s1'), mk('s2'));
  });

  it('a secret cannot be un-redacted by re-hashing: the plaintext never verifies', () => {
    const log = new AuditLog({ run: 'r', redact: ['token'] });
    const entry = structuredClone(log.record(call('a', { token: 'secret' }, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 }));
    entry.args['token'] = 'secret';
    assert.equal(verifyChain([entry]).ok, false);
  });

  it('an empty redact list leaves args untouched', () => {
    const log = new AuditLog({ run: 'r', redact: [] });
    const entry = log.record(call('t', { token: 'visible' }, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
    assert.equal(entry.args['token'], 'visible');
  });

  it('a recorded entry is insulated from later mutation of the caller\'s args', () => {
    // Holding the caller's object by reference would let an agent that reuses
    // its argument object silently invalidate an honest chain: the entry would
    // hash to something the log no longer contains. Tested with no redaction
    // configured, which is the path that used to skip the clone.
    for (const redact of [[], ['other']]) {
      const log = new AuditLog({ run: 'r', redact });
      const args: Record<string, unknown> = { path: '/tmp/ok', nested: { deep: 1 } };
      log.record(call('fs.read', args, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });

      args['path'] = '/etc/passwd';
      (args['nested'] as Record<string, unknown>)['deep'] = 999;

      const [entry] = log.all();
      assert.equal(entry?.args['path'], '/tmp/ok');
      assert.deepEqual(entry?.args['nested'], { deep: 1 });
      assert.equal(verifyChain(log.all()).ok, true);
    }
  });

  it('a redaction path naming a prototype key adds nothing to the entry', () => {
    const log = new AuditLog({ run: 'r', redact: ['constructor', 'toString'] });
    const entry = log.record(call('t', { real: 1 }, T0), ALLOW, { calls: 0, tokens: 0, usd: 0, bytes: 0 });
    assert.deepEqual(Object.keys(entry.args), ['real']);
    assert.equal(verifyChain([entry]).ok, true);
  });
});
