/**
 * Drift: one run measured against the runs before it.
 *
 * The property that matters is the one budgets cannot give: a run that stays
 * under every ceiling but is unlike its own history gets reported, and a run
 * like its history does not. Quiet-run noise (0 -> 1 denial) must stay silent,
 * or the report gets ignored.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Toolwrit, ToolwritDenied } from '../src/toolwrit.js';
import { detectDrift, profileRuns } from '../src/audit/drift.js';
import type { AuditEntry } from '../src/audit/chain.js';
import { frozenClock, policy, rule } from './helpers.js';

const allowReads = policy({ rules: [rule({ id: 'read', tools: ['fs.read', 'fs.list'], effect: 'allow' })] });

/** Append one run of `reads` fs.read calls, plus any extra tools, to a shared log. */
async function run(log: AuditEntry[], name: string, reads: number, extra: string[] = []): Promise<void> {
  const toolwrit = new Toolwrit({ policy: allowReads, run: name, now: frozenClock() });
  for (let i = 0; i < reads; i++) await toolwrit.guard('fs.read', { path: `/w/${i}` }, () => 'x');
  for (const tool of extra) {
    try {
      await toolwrit.guard(tool, {}, () => 'x');
    } catch (err) {
      if (!(err instanceof ToolwritDenied)) throw err;
    }
  }
  log.push(...toolwrit.entries());
}

async function history(): Promise<AuditEntry[]> {
  const log: AuditEntry[] = [];
  await run(log, 'mon', 20);
  await run(log, 'tue', 22);
  await run(log, 'wed', 19);
  return log;
}

describe('detectDrift', () => {
  it('is silent for a run like the ones before it', async () => {
    const log = await history();
    await run(log, 'thu', 21);
    const report = detectDrift(log);
    assert.equal(report.run, 'thu');
    assert.equal(report.judged, true);
    assert.deepEqual(report.baselineRuns, ['mon', 'tue', 'wed']);
    assert.deepEqual(report.findings, []);
  });

  it('reports a run far above its usual volume', async () => {
    const log = await history();
    await run(log, 'thu', 300);
    const metrics = detectDrift(log).findings.map((f) => f.metric);
    assert.ok(metrics.includes('calls'));
    assert.ok(metrics.includes('tool:fs.read'));
    const calls = detectDrift(log).findings.find((f) => f.metric === 'calls')!;
    assert.equal(calls.value, 300);
    assert.equal(calls.baseline, 20);
  });

  it('reports the first call to a tool no earlier run used, even when it was denied', async () => {
    const log = await history();
    await run(log, 'thu', 20, ['shell.exec']);
    const findings = detectDrift(log).findings;
    assert.deepEqual(findings.map((f) => f.metric), ['new-tool:shell.exec']);
  });

  it('reports a burst of denials but not a single one', async () => {
    const quiet = await history();
    await run(quiet, 'thu', 20, ['shell.exec']);
    assert.ok(!detectDrift(quiet).findings.some((f) => f.metric === 'denied'));

    const noisy = await history();
    await run(noisy, 'thu', 20, ['shell.exec', 'shell.exec', 'shell.exec', 'net.post']);
    assert.ok(detectDrift(noisy).findings.some((f) => f.metric === 'denied'));
  });

  it('gives no verdict without enough history', async () => {
    const log: AuditEntry[] = [];
    await run(log, 'mon', 20);
    await run(log, 'tue', 500);
    const report = detectDrift(log);
    assert.equal(report.judged, false);
    assert.deepEqual(report.findings, []);
  });

  it('judges a named run against only the runs before it', async () => {
    const log = await history();
    await run(log, 'thu', 300);
    await run(log, 'fri', 20);
    assert.equal(detectDrift(log).findings.length, 0, 'fri is normal');
    assert.ok(detectDrift(log, { run: 'thu' }).findings.length > 0);
    assert.throws(() => detectDrift(log, { run: 'nope' }), /not in the audit log/);
  });

  it('respects a custom factor', async () => {
    const log = await history();
    await run(log, 'thu', 45);
    assert.equal(detectDrift(log).findings.length, 0, '45 is under 3x of 20');
    assert.ok(detectDrift(log, { factor: 2 }).findings.length > 0);
  });

  it('profiles runs without counting bookkeeping entries', async () => {
    const log = await history();
    const profiles = profileRuns(log);
    assert.deepEqual(profiles.map((p) => [p.run, p.calls]), [['mon', 20], ['tue', 22], ['wed', 19]]);
  });
});
