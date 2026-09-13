/**
 * Chain verification.
 *
 * Verification is the product. Anyone can write a log; the value is being able
 * to hand a regulator, a customer or an acquirer a file and a one-line command
 * that proves the file was not edited after the fact.
 */

import { readFileSync } from 'node:fs';
import { GENESIS, hashEntry, type AuditEntry } from './chain.js';

export interface VerifyResult {
  ok: boolean;
  /** Number of entries examined. */
  count: number;
  /** Hash of the final entry, or GENESIS for an empty log. */
  head: string;
  /** Populated when ok is false; identifies the first entry that failed. */
  failure?: {
    seq: number;
    reason: 'bad-hash' | 'broken-link' | 'bad-sequence' | 'malformed';
    detail: string;
  };
}

/** Verify an in-memory chain. Stops at the first inconsistency. */
export function verifyChain(entries: readonly AuditEntry[]): VerifyResult {
  let prev = GENESIS;

  for (const [i, entry] of entries.entries()) {
    const seq = i + 1;
    const fail = (reason: NonNullable<VerifyResult['failure']>['reason'], detail: string): VerifyResult => ({
      ok: false,
      count: entries.length,
      head: prev,
      failure: { seq, reason, detail },
    });

    if (entry.seq !== seq) {
      return fail('bad-sequence', `entry declares seq ${entry.seq} but sits at position ${seq}`);
    }
    if (entry.prev !== prev) {
      return fail('broken-link', `entry links to ${short(entry.prev)} but predecessor hashes to ${short(prev)}`);
    }

    const { hash, ...body } = entry;
    const recomputed = hashEntry(body);
    if (recomputed !== hash) {
      return fail('bad-hash', `entry hashes to ${short(recomputed)} but claims ${short(hash)}`);
    }

    prev = hash;
  }

  return { ok: true, count: entries.length, head: prev };
}

/** Verify a JSONL audit file written by AuditLog. */
export function verifyFile(file: string): VerifyResult {
  const lines = readFileSync(file, 'utf8').split('\n').filter((line) => line.trim().length > 0);

  const entries: AuditEntry[] = [];
  for (const [i, line] of lines.entries()) {
    try {
      entries.push(JSON.parse(line) as AuditEntry);
    } catch (err) {
      return {
        ok: false,
        count: lines.length,
        head: GENESIS,
        failure: {
          seq: i + 1,
          reason: 'malformed',
          detail: `line ${i + 1} is not valid JSON (${(err as Error).message})`,
        },
      };
    }
  }

  return verifyChain(entries);
}

function short(hash: string): string {
  return hash.slice(0, 12);
}
