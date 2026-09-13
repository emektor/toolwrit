/**
 * Tamper-evident audit log.
 *
 * Entries form a hash chain: each one commits to the hash of its predecessor,
 * so editing or deleting any past entry invalidates every hash after it. This
 * is what turns "we had a policy" into "here is what the policy actually did",
 * which is the only version an auditor accepts.
 *
 * The format is JSONL — one entry per line — so it survives a crash mid-run
 * and can be tailed, grepped and shipped to any log pipeline unchanged.
 */

import { createHash } from 'node:crypto';
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { BudgetUsage, Decision, ToolCall } from '../types.js';

/** Hash recorded as the predecessor of the first entry. */
export const GENESIS = '0'.repeat(64);

export interface AuditEntry {
  /** 1-based position in the chain. */
  seq: number;
  /** Milliseconds since epoch, taken from the tool call. */
  at: number;
  /** Run identifier, so several runs can share one log file. */
  run: string;
  tool: string;
  /** Arguments as evaluated. Redacted fields are replaced before hashing. */
  args: Record<string, unknown>;
  decision: Decision;
  /** Budget consumption at the moment of the decision. */
  usage: Pick<BudgetUsage, 'calls' | 'tokens' | 'usd' | 'bytes'>;
  /** Hash of the preceding entry, or GENESIS. */
  prev: string;
  /** sha256 over the canonical form of this entry, excluding `hash` itself. */
  hash: string;
}

/**
 * Deterministic JSON: object keys sorted, no incidental whitespace.
 *
 * Without this the chain would depend on V8's key ordering, and a log written
 * by one process could fail verification in another. Undefined values are
 * dropped, matching JSON.stringify.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';

  // The entry is hashed here and written to the file with JSON.stringify, so
  // the two have to agree on every value. JSON.stringify calls toJSON; reading
  // an object structurally instead would hash a Date as {} while writing it as
  // a string, and the entry would come back from its own file as "bad-hash" --
  // a tamper alarm on an honest run, which in a trust product is its own kind
  // of damage. Affects Date, Decimal.js, Luxon, BigNumber and Mongo ObjectId.
  const toJSON = (value as { toJSON?: unknown }).toJSON;
  if (typeof toJSON === 'function') {
    return canonicalize((toJSON as (key?: string) => unknown).call(value, ''));
  }

  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`);
  return `{${entries.join(',')}}`;
}

export function hashEntry(entry: Omit<AuditEntry, 'hash'>): string {
  return createHash('sha256').update(canonicalize(entry)).digest('hex');
}

export interface AuditLogOptions {
  /** Run identifier stamped on every entry. */
  run: string;
  /** When set, entries are appended to this JSONL file as well as buffered. */
  file?: string;
  /**
   * Argument paths whose values are replaced with "[redacted]" before hashing.
   * Secrets must never reach the log, but the chain still has to cover the
   * redacted shape so a redaction cannot be forged after the fact.
   */
  redact?: string[];
}

export class AuditLog {
  private readonly entries: AuditEntry[] = [];
  private last = GENESIS;

  constructor(private readonly options: AuditLogOptions) {
    if (options.file) mkdirSync(dirname(options.file), { recursive: true });
  }

  /** Append a decision to the chain and return the entry that was written. */
  record(call: ToolCall, decision: Decision, usage: AuditEntry['usage']): AuditEntry {
    const body: Omit<AuditEntry, 'hash'> = {
      seq: this.entries.length + 1,
      at: call.at,
      run: this.options.run,
      tool: call.tool,
      args: redactArgs(call.args, this.options.redact ?? []),
      decision,
      usage,
      prev: this.last,
    };

    const entry: AuditEntry = { ...body, hash: hashEntry(body) };
    this.entries.push(entry);
    this.last = entry.hash;

    if (this.options.file) {
      appendFileSync(this.options.file, `${JSON.stringify(entry)}\n`, 'utf8');
    }
    return entry;
  }

  /** Entries recorded by this instance, oldest first. */
  all(): readonly AuditEntry[] {
    return this.entries;
  }

  /** Hash of the newest entry — the value a receipt should quote. */
  head(): string {
    return this.last;
  }

  /** History in the shape the policy engine wants for rate limiting. */
  history(): { tool: string; rule: string | null; at: number }[] {
    return this.entries
      .filter((e) => e.decision.effect !== 'deny')
      .map((e) => ({ tool: e.tool, rule: e.decision.rule, at: e.at }));
  }
}

function redactArgs(
  args: Record<string, unknown>,
  paths: readonly string[]
): Record<string, unknown> {
  // Always clone, even with nothing to redact. Holding the caller's object by
  // reference would let a later mutation of it change what this entry hashes
  // to, silently invalidating an otherwise honest chain. The clone also keeps
  // the caller's object untouched: the agent may still need the real value.
  const clone = structuredClone(args) as Record<string, unknown>;
  if (paths.length === 0) return clone;
  for (const path of paths) {
    const segments = path.split('.');
    const leaf = segments.pop();
    if (!leaf) continue;

    let cursor: unknown = clone;
    for (const segment of segments) {
      if (typeof cursor !== 'object' || cursor === null) break;
      cursor = (cursor as Record<string, unknown>)[segment];
    }
    // hasOwnProperty, not `in`: a redaction path naming a prototype key such as
    // "constructor" must be a no-op rather than adding an own property that was
    // never in the arguments.
    if (
      typeof cursor === 'object' &&
      cursor !== null &&
      Object.prototype.hasOwnProperty.call(cursor, leaf)
    ) {
      (cursor as Record<string, unknown>)[leaf] = '[redacted]';
    }
  }
  return clone;
}
