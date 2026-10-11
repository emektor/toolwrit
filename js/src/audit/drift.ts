/**
 * Drift: is this run unlike the runs before it?
 *
 * Budgets answer "did the run cross a line someone drew in advance?". They
 * cannot answer "is this run strange?", because a ceiling is set for the worst
 * legitimate day, and a hijacked agent that stays under it passes. A run that
 * normally makes 20 calls and today made 300 is news even with a ceiling of
 * 500, and so is the first call it has ever made to a tool it never used.
 *
 * Drift compares one run against the earlier runs in the same audit log. It is
 * a report, not an enforcement point: it reads a finished log, decides
 * nothing at call time, and is meant for a cron job or CI step that pages a
 * human. Medians, not means, so one bad run in the history does not raise the
 * bar for the next.
 *
 * What it cannot see: anything that never crossed the tool boundary, and misuse
 * that looks exactly like normal use. A run that does the usual number of the
 * usual calls with different intent is not drift.
 */

import type { AuditEntry } from './chain.js';

const BOOKKEEPING = new Set(['toolwrit:plan', 'toolwrit:warning']);

/** Per-run figures that drift compares. */
export interface RunProfile {
  run: string;
  /** Tool calls the agent made, bookkeeping entries excluded. */
  calls: number;
  denied: number;
  /** Highest bytes figure recorded during the run. */
  bytes: number;
  /** Highest USD figure recorded during the run. */
  usd: number;
  /** Calls per tool. */
  tools: Record<string, number>;
}

export interface DriftFinding {
  /** "calls", "denied", "bytes", "usd", "tool:<name>" or "new-tool:<name>". */
  metric: string;
  value: number;
  /** Median over the baseline runs; 0 for a tool never seen before. */
  baseline: number;
  message: string;
}

export interface DriftOptions {
  /** Run to examine. Defaults to the last run that appears in the log. */
  run?: string;
  /** Flag a metric above this multiple of its baseline median. Default 3. */
  factor?: number;
  /** Earlier runs needed before any verdict is given. Default 3. */
  minHistory?: number;
}

export interface DriftReport {
  run: string;
  /** Runs the baseline was built from, oldest first. */
  baselineRuns: string[];
  /** False when there were too few earlier runs to judge. */
  judged: boolean;
  profile: RunProfile;
  findings: DriftFinding[];
}

/**
 * Smallest absolute rise worth reporting, so that 0 -> 1 denials or 2 -> 7
 * calls do not page anyone. A ratio alone flags noise on quiet runs.
 */
const FLOOR: Record<string, number> = { calls: 10, denied: 3, bytes: 1024, usd: 0.01, tool: 5 };

export function profileRuns(entries: readonly AuditEntry[]): RunProfile[] {
  const byRun = new Map<string, RunProfile>();
  for (const entry of entries) {
    let p = byRun.get(entry.run);
    if (!p) {
      p = { run: entry.run, calls: 0, denied: 0, bytes: 0, usd: 0, tools: {} };
      byRun.set(entry.run, p);
    }
    if (BOOKKEEPING.has(entry.tool)) continue;
    p.calls++;
    if (entry.decision.effect === 'deny') p.denied++;
    p.tools[entry.tool] = (p.tools[entry.tool] ?? 0) + 1;
    p.bytes = Math.max(p.bytes, entry.usage?.bytes ?? 0);
    p.usd = Math.max(p.usd, entry.usage?.usd ?? 0);
  }
  return [...byRun.values()];
}

function median(values: readonly number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2;
}

function exceeds(value: number, base: number, factor: number, floor: number): boolean {
  return value - base >= floor && (base === 0 || value > base * factor);
}

export function detectDrift(entries: readonly AuditEntry[], options: DriftOptions = {}): DriftReport {
  const factor = options.factor ?? 3;
  const minHistory = options.minHistory ?? 3;
  const runs = profileRuns(entries);
  if (runs.length === 0) throw new Error('the audit log has no runs');

  const index = options.run === undefined ? runs.length - 1 : runs.findIndex((r) => r.run === options.run);
  if (index === -1) throw new Error(`run "${options.run}" is not in the audit log`);

  const profile = runs[index]!;
  const history = runs.slice(0, index);
  const report: DriftReport = {
    run: profile.run,
    baselineRuns: history.map((r) => r.run),
    judged: history.length >= minHistory,
    profile,
    findings: [],
  };
  if (!report.judged) return report;

  for (const metric of ['calls', 'denied', 'bytes', 'usd'] as const) {
    const base = median(history.map((r) => r[metric]));
    const value = profile[metric];
    if (exceeds(value, base, factor, FLOOR[metric]!)) {
      report.findings.push({
        metric,
        value,
        baseline: base,
        message: `${metric} ${value} against a usual ${base}`,
      });
    }
  }

  const seen = new Set(history.flatMap((r) => Object.keys(r.tools)));
  for (const [tool, count] of Object.entries(profile.tools).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    if (!seen.has(tool)) {
      report.findings.push({
        metric: `new-tool:${tool}`,
        value: count,
        baseline: 0,
        message: `${tool} was called ${count} time(s); no earlier run called it`,
      });
      continue;
    }
    const base = median(history.map((r) => r.tools[tool] ?? 0));
    if (exceeds(count, base, factor, FLOOR.tool!)) {
      report.findings.push({
        metric: `tool:${tool}`,
        value: count,
        baseline: base,
        message: `${tool} called ${count} times against a usual ${base}`,
      });
    }
  }
  return report;
}
