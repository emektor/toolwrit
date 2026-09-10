#!/usr/bin/env node
/**
 * The `leash` binary.
 *
 * The adoption story for a policy tool is "can I put it in front of what I
 * already run, without editing anything?". `leash run --policy p.yaml -- <cmd>`
 * is that story: a prefix on an existing MCP server command. The other
 * subcommands exist so a policy can be reviewed (`explain`), tested in CI
 * (`check`) and defended afterwards (`verify`) without writing any code.
 *
 * Argument parsing is hand-rolled because a security tool with a dependency
 * tree is a harder sell than one without, and this grammar is small enough to
 * fit in a page.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createMcpProxy } from './adapters/mcp-proxy.js';
import { verifyFile } from './audit/verify.js';
import { Leash } from './leash.js';
import { loadPolicyFile } from './policy/load.js';
import type { ArgConstraint, Decision, Policy } from './types.js';

const USAGE = `leash — a deterministic leash for AI agents.

Usage:
  leash run     --policy <file> [--audit <file>] [--run <id>] -- <command> [args...]
  leash verify  <audit.jsonl>
  leash check   --policy <file> --tool <name> [--args <json>]
  leash explain --policy <file>

Options:
  --help       Show this text.
  --version    Print the leash version.

Exit codes:
  run      0 when the downstream server exits cleanly.
  verify   0 when the chain is intact, 1 when it is not.
  check    0 allow, 1 deny, 2 ask.
`;

interface ParsedArgs {
  flags: Map<string, string>;
  positional: string[];
  /** Everything after a bare `--`, passed through untouched. */
  rest: string[];
}

/**
 * Parse `--key value` / `--key=value` flags plus positionals.
 *
 * `--` is a hard stop: the remainder is the downstream command line and must
 * never be interpreted, or a server's own `--policy` flag would be stolen.
 */
function parseArgs(argv: readonly string[]): ParsedArgs {
  const flags = new Map<string, string>();
  const positional: string[] = [];
  const rest: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i]!;
    if (token === '--') {
      rest.push(...argv.slice(i + 1));
      break;
    }
    if (token.startsWith('--')) {
      const body = token.slice(2);
      const eq = body.indexOf('=');
      if (eq !== -1) {
        flags.set(body.slice(0, eq), body.slice(eq + 1));
        continue;
      }
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flags.set(body, next);
        i++;
      } else {
        flags.set(body, 'true');
      }
      continue;
    }
    positional.push(token);
  }

  return { flags, positional, rest };
}

/** Errors we raise ourselves, and can therefore report without a stack trace. */
class CliError extends Error {}

function main(): void | Promise<void> {
  const argv = process.argv.slice(2);
  const parsed = parseArgs(argv);

  if (argv.length === 0 || parsed.flags.has('help') || parsed.positional[0] === 'help') {
    process.stdout.write(USAGE);
    return;
  }
  if (parsed.flags.has('version')) {
    process.stdout.write(`${version()}\n`);
    return;
  }

  const subcommand = parsed.positional[0];
  switch (subcommand) {
    case 'run':
      return cmdRun(parsed);
    case 'verify':
      return cmdVerify(parsed);
    case 'check':
      return cmdCheck(parsed);
    case 'explain':
      return cmdExplain(parsed);
    default:
      throw new CliError(`unknown subcommand "${subcommand ?? ''}"\n\n${USAGE}`);
  }
}

async function cmdRun(parsed: ParsedArgs): Promise<void> {
  const policyFile = requireFlag(parsed, 'policy');
  const [command, ...args] = parsed.rest;
  if (!command) {
    throw new CliError('run needs a downstream command after `--`, e.g. `leash run --policy p.yaml -- npx my-server`');
  }

  const policy = loadPolicy(policyFile);
  const auditFile = parsed.flags.get('audit');
  const run = parsed.flags.get('run');

  const leash = new Leash({
    policy,
    ...(auditFile ? { auditFile } : {}),
    ...(run ? { run } : {}),
  });

  const proxy = createMcpProxy({ leash, command, args, policy });

  // Diagnostics go to stderr only: stdout is the client's protocol channel.
  process.stderr.write(
    `leash: guarding "${[command, ...args].join(' ')}" with ${policyFile} (run ${leash.run})\n`
  );

  const shutdown = () => {
    void proxy.stop();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  await proxy.start();
}

function cmdVerify(parsed: ParsedArgs): void {
  const file = parsed.positional[1];
  if (!file) throw new CliError('verify needs an audit file, e.g. `leash verify audit.jsonl`');

  let result;
  try {
    result = verifyFile(file);
  } catch (err) {
    throw new CliError(`cannot read audit file ${file} (${(err as Error).message})`);
  }

  if (result.ok) {
    process.stdout.write(`ok: ${result.count} entr${result.count === 1 ? 'y' : 'ies'} verified\n`);
    process.stdout.write(`head: ${result.head}\n`);
    return;
  }

  const failure = result.failure;
  process.stderr.write(`FAILED: audit chain is not intact (${result.count} entries read)\n`);
  if (failure) {
    process.stderr.write(`  seq:    ${failure.seq}\n`);
    process.stderr.write(`  reason: ${failure.reason}\n`);
    process.stderr.write(`  detail: ${failure.detail}\n`);
  }
  process.exitCode = 1;
}

function cmdCheck(parsed: ParsedArgs): void {
  const policy = loadPolicy(requireFlag(parsed, 'policy'));
  const tool = requireFlag(parsed, 'tool');

  const raw = parsed.flags.get('args');
  let args: Record<string, unknown> = {};
  if (raw !== undefined && raw !== 'true') {
    let value: unknown;
    try {
      value = JSON.parse(raw);
    } catch (err) {
      throw new CliError(`--args is not valid JSON (${(err as Error).message})`);
    }
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      throw new CliError('--args must be a JSON object');
    }
    args = value as Record<string, unknown>;
  }

  // No audit file and no execution: `check` is a dry run, safe to put in CI.
  const decision = new Leash({ policy }).check(tool, args);
  printDecision(tool, decision);

  process.exitCode = decision.effect === 'allow' ? 0 : decision.effect === 'deny' ? 1 : 2;
}

function printDecision(tool: string, decision: Decision): void {
  process.stdout.write(`${decision.effect.toUpperCase()} ${tool}\n`);
  process.stdout.write(`  rule:   ${decision.rule ?? '(policy default)'}\n`);
  process.stdout.write(`  reason: ${decision.reason}\n`);
  if (decision.violations.length > 0) {
    process.stdout.write('  violations:\n');
    for (const violation of decision.violations) {
      const where = violation.path ? ` ${violation.path}` : '';
      process.stdout.write(`    - [${violation.rule}${where}] ${violation.constraint}: ${violation.message}\n`);
    }
  }
}

function cmdExplain(parsed: ParsedArgs): void {
  const file = requireFlag(parsed, 'policy');
  const policy = loadPolicy(file);
  process.stdout.write(explainPolicy(policy, file));
}

function explainPolicy(policy: Policy, file: string): string {
  const out: string[] = [];
  out.push(`${policy.name ?? file} (version ${policy.version})`);
  out.push(`default effect: ${policy.default ?? 'deny'}`);

  if (policy.budget) {
    const parts = Object.entries(policy.budget).map(([key, value]) => `${key}=${value}`);
    out.push(`budget: ${parts.length > 0 ? parts.join(', ') : '(none)'}`);
  } else {
    out.push('budget: unlimited');
  }

  out.push('');
  out.push(`rules (${policy.rules.length}); among rules that match, deny beats ask beats allow:`);
  for (const rule of policy.rules) {
    out.push('');
    out.push(`  ${rule.id}  [${rule.effect}]`);
    if (rule.description) out.push(`    ${rule.description}`);
    out.push(`    tools: ${rule.tools.join(', ')}`);
    if (rule.limit) {
      const window = rule.limit.perSeconds ? `${rule.limit.perSeconds}s` : 'run';
      out.push(`    limit: ${rule.limit.max} call(s) per ${window}`);
    }
    for (const [path, constraint] of Object.entries(rule.when ?? {})) {
      out.push(`    when ${path}: ${describeConstraint(constraint)}`);
    }
  }

  return `${out.join('\n')}\n`;
}

/** Render one constraint as a phrase a reviewer can read out loud. */
function describeConstraint(constraint: ArgConstraint): string {
  const parts: string[] = [];
  if (constraint.type) parts.push(`is ${constraint.type}`);
  if (constraint.optional) parts.push('may be absent');
  if (constraint.oneOf) parts.push(`one of ${JSON.stringify(constraint.oneOf)}`);
  if (constraint.noneOf) parts.push(`none of ${JSON.stringify(constraint.noneOf)}`);
  if (constraint.matches) parts.push(`matches /${constraint.matches}/`);
  if (constraint.startsWith) parts.push(`starts with ${constraint.startsWith.join(' | ')}`);
  if (constraint.excludes) parts.push(`excludes ${constraint.excludes.join(' | ')}`);
  if (constraint.urlHosts) parts.push(`url host in ${constraint.urlHosts.join(' | ')}`);
  if (constraint.min !== undefined) parts.push(`>= ${constraint.min}`);
  if (constraint.max !== undefined) parts.push(`<= ${constraint.max}`);
  if (constraint.minLength !== undefined) parts.push(`length >= ${constraint.minLength}`);
  if (constraint.maxLength !== undefined) parts.push(`length <= ${constraint.maxLength}`);
  return parts.length > 0 ? parts.join('; ') : 'any value';
}

function requireFlag(parsed: ParsedArgs, name: string): string {
  const value = parsed.flags.get(name);
  if (value === undefined || value === 'true') throw new CliError(`missing required --${name} <value>`);
  return value;
}

function loadPolicy(file: string): Policy {
  try {
    return loadPolicyFile(file);
  } catch (err) {
    throw new CliError((err as Error).message);
  }
}

function version(): string {
  // The binary runs from dist/, so package.json is one directory up.
  const here = dirname(fileURLToPath(import.meta.url));
  for (const candidate of [join(here, '..', 'package.json'), join(here, '..', '..', 'package.json')]) {
    try {
      const pkg = JSON.parse(readFileSync(candidate, 'utf8')) as { version?: unknown };
      if (typeof pkg.version === 'string') return pkg.version;
    } catch {
      // Try the next candidate; a missing version is not worth failing over.
    }
  }
  return 'unknown';
}

try {
  const result = main();
  if (result instanceof Promise) {
    result.catch(fail);
  }
} catch (err) {
  fail(err);
}

/** Every user-facing failure exits 1 with one line — never a raw stack trace. */
function fail(err: unknown): void {
  const message = err instanceof CliError ? err.message : `${(err as Error).message ?? String(err)}`;
  process.stderr.write(`leash: ${message}\n`);
  process.exitCode = 1;
}
