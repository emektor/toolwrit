/**
 * Policy parsing and validation.
 *
 * Validation is strict and rejects unknown keys. In a security policy a typo
 * is not a harmless no-op: `startWith` silently ignored would turn a scoped
 * filesystem rule into an unscoped one. Fail loudly at load time instead.
 */

import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import type { ArgConstraint, Policy, PolicyRule } from '../types.js';

export class PolicyError extends Error {
  constructor(message: string, readonly path: string) {
    super(`${path}: ${message}`);
    this.name = 'PolicyError';
  }
}

const EFFECTS = new Set(['allow', 'deny', 'ask']);
const POLICY_KEYS = new Set(['version', 'name', 'default', 'budget', 'plan', 'rules']);
const PLAN_KEYS = new Set(['purpose', 'approvedBy', 'warnAt']);
const RULE_KEYS = new Set(['id', 'description', 'tools', 'effect', 'when', 'limit']);
const BUDGET_KEYS = new Set(['calls', 'tokens', 'usd', 'bytes', 'seconds']);
const LIMIT_KEYS = new Set(['max', 'perSeconds']);
const CONSTRAINT_KEYS = new Set([
  'optional', 'oneOf', 'noneOf', 'matches', 'startsWith', 'excludes',
  'min', 'max', 'maxLength', 'minLength', 'urlHosts', 'type',
]);

/** Read and validate a policy from a `.yaml`, `.yml` or `.json` file. */
export function loadPolicyFile(file: string): Policy {
  let raw: string;
  try {
    raw = readFileSync(file, 'utf8');
  } catch (err) {
    throw new PolicyError(`cannot read policy file (${(err as Error).message})`, file);
  }
  return parsePolicy(raw, file);
}

/** Validate an already-read policy document. `source` only decorates errors. */
export function parsePolicy(raw: string, source = 'policy'): Policy {
  let doc: unknown;
  try {
    doc = parseYaml(raw);
  } catch (err) {
    throw new PolicyError(`invalid YAML/JSON (${(err as Error).message})`, source);
  }
  return validatePolicy(doc, source);
}

export function validatePolicy(doc: unknown, source = 'policy'): Policy {
  const root = requireObject(doc, source);
  rejectUnknownKeys(root, POLICY_KEYS, source);

  if (root.version !== '1') {
    throw new PolicyError(
      `unsupported policy version ${JSON.stringify(root.version)}; expected "1"`,
      source
    );
  }

  if (root.name !== undefined && typeof root.name !== 'string') {
    throw new PolicyError('"name" must be a string', source);
  }

  if (root.default !== undefined && !EFFECTS.has(root.default as string)) {
    throw new PolicyError('"default" must be one of allow, deny, ask', source);
  }

  const policy: Policy = {
    version: '1',
    rules: [],
    ...(root.name !== undefined ? { name: root.name as string } : {}),
    ...(root.default !== undefined ? { default: root.default as Policy['default'] } : {}),
  };

  if (root.budget !== undefined) {
    const budget = requireObject(root.budget, `${source}.budget`);
    rejectUnknownKeys(budget, BUDGET_KEYS, `${source}.budget`);
    for (const key of BUDGET_KEYS) {
      const value = budget[key];
      if (value === undefined) continue;
      if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
        throw new PolicyError(`"${key}" must be a positive number`, `${source}.budget`);
      }
    }
    policy.budget = budget as Policy['budget'];
  }

  if (root.plan !== undefined) {
    const plan = requireObject(root.plan, `${source}.plan`);
    rejectUnknownKeys(plan, PLAN_KEYS, `${source}.plan`);

    if (typeof plan.purpose !== 'string' || plan.purpose.trim().length === 0) {
      throw new PolicyError('"purpose" must be a non-empty string', `${source}.plan`);
    }
    if (plan.approvedBy !== undefined && typeof plan.approvedBy !== 'string') {
      throw new PolicyError('"approvedBy" must be a string', `${source}.plan`);
    }
    if (plan.warnAt !== undefined) {
      if (!Array.isArray(plan.warnAt) || plan.warnAt.length === 0) {
        throw new PolicyError('"warnAt" must be a non-empty array', `${source}.plan`);
      }
      for (const t of plan.warnAt) {
        if (typeof t !== 'number' || !(t > 0) || t > 1) {
          throw new PolicyError(
            '"warnAt" entries must be fractions greater than 0 and at most 1, e.g. 0.8',
            `${source}.plan`
          );
        }
      }
    }
    // A plan with nothing to measure against would report nothing, which reads
    // as "all clear" rather than "not configured". Fail loudly instead.
    if (root.budget === undefined) {
      throw new PolicyError(
        'a "plan" requires a "budget" to measure against; add budget limits or remove the plan',
        source
      );
    }

    policy.plan = {
      purpose: plan.purpose,
      ...(plan.approvedBy !== undefined ? { approvedBy: plan.approvedBy as string } : {}),
      ...(plan.warnAt !== undefined
        ? { warnAt: [...(plan.warnAt as number[])].sort((a, b) => a - b) }
        : {}),
    };
  }

  if (!Array.isArray(root.rules)) {
    throw new PolicyError('"rules" must be an array', source);
  }

  const seen = new Set<string>();
  policy.rules = root.rules.map((rule, i) => {
    const parsed = validateRule(rule, `${source}.rules[${i}]`);
    if (seen.has(parsed.id)) {
      throw new PolicyError(`duplicate rule id "${parsed.id}"`, `${source}.rules[${i}]`);
    }
    seen.add(parsed.id);
    return parsed;
  });

  return policy;
}

function validateRule(raw: unknown, path: string): PolicyRule {
  const rule = requireObject(raw, path);
  rejectUnknownKeys(rule, RULE_KEYS, path);

  if (typeof rule.id !== 'string' || rule.id.length === 0) {
    throw new PolicyError('"id" must be a non-empty string', path);
  }
  if (rule.description !== undefined && typeof rule.description !== 'string') {
    throw new PolicyError('"description" must be a string', path);
  }
  if (!Array.isArray(rule.tools) || rule.tools.length === 0) {
    throw new PolicyError('"tools" must be a non-empty array of glob patterns', path);
  }
  for (const tool of rule.tools) {
    if (typeof tool !== 'string' || tool.length === 0) {
      throw new PolicyError('every entry in "tools" must be a non-empty string', path);
    }
  }
  if (!EFFECTS.has(rule.effect as string)) {
    throw new PolicyError('"effect" must be one of allow, deny, ask', path);
  }

  const out: PolicyRule = {
    id: rule.id,
    tools: rule.tools as string[],
    effect: rule.effect as PolicyRule['effect'],
    ...(rule.description !== undefined ? { description: rule.description as string } : {}),
  };

  if (rule.when !== undefined) {
    const when = requireObject(rule.when, `${path}.when`);
    const constraints: Record<string, ArgConstraint> = {};
    for (const [argPath, constraint] of Object.entries(when)) {
      constraints[argPath] = validateConstraint(constraint, `${path}.when["${argPath}"]`);
    }
    out.when = constraints;
  }

  if (rule.limit !== undefined) {
    const limit = requireObject(rule.limit, `${path}.limit`);
    rejectUnknownKeys(limit, LIMIT_KEYS, `${path}.limit`);
    if (typeof limit.max !== 'number' || !Number.isInteger(limit.max) || limit.max < 0) {
      throw new PolicyError('"max" must be a non-negative integer', `${path}.limit`);
    }
    if (
      limit.perSeconds !== undefined &&
      (typeof limit.perSeconds !== 'number' || limit.perSeconds <= 0)
    ) {
      throw new PolicyError('"perSeconds" must be a positive number', `${path}.limit`);
    }
    out.limit = {
      max: limit.max,
      ...(limit.perSeconds !== undefined ? { perSeconds: limit.perSeconds as number } : {}),
    };
  }

  return out;
}

function validateConstraint(raw: unknown, path: string): ArgConstraint {
  const c = requireObject(raw, path);
  rejectUnknownKeys(c, CONSTRAINT_KEYS, path);

  if (c.matches !== undefined) {
    if (typeof c.matches !== 'string') throw new PolicyError('"matches" must be a string', path);
    try {
      new RegExp(c.matches);
    } catch (err) {
      throw new PolicyError(`"matches" is not a valid regexp (${(err as Error).message})`, path);
    }
  }

  for (const key of ['startsWith', 'excludes', 'urlHosts'] as const) {
    const value = c[key];
    if (value === undefined) continue;
    if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
      throw new PolicyError(`"${key}" must be an array of strings`, path);
    }
  }

  for (const key of ['oneOf', 'noneOf'] as const) {
    if (c[key] !== undefined && !Array.isArray(c[key])) {
      throw new PolicyError(`"${key}" must be an array`, path);
    }
  }

  for (const key of ['min', 'max', 'maxLength', 'minLength'] as const) {
    if (c[key] !== undefined && typeof c[key] !== 'number') {
      throw new PolicyError(`"${key}" must be a number`, path);
    }
  }

  if (c.optional !== undefined && typeof c.optional !== 'boolean') {
    throw new PolicyError('"optional" must be a boolean', path);
  }

  if (
    c.type !== undefined &&
    !['string', 'number', 'boolean', 'object', 'array'].includes(c.type as string)
  ) {
    throw new PolicyError(
      '"type" must be one of string, number, boolean, object, array',
      path
    );
  }

  return c as ArgConstraint;
}

function requireObject(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new PolicyError('expected an object', path);
  }
  return value as Record<string, unknown>;
}

function rejectUnknownKeys(obj: Record<string, unknown>, allowed: Set<string>, path: string): void {
  const unknown = Object.keys(obj).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    throw new PolicyError(
      `unknown field(s) ${unknown.map((k) => `"${k}"`).join(', ')}; allowed: ${[...allowed].join(', ')}`,
      path
    );
  }
}
