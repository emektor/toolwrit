/**
 * Argument constraint evaluation.
 *
 * Each check returns a Violation or null. They run in a fixed order so the
 * first reported violation for a given value is always the same one — audit
 * diffs stay stable across releases.
 */

import type { ArgConstraint, Violation } from '../types.js';
import { MISSING, resolvePath } from './match.js';

/**
 * Evaluate every constraint in `when` against `args`.
 * Returns all violations found, so a policy author sees the full picture
 * rather than fixing one argument at a time.
 */
export function checkArgs(
  ruleId: string,
  when: Record<string, ArgConstraint>,
  args: Record<string, unknown>
): Violation[] {
  const violations: Violation[] = [];
  for (const [path, constraint] of Object.entries(when)) {
    violations.push(...checkOne(ruleId, path, constraint, resolvePath(args, path)));
  }
  return violations;
}

function checkOne(
  rule: string,
  path: string,
  c: ArgConstraint,
  value: unknown | typeof MISSING
): Violation[] {
  const v = (constraint: string, message: string): Violation => ({ rule, path, constraint, message });

  // An own property explicitly set to undefined is indistinguishable from an
  // absent one for policy purposes, and treating it as present would let
  // `{ path: undefined }` satisfy a required, scoped constraint.
  if (value === MISSING || value === undefined) {
    if (c.optional) return [];
    return [v('required', `argument "${path}" is required but was not provided`)];
  }

  const out: Violation[] = [];

  if (c.type && !isType(value, c.type)) {
    // A type mismatch makes every downstream check meaningless, so stop here.
    return [v('type', `argument "${path}" must be a ${c.type}, got ${describe(value)}`)];
  }

  // Constraints below are type-specific. Skipping one because the value has an
  // unexpected type would fail OPEN: `startsWith: ["/tmp/"]` would be satisfied
  // by the array ["/etc/passwd"], and the rule would still match and allow the
  // call. `args` is untrusted model output, so a wrong type is a violation.
  const stringConstraints = presentKeys(c, ['matches', 'startsWith', 'excludes', 'urlHosts']);
  const numberConstraints = presentKeys(c, ['min', 'max']);
  const lengthConstraints = presentKeys(c, ['minLength', 'maxLength']);

  const isString = typeof value === 'string';
  const isNumber = typeof value === 'number';
  const hasLength = lengthOf(value) !== null;

  if (stringConstraints.length > 0 && !isString) {
    out.push(
      v(
        'type',
        `argument "${path}" must be a string to be checked against ${list(stringConstraints)}, got ${describe(value)}`
      )
    );
  }
  if (numberConstraints.length > 0 && !isNumber) {
    out.push(
      v(
        'type',
        `argument "${path}" must be a number to be checked against ${list(numberConstraints)}, got ${describe(value)}`
      )
    );
  }
  if (lengthConstraints.length > 0 && !hasLength) {
    out.push(
      v(
        'type',
        `argument "${path}" must be a string or array to be checked against ${list(lengthConstraints)}, got ${describe(value)}`
      )
    );
  }

  if (c.oneOf && !c.oneOf.some((allowed) => deepEqual(allowed, value))) {
    out.push(v('oneOf', `argument "${path}" must be one of ${JSON.stringify(c.oneOf)}`));
  }

  if (c.noneOf && c.noneOf.some((banned) => deepEqual(banned, value))) {
    out.push(v('noneOf', `argument "${path}" must not be ${JSON.stringify(value)}`));
  }

  if (typeof value === 'string') {
    if (c.matches !== undefined && !new RegExp(c.matches).test(value)) {
      out.push(v('matches', `argument "${path}" must match /${c.matches}/`));
    }
    if (c.startsWith && !c.startsWith.some((prefix) => value.startsWith(prefix))) {
      out.push(
        v('startsWith', `argument "${path}" must start with one of ${JSON.stringify(c.startsWith)}`)
      );
    }
    if (c.excludes) {
      const hit = c.excludes.find((needle) => value.includes(needle));
      if (hit !== undefined) {
        out.push(v('excludes', `argument "${path}" must not contain ${JSON.stringify(hit)}`));
      }
    }
    if (c.urlHosts) {
      const host = hostnameOf(value);
      if (host === null) {
        out.push(v('urlHosts', `argument "${path}" is not a parseable URL`));
      } else if (!c.urlHosts.some((allowed) => hostAllowed(host, allowed))) {
        out.push(
          v('urlHosts', `host "${host}" is not in the allowed set ${JSON.stringify(c.urlHosts)}`)
        );
      }
    }
  }

  if (typeof value === 'number') {
    if (c.min !== undefined && value < c.min) {
      out.push(v('min', `argument "${path}" must be >= ${c.min}, got ${value}`));
    }
    if (c.max !== undefined && value > c.max) {
      out.push(v('max', `argument "${path}" must be <= ${c.max}, got ${value}`));
    }
  }

  const length = lengthOf(value);
  if (length !== null) {
    if (c.maxLength !== undefined && length > c.maxLength) {
      out.push(v('maxLength', `argument "${path}" must have length <= ${c.maxLength}, got ${length}`));
    }
    if (c.minLength !== undefined && length < c.minLength) {
      out.push(v('minLength', `argument "${path}" must have length >= ${c.minLength}, got ${length}`));
    }
  }

  return out;
}

/** Which of `keys` the author actually set on this constraint. */
function presentKeys(c: ArgConstraint, keys: readonly (keyof ArgConstraint)[]): string[] {
  return keys.filter((key) => c[key] !== undefined) as string[];
}

function list(names: readonly string[]): string {
  return names.map((n) => `"${n}"`).join(', ');
}

function isType(value: unknown, type: NonNullable<ArgConstraint['type']>): boolean {
  if (type === 'array') return Array.isArray(value);
  if (type === 'object') return typeof value === 'object' && value !== null && !Array.isArray(value);
  return typeof value === type;
}

function lengthOf(value: unknown): number | null {
  if (typeof value === 'string') return value.length;
  if (Array.isArray(value)) return value.length;
  return null;
}

function describe(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function hostnameOf(raw: string): string | null {
  try {
    return new URL(raw).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * An entry starting with "." matches that domain and every subdomain
 * (".example.com" covers "api.example.com" and "example.com"). Anything else
 * must match exactly, so an allowlist never widens by accident.
 */
function hostAllowed(host: string, allowed: string): boolean {
  const pattern = allowed.toLowerCase();
  if (pattern.startsWith('.')) {
    return host === pattern.slice(1) || host.endsWith(pattern);
  }
  return host === pattern;
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return false;
  if (typeof a !== 'object') return false;

  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((item, i) => deepEqual(item, b[i]));
  }

  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const keys = Object.keys(ao);
  if (keys.length !== Object.keys(bo).length) return false;
  return keys.every(
    (k) => Object.prototype.hasOwnProperty.call(bo, k) && deepEqual(ao[k], bo[k])
  );
}
