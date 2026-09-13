/**
 * Tool-name globbing and argument-path resolution.
 *
 * Deliberately tiny and dependency-free: this code sits on the hot path of
 * every tool call, and a policy author must be able to predict what it does
 * without reading a regex dialect reference.
 */

/**
 * `*` matches any run of characters except the separators `.` and `/`.
 * `**` matches anything, separators included.
 * Everything else is literal. Matching is case-sensitive and whole-string.
 */
export function matchesGlob(pattern: string, name: string): boolean {
  return globToRegExp(pattern).test(name);
}

const globCache = new Map<string, RegExp>();

function globToRegExp(pattern: string): RegExp {
  const cached = globCache.get(pattern);
  if (cached) return cached;

  let out = '^';
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;
    if (ch === '*') {
      if (pattern[i + 1] === '*') {
        out += '.*';
        i++;
      } else {
        out += '[^./]*';
      }
    } else {
      out += ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
  }
  out += '$';

  const re = new RegExp(out);
  globCache.set(pattern, re);
  return re;
}

/** True when any pattern in the list matches. An empty list matches nothing. */
export function matchesAnyGlob(patterns: readonly string[], name: string): boolean {
  return patterns.some((p) => matchesGlob(p, name));
}

/** Sentinel distinguishing "resolved to undefined" from "path does not exist". */
export const MISSING = Symbol('toolwrit.missing');

/**
 * Resolve a dotted path against an argument object.
 *
 * Numeric segments index into arrays (`recipients.0`). A path that runs off the
 * end of the object — or through a null — yields MISSING rather than throwing,
 * so a malformed model argument becomes a policy violation, not a crash.
 */
export function resolvePath(args: unknown, path: string): unknown | typeof MISSING {
  const segments = path.split('.');
  let cursor: unknown = args;

  for (const segment of segments) {
    if (cursor === null || cursor === undefined) return MISSING;

    if (Array.isArray(cursor)) {
      const index = Number(segment);
      if (!Number.isInteger(index) || index < 0 || index >= cursor.length) return MISSING;
      cursor = cursor[index];
      continue;
    }

    if (typeof cursor !== 'object') return MISSING;
    if (!Object.prototype.hasOwnProperty.call(cursor, segment)) return MISSING;
    cursor = (cursor as Record<string, unknown>)[segment];
  }

  return cursor;
}
