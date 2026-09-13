/**
 * Glob semantics and argument-path resolution.
 *
 * These two functions decide *which* rule sees a call and *what value* that
 * rule inspects. A mistake in either one silently widens a policy, so the
 * assertions below are deliberately picky about separators, anchoring and
 * prototype pollution.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { MISSING, matchesGlob, matchesAnyGlob, resolvePath } from '../src/policy/match.js';

describe('matchesGlob', () => {
  it('matches a literal name exactly', () => {
    assert.equal(matchesGlob('fs.read', 'fs.read'), true);
    assert.equal(matchesGlob('fs.read', 'fs.write'), false);
  });

  it('anchors the whole string — no prefix or suffix matches', () => {
    assert.equal(matchesGlob('fs.read', 'xfs.read'), false);
    assert.equal(matchesGlob('fs.read', 'fs.reader'), false);
    assert.equal(matchesGlob('fs.read', 'fs.read\n'), false, 'a trailing newline must not sneak past $');
    assert.equal(matchesGlob('read', 'fs.read'), false);
  });

  it('is case sensitive', () => {
    assert.equal(matchesGlob('FS.read', 'fs.read'), false);
    assert.equal(matchesGlob('fs.read', 'FS.READ'), false);
  });

  it('treats `*` as "anything but a separator"', () => {
    assert.equal(matchesGlob('fs.*', 'fs.read'), true);
    assert.equal(matchesGlob('fs.*', 'fs.read_file'), true);
    assert.equal(matchesGlob('fs.*', 'fs.read.raw'), false, '* must not cross a dot');
    assert.equal(matchesGlob('fs.*', 'fs.read/raw'), false, '* must not cross a slash');
    assert.equal(matchesGlob('*', 'read'), true);
    assert.equal(matchesGlob('*', 'fs.read'), false, 'a bare * does not cross a dot');
    assert.equal(matchesGlob('*', 'github/create_issue'), false);
  });

  it('matches the empty run with `*`', () => {
    assert.equal(matchesGlob('fs.*', 'fs.'), true);
    assert.equal(matchesGlob('*', ''), true);
  });

  it('treats `**` as "anything at all", separators included', () => {
    assert.equal(matchesGlob('**', 'fs.read'), true);
    assert.equal(matchesGlob('**', 'github/create_issue'), true);
    assert.equal(matchesGlob('**', ''), true);
    assert.equal(matchesGlob('fs.**', 'fs.read.raw'), true);
    assert.equal(matchesGlob('github/**', 'github/issues/create'), true);
    assert.equal(matchesGlob('**.read', 'a.b.c.read'), true);
    assert.equal(matchesGlob('**.read', 'a.b.c.write'), false);
    // "Anything" includes a newline. Without the `s` flag `.` stops at one, so
    // `fs.**` on a deny rule would not have matched this tool name -- and the
    // Python port, which uses re.DOTALL, would have matched it.
    assert.equal(matchesGlob('**', 'a\nb'), true);
    assert.equal(matchesGlob('fs.**', 'fs.a\nb'), true);
  });

  it('keeps literal dots literal', () => {
    assert.equal(matchesGlob('fs.read', 'fsXread'), false, 'the dot must not act as a regex wildcard');
    assert.equal(matchesGlob('a.b', 'aXb'), false);
  });

  it('escapes regex metacharacters in the pattern', () => {
    // Each of these would change meaning if the pattern reached RegExp unescaped.
    assert.equal(matchesGlob('a+b', 'a+b'), true);
    assert.equal(matchesGlob('a+b', 'aab'), false);
    assert.equal(matchesGlob('a?b', 'a?b'), true);
    assert.equal(matchesGlob('a?b', 'ab'), false);
    assert.equal(matchesGlob('a(b)c', 'a(b)c'), true);
    assert.equal(matchesGlob('a|b', 'a|b'), true);
    assert.equal(matchesGlob('a|b', 'a'), false, 'alternation must not be honoured');
    assert.equal(matchesGlob('a[bc]d', 'a[bc]d'), true);
    assert.equal(matchesGlob('a[bc]d', 'abd'), false, 'a character class must not be honoured');
    assert.equal(matchesGlob('a{1,2}', 'a{1,2}'), true);
    assert.equal(matchesGlob('a\\b', 'a\\b'), true);
    assert.equal(matchesGlob('^a$', '^a$'), true);
    assert.equal(matchesGlob('^a$', 'a'), false);
  });

  it('caches by pattern without cross-contaminating results', () => {
    // The cache is keyed on the pattern string; exercise a repeat to be sure the
    // cached RegExp is not stateful (a /g regexp would alternate true/false).
    for (let i = 0; i < 5; i++) {
      assert.equal(matchesGlob('fs.*', 'fs.read'), true, `iteration ${i}`);
      assert.equal(matchesGlob('fs.*', 'net.read'), false, `iteration ${i}`);
    }
  });
});

describe('matchesAnyGlob', () => {
  it('matches when any pattern matches', () => {
    assert.equal(matchesAnyGlob(['net.*', 'fs.read'], 'fs.read'), true);
  });

  it('an empty list matches nothing', () => {
    assert.equal(matchesAnyGlob([], 'fs.read'), false);
    assert.equal(matchesAnyGlob([], ''), false);
  });
});

describe('resolvePath', () => {
  it('resolves a top-level key', () => {
    assert.equal(resolvePath({ path: '/tmp/x' }, 'path'), '/tmp/x');
  });

  it('resolves nested objects', () => {
    const args = { body: { recipient: { email: 'a@b.c' } } };
    assert.equal(resolvePath(args, 'body.recipient.email'), 'a@b.c');
  });

  it('indexes into arrays with numeric segments', () => {
    const args = { to: ['a@b.c', 'd@e.f'] };
    assert.equal(resolvePath(args, 'to.0'), 'a@b.c');
    assert.equal(resolvePath(args, 'to.1'), 'd@e.f');
  });

  it('resolves through arrays of objects', () => {
    const args = { items: [{ sku: 'x' }, { sku: 'y' }] };
    assert.equal(resolvePath(args, 'items.1.sku'), 'y');
  });

  it('returns MISSING for out-of-range and non-integer array indices', () => {
    const args = { to: ['a'] };
    assert.equal(resolvePath(args, 'to.1'), MISSING);
    assert.equal(resolvePath(args, 'to.-1'), MISSING);
    assert.equal(resolvePath(args, 'to.length'), MISSING, 'array `length` is not addressable');
    assert.equal(resolvePath(args, 'to.1.5'), MISSING);
    assert.equal(resolvePath(args, 'to.0'), 'a');
  });

  it('distinguishes MISSING from a real undefined value', () => {
    const args: Record<string, unknown> = { present: undefined };
    assert.equal(resolvePath(args, 'present'), undefined);
    assert.notEqual(resolvePath(args, 'present'), MISSING);
    assert.equal(resolvePath(args, 'absent'), MISSING);
  });

  it('preserves falsy values rather than reporting them as MISSING', () => {
    const args = { a: 0, b: '', c: false, d: null };
    assert.equal(resolvePath(args, 'a'), 0);
    assert.equal(resolvePath(args, 'b'), '');
    assert.equal(resolvePath(args, 'c'), false);
    assert.equal(resolvePath(args, 'd'), null);
  });

  it('returns MISSING when the path runs through a null or undefined', () => {
    assert.equal(resolvePath({ a: null }, 'a.b'), MISSING);
    assert.equal(resolvePath({ a: { b: null } }, 'a.b.c'), MISSING);
    assert.equal(resolvePath({ a: undefined }, 'a.b'), MISSING);
    assert.equal(resolvePath(null, 'a'), MISSING);
    assert.equal(resolvePath(undefined, 'a'), MISSING);
  });

  it('returns MISSING when the cursor is a primitive', () => {
    assert.equal(resolvePath({ a: 'string' }, 'a.b'), MISSING);
    assert.equal(resolvePath({ a: 'string' }, 'a.0'), MISSING, 'strings are not indexable here');
    assert.equal(resolvePath({ a: 42 }, 'a.toFixed'), MISSING);
    assert.equal(resolvePath({ a: true }, 'a.valueOf'), MISSING);
  });

  it('respects hasOwnProperty — prototype keys are MISSING', () => {
    assert.equal(resolvePath({}, 'constructor'), MISSING);
    assert.equal(resolvePath({}, 'toString'), MISSING);
    assert.equal(resolvePath({}, '__proto__'), MISSING);
    assert.equal(resolvePath({}, 'hasOwnProperty'), MISSING);
    assert.equal(resolvePath({ a: {} }, 'a.constructor.prototype'), MISSING);
  });

  it('resolves an own property that shadows a prototype name', () => {
    assert.equal(resolvePath({ toString: 'shadowed' }, 'toString'), 'shadowed');
  });

  it('works on an object with a null prototype', () => {
    const bare = Object.create(null) as Record<string, unknown>;
    bare.token = 'secret';
    assert.equal(resolvePath(bare, 'token'), 'secret');
    assert.equal(resolvePath(bare, 'missing'), MISSING);
  });

  it('an empty path segment does not resolve', () => {
    assert.equal(resolvePath({ a: 1 }, ''), MISSING);
    assert.equal(resolvePath({ a: 1 }, 'a.'), MISSING);
  });

  it('does not mutate the object it inspects', () => {
    const args = { a: { b: 1 } };
    const before = JSON.stringify(args);
    resolvePath(args, 'a.b.c.d');
    resolvePath(args, 'constructor');
    assert.equal(JSON.stringify(args), before);
  });
});
