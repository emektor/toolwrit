/**
 * Argument constraint evaluation.
 *
 * `checkArgs` is where an allowlist actually bites. Each block below pins one
 * constraint's exact behaviour, including the boundary values, so a refactor
 * cannot quietly loosen a filesystem scope or a URL allowlist.
 *
 * NOTE: three tests near the bottom are marked "BUG" — they assert the *safe*
 * behaviour and currently FAIL against src/policy/constraints.ts. See the
 * summary at the end of this file and the report.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { checkArgs } from '../src/policy/constraints.js';
import type { ArgConstraint, Violation } from '../src/types.js';

/** Run one constraint against one value and return the violations. */
function check(c: ArgConstraint, args: Record<string, unknown>, path = 'x'): Violation[] {
  return checkArgs('r1', { [path]: c }, args);
}

/** The constraint names that fired, in order. */
function names(violations: Violation[]): string[] {
  return violations.map((v) => v.constraint);
}

describe('checkArgs: presence', () => {
  it('a missing required argument produces exactly one `required` violation', () => {
    const v = check({ type: 'string', startsWith: ['/tmp'] }, {});
    assert.deepEqual(names(v), ['required']);
    assert.equal(v[0]!.rule, 'r1');
    assert.equal(v[0]!.path, 'x');
    assert.match(v[0]!.message, /"x" is required/);
  });

  it('a missing optional argument produces no violations', () => {
    assert.deepEqual(check({ optional: true, type: 'string' }, {}), []);
  });

  it('optional does not excuse a present-but-invalid value', () => {
    assert.deepEqual(names(check({ optional: true, type: 'string' }, { x: 5 })), ['type']);
  });

  it('a missing nested path is reported against the full dotted path', () => {
    const v = checkArgs('r1', { 'body.to.0': { type: 'string' } }, { body: {} });
    assert.deepEqual(names(v), ['required']);
    assert.equal(v[0]!.path, 'body.to.0');
  });

  it('checks every path in `when` and reports all of them', () => {
    const v = checkArgs(
      'r1',
      { a: { type: 'string' }, b: { type: 'number' } },
      { a: 1, b: 'two' }
    );
    assert.deepEqual(names(v), ['type', 'type']);
    assert.deepEqual(v.map((x) => x.path), ['a', 'b']);
  });

  it('an empty `when` matches anything', () => {
    assert.deepEqual(checkArgs('r1', {}, { anything: true }), []);
  });
});

describe('checkArgs: type', () => {
  const cases: [ArgConstraint['type'], unknown, boolean][] = [
    ['string', 'a', true],
    ['string', '', true],
    ['string', 1, false],
    ['number', 1, true],
    ['number', 0, true],
    ['number', NaN, true],
    ['number', '1', false],
    ['boolean', false, true],
    ['boolean', 'false', false],
    ['object', {}, true],
    ['object', { a: 1 }, true],
    ['object', [], false],
    ['object', null, false],
    ['array', [], true],
    ['array', [1], true],
    ['array', {}, false],
    ['array', 'ab', false],
  ];

  for (const [type, value, ok] of cases) {
    it(`type:${type} ${ok ? 'accepts' : 'rejects'} ${JSON.stringify(value) ?? String(value)}`, () => {
      const v = check({ type }, { x: value });
      assert.deepEqual(names(v), ok ? [] : ['type']);
    });
  }

  it('a type mismatch short-circuits and returns exactly one violation', () => {
    // Without the short-circuit this value would also trip min, minLength and
    // oneOf; a policy author should see the one root cause, not four symptoms.
    const v = check(
      { type: 'string', oneOf: ['a'], min: 100, minLength: 10, startsWith: ['/tmp'] },
      { x: 5 }
    );
    assert.equal(v.length, 1);
    assert.equal(v[0]!.constraint, 'type');
    assert.match(v[0]!.message, /must be a string, got number/);
  });

  it('describes null and array mismatches by shape, not by typeof', () => {
    assert.match(check({ type: 'object' }, { x: null })[0]!.message, /got null$/);
    assert.match(check({ type: 'object' }, { x: [1] })[0]!.message, /got array$/);
  });
});

describe('checkArgs: oneOf / noneOf', () => {
  it('oneOf accepts a listed primitive and rejects an unlisted one', () => {
    assert.deepEqual(check({ oneOf: ['read', 'list'] }, { x: 'read' }), []);
    assert.deepEqual(names(check({ oneOf: ['read', 'list'] }, { x: 'write' })), ['oneOf']);
  });

  it('oneOf uses strict equality across types', () => {
    assert.deepEqual(names(check({ oneOf: [1] }, { x: '1' })), ['oneOf']);
    assert.deepEqual(names(check({ oneOf: [0] }, { x: false })), ['oneOf']);
    assert.deepEqual(check({ oneOf: [null] }, { x: null }), []);
  });

  it('oneOf compares objects deeply and order-insensitively by key', () => {
    const c: ArgConstraint = { oneOf: [{ a: 1, b: { c: [1, 2] } }] };
    assert.deepEqual(check(c, { x: { b: { c: [1, 2] }, a: 1 } }), [], 'key order must not matter');
    assert.deepEqual(names(check(c, { x: { a: 1, b: { c: [2, 1] } } })), ['oneOf'], 'array order must matter');
    assert.deepEqual(names(check(c, { x: { a: 1 } })), ['oneOf'], 'a missing key must not match');
    assert.deepEqual(
      names(check(c, { x: { a: 1, b: { c: [1, 2] }, extra: true } })),
      ['oneOf'],
      'an extra key must not match'
    );
  });

  it('oneOf compares arrays deeply, including length and nesting', () => {
    const c: ArgConstraint = { oneOf: [[1, [2, 3]]] };
    assert.deepEqual(check(c, { x: [1, [2, 3]] }), []);
    assert.deepEqual(names(check(c, { x: [1, [2, 3], 4] })), ['oneOf']);
    assert.deepEqual(names(check(c, { x: [1, [3, 2]] })), ['oneOf']);
  });

  it('an array does not deep-equal an object with the same indices', () => {
    assert.deepEqual(names(check({ oneOf: [{ 0: 'a' }] }, { x: ['a'] })), ['oneOf']);
    assert.deepEqual(names(check({ oneOf: [['a']] }, { x: { 0: 'a' } })), ['oneOf']);
  });

  it('an empty oneOf rejects everything', () => {
    assert.deepEqual(names(check({ oneOf: [] }, { x: 'anything' })), ['oneOf']);
  });

  it('noneOf rejects a listed value and accepts anything else', () => {
    assert.deepEqual(names(check({ noneOf: ['rm -rf /'] }, { x: 'rm -rf /' })), ['noneOf']);
    assert.deepEqual(check({ noneOf: ['rm -rf /'] }, { x: 'ls' }), []);
  });

  it('noneOf compares objects and arrays deeply', () => {
    const c: ArgConstraint = { noneOf: [{ scope: ['admin'] }] };
    assert.deepEqual(names(check(c, { x: { scope: ['admin'] } })), ['noneOf']);
    assert.deepEqual(check(c, { x: { scope: ['reader'] } }), []);
  });

  it('an empty noneOf rejects nothing', () => {
    assert.deepEqual(check({ noneOf: [] }, { x: 'anything' }), []);
  });

  it('oneOf and noneOf can both fire on the same value', () => {
    assert.deepEqual(names(check({ oneOf: ['a'], noneOf: ['b'] }, { x: 'b' })), ['oneOf', 'noneOf']);
  });
});

describe('checkArgs: matches', () => {
  it('accepts a matching string and rejects a non-matching one', () => {
    assert.deepEqual(check({ matches: '^[a-z]+$' }, { x: 'abc' }), []);
    assert.deepEqual(names(check({ matches: '^[a-z]+$' }, { x: 'abc1' })), ['matches']);
  });

  it('is unanchored unless the author anchors it', () => {
    // Documented behaviour: "anchored by the author, not by us".
    assert.deepEqual(check({ matches: 'abc' }, { x: 'xxabcxx' }), []);
    assert.deepEqual(names(check({ matches: '^abc$' }, { x: 'xxabcxx' })), ['matches']);
  });

  it('an empty pattern matches every string', () => {
    assert.deepEqual(check({ matches: '' }, { x: 'anything' }), []);
  });

  it('reports the pattern in the message', () => {
    assert.match(check({ matches: '^ok$' }, { x: 'no' })[0]!.message, /must match \/\^ok\$\//);
  });

  it('is not stateful across calls (no lastIndex leakage)', () => {
    const c: ArgConstraint = { matches: 'a' };
    for (let i = 0; i < 4; i++) assert.deepEqual(check(c, { x: 'a' }), [], `iteration ${i}`);
  });
});

describe('checkArgs: startsWith', () => {
  it('accepts any listed prefix', () => {
    const c: ArgConstraint = { startsWith: ['/tmp/', '/var/tmp/'] };
    assert.deepEqual(check(c, { x: '/tmp/a' }), []);
    assert.deepEqual(check(c, { x: '/var/tmp/a' }), []);
  });

  it('rejects a path outside every prefix', () => {
    const c: ArgConstraint = { startsWith: ['/tmp/'] };
    assert.deepEqual(names(check(c, { x: '/etc/passwd' })), ['startsWith']);
    assert.deepEqual(names(check(c, { x: 'x/tmp/a' })), ['startsWith'], 'the prefix must be at position 0');
  });

  it('is a raw string prefix test — it does not normalise paths', () => {
    // This is why `excludes: ['..']` exists; documented as a "cheap guard".
    assert.deepEqual(check({ startsWith: ['/tmp/'] }, { x: '/tmp/../etc/passwd' }), []);
  });

  it('an empty startsWith list rejects everything', () => {
    assert.deepEqual(names(check({ startsWith: [] }, { x: '/tmp/a' })), ['startsWith']);
  });

  it('an empty-string prefix accepts everything', () => {
    assert.deepEqual(check({ startsWith: [''] }, { x: '/etc/passwd' }), []);
  });
});

describe('checkArgs: excludes', () => {
  it('rejects a string containing any banned substring', () => {
    const c: ArgConstraint = { excludes: ['..', '~'] };
    assert.deepEqual(names(check(c, { x: '/tmp/../etc' })), ['excludes']);
    assert.deepEqual(names(check(c, { x: '~/.ssh' })), ['excludes']);
    assert.deepEqual(check(c, { x: '/tmp/ok' }), []);
  });

  it('matches anywhere in the string, not just at the start', () => {
    assert.deepEqual(names(check({ excludes: ['secret'] }, { x: 'my secret plan' })), ['excludes']);
  });

  it('reports the first banned substring that hit, in list order', () => {
    const v = check({ excludes: ['~', '..'] }, { x: '~/../x' });
    assert.equal(v.length, 1);
    assert.match(v[0]!.message, /must not contain "~"/);
  });

  it('an empty excludes list rejects nothing', () => {
    assert.deepEqual(check({ excludes: [] }, { x: '../..' }), []);
  });
});

describe('checkArgs: min / max', () => {
  it('min is inclusive', () => {
    assert.deepEqual(check({ min: 10 }, { x: 10 }), []);
    assert.deepEqual(check({ min: 10 }, { x: 11 }), []);
    assert.deepEqual(names(check({ min: 10 }, { x: 9.999 })), ['min']);
  });

  it('max is inclusive', () => {
    assert.deepEqual(check({ max: 10 }, { x: 10 }), []);
    assert.deepEqual(check({ max: 10 }, { x: 9 }), []);
    assert.deepEqual(names(check({ max: 10 }, { x: 10.001 })), ['max']);
  });

  it('handles negative and zero bounds', () => {
    assert.deepEqual(check({ min: -5, max: 0 }, { x: -5 }), []);
    assert.deepEqual(check({ min: -5, max: 0 }, { x: 0 }), []);
    assert.deepEqual(names(check({ min: -5, max: 0 }, { x: 1 })), ['max']);
    assert.deepEqual(names(check({ min: -5, max: 0 }, { x: -6 })), ['min']);
  });

  it('both bounds can fire only one at a time', () => {
    assert.deepEqual(names(check({ min: 1, max: 2 }, { x: 5 })), ['max']);
    assert.deepEqual(names(check({ min: 1, max: 2 }, { x: 0 })), ['min']);
  });
});

describe('checkArgs: minLength / maxLength', () => {
  it('bounds string length inclusively', () => {
    assert.deepEqual(check({ maxLength: 3 }, { x: 'abc' }), []);
    assert.deepEqual(names(check({ maxLength: 3 }, { x: 'abcd' })), ['maxLength']);
    assert.deepEqual(check({ minLength: 3 }, { x: 'abc' }), []);
    assert.deepEqual(names(check({ minLength: 3 }, { x: 'ab' })), ['minLength']);
  });

  it('bounds array length inclusively', () => {
    assert.deepEqual(check({ maxLength: 2 }, { x: [1, 2] }), []);
    assert.deepEqual(names(check({ maxLength: 2 }, { x: [1, 2, 3] })), ['maxLength']);
    assert.deepEqual(check({ minLength: 1 }, { x: [1] }), []);
    assert.deepEqual(names(check({ minLength: 1 }, { x: [] })), ['minLength']);
  });

  it('minLength: 0 accepts the empty string and empty array', () => {
    assert.deepEqual(check({ minLength: 0 }, { x: '' }), []);
    assert.deepEqual(check({ minLength: 0 }, { x: [] }), []);
  });

  it('maxLength: 0 rejects any non-empty value', () => {
    assert.deepEqual(names(check({ maxLength: 0 }, { x: 'a' })), ['maxLength']);
    assert.deepEqual(check({ maxLength: 0 }, { x: '' }), []);
  });

  it('rejects a value that has no length rather than skipping the bound', () => {
    // Skipping the check would fail OPEN: the constraint would be satisfied,
    // the rule would match, and the call would be allowed. A value of the
    // wrong type is a violation, not a reason to stop looking.
    assert.deepEqual(names(check({ maxLength: 0 }, { x: { a: 1, b: 2 } })), ['type']);
    assert.deepEqual(names(check({ maxLength: 0 }, { x: 12345 })), ['type']);
    assert.deepEqual(names(check({ minLength: 5 }, { x: true })), ['type']);
  });

  it('maxLength and minLength can be combined into an exact length', () => {
    assert.deepEqual(check({ minLength: 2, maxLength: 2 }, { x: 'ab' }), []);
    assert.deepEqual(names(check({ minLength: 2, maxLength: 2 }, { x: 'abc' })), ['maxLength']);
    assert.deepEqual(names(check({ minLength: 2, maxLength: 2 }, { x: 'a' })), ['minLength']);
  });

  it('counts UTF-16 code units, as documented by String#length', () => {
    assert.deepEqual(names(check({ maxLength: 1 }, { x: '😀' })), ['maxLength']);
  });
});

describe('checkArgs: urlHosts', () => {
  const exact: ArgConstraint = { urlHosts: ['example.com'] };
  const wildcard: ArgConstraint = { urlHosts: ['.example.com'] };

  it('accepts an exact host', () => {
    assert.deepEqual(check(exact, { x: 'https://example.com/path?q=1' }), []);
  });

  it('an exact entry does NOT cover subdomains', () => {
    assert.deepEqual(names(check(exact, { x: 'https://api.example.com/' })), ['urlHosts']);
  });

  it('a leading-dot entry covers subdomains', () => {
    assert.deepEqual(check(wildcard, { x: 'https://api.example.com/' }), []);
    assert.deepEqual(check(wildcard, { x: 'https://a.b.example.com/' }), []);
  });

  it('a leading-dot entry also covers the bare apex', () => {
    assert.deepEqual(check(wildcard, { x: 'https://example.com/' }), []);
  });

  it('a host that merely ENDS WITH the allowed name is not a subdomain', () => {
    // The classic allowlist bypass: notexample.com must never satisfy
    // ".example.com". The leading dot in the suffix test is what prevents it.
    assert.deepEqual(names(check(wildcard, { x: 'https://notexample.com/' })), ['urlHosts']);
    assert.deepEqual(names(check(exact, { x: 'https://notexample.com/' })), ['urlHosts']);
    assert.deepEqual(names(check(wildcard, { x: 'https://evil-example.com/' })), ['urlHosts']);
  });

  it('the allowed name must be the registrable suffix, not a path or query', () => {
    assert.deepEqual(names(check(exact, { x: 'https://evil.com/example.com' })), ['urlHosts']);
    assert.deepEqual(names(check(exact, { x: 'https://evil.com/?to=example.com' })), ['urlHosts']);
    assert.deepEqual(names(check(exact, { x: 'https://evil.com#example.com' })), ['urlHosts']);
  });

  it('userinfo before an @ does not decide the host', () => {
    // "https://example.com@evil.com/" has hostname evil.com.
    assert.deepEqual(names(check(exact, { x: 'https://example.com@evil.com/' })), ['urlHosts']);
  });

  it('host comparison is case-insensitive in both directions', () => {
    assert.deepEqual(check(exact, { x: 'https://EXAMPLE.COM/' }), []);
    assert.deepEqual(check({ urlHosts: ['EXAMPLE.COM'] }, { x: 'https://example.com/' }), []);
    assert.deepEqual(check({ urlHosts: ['.EXAMPLE.COM'] }, { x: 'https://API.example.com/' }), []);
  });

  it('a port is not part of the hostname', () => {
    assert.deepEqual(check(exact, { x: 'https://example.com:8443/' }), []);
  });

  it('the scheme is not constrained by urlHosts alone', () => {
    // Documented scope: urlHosts checks the host. Restricting the scheme is the
    // job of `matches` / `startsWith`; this test pins that division of labour.
    assert.deepEqual(check(exact, { x: 'ftp://example.com/x' }), []);
    assert.deepEqual(check(exact, { x: 'file://example.com/x' }), []);
  });

  it('a non-URL string is rejected as unparseable', () => {
    const v = check(exact, { x: 'not a url' });
    assert.deepEqual(names(v), ['urlHosts']);
    assert.match(v[0]!.message, /not a parseable URL/);
    assert.deepEqual(names(check(exact, { x: 'example.com/path' })), ['urlHosts'], 'a bare host has no scheme');
    assert.deepEqual(names(check(exact, { x: '' })), ['urlHosts']);
  });

  it('an empty urlHosts list rejects every parseable URL', () => {
    assert.deepEqual(names(check({ urlHosts: [] }, { x: 'https://example.com/' })), ['urlHosts']);
  });

  it('reports the offending host in the message', () => {
    assert.match(check(exact, { x: 'https://evil.com/' })[0]!.message, /host "evil\.com" is not in the allowed set/);
  });

  it('combines with other constraints on the same value', () => {
    const c: ArgConstraint = { type: 'string', urlHosts: ['.example.com'], excludes: ['..'] };
    assert.deepEqual(check(c, { x: 'https://api.example.com/v1' }), []);
    assert.deepEqual(names(check(c, { x: 'https://api.example.com/../x' })), ['excludes']);
  });
});

/* ------------------------------------------------------------------ *
 * FINDINGS. The three tests below assert the behaviour a policy author
 * would need in order to be safe. They FAIL against the current
 * implementation. See the report — do not "fix" them by relaxing the
 * assertion.
 * ------------------------------------------------------------------ */
describe('checkArgs: FINDINGS (currently failing — real gaps in src/policy/constraints.ts)', () => {
  it('BUG: string constraints must not be skipped for a non-string value', () => {
    // src/policy/constraints.ts:57 gates matches/startsWith/excludes/urlHosts on
    // `typeof value === 'string'`. When a policy omits `type: string` (which
    // nothing forces it to declare), a model can hand in an array or a number
    // and the whole scoping constraint evaporates: the rule then MATCHES and
    // the call is allowed. Fail-open on untrusted model output.
    assert.notDeepEqual(
      check({ startsWith: ['/tmp/'] }, { x: ['/etc/passwd'] }),
      [],
      'startsWith silently passed for an array value'
    );
    assert.notDeepEqual(
      check({ urlHosts: ['example.com'] }, { x: 12345 }),
      [],
      'urlHosts silently passed for a number value'
    );
    assert.notDeepEqual(
      check({ excludes: ['..'] }, { x: { path: '/tmp/../etc' } }),
      [],
      'excludes silently passed for an object value'
    );
  });

  it('BUG: numeric bounds must not be skipped for a non-number value', () => {
    // src/policy/constraints.ts:84 — same shape of gap for min/max.
    assert.notDeepEqual(
      check({ max: 100 }, { x: '999999' }),
      [],
      'max silently passed for a numeric string'
    );
  });

  it('BUG: an explicitly-undefined argument must not satisfy a constraint', () => {
    // resolvePath returns `undefined` (not MISSING) for an own key whose value
    // is undefined, so src/policy/constraints.ts:37 does not treat it as absent
    // and every downstream check then skips it. `{ path: undefined }` therefore
    // satisfies a required, scoped string constraint.
    assert.notDeepEqual(
      check({ startsWith: ['/tmp/'] }, { x: undefined }),
      [],
      'an undefined value satisfied a required scoped constraint'
    );
  });
});
