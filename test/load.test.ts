/**
 * Policy parsing and validation.
 *
 * Strictness here IS a security property. A silently-ignored key in a security
 * policy is a widened policy: `startWith` instead of `startsWith` turns a
 * scoped filesystem rule into an unscoped one. Every test that asserts a
 * rejection also asserts that the error names the offending key, because an
 * operator has to be able to find the typo.
 */

import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { PolicyError, loadPolicyFile, parsePolicy, validatePolicy } from '../src/policy/load.js';
import { tempDir } from './helpers.js';

const tmp = tempDir();
after(() => tmp.cleanup());

/** Run `fn`, requiring it to throw a PolicyError, and return it. */
function caught(fn: () => unknown): PolicyError {
  try {
    fn();
  } catch (err) {
    if (!(err instanceof PolicyError)) {
      assert.fail(`expected a PolicyError, got ${(err as Error)?.constructor?.name}: ${String(err)}`);
    }
    return err;
  }
  assert.fail('expected a PolicyError to be thrown, but nothing was');
}

/** Assert that parsing throws a PolicyError whose message mentions each fragment. */
function rejects(raw: string, ...fragments: (string | RegExp)[]): PolicyError {
  const err = caught(() => parsePolicy(raw, 'p'));
  assert.equal(err.name, 'PolicyError');
  for (const fragment of fragments) {
    if (typeof fragment === 'string') {
      assert.ok(
        err.message.includes(fragment),
        `expected message to mention ${JSON.stringify(fragment)}, got: ${err.message}`
      );
    } else {
      assert.match(err.message, fragment);
    }
  }
  return err;
}

const VALID_YAML = `
version: "1"
name: demo
default: deny
budget:
  calls: 10
  tokens: 100000
  usd: 1.5
  seconds: 300
rules:
  - id: fs-read
    description: read the workspace
    tools: ["fs.read", "fs.list"]
    effect: allow
    when:
      path:
        type: string
        startsWith: ["/workspace/"]
        excludes: [".."]
    limit:
      max: 20
      perSeconds: 60
  - id: net
    tools: ["net.*"]
    effect: ask
    when:
      url:
        urlHosts: [".example.com"]
  - id: no-shell
    tools: ["shell.**"]
    effect: deny
`;

describe('parsePolicy: happy path', () => {
  it('parses a complete YAML policy', () => {
    const p = parsePolicy(VALID_YAML, 'demo.yaml');
    assert.equal(p.version, '1');
    assert.equal(p.name, 'demo');
    assert.equal(p.default, 'deny');
    assert.deepEqual(p.budget, { calls: 10, tokens: 100000, usd: 1.5, seconds: 300 });
    assert.deepEqual(p.rules.map((r) => r.id), ['fs-read', 'net', 'no-shell']);
    assert.deepEqual(p.rules[0]!.tools, ['fs.read', 'fs.list']);
    assert.deepEqual(p.rules[0]!.when!['path'], {
      type: 'string',
      startsWith: ['/workspace/'],
      excludes: ['..'],
    });
    assert.deepEqual(p.rules[0]!.limit, { max: 20, perSeconds: 60 });
    assert.equal(p.rules[2]!.effect, 'deny');
  });

  it('parses the equivalent JSON to a deep-equal policy', () => {
    const asJson = JSON.stringify({
      version: '1',
      name: 'demo',
      default: 'deny',
      budget: { calls: 10, tokens: 100000, usd: 1.5, seconds: 300 },
      rules: [
        {
          id: 'fs-read',
          description: 'read the workspace',
          tools: ['fs.read', 'fs.list'],
          effect: 'allow',
          when: { path: { type: 'string', startsWith: ['/workspace/'], excludes: ['..'] } },
          limit: { max: 20, perSeconds: 60 },
        },
        { id: 'net', tools: ['net.*'], effect: 'ask', when: { url: { urlHosts: ['.example.com'] } } },
        { id: 'no-shell', tools: ['shell.**'], effect: 'deny' },
      ],
    });
    assert.deepEqual(parsePolicy(asJson, 'demo.json'), parsePolicy(VALID_YAML, 'demo.yaml'));
  });

  it('accepts a minimal policy: version plus an empty rules array', () => {
    const p = parsePolicy('version: "1"\nrules: []\n');
    assert.deepEqual(p, { version: '1', rules: [] });
    assert.equal(p.default, undefined, 'no default key means the engine\'s deny-by-default applies');
  });

  it('omits optional keys rather than setting them to undefined', () => {
    const p = parsePolicy('version: "1"\nrules: []\n');
    assert.deepEqual(Object.keys(p).sort(), ['rules', 'version']);
  });

  it('accepts every effect for `default` and for a rule', () => {
    for (const effect of ['allow', 'deny', 'ask']) {
      const p = parsePolicy(`version: "1"\ndefault: ${effect}\nrules:\n  - id: r\n    tools: ["*"]\n    effect: ${effect}\n`);
      assert.equal(p.default, effect);
      assert.equal(p.rules[0]!.effect, effect);
    }
  });

  it('accepts a limit without perSeconds and max: 0', () => {
    const p = parsePolicy('version: "1"\nrules:\n  - id: r\n    tools: ["*"]\n    effect: allow\n    limit: { max: 0 }\n');
    assert.deepEqual(p.rules[0]!.limit, { max: 0 });
  });

  it('validatePolicy accepts an already-parsed object', () => {
    assert.deepEqual(validatePolicy({ version: '1', rules: [] }), { version: '1', rules: [] });
  });
});

describe('parsePolicy: document-level rejections', () => {
  it('rejects malformed YAML as a PolicyError, not a raw YAMLParseError', () => {
    const err = rejects('version: "1"\nrules:\n  - id: [unclosed\n', 'invalid YAML/JSON');
    assert.equal(err.name, 'PolicyError');
    assert.equal(err.constructor.name, 'PolicyError');
    assert.equal(err.path, 'p');
  });

  it('rejects YAML that is not a mapping', () => {
    rejects('- a\n- b\n', 'expected an object');
    rejects('just a string\n', 'expected an object');
    rejects('', 'expected an object');
    rejects('null\n', 'expected an object');
  });

  it('rejects a missing version', () => {
    rejects('rules: []\n', 'unsupported policy version', 'undefined');
  });

  it('rejects a numeric version — "1" is a string', () => {
    rejects('version: 1\nrules: []\n', 'unsupported policy version 1');
  });

  it('rejects an unknown future version', () => {
    rejects('version: "2"\nrules: []\n', 'unsupported policy version "2"');
  });

  it('rejects an unknown top-level key and names it', () => {
    const err = rejects('version: "1"\nrules: []\ndefualt: allow\n', '"defualt"');
    assert.match(err.message, /unknown field\(s\)/);
    assert.match(err.message, /allowed: /, 'the message lists what was allowed');
  });

  it('names every unknown top-level key at once', () => {
    rejects('version: "1"\nrules: []\nfoo: 1\nbar: 2\n', '"foo"', '"bar"');
  });

  it('rejects a bad default effect', () => {
    rejects('version: "1"\ndefault: maybe\nrules: []\n', '"default" must be one of allow, deny, ask');
  });

  it('rejects a non-string name', () => {
    rejects('version: "1"\nname: 42\nrules: []\n', '"name" must be a string');
  });

  it('rejects a missing or non-array rules key', () => {
    rejects('version: "1"\n', '"rules" must be an array');
    rejects('version: "1"\nrules: {}\n', '"rules" must be an array');
  });

  it('rejects duplicate rule ids and points at the second one', () => {
    const err = rejects(
      'version: "1"\nrules:\n  - id: dup\n    tools: ["a"]\n    effect: allow\n  - id: dup\n    tools: ["b"]\n    effect: deny\n',
      'duplicate rule id "dup"'
    );
    assert.equal(err.path, 'p.rules[1]');
  });
});

describe('parsePolicy: budget rejections', () => {
  const wrap = (budget: string) => `version: "1"\nrules: []\nbudget:\n${budget}`;

  it('rejects an unknown budget key', () => {
    const err = rejects(wrap('  minutes: 5\n'), '"minutes"');
    assert.equal(err.path, 'p.budget');
  });

  it('rejects a non-object budget', () => {
    rejects('version: "1"\nrules: []\nbudget: 5\n', 'expected an object');
  });

  for (const key of ['calls', 'tokens', 'usd', 'seconds']) {
    it(`rejects a zero, negative, non-finite or non-numeric ${key}`, () => {
      rejects(wrap(`  ${key}: 0\n`), `"${key}" must be a positive number`);
      rejects(wrap(`  ${key}: -1\n`), `"${key}" must be a positive number`);
      rejects(wrap(`  ${key}: .inf\n`), `"${key}" must be a positive number`);
      rejects(wrap(`  ${key}: "10"\n`), `"${key}" must be a positive number`);
      rejects(wrap(`  ${key}: null\n`), `"${key}" must be a positive number`);
    });
  }

  it('accepts a fractional budget', () => {
    assert.deepEqual(parsePolicy(wrap('  usd: 0.01\n')).budget, { usd: 0.01 });
  });
});

describe('parsePolicy: rule rejections', () => {
  const wrap = (body: string) => `version: "1"\nrules:\n  - ${body.trim().split('\n').join('\n    ')}\n`;

  it('rejects a non-object rule', () => {
    rejects('version: "1"\nrules: ["nope"]\n', 'expected an object');
  });

  it('rejects an unknown rule key and names it', () => {
    const err = rejects(wrap('id: r\ntools: ["a"]\neffect: allow\nwhne: {}'), '"whne"');
    assert.equal(err.path, 'p.rules[0]');
  });

  it('rejects a missing, empty or non-string id', () => {
    rejects(wrap('tools: ["a"]\neffect: allow'), '"id" must be a non-empty string');
    rejects(wrap('id: ""\ntools: ["a"]\neffect: allow'), '"id" must be a non-empty string');
    rejects(wrap('id: 7\ntools: ["a"]\neffect: allow'), '"id" must be a non-empty string');
  });

  it('rejects a non-string description', () => {
    rejects(wrap('id: r\ndescription: 7\ntools: ["a"]\neffect: allow'), '"description" must be a string');
  });

  it('rejects missing, empty, or non-array tools', () => {
    rejects(wrap('id: r\neffect: allow'), '"tools" must be a non-empty array');
    rejects(wrap('id: r\ntools: []\neffect: allow'), '"tools" must be a non-empty array');
    rejects(wrap('id: r\ntools: "fs.read"\neffect: allow'), '"tools" must be a non-empty array');
  });

  it('rejects a non-string or empty entry inside tools', () => {
    rejects(wrap('id: r\ntools: ["a", 7]\neffect: allow'), 'every entry in "tools" must be a non-empty string');
    rejects(wrap('id: r\ntools: ["a", ""]\neffect: allow'), 'every entry in "tools" must be a non-empty string');
  });

  it('rejects a missing or bad effect', () => {
    rejects(wrap('id: r\ntools: ["a"]'), '"effect" must be one of allow, deny, ask');
    rejects(wrap('id: r\ntools: ["a"]\neffect: permit'), '"effect" must be one of allow, deny, ask');
    rejects(wrap('id: r\ntools: ["a"]\neffect: Allow'), '"effect" must be one of allow, deny, ask');
  });

  it('rejects an unknown limit key', () => {
    const err = rejects(wrap('id: r\ntools: ["a"]\neffect: allow\nlimit: { max: 1, per_seconds: 60 }'), '"per_seconds"');
    assert.equal(err.path, 'p.rules[0].limit');
  });

  it('rejects a bad limit.max', () => {
    rejects(wrap('id: r\ntools: ["a"]\neffect: allow\nlimit: { max: -1 }'), '"max" must be a non-negative integer');
    rejects(wrap('id: r\ntools: ["a"]\neffect: allow\nlimit: { max: 1.5 }'), '"max" must be a non-negative integer');
    rejects(wrap('id: r\ntools: ["a"]\neffect: allow\nlimit: {}'), '"max" must be a non-negative integer');
  });

  it('rejects a non-positive perSeconds', () => {
    rejects(wrap('id: r\ntools: ["a"]\neffect: allow\nlimit: { max: 1, perSeconds: 0 }'), '"perSeconds" must be a positive number');
    rejects(wrap('id: r\ntools: ["a"]\neffect: allow\nlimit: { max: 1, perSeconds: "60" }'), '"perSeconds" must be a positive number');
  });

  it('rejects a non-object when block', () => {
    rejects(wrap('id: r\ntools: ["a"]\neffect: allow\nwhen: "path"'), 'expected an object');
  });
});

describe('parsePolicy: constraint rejections', () => {
  const wrap = (constraint: string) =>
    `version: "1"\nrules:\n  - id: r\n    tools: ["a"]\n    effect: allow\n    when:\n      path: ${constraint}\n`;

  it('rejects an unknown constraint key, naming it and its path', () => {
    // The motivating example from the module header: a typo'd startsWith would
    // otherwise be dropped and the rule would allow every path.
    const err = rejects(wrap('{ startWith: ["/tmp/"] }'), '"startWith"');
    assert.equal(err.path, 'p.rules[0].when["path"]');
    assert.match(err.message, /allowed: .*startsWith/);
  });

  it('rejects a non-object constraint', () => {
    rejects(wrap('"/tmp/"'), 'expected an object');
  });

  it('rejects an invalid regex in matches', () => {
    const err = rejects(wrap('{ matches: "([a-" }'), '"matches" is not a valid regexp');
    assert.equal(err.path, 'p.rules[0].when["path"]');
  });

  it('rejects a non-string matches', () => {
    rejects(wrap('{ matches: 7 }'), '"matches" must be a string');
  });

  it('accepts a valid regex, including one with escapes', () => {
    const p = parsePolicy(wrap('{ matches: "^/tmp/[a-z0-9_.-]+$" }'));
    assert.equal(p.rules[0]!.when!['path']!.matches, '^/tmp/[a-z0-9_.-]+$');
  });

  for (const key of ['startsWith', 'excludes', 'urlHosts']) {
    it(`rejects a non-array or non-string-element ${key}`, () => {
      rejects(wrap(`{ ${key}: "/tmp/" }`), `"${key}" must be an array of strings`);
      rejects(wrap(`{ ${key}: ["/tmp/", 7] }`), `"${key}" must be an array of strings`);
    });
  }

  for (const key of ['oneOf', 'noneOf']) {
    it(`rejects a non-array ${key}`, () => {
      rejects(wrap(`{ ${key}: "read" }`), `"${key}" must be an array`);
    });
  }

  for (const key of ['min', 'max', 'maxLength', 'minLength']) {
    it(`rejects a non-numeric ${key}`, () => {
      rejects(wrap(`{ ${key}: "10" }`), `"${key}" must be a number`);
    });
  }

  it('rejects a non-boolean optional', () => {
    rejects(wrap('{ optional: "yes" }'), '"optional" must be a boolean');
  });

  it('rejects an unknown type', () => {
    rejects(wrap('{ type: integer }'), '"type" must be one of string, number, boolean, object, array');
  });

  it('accepts every valid type', () => {
    for (const type of ['string', 'number', 'boolean', 'object', 'array']) {
      assert.equal(parsePolicy(wrap(`{ type: ${type} }`)).rules[0]!.when!['path']!.type, type);
    }
  });

  it('reports the constraint path for a deeply nested argument', () => {
    const err = rejects(
      `version: "1"\nrules:\n  - id: r\n    tools: ["a"]\n    effect: allow\n    when:\n      "body.to.0": { nope: 1 }\n`,
      '"nope"'
    );
    assert.equal(err.path, 'p.rules[0].when["body.to.0"]');
  });
});

describe('loadPolicyFile', () => {
  it('loads a policy from disk', () => {
    const file = join(tmp.path, 'policy.yaml');
    writeFileSync(file, VALID_YAML, 'utf8');
    assert.deepEqual(loadPolicyFile(file), parsePolicy(VALID_YAML));
  });

  it('loads a .json policy from disk', () => {
    const file = join(tmp.path, 'policy.json');
    writeFileSync(file, '{"version":"1","rules":[]}', 'utf8');
    assert.deepEqual(loadPolicyFile(file), { version: '1', rules: [] });
  });

  it('reports a missing file as a PolicyError carrying the path', () => {
    const file = join(tmp.path, 'does-not-exist.yaml');
    const err = caught(() => loadPolicyFile(file));
    assert.equal(err.path, file);
    assert.match(err.message, /cannot read policy file/);
  });

  it('decorates a validation error with the file path', () => {
    const file = join(tmp.path, 'bad.yaml');
    writeFileSync(file, 'version: "1"\nrules: []\nnope: 1\n', 'utf8');
    const err = caught(() => loadPolicyFile(file));
    assert.equal(err.path, file);
    assert.ok(err.message.startsWith(file));
  });
});

describe('matches: catastrophic backtracking', () => {
  const load = (pattern: string) =>
    parsePolicy(
      `version: "1"\ndefault: deny\nrules:\n  - id: r\n    tools: ["t"]\n    effect: allow\n` +
        `    when:\n      v:\n        matches: ${JSON.stringify(pattern)}\n`
    );

  it('rejects the nested-quantifier family at load time', () => {
    // Argument values are model output, and evaluation is synchronous, so one
    // crafted value against a pattern like this freezes the whole enforcement
    // point. The first of these hung both implementations for over ten seconds
    // on a 44-character input before this check existed.
    for (const pattern of [
      '^(([a-zA-Z0-9]+)+@)+example\\.com$',
      '(a+)+$',
      '(a*)*b',
      '(\\w+\\s?)*$',
      '((ab)+)+',
      '(x{2,})+',
    ]) {
      assert.throws(() => load(pattern), /backtrack catastrophically/, pattern);
    }
  });

  it('accepts the patterns a policy author actually writes', () => {
    for (const pattern of [
      '^[A-Za-z0-9._%+-]+@(support\\.)?example\\.com$', // the support example's own rule
      '^/srv/[a-z]+/[a-z]+\\.txt$',
      '^(abc)+$', // quantified group, nothing quantified inside it
      '(a|b){2,5}',
      '^(foo|bar)*$',
      '(\\d+)\\.(\\d+)',
    ]) {
      assert.doesNotThrow(() => load(pattern), pattern);
    }
  });

  it('does not mistake a quantifier inside a character class for syntax', () => {
    assert.doesNotThrow(() => load('[+*]+'));
  });

  it('does not mistake an escaped parenthesis for a group', () => {
    assert.doesNotThrow(() => load('\\(a+\\)+'));
  });

  it('ignores quantifiers that cannot blow up', () => {
    // `?` and {0,1} repeat at most once, so nesting them is harmless.
    assert.doesNotThrow(() => load('(a?)+'));
    assert.doesNotThrow(() => load('(a{0,1})+'));
  });

  it('names the offending quantifier so the author can find it', () => {
    assert.throws(() => load('(a+)+'), /nested quantifier: a "\+"/);
  });
});
