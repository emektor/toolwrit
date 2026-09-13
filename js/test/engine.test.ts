/**
 * The decision function.
 *
 * `evaluate` is the whole product in one pure function. These tests walk the
 * documented precedence ladder end to end:
 *
 *   budget > exhausted rate limit > deny > ask > allow > policy default (deny)
 *
 * and pin the boundary conditions of each rung, because "deterministic" is a
 * claim that only means something if the boundaries are nailed down.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate } from '../src/policy/engine.js';
import type { Decision, EvalContext } from '../src/types.js';
import { at, call, ctx, policy, rule, shape, snapshot, usage } from './helpers.js';

describe('evaluate: matching and defaults', () => {
  it('denies by default when there are no rules at all', () => {
    const d = evaluate(call('fs.read'), ctx());
    assert.deepEqual(shape(d), { effect: 'deny', rule: null, constraints: ['default'] });
    assert.equal(d.violations[0]!.rule, 'policy');
    assert.match(d.reason, /no rule allows tool "fs\.read"/);
  });

  it('denies by default when no rule matches the tool name', () => {
    const c = ctx({ policy: policy({ rules: [rule({ id: 'r', tools: ['net.*'], effect: 'allow' })] }) });
    assert.equal(evaluate(call('fs.read'), c).effect, 'deny');
  });

  it('honours an explicit `default: allow`', () => {
    const c = ctx({ policy: policy({ default: 'allow' }) });
    const d = evaluate(call('anything'), c);
    assert.deepEqual(shape(d), { effect: 'allow', rule: null, constraints: [] });
    assert.match(d.reason, /policy default is allow/);
  });

  it('honours an explicit `default: ask`', () => {
    const c = ctx({ policy: policy({ default: 'ask' }) });
    const d = evaluate(call('anything'), c);
    assert.equal(d.effect, 'ask');
    assert.equal(d.rule, null);
    assert.deepEqual(d.violations.map((v) => v.constraint), ['default']);
  });

  it('allows via a matching rule and names it', () => {
    const c = ctx({ policy: policy({ rules: [rule({ id: 'fs-read', tools: ['fs.read'] })] }) });
    const d = evaluate(call('fs.read'), c);
    assert.deepEqual(shape(d), { effect: 'allow', rule: 'fs-read', constraints: [] });
    assert.match(d.reason, /allowed by rule "fs-read"/);
  });

  it('matches on globs, using the same semantics as matchesGlob', () => {
    const c = ctx({ policy: policy({ rules: [rule({ id: 'fs', tools: ['fs.*'] })] }) });
    assert.equal(evaluate(call('fs.read'), c).effect, 'allow');
    assert.equal(evaluate(call('fs.read.raw'), c).effect, 'deny');
  });

  it('a rule with a `when` that holds matches', () => {
    const c = ctx({
      policy: policy({
        rules: [rule({ id: 'scoped', tools: ['fs.read'], when: { path: { startsWith: ['/tmp/'] } } })],
      }),
    });
    assert.equal(evaluate(call('fs.read', { path: '/tmp/a' }), c).effect, 'allow');
  });
});

describe('evaluate: precedence among matching rules', () => {
  const rules = [
    rule({ id: 'allow-all', tools: ['**'], effect: 'allow' }),
    rule({ id: 'ask-fs', tools: ['fs.*'], effect: 'ask' }),
    rule({ id: 'deny-secrets', tools: ['fs.read'], effect: 'deny', description: 'no secrets' }),
  ];

  it('deny beats ask and allow, regardless of declaration order', () => {
    for (const order of [rules, [...rules].reverse()]) {
      const d = evaluate(call('fs.read'), ctx({ policy: policy({ rules: order }) }));
      assert.deepEqual(shape(d), { effect: 'deny', rule: 'deny-secrets', constraints: ['rule'] });
      assert.equal(d.reason, 'no secrets');
    }
  });

  it('ask beats allow', () => {
    const d = evaluate(call('fs.write'), ctx({ policy: policy({ rules }) }));
    assert.deepEqual(shape(d), { effect: 'ask', rule: 'ask-fs', constraints: [] });
  });

  it('allow wins when nothing stronger matches', () => {
    const d = evaluate(call('net.get'), ctx({ policy: policy({ rules }) }));
    assert.deepEqual(shape(d), { effect: 'allow', rule: 'allow-all', constraints: [] });
  });

  it('picks the first rule of the winning effect when several tie', () => {
    const c = ctx({
      policy: policy({
        rules: [
          rule({ id: 'a1', tools: ['t'], effect: 'allow' }),
          rule({ id: 'a2', tools: ['t'], effect: 'allow' }),
        ],
      }),
    });
    assert.equal(evaluate(call('t'), c).rule, 'a1');
  });

  it('a deny rule whose `when` fails does not deny', () => {
    const c = ctx({
      policy: policy({
        rules: [
          rule({ id: 'deny-etc', tools: ['fs.read'], effect: 'deny', when: { path: { startsWith: ['/etc/'] } } }),
          rule({ id: 'allow-tmp', tools: ['fs.read'], effect: 'allow', when: { path: { startsWith: ['/tmp/'] } } }),
        ],
      }),
    });
    assert.equal(evaluate(call('fs.read', { path: '/tmp/ok' }), c).rule, 'allow-tmp');
    assert.equal(evaluate(call('fs.read', { path: '/etc/passwd' }), c).rule, 'deny-etc');
  });

  it('uses the rule description as the denial reason, falling back to a generated one', () => {
    const described = evaluate(
      call('t'),
      ctx({ policy: policy({ rules: [rule({ id: 'd', tools: ['t'], effect: 'deny', description: 'because' })] }) })
    );
    assert.equal(described.reason, 'because');
    assert.equal(described.violations[0]!.message, 'because');

    const bare = evaluate(
      call('t'),
      ctx({ policy: policy({ rules: [rule({ id: 'd', tools: ['t'], effect: 'deny' })] }) })
    );
    assert.equal(bare.reason, 'denied by rule "d"');
    assert.match(bare.violations[0]!.message, /tool "t" is denied by rule "d"/);
  });
});

describe('evaluate: near-miss reporting', () => {
  const c = ctx({
    policy: policy({
      rules: [
        rule({
          id: 'allow-tmp',
          tools: ['fs.write'],
          effect: 'allow',
          when: { path: { type: 'string', startsWith: ['/tmp/'] } },
        }),
      ],
    }),
  });

  it('an allow rule whose `when` fails falls through to the default deny', () => {
    const d = evaluate(call('fs.write', { path: '/etc/passwd' }), c);
    assert.equal(d.effect, 'deny');
    assert.equal(d.rule, null, 'the near-miss rule did not decide, so `rule` stays null');
  });

  it('surfaces the near-miss violations instead of a bare "not in the policy"', () => {
    const d = evaluate(call('fs.write', { path: '/etc/passwd' }), c);
    assert.deepEqual(d.violations.map((v) => v.constraint), ['startsWith']);
    assert.equal(d.violations[0]!.rule, 'allow-tmp');
    assert.equal(d.violations[0]!.path, 'path');
    assert.match(d.reason, /no rule allows "fs\.write" with these arguments/);
  });

  it('falls back to the generic message when no rule wanted the tool at all', () => {
    const d = evaluate(call('net.get', { path: '/etc/passwd' }), c);
    assert.deepEqual(d.violations.map((v) => v.constraint), ['default']);
    assert.match(d.reason, /no rule allows tool "net\.get"/);
  });

  it('collects near-misses from several rules', () => {
    const many = ctx({
      policy: policy({
        rules: [
          rule({ id: 'r1', tools: ['t'], effect: 'allow', when: { a: { type: 'string' } } }),
          rule({ id: 'r2', tools: ['t'], effect: 'ask', when: { b: { type: 'string' } } }),
        ],
      }),
    });
    const d = evaluate(call('t', {}), many);
    assert.deepEqual(d.violations.map((v) => `${v.rule}:${v.constraint}`), ['r1:required', 'r2:required']);
  });

  it('does not leak a deny rule\'s constraint failures as near-misses', () => {
    // A deny rule that did not fire is not a near-miss: reporting it would tell
    // the agent exactly which argument to change to stay out of the deny rule.
    const withDeny = ctx({
      policy: policy({
        rules: [rule({ id: 'deny-etc', tools: ['t'], effect: 'deny', when: { p: { startsWith: ['/etc/'] } } })],
      }),
    });
    const d = evaluate(call('t', { p: '/tmp/x' }), withDeny);
    assert.deepEqual(d.violations.map((v) => v.constraint), ['default']);
  });
});

describe('evaluate: budget', () => {
  const allowAll = policy({ rules: [rule({ id: 'yes', tools: ['**'], effect: 'allow' })] });

  function withBudget(budget: NonNullable<ReturnType<typeof policy>['budget']>, u: Partial<ReturnType<typeof usage>>): EvalContext {
    return ctx({ policy: { ...allowAll, budget }, usage: usage(u) });
  }

  it('no budget block means no budget denial', () => {
    const d = evaluate(call('t'), ctx({ policy: allowAll, usage: usage({ calls: 1e9, tokens: 1e9, usd: 1e9 }) }));
    assert.equal(d.effect, 'allow');
  });

  it('denies on calls at the limit (>= not >)', () => {
    assert.equal(evaluate(call('t'), withBudget({ calls: 3 }, { calls: 2 })).effect, 'allow');
    const d = evaluate(call('t'), withBudget({ calls: 3 }, { calls: 3 }));
    assert.deepEqual(shape(d), { effect: 'deny', rule: null, constraints: ['calls'] });
    assert.equal(d.violations[0]!.rule, 'budget');
    assert.match(d.reason, /call budget exhausted: 3\/3 calls used/);
    assert.equal(evaluate(call('t'), withBudget({ calls: 3 }, { calls: 4 })).effect, 'deny');
  });

  it('denies on tokens at the limit', () => {
    assert.equal(evaluate(call('t'), withBudget({ tokens: 1000 }, { tokens: 999 })).effect, 'allow');
    const d = evaluate(call('t'), withBudget({ tokens: 1000 }, { tokens: 1000 }));
    assert.deepEqual(shape(d), { effect: 'deny', rule: null, constraints: ['tokens'] });
    assert.match(d.reason, /token budget exhausted: 1000\/1000/);
  });

  it('denies on usd at the limit', () => {
    assert.equal(evaluate(call('t'), withBudget({ usd: 1 }, { usd: 0.9999 })).effect, 'allow');
    const d = evaluate(call('t'), withBudget({ usd: 1 }, { usd: 1 }));
    assert.deepEqual(shape(d), { effect: 'deny', rule: null, constraints: ['usd'] });
    assert.match(d.reason, /spend budget exhausted: \$1\.0000\/\$1\.0000/);
  });

  it('denies on elapsed seconds at the limit', () => {
    const b = { seconds: 60 };
    assert.equal(
      evaluate(call('t', {}, at(59.999)), withBudget(b, { startedAt: at(0) })).effect,
      'allow'
    );
    const d = evaluate(call('t', {}, at(60)), withBudget(b, { startedAt: at(0) }));
    assert.deepEqual(shape(d), { effect: 'deny', rule: null, constraints: ['seconds'] });
    assert.match(d.reason, /time budget exhausted: 60\.0s\/60s elapsed/);
  });

  it('the seconds budget is a no-op while usage.startedAt is null', () => {
    // Nothing has been metered yet, so the run has not started; a huge `at` must
    // not retroactively exhaust the clock.
    const d = evaluate(call('t', {}, at(1e6)), withBudget({ seconds: 1 }, { startedAt: null }));
    assert.equal(d.effect, 'allow');
  });

  it('a call before startedAt yields negative elapsed and does not deny', () => {
    const d = evaluate(call('t', {}, at(-10)), withBudget({ seconds: 1 }, { startedAt: at(0) }));
    assert.equal(d.effect, 'allow');
  });

  it('each limit is checked independently', () => {
    assert.equal(evaluate(call('t'), withBudget({ calls: 5, tokens: 5, usd: 5 }, { tokens: 5 })).effect, 'deny');
    assert.equal(evaluate(call('t'), withBudget({ calls: 5, tokens: 5, usd: 5 }, { usd: 5 })).effect, 'deny');
    assert.equal(evaluate(call('t'), withBudget({ calls: 5, tokens: 5, usd: 5 }, { calls: 5 })).effect, 'deny');
  });

  it('reports limits in a fixed order when several are exhausted', () => {
    const d = evaluate(call('t'), withBudget({ calls: 1, tokens: 1, usd: 1 }, { calls: 9, tokens: 9, usd: 9 }));
    assert.equal(d.violations[0]!.constraint, 'calls', 'calls is checked first, deterministically');
    assert.equal(d.violations.length, 1);
  });

  it('an exhausted budget denies even when an allow rule matches cleanly', () => {
    const d = evaluate(call('t'), withBudget({ calls: 1 }, { calls: 1 }));
    assert.equal(d.effect, 'deny');
    assert.equal(d.rule, null, 'budget denials are engine-level, not rule-level');
  });

  it('an exhausted budget beats a rate limit that would also have denied', () => {
    const c: EvalContext = {
      policy: {
        ...policy({ rules: [rule({ id: 'lim', tools: ['t'], effect: 'allow', limit: { max: 1 } })] }),
        budget: { calls: 1 },
      },
      usage: usage({ calls: 1 }),
      history: [{ tool: 't', rule: 'lim', at: at(0) }],
    };
    assert.equal(evaluate(call('t', {}, at(1)), c).violations[0]!.constraint, 'calls');
  });
});

describe('evaluate: rate limits', () => {
  function limited(max: number, perSeconds?: number, effect: 'allow' | 'deny' | 'ask' = 'allow') {
    return policy({
      rules: [
        rule({
          id: 'lim',
          tools: ['t'],
          effect,
          limit: perSeconds === undefined ? { max } : { max, perSeconds },
        }),
      ],
    });
  }

  it('allows while under the per-run limit and denies at it', () => {
    const p = limited(2);
    const history = [
      { tool: 't', rule: 'lim', at: at(0) },
      { tool: 't', rule: 'lim', at: at(1) },
    ];
    assert.equal(evaluate(call('t', {}, at(2)), ctx({ policy: p, history: history.slice(0, 1) })).effect, 'allow');

    const d = evaluate(call('t', {}, at(2)), ctx({ policy: p, history }));
    assert.deepEqual(shape(d), { effect: 'deny', rule: 'lim', constraints: ['limit'] });
    assert.match(d.reason, /rate limit exhausted for rule "lim"/);
    assert.match(d.violations[0]!.message, /allows 2 call\(s\) per this run; 2 already used/);
  });

  it('a per-run limit ignores how long ago the calls happened', () => {
    const history = [{ tool: 't', rule: 'lim', at: at(-1e6) }];
    assert.equal(evaluate(call('t', {}, at(0)), ctx({ policy: limited(1), history })).effect, 'deny');
  });

  it('`max: 0` denies the very first call', () => {
    const d = evaluate(call('t', {}, at(0)), ctx({ policy: limited(0), history: [] }));
    assert.deepEqual(shape(d), { effect: 'deny', rule: 'lim', constraints: ['limit'] });
  });

  it('only counts history attributed to the same rule', () => {
    const history = [
      { tool: 't', rule: 'other', at: at(0) },
      { tool: 't', rule: null, at: at(0) },
    ];
    assert.equal(evaluate(call('t', {}, at(1)), ctx({ policy: limited(1), history })).effect, 'allow');
  });

  it('a sliding window excludes entries older than the window', () => {
    const p = limited(1, 60);
    const inside = [{ tool: 't', rule: 'lim', at: at(0) }];
    assert.equal(evaluate(call('t', {}, at(59)), ctx({ policy: p, history: inside })).effect, 'deny');
    assert.equal(evaluate(call('t', {}, at(61)), ctx({ policy: p, history: inside })).effect, 'allow');
  });

  it('an entry exactly at the window edge has expired (strict `>` on the floor)', () => {
    // floor = now - perSeconds*1000; an entry with at === floor is NOT counted.
    const p = limited(1, 60);
    const edge = [{ tool: 't', rule: 'lim', at: at(0) }];
    assert.equal(evaluate(call('t', {}, at(60)), ctx({ policy: p, history: edge })).effect, 'allow');
    assert.equal(
      evaluate(call('t', {}, at(59.999)), ctx({ policy: p, history: edge })).effect,
      'deny',
      'one millisecond inside the window still counts'
    );
  });

  it('counts several entries inside the window and names the window in the message', () => {
    const history = [at(0), at(10), at(20)].map((t) => ({ tool: 't', rule: 'lim', at: t }));
    const d = evaluate(call('t', {}, at(25)), ctx({ policy: limited(3, 60), history }));
    assert.equal(d.effect, 'deny');
    assert.match(d.violations[0]!.message, /allows 3 call\(s\) per 60s; 3 already used/);
  });

  it('an exhausted limit denies a rule whose effect is `ask`', () => {
    const history = [{ tool: 't', rule: 'lim', at: at(0) }];
    const d = evaluate(call('t', {}, at(1)), ctx({ policy: limited(1, 60, 'ask'), history }));
    assert.deepEqual(shape(d), { effect: 'deny', rule: 'lim', constraints: ['limit'] });
  });

  it('an exhausted limit on a deny rule still denies, attributed to the limit', () => {
    const history = [{ tool: 't', rule: 'lim', at: at(0) }];
    const d = evaluate(call('t', {}, at(1)), ctx({ policy: limited(1, 60, 'deny'), history }));
    assert.deepEqual(shape(d), { effect: 'deny', rule: 'lim', constraints: ['limit'] });
  });

  it('a rate limit beats a deny rule from a different clause', () => {
    const p = policy({
      rules: [
        rule({ id: 'lim', tools: ['t'], effect: 'allow', limit: { max: 1 } }),
        rule({ id: 'nope', tools: ['t'], effect: 'deny' }),
      ],
    });
    const history = [{ tool: 't', rule: 'lim', at: at(0) }];
    const d = evaluate(call('t', {}, at(1)), ctx({ policy: p, history }));
    assert.equal(d.rule, 'lim', 'the rate limit is checked before the deny ladder');
    assert.equal(d.violations[0]!.constraint, 'limit');
  });

  it('a rate limit on a rule that did not match is ignored', () => {
    const p = policy({
      rules: [
        rule({ id: 'lim', tools: ['t'], effect: 'allow', when: { ok: { type: 'boolean' } }, limit: { max: 0 } }),
        rule({ id: 'fallback', tools: ['t'], effect: 'allow' }),
      ],
    });
    // `ok` is missing, so `lim` never matches and its max:0 must not fire.
    assert.equal(evaluate(call('t', {}, at(0)), ctx({ policy: p })).rule, 'fallback');
  });
});

describe('evaluate: purity', () => {
  const c: EvalContext = {
    policy: policy({
      budget: { calls: 10, tokens: 100, usd: 1, seconds: 60 },
      rules: [
        rule({ id: 'a', tools: ['fs.*'], effect: 'allow', when: { path: { startsWith: ['/tmp/'] } }, limit: { max: 5, perSeconds: 30 } }),
        rule({ id: 'd', tools: ['fs.delete'], effect: 'deny' }),
        rule({ id: 'k', tools: ['net.*'], effect: 'ask' }),
      ],
    }),
    usage: usage({ calls: 2, tokens: 20, usd: 0.1, startedAt: at(0) }),
    history: [{ tool: 'fs.read', rule: 'a', at: at(1) }],
  };

  const calls = [
    call('fs.read', { path: '/tmp/a' }, at(5)),
    call('fs.read', { path: '/etc/a' }, at(5)),
    call('fs.delete', { path: '/tmp/a' }, at(5)),
    call('net.get', {}, at(5)),
    call('unknown.tool', {}, at(5)),
  ];

  it('produces deep-equal decisions on repeated evaluation', () => {
    for (const k of calls) {
      const first: Decision = evaluate(k, c);
      const second: Decision = evaluate(k, c);
      assert.deepEqual(second, first, `unstable decision for ${k.tool}`);
      assert.notEqual(second, first, 'each call must return a fresh object');
    }
  });

  it('does not mutate the context, the policy, the usage, the history or the call', () => {
    const before = snapshot({ policy: c.policy, usage: c.usage, history: c.history });
    const callsBefore = snapshot(calls);
    for (const k of calls) evaluate(k, c);
    assert.deepEqual(snapshot({ policy: c.policy, usage: c.usage, history: c.history }), before);
    assert.deepEqual(snapshot(calls), callsBefore);
  });

  it('is insensitive to the call id — only tool, args and time matter', () => {
    const a = evaluate({ ...calls[0]!, id: 'id-one' }, c);
    const b = evaluate({ ...calls[0]!, id: 'id-two' }, c);
    assert.deepEqual(a, b);
  });

  it('mutating a returned decision does not affect the next evaluation', () => {
    const d = evaluate(calls[1]!, c);
    d.violations.length = 0;
    d.effect = 'allow';
    assert.equal(evaluate(calls[1]!, c).effect, 'deny');
    assert.equal(evaluate(calls[1]!, c).violations.length, 1);
  });
});
