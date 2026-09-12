/**
 * The decision function.
 *
 * `evaluate` is pure: same policy + same usage + same history + same call
 * always yields the same Decision. No clock reads, no I/O, no model in the
 * loop. That property is what makes a Leash audit log replayable, and it is
 * the difference between this and a guardrail that asks an LLM for permission.
 *
 * Precedence, in order:
 *   1. Budget. An exhausted budget denies everything, whatever the rules say.
 *   2. A matching rule whose rate limit is spent denies.
 *   3. Among matching rules: deny beats ask beats allow.
 *   4. No match at all falls through to `policy.default` (deny unless set).
 */

import type { Decision, EvalContext, PolicyRule, ToolCall, Violation } from '../types.js';
import { checkArgs } from './constraints.js';
import { matchesAnyGlob } from './match.js';

export function evaluate(call: ToolCall, ctx: EvalContext): Decision {
  const budgetViolation = checkBudget(call, ctx);
  if (budgetViolation) {
    return {
      effect: 'deny',
      rule: null,
      reason: budgetViolation.message,
      violations: [budgetViolation],
    };
  }

  const matched: PolicyRule[] = [];
  /** Rules that targeted this tool but whose constraints rejected the arguments. */
  const nearMisses: Violation[] = [];

  for (const rule of ctx.policy.rules) {
    if (!matchesAnyGlob(rule.tools, call.tool)) continue;

    const violations = rule.when ? checkArgs(rule.id, rule.when, call.args) : [];
    if (violations.length > 0) {
      if (rule.effect !== 'deny') nearMisses.push(...violations);
      continue;
    }
    matched.push(rule);
  }

  for (const rule of matched) {
    if (!rule.limit) continue;
    const used = countRecent(ctx, rule.id, call.at, rule.limit.perSeconds);
    if (used >= rule.limit.max) {
      const window = rule.limit.perSeconds ? `${rule.limit.perSeconds}s` : 'this run';
      return {
        effect: 'deny',
        rule: rule.id,
        reason: `rate limit exhausted for rule "${rule.id}"`,
        violations: [
          {
            rule: rule.id,
            constraint: 'limit',
            message: `rule "${rule.id}" allows ${rule.limit.max} call(s) per ${window}; ${used} already used`,
          },
        ],
      };
    }
  }

  const denied = matched.find((r) => r.effect === 'deny');
  if (denied) {
    return {
      effect: 'deny',
      rule: denied.id,
      reason: denied.description ?? `denied by rule "${denied.id}"`,
      violations: [
        {
          rule: denied.id,
          constraint: 'rule',
          message: denied.description ?? `tool "${call.tool}" is denied by rule "${denied.id}"`,
        },
      ],
    };
  }

  const ask = matched.find((r) => r.effect === 'ask');
  if (ask) {
    return {
      effect: 'ask',
      rule: ask.id,
      reason: ask.description ?? `rule "${ask.id}" requires approval`,
      violations: [],
    };
  }

  const allow = matched.find((r) => r.effect === 'allow');
  if (allow) {
    return { effect: 'allow', rule: allow.id, reason: `allowed by rule "${allow.id}"`, violations: [] };
  }

  const fallback = ctx.policy.default ?? 'deny';
  if (fallback === 'allow') {
    return { effect: 'allow', rule: null, reason: 'no rule matched; policy default is allow', violations: [] };
  }

  // Deny-by-default is the common path, so spend the effort on a message the
  // agent can act on: if a rule wanted this tool but rejected the arguments,
  // say which argument rather than the useless "no rule matched".
  return {
    effect: fallback,
    rule: null,
    reason:
      nearMisses.length > 0
        ? `no rule allows "${call.tool}" with these arguments`
        : `no rule allows tool "${call.tool}"`,
    violations:
      nearMisses.length > 0
        ? nearMisses
        : [
            {
              rule: 'policy',
              constraint: 'default',
              message: `tool "${call.tool}" is not in the policy; the default effect is ${fallback}`,
            },
          ],
  };
}

function checkBudget(call: ToolCall, ctx: EvalContext): Violation | null {
  const limits = ctx.policy.budget;
  if (!limits) return null;
  const { usage } = ctx;

  const over = (constraint: string, message: string): Violation => ({
    rule: 'budget',
    constraint,
    message,
  });

  if (limits.calls !== undefined && usage.calls >= limits.calls) {
    return over('calls', `call budget exhausted: ${usage.calls}/${limits.calls} calls used`);
  }
  if (limits.tokens !== undefined && usage.tokens >= limits.tokens) {
    return over('tokens', `token budget exhausted: ${usage.tokens}/${limits.tokens} tokens used`);
  }
  if (limits.usd !== undefined && usage.usd >= limits.usd) {
    return over('usd', `spend budget exhausted: $${usage.usd.toFixed(4)}/$${limits.usd.toFixed(4)} used`);
  }
  if (limits.bytes !== undefined && usage.bytes >= limits.bytes) {
    return over(
      'bytes',
      `data budget exhausted: ${usage.bytes}/${limits.bytes} bytes returned by tools`
    );
  }
  if (limits.seconds !== undefined && usage.startedAt !== null) {
    const elapsed = (call.at - usage.startedAt) / 1000;
    if (elapsed >= limits.seconds) {
      return over(
        'seconds',
        `time budget exhausted: ${elapsed.toFixed(1)}s/${limits.seconds}s elapsed`
      );
    }
  }

  return null;
}

/** Calls already attributed to `ruleId`, within the sliding window if one is set. */
function countRecent(
  ctx: EvalContext,
  ruleId: string,
  now: number,
  perSeconds: number | undefined
): number {
  const floor = perSeconds === undefined ? -Infinity : now - perSeconds * 1000;
  let count = 0;
  for (const entry of ctx.history) {
    if (entry.rule === ruleId && entry.at > floor) count++;
  }
  return count;
}
