/**
 * Customer-support agent under a CRM/email policy.
 *
 * Run:  npm run build && node examples/support-agent.mjs
 *
 * No model, no network: the turns are hardcoded OpenAI-shaped tool calls, so
 * what you are watching is the policy — including the `ask` path, where the
 * decision leaves the engine and goes to a human.
 */

import { mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Toolwrit, loadPolicyFile, verifyFile } from '../dist/index.js';
import { guardOpenAIToolCall, meterOpenAIUsage } from '../dist/adapters/sdk.js';

const here = dirname(fileURLToPath(import.meta.url));
const auditFile = join(here, '.toolwrit', 'support-agent.audit.jsonl');

rmSync(auditFile, { force: true });
mkdirSync(join(here, '.toolwrit'), { recursive: true });

/** Approvals seen by the operator, so the example can show what was escalated. */
const approvals = [];

const toolwrit = new Toolwrit({
  policy: loadPolicyFile(join(here, 'support-agent.policy.yaml')),
  auditFile,
  run: 'example-support-agent',

  /**
   * The `ask` handler. This example auto-approves so it can run unattended; a
   * real integration posts the call to Slack, opens a task in the queue, or
   * blocks on a terminal prompt, and returns the human's answer. Whatever it
   * does, returning false (or having no handler at all) denies — Toolwrit never
   * upgrades an unanswered question into permission.
   */
  onAsk: (call, decision) => {
    approvals.push({ tool: call.tool, amount: call.args.amount, rule: decision.rule });
    return true;
  },
});

const handlers = {
  'crm.lookup_customer': ({ query }) => ({ id: 'cus_8812', email: query, plan: 'pro', since: '2023-04-01' }),
  'crm.create_ticket': ({ subject }) => ({ ticket: 'TKT-4471', subject, status: 'open' }),
  'crm.issue_refund': ({ amount, customer }) => ({ refund: 're_5590', customer, amount, status: 'settled' }),
  'email.send': ({ to, subject }) => ({ message_id: 'msg_1042', to, subject }),
};

/** What the model asked for, turn by turn. */
const turns = [
  ['look the customer up', 'crm.lookup_customer', { query: 'ada@customer.example' }],
  ['open a ticket', 'crm.create_ticket', { subject: 'Double charge on invoice 8812', body: 'Customer was billed twice in March.' }],
  ['refund a small amount', 'crm.issue_refund', { customer: 'cus_8812', amount: 24.5 }],
  ['refund an amount that needs a human', 'crm.issue_refund', { customer: 'cus_8812', amount: 180 }],
  ['refund far past the ceiling', 'crm.issue_refund', { customer: 'cus_8812', amount: 900 }],
  ['mail a colleague', 'email.send', { to: 'billing@support.example.com', subject: 'Refund re_5590 issued' }],
  ['mail the open internet', 'email.send', { to: 'ada@customer.example', subject: 'Refund issued' }],
  ['emit broken arguments', 'crm.create_ticket', '{"subject": "unterminated'],
  ['reach for a tool nobody granted', 'crm.delete_customer', { id: 'cus_8812' }],
];

console.log(`\n  Toolwrit — customer-support agent example`);
console.log(`  policy: support-agent.policy.yaml    run: ${toolwrit.run}\n`);

let allowed = 0;
let refused = 0;

for (const [index, [label, name, args]] of turns.entries()) {
  // `arguments` is a JSON string on the wire, which is why one of the turns
  // above is deliberately malformed: that is a real failure mode, not a typo.
  const toolCall = {
    id: `call_${index + 1}`,
    type: 'function',
    function: { name, arguments: typeof args === 'string' ? args : JSON.stringify(args) },
  };

  const message = await guardOpenAIToolCall(toolwrit, toolCall, handlers);

  // The OpenAI tool message has no error flag, so read the verdict off the
  // audit chain instead of pattern-matching the text we just produced.
  const effect = toolwrit.entries().at(-1).decision.effect;
  if (effect === 'allow') allowed++;
  else refused++;

  console.log(`  ${effect === 'allow' ? 'ALLOW' : 'DENY '}  ${label}`);
  console.log(`         ${name} ${toolCall.function.arguments}`);
  for (const line of message.content.split('\n')) console.log(`         ${line}`);
  console.log();

  meterOpenAIUsage(toolwrit, { prompt_tokens: 900, completion_tokens: 140 }, { input: 0.0005, output: 0.0015 });
}

const usage = toolwrit.usage();
const verified = verifyFile(auditFile);

console.log(`  ${allowed} allowed, ${refused} refused`);
console.log(`  escalated to a human: ${approvals.length ? approvals.map((a) => `${a.tool} $${a.amount} (${a.rule})`).join(', ') : 'none'}`);
console.log(`  budget: ${usage.calls} calls  ${usage.tokens.toLocaleString('en-US')} tokens  $${usage.usd.toFixed(4)}`);
console.log(`  audit:  ${auditFile}`);
console.log(`          ${verified.count} entries, chain ${verified.ok ? 'intact' : 'BROKEN'}, head ${toolwrit.head().slice(0, 16)}\n`);
