# Leash examples

Both examples are self-contained: no API key, no network, no model. The model
turns are hardcoded tool calls in the exact shape the Anthropic and OpenAI SDKs
produce, so what you see is the policy engine deciding, not a model behaving.

Build once:

```sh
npm run build
```

## Coding agent — filesystem and shell

```sh
node examples/filesystem.mjs
```

Policy: [`filesystem.policy.yaml`](./filesystem.policy.yaml). Reads anywhere in
the project, writes only under `./src` and `./test`, no `..` and no `.env`,
`fs.delete` denied outright, `shell.exec` limited to four literal commands at
10 per minute, with a 200-call / 2M-token / $5.00 budget.

Shows `guardToolUse` (Anthropic `tool_use` in, `tool_result` out),
`meterAnthropicUsage`, and the hash-chained audit file at the end — a refusal
comes back as a readable `is_error` result rather than an exception, so the
agent loop survives it.

## Support agent — CRM and email

```sh
node examples/support-agent.mjs
```

Policy: [`support-agent.policy.yaml`](./support-agent.policy.yaml). Customer
lookups and tickets are free; refunds up to $50 are automatic, above that they
require approval, and at $500 they are refused no matter who approves; outbound
mail is pinned to the corporate domain and rate-limited.

Shows `guardOpenAIToolCall` (OpenAI tool call in, `role: "tool"` message out),
`meterOpenAIUsage`, the `onAsk` approval handler (auto-approving here; a real
integration prompts a human or posts to Slack), and what happens when the model
emits malformed JSON arguments.

Both runs write a verifiable JSONL audit chain under `examples/.leash/`.
