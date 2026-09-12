# Leash

**A deterministic leash for AI agents.** Allowlist the tools, cap the budget, prove what happened.

`npm` version · build status · Apache-2.0 · Node >= 20 *(badges go here)*

Leash is a **library and a sidecar, not a gateway**. Your traffic never leaves your infrastructure. You do not point your agent at someone else's cloud — you wrap your tool handlers in three lines, or you put `leash run --policy leash.yaml --` in front of an MCP server you already run.

---

## The problem in 5 lines

An agent with tool access has whatever authority its tools have.
A `fs.write` tool is a write primitive; a `billing.refund` tool is a refund primitive. The model decides when to pull them.
Prompt-level guardrails — "never touch files outside the workspace" — are advisory. They live inside the same text channel the attacker (or the confused model) controls.
You need enforcement that sits **outside the model**: a check that runs on the call itself, cannot be argued with, and leaves a record.
That is all Leash is.

---

## 60-second start

```
npm install shortleash
```

The package is published as `shortleash`; the binary it installs is `leash`. A Python port with the same policy language and a byte-compatible audit chain is on PyPI as `shortleash` too — see [`docs/python.md`](docs/python.md).

**`leash.yaml`**

```yaml
version: "1"
name: support-agent
default: deny

budget:
  calls: 50
  usd: 2.00

rules:
  - id: read-workspace
    tools: ["fs.read", "fs.list"]
    effect: allow
    when:
      path:
        startsWith: ["/srv/workspace/"]
        excludes: [".."]

  - id: no-secrets
    tools: ["fs.*"]
    effect: deny
    when:
      path:
        matches: "\\.env|id_rsa"
```

**The three-line code change.** Wherever you currently execute a tool call, wrap it:

```ts
import { Leash, LeashDenied, loadPolicyFile } from 'shortleash';

const leash = new Leash({
  policy: loadPolicyFile('./leash.yaml'),
  auditFile: './audit.jsonl',
});

// before:  const result = await tools[name](args);
// after:
const result = await leash.guard(name, args, () => tools[name](args));
```

That is the whole integration. `guard` evaluates the call, writes the decision to the audit chain, and only then invokes your handler. A refusal throws `LeashDenied` — never a silently skipped side effect:

```ts
try {
  return await leash.guard(name, args, () => tools[name](args));
} catch (err) {
  if (err instanceof LeashDenied) {
    // Hand the boundary back to the model so it can adapt.
    return { isError: true, content: [{ type: 'text', text: err.message }] };
  }
  throw err;
}
```

Metering is explicit, because the pricing assumption should be visible in your code rather than guessed by ours:

```ts
leash.meter(inputTokens, outputTokens, { input: 0.003, output: 0.015 }); // USD per 1k tokens
leash.spend(0.02);                                                       // non-token spend
```

And at the end of the run:

```ts
console.log(leash.usage()); // { calls: 1, tokens: 1500, usd: 0.0281, bytes: 512, startedAt: 1789035198799 }
console.log(leash.head());  // 994b15a1... — the head of this run's audit chain
```

---

## The MCP one-liner

If your agent already talks to an MCP server, you do not need to touch application code at all. Put Leash in front of the server process. Every `tools/call` that crosses the boundary is enforced against your policy.

Before, in your MCP client config:

```json
{ "command": "npx", "args": ["-y", "@acme/filesystem-mcp", "/srv/workspace"] }
```

After:

```json
{
  "command": "leash",
  "args": [
    "run", "--policy", "./leash.yaml", "--audit", "./audit.jsonl",
    "--", "npx", "-y", "@acme/filesystem-mcp", "/srv/workspace"
  ]
}
```

Or from a shell:

```
leash run --policy ./leash.yaml --audit ./audit.jsonl -- npx -y @acme/filesystem-mcp /srv/workspace
```

A refusal is returned to the agent as an **MCP tool error, not a protocol error**. That distinction matters: a protocol error looks like a broken server and the model retries blindly, while a tool error is content the model reads — it sees the boundary, sees which argument was wrong, and adapts. The stated reason is the same text a human operator gets.

### The rest of the CLI

```
leash run     --policy <file> [--audit <file>] [--run <id>] -- <command> [args...]
leash verify  <audit.jsonl> [--against <anchor.jsonl>]
leash receipt <audit.jsonl> [--json]
leash anchor  <audit.jsonl> --to <anchor.jsonl>
leash check   --policy <file> --tool <name> [--args <json>]
leash explain --policy <file>
```

| Command | Purpose | Exit codes |
| --- | --- | --- |
| `run` | Wrap an MCP server process; enforce every `tools/call`. | passthrough |
| `verify` | Verify the hash chain of an audit file. With `--against`, also check its head still matches the receipt anchored for that run. | `0` every requested check passed, `1` any failed |
| `receipt` | Summarise a run as one object — plan, usage, outcome, warnings. `--json` for one line of JSON. | `0` chain verifies, `1` it does not |
| `anchor` | Append that receipt to an append-only anchor file. | `0` appended, `1` the chain does not verify |
| `check` | Evaluate a single hypothetical call against a policy. | `0` allow, `1` deny, `2` ask |
| `explain` | Human-readable policy summary for a reviewer. | `0` |

`check` exists for CI. A policy is a security control, so regressions in it should break the build:

```
leash check --policy leash.yaml --tool fs.read  --args '{"path":"/srv/workspace/notes.md"}'   # expect 0
leash check --policy leash.yaml --tool fs.write --args '{"path":"/etc/passwd"}'               # expect 1
leash check --policy leash.yaml --tool shell.exec                                             # expect 1
```

Assert what your policy must *refuse*, not only what it permits. Allowlists rot in the permissive direction.

---

## How a decision is made

`evaluate(call, ctx)` is a pure function of **policy + call + ledger state**. No clock reads, no I/O, no model in the loop. The same three inputs always produce the same `Decision`, which is what makes the audit log replayable months later.

The ladder, in order:

1. **Budget.** An exhausted budget denies everything, whatever the rules say. `calls`, `tokens`, `usd`, `bytes` and `seconds` are checked in that order; the first one at or over its limit wins.
2. **Rate limits.** Among rules whose tool glob and argument constraints matched, any rule with a spent `limit` denies immediately.
3. **Effect precedence among matching rules: `deny` beats `ask` beats `allow`.** Rule order in the file does not matter. You cannot accidentally shadow a deny by putting an allow above it.
4. **No match at all** falls through to `policy.default`, which is **`deny`** unless you set it otherwise.

Deny-by-default is the whole posture. An unknown tool is denied. A known tool with arguments no rule accepts is denied. An `ask` rule with no `onAsk` handler configured is denied — an unattended run must never silently upgrade itself to allowed.

Two details worth internalising:

- A rule with `effect: deny` whose `when` constraints do *not* hold simply does not apply. It is not a trapdoor to allow; the call still has to find an allow rule of its own.
- Rate limits count entries attributed to that rule id in the audit history. Denied calls are not counted — being refused does not burn your quota.

### A worked near-miss

Using the policy above, the agent asks for `fs.read` with `{"path": "/etc/passwd"}`. The `read-workspace` rule targets `fs.read`, so it is considered — but its `startsWith` constraint rejects the argument. No other rule allows it, so the default applies:

```json
{
  "effect": "deny",
  "rule": null,
  "reason": "no rule allows \"fs.read\" with these arguments",
  "violations": [
    {
      "rule": "read-workspace",
      "path": "path",
      "constraint": "startsWith",
      "message": "argument \"path\" must start with one of [\"/srv/workspace/\"]"
    }
  ]
}
```

Note the shape. When a rule *wanted* this tool but rejected the arguments, Leash reports that near-miss instead of the useless "no rule matched" — so the model is told which argument was wrong and can retry inside the boundary. When nothing targeted the tool at all, you get the blunter version:

```json
{
  "effect": "deny",
  "rule": null,
  "reason": "no rule allows tool \"shell.exec\"",
  "violations": [
    {
      "rule": "policy",
      "constraint": "default",
      "message": "tool \"shell.exec\" is not in the policy; the default effect is deny"
    }
  ]
}
```

`LeashDenied.message` is that `reason` prefixed with the tool name:

```
leash: fs.read denied — no rule allows "fs.read" with these arguments
```

---

## Policy reference

Full reference with a worked example per constraint: [`docs/policy-reference.md`](docs/policy-reference.md).

### Policy

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `version` | `"1"` | yes | Schema version. Only `"1"` exists; anything else is rejected at load. |
| `name` | `string` | no | Free-text label carried into audit exports. |
| `default` | `"allow" \| "deny" \| "ask"` | no | Effect when no rule matches. **Defaults to `deny`.** |
| `budget` | `BudgetLimits` | no | Run-scoped ceilings. Absent means unlimited. |
| `rules` | `PolicyRule[]` | yes | The clauses. May be empty, which with the default means "deny everything". |

Unknown top-level keys are a hard load error. In a security policy a typo is not a harmless no-op — a silently ignored `startWith` would turn a scoped filesystem rule into an unscoped one.

### PolicyRule

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `id` | `string` | yes | Stable identifier. Must be unique within the policy. Surfaced in decisions and audit entries, and used to attribute rate-limit counts. |
| `description` | `string` | no | Human-readable justification. Becomes the `reason` in a denial and the text a reviewer reads. |
| `tools` | `string[]` | yes | Non-empty list of tool-name globs. |
| `effect` | `"allow" \| "deny" \| "ask"` | yes | What this rule does when it matches. |
| `when` | `Record<string, ArgConstraint>` | no | Argument constraints keyed by dotted path. **All** must hold for the rule to match. |
| `limit` | `RateLimit` | no | Throttle for calls attributed to this rule. Exceeding it denies. |

**Glob semantics.** `*` matches any run of characters **except the separators `.` and `/`**. `**` matches anything, separators included. Everything else is literal; matching is case-sensitive and whole-string.

| Pattern | `fs.read` | `fs.read.raw` | `github/create_issue` |
| --- | --- | --- | --- |
| `fs.read` | match | — | — |
| `fs.*` | match | — | — |
| `fs.**` | match | match | — |
| `github/*` | — | — | match |
| `*` | — | — | — |
| `**` | match | match | match |

Use `**`, not `*`, when you mean "every tool".

### ArgConstraint

Applied to one argument, addressed by a dotted path (`path`, `body.recipients.0`). Numeric segments index into arrays. A path that runs off the end of the object — or through a `null` — resolves to *missing* rather than throwing, so a malformed model argument becomes a policy violation and not a crash.

Every constraint present must hold. **An absent value fails every constraint except `optional`.**

| Field | Type | Applies to | Meaning |
| --- | --- | --- | --- |
| `optional` | `boolean` | any | Allow the argument to be missing entirely. Default `false`. |
| `type` | `"string" \| "number" \| "boolean" \| "object" \| "array"` | any | Runtime type check. A mismatch short-circuits: no other constraint on that path is reported. |
| `oneOf` | `unknown[]` | any | Value must deep-equal one of these. |
| `noneOf` | `unknown[]` | any | Value must deep-equal none of these. |
| `matches` | `string` | strings | Must match this regular expression. **Not anchored for you** — write `^…$` if you mean the whole string. |
| `startsWith` | `string[]` | strings | Must start with one of these prefixes. The filesystem-scoping primitive. |
| `excludes` | `string[]` | strings | Must not contain any of these substrings. Cheap traversal guard (`".."`). |
| `urlHosts` | `string[]` | strings | Must parse as a URL whose hostname is in this list. An unparseable string fails. |
| `min` | `number` | numbers | Inclusive lower bound. |
| `max` | `number` | numbers | Inclusive upper bound. |
| `minLength` | `number` | strings, arrays | Inclusive lower bound on `.length`. |
| `maxLength` | `number` | strings, arrays | Inclusive upper bound on `.length`. |

Constraints that do not apply to the value's runtime type are simply not evaluated — `min` on a string is inert. Pair a bound with `type` when you want the type itself enforced.

**`urlHosts` and the leading dot.** An entry beginning with `.` matches that domain *and every subdomain*: `.example.com` covers `example.com` and `api.example.com`. Anything else must match the hostname exactly, so an allowlist never widens by accident. `example.com` (no dot) does **not** admit `api.example.com`, and — importantly — `.example.com` does not admit `notexample.com`.

### RateLimit

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `max` | `number` (non-negative integer) | yes | Maximum calls attributed to this rule inside the window. |
| `perSeconds` | `number` (positive) | no | Sliding window length in seconds. **Omit for "per run".** |

`max: 0` is legal and means "never" — a way to disable a rule without deleting it.

### BudgetLimits

Run-scoped. Every field is optional; each must be a positive number. All are checked **before** any rule, and use `>=`: a limit of `calls: 50` permits calls 1 through 50 and refuses the 51st.

| Field | Type | Meaning |
| --- | --- | --- |
| `calls` | `number` | Hard ceiling on total permitted tool calls in the run. |
| `tokens` | `number` | Hard ceiling on input+output tokens attributed to the run, via `meter()`. |
| `usd` | `number` | Hard ceiling on estimated spend, from `meter()` pricing and `spend()`. |
| `seconds` | `number` | Wall-clock ceiling, measured from the **first metered event**, not from process start. |

Leash does not count tokens or dollars for you — it cannot see your model calls. `meter()` and `spend()` are how consumption enters the ledger. A `tokens` or `usd` budget with no `meter()` calls is inert; a `seconds` budget only begins once something has been metered or a call has been permitted.

### Leash options

```ts
new Leash({
  policy,                       // Policy — required
  run: 'run-2026-09-10-a',      // string — stamped on audit entries; a UUID when omitted
  auditFile: './audit.jsonl',   // string — append entries here; they are buffered either way
  redact: ['headers.authorization'], // string[] — dotted paths blanked before hashing
  onAsk: async (call, decision) => confirmWithHuman(call), // ApprovalHandler
  now: () => Date.now(),        // () => number — injectable clock; tests pass a fixed one
});
```

| Method | Returns | Notes |
| --- | --- | --- |
| `check(tool, args?)` | `Decision` | Evaluates without recording or executing. For dry runs and operator previews. |
| `guard(tool, args, execute)` | `Promise<T>` | Evaluate, record, then execute. Throws `LeashDenied` on refusal. |
| `meter(input, output, price?)` | `void` | Record a model turn. `price` is USD per **1,000** tokens. |
| `spend(usd)` | `void` | Record non-token spend. |
| `usage()` | `BudgetUsage` | `{ calls, tokens, usd, startedAt }`. |
| `entries()` | `readonly AuditEntry[]` | The chain recorded so far. |
| `head()` | `string` | Hash of the newest entry — the receipt for the run. |

`LeashDenied` carries `tool`, `decision` and `auditHash` — the hash of the entry recording the refusal, worth quoting in a support ticket.

The library also exports the pieces directly for embedding: `evaluate`, `loadPolicyFile`, `parsePolicy`, `validatePolicy`, `PolicyError`, `matchesGlob`, `resolvePath`, `Ledger`, `AuditLog`, `canonicalize`, `hashEntry`, `GENESIS`, `verifyChain`, `verifyFile`.

---

## Audit and verification

Every decision — allowed, denied, or approved-after-ask — is appended to a hash chain. The format is JSONL, one entry per line, so it survives a crash mid-run and can be tailed, grepped and shipped to any log pipeline unchanged.

A real entry:

```json
{
  "seq": 2,
  "at": 1789035198799,
  "run": "f37b4b88-19ed-42ad-914f-b45e163a3874",
  "tool": "fs.read",
  "args": { "path": "/srv/workspace/README.md" },
  "decision": {
    "effect": "allow",
    "rule": "read-workspace",
    "reason": "allowed by rule \"read-workspace\"",
    "violations": []
  },
  "usage": { "calls": 0, "tokens": 0, "usd": 0 },
  "prev": "70353bddfb256edd47e8694a3d0fb10e770b026005e5f524b7ac647c409c14b2",
  "hash": "994b15a18ec8937a1d1c38f4c408b45e81d8090ca46b354c82a2896236b268b4"
}
```

`usage` is consumption **at the moment of the decision**, before this call is counted — which is exactly the state the engine saw, so a reviewer can replay the decision from the entry alone.

### How the chain works

- `prev` on entry *n* is the `hash` of entry *n−1*. The first entry's `prev` is `GENESIS`, sixty-four zeroes.
- `hash` is `sha256` over a **canonical** serialisation of the entry excluding `hash` itself: object keys sorted, no incidental whitespace, `undefined` dropped. Without canonicalisation the chain would depend on V8's key ordering and a log written by one process could fail verification in another.
- Editing, deleting or reordering any past entry invalidates that entry's hash and every link after it.

```
leash verify audit.jsonl
```

Exit `0` if the chain is intact, `1` if it is not. `verifyFile` returns the same result programmatically, and it stops at the **first** inconsistency with a specific cause:

```json
{
  "ok": false,
  "count": 1,
  "head": "0000000000000000000000000000000000000000000000000000000000000000",
  "failure": {
    "seq": 1,
    "reason": "bad-hash",
    "detail": "entry hashes to 604bcf30e8eb but claims 5785cdfb11e3"
  }
}
```

`reason` is one of `bad-hash` (contents were edited), `broken-link` (an entry was inserted or removed), `bad-sequence` (entries reordered), or `malformed` (a line is not valid JSON).

### Redaction

Secrets must never reach the log. Pass dotted paths to `redact` and the value is replaced with the literal string `"[redacted]"` before the entry is hashed:

```ts
new Leash({ policy, auditFile: './audit.jsonl', redact: ['headers.authorization'] });
```

```json
"args": { "url": "https://api.example.com", "headers": { "authorization": "[redacted]" } }
```

Two properties follow, and both matter:

- The **redacted shape is what gets hashed.** A redaction is therefore part of the committed record, not a later edit — you cannot retroactively redact a logged secret and still pass `verify`, and you cannot forge a redaction to hide what an argument was.
- Your caller's object is untouched. Leash clones before redacting, so the real argument value is still available to the tool.

Redaction is declared per-`Leash`, not per-rule. If a value is sensitive anywhere, redact it everywhere.

---

## What Leash is not

Being straight about the boundary is worth more than overclaiming.

- **It does not inspect prompts or model output.** There is no classifier, no jailbreak detector, no content filter. Leash sees tool names and arguments, and nothing else.
- **It cannot stop an allowed tool from doing something harmful.** If your policy permits `fs.write` under `/srv/workspace/`, Leash will let the agent write nonsense there all day. The policy is the security boundary; Leash only enforces it faithfully.
- **It is not a network egress filter.** `urlHosts` constrains a *URL-shaped argument you chose to constrain*. A tool that opens its own sockets is invisible to Leash. If you need egress control, you need it at the network layer.
- **It governs the tool boundary only.** Anything a tool does internally, anything the model does without calling a tool, and anything another process on the host does are all outside its remit.
- **The audit log is tamper-evident, not tamper-proof.** An attacker with write access to the file can rewrite the entire chain consistently. Evidence requires that the head hash be anchored somewhere they do not control. See [`docs/threat-model.md`](docs/threat-model.md).
- **The budget is an estimate, not a bill.** `usd` is whatever your `meter()` price table and `spend()` calls say it is.

---

## Comparison

Describing categories, not products.

| | Deterministic | Self-hosted | Adds latency | Jailbreakable | Audit artefact |
| --- | --- | --- | --- | --- | --- |
| **Prompt-level guardrails** (system-prompt rules, tool descriptions) | No — the model decides | Yes | No | Yes, directly — it is text in the same channel | No |
| **LLM-judge guardrails** (a second model approves each call) | No — sampled output | Usually a vendor API | Yes — an extra model call per tool call | Yes — the judge takes a prompt too | Only if the vendor keeps one; not verifiable by you |
| **API gateways / egress proxies** | Yes, for what they can see | Sometimes; often a hosted hop | Yes — a network round trip | No | Request logs, not decision logs; usually not hash-chained |
| **Leash** | Yes — a pure function of policy + call + ledger | Yes — in-process or a local sidecar | Negligible — no network, no model | No prompt to jailbreak | Hash-chained JSONL, verifiable offline with one command |

The wedge is narrow and deliberate: Leash does one layer, deterministically, in your infrastructure, and hands you a file you can prove things with. It complements the other rows rather than replacing them — an LLM judge on top of a deny-by-default allowlist is a reasonable architecture; an LLM judge *instead of* one is not.

**One runtime dependency** (`yaml`). Apache-2.0. Node >= 20.

---

## Documentation

- [`docs/policy-reference.md`](docs/policy-reference.md) — exhaustive constraint reference and common policies.
- [`docs/threat-model.md`](docs/threat-model.md) — what Leash defends against, what it does not, and how to anchor the audit chain.

## Licence

Apache License 2.0. See [`LICENSE`](LICENSE).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The short version: no new runtime dependencies, and any change to enforcement semantics needs a test that fails without it.
