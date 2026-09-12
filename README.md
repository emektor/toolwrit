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
console.log(leash.head());  // a 64-char sha256 — the head of this run's audit chain
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

## Run plans

A `plan:` block is the envelope a run declares before it starts and a human approves once.

```yaml
budget:
  calls: 200
  usd: 5.00
  bytes: 20000000
  seconds: 3600

plan:
  purpose: nightly CRM export for the EU region
  approvedBy: ergin
  # warnAt: [0.8, 0.95]   # the default
```

The argument for it is worth stating plainly, because it is the whole reason the feature exists. **A global threshold has to guess at every job at once.** "More than 50MB is suspicious" is either too loose to catch anything — the number has to clear your biggest legitimate job — or too tight to leave switched on, in which case somebody mutes it, and an alert people mute is the same as no alert.

A declared envelope does not guess. A render job that asked for an hour and two gigabytes gets exactly that, uninterrupted. The signal stops being "this looks like a lot" and becomes "this run left the envelope its operator approved" — which is a fact, not a hunch. Approve once at the start, hear nothing until a threshold.

**The plan is written into the audit chain as entry 1, before the run can consume anything.** The `Leash` constructor records it; no guarded call can precede it. What was *authorised* is therefore part of the tamper-evident record, not just what happened, and nobody can later claim a different budget was approved than the one the run started under:

```json
{
  "seq": 1,
  "at": 1789178401000,
  "run": "nightly-2026-09-12",
  "tool": "leash:plan",
  "args": {
    "purpose": "nightly CRM export for the EU region",
    "approvedBy": "ergin",
    "budget": { "calls": 200, "usd": 5, "bytes": 20000000, "seconds": 3600 },
    "warnAt": [0.8, 0.95]
  },
  "decision": { "effect": "allow", "rule": "plan", "reason": "run plan recorded", "violations": [] },
  "usage": { "calls": 0, "tokens": 0, "usd": 0, "bytes": 0 },
  "prev": "0000000000000000000000000000000000000000000000000000000000000000",
  "hash": "e375bde8b22e4e1d2726a1a9d4110a5ae1fd922329689f2aa2b1f64d1ed43382"
}
```

Note the zero usage: the envelope is committed before anything can be spent against it. The defaults Leash will actually use are recorded too (`warnAt: [0.8, 0.95]`, `approvedBy: null` when unset), so the entry is self-describing rather than a document you have to re-derive from the policy file.

### Warnings

`warnAt` is a list of fractions of the budget. Each threshold fires **at most once per dimension**, across `calls`, `tokens`, `usd`, `bytes` and `seconds` — repetition is what gets an alert muted. A warning is delivered to `onWarn` *and* recorded in the chain, so "nobody told me it was at 95%" is answerable from the log rather than from whether a Slack message happened to get delivered.

```ts
const leash = new Leash({
  policy: loadPolicyFile('./export.yaml'),
  auditFile: './audit.jsonl',
  // Keep this non-blocking: it runs inline with metering. Queue the post,
  // do not await it.
  onWarn: (w) => console.log(w.message),
});
```

```
run "nightly-2026-09-12" (nightly CRM export for the EU region) has used 16,000,000/20,000,000 bytes — 80% of the approved envelope
```

The `BudgetWarning` handed to `onWarn` carries `dimension`, `threshold`, `used`, `limit` and that ready-to-send `message`. The chain entry carries the same fields:

```json
{
  "seq": 6,
  "at": 1789178410000,
  "run": "nightly-2026-09-12",
  "tool": "leash:warning",
  "args": {
    "dimension": "bytes",
    "threshold": 0.8,
    "used": 16000000,
    "limit": 20000000,
    "message": "run \"nightly-2026-09-12\" (nightly CRM export for the EU region) has used 16,000,000/20,000,000 bytes — 80% of the approved envelope"
  },
  "decision": { "effect": "allow", "rule": "plan", "reason": "run \"nightly-2026-09-12\" (nightly CRM export for the EU region) has used 16,000,000/20,000,000 bytes — 80% of the approved envelope", "violations": [] },
  "usage": { "calls": 4, "tokens": 0, "usd": 0, "bytes": 16000000 },
  "prev": "da02708df6bc2338bf03089dd7356bf1e81a0b1c3e6895216a655f877bc4e905",
  "hash": "4cd48e58f9b83f20a143534960983d5d72062507d8c356b35b2292845ce479cd"
}
```

A warning is a report, not an enforcement action: crossing 95% does not refuse anything. The budget does the refusing, at 100%.

Three load-time rules, all of which fail loudly:

- `purpose` is required and must be non-empty.
- A `plan` requires a `budget` to measure against. A plan with nothing to measure would report nothing, and silence reads as "all clear" rather than "not configured".
- `warnAt` entries must be greater than `0` and at most `1`. They are sorted ascending at load, so the order you write them in does not matter.

---

## The bytes ceiling

`budget.bytes` caps the total size of what tools **return** over a run. It is the volume half of containment, and it catches a different attack from the rules.

Bulk exfiltration is rarely a forbidden action. It is a permitted action repeated until something is drained — page 1, page 2, page 3, up to page nine thousand. Every one of those calls passes the allowlist, because reading customer records is exactly what the agent is for. Only the running total gives it away.

```yaml
budget:
  bytes: 20000000   # 20 MB of tool output for the whole run
```

```
call 1: ok, bytes now 4000000
call 2: ok, bytes now 8000000
call 3: ok, bytes now 12000000
call 4: ok, bytes now 16000000
call 5: ok, bytes now 20000000
call 6: leash: crm.search denied — data budget exhausted: 20000000/20000000 bytes returned by tools
```

### The limitation, stated up front

**A result's size cannot be known before the tool runs.** So the measurement happens after the fact, and the ordering it imposes is unavoidable:

> The call that blows the ceiling **completes**, and the **next** one is refused. A bytes ceiling bounds a run at the limit *plus one call*, never exactly the limit.

If a single tool call can return your entire database, a bytes ceiling will not save you — cap the page size on the tool itself, with `maxLength` or a server-side limit. What the ceiling bounds is *iteration*: the second, tenth and hundredth call in a drain.

A second honest limit: **an unserialisable result is under-counted.** Sizes are measured as the UTF-8 byte length of a string, the byte length of a `Uint8Array`/`ArrayBuffer`, or the UTF-8 byte length of `JSON.stringify(result)` for anything else. A value that cannot be stringified (a cycle, a throwing `toJSON`) falls back to its `String()` form, which is usually far smaller than the data it holds. `null` and `undefined` count as zero. This fails *open* — it is documented rather than hidden, because throwing an exception from inside the enforcement layer would be worse.

Two smaller notes:

- Bytes are attributed to the call's own timestamp, not to a fresh clock read, so the ledger does not depend on how long a tool happened to take.
- Under `leash run`, what is measured is the **whole JSON-RPC response object** the downstream MCP server sent, not just the text inside it. In a measured run a 100-character text result cost 173 bytes. Size the budget against the protocol envelope, not the payload. The proxy also handles requests concurrently, so calls already in flight are not counted until they return.

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
| `plan` | `RunPlan` | no | The declared, pre-approved envelope. **Requires `budget`.** |
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
| `bytes` | `number` | Hard ceiling on bytes **returned by tools** across the run. Measured after each call, so the breaching call completes and the next is refused — see [The bytes ceiling](#the-bytes-ceiling). |
| `seconds` | `number` | Wall-clock ceiling, measured from the **first metered event**, not from process start. |

Leash does not count tokens or dollars for you — it cannot see your model calls. `meter()` and `spend()` are how consumption enters the ledger. A `tokens` or `usd` budget with no `meter()` calls is inert; a `seconds` budget only begins once something has been metered or a call has been permitted. `calls` and `bytes` are the two dimensions Leash fills in by itself, from `guard()`.

### RunPlan

Requires a `budget`; a plan with nothing to measure against is a load error.

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `purpose` | `string` | yes | What the run is for, in the operator's words. Must be non-empty. Carried into the audit log and every warning message. |
| `approvedBy` | `string` | no | Who approved the envelope. **Recorded, never verified by Leash.** Logged as `null` when unset. |
| `warnAt` | `number[]` | no | Fractions of the budget at which the run reports. Each entry must be `> 0` and `<= 1`. Sorted ascending at load. Defaults to `[0.8, 0.95]`. |

### BudgetWarning

Passed to `onWarn` and recorded as a `leash:warning` audit entry. Fires at most once per threshold per dimension.

| Field | Type | Meaning |
| --- | --- | --- |
| `dimension` | `"calls" \| "tokens" \| "usd" \| "seconds" \| "bytes"` | Which budget dimension crossed. |
| `threshold` | `number` | The `warnAt` fraction that fired. |
| `used` / `limit` | `number` | Consumption and ceiling for that dimension. |
| `message` | `string` | Ready-to-send summary. |

### Leash options

```ts
new Leash({
  policy,                       // Policy — required
  run: 'run-2026-09-10-a',      // string — stamped on audit entries; a UUID when omitted
  auditFile: './audit.jsonl',   // string — append entries here; they are buffered either way
  redact: ['headers.authorization'], // string[] — dotted paths blanked before hashing
  onAsk: async (call, decision) => confirmWithHuman(call), // ApprovalHandler
  onWarn: (warning) => postToSlack(warning.message),       // (w: BudgetWarning) => void
  now: () => Date.now(),        // () => number — injectable clock; tests pass a fixed one
});
```

`onWarn` runs inline with metering. Keep it non-blocking — queue the notification rather than awaiting it. If the policy has a `plan`, the constructor writes the `leash:plan` entry immediately, so constructing a `Leash` with an `auditFile` always appends entry 1 before you call anything.

| Method | Returns | Notes |
| --- | --- | --- |
| `check(tool, args?)` | `Decision` | Evaluates without recording or executing. For dry runs and operator previews. |
| `guard(tool, args, execute)` | `Promise<T>` | Evaluate, record, then execute. Throws `LeashDenied` on refusal. |
| `meter(input, output, price?)` | `void` | Record a model turn. `price` is USD per **1,000** tokens. |
| `spend(usd)` | `void` | Record non-token spend. |
| `usage()` | `BudgetUsage` | `{ calls, tokens, usd, bytes, startedAt }`. |
| `entries()` | `readonly AuditEntry[]` | The chain recorded so far. |
| `head()` | `string` | Hash of the newest entry — what an anchor commits to. |

`LeashDenied` carries `tool`, `decision` and `auditHash` — the hash of the entry recording the refusal, worth quoting in a support ticket.

The library also exports the pieces directly for embedding: `evaluate`, `loadPolicyFile`, `parsePolicy`, `validatePolicy`, `PolicyError`, `matchesGlob`, `resolvePath`, `Ledger`, `AuditLog`, `canonicalize`, `hashEntry`, `GENESIS`, `verifyChain`, `verifyFile`, `summarize`, `verifyAgainstReceipt`.

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
  "usage": { "calls": 1, "tokens": 0, "usd": 0, "bytes": 13 },
  "prev": "4e700ae4f574319b9c49ea9da35265a498ed0e156551a5e0e3251aca76a8665e",
  "hash": "bf67c74f8195def87444a9a5bc02a2535d768c8d70a4658920679eaf1e7b4e5f"
}
```

`usage` is consumption **at the moment of the decision**, before this call is counted — which is exactly the state the engine saw, so a reviewer can replay the decision from the entry alone. `bytes` lags by one call for the same reason: it is the total *before* this tool has returned anything.

Two entries describe Leash itself rather than a guarded tool call: `leash:plan` (the approved envelope, always entry 1 when a policy declares a plan) and `leash:warning` (a threshold that fired). They share the ordinary entry shape, so one chain and one verifier cover everything.

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

## Run receipts

A hash chain proves what one run did. Nobody reads chains at scale. A fleet of 100,000 agents leaves hundreds of millions of entries behind, and "review the logs" is not an instruction anyone can act on.

A receipt is one small summary object per run. The fleet becomes **100,000 receipts instead of 100,000,000 entries**, with the runs that left their approved envelope already flagged in the summary rather than buried in it.

```
leash receipt audit.jsonl
```

```
run:      nightly-2026-09-12
entries:  9  2026-09-12T02:00:01.000Z → 2026-09-12T02:00:14.000Z
chain:    ok
head:     6a5900e535789622d82e8b78374597e412d95c016fa408401697fcff01da0ea6
purpose:  nightly CRM export for the EU region (approved by ergin)
usage:    5 calls, 0 tokens, $0.0000
budget:   calls 3%, usd 0%, bytes 100% of the approved envelope
outcome:  5 allowed, 1 denied, 0 asked
warnings: bytes at 80%, bytes at 95%
denied:   crm.search ×1
exceeded: YES — the run hit a budget ceiling
```

`--json` prints the same thing as one line, which is the form a console ingests:

```json
{
  "run": "nightly-2026-09-12",
  "from": 1789178401000,
  "to": 1789178414000,
  "entryCount": 9,
  "head": "6a5900e535789622d82e8b78374597e412d95c016fa408401697fcff01da0ea6",
  "chainOk": true,
  "plan": {
    "purpose": "nightly CRM export for the EU region",
    "approvedBy": "ergin",
    "budget": { "calls": 200, "usd": 5, "bytes": 20000000, "seconds": 3600 },
    "warnAt": [0.8, 0.95]
  },
  "usage": { "calls": 5, "tokens": 0, "usd": 0, "bytes": 20000000 },
  "consumed": { "calls": 0.025, "usd": 0, "bytes": 1 },
  "allowed": 5,
  "denied": 1,
  "asked": 0,
  "warnings": [
    { "dimension": "bytes", "threshold": 0.8, "used": 16000000, "limit": 20000000 },
    { "dimension": "bytes", "threshold": 0.95, "used": 20000000, "limit": 20000000 }
  ],
  "deniedTools": { "crm.search": 1 },
  "exceeded": true
}
```

The three fields to sort a fleet by: **`exceeded`** (a call was refused because a budget ceiling was reached), **`consumed`** (fraction of each budgeted dimension used — `bytes: 1` is 100% of the approved envelope), and **`deniedTools`** (which tools were refused, and how often). `chainOk: false` means the file did not verify; `receipt` still prints — a receipt over a broken chain has to say what it saw — but exits `1` so a CI step cannot accept it.

`summarize` is **pure**: a function of the chain alone, no I/O and no clock. The same entries always produce the same receipt, so one recomputed during an audit can be compared byte for byte with the one issued at the time.

```ts
import { readFileSync } from 'node:fs';
import { summarize } from 'shortleash';

const entries = readFileSync('./audit.jsonl', 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const receipt = summarize(entries);
if (receipt.exceeded || receipt.denied > 0) escalate(receipt);
```

One accounting detail worth knowing. Each entry records usage **as of the decision**, before the call it authorises is counted, so the last entry's call count always lags by one. `usage.calls` in a receipt is therefore the count of allowed entries, not the last entry's figure — otherwise every receipt would read "9 allowed, 8 calls", which a reviewer notices immediately. Tokens, dollars and bytes still come from the last entry, since metering lands there between calls. Leash's own `leash:plan` and `leash:warning` entries are excluded from `allowed`/`denied`/`asked`.

---

## Anchoring

Here is the hole that `verify` alone cannot close.

**Verifying a chain in isolation cannot detect that its tail was cut off.** A prefix of a valid chain is itself a valid chain: every link intact, every hash correct, `seq` running 1..n. An agent that deletes its last twenty entries hands you a log that passes.

```
leash verify truncated.jsonl
ok: 6 entries verified
head: 4cd48e58f9b83f20a143534960983d5d72062507d8c356b35b2292845ce479cd
```

Exit `0`. Three calls and both budget warnings are gone, and nothing inside the file says so.

What closes it is a receipt issued at the time, kept somewhere else. `leash anchor` appends one receipt line — including the head — to an append-only file:

```
leash anchor audit.jsonl --to anchors.jsonl
```

```
anchored run nightly-2026-09-12 (head 6a5900e535789622d82e8b78374597e412d95c016fa408401697fcff01da0ea6) to anchors.jsonl
note: an anchor only proves anything where the agent cannot rewrite it.
```

`leash verify --against` then runs **two** checks and reports them separately, because only the second can catch a truncation and an operator has to see which one failed:

```
leash verify audit.jsonl --against anchors.jsonl
ok: chain check — 9 entries verified
ok: anchor check — head matches the receipt anchored for run nightly-2026-09-12
head: 6a5900e535789622d82e8b78374597e412d95c016fa408401697fcff01da0ea6
```

The same command on the truncated log:

```
leash verify truncated.jsonl --against anchors.jsonl
ok: chain check — 6 entries verified
FAILED: anchor check — log does not match the anchored receipt (6 entries read)
  seq:    6
  reason: broken-link
  detail: chain head 4cd48e58f9b8 does not match the receipt's head 6a5900e53578 (6 entries present, receipt recorded 9)
```

Exit `1`. The head quoted at the time cannot be reached by any shorter or rewritten chain. A run with no anchor at all fails too, rather than passing quietly:

```
FAILED: anchor check — no receipt for run "nightly-2026-09-12" in anchors.jsonl
  detail: an unanchored run cannot be shown to be complete
```

Anchoring the same run more than once is normal — mid-run and again at the end. The **last** matching line for a run wins, because the newest receipt is the strongest claim about how far the chain got. `anchor` refuses to write at all if the chain does not verify.

The programmatic form is `verifyAgainstReceipt(entries, receipt)`, which returns the same `VerifyResult` shape as `verifyChain`.

### The part Leash cannot do for you

**An anchor is only worth something where the agent cannot rewrite it.** An anchor file sitting next to the audit file, writable by the same process, is not evidence — an attacker who truncates one can truncate the other. Leash cannot enforce where the anchor lives. It can only make putting it there one command:

```
leash anchor audit.jsonl --to /mnt/worm/anchors.jsonl   # a volume the agent's user can append to and not rewrite
```

Another host, an object store with object-lock or append-only retention, a log pipeline under credentials the agent process does not hold, a ticket, a colleague's inbox. Pick by asking who has to be convinced. [`docs/threat-model.md`](docs/threat-model.md) lays out the options in ascending order of effort.

---

## What Leash is not

Being straight about the boundary is worth more than overclaiming.

- **It does not inspect prompts or model output.** There is no classifier, no jailbreak detector, no content filter. Leash sees tool names and arguments, and nothing else.
- **It cannot stop an allowed tool from doing something harmful.** If your policy permits `fs.write` under `/srv/workspace/`, Leash will let the agent write nonsense there all day. The policy is the security boundary; Leash only enforces it faithfully.
- **It is not a network egress filter.** `urlHosts` constrains a *URL-shaped argument you chose to constrain*. A tool that opens its own sockets is invisible to Leash. If you need egress control, you need it at the network layer.
- **It governs the tool boundary only.** Anything a tool does internally, anything the model does without calling a tool, and anything another process on the host does are all outside its remit.
- **The audit log is tamper-evident, not tamper-proof.** An attacker with write access to the file can rewrite the entire chain consistently, and the result verifies perfectly. Nothing inside a file distinguishes an honest chain from a consistently forged one. Evidence requires that the head hash be anchored somewhere they do not control. See [`docs/threat-model.md`](docs/threat-model.md).
- **`verify` alone cannot detect truncation.** A prefix of a valid chain is a valid chain. Only `verify --against` an anchored receipt catches a tail that was cut off — and only if the anchor lives somewhere the agent cannot rewrite. Leash cannot enforce that; it can only make putting it there one command.
- **A bytes ceiling bounds a run at the limit plus one call, not at the limit.** A result's size is not knowable before the tool runs, so the breaching call completes and the next one is refused. It bounds iteration, not a single oversized response.
- **Byte measurement under-counts an unserialisable result.** A cyclic object or a throwing `toJSON` falls back to its string form, which is usually much smaller than the data it holds. This fails open, and is documented rather than hidden.
- **`approvedBy` is recorded, not verified.** A plan's approver is a string Leash writes into the chain. It is evidence of what the policy file claimed, not proof that a particular human agreed.
- **A warning is a report, not a control.** Crossing a `warnAt` threshold refuses nothing. The budget does the refusing, at 100%.
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

- [`docs/policy-reference.md`](docs/policy-reference.md) — exhaustive constraint reference, the `plan` block, and common policies.
- [`docs/threat-model.md`](docs/threat-model.md) — what Leash defends against, what it does not, and how to anchor the audit chain.
- [`docs/python.md`](docs/python.md) — the Python package (`shortleash`, imports as `leash`), its API, and the chain-compatibility guarantee.

## Licence

Apache License 2.0. See [`LICENSE`](LICENSE).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The short version: no new runtime dependencies, and any change to enforcement semantics needs a test that fails without it.
