# Policy reference

A Leash policy is a YAML or JSON document. It is loaded with `loadPolicyFile(path)`, or handed to the CLI with `--policy`. Validation is strict: unknown keys are a hard error, because a silently ignored `startWith` would turn a scoped filesystem rule into an unscoped one.

Everything here is checked against the engine's actual behaviour. Where the implementation is subtler than it looks, this document says so.

---

## Document shape

```yaml
version: "1"          # required, must be the string "1"
name: my-agent        # optional label, carried into audit exports
default: deny         # optional; allow | deny | ask. DEFAULTS TO deny.

budget:               # optional, run-scoped ceilings
  calls: 100
  tokens: 500000
  usd: 5.00
  seconds: 900

rules:                # required array (may be empty)
  - id: some-rule
    description: Why this exists
    tools: ["fs.read"]
    effect: allow
    when:
      path: { startsWith: ["/srv/workspace/"] }
    limit: { max: 20, perSeconds: 60 }
```

`version` must be the **string** `"1"`. Unquoted `version: 1` is the number 1 in YAML and is rejected.

Rule `id`s must be unique within the document. Duplicates are a load error, because ids are how rate-limit counts are attributed and how audit entries name their decision.

---

## The decision ladder

`evaluate(call, ctx)` is a pure function of policy, call and ledger state. No clock reads, no I/O, no model. The same inputs always yield the same `Decision`.

1. **Budget.** Checked first, before any rule. An exhausted budget denies everything. Order within the budget: `calls`, `tokens`, `usd`, `seconds`; the first at-or-over its limit produces the violation.
2. **Rule matching.** For each rule, in document order: does any glob in `tools` match the tool name? If so, do all of `when`'s constraints hold against the arguments? Rules passing both are *matched*.
3. **Rate limits.** Any matched rule whose `limit` is spent denies immediately.
4. **Effect precedence.** Among matched rules, `deny` beats `ask` beats `allow`. **Document order does not break ties across effects** — you cannot shadow a deny by putting an allow above it. Within a single effect, the first matching rule in document order supplies the id and description.
5. **Fallthrough.** No matched rule at all falls through to `default`, which is `deny` unless set.

### Near-misses

When a rule targeted the tool but its constraints rejected the arguments, and nothing else allowed the call, the resulting denial reports **that rule's violations** rather than a bare "no rule matched":

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

This is deliberate: the model is told *which argument* was wrong and can retry inside the boundary instead of guessing.

Note that `rule` is `null` here. `rule` names the rule that *decided*, and a near-miss is decided by the default, not by the rule that nearly matched. The near-missing rule appears in `violations[].rule`.

**Only non-deny rules contribute near-misses.** A `deny` rule whose constraints do not hold is simply inapplicable, and reporting it would tell the model how to slip past a prohibition. Such a call falls through to the plain form:

```json
{
  "effect": "deny",
  "rule": null,
  "reason": "no rule allows tool \"t\"",
  "violations": [
    { "rule": "policy", "constraint": "default", "message": "tool \"t\" is not in the policy; the default effect is deny" }
  ]
}
```

---

## Tool globs

`tools` is a non-empty array of patterns. Matching is whole-string and case-sensitive.

| Token | Meaning |
| --- | --- |
| `*` | Any run of characters **except** the separators `.` and `/` |
| `**` | Anything, separators included |
| anything else | Literal |

```yaml
tools: ["fs.read"]        # exactly fs.read
tools: ["fs.*"]           # fs.read, fs.write — but NOT fs.read.raw
tools: ["fs.**"]          # fs.read, fs.read.raw, fs.a.b.c
tools: ["github/*"]       # github/create_issue
tools: ["**"]             # every tool
```

The common mistake is writing `tools: ["*"]` for "everything". It does not match `fs.read`, because `*` will not cross a `.`. Use `**`.

An empty `tools` array is a load error, not a match-nothing rule.

---

## Argument paths

`when` is keyed by dotted paths resolved against the argument object.

| Path | Resolves against `{ "body": { "to": ["a@x.com"] } }` |
| --- | --- |
| `body` | the object |
| `body.to` | the array |
| `body.to.0` | `"a@x.com"` |
| `body.cc` | *missing* |
| `body.to.7` | *missing* |

Numeric segments index arrays. A path that runs off the end of the object, indexes past the end of an array, or passes through a `null` resolves to *missing* rather than throwing — a malformed model argument becomes a policy violation, not a crash.

**Missing fails everything except `optional`.** If the path does not resolve and the constraint does not say `optional: true`, you get:

```json
{ "rule": "mail", "path": "subject", "constraint": "required",
  "message": "argument \"subject\" is required but was not provided" }
```

This is the fail-closed posture applied to arguments: an allow rule cannot be satisfied by *omitting* the argument it constrains.

All constraints in `when` must hold. `when` is an AND across paths and an AND across the constraints on each path. There is no OR — express alternatives as separate allow rules.

---

## Constraints, one at a time

Every example below is a complete, loadable policy fragment with the calls it accepts and refuses.

### `optional`

Allow the argument to be absent. Default `false`. When the value *is* present, every other constraint still applies.

```yaml
- id: mail
  tools: ["mail.send"]
  effect: allow
  when:
    priority: { optional: true, oneOf: ["low", "normal"] }
```

| Call | Result |
| --- | --- |
| `{}` | allow — absent is fine |
| `{"priority": "low"}` | allow |
| `{"priority": "urgent"}` | deny — `oneOf` |

### `type`

Runtime type check: `string`, `number`, `boolean`, `object`, `array`. `array` matches only arrays; `object` matches non-null non-array objects.

```yaml
when:
  count: { type: number, max: 100 }
```

A type mismatch **short-circuits**: no other constraint on that path is evaluated or reported, because downstream checks would be meaningless.

| Call | Violation |
| --- | --- |
| `{"count": 50}` | — |
| `{"count": "50"}` | `type`: `argument "count" must be a number, got string` |

Constraints that do not apply to the value's runtime type are silently inert — `min` against a string is not checked. **Pair a bound with `type` whenever the type itself matters**, otherwise `{"count": "9999"}` sails past a `max: 100`.

### `oneOf` / `noneOf`

Deep equality, so objects and arrays work as members, not just scalars.

```yaml
when:
  mode:   { oneOf: ["read", "list"] }
  target: { noneOf: ["production", "prod"] }
```

| Call | Violation |
| --- | --- |
| `{"mode": "read", "target": "staging"}` | — |
| `{"mode": "delete", ...}` | `oneOf`: `argument "mode" must be one of ["read","list"]` |
| `{"mode": "read", "target": "prod"}` | `noneOf`: `argument "target" must not be "prod"` |

`noneOf` is a denylist inside an allow rule. Prefer a separate `effect: deny` rule when the prohibition is important — that survives someone later adding a second, laxer allow rule.

### `matches`

A JavaScript regular expression, applied to string values only.

```yaml
when:
  to.0: { matches: "@acme\\.com$" }
```

| Call | Violation |
| --- | --- |
| `{"to": ["a@acme.com"]}` | — |
| `{"to": ["a@evil.com"]}` | `matches`: `argument "to.0" must match /@acme\.com$/` |

**It is not anchored for you.** `matches: "admin"` matches `"superadmin-tools"`. Write `^…$` when you mean the whole string. In YAML, a backslash inside a double-quoted scalar must itself be escaped (`"\\."`); single-quoted scalars pass backslashes through unchanged (`'\.'`).

The pattern is compiled at load time, and an invalid regex is a load error rather than a runtime surprise.

### `startsWith`

Value must begin with one of the listed prefixes. This is the filesystem-scoping primitive.

```yaml
when:
  path:
    startsWith: ["/srv/workspace/"]
    excludes: [".."]
```

| Call | Violation |
| --- | --- |
| `{"path": "/srv/workspace/notes.md"}` | — |
| `{"path": "/etc/passwd"}` | `startsWith`: `argument "path" must start with one of ["/srv/workspace/"]` |
| `{"path": "/srv/workspace/../../etc/passwd"}` | `excludes` |

Keep the trailing slash. `startsWith: ["/srv/workspace"]` also admits `/srv/workspace-evil/`.

`startsWith` is a **string** check, not a path check. It does not resolve symlinks and it does not normalise `.` or `..` — pair it with `excludes: [".."]`, and remember that a tool which resolves symlinks internally can still escape a prefix that looked safe. Argument scoping constrains what the agent may *ask for*; it does not constrain what the filesystem does with the request.

### `excludes`

Value must not contain any of these substrings. A cheap, honest traversal guard.

```yaml
when:
  command: { excludes: ["..", "|", ";", "$("] }
```

| Call | Violation |
| --- | --- |
| `{"command": "ls -la"}` | — |
| `{"command": "ls; rm -rf /"}` | `excludes`: `argument "command" must not contain ";"` |

Do not mistake this for shell-injection defence. It is a blunt substring filter, and denylists over an infinite input space always lose. Scope with `startsWith`/`oneOf` and let `excludes` be a backstop.

### `urlHosts`

Value must parse as a URL whose hostname appears in the list. An unparseable string fails.

```yaml
when:
  url: { urlHosts: [".example.com", "docs.python.org"] }
```

| Call | Result |
| --- | --- |
| `https://api.example.com/v1` | allow — subdomain of `.example.com` |
| `https://example.com/` | allow — a leading dot covers the apex too |
| `https://docs.python.org/3/` | allow — exact match |
| `https://evil.com/x` | deny — `host "evil.com" is not in the allowed set [".example.com","docs.python.org"]` |
| `not a url` | deny — `argument "url" is not a parseable URL` |

**The leading-dot convention.** An entry starting with `.` matches that domain *and every subdomain*: `.example.com` covers `example.com` and `api.example.com`. Anything else must match the hostname exactly, so an allowlist never widens by accident:

| Entry | `example.com` | `api.example.com` | `notexample.com` |
| --- | --- | --- | --- |
| `example.com` | match | — | — |
| `.example.com` | match | match | — |

Hostname comparison is case-insensitive on both sides. Only the hostname is checked — not the scheme, port or path. If you need `https` only, add `matches: "^https://"` alongside.

### `min` / `max`

Inclusive numeric bounds, applied to numbers only.

```yaml
when:
  amount_usd: { type: number, min: 0, max: 100 }
```

| Call | Violation |
| --- | --- |
| `{"amount_usd": 100}` | — (inclusive) |
| `{"amount_usd": 100.01}` | `max`: `argument "amount_usd" must be <= 100, got 100.01` |
| `{"amount_usd": "100"}` | `type` — and without `type: number`, no violation at all |

### `minLength` / `maxLength`

Inclusive bounds on `.length`, applied to strings and arrays.

```yaml
when:
  subject:     { type: string, minLength: 1, maxLength: 120 }
  attachments: { optional: true, type: array, maxLength: 3 }
```

| Call | Violation |
| --- | --- |
| `{"subject": "hi"}` | — |
| `{"subject": "x" * 200}` | `maxLength`: `argument "subject" must have length <= 120, got 200` |
| `{"subject": "hi", "attachments": [1,2,3,4]}` | `maxLength`: `argument "attachments" must have length <= 3, got 4` |

Useful as a blast-radius cap: a `maxLength` on a recipients array turns "email the customer" into something that cannot become "email every customer".

---

## Rate limits

```yaml
- id: search
  tools: ["web.search"]
  effect: allow
  limit: { max: 2, perSeconds: 60 }
```

| Field | Meaning |
| --- | --- |
| `max` | Non-negative integer. Maximum calls attributed to this rule within the window. |
| `perSeconds` | Positive number. Sliding window in seconds. **Omit for "per run"** — an unbounded window. |

Three properties to internalise:

- **Counting is per rule id**, not per tool. Two rules matching the same tool have independent counters, and renaming a rule resets its counter.
- **Denied calls do not count.** The history the engine reads excludes denials, so being refused does not burn quota.
- **The window slides** against the call's own timestamp. Once the oldest calls fall outside `perSeconds`, capacity returns.

When the limit is spent:

```json
{
  "effect": "deny",
  "rule": "search",
  "reason": "rate limit exhausted for rule \"search\"",
  "violations": [
    { "rule": "search", "constraint": "limit",
      "message": "rule \"search\" allows 2 call(s) per 60s; 2 already used" }
  ]
}
```

Omitting `perSeconds` renders the window as `this run` in that message. `max: 0` means "never" — a way to mothball a rule without deleting it, keeping its id stable in your audit history.

Rate limits are the answer to the runaway loop. An agent stuck retrying `web.search` forever is not a security failure, it is a bill; `limit` turns it into a bounded one.

---

## Budgets

```yaml
budget:
  calls: 100
  tokens: 500000
  usd: 5.00
  seconds: 900
```

All fields optional, each a positive number. Checked before every rule, using `>=` — `calls: 100` permits calls 1 through 100 and refuses the 101st.

| Field | Fed by | Message on exhaustion |
| --- | --- | --- |
| `calls` | every permitted `guard()` | `call budget exhausted: 2/2 calls used` |
| `tokens` | `meter(input, output)` | `token budget exhausted: 1500/1000 tokens used` |
| `usd` | `meter(..., price)` and `spend(usd)` | `spend budget exhausted: $1.5000/$1.0000 used` |
| `seconds` | wall clock from the first metered event | `time budget exhausted: 301.0s/300s elapsed` |

Leash cannot see your model calls, so nothing enters the ledger by itself:

```ts
leash.meter(inputTokens, outputTokens, { input: 0.003, output: 0.015 }); // USD per 1,000 tokens
leash.spend(0.02); // a metered third-party API call
```

`price` is per **1,000** tokens, and defaults to `{ input: 0, output: 0 }` — calling `meter()` without a price table counts tokens but never accrues dollars. A `usd` budget with no priced `meter()` and no `spend()` is inert.

The `seconds` clock starts at the first metered event — the first permitted call, `meter()` or `spend()` — not at process start. A run that sits idle for an hour before doing anything gets its full time budget.

Budget violations report `rule: null` and `violations[0].rule: "budget"`, distinguishing them from rule denials at a glance in the audit log.

---

## Approval: the `ask` effect

```yaml
- id: refunds
  description: Refunds over $100 need a human
  tools: ["billing.refund"]
  effect: ask
  when:
    amount_usd: { type: number, min: 100.01 }
```

```ts
const leash = new Leash({
  policy,
  onAsk: async (call, decision) => confirmWithOperator(call.tool, call.args, decision.reason),
});
```

The handler receives the `ToolCall` and the `Decision`, and returns (or resolves to) a boolean.

**Without an `onAsk` handler, `ask` denies.** An unattended run must never silently upgrade itself to allowed:

```
leash: billing.refund denied — Refunds over $100 need a human (no approval handler configured)
```

```json
{ "rule": "refunds", "constraint": "ask",
  "message": "this call requires approval but no onAsk handler was configured; denying by default" }
```

A refusal from the handler reads:

```
leash: billing.refund denied — Refunds over $100 need a human (approval refused)
```

An approval turns the decision into an allow with `(approved)` appended to the reason, and the audit entry records the allow — so the chain shows the human's decision, not just the policy's.

Note that `ask` beats `allow` in precedence. A tool covered by both an `ask` rule and an `allow` rule always asks. Write the narrow `ask` rule for the dangerous case and a broad `allow` for the rest, and the ladder sorts it out:

```yaml
- id: refunds-large
  tools: ["billing.refund"]
  effect: ask
  when: { amount_usd: { type: number, min: 100.01 } }
- id: refunds-small
  tools: ["billing.refund"]
  effect: allow
  when: { amount_usd: { type: number, min: 0, max: 100 } }
```

Give the `ask` rule a `description`. It is the text your operator reads at 3am when the approval prompt fires.

---

## Common policies

### Read-only agent

The safest useful agent: it can look at things and cannot change any of them.

```yaml
version: "1"
name: read-only-agent
default: deny

budget:
  calls: 200
  seconds: 600

rules:
  - id: read
    description: Read and list within the workspace
    tools: ["fs.read", "fs.list", "fs.stat"]
    effect: allow
    when:
      path:
        type: string
        startsWith: ["/srv/workspace/"]
        excludes: [".."]

  - id: no-secrets
    description: Credential material is off limits even inside the workspace
    tools: ["fs.**"]
    effect: deny
    when:
      path:
        matches: "(\\.env|\\.pem$|id_rsa|/\\.git/|credentials)"

  - id: search-docs
    description: Documentation lookups only
    tools: ["http.get"]
    effect: allow
    when:
      url:
        urlHosts: [".example.com", "docs.python.org", "developer.mozilla.org"]
    limit: { max: 30, perSeconds: 60 }
```

Everything not named — `fs.write`, `shell.exec`, anything a future MCP server adds — is denied by the default. That is the point of deny-by-default: the policy does not need updating when the tool surface grows.

The `no-secrets` deny rule uses `fs.**` rather than `fs.*` so it also covers `fs.read.raw`-style nested names. Deny rules should always be written *wider* than the allow rules they backstop.

### Coding agent scoped to a directory

```yaml
version: "1"
name: coding-agent
default: deny

budget:
  calls: 500
  usd: 10.00
  seconds: 3600

rules:
  - id: repo-read
    description: Read anything in the repo
    tools: ["fs.read", "fs.list"]
    effect: allow
    when:
      path:
        type: string
        startsWith: ["/srv/repo/"]
        excludes: [".."]

  - id: repo-write
    description: Write only under src/ and test/
    tools: ["fs.write", "fs.mkdir"]
    effect: allow
    when:
      path:
        type: string
        startsWith: ["/srv/repo/src/", "/srv/repo/test/"]
        excludes: [".."]

  - id: protect-ci
    description: CI config and lockfiles are changed by humans, not agents
    tools: ["fs.write", "fs.delete", "fs.move"]
    effect: deny
    when:
      path:
        matches: "(/\\.github/|/\\.git/|package-lock\\.json$|Dockerfile$|\\.env)"

  - id: build-and-test
    description: Only the project's own build commands
    tools: ["shell.exec"]
    effect: allow
    when:
      command:
        type: string
        oneOf: ["npm run build", "npm test", "npm run typecheck"]
      cwd:
        optional: true
        startsWith: ["/srv/repo"]
    limit: { max: 40 }

  - id: open-pr
    description: Opening a PR is fine; merging is not
    tools: ["github/create_pull_request"]
    effect: allow
    when:
      base: { oneOf: ["main"] }
      head: { type: string, matches: "^agent/" }
    limit: { max: 3 }
```

Three ideas worth stealing here:

- **Read wide, write narrow.** `repo-read` covers the whole repo; `repo-write` covers two subdirectories. The agent can understand the codebase without being able to rewrite its own CI.
- **`oneOf` for shell, never a pattern.** An allowlist of exact command strings is the only shell policy that holds. The moment you reach for `matches` on a command line, you have started playing a game you lose.
- **`limit` on the irreversible things.** `max: 3` on PR creation, with no `perSeconds`, means three per run — a loop that discovers PR creation cannot produce three hundred of them.

Note `protect-ci` denies `fs.write` under paths that `repo-write` would otherwise allow. Deny beats allow, regardless of order, so `/srv/repo/src/.env` is refused.

### Support agent with an approval threshold

```yaml
version: "1"
name: support-agent
default: deny

budget:
  calls: 60
  usd: 1.00

rules:
  - id: lookup
    description: Read customer records
    tools: ["crm.get_customer", "crm.get_order", "crm.search"]
    effect: allow
    limit: { max: 40 }

  - id: refund-small
    description: Refunds up to $100 are automatic
    tools: ["billing.refund"]
    effect: allow
    when:
      amount_usd: { type: number, min: 0, max: 100 }
      order_id:   { type: string, matches: "^ord_[a-z0-9]+$" }
    limit: { max: 5, perSeconds: 3600 }

  - id: refund-large
    description: Refunds over $100 require a human approval
    tools: ["billing.refund"]
    effect: ask
    when:
      amount_usd: { type: number, min: 100.01 }

  - id: no-account-changes
    description: Account and credential changes are never agent-initiated
    tools: ["crm.update_account", "crm.delete_customer", "auth.**"]
    effect: deny

  - id: reply
    description: Reply to the customer, one message, capped length
    tools: ["mail.send"]
    effect: allow
    when:
      to:      { type: array, maxLength: 1 }
      subject: { type: string, minLength: 1, maxLength: 120 }
      body:    { type: string, maxLength: 4000 }
```

```ts
const leash = new Leash({
  policy: loadPolicyFile('./support.yaml'),
  auditFile: `./audit/${runId}.jsonl`,
  redact: ['api_key', 'headers.authorization'],
  onAsk: (call, decision) =>
    escalateToQueue({ tool: call.tool, args: call.args, why: decision.reason }),
});
```

The `to: { maxLength: 1 }` constraint is the important line. A support agent that can email one person is a support agent; one that can email an array is a mailing-list incident waiting for a bad prompt.

If the approval queue is unstaffed and `onAsk` is omitted, every large refund is denied rather than approved. That is the correct failure direction, and it is the default.

### Research agent with a hard dollar cap

```yaml
version: "1"
name: research-agent
default: deny

budget:
  calls: 300
  tokens: 2000000
  usd: 25.00
  seconds: 7200

rules:
  - id: search
    description: Web search, throttled
    tools: ["web.search"]
    effect: allow
    when:
      query: { type: string, minLength: 1, maxLength: 400 }
    limit: { max: 60, perSeconds: 300 }

  - id: fetch
    description: Fetch pages over https only
    tools: ["web.fetch", "http.get"]
    effect: allow
    when:
      url:
        type: string
        matches: "^https://"
    limit: { max: 200 }

  - id: no-internal
    description: Never reach internal or link-local addresses
    tools: ["web.fetch", "http.**"]
    effect: deny
    when:
      url:
        matches: "(localhost|127\\.0\\.0\\.1|169\\.254\\.|\\.internal|\\.local)"

  - id: notes
    description: Write findings to the notes directory
    tools: ["fs.write"]
    effect: allow
    when:
      path:
        type: string
        startsWith: ["/srv/research/notes/"]
        excludes: [".."]
```

```ts
// After every model turn — this is what makes the usd budget real.
leash.meter(usage.input_tokens, usage.output_tokens, { input: 0.003, output: 0.015 });
// Metered third-party APIs.
leash.spend(0.01);
```

The cap only binds if you call `meter()`. Wire it into the same place you already read token usage from your model response, and the 301st dollar becomes impossible rather than merely unlikely.

`no-internal` is a *best-effort* SSRF backstop, not an egress control. It inspects a URL-shaped argument; a tool that follows a redirect, resolves a hostname to a private address, or opens its own socket is outside Leash's view. Real SSRF defence lives in the network layer. See [`threat-model.md`](threat-model.md).

---

## Testing a policy in CI

`leash check` evaluates one hypothetical call and exits `0` for allow, `1` for deny, `2` for ask. Assert both directions:

```bash
#!/usr/bin/env bash
set -euo pipefail
P=./leash.yaml

expect() {  # expect <exit-code> <description> -- <args...>
  local want=$1 desc=$2; shift 3
  local got=0; leash check --policy "$P" "$@" >/dev/null 2>&1 || got=$?
  [[ "$got" == "$want" ]] || { echo "FAIL: $desc (exit $got, wanted $want)"; exit 1; }
}

expect 0 "reads inside workspace"  -- --tool fs.read  --args '{"path":"/srv/workspace/a.md"}'
expect 1 "no reads outside"        -- --tool fs.read  --args '{"path":"/etc/passwd"}'
expect 1 "no traversal"            -- --tool fs.read  --args '{"path":"/srv/workspace/../../etc/passwd"}'
expect 1 "unknown tools denied"    -- --tool shell.exec
expect 1 "no dotenv"               -- --tool fs.read  --args '{"path":"/srv/workspace/.env"}'
expect 2 "large refunds ask"       -- --tool billing.refund --args '{"amount_usd":500}'
echo "policy ok"
```

Weight the suite toward refusals. Allowlists rot in the permissive direction — nobody files a bug because the agent was allowed to do something.

`leash explain --policy leash.yaml` prints a human-readable summary of the same document, which is the artefact to paste into a change review when the policy is edited.

---

## Authoring checklist

- `default` is `deny`, or you have written down why it is not.
- Deny rules are wider than the allow rules they backstop (`fs.**`, not `fs.*`).
- Every path prefix ends in `/`, and is paired with `excludes: [".."]`.
- Every numeric or length bound that matters is paired with `type`.
- Every `matches` that means "the whole string" is anchored with `^…$`.
- Shell and other command arguments use `oneOf`, not a pattern.
- Irreversible tools have a `limit`.
- The budget's `usd`/`tokens` fields are backed by real `meter()` calls.
- Sensitive argument paths are listed in `redact`.
- `ask` rules have a `description` an operator can act on, and a real `onAsk` handler in production.
- CI asserts the refusals, not only the permissions.
