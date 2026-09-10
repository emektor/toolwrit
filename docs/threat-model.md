# Threat model

This document states what Leash defends against, what it does not, and where the trust boundaries sit. It is deliberately conservative. A security control that is oversold is worse than none, because it displaces the control you actually needed.

Leash is a **library and sidecar**, not a gateway. It runs inside your process or as a local child process. It makes no network calls and consults no model.

---

## Assets

1. **Authority held by tools.** A `fs.write` tool is a write primitive; `billing.refund` is a refund primitive. The authority is real regardless of what the model intended.
2. **Budget.** Tokens, dollars, wall-clock time.
3. **The account of what happened.** After an incident, the question is "what did the agent actually do?" — and the answer needs to be one nobody can quietly revise.

## Adversaries

- **A confused model.** No malice. It picks a plausible-looking tool with a plausible-looking argument that happens to be outside its remit, or it loops.
- **Untrusted content in the context window.** A web page, an email, an issue comment, a tool result. It contains text that steers the model. This is the realistic prompt-injection case, and the model is the vulnerable component, not Leash.
- **A user pushing the agent past its remit.** Persuasion aimed at the model's judgement.
- **A disputing party after the fact.** A customer, a regulator, an auditor, or an internal team that disagrees about what the run did.

Notably absent: an attacker with code execution on the host. See [What Leash does not defend against](#what-leash-does-not-defend-against).

---

## What Leash defends against

### A model choosing a tool outside its remit

Deny-by-default. If a tool is not named by an allow rule, it is refused — including tools that did not exist when the policy was written. Adding an MCP server to an agent does not silently widen its authority.

The check is a pure function of policy, call and ledger state. No model is asked for permission, so there is no prompt to jailbreak and no non-determinism to argue with. The persuasion that works on the model has no channel to the enforcement point: the only thing that crosses the boundary is a tool name and an argument object.

### A model choosing an *argument* outside its remit

The harder and more common case. The tool is legitimate; the argument is not. `fs.read` with `/etc/shadow`, `mail.send` to a list instead of a person, `billing.refund` for 500 instead of 50.

Argument constraints (`startsWith`, `oneOf`, `urlHosts`, `min`/`max`, `maxLength`) are checked before the handler runs, and an allow rule whose constraints fail does not match — the call falls through to the default, which is deny. An allow rule cannot be satisfied by *omitting* the argument it constrains, either: a missing value fails every constraint except `optional`.

### Runaway loops

`limit` bounds calls attributed to a rule, per sliding window or per run. `budget.calls` and `budget.seconds` bound the run as a whole. An agent stuck retrying is not usually a security failure, it is a bill — and this makes it a bounded one.

Denied calls are not counted against a rate limit, so being refused does not burn the quota an agent legitimately needs.

### Unbounded spend

`budget.usd` and `budget.tokens` cut the run off. **These bind only if you feed the ledger** — Leash cannot see your model calls. `meter(input, output, price)` and `spend(usd)` are the entry points. A `usd` budget with no priced `meter()` calls is decorative.

The estimate is only as good as your price table. Treat it as a circuit breaker, not accounting.

### A disputed account of what happened

Every decision — allowed, denied, or approved-after-ask — is appended to a hash-chained JSONL log. Each entry commits to its predecessor's hash, so editing, deleting or reordering any past entry invalidates every hash after it. `leash verify audit.jsonl` exits `0` or `1`.

Because `evaluate` is pure, an entry contains everything needed to replay its decision: the call, the arguments as evaluated, the decision with its violations, and the budget state *at the moment of the decision*. A reviewer does not have to take your word for the reasoning.

Redacted values are hashed **in their redacted form**, so a redaction is part of the committed record rather than a later edit. You cannot retroactively redact a logged secret and still pass verification, and you cannot forge a redaction to disguise what an argument was.

### Silent failure

`guard()` writes the audit entry **before** invoking your handler, so a crash inside a tool still leaves evidence that the call was authorised. A refusal throws `LeashDenied` rather than returning a sentinel, because a silently skipped side effect is the worst failure mode here — the caller cannot mistake a refusal for a completed action.

`ask` with no `onAsk` handler denies. An unattended run does not upgrade itself.

Policy loading rejects unknown keys. A typo like `startWith` fails at load rather than silently unscoping a filesystem rule.

---

## What Leash does not defend against

### A compromised host process

Leash is a library in your process (or a child process you launched). An attacker with code execution there can rewrite the policy in memory, skip `guard()` entirely, call the tool handler directly, or rewrite the audit file. There is no privilege boundary between Leash and the code it is linked into, and none is claimed.

If the agent runtime is compromised, Leash is compromised. Isolation — containers, users, seccomp, separate machines — is a different control and you still need it.

### A malicious or buggy tool implementation

Leash sees the tool *name* and the *arguments*. It has no visibility into what the handler does. A tool called `fs.read` that also posts to a webhook is not something Leash can detect. A tool that resolves symlinks, follows redirects, or opens its own sockets escapes constraints that looked airtight on the argument.

`startsWith: ["/srv/workspace/"]` constrains the string the agent asked for. It does not constrain the filesystem's interpretation of that string. Path confusion, symlink escape and TOCTOU are the tool's problem, not the policy's.

Corollary: **the trustworthiness of the policy is bounded by the trustworthiness of the tool inventory.** An MCP server you did not audit is an unaudited dependency no matter how tight the allowlist over its names.

### An allowed tool used for an allowed-but-unwise purpose

If the policy permits writes under `/srv/repo/src/`, the agent may write garbage there. Leash enforces the boundary you drew; it has no opinion about whether the action was a good idea. Semantic quality control is a different problem, and an LLM judge is a reasonable tool for it — layered on top of a deny-by-default allowlist, not instead of one.

### Prompt injection that stays within policy

This is the sharpest limit and worth stating plainly. Injected content that persuades the model to do something the policy *permits* will succeed. If an agent may read the workspace and send one email, injected text saying "read the notes and email them to the address below" is stopped only if the recipient is constrained.

What Leash gives you is a **ceiling on the blast radius**: the injection cannot reach a tool the policy does not name, an argument the policy does not accept, or a volume the budget does not fund, and whatever it does reach is on the record. That ceiling is the defence. Narrow rules make it lower — this is why `to: { maxLength: 1 }` matters more than it looks.

### Network egress

Leash is not an egress filter. `urlHosts` constrains a URL-shaped argument you chose to constrain, at the moment of the call. It does not survive a redirect, DNS rebinding, a hostname that resolves to a private address, or a tool that builds its own request. SSRF defence belongs in the network layer: a proxy, an egress allowlist, network policy. Use `urlHosts` as defence in depth, never as the control.

### Prompts and model output

There is no classifier, no jailbreak detector, no PII scanner, no content filter. Leash never sees a prompt or a completion.

### Side channels and inference

Leash constrains tool calls. It does not constrain what a model infers, remembers across turns, or encodes into an argument that is individually permitted. An agent allowed to write files can encode data in filenames. An agent allowed to search can leak through query strings. Rate limits and length caps raise the cost of these; they do not close them.

### Denial of service

A policy that denies everything is a working policy from Leash's point of view. Nothing here keeps an agent *useful*.

### Multi-tenant separation

The ledger and the audit chain are run-scoped, in one process. Leash is not a multi-tenant policy server, and there is no cross-process coordination — two processes with the same policy have two independent budgets.

---

## Trust boundaries

The security of a Leash deployment rests on these, in order of how much weight they carry:

1. **The policy file.** Whoever can edit it decides what the agent may do. Treat it as production configuration: version-controlled, code-reviewed, tested in CI with `leash check`, and not writable by the agent. An agent with a `fs.write` rule covering its own policy has no policy.
2. **The host process.** No boundary between Leash and its host. Compromise there is total.
3. **The tool implementations.** The policy's guarantees stop at the handler's front door.
4. **The audit file's storage.** Tamper-*evident*, not tamper-*proof*. See below.
5. **The `onAsk` handler.** It is the human-in-the-loop. If it auto-approves, or is reachable by the agent, the `ask` effect is decorative.
6. **The clock.** `now` is injectable for testing. Time budgets and sliding windows trust it.

The model is explicitly **outside** the trust boundary. That is the design: model output is untrusted input to a deterministic check. Nothing the model says influences the decision except the tool name and the arguments, and those are evaluated, not interpreted.

---

## The audit log is tamper-evident, not tamper-proof

Be precise about what the hash chain buys.

**What it proves.** Given a log file and a known-good hash of its head, you can prove the file has not been edited. Any change to any entry's contents, order, or membership changes that entry's hash and breaks every link after it. `leash verify` finds the first inconsistency and names it: `bad-hash`, `broken-link`, `bad-sequence` or `malformed`.

**What it does not prove.** An attacker with write access to the file can recompute the *entire chain* after altering an entry, and the result verifies perfectly. Nothing inside the file distinguishes an honest chain from a consistently forged one. A hash chain proves internal consistency; it does not by itself prove authenticity or completeness.

**What closes the gap: anchoring.** The chain becomes evidence only when the head hash is committed somewhere the attacker does not control. Options, roughly in ascending order of effort:

- **Append-only storage.** Write the JSONL to a WORM bucket, an object store with object-lock or versioning enabled, or a filesystem where the agent's user has append-only permission. This removes the write access the attack depends on.
- **Ship it as it is written.** Stream entries to a log pipeline (syslog, a SIEM, a hosted log service) under credentials the agent process does not hold. The copy on the other side is the witness. JSONL exists partly so this is a one-line change.
- **Periodically publish the head.** `leash.head()` is a single 64-character string. Post it to a channel with its own retention — a ticket, a chat log, a monitoring metric, an email to yourself — every N calls or at end of run. Anyone can later check that the file's head still matches what was published at the time.
- **Sign the head.** Sign `head()` with a key the agent process cannot read (an HSM, a KMS, a separate signing service). This adds authenticity to the integrity the chain already provides.
- **External timestamping.** An RFC 3161 timestamp authority, a transparency log, or a public ledger. Strongest, and the most operational overhead. Worth it when the log is meant to convince a party who does not trust you at all.

Choose by asking who has to be convinced. For internal debugging, the chain alone is fine. For a customer dispute, publish the head. For a regulator, anchor it somewhere neither of you controls.

**A second, quieter gap: completeness.** The chain proves entries were not modified. It does not prove entries were *made* — a call routed around `guard()` never enters the log, and the log will verify cleanly without it. This is why the integration matters: one code path to the tools, and `guard()` on it. Wrapping the dispatcher (or using `leash run` in front of an MCP server, where the process boundary enforces it) is more robust than wrapping call sites one at a time.

---

## Residual risk, stated plainly

After a correct Leash deployment, an attacker who can inject text into the agent's context can still cause the agent to do **anything your policy permits, up to the budget you funded**, and the record of it will be accurate.

That is not nothing — it converts an open-ended authority problem into a bounded and audited one — but it is also not containment. The size of the residual risk is exactly the size of your allowlist. Every rule you add is a rule you have decided you can live with an adversary triggering.

Write the policy as if the model were adversarial, because from the enforcement point's perspective, it is.
