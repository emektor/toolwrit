# Independent review: findings, fixes, and what remains

Two independent reviews were run against this codebase in September 2026. One
attacked the enforcement guarantees directly; the other read it as the engineer
who would have to maintain it. Neither reviewer was allowed to fix anything, so
every finding below was reported before any code changed, and every one was
reproduced again before it was acted on.

This is published because a security library that only advertises its successes
is asking to be trusted on faith. Everything found is here, including the four
things that are still open — if you are deciding whether to run this in front
of your own tools, the open list is the part you need.

---

## Summary

| | |
|---|---|
| Findings reproduced | 11 |
| Fixed and covered by tests | 8 |
| Open, one of them mitigated | 3 |
| Tests before review | 343 TypeScript · 448 Python |
| Tests after | **387 TypeScript · 464 Python** |

Three of the seven fixed were failures of a guarantee the product is sold on.

---

## Fixed

### 1. The MCP proxy enforced nothing on an id-less call — CRITICAL

`tools/call` was only intercepted when the message carried an `id`. A call
shaped like a notification fell straight through to the downstream server,
unguarded and unaudited.

```
same policy, same tool, same argument:
  with an id     fs.delete /etc/passwd  ->  DENIED, server never saw it
  without an id  fs.delete /etc/passwd  ->  [SERVER] EXECUTED
```

The entire policy was bypassable by omitting one field, in the feature the
product leads with. Every `tools/call` is now enforced; a refused notification
is dropped and reported to the operator, since nothing is waiting for a reply.
Three tests pin it: missing id, `null` id, missing tool name.

### 2. The Python verifier did not detect fields added to an entry — CRITICAL

It rebuilt each entry into a dataclass before rehashing, silently discarding
any key it did not recognise. An appended top-level `note`, or a forged
`decision.approvedBy`, vanished before the hash was recomputed.

```
one tampered file:
  TypeScript  ->  bad-hash, exit 1
  Python      ->  ok,       exit 0
```

A verifier that only notices edits to fields it already expected is not a
tamper detector. The Python verifier now hashes the object exactly as parsed,
matching TypeScript.

### 3. One bad metering call disabled a budget permanently and silently — HIGH

The ledger validated nothing, and every ceiling test is `used >= limit`. A
single `NaN` makes that false forever.

```
meter(undefined, 300)   ->  tokens = NaN
200,000 tokens against a 1,000 ceiling  ->  ALLOW
spend(-9)               ->  reopens a spent budget
```

Both ledgers now reject non-finite, non-numeric and negative consumption with
an exception. A metering bug has to surface, not quietly switch a limit off.

### 4. Concurrent calls through an `ask` rule all passed a budget of one — HIGH

The decision was evaluated, the approval handler awaited, and only then was the
call recorded and counted. Three simultaneous guards against `calls: 1`
snapshotted the same empty ledger, were all approved, and all executed — the
realistic way to drive a human-gated irreversible tool N times in one burst.

Deciding, recording and counting is now one serialized critical section in both
languages. The tool still runs outside it, and the common path never awaits
inside it, so nothing serializes unless an approval is genuinely pending.

### 5. `toolwrit run` always exited 0 — MEDIUM

A crashed downstream server, a clean shutdown and a command that could not be
spawned were indistinguishable to anything supervising the process. The proxy
now carries the child's status back out: its own exit code, 128+n for a signal,
127 when it could not be started.

### 6. `stop()` never settled after a failed spawn — MEDIUM

A process that fails to spawn emits `error` and never `exit`, so `stop()`
awaited an event that could not arrive and a CLI shutting down after a bad
command hung instead of exiting. Found by the new proxy tests.

### 7. Claims the code did not support — MEDIUM

Corrected in the README, the policy reference and the landing page:

- The landing page called a stylised transcript "real output". It is now an
  abridged excerpt of `examples/filesystem.mjs`, which ships in the repo.
- The page's sample policy used `50_000_000`, which YAML 1.2 does not parse —
  the advertised example did not load in the implementation it advertised.
- "byte-identical audit chains" overstated it. The canonical form and the
  hashes are identical; the files can differ cosmetically in field order.
- "CI proves it on every commit" — CI had never run.
- The docs still said a constraint against a wrong type was "inert". It has
  failed closed since the bypass fix; they now say so.
- Python `explain` omitted `bytes`, so the two CLIs printed different budget
  lines for the same policy.

---

## Open — pinned as tests, not fixed

Each is reproduced and covered by a test that documents the real behaviour.

### A. ReDoS through an attacker-supplied argument value — HIGH, mitigated

`matches` patterns are compiled at load but run against untrusted argument
strings. A plausible author-written pattern with nested quantifiers hung both
implementations on a 44-character value:

```
matches: "^(([a-zA-Z0-9]+)+@)+example\.com$"
value  : "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@@@@@@@@@@@@"   -> >10s, both languages
```

`evaluate` is synchronous and on the hot path, so one such argument stalls the
enforcement point.

**Mitigated, not eliminated.** A policy carrying that shape is now rejected at
load, in both implementations, with the offending quantifier named. The check is
structural rather than timed, deliberately: rejecting a pattern for running
slowly would make acceptance depend on the machine and the regex engine, so the
same policy could load in one implementation and fail in the other — and "the
same policy always reaches the same verdict" is the property this library exists
for. Both implementations were checked against a twenty-pattern corpus and agree
on every one.

It catches the classic nested-quantifier family, not every pathological pattern.
The real fix is a linear-time engine, which would cost the single-dependency
property — a trade worth a decision rather than a reflex, so it is on the
roadmap rather than made quietly. The docs steer authors to `startsWith`,
`oneOf` and `excludes`, which cannot backtrack at all.

### B. `Date` and other `toJSON` arguments fail their own verify — MEDIUM

The canonicaliser treats objects structurally (`Date` → `{}`) while the JSONL
line is written with `JSON.stringify`, which honours `toJSON`. On reload the two
disagree and an entirely honest run reports `bad-hash` — a false tamper alarm,
which in a trust product is its own kind of damage. Affects arguments carrying
`Date`, Decimal.js, Luxon, BigNumber or Mongo ObjectId. Plain JSON arguments,
which is what an MCP server delivers, are unaffected.

### C. Parser divergences between the implementations — MEDIUM

The cross-language chain is real, but a few verdicts differ:

```
http://evil.com\@allowed.com/   TypeScript: DENY (host evil.com)
                                Python:     ALLOW (host allowed.com)
```

Browsers and curl agree with TypeScript; Python's `urllib` reads the backslash
literally. A known SSRF-allowlist trick, and the Python port is on the unsafe
side of it. Also: `$` in Python matches before a trailing newline and in
JavaScript does not, and the TypeScript glob `**` fails to match a tool name
containing a newline. `urlHosts` is documented as defence-in-depth rather than
a primary control, which caps the severity but does not excuse it.

### D. A pipelined client can overrun the bytes ceiling — MEDIUM

A result's size is unknowable before the tool runs, so with four `tools/call`
messages written in a single batch, all four are decided against `bytes: 0`.
Measured: a 100-byte ceiling overrun to more than 2,000. Bounded by the
client's pipeline depth, not unbounded, and the paired test shows the ceiling
holding correctly for a client that waits for each reply. The `calls` budget is
unaffected.

### E. Two smaller proxy defects

On downstream exit, the error reply carries no `id`, so a client with several
requests in flight learns something died but not which; and a pending
`tools/call` receives no reply at all, because its continuation runs after the
output stream was ended.

---

## What was attacked and held

Reported with the same specificity as the findings, because it is the more
useful half: it says where the guarantees actually hold.

- **Deny-by-default**, across unknown tools, known tools with no accepting
  rule, and `default: allow` behaving as documented.
- **Prototype pollution.** `resolvePath` uses `hasOwnProperty`, not `in`:
  `__proto__`, `constructor` and `toString` all resolve to MISSING; a JSON body
  `{"__proto__": {"path": "..."}}` does not shadow a real argument; a redaction
  path of `__proto__.polluted` does not touch `Object.prototype`.
- **`urlHosts` against its classic attacks.** `https://allowed.com@evil.com/`,
  `#allowed.com`, `%2F@`, tab-in-userinfo, trailing-dot, IPv6, punycode and
  port garbage were all denied in both languages. The leading-dot suffix match
  does not widen to `notexample.com`.
- **Canonicalisation.** Keys containing quotes, backslashes, newlines and a
  lone surrogate serialise identically; UTF-16 key ordering matches JavaScript;
  a differential fuzz of 4,000+ doubles including subnormals and `1e21` found
  no mismatch between the implementations.
- **The proxy against smuggling.** Method-casing variants, JSON batch arrays,
  and id-less and null-id calls were all refused or not executed.
- **Redaction.** Hashed in redacted form, not forgeable retroactively, and the
  caller's own object is left untouched.
- **Fail-closed paths.** `ask` with no handler denies; unknown policy fields
  are rejected at load in both languages; a wrong-typed argument is a violation
  rather than a skipped check.

---

## Honest reading

The deterministic core held up under direct attack. What did not hold were the
edges: a proxy written last and tested never, a verifier that trusted its own
reader, and a ledger that trusted its caller. That is a recognisable shape —
the interesting part was reviewed hardest and the plumbing was not — and it is
worth knowing that the three most serious findings were all in the plumbing.

Three findings remain open, and the ReDoS one is mitigated at the policy boundary. None is a design flaw; each is bounded, reproducible
and documented in place. Fixing ReDoS *properly* is the only one that would change an architectural
decision, because a linear-time engine costs the single-dependency property.

An earlier fail-open, found by the project's own test suite during development
rather than by these reviewers, is described in the README and visible in the
commit history of this repository: a constraint applied to a wrong-typed argument was being
skipped, so an array slipped past a filesystem scope.
