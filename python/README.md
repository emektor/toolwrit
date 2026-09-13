# toolwrit

A written authority for AI agents. Allowlist the tools, cap the budget, prove
what happened.

This is the Python port of
[Toolwrit](https://github.com/emektor/toolwrit). **The full documentation lives
in the main project's docs** — the policy language, the threat model and the
design rationale are the same here, clause for clause:

- [the overview](https://github.com/emektor/toolwrit#readme) — run plans, the
  bytes ceiling, receipts and anchoring.
- [`policy-reference.md`](https://github.com/emektor/toolwrit/blob/main/js/docs/policy-reference.md) — every
  policy field with a worked example.
- [`threat-model.md`](https://github.com/emektor/toolwrit/blob/main/js/docs/threat-model.md) — what is and is
  not defended against.
- [`python.md`](https://github.com/emektor/toolwrit/blob/main/js/docs/python.md) — the Python-specific
  reference: the full API table, the sync/async split, and everything below in
  more detail.

What follows is only what a Python user needs on top of that.

```bash
pip install toolwrit
```

Until the first release is published:
`pip install "git+https://github.com/emektor/toolwrit.git#subdirectory=python"`

```python
from toolwrit import Toolwrit, ToolwritDenied, load_policy_file

toolwrit = Toolwrit(load_policy_file("policy.yaml"), audit_file="audit.jsonl")

try:
    contents = toolwrit.guard("fs.read", {"path": "/tmp/notes"}, lambda: read_file())
except ToolwritDenied as denied:
    print(denied.decision.reason, denied.audit_hash)

toolwrit.meter(1200, 350)          # input tokens, output tokens
print(toolwrit.usage())            # BudgetUsage(calls=…, tokens=…, usd=…, bytes=…, started_at=…)
print(toolwrit.head())             # the head of this run's audit chain
```

```bash
toolwrit check   --policy policy.yaml --tool fs.read --args '{"path":"/tmp/x"}'
toolwrit explain --policy policy.yaml
toolwrit verify  audit.jsonl
```

## Run plans

A `plan:` block declares the envelope a run is approved for, and it works here
exactly as it does in TypeScript.

```yaml
budget:
  calls: 200
  usd: 5.00
  bytes: 20000000
  seconds: 3600

plan:
  purpose: nightly CRM export for the EU region
  approvedBy: ergin
  warnAt: [0.8, 0.95]     # the default
```

The argument for declaring an envelope rather than setting a global threshold:
a global threshold has to guess at every job at once, so it is either too loose
to catch anything or too tight to leave switched on — and an alert people mute
is the same as no alert. A declared envelope does not guess. Approve once at
the start, hear nothing until a threshold.

```python
toolwrit = Toolwrit(
    load_policy_file("export.yaml"),
    run="nightly-2026-09-12",
    audit_file="audit.jsonl",
    on_warn=lambda w: print("on_warn ->", w.message),
)
```

```
on_warn -> run "nightly-2026-09-12" (nightly CRM export for the EU region) has used 16,000,000/20,000,000 bytes — 80% of the approved envelope
```

Two properties worth knowing:

- **The plan is entry 1 of the audit chain**, written by the constructor before
  anything can be guarded. What was *authorised* is in the tamper-evident record
  alongside what happened.
- **Each threshold fires at most once per dimension**, across `calls`, `tokens`,
  `usd`, `bytes` and `seconds`, and every warning is recorded in the chain as a
  `toolwrit:warning` entry as well as delivered to `on_warn`. Keep `on_warn`
  non-blocking; it runs inline with metering.

A `plan` requires a `budget` to measure against, `purpose` must be non-empty,
and `warnAt` entries must be greater than 0 and at most 1. All three are load
errors, with the same messages as the TypeScript implementation.

## The bytes ceiling

`budget.bytes` caps the total size of what tools **return** over a run. Bulk
exfiltration is rarely a forbidden action — it is a permitted action repeated
until something is drained, so every individual call passes the allowlist and
only the running total gives it away. Unlike `usd` and `tokens`, this dimension
needs no cooperation from your integration: `guard` and `guard_async` feed it.

```
call 5: ok, bytes now 20000000
call 6: toolwrit: crm.search denied — data budget exhausted: 20000000/20000000 bytes returned by tools
```

**The limitation, stated up front.** A result's size is not knowable before the
tool runs, so the measurement happens afterwards: the call that blows the
ceiling **completes**, and the **next** one is refused. A bytes ceiling bounds a
run at the limit *plus one call*, never exactly the limit. If one call can
return everything, cap the response at the tool.

Sizes: `None` → 0; `str` → its UTF-8 byte length; `bytes`/`bytearray`/
`memoryview` → their length; anything else → the UTF-8 byte length of its
canonical JSON, which equals what TypeScript gets from `JSON.stringify`. A
result that cannot be serialised falls back to `str(result)` and is therefore
**under-counted** — documented rather than hidden, because under-counting a
volume ceiling fails open.

## Receipts and anchoring: use the TypeScript CLI

Run receipts (`summarize`, `verifyAgainstReceipt`) and the `toolwrit receipt`,
`toolwrit anchor` and `toolwrit verify --against` subcommands are **not ported**.
Because the chains are compatible, that is not a blocker — point the TypeScript
CLI at a Python-written log:

```bash
toolwrit receipt audit.jsonl                        # written by toolwrit for Python
toolwrit anchor  audit.jsonl --to anchors.jsonl
toolwrit verify  audit.jsonl --against anchors.jsonl
```

This matters more than it sounds. Verifying a chain in isolation **cannot**
detect that its tail was cut off: a prefix of a valid chain is itself a valid
chain and verifies clean, so an agent that deletes its last twenty entries hands
you a log that passes. Comparing against a receipt anchored at the time closes
that hole — and only if the anchor lives where the agent cannot rewrite it,
which Toolwrit cannot enforce.

The Python `toolwrit verify` **refuses** `--against` rather than ignoring it:

```
$ toolwrit verify truncated.jsonl --against anchors.jsonl
toolwrit: `verify --against <anchor>` is not implemented in the Python CLI; ...
$ echo $?
1
```

Accepting the flag and dropping it would print `ok` and exit 0 on precisely the
truncated log the flag exists to catch — a fail-open in the one command whose
job is detecting tampering. Every subcommand rejects flags it does not
implement for the same reason. Use the TypeScript CLI for anchoring; it reads
chains written here.

## Chain compatibility

An audit chain written here verifies under the TypeScript `toolwrit verify`, and
one written there verifies here — same canonical string, same SHA-256, same
head hash. `tests/test_interop.py` proves it in both directions, and goes
further than "both say ok": it builds the same chain with both implementations
and asserts the entry hashes are equal, which no pair of mutually incompatible
serialisers could manage.

Getting there is mostly about numbers. JavaScript has one numeric type and
prints it with `Number::toString` — `1.0` is `"1"`, `1e21` is `"1e+21"`, `1e16`
is `"10000000000000000"` — where Python's `repr` keeps the `.0` and switches to
exponent notation at a different magnitude. `toolwrit._js` implements the
ECMAScript algorithm directly; `test_audit.py` pins the values one by one.

## Differences from the TypeScript version

Behaviour is otherwise identical. These are the exceptions, and none of them
loosens a policy.

**`None` is `null`, not `undefined`.** JavaScript has two empty values and
`JSON.stringify` treats them differently: `null` is serialised, `undefined` is
dropped. Python has one. Since `decision.rule` is legitimately `null` on every
default-deny and the TypeScript chain commits to it, `canonicalize` **keeps**
`None` as `null` — dropping it would break the chain outright. The "drop me"
meaning is carried by an explicit `toolwrit._js.UNDEFINED` sentinel instead.

The visible consequence is in constraints: an argument key present but set to
`None` counts as **absent**, so it fails a non-`optional` constraint with a
`required` violation. TypeScript would call `{"path": null}` a present null and
report a `type` violation instead. Both refuse the call; only the violation
name differs.

**`guard` is split in two.** Python cannot await from a synchronous frame, so
`guard(tool, args, execute)` serves ordinary functions and
`await guard_async(tool, args, execute)` awaits whatever it is given — an async
tool, an async `on_ask` handler, or plain functions unchanged. Passing an async
`on_ask` to the synchronous `guard` raises `TypeError` rather than guessing.

**`toolwrit run` is not ported.** The MCP stdio proxy and the Anthropic/OpenAI SDK
adapters stay in the TypeScript package; `toolwrit run` here exits 1 and says so.
`check`, `explain` and `verify` behave identically, exit codes included.

**Run receipts and anchoring are not ported.** There is no `summarize` or
`verify_against_receipt`, and no `receipt`, `anchor` or working `verify
--against` in this CLI. Use the TypeScript CLI over the Python-written log; see
the section above.

**Regexes are Python regexes.** A `matches:` pattern is compiled with `re`, not
V8's `RegExp`. The common syntax is shared, but the dialects diverge on named
groups (`(?P<x>)` vs `(?<x>)`), lookbehind and the Unicode semantics of `\d`
and `\w`. A policy shared between the two implementations should stay inside
the common subset.

**URLs are parsed with `urllib.parse`,** with an explicit absolute-URL gate
(scheme required, declared authority must exist) standing in for the throw that
WHATWG `new URL()` performs. The tested behaviour matches, including the
`https://example.com@evil.com/` case. Two untested corners differ: an IPv6 host
comes back as `::1` rather than `[::1]`, and an internationalised domain is not
converted to punycode, so an IDN `urlHosts` entry must be written in the same
form the argument uses.

**YAML is YAML 1.1.** PyYAML implements 1.1, the TypeScript `yaml` package
implements 1.2. The difference a policy author can hit is bare `yes`/`no`/
`on`/`off`, which PyYAML reads as booleans and the TypeScript reads as strings.
Quote them. JSON parses identically under both.

**The JSONL byte layout differs cosmetically.** Within a violation object this
port writes `path` last where the TypeScript writes it second. The canonical
form sorts keys, so the hashes are unaffected and each implementation verifies
the other's file; only a byte-for-byte `diff` of the two logs shows it.

## Development

```bash
pip install -e '.[test]'
python -m pytest
```

The cross-language tests need `node` and a built copy of the TypeScript
implementation; they look for it at `../js` or at `$TOOLWRIT_TS_ROOT`, and skip
when it is absent.

## Licence

Apache-2.0.
