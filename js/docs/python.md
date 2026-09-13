# Toolwrit for Python

The Python port lives in [`python/`](../../python) and is published to PyPI as **`toolwrit`**, the same name as the npm package.

```bash
pip install toolwrit
```

Python 3.10 or newer. One runtime dependency (`pyyaml`). Apache-2.0.

This document covers what is different. The policy language, the decision ladder, the threat model and the design rationale are identical, clause for clause — read [`policy-reference.md`](policy-reference.md) and [`threat-model.md`](threat-model.md) for those, and note only the divergences listed below.

---

## 60-second start

```python
from toolwrit import Toolwrit, ToolwritDenied, load_policy_file

toolwrit = Toolwrit(
    load_policy_file("./toolwrit.yaml"),
    audit_file="./audit.jsonl",
)

try:
    result = toolwrit.guard("fs.read", {"path": "/srv/workspace/notes.md"}, lambda: read_file())
except ToolwritDenied as denied:
    # Hand the boundary back to the model so it can adapt.
    result = {"is_error": True, "text": str(denied)}

toolwrit.meter(1200, 300, {"input": 0.003, "output": 0.015})  # USD per 1,000 tokens
toolwrit.spend(0.02)

print(toolwrit.usage())
# BudgetUsage(calls=1, tokens=1500, usd=0.0281, bytes=8, started_at=1789035198799)
print(toolwrit.head())  # a 64-char sha256 — the head of this run's audit chain
```

The policy is the **first positional argument**; everything else is keyword-only.

---

## API

### `Toolwrit`

```python
Toolwrit(
    policy,                       # Policy — required, positional
    *,
    run="run-2026-09-12-a",       # str  — stamped on audit entries; a uuid4 when omitted
    audit_file="./audit.jsonl",   # str  — append entries here; they are buffered either way
    redact=["headers.authorization"],  # Sequence[str] — dotted paths blanked before hashing
    on_ask=confirm_with_human,    # (ToolCall, Decision) -> bool | Awaitable[bool]
    on_warn=lambda w: post(w.message),  # (BudgetWarning) -> None
    now=lambda: 1789178401000,    # () -> int — injectable clock, ms since epoch
)
```

| Method | Returns | Notes |
| --- | --- | --- |
| `check(tool, args=None)` | `Decision` | Evaluates without recording or executing. |
| `guard(tool, args, execute)` | `T` | Synchronous. Evaluate, record, then call `execute()`. Raises `ToolwritDenied` on refusal. |
| `await guard_async(tool, args, execute)` | `T` | Same, awaiting an async `execute` and an async `on_ask`. Plain functions work unchanged. |
| `meter(input_tokens, output_tokens, price=None)` | `None` | `price` is a `TokenPrice` or a plain mapping, USD per **1,000** tokens. |
| `spend(usd)` | `None` | Non-token spend. |
| `usage()` | `BudgetUsage` | `calls`, `tokens`, `usd`, `bytes`, `started_at`. |
| `entries()` | `list[AuditEntry]` | The chain recorded so far. |
| `head()` | `str` | Hash of the newest entry — what an anchor commits to. |

`ToolwritDenied` carries `.tool`, `.decision` and `.audit_hash`.

### Naming

Methods and module-level functions are `snake_case`; **policy field names stay exactly as they are in the YAML**, which means `camelCase` on the dataclasses. This is not an oversight — the dataclasses are the serialised policy, and renaming a field here would break the chain, since the plan entry commits to `approvedBy` and `warnAt` as written.

```python
from toolwrit import RunPlan, BudgetLimits, ArgConstraint

RunPlan(purpose="nightly CRM export", approvedBy="ergin", warnAt=[0.8, 0.95])
BudgetLimits(calls=200, usd=5.0, bytes=20_000_000, seconds=3600)
ArgConstraint(startsWith=["/srv/workspace/"], excludes=[".."], maxLength=200)
```

`BudgetUsage.started_at` is the one exception: it is runtime state, never serialised into a policy, so it follows Python convention.

### Exports

```python
from toolwrit import (
    Toolwrit, ToolwritDenied, ApprovalHandler,
    evaluate, load_policy_file, parse_policy, validate_policy, PolicyError,
    matches_glob, matches_any_glob, resolve_path, MISSING,
    Ledger, TokenPrice,
    AuditLog, AuditLogOptions, AuditEntry, canonicalize, hash_entry,
    entry_to_dict, entry_from_dict, GENESIS,
    verify_chain, verify_file, VerifyResult, VerifyFailure,
    ArgConstraint, BudgetLimits, BudgetUsage, BudgetWarning, Decision, Effect,
    EvalContext, HistoryEntry, Policy, PolicyRule, RateLimit, RunPlan,
    ToolCall, Violation,
)
```

---

## The sync/async split

TypeScript has one `guard`, because `await` is available from any function. Python cannot await from a synchronous frame, so there are two:

```python
# Ordinary functions, ordinary on_ask.
rows = toolwrit.guard("crm.search", {"q": "eu"}, lambda: db.query(...))

# An async tool, an async on_ask, or both. Plain functions are accepted here too.
rows = await toolwrit.guard_async("crm.search", {"q": "eu"}, lambda: client.search("eu"))
```

`guard_async` awaits whatever it is given: it awaits the result of `execute()` if it is awaitable, and the result of `on_ask` if that is a coroutine. Passing an **async `on_ask` to the synchronous `guard` raises `TypeError` rather than guessing**:

```
TypeError: the configured on_ask handler is asynchronous; use guard_async
```

The coroutine is closed rather than left dangling, so there is no "never awaited" warning and nothing of the handler's body has run.

Both paths run the same evaluate → record → enforce → measure sequence, in the same order, and produce identical audit entries. Only the calling convention differs.

---

## Run plans and the bytes ceiling

Both are implemented here and behave identically, including the wording of every message.

```yaml
budget:
  calls: 200
  usd: 5.00
  bytes: 20000000
  seconds: 3600

plan:
  purpose: nightly CRM export for the EU region
  approvedBy: ergin
  warnAt: [0.8, 0.95]
```

```python
toolwrit = Toolwrit(
    load_policy_file("./export.yaml"),
    run="nightly-2026-09-12",
    audit_file="./audit.jsonl",
    on_warn=lambda w: print("on_warn ->", w.message),
)
```

```
on_warn -> run "nightly-2026-09-12" (nightly CRM export for the EU region) has used 16,000,000/20,000,000 bytes — 80% of the approved envelope
on_warn -> run "nightly-2026-09-12" (nightly CRM export for the EU region) has used 20,000,000/20,000,000 bytes — 100% of the approved envelope
call 6: toolwrit: crm.search denied — data budget exhausted: 20000000/20000000 bytes returned by tools
```

The `toolwrit:plan` entry is written by the constructor, before anything can be guarded, exactly as in TypeScript. Thousands separators and percentage rounding in the message text go through a reimplementation of the ECMAScript number algorithm (`toolwrit._js`) rather than Python's `repr`, so the two produce byte-identical warning strings — which matters, because the message is inside the hashed entry.

Result sizes are measured as: `None` → 0; `str` → its UTF-8 byte length; `bytes`/`bytearray`/`memoryview` → their length; anything else → the UTF-8 byte length of its **canonical** JSON. Sorting keys reorders bytes but adds and removes none, so this equals what TypeScript gets from `JSON.stringify`. A value that cannot be serialised falls back to `str(result)` and is therefore **under-counted** — the same documented fail-open as in TypeScript.

The same ordering limitation applies: a result's size is unknowable before the tool runs, so the breaching call completes and the **next** one is refused. A bytes ceiling bounds a run at the limit plus one call.

---

## What is not ported

| | TypeScript | Python |
| --- | --- | --- |
| Policy engine, constraints, globs, budgets, plans, bytes | yes | yes |
| Audit chain, redaction, `verify` | yes | yes |
| `toolwrit check` / `explain` / `verify` | yes | yes |
| `toolwrit run` (the MCP stdio proxy) | yes | **no** |
| Anthropic / OpenAI SDK adapters | yes | **no** |
| Run receipts (`summarize`, `verifyAgainstReceipt`) | yes | **no** |
| `toolwrit receipt` / `toolwrit anchor` / `verify --against` | yes | **no** |

`toolwrit run` exits 1 and says so:

```
toolwrit: `toolwrit run` (the MCP proxy) is not part of the Python port; use the TypeScript CLI for it
```

`toolwrit receipt` and `toolwrit anchor` are not subcommands here at all, and exit 1 with the usage text.

`toolwrit verify --against <anchor>` is likewise not implemented in Python, and it **refuses rather than ignoring the flag**:

```
$ toolwrit verify truncated.jsonl --against anchors.jsonl
toolwrit: `verify --against <anchor>` is not implemented in the Python CLI; the chain
check alone cannot detect a truncated log, so use the TypeScript CLI
(`toolwrit verify <file> --against <anchor>`) rather than reading this run as a pass
$ echo $?
1
```

That refusal is the point. A chain check on its own cannot detect a truncated log — a prefix of a valid chain is itself a valid chain — so a Python `verify` that accepted `--against`, dropped it, and printed `ok` with exit 0 would report a pass on exactly the log the flag exists to catch. Every subcommand now rejects flags it does not implement for the same reason.

Use the TypeScript CLI for receipts and anchoring. It reads chains written by Python; that is the whole point of the shared canonical form.

Because the chains are compatible, none of this blocks you: **run the TypeScript CLI over a Python-written log.** This works and is the recommended path for receipts and anchoring in a Python deployment:

```
toolwrit receipt audit.jsonl                        # written by toolwrit for Python
toolwrit anchor  audit.jsonl --to anchors.jsonl
toolwrit verify  audit.jsonl --against anchors.jsonl
```

---

## Chain compatibility

**A log written by either implementation verifies with the other, and the entry hashes are equal.** Not merely "both say ok" — the same run, same clock, same calls produces the same 64-character hash for every entry, and in the common case the two files are byte-identical.

```
$ node .../js/dist/cli.js verify audit-py.jsonl     # TypeScript over a Python log
ok: 9 entries verified
head: 6a5900e535789622d82e8b78374597e412d95c016fa408401697fcff01da0ea6

$ toolwrit verify audit.jsonl                            # Python over a TypeScript log
ok: 9 entries verified
head: 6a5900e535789622d82e8b78374597e412d95c016fa408401697fcff01da0ea6
```

`toolwrit receipt` and `toolwrit anchor` from the TypeScript package read a Python-written chain without any conversion step, plan and warning entries included.

The hard part is numbers. JavaScript has one numeric type and prints it with `Number::toString`: `1.0` is `"1"`, `1e21` is `"1e+21"`, `1e16` is `"10000000000000000"`. Python's `repr` keeps the `.0` and switches to exponent notation at a different magnitude. `toolwrit._js` implements the ECMAScript algorithm directly, and the port's `test_audit.py` pins the values one at a time. `tests/test_interop.py` builds the same chain with both implementations and asserts the hashes are equal, which no pair of mutually incompatible serialisers could manage.

---

## Behavioural divergences

Behaviour is otherwise identical. These are the exceptions, and **none of them loosens a policy**.

### `None` is `null`, not `undefined`

JavaScript has two empty values and `JSON.stringify` treats them differently: `null` is serialised, `undefined` is dropped. Python has one. Since `decision.rule` is legitimately `null` on every default-deny and the TypeScript chain commits to it, `canonicalize` **keeps** `None` as `null` — dropping it would break the chain outright. The "drop me" meaning is carried by an explicit `toolwrit._js.UNDEFINED` sentinel instead.

The visible consequence is in constraints: an argument key present but set to `None` counts as **absent**, so it fails a non-`optional` constraint with a `required` violation. TypeScript calls `{"path": None}` a present null and reports a `type` violation instead. Both refuse the call; only the violation name differs.

### Regexes are Python regexes

A `matches:` pattern is compiled with `re`, not V8's `RegExp`. The common syntax is shared, but the dialects diverge on named groups (`(?P<x>)` vs `(?<x>)`), lookbehind, and the Unicode semantics of `\d` and `\w`. A policy shared between the two implementations should stay inside the common subset.

### URLs are parsed with `urllib.parse`

With an explicit absolute-URL gate — scheme required, declared authority must exist — standing in for the throw that WHATWG `new URL()` performs. The tested behaviour matches, including the `https://example.com@evil.com/` case. Two untested corners differ: an IPv6 host comes back as `::1` rather than `[::1]`, and an internationalised domain is not converted to punycode, so an IDN `urlHosts` entry must be written in the same form the argument uses.

### YAML is YAML 1.1

PyYAML implements 1.1; the TypeScript `yaml` package implements 1.2. The difference a policy author can hit is bare `yes`/`no`/`on`/`off`, which PyYAML reads as booleans and the TypeScript reads as strings. Quote them. JSON parses identically under both.

### The JSONL byte layout differs cosmetically

Within a violation object this port writes `path` last where the TypeScript writes it second. The canonical form sorts keys, so hashes are unaffected and each implementation verifies the other's file; only a byte-for-byte `diff` of two logs containing path-bearing violations shows it.

---

## Development

```bash
cd python
pip install -e '.[test]'
python -m pytest
```

The cross-language tests need `node` and a built copy of the TypeScript implementation; they look for it at `../js` or at `$TOOLWRIT_TS_ROOT`, and skip when it is absent.
