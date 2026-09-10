# shortleash

A deterministic leash for AI agents. Allowlist the tools, cap the budget, prove
what happened.

This is a Python port of [Leash](../leash). **The full documentation lives in
the main project's [README](../leash/README.md)** — the policy language, the
threat model and the design rationale are the same here, clause for clause.
What follows is only what a Python user needs on top of that.

```bash
pip install shortleash          # imports as `leash`
```

```python
from leash import Leash, LeashDenied, load_policy_file

leash = Leash(load_policy_file("policy.yaml"), audit_file="audit.jsonl")

try:
    contents = leash.guard("fs.read", {"path": "/tmp/notes"}, lambda: read_file())
except LeashDenied as denied:
    print(denied.decision.reason, denied.audit_hash)

leash.meter(input_tokens=1200, output_tokens=350)
print(leash.head())   # the receipt for the run so far
```

```bash
leash check   --policy policy.yaml --tool fs.read --args '{"path":"/tmp/x"}'
leash explain --policy policy.yaml
leash verify  audit.jsonl
```

## Chain compatibility

An audit chain written here verifies under the TypeScript `leash verify`, and
one written there verifies here — same canonical string, same SHA-256, same
head hash. `tests/test_interop.py` proves it in both directions, and goes
further than "both say ok": it builds the same chain with both implementations
and asserts the entry hashes are equal, which no pair of mutually incompatible
serialisers could manage.

Getting there is mostly about numbers. JavaScript has one numeric type and
prints it with `Number::toString` — `1.0` is `"1"`, `1e21` is `"1e+21"`, `1e16`
is `"10000000000000000"` — where Python's `repr` keeps the `.0` and switches to
exponent notation at a different magnitude. `leash._js` implements the
ECMAScript algorithm directly; `test_audit.py` pins the values one by one.

## Differences from the TypeScript version

Behaviour is otherwise identical. These are the exceptions, and none of them
loosens a policy.

**`None` is `null`, not `undefined`.** JavaScript has two empty values and
`JSON.stringify` treats them differently: `null` is serialised, `undefined` is
dropped. Python has one. Since `decision.rule` is legitimately `null` on every
default-deny and the TypeScript chain commits to it, `canonicalize` **keeps**
`None` as `null` — dropping it would break the chain outright. The "drop me"
meaning is carried by an explicit `leash._js.UNDEFINED` sentinel instead.

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

**`leash run` is not ported.** The MCP stdio proxy and the Anthropic/OpenAI SDK
adapters stay in the TypeScript package; `leash run` here exits 1 and says so.
`check`, `explain` and `verify` behave identically, exit codes included.

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
implementation; they look for it at `../leash` or at `$LEASH_TS_ROOT`, and skip
when it is absent.

## Licence

Apache-2.0.
