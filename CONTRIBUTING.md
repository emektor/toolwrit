# Contributing to Leash

Thanks for looking. Leash is a security control, so the bar for changes is a little higher than for a typical utility library — but the process is short.

## Build and test

Node >= 20.

```
npm install
npm run build      # tsc -p tsconfig.json  ->  dist/
npm test           # tsc -p tsconfig.test.json && node --test dist-test/test/*.test.js
npm run typecheck  # tsc --noEmit
```

`npm test` compiles first, so a type error fails the test run. Run it before opening a pull request.

## The no-dependencies rule

Leash has **one** runtime dependency: `yaml`. Adding a second requires an issue and a strong argument first — not a pull request that already contains it.

The reason is not minimalism for its own sake. Leash is the thing that decides whether an agent may act, and it is installed by people who want a small, auditable amount of code between the model and their systems. Every transitive dependency is code they did not choose and a supply-chain surface they did not agree to.

In practice:

- Prefer the Node standard library. `node:crypto`, `node:fs` and `node:path` cover almost everything here.
- Prefer twenty lines of obvious code to a package. The glob matcher and the deep-equality check are deliberately hand-written and deliberately small.
- Dev dependencies (types, TypeScript) are fine. Test dependencies beyond `node:test` are not.

## Changes to enforcement semantics need a test that fails without them

Enforcement semantics means anything that can change a `Decision`: the precedence ladder, constraint evaluation, glob matching, path resolution, rate-limit or budget arithmetic, the audit chain, redaction, verification.

For any such change, include a test that **fails on `main` and passes with your change**. Say so in the pull request description, and say which behaviour the test pins. "Refactor, no behaviour change" is a claim a test should back up, not a reason to skip one.

Bias tests toward refusals. An allow that should have been a deny is a vulnerability; a deny that should have been an allow is a bug report. The failure modes are not symmetric, and neither should the test suite be.

Some things worth a test whenever you touch them:

- Deny beats ask beats allow, independent of rule order in the document.
- Unknown tool denies. Missing required argument denies. `ask` with no `onAsk` handler denies.
- A deny rule whose constraints do not hold does not leak into the near-miss violations.
- Budget and rate-limit boundaries are `>=`, so the limit-th call is permitted and the next one is not.
- Redacted arguments are hashed in their redacted form, and the chain still verifies.
- Any edit to an entry — contents, order, or membership — makes `verifyChain` fail with the right `reason`.

Determinism is a feature, not an implementation detail. `evaluate` must stay a pure function of policy, call and ledger state: no clock reads, no I/O, no randomness, no network, no model. If a change needs the time, it takes it from the `ToolCall`, and anything else needing a clock takes the injectable `now`.

## Policy schema changes

Validation rejects unknown keys on purpose. If you add a field, add it to the relevant key set in `src/policy/load.ts`, validate its type there, and document it in `README.md` and `docs/policy-reference.md` in the same pull request. An undocumented policy field is a bug.

Adding a field is a compatibility promise. Removing or narrowing one is a breaking change to a security policy someone is relying on — raise an issue first.

## Documentation

Every code sample, YAML snippet and API name in the docs must be correct against the source. If you change behaviour that a documented example demonstrates, update the example.

## Pull requests

- One concern per pull request.
- Describe the behaviour change first, the implementation second.
- Note explicitly whether enforcement semantics changed, and link the test that pins the new behaviour.

## Security issues

Do not open a public issue for a vulnerability — particularly a policy bypass, an argument-constraint escape, or anything that lets a forged audit chain pass `leash verify`. Report it privately to the maintainers and give us a chance to ship a fix first.

## Licence

By contributing you agree that your contributions are licensed under the Apache License 2.0, as in [`LICENSE`](LICENSE).
