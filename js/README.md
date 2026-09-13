# toolwrit

A written authority for AI agents. Allowlist the tools, cap the budget, prove
what happened.

This is the TypeScript package. The Python port publishes under the same name
on PyPI and writes a compatible audit chain — a log from either verifies with
the other.

**Full documentation, the threat model and the policy reference live in the
repository: https://github.com/emektor/toolwrit**

## 60-second start

```
npm install toolwrit
```

Until the first release is published, install from the repository instead —
`git clone https://github.com/emektor/toolwrit && npm install ./toolwrit/js`,
which builds on install.

The package installs a binary of the same name, `toolwrit`. The Python port is
`pip install toolwrit` — same policy language, same chain; see
[`docs/python.md`](https://github.com/emektor/toolwrit/blob/main/js/docs/python.md).

**`toolwrit.yaml`**

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
import { Toolwrit, ToolwritDenied, loadPolicyFile } from 'toolwrit';

const toolwrit = new Toolwrit({
  policy: loadPolicyFile('./toolwrit.yaml'),
  auditFile: './audit.jsonl',
});

// before:  const result = await tools[name](args);
// after:
const result = await toolwrit.guard(name, args, () => tools[name](args));
```

That is the whole integration. `guard` evaluates the call, writes the decision to the audit chain, and only then invokes your handler. A refusal throws `ToolwritDenied` — never a silently skipped side effect:

```ts
try {
  return await toolwrit.guard(name, args, () => tools[name](args));
} catch (err) {
  if (err instanceof ToolwritDenied) {
    // Hand the boundary back to the model so it can adapt.
    return { isError: true, content: [{ type: 'text', text: err.message }] };
  }
  throw err;
}
```

Metering is explicit, because the pricing assumption should be visible in your code rather than guessed by ours:

```ts
toolwrit.meter(inputTokens, outputTokens, { input: 0.003, output: 0.015 }); // USD per 1k tokens
toolwrit.spend(0.02);                                                       // non-token spend
```

And at the end of the run:

```ts
console.log(toolwrit.usage()); // { calls: 1, tokens: 1500, usd: 0.0281, bytes: 512, startedAt: 1789035198799 }
console.log(toolwrit.head());  // a 64-char sha256 — the head of this run's audit chain
```

---

## The MCP one-liner

Put it in front of an MCP server you already run, without touching that
server's code:

```
toolwrit run --policy toolwrit.yaml -- node my-mcp-server.js
```

Every `tools/call` is checked before it is forwarded. A refusal comes back to
the agent as a tool error naming the constraint that failed, so the model can
read the boundary and adapt, rather than as a protocol error that would kill
its turn.

## What it does not do

It governs the tool boundary. It does not read prompts or model output, it is
not a network egress filter, and it cannot survive its own host being
compromised. The audit log is tamper-*evident*, not tamper-proof: anchor the
head hash somewhere the agent cannot reach, or it proves nothing.

The full list, including the findings from two independent security reviews and
the one that is still open, is in
[`SECURITY-REVIEW.md`](https://github.com/emektor/toolwrit/blob/main/SECURITY-REVIEW.md).

## Licence

Apache-2.0.
