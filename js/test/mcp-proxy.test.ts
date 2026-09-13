/**
 * The MCP stdio proxy — the place where policy actually stops a tool call.
 *
 * Every other test in this suite asks "would the engine refuse this?". This
 * one asks the only question that costs money when the answer is wrong: did
 * the call reach the downstream server? So the assertions here are made against
 * what a real child process *recorded receiving*, not against the reply the
 * client got back. A proxy that answers "denied" and forwards anyway would pass
 * a reply-only test and lose the whole trust boundary.
 *
 * The proxy is driven end to end: PassThrough streams for the client side and a
 * real fixture MCP server (test/fixtures/mcp-server.ts) spawned as a child, so
 * framing, spawning, routing and exit handling are exercised rather than mocked.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createMcpProxy, visibleTools } from '../src/adapters/mcp-proxy.js';
import { Toolwrit } from '../src/toolwrit.js';
import { parsePolicy } from '../src/policy/load.js';
import type { Policy } from '../src/types.js';
import { frozenClock } from './helpers.js';

/** The compiled fixture server lives next to the compiled tests. */
const FIXTURE = fileURLToPath(new URL('./fixtures/mcp-server.js', import.meta.url));

/** Every test gets its own timeout so a stuck child fails fast instead of hanging. */
const TIMEOUT = { timeout: 10_000 };

interface Message {
  jsonrpc?: unknown;
  id?: string | number | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: unknown;
  [key: string]: unknown;
}

function policyOf(yaml: string): Policy {
  return parsePolicy(yaml);
}

const ALLOW_ALL = policyOf('version: "1"\ndefault: allow\nrules: []\n');

interface Harness {
  /** Write messages to the client side. All of them land in a single write. */
  send(...messages: Message[]): void;
  /** Write raw bytes to the client side, bypassing JSON framing. */
  raw(text: string): void;
  /** Resolve once a message matching `pred` has been received by the client. */
  waitFor(pred: (m: Message) => boolean, what?: string): Promise<Message>;
  /** Send one request and wait for the reply carrying the same id. */
  call(message: Message & { id: string | number }): Promise<Message>;
  /** Everything the client has received so far, in order. */
  received: Message[];
  /** Raw lines the proxy wrote to the output stream, before parsing. */
  rawLines: string[];
  /** Errors emitted by the output stream (e.g. a write after it was ended). */
  outputErrors: Error[];
  /** Every message the downstream server actually received, in order. */
  serverLog(): Message[];
  toolwrit: Toolwrit;
  stop(): Promise<void>;
  exited(): Promise<number>;
}

interface ProxyOptions {
  policy?: Policy;
  /** Pass the policy to the proxy too, which turns on tools/list filtering. */
  filterList?: boolean;
}

async function withProxy(
  options: ProxyOptions,
  body: (h: Harness) => Promise<void>
): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), 'toolwrit-mcp-'));
  const logFile = join(dir, 'received.jsonl');
  writeFileSync(logFile, '');

  const policy = options.policy ?? ALLOW_ALL;
  const input = new PassThrough();
  const output = new PassThrough();

  const received: Message[] = [];
  const rawLines: string[] = [];
  const outputErrors: Error[] = [];
  const waiters: { pred: (m: Message) => boolean; resolve: (m: Message) => void }[] = [];

  output.on('error', (err: Error) => outputErrors.push(err));

  let buffer = '';
  output.on('data', (chunk: Buffer) => {
    buffer += chunk.toString('utf8');
    let index = buffer.indexOf('\n');
    while (index !== -1) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      index = buffer.indexOf('\n');
      if (line.length === 0) continue;
      rawLines.push(line);
      const message = JSON.parse(line) as Message;
      received.push(message);
      for (let i = waiters.length - 1; i >= 0; i--) {
        const waiter = waiters[i]!;
        if (waiter.pred(message)) {
          waiters.splice(i, 1);
          waiter.resolve(message);
        }
      }
    }
  });

  const toolwrit = new Toolwrit({ policy, now: frozenClock() });
  const proxy = createMcpProxy({
    toolwrit,
    command: process.execPath,
    args: [FIXTURE, logFile],
    input,
    output,
    ...(options.filterList ? { policy } : {}),
  });

  const harness: Harness = {
    send(...messages) {
      input.write(messages.map((m) => `${JSON.stringify(m)}\n`).join(''));
    },
    raw(text) {
      input.write(text);
    },
    waitFor(pred, what = 'a matching message') {
      const already = received.find(pred);
      if (already) return Promise.resolve(already);
      return new Promise<Message>((resolve, reject) => {
        // Shorter than the test timeout so the child is still cleaned up when
        // a message never arrives, instead of the runner killing the test.
        const timer = setTimeout(() => reject(new Error(`timed out waiting for ${what}`)), 5000);
        waiters.push({
          pred,
          resolve: (m) => {
            clearTimeout(timer);
            resolve(m);
          },
        });
      });
    },
    call(message) {
      const wait = harness.waitFor((m) => m.id === message.id, `reply to ${String(message.id)}`);
      harness.send(message);
      return wait;
    },
    received,
    rawLines,
    outputErrors,
    serverLog() {
      return readFileSync(logFile, 'utf8')
        .split('\n')
        .filter((line) => line.trim().length > 0)
        .map((line) => JSON.parse(line) as Message);
    },
    toolwrit,
    stop: () => proxy.stop(),
    exited: () => proxy.exited(),
  };

  await proxy.start();
  try {
    await body(harness);
  } finally {
    await proxy.stop();
    rmSync(dir, { recursive: true, force: true });
  }
}

/** tools/call messages the downstream server actually saw, by tool name. */
function toolsCalled(log: Message[]): string[] {
  const names: string[] = [];
  for (const message of log) {
    if (message.method !== 'tools/call') continue;
    const params = message.params as { name?: unknown } | undefined;
    names.push(typeof params?.name === 'string' ? params.name : '');
  }
  return names;
}

function resultText(message: Message): string {
  const result = message.result as { content?: { text?: unknown }[] } | undefined;
  return String(result?.content?.[0]?.text ?? '');
}

function isError(message: Message): boolean {
  return (message.result as { isError?: unknown } | undefined)?.isError === true;
}

/** Intercept the proxy's operator warnings, which go straight to process.stderr. */
function captureStderr(): { text(): string; restore(): void } {
  const original = process.stderr.write;
  let text = '';
  process.stderr.write = ((chunk: string | Uint8Array) => {
    text += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
    return true;
  }) as typeof process.stderr.write;
  return {
    text: () => text,
    restore: () => {
      process.stderr.write = original;
    },
  };
}

const SCOPED = policyOf(
  `version: "1"
default: deny
rules:
  - id: scoped-read
    tools: ["fs.read"]
    effect: allow
    when:
      path:
        startsWith: ["/tmp/"]
`
);

describe('mcp proxy: enforcement', () => {
  it('never forwards a denied tools/call to the downstream server', TIMEOUT, async () => {
    await withProxy({ policy: SCOPED }, async (h) => {
      h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'secret.dump' } });
      const reply = await h.waitFor((m) => m.id === 1);

      assert.equal(isError(reply), true);
      // The oracle: the child process recorded nothing. A proxy that replied
      // "denied" and forwarded anyway would still pass an assertion on `reply`.
      assert.deepEqual(toolsCalled(h.serverLog()), []);
    });
  });

  it('forwards an allowed tools/call and returns the server result', TIMEOUT, async () => {
    await withProxy({ policy: SCOPED }, async (h) => {
      const reply = await h.call({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'fs.read', arguments: { path: '/tmp/ok' } },
      });

      assert.equal(isError(reply), false);
      assert.equal(resultText(reply), 'ran fs.read');
      assert.deepEqual(toolsCalled(h.serverLog()), ['fs.read']);
    });
  });

  it('refuses the same tool when the arguments leave the allowed scope', TIMEOUT, async () => {
    await withProxy({ policy: SCOPED }, async (h) => {
      const reply = await h.call({
        jsonrpc: '2.0',
        id: 'a',
        method: 'tools/call',
        params: { name: 'fs.read', arguments: { path: '/etc/shadow' } },
      });

      assert.equal(isError(reply), true);
      assert.match(resultText(reply), /must start with one of \["\/tmp\/"\]/);
      assert.deepEqual(toolsCalled(h.serverLog()), []);
    });
  });

  it('preserves the client id and its JSON type on the reply', TIMEOUT, async () => {
    await withProxy({}, async (h) => {
      const numeric = await h.call({
        jsonrpc: '2.0',
        id: 7,
        method: 'tools/call',
        params: { name: 'fs.read' },
      });
      const textual = await h.call({
        jsonrpc: '2.0',
        id: 'req-alpha',
        method: 'tools/call',
        params: { name: 'fs.read' },
      });

      assert.equal(numeric.id, 7);
      assert.equal(textual.id, 'req-alpha');
    });
  });

  it('KNOWN LIMITATION: a server reply on the wrong id is not re-addressed', TIMEOUT, async () => {
    await withProxy({}, async (h) => {
      // `handleToolsCall` ends with `toClient({ ...response, id: request.id })`,
      // which reads as "the client's id always wins". It only wins when the
      // server echoed the right id in the first place: routing is keyed on the
      // id the *response* carries, so a mismatched reply never reaches that
      // line at all. It is forwarded verbatim on the server's id instead, and
      // the client is left waiting on its own. Pinned as the real behaviour so
      // nobody reads that line as protection against a confused server.
      h.send({
        jsonrpc: '2.0',
        id: 42,
        method: 'tools/call',
        params: { name: 'fs.read', arguments: { echoId: 99 } },
      });
      const stray = await h.waitFor((m) => m.id === 99, 'the misaddressed reply');

      assert.equal(resultText(stray), 'ran fs.read');
      assert.equal(h.received.some((m) => m.id === 42), false);
      // The call itself was allowed and metered — only the reply went astray.
      assert.equal(h.toolwrit.usage().calls, 1);
    });
  });
});

describe('mcp proxy: the id-less tools/call bypass', () => {
  // THIS IS THE REGRESSION TEST THAT MATTERS MOST IN THIS FILE.
  //
  // A tools/call with no `id` is shaped like a JSON-RPC notification. An
  // earlier version of the proxy only enforced messages that had an id, so a
  // client could execute any tool at all — including one the policy denies —
  // by simply leaving the field out. One omitted field, the entire policy
  // bypassed. If any of these three tests ever goes green by forwarding, the
  // proxy is not a security boundary any more.

  it('enforces a denied tools/call that carries no id at all', TIMEOUT, async () => {
    await withProxy({ policy: SCOPED }, async (h) => {
      const stderr = captureStderr();
      try {
        h.send({ jsonrpc: '2.0', method: 'tools/call', params: { name: 'secret.dump' } });
        // A later, allowed request proves the id-less one was fully processed
        // first: messages are handled in order, synchronously, as they arrive.
        await h.call({ jsonrpc: '2.0', id: 'after', method: 'initialize' });

        assert.deepEqual(toolsCalled(h.serverLog()), []);
        // Nobody is waiting on a notification, so the refusal goes to the
        // operator and nothing at all is written back to the client.
        assert.deepEqual(h.received.map((m) => m.id), ['after']);
        assert.match(stderr.text(), /denied notification tools\/call "secret.dump"/);
      } finally {
        stderr.restore();
      }
    });
  });

  it('still forwards an allowed tools/call that carries no id', TIMEOUT, async () => {
    await withProxy({ policy: SCOPED }, async (h) => {
      h.send({
        jsonrpc: '2.0',
        method: 'tools/call',
        params: { name: 'fs.read', arguments: { path: '/tmp/ok' } },
      });
      await h.call({ jsonrpc: '2.0', id: 'after', method: 'initialize' });

      assert.deepEqual(toolsCalled(h.serverLog()), ['fs.read']);
      // Still no reply: the client did not ask for one.
      assert.deepEqual(h.received.map((m) => m.id), ['after']);
    });
  });

  it('treats an explicit id: null exactly like a missing id', TIMEOUT, async () => {
    await withProxy({ policy: SCOPED }, async (h) => {
      const stderr = captureStderr();
      try {
        h.send({
          jsonrpc: '2.0',
          id: null,
          method: 'tools/call',
          params: { name: 'secret.dump' },
        });
        h.send({
          jsonrpc: '2.0',
          id: null,
          method: 'tools/call',
          params: { name: 'fs.read', arguments: { path: '/tmp/ok' } },
        });
        await h.call({ jsonrpc: '2.0', id: 'after', method: 'initialize' });

        assert.deepEqual(toolsCalled(h.serverLog()), ['fs.read']);
        assert.deepEqual(h.received.map((m) => m.id), ['after']);
        assert.match(stderr.text(), /denied notification tools\/call "secret.dump"/);
      } finally {
        stderr.restore();
      }
    });
  });

  it('enforces a tools/call whose name is missing entirely', TIMEOUT, async () => {
    await withProxy({ policy: SCOPED }, async (h) => {
      // A nameless call evaluates as tool "" — under deny-by-default that is a
      // refusal, not an unguarded passthrough.
      const reply = await h.call({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} });

      assert.equal(isError(reply), true);
      assert.deepEqual(toolsCalled(h.serverLog()), []);
    });
  });
});

describe('mcp proxy: denials are tool errors, not protocol errors', () => {
  it('answers with a JSON-RPC result, never a JSON-RPC error', TIMEOUT, async () => {
    await withProxy({ policy: SCOPED }, async (h) => {
      const reply = await h.call({
        jsonrpc: '2.0',
        id: 9,
        method: 'tools/call',
        params: { name: 'secret.dump' },
      });

      // A protocol error reads as a broken server and usually aborts the
      // agent's turn; a tool error is content the model can read and route
      // around. This distinction is the difference between a guardrail the
      // agent can work with and one that just breaks the run.
      assert.equal(reply.error, undefined);
      assert.ok(reply.result, 'denial must be carried in `result`');
      assert.equal(isError(reply), true);
      assert.equal(reply.jsonrpc, '2.0');
    });
  });

  it('names the tool and the constraint that failed', TIMEOUT, async () => {
    await withProxy({ policy: SCOPED }, async (h) => {
      const reply = await h.call({
        jsonrpc: '2.0',
        id: 9,
        method: 'tools/call',
        params: { name: 'fs.read', arguments: { path: '/etc/shadow' } },
      });

      const text = resultText(reply);
      assert.match(text, /Denied by policy: no rule allows "fs\.read" with these arguments/);
      // The argument that failed, by path, so the model can retry differently
      // instead of concluding the tool is broken.
      assert.match(text, /- path: argument "path" must start with one of \["\/tmp\/"\]/);
      assert.match(text, /Tool "fs\.read" was not executed/);
      assert.match(text, /Audit: [0-9a-f]{12}/);
    });
  });

  it('quotes the rule id when a rule did the denying', TIMEOUT, async () => {
    const p = policyOf(
      `version: "1"
default: allow
rules:
  - id: no-secrets
    description: secrets stay put
    tools: ["secret.*"]
    effect: deny
`
    );
    await withProxy({ policy: p }, async (h) => {
      const reply = await h.call({
        jsonrpc: '2.0',
        id: 9,
        method: 'tools/call',
        params: { name: 'secret.dump' },
      });

      const text = resultText(reply);
      assert.match(text, /Denied by policy: secrets stay put/);
      assert.match(text, /Rule: no-secrets/);
      assert.deepEqual(toolsCalled(h.serverLog()), []);
    });
  });
});

describe('mcp proxy: visibleTools', () => {
  const names = ['fs.read', 'fs.write', 'net.fetch', 'secret.dump'];

  it('hides a tool no rule targets when the default is deny', () => {
    const hidden = visibleTools(
      policyOf('version: "1"\nrules:\n  - id: r\n    tools: ["fs.read"]\n    effect: allow\n'),
      names
    );
    assert.deepEqual(hidden, ['fs.read']);
  });

  it('hides nothing when the default is allow or ask', () => {
    const allow = policyOf('version: "1"\ndefault: allow\nrules: []\n');
    const ask = policyOf('version: "1"\ndefault: ask\nrules: []\n');
    assert.deepEqual(visibleTools(allow, names), names);
    assert.deepEqual(visibleTools(ask, names), names);
  });

  it('keeps a tool matched by a glob', () => {
    const p = policyOf('version: "1"\nrules:\n  - id: r\n    tools: ["fs.*"]\n    effect: allow\n');
    assert.deepEqual(visibleTools(p, names), ['fs.read', 'fs.write']);
  });

  it('keeps a tool a deny rule targets, because arguments still decide', () => {
    // Visibility answers "could any arguments ever work?", not "would today's".
    // A tool named by a rule stays advertised even when that rule denies it
    // under some arguments; only the permanently unreachable ones disappear.
    const p = policyOf(
      'version: "1"\nrules:\n  - id: r\n    tools: ["net.fetch"]\n    effect: deny\n'
    );
    assert.deepEqual(visibleTools(p, names), ['net.fetch']);
  });

  it('hides everything under a bare deny-by-default policy', () => {
    assert.deepEqual(visibleTools(policyOf('version: "1"\nrules: []\n'), names), []);
    assert.deepEqual(visibleTools(ALLOW_ALL, []), []);
  });
});

describe('mcp proxy: tools/list filtering', () => {
  it('filters the real tools/list response on its way back', TIMEOUT, async () => {
    const p = policyOf(
      'version: "1"\nrules:\n  - id: r\n    tools: ["fs.*"]\n    effect: allow\n'
    );
    await withProxy({ policy: p, filterList: true }, async (h) => {
      const reply = await h.call({ jsonrpc: '2.0', id: 'list', method: 'tools/list' });
      const tools = (reply.result as { tools: { name: string }[] }).tools;

      assert.deepEqual(tools.map((t) => t.name), ['fs.read', 'fs.write']);
      // Filtering is presentational; the request itself still reached the server.
      assert.equal(h.serverLog().some((m) => m.method === 'tools/list'), true);
    });
  });

  it('advertises the list unchanged when no policy was handed to the proxy', TIMEOUT, async () => {
    const p = policyOf(
      'version: "1"\nrules:\n  - id: r\n    tools: ["fs.*"]\n    effect: allow\n'
    );
    await withProxy({ policy: p, filterList: false }, async (h) => {
      const reply = await h.call({ jsonrpc: '2.0', id: 'list', method: 'tools/list' });
      const tools = (reply.result as { tools: { name: string }[] }).tools;

      assert.deepEqual(tools.map((t) => t.name), [
        'fs.read',
        'fs.write',
        'net.fetch',
        'secret.dump',
      ]);
    });
  });
});

describe('mcp proxy: passthrough', () => {
  it('forwards initialize, resources/* and prompts/* verbatim with ids intact', TIMEOUT, async () => {
    await withProxy({ policy: SCOPED }, async (h) => {
      const init = await h.call({
        jsonrpc: '2.0',
        id: 'i-1',
        method: 'initialize',
        params: { protocolVersion: '2024-11-05' },
      });
      const res = await h.call({
        jsonrpc: '2.0',
        id: 2,
        method: 'resources/read',
        params: { uri: 'file:///x' },
      });
      const prompt = await h.call({
        jsonrpc: '2.0',
        id: 3,
        method: 'prompts/get',
        params: { name: 'p' },
      });

      assert.deepEqual([init.id, res.id, prompt.id], ['i-1', 2, 3]);
      assert.deepEqual((init.result as { echo: string }).echo, 'initialize');
      // The params arrived at the server untouched — deny-by-default governs
      // tools/call only, and must not quietly mangle the rest of the protocol.
      const sent = h.serverLog().find((m) => m.id === 2);
      assert.deepEqual(sent?.params, { uri: 'file:///x' });
    });
  });

  it('forwards a client notification without inventing a reply', TIMEOUT, async () => {
    await withProxy({}, async (h) => {
      h.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      await h.call({ jsonrpc: '2.0', id: 'after', method: 'initialize' });

      assert.equal(
        h.serverLog().some((m) => m.method === 'notifications/initialized'),
        true
      );
      assert.deepEqual(h.received.map((m) => m.id), ['after']);
    });
  });

  it('passes server-initiated requests and notifications to the client', TIMEOUT, async () => {
    await withProxy({}, async (h) => {
      await h.call({ jsonrpc: '2.0', id: 'e', method: 'test/emit' });

      const request = h.received.find((m) => m.id === 'srv-1');
      const notification = h.received.find((m) => m.method === 'notifications/message');
      assert.equal(request?.method, 'roots/list');
      assert.ok(notification, 'server notification must reach the client');
    });
  });

  it('routes out-of-order responses back to the right waiter', TIMEOUT, async () => {
    await withProxy({}, async (h) => {
      // The fixture parks three answers and flushes them in reverse, so a
      // proxy that paired responses positionally instead of by id would
      // return each caller somebody else's result.
      const calls = ['a', 'b', 'c'].map((tag) =>
        h.call({
          jsonrpc: '2.0',
          id: tag,
          method: 'tools/call',
          params: { name: `fs.read`, arguments: { hold: 3, size: tag.charCodeAt(0) } },
        })
      );
      const replies = await Promise.all(calls);

      assert.deepEqual(replies.map((r) => r.id), ['a', 'b', 'c']);
      // Each reply carries the body sized for its own request, not its neighbour's.
      assert.deepEqual(
        replies.map((r) => resultText(r).length),
        ['a', 'b', 'c'].map((t) => t.charCodeAt(0))
      );
      assert.deepEqual(h.received.map((m) => m.id), ['c', 'b', 'a']);
    });
  });
});

describe('mcp proxy: framing and robustness', () => {
  it('reassembles a message split across chunk boundaries', TIMEOUT, async () => {
    await withProxy({}, async (h) => {
      const line = JSON.stringify({ jsonrpc: '2.0', id: 'split', method: 'initialize' });
      const wait = h.waitFor((m) => m.id === 'split');

      // Three writes, one message: chunk boundaries have nothing to do with
      // message boundaries, and dropping the held partial line corrupts the
      // session silently instead of failing.
      const third = Math.floor(line.length / 3);
      h.raw(line.slice(0, third));
      h.raw(line.slice(third, third * 2));
      h.raw(`${line.slice(third * 2)}\n`);

      const reply = await wait;
      assert.equal((reply.result as { echo: string }).echo, 'initialize');
    });
  });

  it('skips a malformed line with a warning and leaves its neighbours alone', TIMEOUT, async () => {
    await withProxy({}, async (h) => {
      const stderr = captureStderr();
      try {
        h.raw(
          `${JSON.stringify({ jsonrpc: '2.0', id: 'one', method: 'initialize' })}\n` +
            `{ this is not json\n` +
            `${JSON.stringify({ jsonrpc: '2.0', id: 'two', method: 'initialize' })}\n`
        );

        await h.waitFor((m) => m.id === 'two');
        assert.deepEqual(h.received.map((m) => m.id), ['one', 'two']);
        assert.match(stderr.text(), /ignoring malformed JSON from client/);
        // Junk must never be relayed downstream either.
        assert.equal(h.serverLog().length, 2);
      } finally {
        stderr.restore();
      }
    });
  });

  it('ignores blank and whitespace-only lines', TIMEOUT, async () => {
    await withProxy({}, async (h) => {
      const stderr = captureStderr();
      try {
        h.raw(
          `\n   \n${JSON.stringify({ jsonrpc: '2.0', id: 'blank', method: 'initialize' })}\n\n`
        );
        await h.waitFor((m) => m.id === 'blank');

        assert.equal(h.serverLog().length, 1);
        assert.doesNotMatch(stderr.text(), /malformed/);
      } finally {
        stderr.restore();
      }
    });
  });

  it('carries a very long line in both directions', TIMEOUT, async () => {
    await withProxy({}, async (h) => {
      const blob = 'z'.repeat(200_000);
      const reply = await h.call({
        jsonrpc: '2.0',
        id: 'big',
        method: 'tools/call',
        params: { name: 'fs.read', arguments: { blob, size: 100_000 } },
      });

      const sent = h.serverLog().find((m) => m.method === 'tools/call');
      const args = (sent?.params as { arguments: { blob: string } }).arguments;
      assert.equal(args.blob.length, 200_000);
      assert.equal(resultText(reply).length, 100_000);
    });
  });

  it('writes nothing but JSON-RPC to the output stream', TIMEOUT, async () => {
    await withProxy({ policy: SCOPED }, async (h) => {
      const stderr = captureStderr();
      try {
        h.raw('garbage\n');
        h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'secret.dump' } });
        await h.call({ jsonrpc: '2.0', id: 2, method: 'initialize' });
      } finally {
        stderr.restore();
      }

      assert.ok(h.rawLines.length > 0);
      for (const line of h.rawLines) {
        const parsed: unknown = JSON.parse(line);
        assert.equal(typeof parsed, 'object');
        assert.equal((parsed as Message).jsonrpc, '2.0');
      }
    });
  });
});

describe('mcp proxy: lifecycle and exit status', () => {
  const bare = (command: string, args: string[]) => {
    const input = new PassThrough();
    const output = new PassThrough();
    output.resume();
    output.on('error', () => {});
    return createMcpProxy({
      toolwrit: new Toolwrit({ policy: ALLOW_ALL, now: frozenClock() }),
      command,
      args,
      input,
      output,
    });
  };

  it("reports the child's own exit code", TIMEOUT, async () => {
    const proxy = bare(process.execPath, ['-e', 'process.exit(3)']);
    await proxy.start();
    try {
      assert.equal(await proxy.exited(), 3);
    } finally {
      await proxy.stop();
    }
  });

  it('reports 128+n when a signal killed the child', TIMEOUT, async () => {
    const proxy = bare(process.execPath, ['-e', 'setInterval(() => {}, 1000)']);
    await proxy.start();
    // stop() sends SIGTERM, which is 15: a supervisor that cannot tell a
    // killed server from a clean one reports a failed run as a success.
    await proxy.stop();
    assert.equal(await proxy.exited(), 128 + 15);
  });

  it('reports 127 when the command cannot be spawned at all', TIMEOUT, async () => {
    const stderr = captureStderr();
    const proxy = bare('toolwrit-no-such-command-8f21a', []);
    try {
      await proxy.start();
      assert.equal(await proxy.exited(), 127);
      assert.match(stderr.text(), /failed to start "toolwrit-no-such-command-8f21a"/);
    } finally {
      stderr.restore();
    }
  });

  it('stop() settles after a failed spawn instead of hanging', TIMEOUT, async () => {
    // A process that failed to spawn emits "error" and never "exit", so a stop()
    // that waits only on "exit" never returns and a CLI shutting down after a
    // bad --command hangs instead of exiting 127. stop() now also races the
    // settled exit status, which the spawn failure resolves.
    const stderr = captureStderr();
    const proxy = bare('toolwrit-no-such-command-8f21a', []);
    try {
      await proxy.start();
      const settled = await Promise.race([
        proxy.stop().then(() => 'settled'),
        new Promise((resolve) => setTimeout(resolve, 500)).then(() => 'pending'),
      ]);
      assert.equal(settled, 'settled');
      assert.equal(await proxy.exited(), 127);
    } finally {
      stderr.restore();
    }
  });

  it('is idempotent under repeated stop()', TIMEOUT, async () => {
    const proxy = bare(process.execPath, ['-e', 'setInterval(() => {}, 1000)']);
    await proxy.start();
    await proxy.stop();
    await proxy.stop();
    await proxy.stop();
    assert.equal(await proxy.exited(), 128 + 15);
  });

  it('releases a pending passthrough waiter when the child dies', TIMEOUT, async () => {
    await withProxy({}, async (h) => {
      h.send({ jsonrpc: '2.0', id: 'hangs', method: 'test/hang' });
      // Round-trip a second request to prove the first one has arrived.
      await h.call({ jsonrpc: '2.0', id: 'ping', method: 'initialize' });

      const wait = h.waitFor(
        (m) => (m.error as { code?: number } | undefined)?.code === -32000,
        'the downstream-exited error'
      );
      await h.stop();
      const reply = await wait;

      assert.match((reply.error as { message: string }).message, /downstream server exited/);
      // The failure names the request it belongs to. Without the id a client
      // with several requests in flight learns that something died but not
      // which, and cannot fail just that one.
      assert.equal(reply.id, 'hangs');
    });
  });

  it('answers a pending tools/call when the child dies', TIMEOUT, async () => {
    // The reply to a tools/call is produced after an await, so ending the
    // transport inside the same exit handler used to close the stream first
    // and the client was told nothing at all about that call -- worse than the
    // passthrough case above, which at least got an error. Shutdown now waits
    // for handlers that are mid-call.
    await withProxy({}, async (h) => {
      h.send({
        jsonrpc: '2.0',
        id: 'stuck',
        method: 'tools/call',
        params: { name: 'fs.read', arguments: { hang: true } },
      });
      await h.call({ jsonrpc: '2.0', id: 'ping', method: 'initialize' });

      await h.stop();
      for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve));

      const stuck = h.received.find((m) => m.id === 'stuck');
      assert.ok(stuck, `no reply for "stuck": ${JSON.stringify(h.received.map((m) => m.id))}`);
      assert.equal((stuck.error as { code?: number } | undefined)?.code, -32000);
    });
  });
});

describe('mcp proxy: budgets', () => {
  it('refuses calls past the call budget without reaching the server', TIMEOUT, async () => {
    const p = policyOf('version: "1"\ndefault: allow\nbudget:\n  calls: 2\nrules: []\n');
    await withProxy({ policy: p }, async (h) => {
      const first = await h.call({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'fs.read' },
      });
      const second = await h.call({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'fs.read' },
      });
      const third = await h.call({
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: { name: 'fs.read' },
      });

      assert.deepEqual([isError(first), isError(second), isError(third)], [false, false, true]);
      assert.match(resultText(third), /call budget exhausted/);
      assert.deepEqual(toolsCalled(h.serverLog()), ['fs.read', 'fs.read']);
      assert.equal(h.toolwrit.usage().calls, 2);
    });
  });
});

describe('mcp proxy: the bytes ceiling under pipelining', () => {
  const BYTES = policyOf('version: "1"\ndefault: allow\nbudget:\n  bytes: 100\nrules: []\n');

  const bigCall = (id: number): Message & { id: number } => ({
    jsonrpc: '2.0',
    id,
    method: 'tools/call',
    params: { name: 'fs.read', arguments: { size: 500 } },
  });

  it('holds the ceiling when the client waits for each reply', TIMEOUT, async () => {
    await withProxy({ policy: BYTES }, async (h) => {
      const first = await h.call(bigCall(1));
      const second = await h.call(bigCall(2));

      assert.equal(isError(first), false);
      assert.equal(isError(second), true);
      assert.match(resultText(second), /data budget exhausted/);
      // One call's worth of overrun is by design (a result's size is unknown
      // until it exists); the second call is stopped before it is forwarded.
      assert.deepEqual(toolsCalled(h.serverLog()), ['fs.read']);
    });
  });

  it('holds the bytes ceiling against a pipelined batch', TIMEOUT, async () => {
    // The regression this pins. A client that writes several tools/call
    // messages before reading any reply used to get them all handled in one
    // synchronous pass, so every decision in the batch was taken against
    // `bytes: 0` and every one was allowed: a 100-byte ceiling ran past 2,000.
    //
    // A result's size still cannot be known before the tool produces it, so
    // the bound is the limit plus one call, never exactly the limit. What has
    // changed is that the overrun no longer scales with the client's pipeline
    // depth: where a bytes budget is declared, calls are decided one at a time.
    await withProxy({ policy: BYTES }, async (h) => {
      h.send(bigCall(1), bigCall(2), bigCall(3), bigCall(4));
      await Promise.all([1, 2, 3, 4].map((id) => h.waitFor((m) => m.id === id)));

      const replies = [1, 2, 3, 4].map((id) => h.received.find((m) => m.id === id)!);
      // The first is allowed, and its result exhausts the ceiling for the rest.
      assert.equal(isError(replies[0]!), false);
      assert.deepEqual(replies.slice(1).map(isError), [true, true, true]);
      assert.match(resultText(replies[1]!), /data budget exhausted/);
      // Only the first call ever reached the downstream server.
      assert.deepEqual(toolsCalled(h.serverLog()), ['fs.read']);

      const next = await h.call(bigCall(5));
      assert.equal(isError(next), true);
      assert.deepEqual(toolsCalled(h.serverLog()), ['fs.read']);
    });
  });
});
