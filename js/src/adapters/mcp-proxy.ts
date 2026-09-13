/**
 * MCP stdio proxy.
 *
 * The cheapest place to hold an agent to its writ is the wire between it and
 * its tools. This module spawns a downstream MCP server as a child process and
 * sits in the middle of the stdio transport, so an existing client and an existing
 * server both keep working unmodified while every `tools/call` has to pass the
 * policy engine first. No SDK is involved on purpose: MCP over stdio is
 * newline-delimited JSON-RPC 2.0, and re-implementing that is a few dozen lines
 * against a dependency we would otherwise have to trust inside the trust
 * boundary.
 */

import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { ToolwritDenied, type Toolwrit } from '../toolwrit.js';
import { matchesAnyGlob } from '../policy/match.js';
import type { Policy } from '../types.js';

/** A JSON-RPC 2.0 message in either direction. Fields are optional by role. */
interface JsonRpcMessage {
  jsonrpc?: unknown;
  id?: string | number | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: unknown;
  [key: string]: unknown;
}

export interface McpProxyOptions {
  /** Policy enforcer. The proxy owns no policy state of its own. */
  toolwrit: Toolwrit;
  /** Downstream MCP server executable. */
  command: string;
  args?: string[];
  env?: NodeJS.ProcessEnv;
  /** Client side of the transport. Defaults to this process's stdio. */
  input?: NodeJS.ReadableStream;
  output?: NodeJS.WritableStream;
  /**
   * The same policy the enforcer was constructed with. `Toolwrit` deliberately
   * keeps its policy private, so tools/list filtering is opt-in: without this the
   * proxy still enforces every call, it just advertises the server's tool list
   * unchanged.
   */
  policy?: Policy;
}

export interface McpProxy {
  start(): Promise<void>;
  /**
   * Resolves with the status the proxy itself should exit with, once the
   * downstream server is gone.
   *
   * A supervisor that cannot tell a crashed server from a clean shutdown will
   * report a failed run as a success, so the child's fate has to travel back
   * out: its own exit code, 128+n when a signal killed it, and 127 when it
   * could not be started at all — the shell's convention for a missing command.
   */
  exited(): Promise<number>;
  stop(): Promise<void>;
}

/** Exit status for a command that could not be spawned, following the shell. */
const EXIT_NOT_RUNNABLE = 127;

/**
 * Tools the agent should even be told about.
 *
 * A tool is hidden only when no rule's glob mentions it *and* the policy denies
 * by default — i.e. when there is no argument shape whatsoever that could make
 * the call succeed. Arguments matter, so a tool that some rule targets stays
 * visible even if today's arguments would be refused; the agent is allowed to
 * try again with better ones. Hiding the permanently-unreachable tools cuts
 * prompt noise and removes a whole class of wasted turns where the model calls
 * something it can never be permitted to use.
 */
export function visibleTools(policy: Policy, toolNames: readonly string[]): string[] {
  if ((policy.default ?? 'deny') !== 'deny') return [...toolNames];
  return toolNames.filter((name) => policy.rules.some((rule) => matchesAnyGlob(rule.tools, name)));
}

/** The few signals worth reporting precisely; anything else lands on 128. */
const SIGNAL_NUMBERS: Record<string, number> = {
  SIGHUP: 1,
  SIGINT: 2,
  SIGQUIT: 3,
  SIGKILL: 9,
  SIGTERM: 15,
};

export function createMcpProxy(options: McpProxyOptions): McpProxy {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;

  let child: ChildProcessWithoutNullStreams | null = null;
  let stopped = false;

  // Settled by whichever comes first: the child exiting, or failing to start.
  let settleExit: (status: number) => void = () => {};
  const exitStatus = new Promise<number>((resolve) => {
    let settled = false;
    settleExit = (status) => {
      if (settled) return;
      settled = true;
      resolve(status);
    };
  });
  let ended = false;

  /**
   * Responses the child owes us, keyed by the client's request id. Each entry
   * decides what happens to that response — forwarded verbatim, filtered, or
   * handed back to the `guard` continuation waiting on it.
   */
  const pending = new Map<
    string,
    { id: JsonRpcMessage['id']; deliver: (message: JsonRpcMessage) => void }
  >();

  /**
   * `tools/call` handlers that have not finished yet.
   *
   * Their replies are produced after an `await`, so ending the transport the
   * instant the child dies would close the stream before those continuations
   * run, and a client with a call in flight would be left waiting forever on a
   * reply that was written into a closed pipe. Shutdown waits for these first.
   */
  const inFlight = new Set<Promise<unknown>>();

  function track(work: Promise<unknown>): void {
    inFlight.add(work);
    void work.finally(() => inFlight.delete(work));
  }

  function send(stream: NodeJS.WritableStream, message: JsonRpcMessage): void {
    stream.write(`${JSON.stringify(message)}\n`);
  }

  function toClient(message: JsonRpcMessage): void {
    send(output, message);
  }

  function toChild(message: JsonRpcMessage): void {
    if (child) send(child.stdin, message);
  }

  /** Forward a request downstream and resolve with whatever comes back. */
  function forwardToChild(request: JsonRpcMessage): Promise<JsonRpcMessage> {
    return new Promise((resolve) => {
      const key = idKey(request.id);
      if (key === null) {
        // A notification has no response; resolve immediately so guard returns.
        toChild(request);
        resolve({ jsonrpc: '2.0' });
        return;
      }
      pending.set(key, { id: request.id, deliver: resolve });
      toChild(request);
    });
  }

  async function handleToolsCall(request: JsonRpcMessage): Promise<void> {
    const params = isObject(request.params) ? request.params : {};
    const name = typeof params.name === 'string' ? params.name : '';
    const args = isObject(params.arguments) ? params.arguments : {};

    // A tools/call with no id is shaped like a notification, so there is no
    // response to send and nothing downstream will answer. It still has to be
    // enforced: forwarding it unguarded would let a client execute any tool by
    // simply omitting the id, which is the whole policy bypassed by one field.
    // It is guarded and audited like any other call, and a refusal is dropped
    // rather than answered, because the client is not waiting for a reply.
    const isNotification = request.id === undefined || request.id === null;

    try {
      // forwardToChild already resolves immediately for an id-less message.
      const response = await options.toolwrit.guard(name, args, () => forwardToChild(request));
      if (isNotification) return;
      // Preserve the client's id even if the downstream server echoed something else.
      toClient({ ...response, id: request.id ?? null });
    } catch (err) {
      if (isNotification) {
        // Nothing is waiting for an answer, so the refusal goes to the operator
        // rather than to the agent. Dropping it is the enforcement.
        warn(
          err instanceof ToolwritDenied
            ? `denied notification tools/call "${name}": ${err.decision.reason}`
            : `error guarding notification tools/call "${name}": ${(err as Error).message}`
        );
        return;
      }

      if (!(err instanceof ToolwritDenied)) {
        warn(`unexpected error guarding ${name}: ${(err as Error).message}`);
        toClient({
          jsonrpc: '2.0',
          id: request.id ?? null,
          result: {
            content: [{ type: 'text', text: `toolwrit: internal error enforcing policy for "${name}"` }],
            isError: true,
          },
        });
        return;
      }

      // A denial is reported as a *successful* JSON-RPC result carrying an MCP
      // tool error. A protocol-level error would look like a broken server and
      // usually aborts the agent's turn; a tool error is content the model
      // reads, so it can see the boundary and pick a different approach.
      toClient({
        jsonrpc: '2.0',
        id: request.id ?? null,
        result: { content: [{ type: 'text', text: denialText(name, err) }], isError: true },
      });
    }
  }

  function handleFromClient(message: JsonRpcMessage): void {
    // Every tools/call is enforced, with or without an id. Requiring an id here
    // would make omitting one a complete policy bypass.
    if (message.method === 'tools/call') {
      track(handleToolsCall(message));
      return;
    }

    const key = idKey(message.id);
    if (key !== null && typeof message.method === 'string') {
      // Register interest in the response so tools/list can be filtered on the
      // way back; everything else is handed through untouched.
      const filter = message.method === 'tools/list';
      pending.set(key, {
        id: message.id,
        deliver: (response) => {
          toClient(filter ? filterToolsListResponse(response) : response);
        },
      });
    }
    toChild(message);
  }

  function handleFromChild(message: JsonRpcMessage): void {
    const key = idKey(message.id);
    if (key !== null) {
      const waiting = pending.get(key);
      if (waiting) {
        pending.delete(key);
        waiting.deliver(message);
        return;
      }
    }
    // Server-initiated requests (sampling, roots) and notifications pass through.
    toClient(message);
  }

  function filterToolsListResponse(response: JsonRpcMessage): JsonRpcMessage {
    const policy = options.policy;
    if (!policy) return response;

    const result = response.result;
    if (!isObject(result) || !Array.isArray(result.tools)) return response;

    const names: string[] = [];
    for (const tool of result.tools) {
      if (isObject(tool) && typeof tool.name === 'string') names.push(tool.name);
    }
    const allowed = new Set(visibleTools(policy, names));

    return {
      ...response,
      result: {
        ...result,
        tools: result.tools.filter(
          (tool) => !isObject(tool) || typeof tool.name !== 'string' || allowed.has(tool.name)
        ),
      },
    };
  }

  return {
    async start(): Promise<void> {
      if (child) return;

      const spawned = spawn(options.command, options.args ?? [], {
        env: options.env ?? process.env,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      child = spawned;

      spawned.on('error', (err) => {
        warn(`failed to start "${options.command}": ${err.message}`);
        settleExit(EXIT_NOT_RUNNABLE);
        endOutput();
      });

      // The child's stderr is its own diagnostics channel; keep it separate from
      // the protocol stream but visible to whoever is running the proxy.
      spawned.stderr.on('data', (chunk: Buffer) => {
        process.stderr.write(chunk);
      });

      readLines(spawned.stdout, (line) => {
        const message = parseLine(line, 'downstream server');
        if (message) handleFromChild(message);
      });

      readLines(input, (line) => {
        const message = parseLine(line, 'client');
        if (message) handleFromClient(message);
      });

      input.on('end', () => {
        // The client hung up: closing the child's stdin lets it shut down cleanly.
        if (child && !child.killed) child.stdin.end();
      });

      spawned.on('exit', (code, signal) => {
        child = null;
        if (!stopped) warn(`downstream server exited (code ${code ?? 'null'}, signal ${signal ?? 'null'})`);
        // Nothing can answer the client any more, so end the transport rather
        // than leaving it waiting on responses that will never arrive. Each
        // failure carries the id it belongs to: a client with several requests
        // in flight otherwise learns that something died but not which.
        for (const { id, deliver } of pending.values()) {
          deliver({
            jsonrpc: '2.0',
            id: id ?? null,
            error: { code: -32000, message: 'downstream server exited' },
          });
        }
        pending.clear();
        settleExit(signal ? 128 + (SIGNAL_NUMBERS[signal] ?? 0) : code ?? 0);
        void endOutputWhenQuiet();
      });

      await new Promise<void>((resolve) => {
        spawned.once('spawn', () => resolve());
        spawned.once('error', () => resolve());
      });
    },

    exited(): Promise<number> {
      return exitStatus;
    },

    async stop(): Promise<void> {
      stopped = true;
      const running = child;
      if (!running) return;

      // A process that failed to spawn emits 'error' and never 'exit', so
      // waiting on 'exit' alone hangs forever -- a CLI shutting down after a
      // bad command would never reach its own exit. Waiting on the settled
      // exit status covers both: it is resolved by the spawn failure too.
      await Promise.race([
        new Promise<void>((resolve) => {
          running.once('exit', () => resolve());
          running.kill();
        }),
        exitStatus.then(() => undefined),
      ]);
    },
  };

  /**
   * Propagate the downstream server's death to the client by closing the
   * transport, and let go of stdin so a host process can actually exit.
   */
  /**
   * Close the transport, but not before the handlers that were mid-call have
   * written their replies. Each one was just resolved with a downstream-exited
   * error, so this settles in a turn or two; the loop repeats because settling
   * one handler can leave another still running.
   */
  async function endOutputWhenQuiet(): Promise<void> {
    while (inFlight.size > 0) {
      await Promise.allSettled([...inFlight]);
    }
    endOutput();
  }

  function endOutput(): void {
    if (ended) return;
    ended = true;
    if (input === process.stdin) process.stdin.pause();
    output.end();
  }
}

/** Human-readable refusal, including the constraints that actually failed. */
function denialText(tool: string, denied: ToolwritDenied): string {
  const lines = [`Denied by policy: ${denied.decision.reason}`];
  if (denied.decision.rule) lines.push(`Rule: ${denied.decision.rule}`);
  for (const violation of denied.decision.violations) {
    lines.push(`- ${violation.path ? `${violation.path}: ` : ''}${violation.message}`);
  }
  lines.push(`Tool "${tool}" was not executed. Audit: ${denied.auditHash.slice(0, 12)}`);
  return lines.join('\n');
}

/**
 * Split a stream into newline-delimited records.
 *
 * Chunk boundaries have nothing to do with message boundaries, so a partial
 * line is held until its newline arrives. Losing that buffer would silently
 * corrupt the protocol, which is worse than any crash.
 */
function readLines(stream: NodeJS.ReadableStream, onLine: (line: string) => void): void {
  let buffer = '';
  stream.on('data', (chunk: Buffer | string) => {
    buffer += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
    let index = buffer.indexOf('\n');
    while (index !== -1) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      if (line.trim().length > 0) onLine(line);
      index = buffer.indexOf('\n');
    }
  });
  stream.on('end', () => {
    if (buffer.trim().length > 0) onLine(buffer);
    buffer = '';
  });
}

function parseLine(line: string, origin: string): JsonRpcMessage | null {
  try {
    const parsed: unknown = JSON.parse(line);
    if (!isObject(parsed)) {
      warn(`ignoring non-object JSON-RPC message from ${origin}`);
      return null;
    }
    return parsed as JsonRpcMessage;
  } catch (err) {
    // A malformed line is one bad message, not a reason to drop the session.
    warn(`ignoring malformed JSON from ${origin}: ${(err as Error).message}`);
    return null;
  }
}

/** Normalises a request id for map keys; null for notifications. */
function idKey(id: unknown): string | null {
  if (typeof id === 'string') return `s:${id}`;
  if (typeof id === 'number') return `n:${id}`;
  return null;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function warn(message: string): void {
  // stdout carries protocol only — anything else there corrupts the session.
  process.stderr.write(`toolwrit: ${message}\n`);
}
