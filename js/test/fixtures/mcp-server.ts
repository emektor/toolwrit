/**
 * A tiny, real MCP-shaped stdio server for the proxy tests.
 *
 * The proxy's whole job is to sit between a client and a *process*, so the
 * tests drive it against a real child rather than a mock: anything that only
 * works because the downstream was faked is not evidence about the proxy.
 *
 * Every message this server receives is appended to the log file named by
 * argv[2], one JSON object per line. That file is the enforcement oracle — a
 * denied call must leave no trace in it.
 *
 * Behaviour is steered entirely by the call's own arguments so the tests stay
 * declarative:
 *   size    — return a result body of exactly that many characters
 *   hang    — never answer (used to leave a request pending at exit)
 *   echoId  — answer with this id instead of the request's own
 *   hold    — buffer the answer until `hold` answers are buffered, then flush
 *             them in reverse order (deterministic out-of-order responses)
 */

import { appendFileSync } from 'node:fs';

interface JsonRpcMessage {
  jsonrpc?: unknown;
  id?: string | number | null;
  method?: string;
  params?: unknown;
  [key: string]: unknown;
}

const logFile = process.argv[2];

/** The catalogue tools/list advertises. Tests write policies against these names. */
const TOOLS = [
  { name: 'fs.read', description: 'read a file' },
  { name: 'fs.write', description: 'write a file' },
  { name: 'net.fetch', description: 'fetch a url' },
  { name: 'secret.dump', description: 'dump everything' },
];

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function send(message: JsonRpcMessage): void {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

/** Answers parked by `hold`, flushed in reverse once enough have accumulated. */
let held: JsonRpcMessage[] = [];

function handle(message: JsonRpcMessage): void {
  if (logFile) appendFileSync(logFile, `${JSON.stringify(message)}\n`);

  const method = typeof message.method === 'string' ? message.method : '';
  const params = isObject(message.params) ? message.params : {};
  const args = isObject(params.arguments) ? params.arguments : {};
  const id = message.id;

  // A notification is answered with silence, exactly as a real server would.
  if (id === undefined || id === null) return;

  if (method === 'tools/list') {
    send({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
    return;
  }

  if (method === 'tools/call') {
    if (args.hang === true) return;

    const name = typeof params.name === 'string' ? params.name : '';
    const size = typeof args.size === 'number' ? args.size : 0;
    const body = size > 0 ? 'x'.repeat(size) : `ran ${name}`;
    const answerId = args.echoId === undefined ? id : (args.echoId as string | number);
    const answer: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: answerId,
      result: { content: [{ type: 'text', text: body }], isError: false },
    };

    const hold = typeof args.hold === 'number' ? args.hold : 0;
    if (hold > 0) {
      held.push(answer);
      if (held.length >= hold) {
        for (const parked of held.reverse()) send(parked);
        held = [];
      }
      return;
    }

    send(answer);
    return;
  }

  // A request the server deliberately never answers, so a test can leave a
  // waiter outstanding when the child dies.
  if (method === 'test/hang') return;

  if (method === 'test/emit') {
    // Unprompted traffic: a server-initiated request and a notification, the
    // two shapes that have no waiter on the proxy's side.
    send({ jsonrpc: '2.0', id: 'srv-1', method: 'roots/list', params: {} });
    send({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info' } });
  }

  // Everything else — initialize, resources/*, prompts/* — is echoed so the
  // test can prove the request arrived unchanged.
  send({ jsonrpc: '2.0', id, result: { echo: method, params } });
}

let buffer = '';
process.stdin.on('data', (chunk: Buffer) => {
  buffer += chunk.toString('utf8');
  let index = buffer.indexOf('\n');
  while (index !== -1) {
    const line = buffer.slice(0, index);
    buffer = buffer.slice(index + 1);
    if (line.trim().length > 0) {
      try {
        handle(JSON.parse(line) as JsonRpcMessage);
      } catch {
        // A test deliberately feeds junk; the proxy should never forward it.
        if (logFile) appendFileSync(logFile, `${JSON.stringify({ unparsable: line })}\n`);
      }
    }
    index = buffer.indexOf('\n');
  }
});

process.stdin.on('end', () => {
  process.exit(0);
});
