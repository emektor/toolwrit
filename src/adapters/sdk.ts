/**
 * Adapters that drop Leash into an agent loop that already exists.
 *
 * The core API throws on refusal, which is right for application code: a
 * silently-skipped side effect is worse than a crash. Inside an agent loop it
 * is exactly wrong — an exception unwinds the loop and the run dies, when what
 * you actually want is for the model to *learn the boundary* and try something
 * else on the next turn. So every function here converts a refusal into the
 * shape the calling SDK already understands as "the tool failed, keep going":
 * an `isError` result, an Anthropic `tool_result` with `is_error`, or an
 * OpenAI `role: "tool"` message.
 *
 * The SDK shapes below are declared structurally on purpose. Leash takes no
 * dependency on `@anthropic-ai/sdk` or `openai`: a policy sidecar that forces
 * you to upgrade your model client is not a sidecar. The types are permissive
 * (extra fields allowed) so real SDK objects assign to them unchanged.
 */

import type { TokenPrice } from '../budget/ledger.js';
import { Leash, LeashDenied } from '../leash.js';

/** A tool implementation: arguments in, result out. Sync or async. */
export type ToolHandler<
  A extends Record<string, unknown> = Record<string, unknown>,
  R = unknown,
> = (args: A) => R | Promise<R>;

/** A single block of textual tool output. Matches the Anthropic content shape. */
export interface TextBlock {
  type: 'text';
  text: string;
}

/**
 * What a wrapped handler returns instead of throwing when policy refuses.
 * `isError` is the flag every major SDK uses to tell the model "this call
 * failed"; the text is written for the model, not for a log line.
 */
export interface ToolErrorResult {
  isError: true;
  content: TextBlock[];
}

/** The signature `wrapTool` hands back: same arguments, refusal folded into the result. */
export type GuardedHandler<
  A extends Record<string, unknown> = Record<string, unknown>,
  R = unknown,
> = (args: A) => Promise<R | ToolErrorResult>;

/** Anthropic `tool_use` content block, structurally. */
export interface ToolUseBlock {
  type: 'tool_use';
  id: string;
  name: string;
  input?: unknown;
  [extra: string]: unknown;
}

/** Anthropic `tool_result` content block, structurally. */
export interface ToolResultBlock {
  type: 'tool_result';
  tool_use_id: string;
  content: TextBlock[];
  is_error: boolean;
}

/** OpenAI tool call from a chat completion, structurally. */
export interface OpenAIToolCall {
  id: string;
  type?: 'function';
  function: {
    name: string;
    /** JSON *text*, not an object — and not necessarily valid JSON. */
    arguments?: string;
  };
  [extra: string]: unknown;
}

/** OpenAI tool result message, structurally. */
export interface OpenAIToolMessage {
  role: 'tool';
  tool_call_id: string;
  content: string;
}

/** Anthropic usage block, structurally. */
export interface AnthropicUsage {
  input_tokens?: number;
  output_tokens?: number;
  [extra: string]: unknown;
}

/** OpenAI usage block, structurally. */
export interface OpenAIUsage {
  prompt_tokens?: number;
  completion_tokens?: number;
  [extra: string]: unknown;
}

/**
 * Wrap one handler so every invocation is evaluated, recorded and — if the
 * policy permits — executed. The wrapper keeps the handler's signature, so
 * swapping it into an existing tool registry is a one-line change.
 *
 * A refusal is returned, never thrown: see the file header.
 */
export function wrapTool<A extends Record<string, unknown>, R>(
  leash: Leash,
  name: string,
  handler: ToolHandler<A, R>
): GuardedHandler<A, R> {
  return async (args: A): Promise<R | ToolErrorResult> => {
    try {
      return await leash.guard(name, args, () => handler(args));
    } catch (err) {
      if (err instanceof LeashDenied) return refusal(err);
      // Anything else is a genuine failure inside the tool. Leash has no
      // opinion about those and must not disguise them as policy decisions.
      throw err;
    }
  };
}

/** `wrapTool` across a whole registry, preserving the tool names as keys. */
export function wrapTools(
  leash: Leash,
  handlers: Record<string, ToolHandler>
): Record<string, GuardedHandler> {
  const wrapped: Record<string, GuardedHandler> = {};
  for (const [name, handler] of Object.entries(handlers)) {
    wrapped[name] = wrapTool(leash, name, handler);
  }
  return wrapped;
}

/**
 * Run one Anthropic `tool_use` block under the leash and return the
 * `tool_result` block to append to the next user turn.
 *
 * This is the whole integration for an Anthropic SDK user: find the tool_use
 * blocks in the response, pass each one here, send the results back.
 */
export async function guardToolUse(
  leash: Leash,
  block: ToolUseBlock,
  handlers: Record<string, ToolHandler>
): Promise<ToolResultBlock> {
  const args = asArgs(block.input);
  const handler = handlers[block.name];

  try {
    const result = await leash.guard(block.name, args, () => {
      // Checked inside `guard` so the decision is still audited: a model asking
      // for a tool that does not exist is worth having on the record.
      if (!handler) throw new UnknownTool(block.name);
      return handler(args);
    });
    return toolResult(block.id, toText(result), false);
  } catch (err) {
    if (err instanceof LeashDenied) return toolResult(block.id, denialText(err), true);
    if (err instanceof UnknownTool) return toolResult(block.id, err.message, true);
    throw err;
  }
}

/**
 * The OpenAI equivalent. Arguments arrive as a JSON *string* the model wrote,
 * so parsing can fail; when it does we still route the call through the leash
 * before refusing it. A model emitting malformed arguments for a privileged
 * tool is a policy-relevant event, and an audit chain with a hole in it where
 * the interesting call should be is worth very little.
 */
export async function guardOpenAIToolCall(
  leash: Leash,
  toolCall: OpenAIToolCall,
  handlers: Record<string, ToolHandler>
): Promise<OpenAIToolMessage> {
  const raw = toolCall.function.arguments ?? '{}';
  const name = toolCall.function.name;
  const parsed = parseArguments(raw);

  if (!parsed.ok) {
    const text = `tool "${name}" was refused: arguments are not valid JSON (${parsed.error})`;
    try {
      // The raw text is recorded under a reserved key so the audit entry shows
      // exactly what the model produced. The result is a refusal whatever the
      // policy says — we have no arguments to hand the tool.
      await leash.guard(name, { _rawArguments: raw }, () => text);
    } catch (err) {
      // The policy almost always refuses this (the arguments it wanted to check
      // are not there), but the model needs to hear about the broken JSON, not
      // about the constraints that could not be evaluated because of it.
      if (err instanceof LeashDenied) {
        return {
          role: 'tool',
          tool_call_id: toolCall.id,
          content: `${text}\n(audit ${err.auditHash.slice(0, 12)}) Re-emit the arguments as valid JSON.`,
        };
      }
      throw err;
    }
    return { role: 'tool', tool_call_id: toolCall.id, content: text };
  }

  const handler = handlers[name];
  try {
    const result = await leash.guard(name, parsed.args, () => {
      if (!handler) throw new UnknownTool(name);
      return handler(parsed.args);
    });
    return { role: 'tool', tool_call_id: toolCall.id, content: toText(result) };
  } catch (err) {
    if (err instanceof LeashDenied) return { role: 'tool', tool_call_id: toolCall.id, content: denialText(err) };
    if (err instanceof UnknownTool) return { role: 'tool', tool_call_id: toolCall.id, content: err.message };
    throw err;
  }
}

/** Meter an Anthropic response's usage block against the run budget. */
export function meterAnthropicUsage(leash: Leash, usage: AnthropicUsage, price?: TokenPrice): void {
  leash.meter(usage.input_tokens ?? 0, usage.output_tokens ?? 0, price);
}

/** Meter an OpenAI completion's usage block against the run budget. */
export function meterOpenAIUsage(leash: Leash, usage: OpenAIUsage, price?: TokenPrice): void {
  leash.meter(usage.prompt_tokens ?? 0, usage.completion_tokens ?? 0, price);
}

/** Raised when the model names a tool the registry does not have. */
class UnknownTool extends Error {
  constructor(name: string) {
    super(`tool "${name}" is not available`);
    this.name = 'UnknownTool';
  }
}

function refusal(err: LeashDenied): ToolErrorResult {
  return { isError: true, content: [{ type: 'text', text: denialText(err) }] };
}

function toolResult(id: string, text: string, isError: boolean): ToolResultBlock {
  return { type: 'tool_result', tool_use_id: id, content: [{ type: 'text', text }], is_error: isError };
}

/**
 * Refusal text aimed at the model: what was refused, why, which argument was at
 * fault, and the audit hash so a human can find the same event in the log.
 */
function denialText(err: LeashDenied): string {
  const lines = [`tool "${err.tool}" was refused by policy: ${err.decision.reason}`];
  for (const violation of err.decision.violations) {
    // A blanket deny rule reports its description as both the reason and the
    // single violation; repeating it back to the model teaches nothing.
    if (violation.message === err.decision.reason) continue;
    lines.push(`- ${violation.message}`);
  }
  lines.push(`(audit ${err.auditHash.slice(0, 12)}) Do not retry this call unchanged.`);
  return lines.join('\n');
}

type ParsedArguments =
  | { ok: true; args: Record<string, unknown> }
  | { ok: false; error: string };

function parseArguments(raw: string): ParsedArguments {
  try {
    const value: unknown = JSON.parse(raw);
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return { ok: false, error: 'expected a JSON object' };
    }
    return { ok: true, args: value as Record<string, unknown> };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

/** Tool input from a model may be absent or a non-object; the engine wants a record. */
function asArgs(input: unknown): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) return {};
  return input as Record<string, unknown>;
}

function toText(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value === undefined) return '';
  return JSON.stringify(value) ?? '';
}
