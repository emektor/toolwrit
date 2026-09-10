/**
 * Leash — a deterministic leash for AI agents.
 *
 * Allowlist the tools, cap the budget, prove what happened.
 */

export { Leash, LeashDenied } from './leash.js';
export type { ApprovalHandler, LeashOptions } from './leash.js';

export {
  wrapTool,
  wrapTools,
  guardToolUse,
  guardOpenAIToolCall,
  meterAnthropicUsage,
  meterOpenAIUsage,
} from './adapters/sdk.js';
export type {
  AnthropicUsage,
  GuardedHandler,
  OpenAIToolCall,
  OpenAIToolMessage,
  OpenAIUsage,
  TextBlock,
  ToolErrorResult,
  ToolHandler,
  ToolResultBlock,
  ToolUseBlock,
} from './adapters/sdk.js';

export { evaluate } from './policy/engine.js';
export { loadPolicyFile, parsePolicy, validatePolicy, PolicyError } from './policy/load.js';
export { matchesGlob, resolvePath } from './policy/match.js';

export { Ledger } from './budget/ledger.js';
export type { TokenPrice } from './budget/ledger.js';

export { AuditLog, canonicalize, hashEntry, GENESIS } from './audit/chain.js';
export type { AuditEntry, AuditLogOptions } from './audit/chain.js';
export { verifyChain, verifyFile } from './audit/verify.js';
export type { VerifyResult } from './audit/verify.js';

export type {
  ArgConstraint,
  BudgetLimits,
  BudgetUsage,
  Decision,
  Effect,
  EvalContext,
  Policy,
  PolicyRule,
  RateLimit,
  ToolCall,
  Violation,
} from './types.js';
