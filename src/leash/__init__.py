"""
Leash — a deterministic leash for AI agents.

Allowlist the tools, cap the budget, prove what happened.

A Python port of the TypeScript reference implementation. The audit chains the
two produce are byte-compatible: a log written here verifies under
``leash verify`` from the npm package, and vice versa.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .audit.chain import (
    GENESIS,
    AuditEntry,
    AuditLog,
    AuditLogOptions,
    canonicalize,
    entry_from_dict,
    entry_to_dict,
    hash_entry,
)
from .audit.verify import VerifyFailure, VerifyResult, verify_chain, verify_file
from .budget.ledger import Ledger, TokenPrice
from .leash import ApprovalHandler, Leash, LeashDenied
from .policy.engine import evaluate
from .policy.load import PolicyError, load_policy_file, parse_policy, validate_policy
from .policy.match import MISSING, matches_any_glob, matches_glob, resolve_path
from .types import (
    ArgConstraint,
    BudgetLimits,
    BudgetUsage,
    BudgetWarning,
    Decision,
    Effect,
    EvalContext,
    HistoryEntry,
    Policy,
    PolicyRule,
    RateLimit,
    RunPlan,
    ToolCall,
    Violation,
)

__all__ = [
    "__version__",
    # runtime
    "Leash",
    "LeashDenied",
    "ApprovalHandler",
    # policy
    "evaluate",
    "load_policy_file",
    "parse_policy",
    "validate_policy",
    "PolicyError",
    "matches_glob",
    "matches_any_glob",
    "resolve_path",
    "MISSING",
    # budget
    "Ledger",
    "TokenPrice",
    # audit
    "AuditLog",
    "AuditLogOptions",
    "AuditEntry",
    "canonicalize",
    "hash_entry",
    "entry_to_dict",
    "entry_from_dict",
    "GENESIS",
    "verify_chain",
    "verify_file",
    "VerifyResult",
    "VerifyFailure",
    # types
    "ArgConstraint",
    "BudgetLimits",
    "BudgetUsage",
    "BudgetWarning",
    "Decision",
    "Effect",
    "EvalContext",
    "HistoryEntry",
    "Policy",
    "PolicyRule",
    "RateLimit",
    "RunPlan",
    "ToolCall",
    "Violation",
]
