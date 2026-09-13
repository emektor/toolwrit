"""
Policy parsing and validation.

Validation is strict and rejects unknown keys. In a security policy a typo
is not a harmless no-op: ``startWith`` silently ignored would turn a scoped
filesystem rule into an unscoped one. Fail loudly at load time instead.

Throughout this module an absent key and a key written as ``null`` are held
apart, via the UNDEFINED sentinel. They are not the same thing: an absent
``budget.calls`` means "no ceiling", while ``calls: null`` is a policy the
author got wrong and should hear about.
"""

from __future__ import annotations

import math
import re
from typing import Any, Final

import yaml

from .._js import UNDEFINED, js_json
from ..types import (
    ArgConstraint,
    BudgetLimits,
    Effect,
    Policy,
    PolicyRule,
    RateLimit,
    RunPlan,
)


class PolicyError(Exception):
    """A policy that cannot be trusted. Carries the location of the problem."""

    def __init__(self, message: str, path: str) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path


EFFECTS: Final[frozenset[str]] = frozenset({"allow", "deny", "ask"})
_POLICY_KEYS: Final = ("version", "name", "default", "budget", "plan", "rules")
_PLAN_KEYS: Final = ("purpose", "approvedBy", "warnAt")
_RULE_KEYS: Final = ("id", "description", "tools", "effect", "when", "limit")
_BUDGET_KEYS: Final = ("calls", "tokens", "usd", "bytes", "seconds")
_LIMIT_KEYS: Final = ("max", "perSeconds")
_CONSTRAINT_KEYS: Final = (
    "optional", "oneOf", "noneOf", "matches", "startsWith", "excludes",
    "min", "max", "maxLength", "minLength", "urlHosts", "type",
)
_ARG_TYPES: Final = ("string", "number", "boolean", "object", "array")


def load_policy_file(file: str) -> Policy:
    """Read and validate a policy from a ``.yaml``, ``.yml`` or ``.json`` file."""
    try:
        with open(file, "r", encoding="utf-8") as handle:
            raw = handle.read()
    except OSError as err:
        raise PolicyError(f"cannot read policy file ({err})", file) from err
    return parse_policy(raw, file)


def parse_policy(raw: str, source: str = "policy") -> Policy:
    """Validate an already-read policy document. ``source`` only decorates errors."""
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as err:
        raise PolicyError(f"invalid YAML/JSON ({err})", source) from err
    return validate_policy(doc, source)


def validate_policy(doc: Any, source: str = "policy") -> Policy:
    root = _require_object(doc, source)
    _reject_unknown_keys(root, _POLICY_KEYS, source)

    version = _get(root, "version")
    if version != "1":
        raise PolicyError(
            f"unsupported policy version {_describe_value(version)}; expected \"1\"",
            source,
        )

    name = _get(root, "name")
    if name is not UNDEFINED and not isinstance(name, str):
        raise PolicyError('"name" must be a string', source)

    default = _get(root, "default")
    if default is not UNDEFINED and default not in EFFECTS:
        raise PolicyError('"default" must be one of allow, deny, ask', source)

    policy = Policy(
        version="1",
        rules=[],
        name=None if name is UNDEFINED else name,
        default=None if default is UNDEFINED else _as_effect(default),
    )

    budget_raw = _get(root, "budget")
    if budget_raw is not UNDEFINED:
        budget = _require_object(budget_raw, f"{source}.budget")
        _reject_unknown_keys(budget, _BUDGET_KEYS, f"{source}.budget")
        limits: dict[str, float | None] = {}
        for key in _BUDGET_KEYS:
            value = _get(budget, key)
            if value is UNDEFINED:
                limits[key] = None
                continue
            if not _is_number(value) or not math.isfinite(value) or value <= 0:
                raise PolicyError(f'"{key}" must be a positive number', f"{source}.budget")
            limits[key] = value
        policy.budget = BudgetLimits(**limits)

    plan_raw = _get(root, "plan")
    if plan_raw is not UNDEFINED:
        plan = _require_object(plan_raw, f"{source}.plan")
        _reject_unknown_keys(plan, _PLAN_KEYS, f"{source}.plan")

        purpose = _get(plan, "purpose")
        if not isinstance(purpose, str) or purpose.strip() == "":
            raise PolicyError('"purpose" must be a non-empty string', f"{source}.plan")

        approved_by = _get(plan, "approvedBy")
        if approved_by is not UNDEFINED and not isinstance(approved_by, str):
            raise PolicyError('"approvedBy" must be a string', f"{source}.plan")

        warn_at = _get(plan, "warnAt")
        if warn_at is not UNDEFINED:
            if not isinstance(warn_at, list) or len(warn_at) == 0:
                raise PolicyError('"warnAt" must be a non-empty array', f"{source}.plan")
            for threshold in warn_at:
                if not _is_number(threshold) or not threshold > 0 or threshold > 1:
                    raise PolicyError(
                        '"warnAt" entries must be fractions greater than 0 and at '
                        "most 1, e.g. 0.8",
                        f"{source}.plan",
                    )
        # A plan with nothing to measure against would report nothing, which reads
        # as "all clear" rather than "not configured". Fail loudly instead.
        if budget_raw is UNDEFINED:
            raise PolicyError(
                'a "plan" requires a "budget" to measure against; add budget limits '
                "or remove the plan",
                source,
            )

        policy.plan = RunPlan(
            purpose=purpose,
            approvedBy=None if approved_by is UNDEFINED else approved_by,
            warnAt=None if warn_at is UNDEFINED else sorted(warn_at),
        )

    rules_raw = _get(root, "rules")
    if not isinstance(rules_raw, list):
        raise PolicyError('"rules" must be an array', source)

    seen: set[str] = set()
    for i, raw_rule in enumerate(rules_raw):
        parsed = _validate_rule(raw_rule, f"{source}.rules[{i}]")
        if parsed.id in seen:
            raise PolicyError(f'duplicate rule id "{parsed.id}"', f"{source}.rules[{i}]")
        seen.add(parsed.id)
        policy.rules.append(parsed)

    return policy


def _validate_rule(raw: Any, path: str) -> PolicyRule:
    rule = _require_object(raw, path)
    _reject_unknown_keys(rule, _RULE_KEYS, path)

    identifier = _get(rule, "id")
    if not isinstance(identifier, str) or identifier == "":
        raise PolicyError('"id" must be a non-empty string', path)

    description = _get(rule, "description")
    if description is not UNDEFINED and not isinstance(description, str):
        raise PolicyError('"description" must be a string', path)

    tools = _get(rule, "tools")
    if not isinstance(tools, list) or len(tools) == 0:
        raise PolicyError('"tools" must be a non-empty array of glob patterns', path)
    for tool in tools:
        if not isinstance(tool, str) or tool == "":
            raise PolicyError('every entry in "tools" must be a non-empty string', path)

    effect = _get(rule, "effect")
    if effect not in EFFECTS:
        raise PolicyError('"effect" must be one of allow, deny, ask', path)

    out = PolicyRule(
        id=identifier,
        tools=list(tools),
        effect=_as_effect(effect),
        description=None if description is UNDEFINED else description,
    )

    when_raw = _get(rule, "when")
    if when_raw is not UNDEFINED:
        when = _require_object(when_raw, f"{path}.when")
        out.when = {
            arg_path: _validate_constraint(constraint, f'{path}.when["{arg_path}"]')
            for arg_path, constraint in when.items()
        }

    limit_raw = _get(rule, "limit")
    if limit_raw is not UNDEFINED:
        limit = _require_object(limit_raw, f"{path}.limit")
        _reject_unknown_keys(limit, _LIMIT_KEYS, f"{path}.limit")

        maximum = _get(limit, "max")
        if not _is_number(maximum) or not _is_integer(maximum) or maximum < 0:
            raise PolicyError('"max" must be a non-negative integer', f"{path}.limit")

        per_seconds = _get(limit, "perSeconds")
        if per_seconds is not UNDEFINED and (
            not _is_number(per_seconds) or per_seconds <= 0
        ):
            raise PolicyError('"perSeconds" must be a positive number', f"{path}.limit")

        out.limit = RateLimit(
            max=int(maximum),
            perSeconds=None if per_seconds is UNDEFINED else per_seconds,
        )

    return out


def _validate_constraint(raw: Any, path: str) -> ArgConstraint:
    c = _require_object(raw, path)
    _reject_unknown_keys(c, _CONSTRAINT_KEYS, path)

    matches = _get(c, "matches")
    if matches is not UNDEFINED:
        if not isinstance(matches, str):
            raise PolicyError('"matches" must be a string', path)
        try:
            re.compile(matches)
        except re.error as err:
            raise PolicyError(f'"matches" is not a valid regexp ({err})', path) from err

    for key in ("startsWith", "excludes", "urlHosts"):
        value = _get(c, key)
        if value is UNDEFINED:
            continue
        if not isinstance(value, list) or any(not isinstance(e, str) for e in value):
            raise PolicyError(f'"{key}" must be an array of strings', path)

    for key in ("oneOf", "noneOf"):
        value = _get(c, key)
        if value is not UNDEFINED and not isinstance(value, list):
            raise PolicyError(f'"{key}" must be an array', path)

    for key in ("min", "max", "maxLength", "minLength"):
        value = _get(c, key)
        if value is not UNDEFINED and not _is_number(value):
            raise PolicyError(f'"{key}" must be a number', path)

    optional = _get(c, "optional")
    if optional is not UNDEFINED and not isinstance(optional, bool):
        raise PolicyError('"optional" must be a boolean', path)

    type_ = _get(c, "type")
    if type_ is not UNDEFINED and type_ not in _ARG_TYPES:
        raise PolicyError(
            '"type" must be one of string, number, boolean, object, array', path
        )

    return ArgConstraint(
        **{
            key: (None if (value := _get(c, key)) is UNDEFINED else value)
            for key in _CONSTRAINT_KEYS
        }
    )


def _get(obj: dict[str, Any], key: str) -> Any:
    """The value at ``key``, or UNDEFINED when the key is absent."""
    return obj.get(key, UNDEFINED)


def _describe_value(value: Any) -> str:
    """How the TypeScript template literal renders a rejected version value."""
    return "undefined" if value is UNDEFINED else js_json(value)


def _as_effect(value: Any) -> Effect:
    """Narrow an already-validated string to the Effect literal type."""
    return value  # type: ignore[return-value]


def _is_number(value: Any) -> bool:
    """JavaScript's ``typeof x === 'number'``: booleans are not numbers."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_integer(value: float) -> bool:
    return math.isfinite(value) and float(value).is_integer()


def _require_object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError("expected an object", path)
    return value


def _reject_unknown_keys(obj: dict[str, Any], allowed: tuple[str, ...], path: str) -> None:
    unknown = [key for key in obj if key not in allowed]
    if unknown:
        named = ", ".join('"' + str(key) + '"' for key in unknown)
        raise PolicyError(
            f"unknown field(s) {named}; allowed: {', '.join(allowed)}",
            path,
        )
