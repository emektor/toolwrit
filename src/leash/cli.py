"""
The ``leash`` binary.

A policy is only useful if it can be reviewed (``explain``), tested in CI
(``check``) and defended afterwards (``verify``) without writing any code.
Those three subcommands are what this file provides, with the same grammar,
the same output and the same exit codes as the TypeScript CLI, so a chain or a
policy can move between the two implementations without anyone relearning
anything.

``leash run`` -- the MCP proxy -- is deliberately absent here; see the README.

Argument parsing is hand-rolled rather than argparse-driven because the
TypeScript grammar it has to match is not argparse's, in particular the bare
``--`` hard stop and the ``--flag`` with no value.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Sequence

from . import __version__
from .audit.verify import verify_file
from .leash import Leash
from .policy.load import PolicyError, load_policy_file
from .types import ArgConstraint, Decision, Policy
from ._js import js_json, js_number

USAGE = """leash — a deterministic leash for AI agents.

Usage:
  leash verify  <audit.jsonl>
  leash check   --policy <file> --tool <name> [--args <json>]
  leash explain --policy <file>

Options:
  --help       Show this text.
  --version    Print the leash version.

Exit codes:
  verify   0 when the chain is intact, 1 when it is not.
  check    0 allow, 1 deny, 2 ask.
"""


@dataclass
class ParsedArgs:
    flags: dict[str, str] = field(default_factory=dict)
    positional: list[str] = field(default_factory=list)
    #: Everything after a bare ``--``, passed through untouched.
    rest: list[str] = field(default_factory=list)


def parse_args(argv: Sequence[str]) -> ParsedArgs:
    """
    Parse ``--key value`` / ``--key=value`` flags plus positionals.

    ``--`` is a hard stop: the remainder is a downstream command line and must
    never be interpreted, or a server's own ``--policy`` flag would be stolen.
    """
    parsed = ParsedArgs()
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            parsed.rest.extend(argv[i + 1:])
            break
        if token.startswith("--"):
            body = token[2:]
            if "=" in body:
                key, _, value = body.partition("=")
                parsed.flags[key] = value
            elif i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                parsed.flags[body] = argv[i + 1]
                i += 1
            else:
                parsed.flags[body] = "true"
        else:
            parsed.positional.append(token)
        i += 1
    return parsed


class CliError(Exception):
    """Errors we raise ourselves, and can therefore report without a traceback."""


def _reject_unknown_flags(
    parsed: ParsedArgs, allowed: Sequence[str], subcommand: str
) -> None:
    """
    Refuse a flag this subcommand does not implement.

    A mistyped or unsupported flag that is quietly dropped turns into a check
    the operator believes ran and did not, which is the same class of mistake
    the policy loader refuses to make with an unknown policy field.
    """
    unknown = sorted(set(parsed.flags) - set(allowed) - {"help", "version"})
    if unknown:
        names = ", ".join(f'"--{flag}"' for flag in unknown)
        raise CliError(f"unknown flag(s) {names} for `leash {subcommand}`")


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parsed = parse_args(argv)

    try:
        if not argv or "help" in parsed.flags or parsed.positional[:1] == ["help"]:
            sys.stdout.write(USAGE)
            return 0
        if "version" in parsed.flags:
            sys.stdout.write(f"{__version__}\n")
            return 0

        subcommand = parsed.positional[0] if parsed.positional else ""
        if subcommand == "verify":
            return _cmd_verify(parsed)
        if subcommand == "check":
            return _cmd_check(parsed)
        if subcommand == "explain":
            return _cmd_explain(parsed)
        if subcommand == "run":
            raise CliError(
                "`leash run` (the MCP proxy) is not part of the Python port; "
                "use the TypeScript CLI for it"
            )
        raise CliError(f'unknown subcommand "{subcommand}"\n\n{USAGE}')
    except CliError as err:
        sys.stderr.write(f"leash: {err}\n")
        return 1


def _cmd_verify(parsed: ParsedArgs) -> int:
    file = parsed.positional[1] if len(parsed.positional) > 1 else None
    if not file:
        raise CliError("verify needs an audit file, e.g. `leash verify audit.jsonl`")

    # Silently ignoring an unimplemented flag would be a fail-open in the one
    # command whose job is detecting tampering: `verify --against` exists to
    # catch a truncated log, and a run that prints "ok" and exits 0 without
    # having performed the anchor check is worse than no check at all.
    if "against" in parsed.flags:
        raise CliError(
            "`verify --against <anchor>` is not implemented in the Python CLI; "
            "the chain check alone cannot detect a truncated log, so use the "
            "TypeScript CLI (`leash verify <file> --against <anchor>`) rather "
            "than reading this run as a pass"
        )
    _reject_unknown_flags(parsed, (), "verify")

    try:
        result = verify_file(file)
    except OSError as err:
        raise CliError(f"cannot read audit file {file} ({err})") from err

    if result.ok:
        plural = "y" if result.count == 1 else "ies"
        sys.stdout.write(f"ok: {result.count} entr{plural} verified\n")
        sys.stdout.write(f"head: {result.head}\n")
        return 0

    sys.stderr.write(
        f"FAILED: audit chain is not intact ({result.count} entries read)\n"
    )
    if result.failure is not None:
        sys.stderr.write(f"  seq:    {result.failure.seq}\n")
        sys.stderr.write(f"  reason: {result.failure.reason}\n")
        sys.stderr.write(f"  detail: {result.failure.detail}\n")
    return 1


def _cmd_check(parsed: ParsedArgs) -> int:
    import json

    policy = _load_policy(_require_flag(parsed, "policy"))
    tool = _require_flag(parsed, "tool")

    raw = parsed.flags.get("args")
    args: dict[str, object] = {}
    if raw is not None and raw != "true":
        try:
            value = json.loads(raw)
        except ValueError as err:
            raise CliError(f"--args is not valid JSON ({err})") from err
        if not isinstance(value, dict):
            raise CliError("--args must be a JSON object")
        args = value

    # No audit file and no execution: `check` is a dry run, safe to put in CI.
    decision = Leash(policy).check(tool, args)
    _print_decision(tool, decision)
    return 0 if decision.effect == "allow" else 1 if decision.effect == "deny" else 2


def _print_decision(tool: str, decision: Decision) -> None:
    sys.stdout.write(f"{decision.effect.upper()} {tool}\n")
    sys.stdout.write(f"  rule:   {decision.rule or '(policy default)'}\n")
    sys.stdout.write(f"  reason: {decision.reason}\n")
    if decision.violations:
        sys.stdout.write("  violations:\n")
        for violation in decision.violations:
            where = f" {violation.path}" if violation.path else ""
            sys.stdout.write(
                f"    - [{violation.rule}{where}] {violation.constraint}: "
                f"{violation.message}\n"
            )


def _cmd_explain(parsed: ParsedArgs) -> int:
    file = _require_flag(parsed, "policy")
    sys.stdout.write(explain_policy(_load_policy(file), file))
    return 0


def explain_policy(policy: Policy, file: str) -> str:
    out: list[str] = []
    out.append(f"{policy.name or file} (version {policy.version})")
    out.append(f"default effect: {policy.default or 'deny'}")

    if policy.budget is not None:
        parts = [
            f"{key}={js_number(value)}"
            for key, value in (
                # Same order as the TypeScript CLI: a reviewer comparing the
                # two implementations on one policy must see one rendering, and
                # a dimension missing here reads as a ceiling that isn't set.
                ("calls", policy.budget.calls),
                ("tokens", policy.budget.tokens),
                ("usd", policy.budget.usd),
                ("bytes", policy.budget.bytes),
                ("seconds", policy.budget.seconds),
            )
            if value is not None
        ]
        out.append(f"budget: {', '.join(parts) if parts else '(none)'}")
    else:
        out.append("budget: unlimited")

    out.append("")
    out.append(
        f"rules ({len(policy.rules)}); among rules that match, "
        "deny beats ask beats allow:"
    )
    for rule in policy.rules:
        out.append("")
        out.append(f"  {rule.id}  [{rule.effect}]")
        if rule.description:
            out.append(f"    {rule.description}")
        out.append(f"    tools: {', '.join(rule.tools)}")
        if rule.limit is not None:
            window = (
                f"{js_number(rule.limit.perSeconds)}s"
                if rule.limit.perSeconds is not None
                else "run"
            )
            out.append(f"    limit: {js_number(rule.limit.max)} call(s) per {window}")
        for path, constraint in (rule.when or {}).items():
            out.append(f"    when {path}: {describe_constraint(constraint)}")

    return "\n".join(out) + "\n"


def describe_constraint(c: ArgConstraint) -> str:
    """Render one constraint as a phrase a reviewer can read out loud."""
    parts: list[str] = []
    if c.type:
        parts.append(f"is {c.type}")
    if c.optional:
        parts.append("may be absent")
    if c.oneOf is not None:
        parts.append(f"one of {js_json(c.oneOf)}")
    if c.noneOf is not None:
        parts.append(f"none of {js_json(c.noneOf)}")
    if c.matches:
        parts.append(f"matches /{c.matches}/")
    if c.startsWith is not None:
        parts.append("starts with " + " | ".join(c.startsWith))
    if c.excludes is not None:
        parts.append("excludes " + " | ".join(c.excludes))
    if c.urlHosts is not None:
        parts.append("url host in " + " | ".join(c.urlHosts))
    if c.min is not None:
        parts.append(f">= {js_number(c.min)}")
    if c.max is not None:
        parts.append(f"<= {js_number(c.max)}")
    if c.minLength is not None:
        parts.append(f"length >= {js_number(c.minLength)}")
    if c.maxLength is not None:
        parts.append(f"length <= {js_number(c.maxLength)}")
    return "; ".join(parts) if parts else "any value"


def _require_flag(parsed: ParsedArgs, name: str) -> str:
    value = parsed.flags.get(name)
    if value is None or value == "true":
        raise CliError(f"missing required --{name} <value>")
    return value


def _load_policy(file: str) -> Policy:
    try:
        return load_policy_file(file)
    except PolicyError as err:
        raise CliError(str(err)) from err


if __name__ == "__main__":
    sys.exit(main())
