"""
Argument constraint evaluation.

Each check returns a Violation or nothing. They run in a fixed order so the
first reported violation for a given value is always the same one -- audit
diffs stay stable across releases.
"""

from __future__ import annotations

import re
from typing import Any, Final, Sequence
from urllib.parse import urlsplit

from .._js import js_json, js_number
from ..types import ArgConstraint, Violation
from .match import MISSING, resolve_path

_STRING_CONSTRAINTS: Final = ("matches", "startsWith", "excludes", "urlHosts")
_NUMBER_CONSTRAINTS: Final = ("min", "max")
_LENGTH_CONSTRAINTS: Final = ("minLength", "maxLength")

_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*$")


def check_args(
    rule_id: str,
    when: dict[str, ArgConstraint],
    args: dict[str, Any],
) -> list[Violation]:
    """
    Evaluate every constraint in ``when`` against ``args``.

    Returns all violations found, so a policy author sees the full picture
    rather than fixing one argument at a time.
    """
    violations: list[Violation] = []
    for path, constraint in when.items():
        violations.extend(_check_one(rule_id, path, constraint, resolve_path(args, path)))
    return violations


def _check_one(
    rule: str,
    path: str,
    c: ArgConstraint,
    value: Any,
) -> list[Violation]:
    def v(constraint: str, message: str) -> Violation:
        return Violation(rule=rule, path=path, constraint=constraint, message=message)

    # An own key explicitly set to None is indistinguishable from an absent one
    # for policy purposes, and treating it as present would let
    # ``{"path": None}`` satisfy a required, scoped constraint.
    if value is MISSING or value is None:
        if c.optional:
            return []
        return [v("required", f'argument "{path}" is required but was not provided')]

    out: list[Violation] = []

    if c.type is not None and not _is_type(value, c.type):
        # A type mismatch makes every downstream check meaningless, so stop here.
        return [v("type", f'argument "{path}" must be a {c.type}, got {_describe(value)}')]

    # Constraints below are type-specific. Skipping one because the value has an
    # unexpected type would fail OPEN: `startsWith: ["/tmp/"]` would be satisfied
    # by the list ["/etc/passwd"], and the rule would still match and allow the
    # call. `args` is untrusted model output, so a wrong type is a violation.
    string_constraints = _present_keys(c, _STRING_CONSTRAINTS)
    number_constraints = _present_keys(c, _NUMBER_CONSTRAINTS)
    length_constraints = _present_keys(c, _LENGTH_CONSTRAINTS)

    is_string = isinstance(value, str)
    is_number = isinstance(value, (int, float)) and not isinstance(value, bool)
    has_length = _length_of(value) is not None

    if string_constraints and not is_string:
        out.append(
            v(
                "type",
                f'argument "{path}" must be a string to be checked against '
                f"{_list(string_constraints)}, got {_describe(value)}",
            )
        )
    if number_constraints and not is_number:
        out.append(
            v(
                "type",
                f'argument "{path}" must be a number to be checked against '
                f"{_list(number_constraints)}, got {_describe(value)}",
            )
        )
    if length_constraints and not has_length:
        out.append(
            v(
                "type",
                f'argument "{path}" must be a string or array to be checked against '
                f"{_list(length_constraints)}, got {_describe(value)}",
            )
        )

    if c.oneOf is not None and not any(_deep_equal(allowed, value) for allowed in c.oneOf):
        out.append(v("oneOf", f'argument "{path}" must be one of {js_json(c.oneOf)}'))

    if c.noneOf is not None and any(_deep_equal(banned, value) for banned in c.noneOf):
        out.append(v("noneOf", f'argument "{path}" must not be {js_json(value)}'))

    if is_string:
        if c.matches is not None and re.search(c.matches, value) is None:
            out.append(v("matches", f'argument "{path}" must match /{c.matches}/'))
        if c.startsWith is not None and not any(value.startswith(p) for p in c.startsWith):
            out.append(
                v(
                    "startsWith",
                    f'argument "{path}" must start with one of {js_json(c.startsWith)}',
                )
            )
        if c.excludes is not None:
            hit = next((needle for needle in c.excludes if needle in value), None)
            if hit is not None:
                out.append(
                    v("excludes", f'argument "{path}" must not contain {js_json(hit)}')
                )
        if c.urlHosts is not None:
            host = _hostname_of(value)
            if host is None:
                out.append(v("urlHosts", f'argument "{path}" is not a parseable URL'))
            elif not any(_host_allowed(host, allowed) for allowed in c.urlHosts):
                out.append(
                    v(
                        "urlHosts",
                        f'host "{host}" is not in the allowed set {js_json(c.urlHosts)}',
                    )
                )

    if is_number:
        if c.min is not None and value < c.min:
            out.append(
                v("min", f'argument "{path}" must be >= {js_number(c.min)}, '
                         f"got {js_number(value)}")
            )
        if c.max is not None and value > c.max:
            out.append(
                v("max", f'argument "{path}" must be <= {js_number(c.max)}, '
                         f"got {js_number(value)}")
            )

    length = _length_of(value)
    if length is not None:
        if c.maxLength is not None and length > c.maxLength:
            out.append(
                v(
                    "maxLength",
                    f'argument "{path}" must have length <= {js_number(c.maxLength)}, '
                    f"got {js_number(length)}",
                )
            )
        if c.minLength is not None and length < c.minLength:
            out.append(
                v(
                    "minLength",
                    f'argument "{path}" must have length >= {js_number(c.minLength)}, '
                    f"got {js_number(length)}",
                )
            )

    return out


def _present_keys(c: ArgConstraint, keys: Sequence[str]) -> list[str]:
    """Which of ``keys`` the author actually set on this constraint."""
    return [key for key in keys if getattr(c, key) is not None]


def _list(names: Sequence[str]) -> str:
    return ", ".join(f'"{n}"' for n in names)


def _is_type(value: Any, type_: str) -> bool:
    if type_ == "array":
        return isinstance(value, list)
    if type_ == "object":
        return isinstance(value, dict)
    if type_ == "boolean":
        return isinstance(value, bool)
    if type_ == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, str)


def _length_of(value: Any) -> int | None:
    if isinstance(value, str):
        # JavaScript's String#length counts UTF-16 code units, so an astral
        # character costs two. Python counts code points; convert to keep a
        # maxLength written against one implementation binding in the other.
        return len(value.encode("utf-16-le", errors="surrogatepass")) // 2
    if isinstance(value, list):
        return len(value)
    return None


def _describe(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, list):
        return "array"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return "object"


def _hostname_of(raw: str) -> str | None:
    """The hostname of an absolute URL, or None when it will not parse.

    ``urlsplit`` is permissive where ``new URL()`` throws, so the absolute-URL
    requirement is enforced here: a scheme is mandatory, and a URL that declares
    an authority must actually have one.
    """
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    if not _SCHEME.match(parts.scheme):
        return None
    if raw[len(parts.scheme) + 1:].startswith("//") and not parts.netloc:
        return None
    try:
        host = parts.hostname
    except ValueError:
        return None
    if host is None:
        return "" if parts.netloc == "" else None
    return host.lower()


def _host_allowed(host: str, allowed: str) -> bool:
    """
    An entry starting with "." matches that domain and every subdomain
    (".example.com" covers "api.example.com" and "example.com"). Anything else
    must match exactly, so an allowlist never widens by accident.
    """
    pattern = allowed.lower()
    if pattern.startswith("."):
        return host == pattern[1:] or host.endswith(pattern)
    return host == pattern


def _deep_equal(a: Any, b: Any) -> bool:
    """Structural equality with JavaScript's type strictness.

    Python would call ``1 == True`` and ``1 == 1.0`` equal; the first of those
    would let a boolean argument satisfy a numeric ``oneOf``, so booleans are
    compared only to booleans.
    """
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    if isinstance(a, bool):
        return a is b
    if isinstance(a, dict) or isinstance(b, dict):
        if not (isinstance(a, dict) and isinstance(b, dict)) or len(a) != len(b):
            return False
        return all(k in b and _deep_equal(v, b[k]) for k, v in a.items())
    if isinstance(a, list) or isinstance(b, list):
        if not (isinstance(a, list) and isinstance(b, list)) or len(a) != len(b):
            return False
        return all(_deep_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, str) != isinstance(b, str):
        return False
    if a is None or b is None:
        return a is None and b is None
    return a == b
