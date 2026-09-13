"""
Argument constraint evaluation.

Each check returns a Violation or nothing. They run in a fixed order so the
first reported violation for a given value is always the same one -- audit
diffs stay stable across releases.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any, Final, Sequence
from urllib.parse import urlsplit

from .._js import js_json, js_number
from ..types import ArgConstraint, Violation
from .match import MISSING, resolve_path

_STRING_CONSTRAINTS: Final = ("matches", "startsWith", "excludes", "urlHosts")
_NUMBER_CONSTRAINTS: Final = ("min", "max")
_LENGTH_CONSTRAINTS: Final = ("minLength", "maxLength")

_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*$")

# WHATWG calls these "special" schemes, and in them a backslash is a path
# separator exactly like "/". Every browser, curl and JavaScript's URL agree;
# Python's urlsplit does not, which is the whole reason _whatwg_slashes exists.
_SPECIAL_SCHEMES: Final = frozenset({"http", "https", "ws", "wss", "ftp", "file"})

# "file" is special for backslashes but has its own authority rules: a run of
# slashes is not collapsed (``file:///etc`` is host-less, not host "etc") and
# userinfo is rejected outright. Keeping it out of the collapsing set is the
# difference between agreeing with new URL() and inventing a host.
_AUTHORITY_SCHEMES: Final = _SPECIAL_SCHEMES - {"file"}


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
        if c.matches is not None and _js_regex(c.matches).search(value) is None:
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


@lru_cache(maxsize=512)
def _js_regex(pattern: str) -> re.Pattern[str]:
    r"""Compile ``pattern`` so it means in Python what it means in JavaScript.

    Python's ``$`` also matches just before a trailing newline; JavaScript's
    (without the ``m`` flag) matches only at the very end. So a policy written
    as ``matches: "^/tmp/[a-z]+$"`` accepts ``"/tmp/abc\n"`` here and rejects it
    there -- the same rule, two verdicts, and the permissive one is Python's.
    Rewriting the anchor to ``\Z`` closes that.

    Only a ``$`` that is actually an anchor is touched: one that is escaped or
    inside a character class is an ordinary dollar sign in both languages.
    """
    out: list[str] = []
    in_class = False
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            out.append(pattern[i:i + 2])
            i += 2
            continue
        if in_class:
            in_class = ch != "]"
        elif ch == "[":
            in_class = True
        elif ch == "$":
            out.append(r"\Z")
            i += 1
            continue
        out.append(ch)
        i += 1
    return re.compile("".join(out))


def _after_ipv6_literal(netloc: str) -> str:
    """The part of an authority following a bracketed IPv6 literal.

    An IPv6 host is full of colons, so "is there a port here?" cannot be asked
    of the whole authority without mistaking the address for one.
    """
    end = netloc.rfind("]")
    return netloc[end + 1:] if netloc.startswith("[") and end != -1 else netloc


def _whatwg_slashes(raw: str) -> str:
    """Backslashes before the query become "/" for a special scheme.

    ``http://evil.com\\@allowed.com/`` is the attack this exists for. A browser
    reads the backslash as the end of the authority and goes to ``evil.com``;
    ``urlsplit`` reads it as part of the userinfo and reports ``allowed.com``,
    so an allowlist written against what the request will actually do would
    have passed a URL aimed somewhere else entirely.

    Only the part before the first "?" or "#" is touched: a backslash is an
    ordinary character in a query string or fragment, and rewriting one there
    would change a URL that was never ambiguous.
    """
    if "\\" not in raw:
        return raw
    scheme, colon, rest = raw.partition(":")
    if not colon or scheme.lower() not in _SPECIAL_SCHEMES:
        return raw
    cut = min((i for i in (rest.find("?"), rest.find("#")) if i != -1), default=len(rest))
    return f"{scheme}:{rest[:cut].replace(chr(92), '/')}{rest[cut:]}"


def _hostname_of(raw: str) -> str | None:
    """The hostname of an absolute URL, or None when it will not parse.

    This has to agree with ``new URL().hostname`` on every input, because the
    two implementations enforce the same policy file and a host read one way
    here and another way there is an allowlist that means two different things.
    ``urlsplit`` is permissive where ``new URL()`` throws and strict where it is
    forgiving, so both directions are corrected below.
    """
    normalized = _whatwg_slashes(raw)
    scheme, colon, rest = normalized.partition(":")
    lowered = scheme.lower()
    if colon and lowered in _AUTHORITY_SCHEMES:
        # WHATWG skips any run of slashes between a special scheme and its
        # authority, so "http:a.com/" and "https:///x" both have a host.
        normalized = f"{scheme}://{rest.lstrip('/')}"

    try:
        parts = urlsplit(normalized)
    except ValueError:
        return None
    if not _SCHEME.match(parts.scheme):
        return None
    if lowered == "file":
        # A file URL carries neither userinfo nor a port -- new URL() throws on
        # both -- and its authority is legitimately empty in "file:///etc",
        # which is why this is decided before the empty-authority rule below.
        if "@" in parts.netloc:
            return None
        if ":" in _after_ipv6_literal(parts.netloc):
            return None
        if parts.netloc == "":
            return ""
    elif normalized[len(parts.scheme) + 1:].startswith("//") and not parts.netloc:
        # A special scheme must have an authority; a non-special one may
        # declare an empty one, and new URL() reports that as "".
        return None if lowered in _SPECIAL_SCHEMES else ""
    # urlsplit defers port validation until .port is read, so an authority
    # ending in "8443\" yields a perfectly good host and only complains later.
    # new URL() rejects the whole URL, so the port is checked here.
    # An empty port ("host:") is legal and means the default one.
    port = _after_ipv6_literal(parts.netloc.rpartition("@")[2]).partition(":")
    if port[1] and port[2] and not port[2].isdigit():
        return None

    try:
        host = parts.hostname
    except ValueError:
        return None
    if host is None:
        return "" if parts.netloc == "" else None
    host = host.lower()
    # urlsplit unwraps an IPv6 literal; new URL() keeps the brackets, and an
    # allowlist entry is written to match whichever form is reported.
    if ":" in host:
        return f"[{host}]"
    # IPv4 canonicalisation is part of the *special*-scheme host parser only;
    # for any other scheme WHATWG keeps the host as written, so "0x7f.1" stays
    # itself under "custom://".
    if lowered in _SPECIAL_SCHEMES:
        return _ipv4_canonical(host) or host
    # Outside a special scheme the host is an opaque host, and WHATWG forbids
    # these characters in one outright -- new URL() throws rather than
    # producing a host that no allowlist entry could ever have been written for.
    if any(ch in host for ch in "\\ #/?@[]:<>^|"):
        return None
    return host


def _ipv4_canonical(host: str) -> str | None:
    """WHATWG's IPv4 reading of a host, or None when it is not one.

    ``http://0x7f.1`` and ``http://2130706433`` both reach 127.0.0.1, and a
    browser shows them that way. An allowlist compared against the literal text
    would treat them as unknown hosts -- and a denylist would miss them
    entirely -- so the host is canonicalised the same way the client will.

    Parts may be decimal, octal (a leading 0) or hex (0x), and a short address
    lets its last part absorb the rest: "0x7f.1" is 127.0.0.1, not a domain.
    """
    parts = host.split(".")
    if parts and parts[-1] == "":      # one trailing dot is allowed, "1.2.3.4."
        parts = parts[:-1]
    if not parts or len(parts) > 4:
        return None

    numbers: list[int] = []
    for part in parts:
        text = part.lower()
        if text.startswith(("0x", "-0x")) or (text.startswith("0") and len(text) > 1):
            base = 16 if text.startswith("0x") else 8
            digits = text[2:] if base == 16 else text[1:]
            if digits == "" and base == 16:
                numbers.append(0)
                continue
        else:
            base, digits = 10, text
        allowed = "0123456789abcdef"[:16 if base == 16 else (8 if base == 8 else 10)]
        if digits == "" or any(ch not in allowed for ch in digits):
            return None
        numbers.append(int(digits, base))

    # Every part but the last must fit in a byte; the last absorbs what is left.
    if any(n > 255 for n in numbers[:-1]):
        return None
    if numbers[-1] >= 256 ** (5 - len(numbers)):
        return None

    value = numbers[-1]
    for index, number in enumerate(numbers[:-1]):
        value += number * 256 ** (3 - index)
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


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
