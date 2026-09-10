"""
Tool-name globbing and argument-path resolution.

Deliberately tiny and dependency-free: this code sits on the hot path of
every tool call, and a policy author must be able to predict what it does
without reading a regex dialect reference.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any, Final, Sequence


def matches_glob(pattern: str, name: str) -> bool:
    """
    ``*`` matches any run of characters except the separators ``.`` and ``/``.
    ``**`` matches anything, separators included.
    Everything else is literal. Matching is case-sensitive and whole-string.
    """
    return _glob_to_regexp(pattern).match(name) is not None


@lru_cache(maxsize=None)
def _glob_to_regexp(pattern: str) -> re.Pattern[str]:
    out = ["^"]
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                out.append(".*")
                i += 1
            else:
                out.append("[^./]*")
        else:
            out.append(re.escape(char))
        i += 1
    # \Z rather than $, which in Python (as in JavaScript without /m) would
    # still let a trailing newline slip past the anchor.
    out.append(r"\Z")
    return re.compile("".join(out), re.DOTALL)


def matches_any_glob(patterns: Sequence[str], name: str) -> bool:
    """True when any pattern in the list matches. An empty list matches nothing."""
    return any(matches_glob(p, name) for p in patterns)


class _Missing:
    """Sentinel distinguishing "resolved to null" from "path does not exist"."""

    def __repr__(self) -> str:
        return "MISSING"

    def __bool__(self) -> bool:
        return False


MISSING: Final[_Missing] = _Missing()


def _array_index(segment: str) -> int | None:
    """A path segment as a list index, or None when it does not address one.

    Mirrors ``Number(segment)`` followed by the ``Number.isInteger`` gate, so
    "length" and "-1" resolve to MISSING rather than to something surprising.
    """
    text = segment.strip()
    if text == "":
        return 0
    try:
        value = float(text)
    except ValueError:
        return None
    if value < 0 or not value.is_integer():
        return None
    return int(value)


def resolve_path(args: Any, path: str) -> Any:
    """
    Resolve a dotted path against an argument object.

    Numeric segments index into lists (``recipients.0``). A path that runs off
    the end of the object -- or through a None -- yields MISSING rather than
    raising, so a malformed model argument becomes a policy violation, not a
    crash.
    """
    cursor: Any = args

    for segment in path.split("."):
        if cursor is None:
            return MISSING

        if isinstance(cursor, (list, tuple)):
            index = _array_index(segment)
            if index is None or index >= len(cursor):
                return MISSING
            cursor = cursor[index]
            continue

        if not isinstance(cursor, dict):
            return MISSING
        if segment not in cursor:
            return MISSING
        cursor = cursor[segment]

    return cursor
