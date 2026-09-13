"""
JavaScript-compatible primitives.

This module exists for exactly one reason: a Toolwrit audit chain written by the
Python port must verify under the TypeScript ``toolwrit verify``, and vice versa.
The chain hashes a *canonical string*, so every byte of that string has to be
produced the way JavaScript would produce it -- which is not the way Python
does it by default.

Three places where the two languages disagree, and which are therefore
implemented here from the ECMAScript spec rather than borrowed from ``json``:

* Numbers. JavaScript has one numeric type (a double) and prints it with
  Number::toString: ``1.0`` is ``"1"``, ``1e21`` is ``"1e+21"``, ``1e16`` is
  ``"10000000000000000"``. Python's ``repr`` switches to exponent notation at a
  different magnitude and always keeps the ``.0``.
* Strings. ``JSON.stringify`` escapes lone surrogates as ``\\udXXX``; Python's
  ``json`` emits them raw when ``ensure_ascii=False``.
* Key order. ``canonicalize`` sorts by UTF-16 code unit, which differs from
  Python's code-point order for anything outside the BMP.

Everything here is pure and total: no exceptions escape for values the
serialiser is asked to handle.
"""

from __future__ import annotations

import dataclasses
import math
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Final


class _Undefined:
    """Stand-in for JavaScript ``undefined``.

    Python's ``None`` maps onto JSON ``null``, which JavaScript *keeps*; there
    is no built-in value that maps onto the ``undefined`` that JSON.stringify
    *drops*. Serialising an entry that contains a null-valued key as if the key
    were absent would break chain compatibility outright -- ``decision.rule`` is
    legitimately null on every default-deny -- so the two concepts are kept
    distinct and this sentinel carries the "drop me" meaning.
    """

    _instance: "_Undefined | None" = None

    def __new__(cls) -> "_Undefined":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "UNDEFINED"

    def __bool__(self) -> bool:
        return False


UNDEFINED: Final[_Undefined] = _Undefined()


# --------------------------------------------------------------------------- #
# Numbers
# --------------------------------------------------------------------------- #

def js_number(value: float | int) -> str:
    """Format a number the way JavaScript's ``String(number)`` does.

    ECMAScript Number::toString, section 6.1.6.1.20. The shortest round-tripping
    decimal digits come from Python's own ``repr`` (both languages use the same
    shortest-representation algorithm); only the *layout* of those digits around
    the decimal point differs, and that is what the branches below fix up.
    """
    if isinstance(value, bool):  # bool is an int subclass in Python; not in JS.
        return "true" if value else "false"

    x = _as_double(value)
    if math.isnan(x):
        return "NaN"
    if math.isinf(x):
        return "Infinity" if x > 0 else "-Infinity"
    if x == 0:
        return "0"  # JavaScript prints -0 as "0" too.
    if x < 0:
        return "-" + js_number(-x)

    digits, n = _shortest_digits(x)
    k = len(digits)

    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    exponent = n - 1
    sign = "+" if exponent >= 0 else "-"
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return f"{mantissa}e{sign}{abs(exponent)}"


def js_to_fixed(value: float | int, fraction_digits: int) -> str:
    """``Number.prototype.toFixed``.

    Rounds the *exact* binary value half-away-from-zero, which is why
    ``(1.005).toFixed(2)`` is ``"1.00"`` in both languages: 1.005 as a double is
    fractionally below 1.005. Python's ``format`` rounds half-to-even and would
    disagree on genuine ties, so the arithmetic is done in ``Decimal``.
    """
    x = _as_double(value)
    if math.isnan(x):
        return "NaN"
    if math.isinf(x) or abs(x) >= 1e21:
        return js_number(x)

    sign = "-" if x < 0 else ""
    quantum = Decimal(1).scaleb(-fraction_digits)
    rounded = Decimal(abs(x)).quantize(quantum, rounding=ROUND_HALF_UP)
    return f"{sign}{rounded:f}"


def js_round(value: float) -> int:
    """``Math.round``: ties go towards positive infinity, not towards even."""
    return math.floor(value + 0.5)


def js_locale_integer(value: float | int) -> str:
    """``(n).toLocaleString('en-US')`` for the integral case: 12500 -> "12,500"."""
    return f"{int(value):,}"


def _as_double(value: float | int) -> float:
    """Every JavaScript number is a double; a Python int that will not fit is
    the same overflow JSON.parse would produce, so it becomes an infinity."""
    try:
        return float(value)
    except OverflowError:
        return math.inf if value > 0 else -math.inf


def _shortest_digits(x: float) -> tuple[str, int]:
    """Split a positive finite double into (significant digits, exponent) where
    ``x == 0.digits * 10**n`` -- the (s, k, n) triple the spec is written in."""
    text = repr(x)
    if "e" in text or "E" in text:
        mantissa, _, exponent = text.partition("e")
        power = int(exponent)
    else:
        mantissa, power = text, 0

    integer, _, fraction = mantissa.partition(".")
    significant = (integer + fraction).lstrip("0")
    # value == significant * 10**(power - len(fraction)), so the spec's n --
    # the position of the decimal point relative to the digit string -- is the
    # digit count plus that scale.
    n = len(significant) + power - len(fraction)
    return significant.rstrip("0"), n


# --------------------------------------------------------------------------- #
# Strings
# --------------------------------------------------------------------------- #

_ESCAPES: Final[dict[int, str]] = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def js_string(value: str) -> str:
    """Quote a string exactly as ``JSON.stringify`` does.

    Non-ASCII characters stay literal; only C0 controls, the quote, the
    backslash and unpaired surrogates are escaped.
    """
    out = ['"']
    for char in value:
        code = ord(char)
        escape = _ESCAPES.get(code)
        if escape is not None:
            out.append(escape)
        elif code < 0x20 or 0xD800 <= code <= 0xDFFF:
            # A paired surrogate cannot occur here: Python strings hold code
            # points, so anything in this range is lone and must be escaped to
            # stay well-formed, which is what JSON.stringify does.
            out.append(f"\\u{code:04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _utf16_key(text: str) -> bytes:
    """Sort key reproducing JavaScript's ``<`` on strings (UTF-16 code units)."""
    return text.encode("utf-16-be", errors="surrogatepass")


# --------------------------------------------------------------------------- #
# Structures
# --------------------------------------------------------------------------- #

def to_jsonable(value: Any) -> Any:
    """Convert dataclasses to plain dicts, honouring per-class omission rules.

    A dataclass field listed in the class's ``JSON_OMIT_IF_NONE`` is dropped
    when it is ``None``, mirroring the TypeScript objects that simply never set
    an optional key. Fields not listed keep their ``None`` and serialise as
    ``null`` -- ``Decision.rule`` being the case that matters.
    """
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        omit = getattr(type(value), "JSON_OMIT_IF_NONE", frozenset())
        out: dict[str, Any] = {}
        for field in dataclasses.fields(value):
            item = getattr(value, field.name)
            if item is UNDEFINED or (item is None and field.name in omit):
                continue
            out[field.name] = to_jsonable(item)
        return out
    if isinstance(value, dict):
        return {k: to_jsonable(v) for k, v in value.items() if v is not UNDEFINED}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    return value


def js_json(value: Any, *, sort_keys: bool = False) -> str:
    """``JSON.stringify(value)`` with no indentation.

    With ``sort_keys`` this is the canonical form the hash chain commits to;
    without it, it is the plain stringify used inside human-facing messages,
    which must not reorder what the policy author wrote.
    """
    value = to_jsonable(value)

    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return js_string(value)
    if isinstance(value, (int, float)):
        text = js_number(value)
        # JSON has no NaN or Infinity; JSON.stringify emits null for both.
        return "null" if text in ("NaN", "Infinity", "-Infinity") else text
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(js_json(item, sort_keys=sort_keys) for item in value) + "]"
    if isinstance(value, dict):
        items = [(k, v) for k, v in value.items() if v is not UNDEFINED]
        if sort_keys:
            items.sort(key=lambda pair: _utf16_key(pair[0]))
        body = ",".join(
            f"{js_string(k)}:{js_json(v, sort_keys=sort_keys)}" for k, v in items
        )
        return "{" + body + "}"
    if value is UNDEFINED:
        return "null"
    raise TypeError(f"cannot serialise {type(value).__name__} as JSON")
