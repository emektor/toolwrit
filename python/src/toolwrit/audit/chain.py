"""
Tamper-evident audit log.

Entries form a hash chain: each one commits to the hash of its predecessor,
so editing or deleting any past entry invalidates every hash after it. This
is what turns "we had a policy" into "here is what the policy actually did",
which is the only version an auditor accepts.

The format is JSONL -- one entry per line -- so it survives a crash mid-run
and can be tailed, grepped and shipped to any log pipeline unchanged. A file
written here verifies under the TypeScript ``toolwrit verify`` and the other way
round, which is why ``canonicalize`` goes through the JavaScript-compatible
serialiser in ``toolwrit._js`` rather than through Python's ``json``.
"""

from __future__ import annotations

import copy
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Final, Sequence

from .._js import js_json, to_jsonable
from ..types import Decision, HistoryEntry, ToolCall, Violation

#: Hash recorded as the predecessor of the first entry.
GENESIS: Final[str] = "0" * 64


@dataclass
class AuditEntry:
    #: 1-based position in the chain.
    seq: int
    #: Milliseconds since epoch, taken from the tool call.
    at: int
    #: Run identifier, so several runs can share one log file.
    run: str
    tool: str
    #: Arguments as evaluated. Redacted fields are replaced before hashing.
    args: dict[str, Any]
    decision: Decision
    #: Budget consumption at the moment of the decision.
    usage: dict[str, float]
    #: Hash of the preceding entry, or GENESIS.
    prev: str
    #: sha256 over the canonical form of this entry, excluding ``hash`` itself.
    hash: str = ""

    def body(self) -> dict[str, Any]:
        """The entry without its own hash -- what the hash is taken over."""
        return {
            "seq": self.seq,
            "at": self.at,
            "run": self.run,
            "tool": self.tool,
            "args": self.args,
            "decision": self.decision,
            "usage": self.usage,
            "prev": self.prev,
        }


def canonicalize(value: Any) -> str:
    """
    Deterministic JSON: object keys sorted, no incidental whitespace.

    Without this the chain would depend on the runtime's key ordering, and a log
    written by one process could fail verification in another. UNDEFINED values
    are dropped, matching what JSON.stringify does with ``undefined``; ``None``
    is JSON ``null`` and is kept, because ``decision.rule`` is legitimately null
    on every default-deny and the TypeScript chain commits to it.
    """
    return js_json(value, sort_keys=True)


def hash_entry(body: Any) -> str:
    return hashlib.sha256(canonicalize(body).encode("utf-8")).hexdigest()


def entry_to_dict(entry: AuditEntry) -> dict[str, Any]:
    """The wire form of an entry: plain JSON-able data, hash included."""
    return {**to_jsonable(entry.body()), "hash": entry.hash}


def entry_from_dict(raw: dict[str, Any]) -> AuditEntry:
    """Rebuild an entry from a parsed JSONL line, however malformed."""
    decision_raw = raw.get("decision")
    decision: Any
    if isinstance(decision_raw, dict):
        decision = Decision(
            effect=decision_raw.get("effect"),
            rule=decision_raw.get("rule"),
            reason=decision_raw.get("reason"),
            violations=[
                Violation(
                    rule=v.get("rule"),
                    constraint=v.get("constraint"),
                    message=v.get("message"),
                    path=v.get("path"),
                )
                if isinstance(v, dict)
                else v
                for v in (decision_raw.get("violations") or [])
            ],
        )
        # A violation without a path must stay without one, or the recomputed
        # hash would gain a "path":null the original never had.
        for parsed, original in zip(decision.violations, decision_raw.get("violations") or []):
            if isinstance(original, dict) and "path" not in original:
                parsed.path = None
    else:
        decision = decision_raw

    return AuditEntry(
        seq=raw.get("seq"),
        at=raw.get("at"),
        run=raw.get("run"),
        tool=raw.get("tool"),
        args=raw.get("args"),
        decision=decision,
        usage=raw.get("usage"),
        prev=raw.get("prev"),
        hash=raw.get("hash"),
    )


@dataclass
class AuditLogOptions:
    #: Run identifier stamped on every entry.
    run: str
    #: When set, entries are appended to this JSONL file as well as buffered.
    file: str | None = None
    #: Argument paths whose values are replaced with "[redacted]" before hashing.
    #: Secrets must never reach the log, but the chain still has to cover the
    #: redacted shape so a redaction cannot be forged after the fact.
    redact: list[str] = field(default_factory=list)


class AuditLog:
    def __init__(
        self,
        run: str,
        file: str | None = None,
        redact: Sequence[str] | None = None,
    ) -> None:
        self._options = AuditLogOptions(run=run, file=file, redact=list(redact or []))
        self._entries: list[AuditEntry] = []
        self._last = GENESIS
        if file:
            parent = os.path.dirname(file)
            if parent:
                os.makedirs(parent, exist_ok=True)

    def record(
        self,
        call: ToolCall,
        decision: Decision,
        usage: dict[str, float],
    ) -> AuditEntry:
        """Append a decision to the chain and return the entry that was written."""
        entry = AuditEntry(
            seq=len(self._entries) + 1,
            at=call.at,
            run=self._options.run,
            tool=call.tool,
            args=_redact_args(call.args, self._options.redact),
            decision=decision,
            usage=usage,
            prev=self._last,
        )
        entry.hash = hash_entry(entry.body())
        self._entries.append(entry)
        self._last = entry.hash

        if self._options.file:
            line = js_json(entry_to_dict(entry))
            with open(self._options.file, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        return entry

    def all(self) -> list[AuditEntry]:
        """Entries recorded by this instance, oldest first."""
        return list(self._entries)

    def head(self) -> str:
        """Hash of the newest entry -- the value a receipt should quote."""
        return self._last

    def history(self) -> list[HistoryEntry]:
        """History in the shape the policy engine wants for rate limiting."""
        return [
            HistoryEntry(tool=e.tool, rule=e.decision.rule, at=e.at)
            for e in self._entries
            if e.decision.effect != "deny"
        ]


def _redact_args(args: dict[str, Any], paths: Sequence[str]) -> dict[str, Any]:
    # Always clone, even with nothing to redact. Holding the caller's object by
    # reference would let a later mutation of it change what this entry hashes
    # to, silently invalidating an otherwise honest chain. The clone also keeps
    # the caller's object untouched: the agent may still need the real value.
    clone = copy.deepcopy(args)
    if not paths:
        return clone

    for path in paths:
        segments = path.split(".")
        leaf = segments.pop()
        if not leaf:
            continue

        cursor: Any = clone
        for segment in segments:
            cursor = _step(cursor, segment)
            if cursor is None:
                break

        if isinstance(cursor, dict) and leaf in cursor:
            cursor[leaf] = "[redacted]"
        elif isinstance(cursor, list):
            index = _index(leaf)
            if index is not None and index < len(cursor):
                cursor[index] = "[redacted]"
    return clone


def _step(cursor: Any, segment: str) -> Any:
    if isinstance(cursor, dict):
        return cursor.get(segment)
    if isinstance(cursor, list):
        index = _index(segment)
        return cursor[index] if index is not None and index < len(cursor) else None
    return None


def _index(segment: str) -> int | None:
    return int(segment) if segment.isascii() and segment.isdigit() else None


__all__ = [
    "GENESIS",
    "AuditEntry",
    "AuditLog",
    "AuditLogOptions",
    "canonicalize",
    "entry_from_dict",
    "entry_to_dict",
    "hash_entry",
]
