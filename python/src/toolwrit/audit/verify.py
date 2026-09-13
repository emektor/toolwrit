"""
Chain verification.

Verification is the product. Anyone can write a log; the value is being able
to hand a regulator, a customer or an acquirer a file and a one-line command
that proves the file was not edited after the fact.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal, Sequence

from .chain import GENESIS, AuditEntry, entry_from_dict, hash_entry

FailureReason = Literal["bad-hash", "broken-link", "bad-sequence", "malformed"]


@dataclass(frozen=True)
class VerifyFailure:
    """Identifies the first entry that failed."""

    seq: int
    reason: FailureReason
    detail: str


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    #: Number of entries examined.
    count: int
    #: Hash of the final entry, or GENESIS for an empty log.
    head: str
    #: Populated when ok is False.
    failure: VerifyFailure | None = None


def verify_chain(entries: Sequence[AuditEntry]) -> VerifyResult:
    """Verify an in-memory chain. Stops at the first inconsistency."""
    prev = GENESIS

    for i, entry in enumerate(entries):
        seq = i + 1

        def fail(reason: FailureReason, detail: str) -> VerifyResult:
            return VerifyResult(
                ok=False,
                count=len(entries),
                head=prev,
                failure=VerifyFailure(seq=seq, reason=reason, detail=detail),
            )

        if entry.seq != seq:
            return fail(
                "bad-sequence",
                f"entry declares seq {entry.seq} but sits at position {seq}",
            )
        if entry.prev != prev:
            return fail(
                "broken-link",
                f"entry links to {_short(entry.prev)} but predecessor hashes to "
                f"{_short(prev)}",
            )

        recomputed = hash_entry(entry.body())
        if recomputed != entry.hash:
            return fail(
                "bad-hash",
                f"entry hashes to {_short(recomputed)} but claims {_short(entry.hash)}",
            )

        prev = entry.hash

    return VerifyResult(ok=True, count=len(entries), head=prev)


def verify_raw(raw_entries: Sequence[dict], count: int | None = None) -> VerifyResult:
    """
    Verify entries exactly as they were parsed from JSON.

    This hashes the parsed object itself rather than a dataclass rebuilt from
    the fields we recognise, and that distinction is the whole guarantee.
    Rebuilding silently DROPS any key the reader does not know about, so a
    field appended to an entry -- a top-level "note", a forged
    decision.approvedBy -- disappeared before the hash was recomputed and the
    log verified clean, while the TypeScript verifier, which hashes what it
    parsed, reported the same file as tampered. A verifier that only notices
    edits to fields it already expected is not a tamper detector.
    """
    total = len(raw_entries) if count is None else count
    prev = GENESIS

    for i, raw in enumerate(raw_entries):
        seq = i + 1

        def fail(reason: FailureReason, detail: str) -> VerifyResult:
            return VerifyResult(
                ok=False,
                count=total,
                head=prev,
                failure=VerifyFailure(seq=seq, reason=reason, detail=detail),
            )

        if not isinstance(raw, dict):
            return fail("malformed", f"entry {seq} is not a JSON object")

        claimed_hash = raw.get("hash")
        if not isinstance(claimed_hash, str):
            return fail("malformed", f"entry {seq} has no hash")

        if raw.get("seq") != seq:
            return fail(
                "bad-sequence",
                f"entry declares seq {raw.get('seq')} but sits at position {seq}",
            )
        if raw.get("prev") != prev:
            return fail(
                "broken-link",
                f"entry links to {_short(str(raw.get('prev')))} but predecessor "
                f"hashes to {_short(prev)}",
            )

        body = {key: value for key, value in raw.items() if key != "hash"}
        recomputed = hash_entry(body)
        if recomputed != claimed_hash:
            return fail(
                "bad-hash",
                f"entry hashes to {_short(recomputed)} but claims {_short(claimed_hash)}",
            )

        prev = claimed_hash

    return VerifyResult(ok=True, count=total, head=prev)


def verify_file(file: str) -> VerifyResult:
    """Verify a JSONL audit file written by AuditLog."""
    with open(file, "r", encoding="utf-8") as handle:
        lines = [line for line in handle.read().split("\n") if line.strip()]

    raw_entries: list[dict] = []
    for i, line in enumerate(lines):
        try:
            raw_entries.append(json.loads(line))
        except ValueError as err:
            return VerifyResult(
                ok=False,
                count=len(lines),
                head=GENESIS,
                failure=VerifyFailure(
                    seq=i + 1,
                    reason="malformed",
                    detail=f"line {i + 1} is not valid JSON ({err})",
                ),
            )

    # Verified as parsed, not as reconstructed: see verify_raw.
    return verify_raw(raw_entries, count=len(lines))


def _short(value: str) -> str:
    return str(value)[:12]
