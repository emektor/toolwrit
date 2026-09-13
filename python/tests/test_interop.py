"""
Cross-language hash-chain compatibility.

The claim this file exists to prove: a chain written by the Python port
verifies under the TypeScript ``toolwrit verify``, and a chain written by the
TypeScript implementation verifies here. That only holds if the canonical
string is byte-identical in both languages, so the tests go further than
"both say ok" -- they compare the hashes themselves, which fail on a single
differing byte anywhere in the serialisation.

The tests skip (rather than fail) when node or the built TypeScript CLI is
not present, so the suite still runs in a Python-only environment.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from helpers import T0
from toolwrit.audit.chain import AuditLog, canonicalize
from toolwrit.audit.verify import verify_file
from toolwrit.types import Decision, ToolCall, Violation

#: The read-only TypeScript reference implementation, beside this package.
TS_ROOT = Path(os.environ.get("TOOLWRIT_TS_ROOT", Path(__file__).resolve().parents[2] / "leash"))
TS_CLI = TS_ROOT / "dist" / "cli.js"
TS_INDEX = TS_ROOT / "dist" / "index.js"
INTEROP = Path(__file__).parent / "interop"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or not TS_CLI.exists() or not TS_INDEX.exists(),
    reason=f"needs node and the built TypeScript implementation at {TS_ROOT}",
)


def node(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["node", *args], capture_output=True, text=True, cwd=str(TS_ROOT), check=False
    )


# A deliberately awkward set of entries: floats that Python and JavaScript
# print differently, integral floats, a null rule, unicode, an empty container,
# a nested structure and a violation with no `path` key.
SPEC: list[dict[str, Any]] = [
    {
        "tool": "fs.read",
        "args": {"path": "/tmp/a", "retries": 1.0, "ratio": 1 / 3},
        "at": T0,
        "decision": {
            "effect": "allow",
            "rule": "r1",
            "reason": 'allowed by rule "r1"',
            "violations": [],
        },
        "usage": {"calls": 0, "tokens": 0, "usd": 0},
    },
    {
        "tool": "fs.write",
        "args": {
            "path": "/etc/x",
            "big": 1e21,
            "small": 1e-7,
            "exact": 1e16,
            "note": 'quote " backslash \\ newline \n tab \t',
            "unicode": "héllo 😀 日本",
            "nested": {"z": [1, {"b": True, "a": None}], "a": {}},
            "empty": [],
        },
        "at": T0 + 1,
        # rule is null here, which is the case that forbids dropping None.
        "decision": {
            "effect": "deny",
            "rule": None,
            "reason": 'no rule allows tool "fs.write"',
            "violations": [
                {"rule": "policy", "constraint": "default", "message": "nope"},
                {
                    "rule": "r2",
                    "path": "body.to.0",
                    "constraint": "startsWith",
                    "message": "scoped",
                },
            ],
        },
        "usage": {"calls": 1, "tokens": 10, "usd": 0.01},
    },
    {
        "tool": "api.call",
        "args": {"token": "sk-live-secret", "amount": 1234.5},
        "at": T0 + 2,
        "decision": {
            "effect": "allow",
            "rule": "r3",
            "reason": "ok",
            "violations": [],
        },
        "usage": {"calls": 2, "tokens": 10, "usd": 0.5},
    },
]

REDACT = ["token"]


def build_in_python(path: Path) -> AuditLog:
    log = AuditLog(run="interop-run", file=str(path), redact=REDACT)
    for i, entry in enumerate(SPEC):
        decision = Decision(
            effect=entry["decision"]["effect"],
            rule=entry["decision"]["rule"],
            reason=entry["decision"]["reason"],
            violations=[
                Violation(
                    rule=v["rule"],
                    constraint=v["constraint"],
                    message=v["message"],
                    path=v.get("path"),
                )
                for v in entry["decision"]["violations"]
            ],
        )
        log.record(
            ToolCall(id=f"c{i}", tool=entry["tool"], args=entry["args"], at=entry["at"]),
            decision,
            entry["usage"],
        )
    return log


def build_in_typescript(path: Path, tmp_path: Path) -> dict[str, Any]:
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(
        json.dumps({"run": "interop-run", "redact": REDACT, "file": str(path), "entries": SPEC}),
        encoding="utf-8",
    )
    result = node(str(INTEROP / "build_chain.mjs"), str(spec_file), str(TS_INDEX))
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


class TestCanonicalFormMatches:
    """The canonical string, value by value, against the reference."""

    VALUES: list[Any] = [
        1, 1.0, 0, -0.0, 0.1, 0.01, 1.5, -1.5, 100, 1e16, 1e20, 1e21, -1e21,
        1e-6, 1e-7, 1 / 3, 5e-324, 1.7976931348623157e308, 9007199254740992,
        12345678901234567890, 0.30000000000000004, 1234.5,
        "", "a", 'a"b\\c', "\n\t\x00\x1f", "héllo 😀 日本", "  spaced  ",
        None, True, False,
        [], {}, [1, 2, 3], [[1], {"a": 1}],
        {"b": 1, "a": 2}, {"z": {"d": 1, "c": {"b": 1, "a": 2}}, "y": 3},
        {"a": None, "b": [None, 1.0]},
        {"Z": 1, "a": 2, "A": 3, "_": 4, "0": 5},
        {"key with spaces": 1, "quote\"key": 2, "é": 3},
        {"seq": 1, "at": T0, "usage": {"calls": 0, "tokens": 0, "usd": 0.0}},
    ]

    def test_every_value_canonicalises_identically(self, tmp_path: Path) -> None:
        values_file = tmp_path / "values.json"
        values_file.write_text(json.dumps(self.VALUES), encoding="utf-8")
        result = node(str(INTEROP / "canonicalize.mjs"), str(values_file), str(TS_INDEX))
        assert result.returncode == 0, result.stderr
        reference = json.loads(result.stdout)

        mismatches = [
            (value, mine, theirs)
            for value, theirs in zip(self.VALUES, reference)
            if (mine := canonicalize(value)) != theirs
        ]
        assert mismatches == [], f"{len(mismatches)} canonical form(s) differ"


class TestPythonChainVerifiesInTypeScript:
    def test_the_typescript_cli_verifies_a_python_written_chain(self, tmp_path: Path) -> None:
        path = tmp_path / "python.jsonl"
        log = build_in_python(path)

        result = node(str(TS_CLI), "verify", str(path))
        assert result.returncode == 0, f"{result.stdout}{result.stderr}"
        assert result.stdout == f"ok: {len(SPEC)} entries verified\nhead: {log.head()}\n"

    def test_tampering_with_a_python_chain_is_caught_by_the_typescript_cli(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "tampered.jsonl"
        build_in_python(path)
        lines = path.read_text(encoding="utf-8").rstrip("\n").split("\n")
        second = json.loads(lines[1])
        second["decision"]["effect"] = "allow"
        path.write_text(f"{lines[0]}\n{json.dumps(second)}\n{lines[2]}\n", encoding="utf-8")

        result = node(str(TS_CLI), "verify", str(path))
        assert result.returncode == 1
        assert "FAILED" in result.stderr
        assert "seq:    2" in result.stderr
        assert "reason: bad-hash" in result.stderr


class TestTypeScriptChainVerifiesInPython:
    def test_python_verifies_a_typescript_written_chain(self, tmp_path: Path) -> None:
        path = tmp_path / "typescript.jsonl"
        reference = build_in_typescript(path, tmp_path)

        result = verify_file(str(path))
        assert result.ok is True, result.failure
        assert result.count == len(SPEC)
        assert result.head == reference["head"]

    def test_python_catches_tampering_in_a_typescript_written_chain(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "ts-tampered.jsonl"
        build_in_typescript(path, tmp_path)
        lines = path.read_text(encoding="utf-8").rstrip("\n").split("\n")
        third = json.loads(lines[2])
        third["usage"]["usd"] = 0
        path.write_text(f"{lines[0]}\n{lines[1]}\n{json.dumps(third)}\n", encoding="utf-8")

        result = verify_file(str(path))
        assert result.ok is False
        assert (result.failure.seq, result.failure.reason) == (3, "bad-hash")


class TestTheHashesThemselvesMatch:
    """The strongest form of the claim: identical inputs, identical hashes.

    "Both verify" would still pass if each implementation were self-consistent
    but mutually incompatible. Equal hashes cannot be.
    """

    def test_every_entry_hash_is_identical_across_implementations(
        self, tmp_path: Path
    ) -> None:
        mine = build_in_python(tmp_path / "py.jsonl")
        theirs = build_in_typescript(tmp_path / "ts.jsonl", tmp_path)

        assert [e.hash for e in mine.all()] == theirs["hashes"]
        assert mine.head() == theirs["head"]

    def test_the_redacted_shape_is_identical_too(self, tmp_path: Path) -> None:
        build_in_python(tmp_path / "py.jsonl")
        build_in_typescript(tmp_path / "ts.jsonl", tmp_path)
        py_last = json.loads((tmp_path / "py.jsonl").read_text(encoding="utf-8").splitlines()[2])
        ts_last = json.loads((tmp_path / "ts.jsonl").read_text(encoding="utf-8").splitlines()[2])
        assert py_last["args"] == ts_last["args"] == {"token": "[redacted]", "amount": 1234.5}
