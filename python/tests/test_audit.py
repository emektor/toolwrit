"""
The tamper-evident audit chain.

This is the half of Toolwrit an auditor actually reads. The tests below prove
two things: that the canonical form is stable and JavaScript-shaped (so a log
written by one process verifies in another, in either language), and that
every realistic edit to a written log is detected, with the right entry and
the right reason named.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from helpers import T0, call
from toolwrit._js import UNDEFINED, js_number, js_to_fixed
from toolwrit.audit.chain import (
    GENESIS,
    AuditEntry,
    AuditLog,
    canonicalize,
    entry_from_dict,
    hash_entry,
)
from toolwrit.audit.verify import verify_chain, verify_file
from toolwrit.types import Decision, Violation

ALLOW = Decision(effect="allow", rule="r1", reason='allowed by rule "r1"', violations=[])
DENY = Decision(
    effect="deny",
    rule=None,
    reason='no rule allows tool "fs.write"',
    violations=[Violation(rule="policy", constraint="default", message="nope")],
)


def zero_usage() -> dict[str, float]:
    return {"calls": 0, "tokens": 0, "usd": 0}


def build_chain() -> list[AuditEntry]:
    """Three-entry chain used by most of the tampering tests."""
    log = AuditLog(run="run-1")
    log.record(call("fs.read", {"path": "/tmp/a"}, T0), copy.deepcopy(ALLOW), zero_usage())
    log.record(
        call("fs.write", {"path": "/etc/x"}, T0 + 1),
        copy.deepcopy(DENY),
        {"calls": 1, "tokens": 10, "usd": 0.01},
    )
    log.record(
        call("fs.read", {"path": "/tmp/b"}, T0 + 2),
        copy.deepcopy(ALLOW),
        {"calls": 1, "tokens": 10, "usd": 0.01},
    )
    return copy.deepcopy(log.all())


class TestCanonicalize:
    def test_serialises_primitives_like_json_stringify(self) -> None:
        assert canonicalize(1) == "1"
        assert canonicalize("a") == '"a"'
        assert canonicalize(True) == "true"
        assert canonicalize(None) == "null"
        assert canonicalize(UNDEFINED) == "null"
        assert canonicalize('a"b\\c') == '"a\\"b\\\\c"'

    def test_sorts_object_keys(self) -> None:
        assert canonicalize({"b": 1, "a": 2}) == '{"a":2,"b":1}'

    def test_sorts_keys_recursively_at_every_depth(self) -> None:
        assert (
            canonicalize({"z": {"d": 1, "c": {"b": 1, "a": 2}}, "y": 3})
            == '{"y":3,"z":{"c":{"a":2,"b":1},"d":1}}'
        )

    def test_is_stable_across_differently_ordered_but_equal_objects(self) -> None:
        a = {"tool": "t", "args": {"b": 2, "a": 1}, "seq": 1}
        b = {"seq": 1, "args": {"a": 1, "b": 2}, "tool": "t"}
        assert canonicalize(a) == canonicalize(b)

    def test_hash_entry_inherits_that_stability(self) -> None:
        common = {
            "at": T0,
            "run": "r",
            "decision": ALLOW,
            "usage": zero_usage(),
            "prev": GENESIS,
        }
        a = {"seq": 1, "tool": "t", "args": {"b": 2, "a": 1}, **common}
        b = {**common, "args": {"a": 1, "b": 2}, "tool": "t", "seq": 1}
        assert hash_entry(a) == hash_entry(b)

    def test_preserves_array_order(self) -> None:
        assert canonicalize([3, 1, 2]) == "[3,1,2]"
        assert canonicalize([1, 2]) != canonicalize([2, 1])

    def test_handles_nested_arrays_of_objects(self) -> None:
        assert canonicalize([{"b": 1, "a": 2}, []]) == '[{"a":2,"b":1},[]]'

    def test_drops_undefined_object_values(self) -> None:
        assert canonicalize({"a": 1, "b": UNDEFINED}) == '{"a":1}'
        assert canonicalize({"a": 1, "b": UNDEFINED}) == canonicalize({"a": 1})

    def test_renders_undefined_array_elements_as_null(self) -> None:
        assert canonicalize([1, UNDEFINED, 2]) == "[1,null,2]"

    def test_keeps_none_which_is_json_null_not_undefined(self) -> None:
        # This is the one place the port cannot follow "drop the empty value":
        # decision.rule is legitimately null and the TypeScript chain commits
        # to it, so dropping None would break cross-language verification.
        assert canonicalize({"a": None}) == '{"a":null}'
        assert canonicalize({"a": None}) != canonicalize({})

    def test_emits_no_incidental_whitespace(self) -> None:
        assert canonicalize({"a": [1, {"b": 2}]}) == '{"a":[1,{"b":2}]}'

    def test_does_not_confuse_an_empty_object_with_an_empty_array(self) -> None:
        assert canonicalize({}) != canonicalize([])

    def test_escapes_control_characters_the_way_json_stringify_does(self) -> None:
        assert canonicalize("\n\t") == '"\\n\\t"'
        assert canonicalize("\x00\x1f") == '"\\u0000\\u001f"'
        assert canonicalize("é😀") == '"é😀"', "non-ASCII stays literal"


class TestJavaScriptNumberFormatting:
    """Numbers are where a naive port breaks the chain.

    JavaScript has one numeric type and prints it with Number::toString;
    Python's repr keeps the ``.0`` and switches to exponent notation at a
    different magnitude. These are the exact strings ``JSON.stringify``
    produces for each value.
    """

    @pytest.mark.parametrize(
        "value,expected",
        [
            (1, "1"),
            (1.0, "1"),
            (0.1, "0.1"),
            (0.01, "0.01"),
            (1.5, "1.5"),
            (100, "100"),
            (0.0001, "0.0001"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (1e16, "10000000000000000"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (-0.0, "0"),
            (1 / 3, "0.3333333333333333"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (-1.5, "-1.5"),
            (-1e21, "-1e+21"),
            (9007199254740992, "9007199254740992"),
            (12345678901234567890, "12345678901234567000"),
            (123456789012345678901234567890, "1.2345678901234568e+29"),
        ],
    )
    def test_js_number(self, value: float, expected: str) -> None:
        assert js_number(value) == expected

    def test_canonicalize_uses_it(self) -> None:
        assert canonicalize({"a": 1.0, "b": 1e21, "c": 1e-7}) == '{"a":1,"b":1e+21,"c":1e-7}'

    def test_nan_and_infinity_become_null_as_in_json_stringify(self) -> None:
        assert canonicalize(float("nan")) == "null"
        assert canonicalize(float("inf")) == "null"
        assert canonicalize({"a": float("-inf")}) == '{"a":null}'

    @pytest.mark.parametrize(
        "value,digits,expected",
        [
            (1, 4, "1.0000"),
            (0.1, 4, "0.1000"),
            (0.9999, 4, "0.9999"),
            (60.0, 1, "60.0"),
            (1.005, 2, "1.00"),
            (0.615, 2, "0.61"),
            (1.05, 1, "1.1"),
            (-1.05, 1, "-1.1"),
            (-0.5, 0, "-1"),
            (0.5, 0, "1"),
            (2.5, 0, "3"),
            (0.125, 2, "0.13"),
            (-0.125, 2, "-0.13"),
        ],
    )
    def test_js_to_fixed(self, value: float, digits: int, expected: str) -> None:
        assert js_to_fixed(value, digits) == expected


class TestHashEntry:
    def test_is_sha256_over_the_canonical_form(self) -> None:
        body = {
            "seq": 1,
            "at": T0,
            "run": "r",
            "tool": "t",
            "args": {},
            "decision": ALLOW,
            "usage": zero_usage(),
            "prev": GENESIS,
        }
        expected = hashlib.sha256(canonicalize(body).encode("utf-8")).hexdigest()
        assert hash_entry(body) == expected
        assert len(hash_entry(body)) == 64
        assert all(c in "0123456789abcdef" for c in hash_entry(body))

    def test_changes_when_any_field_changes(self) -> None:
        body: dict[str, Any] = {
            "seq": 1,
            "at": T0,
            "run": "r",
            "tool": "t",
            "args": {"a": 1},
            "decision": ALLOW,
            "usage": zero_usage(),
            "prev": GENESIS,
        }
        base = hash_entry(body)
        for change in (
            {"tool": "u"},
            {"at": T0 + 1},
            {"args": {"a": 2}},
            {"decision": Decision(effect="deny", rule="r1", reason=ALLOW.reason)},
            {"usage": {"calls": 1, "tokens": 0, "usd": 0}},
            {"prev": "f" * 64},
            {"run": "other"},
        ):
            assert hash_entry({**body, **change}) != base, change


class TestAuditLog:
    def test_links_the_chain(self) -> None:
        entries = build_chain()
        assert len(entries) == 3
        assert entries[0].prev == GENESIS
        assert entries[1].prev == entries[0].hash
        assert entries[2].prev == entries[1].hash
        assert [e.seq for e in entries] == [1, 2, 3]

    def test_records_the_call_run_timestamp_decision_and_usage_verbatim(self) -> None:
        first = build_chain()[0]
        assert first.run == "run-1"
        assert first.tool == "fs.read"
        assert first.at == T0
        assert first.args == {"path": "/tmp/a"}
        assert first.decision == ALLOW
        assert first.usage == zero_usage()

    def test_head_equals_the_last_entrys_hash_and_genesis_when_empty(self) -> None:
        log = AuditLog(run="r")
        assert log.head() == GENESIS
        e1 = log.record(call("t", {}, T0), ALLOW, zero_usage())
        assert log.head() == e1.hash
        e2 = log.record(call("t", {}, T0 + 1), ALLOW, {"calls": 1, "tokens": 0, "usd": 0})
        assert log.head() == e2.hash

    def test_is_deterministic(self) -> None:
        assert [e.hash for e in build_chain()] == [e.hash for e in build_chain()]

    def test_a_different_run_id_produces_a_different_chain(self) -> None:
        other = AuditLog(run="run-2")
        entry = other.record(call("fs.read", {"path": "/tmp/a"}, T0), ALLOW, zero_usage())
        assert entry.hash != build_chain()[0].hash

    def test_history_exposes_only_non_denied_calls(self) -> None:
        log = AuditLog(run="r")
        log.record(call("fs.read", {}, T0), ALLOW, zero_usage())
        log.record(call("fs.write", {}, T0 + 1), DENY, {"calls": 1, "tokens": 0, "usd": 0})
        log.record(
            call("fs.read", {}, T0 + 2),
            Decision(effect="ask", rule="r1", reason="x"),
            {"calls": 1, "tokens": 0, "usd": 0},
        )
        assert [(h.tool, h.rule, h.at) for h in log.history()] == [
            ("fs.read", "r1", T0),
            ("fs.read", "r1", T0 + 2),
        ]

    def test_all_reports_entries_oldest_first(self) -> None:
        assert [e.tool for e in build_chain()] == ["fs.read", "fs.write", "fs.read"]


class TestVerifyChainHonestCases:
    def test_accepts_an_empty_chain_with_head_genesis(self) -> None:
        result = verify_chain([])
        assert (result.ok, result.count, result.head, result.failure) == (
            True,
            0,
            GENESIS,
            None,
        )

    def test_accepts_a_good_chain_and_reports_its_head(self) -> None:
        entries = build_chain()
        result = verify_chain(entries)
        assert result.ok is True
        assert result.count == 3
        assert result.head == entries[2].hash
        assert result.failure is None

    def test_accepts_a_chain_that_is_one_legitimate_entry_longer(self) -> None:
        log = AuditLog(run="r")
        for i in range(10):
            log.record(call("t", {"i": i}, T0 + i), ALLOW, {"calls": i, "tokens": 0, "usd": 0})
            assert verify_chain(log.all()).ok is True, f"after {i + 1} entries"


class TestVerifyChainTampering:
    def test_rejects_a_mutated_argument(self) -> None:
        entries = build_chain()
        entries[1].args["path"] = "/tmp/harmless"
        r = verify_chain(entries)
        assert r.ok is False
        assert r.failure.seq == 2
        assert r.failure.reason == "bad-hash"
        assert "hashes to" in r.failure.detail and "but claims" in r.failure.detail

    def test_rejects_a_mutated_decision_a_deny_rewritten_as_an_allow(self) -> None:
        entries = build_chain()
        entries[1].decision.effect = "allow"
        entries[1].decision.violations = []
        r = verify_chain(entries)
        assert (r.ok, r.failure.seq, r.failure.reason) == (False, 2, "bad-hash")

    def test_rejects_a_mutated_usage_figure(self) -> None:
        entries = build_chain()
        entries[2].usage["usd"] = 0
        r = verify_chain(entries)
        assert (r.ok, r.failure.seq, r.failure.reason) == (False, 3, "bad-hash")

    def test_rejects_a_deleted_middle_entry(self) -> None:
        entries = build_chain()
        del entries[1]
        r = verify_chain(entries)
        assert r.ok is False
        assert r.failure.seq == 2, "the gap shows at the position the entry vacated"
        assert r.failure.reason == "bad-sequence"
        assert "declares seq 3 but sits at position 2" in r.failure.detail

    def test_a_deleted_final_entry_is_caught_only_by_the_head_it_reports(self) -> None:
        # Truncation cannot break a hash link, so it is detected by comparing
        # the reported head against the receipt the run handed out.
        entries = build_chain()
        full_head = verify_chain(entries).head
        entries.pop()
        r = verify_chain(entries)
        assert r.ok is True, "a truncated prefix is internally consistent"
        assert r.head != full_head, "but the head no longer matches the receipt"
        assert r.count == 2

    def test_rejects_two_reordered_entries(self) -> None:
        entries = build_chain()
        entries[1], entries[2] = entries[2], entries[1]
        r = verify_chain(entries)
        assert (r.ok, r.failure.seq, r.failure.reason) == (False, 2, "bad-sequence")

    def test_rejects_a_forged_entry_spliced_into_the_middle(self) -> None:
        entries = build_chain()
        forged = AuditEntry(
            seq=2,
            at=T0 + 1,
            run="run-1",
            tool="fs.write",
            args={"path": "/etc/x"},
            # The attacker's goal: make the denial look authorised.
            decision=copy.deepcopy(ALLOW),
            usage={"calls": 1, "tokens": 10, "usd": 0.01},
            prev=entries[0].hash,
        )
        # A well-formed forgery: correct seq, correct prev, recomputed hash.
        forged.hash = hash_entry(forged.body())
        entries[1] = forged

        r = verify_chain(entries)
        assert r.ok is False
        assert r.failure.seq == 3, "the successor is what exposes the splice"
        assert r.failure.reason == "broken-link"
        assert "links to" in r.failure.detail and "predecessor hashes to" in r.failure.detail

    def test_rejects_an_entry_whose_hash_was_rewritten(self) -> None:
        entries = build_chain()
        entries[0].hash = "f" * 64
        r = verify_chain(entries)
        assert (r.ok, r.failure.seq, r.failure.reason) == (False, 1, "bad-hash")

    def test_rejects_a_rewritten_prev_link(self) -> None:
        entries = build_chain()
        entries[1].prev = GENESIS
        r = verify_chain(entries)
        assert (r.ok, r.failure.seq, r.failure.reason) == (False, 2, "broken-link")

    def test_rejects_a_renumbered_first_entry(self) -> None:
        entries = build_chain()
        entries[0].seq = 0
        r = verify_chain(entries)
        assert (r.failure.seq, r.failure.reason) == (1, "bad-sequence")

    def test_stops_at_the_first_inconsistency(self) -> None:
        entries = build_chain()
        entries[1].args["path"] = "tampered"
        entries[2].args["path"] = "tampered"
        assert verify_chain(entries).failure.seq == 2

    def test_reports_the_last_verified_head_alongside_a_failure(self) -> None:
        entries = build_chain()
        entries[2].args["path"] = "tampered"
        r = verify_chain(entries)
        assert r.head == entries[1].hash, "everything up to seq 2 is provably intact"
        assert r.count == 3


class TestVerifyFile:
    def test_verifies_a_jsonl_log_written_by_audit_log(self, tmp_path: Path) -> None:
        file = str(tmp_path / "good.jsonl")
        log = AuditLog(run="file-run", file=file)
        log.record(call("fs.read", {"path": "/tmp/a"}, T0), ALLOW, zero_usage())
        log.record(
            call("fs.write", {"path": "/etc/x"}, T0 + 1), DENY, {"calls": 1, "tokens": 0, "usd": 0}
        )

        r = verify_file(file)
        assert r.ok is True
        assert r.count == 2
        assert r.head == log.head()

    def test_creates_the_parent_directory_for_the_log_file(self, tmp_path: Path) -> None:
        file = str(tmp_path / "nested" / "deeper" / "log.jsonl")
        AuditLog(run="r", file=file).record(call("t", {}, T0), ALLOW, zero_usage())
        assert verify_file(file).ok is True

    def test_detects_an_edit_made_directly_to_the_file_on_disk(self, tmp_path: Path) -> None:
        file = tmp_path / "edited.jsonl"
        log = AuditLog(run="r", file=str(file))
        log.record(call("fs.read", {"path": "/tmp/a"}, T0), ALLOW, zero_usage())
        log.record(
            call("fs.write", {"path": "/etc/shadow"}, T0 + 1),
            DENY,
            {"calls": 1, "tokens": 0, "usd": 0},
        )

        lines = file.read_text(encoding="utf-8").rstrip("\n").split("\n")
        second = json.loads(lines[1])
        second["args"]["path"] = "/tmp/innocent"
        file.write_text(f"{lines[0]}\n{json.dumps(second)}\n", encoding="utf-8")

        r = verify_file(str(file))
        assert (r.ok, r.failure.seq, r.failure.reason) == (False, 2, "bad-hash")

    def test_detects_a_deleted_line(self, tmp_path: Path) -> None:
        file = tmp_path / "truncated.jsonl"
        log = AuditLog(run="r", file=str(file))
        for i in range(3):
            log.record(call("t", {"i": i}, T0 + i), ALLOW, {"calls": i, "tokens": 0, "usd": 0})
        lines = file.read_text(encoding="utf-8").rstrip("\n").split("\n")
        file.write_text(f"{lines[0]}\n{lines[2]}\n", encoding="utf-8")
        r = verify_file(str(file))
        assert (r.ok, r.failure.seq, r.failure.reason) == (False, 2, "bad-sequence")

    def test_reports_malformed_json_with_the_offending_line_number(self, tmp_path: Path) -> None:
        file = tmp_path / "malformed.jsonl"
        AuditLog(run="r", file=str(file)).record(call("t", {}, T0), ALLOW, zero_usage())
        file.write_text(file.read_text(encoding="utf-8") + "{not json}\n", encoding="utf-8")
        r = verify_file(str(file))
        assert r.ok is False
        assert r.failure.reason == "malformed"
        assert r.failure.seq == 2
        assert "line 2 is not valid JSON" in r.failure.detail

    def test_ignores_blank_and_whitespace_only_lines(self, tmp_path: Path) -> None:
        file = tmp_path / "blanks.jsonl"
        AuditLog(run="r", file=str(file)).record(call("t", {}, T0), ALLOW, zero_usage())
        file.write_text(f"\n{file.read_text(encoding='utf-8')}\n   \n", encoding="utf-8")
        assert verify_file(str(file)).ok is True

    def test_verifies_an_empty_file_as_an_empty_chain(self, tmp_path: Path) -> None:
        file = tmp_path / "empty.jsonl"
        file.write_text("", encoding="utf-8")
        r = verify_file(str(file))
        assert (r.ok, r.count, r.head) == (True, 0, GENESIS)

    def test_two_runs_in_one_file_do_not_verify_as_a_whole_file_chain(
        self, tmp_path: Path
    ) -> None:
        # Documented format property: several runs may share a file. The chain is
        # per-AuditLog, so a second log restarts at GENESIS and the combined file
        # fails -- worth pinning so nobody assumes shared-file chaining works.
        file = str(tmp_path / "two-runs.jsonl")
        AuditLog(run="a", file=file).record(call("t", {}, T0), ALLOW, zero_usage())
        AuditLog(run="b", file=file).record(call("t", {}, T0 + 1), ALLOW, zero_usage())
        r = verify_file(file)
        assert (r.ok, r.failure.seq, r.failure.reason) == (False, 2, "bad-sequence")

    def test_a_round_trip_through_the_wire_form_preserves_the_hash(self, tmp_path: Path) -> None:
        # entry_from_dict must rebuild exactly what was hashed -- in particular
        # a violation with no path must not gain a null one.
        file = str(tmp_path / "roundtrip.jsonl")
        log = AuditLog(run="r", file=file)
        log.record(call("fs.write", {"path": "/etc/x"}, T0), DENY, zero_usage())
        with open(file, encoding="utf-8") as handle:
            rebuilt = entry_from_dict(json.loads(handle.readline()))
        assert hash_entry(rebuilt.body()) == log.all()[0].hash


class TestRedaction:
    def test_replaces_a_redacted_path_with_the_marker(self) -> None:
        log = AuditLog(run="r", redact=["token"])
        entry = log.record(
            call("api.call", {"token": "sk-live-secret", "url": "https://x/"}, T0),
            ALLOW,
            zero_usage(),
        )
        assert entry.args["token"] == "[redacted]"
        assert entry.args["url"] == "https://x/"

    def test_redacts_a_nested_path_and_a_list_element(self) -> None:
        log = AuditLog(run="r", redact=["auth.headers.authorization", "keys.1"])
        entry = log.record(
            call(
                "api.call",
                {
                    "auth": {"headers": {"authorization": "Bearer x", "accept": "*/*"}},
                    "keys": ["pub", "priv"],
                },
                T0,
            ),
            ALLOW,
            zero_usage(),
        )
        assert entry.args["auth"]["headers"]["authorization"] == "[redacted]"
        assert entry.args["auth"]["headers"]["accept"] == "*/*"
        assert entry.args["keys"] == ["pub", "[redacted]"]

    def test_does_not_mutate_the_callers_args(self) -> None:
        args = {"token": "sk-live-secret", "nested": {"pw": "hunter2"}}
        AuditLog(run="r", redact=["token", "nested.pw"]).record(
            call("api.call", args, T0), ALLOW, zero_usage()
        )
        assert args["token"] == "sk-live-secret", "the agent still needs the real value"
        assert args["nested"]["pw"] == "hunter2"

    def test_a_redaction_path_that_does_not_exist_is_a_harmless_no_op(self) -> None:
        log = AuditLog(run="r", redact=["nope", "a.b.c.d", "list.9", ""])
        entry = log.record(call("t", {"a": {"b": 1}, "list": []}, T0), ALLOW, zero_usage())
        assert entry.args == {"a": {"b": 1}, "list": []}
        assert verify_chain([entry]).ok is True

    def test_the_chain_still_verifies_over_redacted_entries(self) -> None:
        log = AuditLog(run="r", redact=["token"])
        log.record(call("a", {"token": "s1"}, T0), ALLOW, zero_usage())
        log.record(call("b", {"token": "s2"}, T0 + 1), ALLOW, {"calls": 1, "tokens": 0, "usd": 0})
        assert verify_chain(log.all()).ok is True

    def test_the_hash_commits_to_the_redacted_shape(self) -> None:
        # This is the point of redacting *before* hashing: the log proves what
        # the shape of the call was without ever containing the secret.
        def mk(secret: str) -> str:
            log = AuditLog(run="r", redact=["token"])
            return log.record(call("a", {"token": secret}, T0), ALLOW, zero_usage()).hash

        assert mk("s1") == mk("s2")

    def test_a_secret_cannot_be_un_redacted_by_re_hashing(self) -> None:
        log = AuditLog(run="r", redact=["token"])
        entry = copy.deepcopy(
            log.record(call("a", {"token": "secret"}, T0), ALLOW, zero_usage())
        )
        entry.args["token"] = "secret"
        assert verify_chain([entry]).ok is False

    def test_an_empty_redact_list_leaves_args_untouched(self) -> None:
        log = AuditLog(run="r", redact=[])
        entry = log.record(call("t", {"token": "visible"}, T0), ALLOW, zero_usage())
        assert entry.args["token"] == "visible"

    @pytest.mark.parametrize("redact", [[], ["other"]])
    def test_a_recorded_entry_is_insulated_from_later_mutation(self, redact: list[str]) -> None:
        # Holding the caller's object by reference would let an agent that reuses
        # its argument object silently invalidate an honest chain: the entry
        # would hash to something the log no longer contains.
        log = AuditLog(run="r", redact=redact)
        args: dict[str, Any] = {"path": "/tmp/ok", "nested": {"deep": 1}}
        log.record(call("fs.read", args, T0), ALLOW, zero_usage())

        args["path"] = "/etc/passwd"
        args["nested"]["deep"] = 999

        entry = log.all()[0]
        assert entry.args["path"] == "/tmp/ok"
        assert entry.args["nested"] == {"deep": 1}
        assert verify_chain(log.all()).ok is True

    def test_a_redaction_path_naming_an_attribute_adds_nothing_to_the_entry(self) -> None:
        log = AuditLog(run="r", redact=["keys", "items"])
        entry = log.record(call("t", {"real": 1}, T0), ALLOW, zero_usage())
        assert list(entry.args) == ["real"]
        assert verify_chain([entry]).ok is True
