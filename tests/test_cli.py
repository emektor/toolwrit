"""
The ``leash`` binary.

A policy tool that cannot be run from a shell script does not get adopted, so
the three code-free subcommands are pinned here: their output, and -- more
importantly for CI -- their exit codes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from helpers import T0, call
from leash.audit.chain import AuditLog
from leash.cli import main, parse_args
from leash.types import Decision

POLICY = """
version: "1"
name: demo
default: deny
budget:
  calls: 10
rules:
  - id: fs-read
    description: read the workspace
    tools: ["fs.read"]
    effect: allow
    when:
      path:
        type: string
        startsWith: ["/tmp/"]
    limit:
      max: 20
      perSeconds: 60
  - id: confirm
    tools: ["fs.write"]
    effect: ask
"""


@pytest.fixture()
def policy_file(tmp_path: Path) -> str:
    file = tmp_path / "policy.yaml"
    file.write_text(POLICY, encoding="utf-8")
    return str(file)


class TestParseArgs:
    def test_parses_flags_with_a_space_or_an_equals(self) -> None:
        parsed = parse_args(["check", "--policy", "p.yaml", "--tool=fs.read"])
        assert parsed.positional == ["check"]
        assert parsed.flags == {"policy": "p.yaml", "tool": "fs.read"}

    def test_a_valueless_flag_becomes_true(self) -> None:
        assert parse_args(["--help"]).flags == {"help": "true"}

    def test_a_bare_double_dash_is_a_hard_stop(self) -> None:
        # A downstream server's own --policy flag must never be stolen.
        parsed = parse_args(["run", "--policy", "p.yaml", "--", "npx", "srv", "--policy", "x"])
        assert parsed.flags == {"policy": "p.yaml"}
        assert parsed.rest == ["npx", "srv", "--policy", "x"]


class TestCheck:
    def test_exits_zero_and_prints_allow(
        self, policy_file: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = main(["check", "--policy", policy_file, "--tool", "fs.read",
                     "--args", '{"path":"/tmp/x"}'])
        out = capsys.readouterr().out
        assert code == 0
        assert out.startswith("ALLOW fs.read\n")
        assert "rule:   fs-read" in out

    def test_exits_one_and_lists_violations_on_deny(
        self, policy_file: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = main(["check", "--policy", policy_file, "--tool", "fs.read",
                     "--args", '{"path":"/etc/passwd"}'])
        out = capsys.readouterr().out
        assert code == 1
        assert out.startswith("DENY fs.read\n")
        assert "rule:   (policy default)" in out
        assert "- [fs-read path] startsWith:" in out

    def test_exits_two_on_ask(self, policy_file: str, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["check", "--policy", policy_file, "--tool", "fs.write"]) == 2
        assert capsys.readouterr().out.startswith("ASK fs.write\n")

    def test_rejects_args_that_are_not_a_json_object(
        self, policy_file: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["check", "--policy", policy_file, "--tool", "t", "--args", "[1]"]) == 1
        assert "must be a JSON object" in capsys.readouterr().err

    def test_reports_a_missing_flag_without_a_traceback(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["check", "--tool", "t"]) == 1
        assert capsys.readouterr().err == "leash: missing required --policy <value>\n"

    def test_reports_a_bad_policy_as_one_line(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text('version: "1"\nrules: []\nnope: 1\n', encoding="utf-8")
        assert main(["check", "--policy", str(bad), "--tool", "t"]) == 1
        err = capsys.readouterr().err
        assert err.startswith("leash: ") and err.count("\n") == 1
        assert '"nope"' in err


class TestVerify:
    def test_exits_zero_on_an_intact_chain(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        file = tmp_path / "audit.jsonl"
        log = AuditLog(run="r", file=str(file))
        log.record(
            call("t", {}, T0),
            Decision(effect="allow", rule="r1", reason="ok"),
            {"calls": 0, "tokens": 0, "usd": 0},
        )
        assert main(["verify", str(file)]) == 0
        assert capsys.readouterr().out == f"ok: 1 entry verified\nhead: {log.head()}\n"

    def test_exits_one_and_names_the_failure(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        file = tmp_path / "audit.jsonl"
        log = AuditLog(run="r", file=str(file))
        for i in range(2):
            log.record(
                call("t", {"i": i}, T0 + i),
                Decision(effect="allow", rule="r1", reason="ok"),
                {"calls": i, "tokens": 0, "usd": 0},
            )
        file.write_text(
            file.read_text(encoding="utf-8").replace('"i":1', '"i":9'), encoding="utf-8"
        )
        assert main(["verify", str(file)]) == 1
        err = capsys.readouterr().err
        assert "FAILED: audit chain is not intact" in err
        assert "seq:    2" in err
        assert "reason: bad-hash" in err

    def test_needs_a_file(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["verify"]) == 1
        assert "verify needs an audit file" in capsys.readouterr().err


class TestExplain:
    def test_renders_the_policy_for_a_human_reviewer(
        self, policy_file: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["explain", "--policy", policy_file]) == 0
        out = capsys.readouterr().out
        assert out.startswith("demo (version 1)\n")
        assert "default effect: deny" in out
        assert "budget: calls=10" in out
        assert "rules (2); among rules that match, deny beats ask beats allow:" in out
        assert "  fs-read  [allow]" in out
        assert "    read the workspace" in out
        assert "    tools: fs.read" in out
        assert "    limit: 20 call(s) per 60s" in out
        assert "    when path: is string; starts with /tmp/" in out

    def test_says_unlimited_when_there_is_no_budget(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        file = tmp_path / "p.yaml"
        file.write_text('version: "1"\nrules: []\n', encoding="utf-8")
        assert main(["explain", "--policy", str(file)]) == 0
        assert "budget: unlimited" in capsys.readouterr().out


class TestTopLevel:
    def test_prints_usage_with_no_arguments(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main([]) == 0
        assert capsys.readouterr().out.startswith("leash — a deterministic leash")

    def test_prints_the_version(self, capsys: pytest.CaptureFixture[str]) -> None:
        from leash import __version__

        assert main(["--version"]) == 0
        assert capsys.readouterr().out == f"{__version__}\n"

    def test_rejects_an_unknown_subcommand(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["frobnicate"]) == 1
        assert 'unknown subcommand "frobnicate"' in capsys.readouterr().err

    def test_says_plainly_that_run_is_not_ported(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["run", "--policy", "p.yaml", "--", "srv"]) == 1
        assert "not part of the Python port" in capsys.readouterr().err
