"""
Policy parsing and validation.

Strictness here IS a security property. A silently-ignored key in a security
policy is a widened policy: ``startWith`` instead of ``startsWith`` turns a
scoped filesystem rule into an unscoped one. Every test that asserts a
rejection also asserts that the error names the offending key, because an
operator has to be able to find the typo.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from helpers import plain
from leash.policy.load import PolicyError, load_policy_file, parse_policy, validate_policy


def rejects(raw: str, *fragments: str) -> PolicyError:
    """Assert that parsing raises a PolicyError mentioning each fragment."""
    with pytest.raises(PolicyError) as info:
        parse_policy(raw, "p")
    message = str(info.value)
    for fragment in fragments:
        assert fragment in message, f"expected {fragment!r} in: {message}"
    return info.value


VALID_YAML = """
version: "1"
name: demo
default: deny
budget:
  calls: 10
  tokens: 100000
  usd: 1.5
  seconds: 300
rules:
  - id: fs-read
    description: read the workspace
    tools: ["fs.read", "fs.list"]
    effect: allow
    when:
      path:
        type: string
        startsWith: ["/workspace/"]
        excludes: [".."]
    limit:
      max: 20
      perSeconds: 60
  - id: net
    tools: ["net.*"]
    effect: ask
    when:
      url:
        urlHosts: [".example.com"]
  - id: no-shell
    tools: ["shell.**"]
    effect: deny
"""


class TestHappyPath:
    def test_parses_a_complete_yaml_policy(self) -> None:
        p = parse_policy(VALID_YAML, "demo.yaml")
        assert p.version == "1"
        assert p.name == "demo"
        assert p.default == "deny"
        assert plain(p.budget) == {
            "calls": 10,
            "tokens": 100000,
            "usd": 1.5,
            "seconds": 300,
        }
        assert [r.id for r in p.rules] == ["fs-read", "net", "no-shell"]
        assert p.rules[0].tools == ["fs.read", "fs.list"]
        assert plain(p.rules[0].when["path"]) == {
            "type": "string",
            "startsWith": ["/workspace/"],
            "excludes": [".."],
        }
        assert plain(p.rules[0].limit) == {"max": 20, "perSeconds": 60}
        assert p.rules[2].effect == "deny"

    def test_parses_the_equivalent_json_to_an_equal_policy(self) -> None:
        as_json = json.dumps(
            {
                "version": "1",
                "name": "demo",
                "default": "deny",
                "budget": {"calls": 10, "tokens": 100000, "usd": 1.5, "seconds": 300},
                "rules": [
                    {
                        "id": "fs-read",
                        "description": "read the workspace",
                        "tools": ["fs.read", "fs.list"],
                        "effect": "allow",
                        "when": {
                            "path": {
                                "type": "string",
                                "startsWith": ["/workspace/"],
                                "excludes": [".."],
                            }
                        },
                        "limit": {"max": 20, "perSeconds": 60},
                    },
                    {
                        "id": "net",
                        "tools": ["net.*"],
                        "effect": "ask",
                        "when": {"url": {"urlHosts": [".example.com"]}},
                    },
                    {"id": "no-shell", "tools": ["shell.**"], "effect": "deny"},
                ],
            }
        )
        assert parse_policy(as_json, "demo.json") == parse_policy(VALID_YAML, "demo.yaml")

    def test_accepts_a_minimal_policy(self) -> None:
        p = parse_policy('version: "1"\nrules: []\n')
        assert plain(p) == {"version": "1", "rules": []}
        assert p.default is None, "no default key means the engine's deny-by-default"

    def test_omits_optional_keys_rather_than_setting_them_to_null(self) -> None:
        assert sorted(plain(parse_policy('version: "1"\nrules: []\n'))) == [
            "rules",
            "version",
        ]

    @pytest.mark.parametrize("effect", ["allow", "deny", "ask"])
    def test_accepts_every_effect_for_default_and_for_a_rule(self, effect: str) -> None:
        p = parse_policy(
            f'version: "1"\ndefault: {effect}\nrules:\n  - id: r\n'
            f'    tools: ["*"]\n    effect: {effect}\n'
        )
        assert p.default == effect
        assert p.rules[0].effect == effect

    def test_accepts_a_limit_without_per_seconds_and_max_zero(self) -> None:
        p = parse_policy(
            'version: "1"\nrules:\n  - id: r\n    tools: ["*"]\n'
            "    effect: allow\n    limit: { max: 0 }\n"
        )
        assert plain(p.rules[0].limit) == {"max": 0}

    def test_validate_policy_accepts_an_already_parsed_object(self) -> None:
        assert plain(validate_policy({"version": "1", "rules": []})) == {
            "version": "1",
            "rules": [],
        }


class TestDocumentLevelRejections:
    def test_rejects_malformed_yaml_as_a_policy_error(self) -> None:
        err = rejects('version: "1"\nrules:\n  - id: [unclosed\n', "invalid YAML/JSON")
        assert err.path == "p"

    @pytest.mark.parametrize("raw", ["- a\n- b\n", "just a string\n", "", "null\n"])
    def test_rejects_yaml_that_is_not_a_mapping(self, raw: str) -> None:
        rejects(raw, "expected an object")

    def test_rejects_a_missing_version(self) -> None:
        rejects("rules: []\n", "unsupported policy version", "undefined")

    def test_rejects_a_numeric_version(self) -> None:
        rejects('version: 1\nrules: []\n', "unsupported policy version 1")

    def test_rejects_an_unknown_future_version(self) -> None:
        rejects('version: "2"\nrules: []\n', 'unsupported policy version "2"')

    def test_rejects_an_unknown_top_level_key_and_names_it(self) -> None:
        err = rejects('version: "1"\nrules: []\ndefualt: allow\n', '"defualt"')
        assert "unknown field(s)" in str(err)
        assert "allowed: " in str(err), "the message lists what was allowed"

    def test_names_every_unknown_top_level_key_at_once(self) -> None:
        rejects('version: "1"\nrules: []\nfoo: 1\nbar: 2\n', '"foo"', '"bar"')

    def test_rejects_a_bad_default_effect(self) -> None:
        rejects(
            'version: "1"\ndefault: maybe\nrules: []\n',
            '"default" must be one of allow, deny, ask',
        )

    def test_rejects_a_non_string_name(self) -> None:
        rejects('version: "1"\nname: 42\nrules: []\n', '"name" must be a string')

    def test_rejects_a_missing_or_non_array_rules_key(self) -> None:
        rejects('version: "1"\n', '"rules" must be an array')
        rejects('version: "1"\nrules: {}\n', '"rules" must be an array')

    def test_rejects_duplicate_rule_ids_and_points_at_the_second_one(self) -> None:
        err = rejects(
            'version: "1"\nrules:\n  - id: dup\n    tools: ["a"]\n    effect: allow\n'
            '  - id: dup\n    tools: ["b"]\n    effect: deny\n',
            'duplicate rule id "dup"',
        )
        assert err.path == "p.rules[1]"


class TestBudgetRejections:
    @staticmethod
    def wrap(budget: str) -> str:
        return f'version: "1"\nrules: []\nbudget:\n{budget}'

    def test_rejects_an_unknown_budget_key(self) -> None:
        err = rejects(self.wrap("  minutes: 5\n"), '"minutes"')
        assert err.path == "p.budget"

    def test_rejects_a_non_object_budget(self) -> None:
        rejects('version: "1"\nrules: []\nbudget: 5\n', "expected an object")

    @pytest.mark.parametrize("key", ["calls", "tokens", "usd", "seconds"])
    @pytest.mark.parametrize("value", ["0", "-1", ".inf", '"10"', "null", "true"])
    def test_rejects_a_non_positive_or_non_numeric_limit(self, key: str, value: str) -> None:
        rejects(self.wrap(f"  {key}: {value}\n"), f'"{key}" must be a positive number')

    def test_accepts_a_fractional_budget(self) -> None:
        assert plain(parse_policy(self.wrap("  usd: 0.01\n")).budget) == {"usd": 0.01}


class TestRuleRejections:
    @staticmethod
    def wrap(body: str) -> str:
        indented = "\n    ".join(body.strip().split("\n"))
        return f'version: "1"\nrules:\n  - {indented}\n'

    def test_rejects_a_non_object_rule(self) -> None:
        rejects('version: "1"\nrules: ["nope"]\n', "expected an object")

    def test_rejects_an_unknown_rule_key_and_names_it(self) -> None:
        err = rejects(self.wrap('id: r\ntools: ["a"]\neffect: allow\nwhne: {}'), '"whne"')
        assert err.path == "p.rules[0]"

    @pytest.mark.parametrize(
        "body",
        ['tools: ["a"]\neffect: allow', 'id: ""\ntools: ["a"]\neffect: allow',
         'id: 7\ntools: ["a"]\neffect: allow'],
    )
    def test_rejects_a_missing_empty_or_non_string_id(self, body: str) -> None:
        rejects(self.wrap(body), '"id" must be a non-empty string')

    def test_rejects_a_non_string_description(self) -> None:
        rejects(
            self.wrap('id: r\ndescription: 7\ntools: ["a"]\neffect: allow'),
            '"description" must be a string',
        )

    @pytest.mark.parametrize(
        "body",
        ["id: r\neffect: allow", "id: r\ntools: []\neffect: allow",
         'id: r\ntools: "fs.read"\neffect: allow'],
    )
    def test_rejects_missing_empty_or_non_array_tools(self, body: str) -> None:
        rejects(self.wrap(body), '"tools" must be a non-empty array')

    @pytest.mark.parametrize("tools", ['["a", 7]', '["a", ""]'])
    def test_rejects_a_non_string_or_empty_entry_inside_tools(self, tools: str) -> None:
        rejects(
            self.wrap(f"id: r\ntools: {tools}\neffect: allow"),
            'every entry in "tools" must be a non-empty string',
        )

    @pytest.mark.parametrize(
        "body", ['id: r\ntools: ["a"]', 'id: r\ntools: ["a"]\neffect: permit',
                 'id: r\ntools: ["a"]\neffect: Allow'],
    )
    def test_rejects_a_missing_or_bad_effect(self, body: str) -> None:
        rejects(self.wrap(body), '"effect" must be one of allow, deny, ask')

    def test_rejects_an_unknown_limit_key(self) -> None:
        err = rejects(
            self.wrap('id: r\ntools: ["a"]\neffect: allow\nlimit: { max: 1, per_seconds: 60 }'),
            '"per_seconds"',
        )
        assert err.path == "p.rules[0].limit"

    @pytest.mark.parametrize("limit", ["{ max: -1 }", "{ max: 1.5 }", "{}"])
    def test_rejects_a_bad_limit_max(self, limit: str) -> None:
        rejects(
            self.wrap(f'id: r\ntools: ["a"]\neffect: allow\nlimit: {limit}'),
            '"max" must be a non-negative integer',
        )

    @pytest.mark.parametrize("limit", ["{ max: 1, perSeconds: 0 }", '{ max: 1, perSeconds: "60" }'])
    def test_rejects_a_non_positive_per_seconds(self, limit: str) -> None:
        rejects(
            self.wrap(f'id: r\ntools: ["a"]\neffect: allow\nlimit: {limit}'),
            '"perSeconds" must be a positive number',
        )

    def test_rejects_a_non_object_when_block(self) -> None:
        rejects(
            self.wrap('id: r\ntools: ["a"]\neffect: allow\nwhen: "path"'),
            "expected an object",
        )


class TestConstraintRejections:
    @staticmethod
    def wrap(constraint: str) -> str:
        return (
            'version: "1"\nrules:\n  - id: r\n    tools: ["a"]\n    effect: allow\n'
            f"    when:\n      path: {constraint}\n"
        )

    def test_rejects_an_unknown_constraint_key_naming_it_and_its_path(self) -> None:
        # The motivating example from the module header: a typo'd startsWith
        # would otherwise be dropped and the rule would allow every path.
        err = rejects(self.wrap('{ startWith: ["/tmp/"] }'), '"startWith"')
        assert err.path == 'p.rules[0].when["path"]'
        assert "startsWith" in str(err), "the message lists what was allowed"

    def test_rejects_a_non_object_constraint(self) -> None:
        rejects(self.wrap('"/tmp/"'), "expected an object")

    def test_rejects_an_invalid_regex_in_matches(self) -> None:
        err = rejects(self.wrap('{ matches: "([a-" }'), '"matches" is not a valid regexp')
        assert err.path == 'p.rules[0].when["path"]'

    def test_rejects_a_non_string_matches(self) -> None:
        rejects(self.wrap("{ matches: 7 }"), '"matches" must be a string')

    def test_accepts_a_valid_regex_including_one_with_escapes(self) -> None:
        p = parse_policy(self.wrap('{ matches: "^/tmp/[a-z0-9_.-]+$" }'))
        assert p.rules[0].when["path"].matches == "^/tmp/[a-z0-9_.-]+$"

    @pytest.mark.parametrize("key", ["startsWith", "excludes", "urlHosts"])
    def test_rejects_a_non_array_or_non_string_element(self, key: str) -> None:
        rejects(self.wrap(f'{{ {key}: "/tmp/" }}'), f'"{key}" must be an array of strings')
        rejects(self.wrap(f'{{ {key}: ["/tmp/", 7] }}'), f'"{key}" must be an array of strings')

    @pytest.mark.parametrize("key", ["oneOf", "noneOf"])
    def test_rejects_a_non_array(self, key: str) -> None:
        rejects(self.wrap(f'{{ {key}: "read" }}'), f'"{key}" must be an array')

    @pytest.mark.parametrize("key", ["min", "max", "maxLength", "minLength"])
    def test_rejects_a_non_numeric_bound(self, key: str) -> None:
        rejects(self.wrap(f'{{ {key}: "10" }}'), f'"{key}" must be a number')

    def test_rejects_a_non_boolean_optional(self) -> None:
        rejects(self.wrap('{ optional: "yes" }'), '"optional" must be a boolean')

    def test_rejects_an_unknown_type(self) -> None:
        rejects(
            self.wrap("{ type: integer }"),
            '"type" must be one of string, number, boolean, object, array',
        )

    @pytest.mark.parametrize("type_", ["string", "number", "boolean", "object", "array"])
    def test_accepts_every_valid_type(self, type_: str) -> None:
        p = parse_policy(self.wrap(f"{{ type: {type_} }}"))
        assert p.rules[0].when["path"].type == type_

    def test_reports_the_constraint_path_for_a_deeply_nested_argument(self) -> None:
        err = rejects(
            'version: "1"\nrules:\n  - id: r\n    tools: ["a"]\n    effect: allow\n'
            '    when:\n      "body.to.0": { nope: 1 }\n',
            '"nope"',
        )
        assert err.path == 'p.rules[0].when["body.to.0"]'


class TestLoadPolicyFile:
    def test_loads_a_policy_from_disk(self, tmp_path: Path) -> None:
        file = tmp_path / "policy.yaml"
        file.write_text(VALID_YAML, encoding="utf-8")
        assert load_policy_file(str(file)) == parse_policy(VALID_YAML)

    def test_loads_a_json_policy_from_disk(self, tmp_path: Path) -> None:
        file = tmp_path / "policy.json"
        file.write_text('{"version":"1","rules":[]}', encoding="utf-8")
        assert plain(load_policy_file(str(file))) == {"version": "1", "rules": []}

    def test_reports_a_missing_file_as_a_policy_error_carrying_the_path(
        self, tmp_path: Path
    ) -> None:
        file = str(tmp_path / "does-not-exist.yaml")
        with pytest.raises(PolicyError) as info:
            load_policy_file(file)
        assert info.value.path == file
        assert "cannot read policy file" in str(info.value)

    def test_decorates_a_validation_error_with_the_file_path(self, tmp_path: Path) -> None:
        file = tmp_path / "bad.yaml"
        file.write_text('version: "1"\nrules: []\nnope: 1\n', encoding="utf-8")
        with pytest.raises(PolicyError) as info:
            load_policy_file(str(file))
        assert info.value.path == str(file)
        assert str(info.value).startswith(str(file))


class TestPlanValidation:
    @staticmethod
    def bad(raw: str) -> None:
        with pytest.raises(PolicyError):
            parse_policy(raw)

    def test_rejects_a_plan_with_no_budget_to_measure_against(self) -> None:
        # A plan that reports nothing reads as "all clear" rather than
        # "not configured", which is the dangerous direction.
        self.bad('version: "1"\nplan:\n  purpose: p\nrules: []\n')

    def test_rejects_a_missing_or_empty_purpose(self) -> None:
        self.bad('version: "1"\nbudget:\n  calls: 1\nplan:\n  approvedBy: x\nrules: []\n')
        self.bad('version: "1"\nbudget:\n  calls: 1\nplan:\n  purpose: "   "\nrules: []\n')

    @pytest.mark.parametrize("threshold", ["0", "-0.5", "1.5", '"0.8"'])
    def test_rejects_thresholds_outside_zero_to_one(self, threshold: str) -> None:
        self.bad(
            f'version: "1"\nbudget:\n  calls: 1\nplan:\n  purpose: p\n'
            f"  warnAt: [{threshold}]\nrules: []\n"
        )

    def test_rejects_an_empty_threshold_list(self) -> None:
        self.bad(
            'version: "1"\nbudget:\n  calls: 1\nplan:\n  purpose: p\n  warnAt: []\nrules: []\n'
        )

    def test_rejects_an_unknown_plan_field_so_a_typo_cannot_disable_reporting(self) -> None:
        self.bad(
            'version: "1"\nbudget:\n  calls: 1\nplan:\n  purpose: p\n'
            "  warn_at: [0.8]\nrules: []\n"
        )

    def test_accepts_one_as_a_threshold(self) -> None:
        p = parse_policy(
            'version: "1"\nbudget:\n  calls: 1\nplan:\n  purpose: p\n  warnAt: [1]\nrules: []\n'
        )
        assert p.plan.warnAt == [1]

    def test_sorts_thresholds_ascending_however_they_were_written(self) -> None:
        p = parse_policy(
            'version: "1"\nbudget:\n  calls: 1\nplan:\n  purpose: p\n'
            "  warnAt: [0.9, 0.2, 0.5]\nrules: []\n"
        )
        assert p.plan.warnAt == [0.2, 0.5, 0.9]
