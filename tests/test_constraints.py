"""
Argument constraint evaluation.

``check_args`` is where an allowlist actually bites. Each block below pins one
constraint's exact behaviour, including the boundary values, so a refactor
cannot quietly loosen a filesystem scope or a URL allowlist.

The adversarial block at the end is the important one: a wrongly-typed value
must produce a violation, never be skipped. Skipping fails OPEN -- the
constraint evaporates, the rule matches, and the call is allowed.
"""

from __future__ import annotations

from typing import Any

import pytest

from helpers import names
from leash.policy.constraints import check_args
from leash.types import ArgConstraint, Violation


def check(c: dict[str, Any], args: dict[str, Any], path: str = "x") -> list[Violation]:
    """Run one constraint against one value and return the violations."""
    return check_args("r1", {path: ArgConstraint(**c)}, args)


class TestPresence:
    def test_missing_required_argument_produces_one_required_violation(self) -> None:
        v = check({"type": "string", "startsWith": ["/tmp"]}, {})
        assert names(v) == ["required"]
        assert v[0].rule == "r1"
        assert v[0].path == "x"
        assert '"x" is required' in v[0].message

    def test_a_missing_optional_argument_produces_no_violations(self) -> None:
        assert check({"optional": True, "type": "string"}, {}) == []

    def test_optional_does_not_excuse_a_present_but_invalid_value(self) -> None:
        assert names(check({"optional": True, "type": "string"}, {"x": 5})) == ["type"]

    def test_a_missing_nested_path_is_reported_against_the_full_dotted_path(self) -> None:
        v = check_args("r1", {"body.to.0": ArgConstraint(type="string")}, {"body": {}})
        assert names(v) == ["required"]
        assert v[0].path == "body.to.0"

    def test_checks_every_path_in_when_and_reports_all_of_them(self) -> None:
        v = check_args(
            "r1",
            {"a": ArgConstraint(type="string"), "b": ArgConstraint(type="number")},
            {"a": 1, "b": "two"},
        )
        assert names(v) == ["type", "type"]
        assert [x.path for x in v] == ["a", "b"]

    def test_an_empty_when_matches_anything(self) -> None:
        assert check_args("r1", {}, {"anything": True}) == []


class TestType:
    @pytest.mark.parametrize(
        "type_,value,ok",
        [
            ("string", "a", True),
            ("string", "", True),
            ("string", 1, False),
            ("number", 1, True),
            ("number", 0, True),
            ("number", 1.5, True),
            ("number", float("nan"), True),
            ("number", "1", False),
            ("number", True, False),
            ("boolean", False, True),
            ("boolean", "false", False),
            ("boolean", 0, False),
            ("object", {}, True),
            ("object", {"a": 1}, True),
            ("object", [], False),
            ("array", [], True),
            ("array", [1], True),
            ("array", {}, False),
            ("array", "ab", False),
        ],
    )
    def test_type_gate(self, type_: str, value: Any, ok: bool) -> None:
        assert names(check({"type": type_}, {"x": value})) == ([] if ok else ["type"])

    def test_a_type_mismatch_short_circuits_to_exactly_one_violation(self) -> None:
        # Without the short-circuit this value would also trip min, minLength and
        # oneOf; a policy author should see the one root cause, not four symptoms.
        v = check(
            {
                "type": "string",
                "oneOf": ["a"],
                "min": 100,
                "minLength": 10,
                "startsWith": ["/tmp"],
            },
            {"x": 5},
        )
        assert len(v) == 1
        assert v[0].constraint == "type"
        assert "must be a string, got number" in v[0].message

    def test_describes_mismatches_by_shape(self) -> None:
        assert check({"type": "object"}, {"x": [1]})[0].message.endswith("got array")
        assert check({"type": "string"}, {"x": True})[0].message.endswith("got boolean")


class TestOneOfNoneOf:
    def test_one_of_accepts_a_listed_primitive_and_rejects_an_unlisted_one(self) -> None:
        assert check({"oneOf": ["read", "list"]}, {"x": "read"}) == []
        assert names(check({"oneOf": ["read", "list"]}, {"x": "write"})) == ["oneOf"]

    def test_one_of_uses_strict_equality_across_types(self) -> None:
        assert names(check({"oneOf": [1]}, {"x": "1"})) == ["oneOf"]
        assert names(check({"oneOf": [0]}, {"x": False})) == ["oneOf"], "0 is not False"
        assert names(check({"oneOf": [1]}, {"x": True})) == ["oneOf"], "1 is not True"
        assert check({"oneOf": [True]}, {"x": True}) == []

    def test_one_of_compares_objects_deeply_and_key_order_insensitively(self) -> None:
        c = {"oneOf": [{"a": 1, "b": {"c": [1, 2]}}]}
        assert check(c, {"x": {"b": {"c": [1, 2]}, "a": 1}}) == [], "key order must not matter"
        assert names(check(c, {"x": {"a": 1, "b": {"c": [2, 1]}}})) == ["oneOf"]
        assert names(check(c, {"x": {"a": 1}})) == ["oneOf"], "a missing key must not match"
        assert names(check(c, {"x": {"a": 1, "b": {"c": [1, 2]}, "extra": True}})) == [
            "oneOf"
        ], "an extra key must not match"

    def test_one_of_compares_lists_deeply_including_length_and_nesting(self) -> None:
        c = {"oneOf": [[1, [2, 3]]]}
        assert check(c, {"x": [1, [2, 3]]}) == []
        assert names(check(c, {"x": [1, [2, 3], 4]})) == ["oneOf"]
        assert names(check(c, {"x": [1, [3, 2]]})) == ["oneOf"]

    def test_a_list_does_not_deep_equal_an_object_with_the_same_indices(self) -> None:
        assert names(check({"oneOf": [{"0": "a"}]}, {"x": ["a"]})) == ["oneOf"]
        assert names(check({"oneOf": [["a"]]}, {"x": {"0": "a"}})) == ["oneOf"]

    def test_an_empty_one_of_rejects_everything(self) -> None:
        assert names(check({"oneOf": []}, {"x": "anything"})) == ["oneOf"]

    def test_none_of_rejects_a_listed_value_and_accepts_anything_else(self) -> None:
        assert names(check({"noneOf": ["rm -rf /"]}, {"x": "rm -rf /"})) == ["noneOf"]
        assert check({"noneOf": ["rm -rf /"]}, {"x": "ls"}) == []

    def test_none_of_compares_objects_and_lists_deeply(self) -> None:
        c = {"noneOf": [{"scope": ["admin"]}]}
        assert names(check(c, {"x": {"scope": ["admin"]}})) == ["noneOf"]
        assert check(c, {"x": {"scope": ["reader"]}}) == []

    def test_an_empty_none_of_rejects_nothing(self) -> None:
        assert check({"noneOf": []}, {"x": "anything"}) == []

    def test_one_of_and_none_of_can_both_fire_on_the_same_value(self) -> None:
        assert names(check({"oneOf": ["a"], "noneOf": ["b"]}, {"x": "b"})) == [
            "oneOf",
            "noneOf",
        ]


class TestMatches:
    def test_accepts_a_matching_string_and_rejects_a_non_matching_one(self) -> None:
        assert check({"matches": "^[a-z]+$"}, {"x": "abc"}) == []
        assert names(check({"matches": "^[a-z]+$"}, {"x": "abc1"})) == ["matches"]

    def test_is_unanchored_unless_the_author_anchors_it(self) -> None:
        assert check({"matches": "abc"}, {"x": "xxabcxx"}) == []
        assert names(check({"matches": "^abc$"}, {"x": "xxabcxx"})) == ["matches"]

    def test_an_empty_pattern_matches_every_string(self) -> None:
        assert check({"matches": ""}, {"x": "anything"}) == []

    def test_reports_the_pattern_in_the_message(self) -> None:
        assert "must match /^ok$/" in check({"matches": "^ok$"}, {"x": "no"})[0].message

    def test_is_not_stateful_across_calls(self) -> None:
        for i in range(4):
            assert check({"matches": "a"}, {"x": "a"}) == [], f"iteration {i}"


class TestStartsWith:
    def test_accepts_any_listed_prefix(self) -> None:
        c = {"startsWith": ["/tmp/", "/var/tmp/"]}
        assert check(c, {"x": "/tmp/a"}) == []
        assert check(c, {"x": "/var/tmp/a"}) == []

    def test_rejects_a_path_outside_every_prefix(self) -> None:
        c = {"startsWith": ["/tmp/"]}
        assert names(check(c, {"x": "/etc/passwd"})) == ["startsWith"]
        assert names(check(c, {"x": "x/tmp/a"})) == ["startsWith"], "prefix at position 0"

    def test_is_a_raw_prefix_test_and_does_not_normalise_paths(self) -> None:
        # This is why `excludes: ['..']` exists; documented as a "cheap guard".
        assert check({"startsWith": ["/tmp/"]}, {"x": "/tmp/../etc/passwd"}) == []

    def test_an_empty_starts_with_list_rejects_everything(self) -> None:
        assert names(check({"startsWith": []}, {"x": "/tmp/a"})) == ["startsWith"]

    def test_an_empty_string_prefix_accepts_everything(self) -> None:
        assert check({"startsWith": [""]}, {"x": "/etc/passwd"}) == []


class TestExcludes:
    def test_rejects_a_string_containing_any_banned_substring(self) -> None:
        c = {"excludes": ["..", "~"]}
        assert names(check(c, {"x": "/tmp/../etc"})) == ["excludes"]
        assert names(check(c, {"x": "~/.ssh"})) == ["excludes"]
        assert check(c, {"x": "/tmp/ok"}) == []

    def test_matches_anywhere_in_the_string(self) -> None:
        assert names(check({"excludes": ["secret"]}, {"x": "my secret plan"})) == [
            "excludes"
        ]

    def test_reports_the_first_banned_substring_in_list_order(self) -> None:
        v = check({"excludes": ["~", ".."]}, {"x": "~/../x"})
        assert len(v) == 1
        assert 'must not contain "~"' in v[0].message

    def test_an_empty_excludes_list_rejects_nothing(self) -> None:
        assert check({"excludes": []}, {"x": "../.."}) == []


class TestMinMax:
    def test_min_is_inclusive(self) -> None:
        assert check({"min": 10}, {"x": 10}) == []
        assert check({"min": 10}, {"x": 11}) == []
        assert names(check({"min": 10}, {"x": 9.999})) == ["min"]

    def test_max_is_inclusive(self) -> None:
        assert check({"max": 10}, {"x": 10}) == []
        assert check({"max": 10}, {"x": 9}) == []
        assert names(check({"max": 10}, {"x": 10.001})) == ["max"]

    def test_handles_negative_and_zero_bounds(self) -> None:
        assert check({"min": -5, "max": 0}, {"x": -5}) == []
        assert check({"min": -5, "max": 0}, {"x": 0}) == []
        assert names(check({"min": -5, "max": 0}, {"x": 1})) == ["max"]
        assert names(check({"min": -5, "max": 0}, {"x": -6})) == ["min"]

    def test_both_bounds_can_fire_only_one_at_a_time(self) -> None:
        assert names(check({"min": 1, "max": 2}, {"x": 5})) == ["max"]
        assert names(check({"min": 1, "max": 2}, {"x": 0})) == ["min"]

    def test_reports_bounds_with_javascript_number_formatting(self) -> None:
        assert "must be <= 10, got 12" in check({"max": 10.0}, {"x": 12.0})[0].message


class TestLength:
    def test_bounds_string_length_inclusively(self) -> None:
        assert check({"maxLength": 3}, {"x": "abc"}) == []
        assert names(check({"maxLength": 3}, {"x": "abcd"})) == ["maxLength"]
        assert check({"minLength": 3}, {"x": "abc"}) == []
        assert names(check({"minLength": 3}, {"x": "ab"})) == ["minLength"]

    def test_bounds_list_length_inclusively(self) -> None:
        assert check({"maxLength": 2}, {"x": [1, 2]}) == []
        assert names(check({"maxLength": 2}, {"x": [1, 2, 3]})) == ["maxLength"]
        assert check({"minLength": 1}, {"x": [1]}) == []
        assert names(check({"minLength": 1}, {"x": []})) == ["minLength"]

    def test_min_length_zero_accepts_the_empty_string_and_list(self) -> None:
        assert check({"minLength": 0}, {"x": ""}) == []
        assert check({"minLength": 0}, {"x": []}) == []

    def test_max_length_zero_rejects_any_non_empty_value(self) -> None:
        assert names(check({"maxLength": 0}, {"x": "a"})) == ["maxLength"]
        assert check({"maxLength": 0}, {"x": ""}) == []

    def test_rejects_a_value_that_has_no_length_rather_than_skipping(self) -> None:
        # Skipping the check would fail OPEN: the constraint would be satisfied,
        # the rule would match, and the call would be allowed.
        assert names(check({"maxLength": 0}, {"x": {"a": 1, "b": 2}})) == ["type"]
        assert names(check({"maxLength": 0}, {"x": 12345})) == ["type"]
        assert names(check({"minLength": 5}, {"x": True})) == ["type"]

    def test_can_be_combined_into_an_exact_length(self) -> None:
        assert check({"minLength": 2, "maxLength": 2}, {"x": "ab"}) == []
        assert names(check({"minLength": 2, "maxLength": 2}, {"x": "abc"})) == ["maxLength"]
        assert names(check({"minLength": 2, "maxLength": 2}, {"x": "a"})) == ["minLength"]

    def test_counts_utf16_code_units_as_javascript_does(self) -> None:
        # An astral character costs two units, so a maxLength written against
        # either implementation binds the same way in the other.
        assert names(check({"maxLength": 1}, {"x": "\U0001F600"})) == ["maxLength"]
        assert check({"maxLength": 2}, {"x": "\U0001F600"}) == []


class TestUrlHosts:
    exact = {"urlHosts": ["example.com"]}
    wildcard = {"urlHosts": [".example.com"]}

    def test_accepts_an_exact_host(self) -> None:
        assert check(self.exact, {"x": "https://example.com/path?q=1"}) == []

    def test_an_exact_entry_does_not_cover_subdomains(self) -> None:
        assert names(check(self.exact, {"x": "https://api.example.com/"})) == ["urlHosts"]

    def test_a_leading_dot_entry_covers_subdomains_and_the_apex(self) -> None:
        assert check(self.wildcard, {"x": "https://api.example.com/"}) == []
        assert check(self.wildcard, {"x": "https://a.b.example.com/"}) == []
        assert check(self.wildcard, {"x": "https://example.com/"}) == []

    def test_a_host_that_merely_ends_with_the_allowed_name_is_not_a_subdomain(self) -> None:
        # The classic allowlist bypass: notexample.com must never satisfy
        # ".example.com". The leading dot in the suffix test is what prevents it.
        assert names(check(self.wildcard, {"x": "https://notexample.com/"})) == ["urlHosts"]
        assert names(check(self.exact, {"x": "https://notexample.com/"})) == ["urlHosts"]
        assert names(check(self.wildcard, {"x": "https://evil-example.com/"})) == [
            "urlHosts"
        ]

    def test_the_allowed_name_must_be_the_host_not_a_path_or_query(self) -> None:
        assert names(check(self.exact, {"x": "https://evil.com/example.com"})) == ["urlHosts"]
        assert names(check(self.exact, {"x": "https://evil.com/?to=example.com"})) == [
            "urlHosts"
        ]
        assert names(check(self.exact, {"x": "https://evil.com#example.com"})) == ["urlHosts"]

    def test_userinfo_before_an_at_does_not_decide_the_host(self) -> None:
        assert names(check(self.exact, {"x": "https://example.com@evil.com/"})) == [
            "urlHosts"
        ]

    def test_host_comparison_is_case_insensitive_in_both_directions(self) -> None:
        assert check(self.exact, {"x": "https://EXAMPLE.COM/"}) == []
        assert check({"urlHosts": ["EXAMPLE.COM"]}, {"x": "https://example.com/"}) == []
        assert check({"urlHosts": [".EXAMPLE.COM"]}, {"x": "https://API.example.com/"}) == []

    def test_a_port_is_not_part_of_the_hostname(self) -> None:
        assert check(self.exact, {"x": "https://example.com:8443/"}) == []

    def test_the_scheme_is_not_constrained_by_url_hosts_alone(self) -> None:
        # Documented scope: urlHosts checks the host. Restricting the scheme is
        # the job of `matches` / `startsWith`.
        assert check(self.exact, {"x": "ftp://example.com/x"}) == []
        assert check(self.exact, {"x": "file://example.com/x"}) == []

    def test_a_non_url_string_is_rejected_as_unparseable(self) -> None:
        v = check(self.exact, {"x": "not a url"})
        assert names(v) == ["urlHosts"]
        assert "not a parseable URL" in v[0].message
        assert names(check(self.exact, {"x": "example.com/path"})) == ["urlHosts"]
        assert names(check(self.exact, {"x": ""})) == ["urlHosts"]
        assert names(check(self.exact, {"x": "https://"})) == ["urlHosts"]

    def test_an_empty_url_hosts_list_rejects_every_parseable_url(self) -> None:
        assert names(check({"urlHosts": []}, {"x": "https://example.com/"})) == ["urlHosts"]

    def test_reports_the_offending_host_in_the_message(self) -> None:
        message = check(self.exact, {"x": "https://evil.com/"})[0].message
        assert 'host "evil.com" is not in the allowed set' in message

    def test_combines_with_other_constraints_on_the_same_value(self) -> None:
        c = {"type": "string", "urlHosts": [".example.com"], "excludes": [".."]}
        assert check(c, {"x": "https://api.example.com/v1"}) == []
        assert names(check(c, {"x": "https://api.example.com/../x"})) == ["excludes"]


class TestAdversarialTypeGating:
    """A wrongly-typed value must violate, never be skipped.

    Skipping is the fail-open direction: the constraint disappears, the rule
    matches, and the call is allowed. ``args`` is untrusted model output, and a
    policy is not obliged to declare ``type: string`` for the scoping to bind.
    """

    def test_string_constraints_are_not_skipped_for_a_non_string_value(self) -> None:
        assert names(check({"startsWith": ["/tmp/"]}, {"x": ["/etc/passwd"]})) == ["type"]
        assert names(check({"urlHosts": ["example.com"]}, {"x": 12345})) == ["type"]
        assert names(check({"excludes": [".."]}, {"x": {"path": "/tmp/../etc"}})) == ["type"]
        assert names(check({"matches": "^/tmp/"}, {"x": True})) == ["type"]

    def test_the_type_violation_names_the_constraints_it_could_not_check(self) -> None:
        v = check({"startsWith": ["/tmp/"], "excludes": [".."]}, {"x": ["/etc/passwd"]})
        assert len(v) == 1
        assert '"startsWith", "excludes"' in v[0].message
        assert v[0].message.endswith("got array")

    def test_numeric_bounds_are_not_skipped_for_a_non_number_value(self) -> None:
        assert names(check({"max": 100}, {"x": "999999"})) == ["type"]
        assert names(check({"min": 0}, {"x": [1]})) == ["type"]
        # A boolean is not a number, even though Python's bool subclasses int.
        assert names(check({"max": 100}, {"x": True})) == ["type"]

    def test_an_explicit_none_does_not_satisfy_a_required_scoped_constraint(self) -> None:
        # An own key set to None is indistinguishable from an absent one for
        # policy purposes; treating it as present would let `{"path": None}`
        # satisfy a required, scoped string constraint.
        assert names(check({"startsWith": ["/tmp/"]}, {"x": None})) == ["required"]
        assert names(check({"type": "string"}, {"x": None})) == ["required"]
        assert check({"optional": True, "startsWith": ["/tmp/"]}, {"x": None}) == []

    def test_a_wrongly_typed_value_still_reports_every_applicable_gate(self) -> None:
        v = check({"startsWith": ["/tmp/"], "min": 1, "maxLength": 2}, {"x": True})
        assert names(v) == ["type", "type", "type"]
