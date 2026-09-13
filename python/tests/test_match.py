"""
Glob semantics and argument-path resolution.

These two functions decide *which* rule sees a call and *what value* that
rule inspects. A mistake in either one silently widens a policy, so the
assertions below are deliberately picky about separators, anchoring and
prototype-style key lookups.
"""

from __future__ import annotations

import pytest

from toolwrit.policy.match import MISSING, matches_any_glob, matches_glob, resolve_path


class TestMatchesGlob:
    def test_matches_a_literal_name_exactly(self) -> None:
        assert matches_glob("fs.read", "fs.read") is True
        assert matches_glob("fs.read", "fs.write") is False

    def test_anchors_the_whole_string(self) -> None:
        assert matches_glob("fs.read", "xfs.read") is False
        assert matches_glob("fs.read", "fs.reader") is False
        assert matches_glob("fs.read", "fs.read\n") is False, "no trailing newline"
        assert matches_glob("read", "fs.read") is False

    def test_is_case_sensitive(self) -> None:
        assert matches_glob("FS.read", "fs.read") is False
        assert matches_glob("fs.read", "FS.READ") is False

    def test_star_is_anything_but_a_separator(self) -> None:
        assert matches_glob("fs.*", "fs.read") is True
        assert matches_glob("fs.*", "fs.read_file") is True
        assert matches_glob("fs.*", "fs.read.raw") is False, "* must not cross a dot"
        assert matches_glob("fs.*", "fs.read/raw") is False, "* must not cross a slash"
        assert matches_glob("*", "read") is True
        assert matches_glob("*", "fs.read") is False
        assert matches_glob("*", "github/create_issue") is False

    def test_star_matches_the_empty_run(self) -> None:
        assert matches_glob("fs.*", "fs.") is True
        assert matches_glob("*", "") is True

    def test_doublestar_is_anything_at_all(self) -> None:
        assert matches_glob("**", "fs.read") is True
        assert matches_glob("**", "github/create_issue") is True
        assert matches_glob("**", "") is True
        assert matches_glob("fs.**", "fs.read.raw") is True
        assert matches_glob("github/**", "github/issues/create") is True
        assert matches_glob("**.read", "a.b.c.read") is True
        assert matches_glob("**.read", "a.b.c.write") is False
        # "Anything" includes a newline, asserted on both sides: TypeScript
        # needs its `s` flag for this and Python needs re.DOTALL, and a `**`
        # that quietly stops at a newline is a deny rule that stops matching.
        assert matches_glob("**", "a\nb") is True
        assert matches_glob("fs.**", "fs.a\nb") is True

    def test_keeps_literal_dots_literal(self) -> None:
        assert matches_glob("fs.read", "fsXread") is False
        assert matches_glob("a.b", "aXb") is False

    @pytest.mark.parametrize(
        "pattern,name,expected",
        [
            ("a+b", "a+b", True),
            ("a+b", "aab", False),
            ("a?b", "a?b", True),
            ("a?b", "ab", False),
            ("a(b)c", "a(b)c", True),
            ("a|b", "a|b", True),
            ("a|b", "a", False),
            ("a[bc]d", "a[bc]d", True),
            ("a[bc]d", "abd", False),
            ("a{1,2}", "a{1,2}", True),
            ("a\\b", "a\\b", True),
            ("^a$", "^a$", True),
            ("^a$", "a", False),
        ],
    )
    def test_escapes_regex_metacharacters(
        self, pattern: str, name: str, expected: bool
    ) -> None:
        assert matches_glob(pattern, name) is expected

    def test_caches_by_pattern_without_cross_contamination(self) -> None:
        for i in range(5):
            assert matches_glob("fs.*", "fs.read") is True, f"iteration {i}"
            assert matches_glob("fs.*", "net.read") is False, f"iteration {i}"


class TestMatchesAnyGlob:
    def test_matches_when_any_pattern_matches(self) -> None:
        assert matches_any_glob(["net.*", "fs.read"], "fs.read") is True

    def test_an_empty_list_matches_nothing(self) -> None:
        assert matches_any_glob([], "fs.read") is False
        assert matches_any_glob([], "") is False


class TestResolvePath:
    def test_resolves_a_top_level_key(self) -> None:
        assert resolve_path({"path": "/tmp/x"}, "path") == "/tmp/x"

    def test_resolves_nested_objects(self) -> None:
        args = {"body": {"recipient": {"email": "a@b.c"}}}
        assert resolve_path(args, "body.recipient.email") == "a@b.c"

    def test_indexes_into_lists_with_numeric_segments(self) -> None:
        args = {"to": ["a@b.c", "d@e.f"]}
        assert resolve_path(args, "to.0") == "a@b.c"
        assert resolve_path(args, "to.1") == "d@e.f"

    def test_resolves_through_lists_of_objects(self) -> None:
        assert resolve_path({"items": [{"sku": "x"}, {"sku": "y"}]}, "items.1.sku") == "y"

    def test_missing_for_out_of_range_and_non_integer_indices(self) -> None:
        args = {"to": ["a"]}
        assert resolve_path(args, "to.1") is MISSING
        assert resolve_path(args, "to.-1") is MISSING
        assert resolve_path(args, "to.length") is MISSING, "list length is not addressable"
        assert resolve_path(args, "to.1.5") is MISSING
        assert resolve_path(args, "to.0") == "a"

    def test_an_explicit_none_is_a_value_not_a_missing_key(self) -> None:
        # Python has no `undefined`, so None stands in for JSON null. The
        # distinction that survives is present-vs-absent, and it is the one the
        # constraint layer needs.
        args = {"present": None}
        assert resolve_path(args, "present") is None
        assert resolve_path(args, "present") is not MISSING
        assert resolve_path(args, "absent") is MISSING

    def test_preserves_falsy_values(self) -> None:
        args = {"a": 0, "b": "", "c": False, "d": None}
        assert resolve_path(args, "a") == 0
        assert resolve_path(args, "b") == ""
        assert resolve_path(args, "c") is False
        assert resolve_path(args, "d") is None

    def test_missing_when_the_path_runs_through_a_none(self) -> None:
        assert resolve_path({"a": None}, "a.b") is MISSING
        assert resolve_path({"a": {"b": None}}, "a.b.c") is MISSING
        assert resolve_path(None, "a") is MISSING

    def test_missing_when_the_cursor_is_a_primitive(self) -> None:
        assert resolve_path({"a": "string"}, "a.b") is MISSING
        assert resolve_path({"a": "string"}, "a.0") is MISSING, "strings are not indexable"
        assert resolve_path({"a": 42}, "a.bit_length") is MISSING
        assert resolve_path({"a": True}, "a.real") is MISSING

    def test_attribute_names_are_not_keys(self) -> None:
        # The dict/list lookups are by key only; no attribute of the underlying
        # Python object is ever reachable from a policy path.
        assert resolve_path({}, "keys") is MISSING
        assert resolve_path({}, "__class__") is MISSING
        assert resolve_path({}, "items") is MISSING
        assert resolve_path({"a": {}}, "a.__class__.__name__") is MISSING

    def test_resolves_a_key_that_shadows_an_attribute_name(self) -> None:
        assert resolve_path({"items": "shadowed"}, "items") == "shadowed"

    def test_an_empty_path_segment_does_not_resolve(self) -> None:
        assert resolve_path({"a": 1}, "") is MISSING
        assert resolve_path({"a": 1}, "a.") is MISSING

    def test_does_not_mutate_the_object_it_inspects(self) -> None:
        args = {"a": {"b": 1}}
        before = repr(args)
        resolve_path(args, "a.b.c.d")
        resolve_path(args, "keys")
        assert repr(args) == before
