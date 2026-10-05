"""Acceptance 1: §1's public interface exists with exact signatures, as
corrected by ruling 3.3 (``extract_destinations -> tuple[tuple[Finding, ...], bool]``).

Anything paid needs that is not exported is a defect; anything exported that §1
does not list is an interface widening paid would start to depend on. Both
directions are asserted.
"""
from __future__ import annotations

import dataclasses
import inspect

import pytest

import xaidr.value_origin as vo

EXPECTED_ALL = {
    # §1.1
    "Origin", "WIRE_STRENGTH", "ORIGIN_STRENGTH", "Verdict", "WireValue", "RowState",
    "Writer", "Mode", "MatchKind", "RecordOutcome",
    "UnresolvedReason",                    # ruling 3.3 (reason: walk_bound | parse_failure)
    # §1.2
    "Span", "Authority", "SourceDesignation", "DestinationFinding", "CallVerdict",
    "Finding",                             # ruling 3.3
    # §1.3
    "LEDGER_MAX_ENTRIES", "MAX_ARG_LEAVES", "MAX_ARG_DEPTH", "MAX_LEAF_CHARS",
    "MAX_KEY_TOKENS", "PSL_SNAPSHOT_DATE",
    # §1.4
    "validate_designations", "validate_mode", "bind_ledger", "bind_fresh_ledger",
    "unbind_ledger", "ledger_bound", "record_principal_input", "record_tool_result",
    "evaluate_call", "should_block", "authority_of", "extract_destinations",
    "verdict_of", "row_text",
}

SIGNATURES = {                 # §1.4 as written, extract_destinations as corrected by 3.3
    "validate_designations": "(designations: 'Iterable[SourceDesignation]') -> 'tuple[SourceDesignation, ...]'",
    "validate_mode": "(mode: 'Mode | str') -> 'Mode'",
    "bind_ledger": "() -> 'None'",
    "bind_fresh_ledger": "() -> 'None'",
    "unbind_ledger": "() -> 'None'",
    "ledger_bound": "() -> 'bool'",
    "record_principal_input": "(text: 'str', spans: 'Sequence[Span] | None' = None, *, "
                              "input_clean: 'bool | None', truncated: 'bool' = False) -> 'RecordOutcome'",
    "record_tool_result": "(tool_name: 'str', arguments: 'Mapping[str, object] | None', "
                          "result: 'object', *, designations: 'Sequence[SourceDesignation]', "
                          "result_blocked: 'bool | None') -> 'RecordOutcome'",
    "evaluate_call": "(tool_name: 'str', arguments: 'Mapping[str, object] | None', *, "
                     "flow_active: 'bool') -> 'CallVerdict | None'",
    "should_block": "(verdict: 'CallVerdict', *, mode: 'Mode') -> 'bool'",
    "authority_of": "(value: 'str') -> 'Authority | None'",
    "extract_destinations": "(arguments: 'Mapping[str, object] | None') -> "
                            "'tuple[tuple[Finding, ...], bool]'",
    "verdict_of": "(wire: 'WireValue') -> 'Verdict'",
    "row_text": "(wire: 'str | None', scan_mode: 'str | None') -> 'tuple[RowState, str]'",
}

FIELDS = {
    "Span": ["text", "writer"],
    "Authority": ["scheme", "value"],
    "SourceDesignation": ["tool", "match", "source_arg", "pattern", "key_args", "label"],
    "Finding": ["path", "destination", "reason"],
    "DestinationFinding": ["path", "destination", "reason", "origin", "span_declared",
                           "source_label"],
    "CallVerdict": ["wire", "verdict", "row_state", "detail", "findings", "truncated"],
}

ENUMS = {
    "Origin": ["principal", "trusted_source", "untrusted_source", "unresolved"],
    "Verdict": ["authorized", "unauthorized", "unresolved", "not_evaluated"],
    "WireValue": ["principal", "principal_undeclared_span", "trusted_source",
                  "untrusted_source", "unresolved", "no_destination", "no_flow",
                  "ledger_absent", "ledger_saturated", "input_truncated",
                  "argument_bound", "result_truncated"],       # RULING 1+2 after M8
    "RowState": ["decided", "ran_evidence", "ran_clean", "not_reached", "not_applicable",
                 "not_recorded"],
    "Writer": ["principal", "untrusted"],
    "Mode": ["off", "record", "enforce"],
    "MatchKind": ["any", "url_prefix", "path_glob", "exact"],
    "RecordOutcome": ["recorded", "no_ledger", "saturated", "fault"],
    "UnresolvedReason": ["walk_bound", "parse_failure"],
}


def test_all_is_exactly_the_interface():
    assert set(vo.__all__) == EXPECTED_ALL
    assert len(vo.__all__) == len(set(vo.__all__))
    for name in vo.__all__:
        assert hasattr(vo, name), f"{name} is in __all__ but not exported"


@pytest.mark.parametrize("name", sorted(SIGNATURES))
def test_function_signature_is_exact(name):
    assert str(inspect.signature(getattr(vo, name))) == SIGNATURES[name]


@pytest.mark.parametrize("name", sorted(FIELDS))
def test_value_type_is_frozen_slotted_kw_only(name):
    cls = getattr(vo, name)
    params = cls.__dataclass_params__
    assert params.frozen
    assert "__slots__" in cls.__dict__
    fs = dataclasses.fields(cls)
    assert [f.name for f in fs] == FIELDS[name]
    assert all(f.kw_only for f in fs), f"{name}: every field keyword-only (V-6)"


def test_positional_construction_is_refused():
    """V-6: paid writing SourceDesignation("directory_lookup", MatchKind.EXACT, ...)
    must fail loudly, not bind label to the wrong position."""
    with pytest.raises(TypeError):
        vo.SourceDesignation("directory_lookup", vo.MatchKind.EXACT, "directory",
                             "corporate_directory", ("query",), "Corp dir")


@pytest.mark.parametrize("name", sorted(ENUMS))
def test_enum_values_are_exact(name):
    assert [m.value for m in getattr(vo, name)] == ENUMS[name]
    assert issubclass(getattr(vo, name), str)


def test_strength_tables():
    W, O = vo.WireValue, vo.Origin
    assert dict(vo.WIRE_STRENGTH) == {W.UNTRUSTED_SOURCE: 0, W.UNRESOLVED: 1,
                                      W.PRINCIPAL_UNDECLARED_SPAN: 2, W.TRUSTED_SOURCE: 3,
                                      W.PRINCIPAL: 4}
    assert dict(vo.ORIGIN_STRENGTH) == {O.UNTRUSTED_SOURCE: 0, O.UNRESOLVED: 1,
                                        O.TRUSTED_SOURCE: 2, O.PRINCIPAL: 3}
    with pytest.raises(TypeError):
        vo.WIRE_STRENGTH[W.PRINCIPAL] = 0          # read-only


def test_constants():
    assert (vo.LEDGER_MAX_ENTRIES, vo.MAX_ARG_LEAVES, vo.MAX_ARG_DEPTH,
            vo.MAX_LEAF_CHARS, vo.MAX_KEY_TOKENS) == (10_000, 64, 6, 4_000, 4)
    assert vo.PSL_SNAPSHOT_DATE == "2026-09-24"


def test_authority_key_is_the_only_digested_string():
    assert vo.Authority(scheme="mailto", value="a@x.example").key() == "mailto:a@x.example"


def test_no_ledger_accessor_is_exported():
    """§1: no accessor that returns ledger contents, no direct origin write, no
    function taking a correlation id — each is a laundering/disclosure primitive."""
    for name in vo.__all__:
        obj = getattr(vo, name)
        if callable(obj) and not isinstance(obj, type):
            params = inspect.signature(obj).parameters
            assert not any("correlation" in p or p == "origin" for p in params), name


_VERDICT_CASES = [
    ("principal", "authorized"), ("principal_undeclared_span", "authorized"),
    ("trusted_source", "authorized"), ("untrusted_source", "unauthorized"),
    ("unresolved", "unresolved"), ("no_destination", "not_evaluated"),
    ("no_flow", "not_evaluated"), ("ledger_absent", "not_evaluated"),
    ("ledger_saturated", "not_evaluated"), ("input_truncated", "not_evaluated"),
    ("argument_bound", "unresolved"), ("result_truncated", "not_evaluated")]


def test_the_verdict_table_covers_every_wire_value():
    """Milestone review: the table covered 9 of 12 and nothing noticed."""
    assert {w for w, _ in _VERDICT_CASES} == {w.value for w in vo.WireValue}


@pytest.mark.parametrize("wire,verdict", _VERDICT_CASES)
def test_verdict_of_is_total(wire, verdict):
    assert vo.verdict_of(vo.WireValue(wire)) is vo.Verdict(verdict)


def test_should_block_only_under_enforce_on_unauthorized_or_a_bound():
    # Renamed after RULING 1+2 (was ..._only_on_enforce_unauthorized): the bound
    # states block too (tests/test_value_origin_bounds.py); a plain unresolved does not.
    vo.bind_fresh_ledger()
    try:
        vo.record_tool_result("t", {}, "evil@x.example", designations=(), result_blocked=False)
        unauth = vo.evaluate_call("send", {"to": "evil@x.example"}, flow_active=True)
        unres = vo.evaluate_call("send", {"to": "who@x.example"}, flow_active=True)
    finally:
        vo.unbind_ledger()
    assert unauth.verdict is vo.Verdict.UNAUTHORIZED
    assert vo.should_block(unauth, mode=vo.Mode.ENFORCE)
    assert not vo.should_block(unauth, mode=vo.Mode.RECORD)
    assert not vo.should_block(unauth, mode=vo.Mode.OFF)
    assert not vo.should_block(unres, mode=vo.Mode.ENFORCE), "UNRESOLVED never blocks"


def test_validate_mode():
    assert vo.validate_mode("enforce") is vo.Mode.ENFORCE
    assert vo.validate_mode(vo.Mode.RECORD) is vo.Mode.RECORD
    with pytest.raises(ValueError, match="'Enforce'"):
        vo.validate_mode("Enforce")


D = vo.SourceDesignation
M = vo.MatchKind


@pytest.mark.parametrize("bad,field", [
    ("not a designation", "not a SourceDesignation"),
    (D(tool="", match=M.ANY, label="x"), ".tool"),
    (D(tool="t", match=M.ANY, label=""), ".label"),
    (D(tool="t", match=M.EXACT, pattern="p", label="x"), ".source_arg"),
    (D(tool="t", match=M.EXACT, source_arg="a", label="x"), ".pattern"),
    (D(tool="t", match=M.URL_PREFIX, source_arg="u", pattern="/no/host", label="x"), ".pattern"),
    (D(tool="t", match=M.PATH_GLOB, source_arg="p", pattern="rel/*", label="x"), ".pattern"),
    (D(tool="t", match=M.PATH_GLOB, source_arg="p", pattern="/a/../b/*", label="x"), ".pattern"),
    (D(tool="t", match=M.EXACT, source_arg="a", pattern="p", key_args=("a",), label="x"), ".key_args"),
    (D(tool="t", match="exact", source_arg="a", pattern="p", label="x"), ".match"),
])
def test_validate_designations_names_the_field(bad, field):
    with pytest.raises(ValueError, match=field.replace(".", r"\.")):
        vo.validate_designations([bad])


def test_validate_designations_rejects_duplicates():
    d = D(tool="t", match=M.EXACT, source_arg="a", pattern="p", label="x")
    with pytest.raises(ValueError, match="duplicate"):
        vo.validate_designations([d, D(tool="t", match=M.EXACT, source_arg="a", pattern="p", label="y")])
    assert vo.validate_designations([d]) == (d,)
