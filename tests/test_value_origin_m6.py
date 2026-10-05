"""A2 M6: principal input recording (ARCHITECTURE.md §1.1, §5 M6). Checks live
in tests/outside/drivers/m6_principal_input.py, run here in-process and from
the built wheel in tests/outside/test_m6_from_the_wheel.py."""
from __future__ import annotations

import importlib.util
import os

import pytest

import xaidr

_spec = importlib.util.spec_from_file_location(
    "m6_principal_input", os.path.join(os.path.dirname(__file__), "outside", "drivers", "m6_principal_input.py"))
m6 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m6)

EXPECT = {
    "undeclared": "principal_undeclared_span",
    "declared": "principal",
    "bytes": "principal_undeclared_span",
    "s30": ["principal_undeclared_span", "unresolved"],
    "s30_host_record_hop": ["principal_undeclared_span", "unresolved"],
    "s2_circuit_open": ["principal_undeclared_span", True, "unresolved"],
    "spans_ignored_warnings": 1,
    "not_scannable_ends_previous": "unresolved",
    "a2a_inbound_ends_implicit": "unresolved",
    "a2a_inbound_keeps_explicit": "principal_undeclared_span",
    "spans_mismatch_warnings": 1,
    # Owner, 2026-10-05: past the cap the destination is RECORDED (atoms over the whole
    # input). Its origin is the input's own (V-9): this filler is flagged, so untrusted
    # -- the same as the head. Was "input_truncated" (lost), the pin until this ruling.
    "input_cap": [True, "untrusted_source"],
}
WHY = {
    "undeclared": "the input seam recorded nothing",
    "declared": "spans= was not honoured",
    "bytes": "a bytes prompt was not recorded as its decoded text",
    "s30": "request 2 saw request 1's principal input (S30)",
    "s30_host_record_hop": "a host recording its own hop carried request 1's authority into request 2",
    "s2_circuit_open": "a circuit-open input did not end the previous request's implicit authority (S-2)",
    "not_scannable_ends_previous": "a non-scannable input did not end the previous request (S-2)",
    "a2a_inbound_ends_implicit": "an inbound A2A message kept the previous request's implicit ledger (Q21)",
    "a2a_inbound_keeps_explicit": "an inbound A2A message dropped begin_flow's explicit ledger (ruling 3.1)",
    "spans_mismatch_warnings": "a spans/text mismatch dropped the record silently (M6 silent-failure review)",
    "input_cap": "a destination past the input cap was lost instead of recorded with the input's own V-9 origin (owner, 2026-10-05: don't lose the destination)",
}


@pytest.fixture(scope="module")
def seen():
    return m6.collect(xaidr)


def check(seen):
    bad = [f"{k}: got {seen[k]!r}, want {v!r} -- {WHY.get(k, '')}"
           for k, v in EXPECT.items() if seen[k] != v]
    action, w = seen["flagged"]
    if action == "allowed":
        bad.append(f"flagged: precondition, the attack input was allowed ({seen['flagged']})")
    elif w != "untrusted_source":
        bad.append(f"flagged: a flagged input donated principal authority (wire {w!r}, V-9)")
    if seen["flagged_softened"][1] != "untrusted_source":
        bad.append(f"flagged_softened: a flagged input donated principal authority once an S6 "
                   f"transform softened it to {seen['flagged_softened'][0]!r} (wire "
                   f"{seen['flagged_softened'][1]!r}): input_clean read the post-mode verdict")
    assert not bad, "M6 principal input: " + "; ".join(bad)


def test_m6_principal_input(seen):
    check(seen)


def test_a_recorder_fault_never_reaches_the_host(monkeypatch, caplog):
    """Recording runs in a finally OUTSIDE scan()'s own try/except, so its guard
    is the only line between a recorder fault and the caller (M6 sabotage 3 and
    review: nothing committed guarded it). The verdict equals OFF's, and the
    fault is logged once."""
    import logging
    import warnings
    import xaidr.value_origin as vo

    def boom(*a, **k):
        raise RuntimeError("m6 injected recorder fault")
    monkeypatch.setattr(vo, "record_principal_input", boom)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        rec = xaidr.Sensor(agent_id="m6-guard", value_origin="record", reporter=m6._Null())
        off = xaidr.Sensor(agent_id="m6-guard-off", value_origin="off", reporter=m6._Null())
    with caplog.at_level(logging.ERROR, logger="xaidr.sensor"):
        r = [rec.scan("summarise the quarterly report", direction="input") for _ in range(2)]
    o = off.scan("summarise the quarterly report", direction="input")
    assert [(x.action, x.score, x.rules) for x in r] == [(o.action, o.score, o.rules)] * 2
    assert sum("input recording faulted" in x.getMessage() for x in caplog.records) == 1
