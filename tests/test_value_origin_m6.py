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
}
WHY = {
    "undeclared": "the input seam recorded nothing",
    "declared": "spans= was not honoured",
    "bytes": "a bytes prompt was not recorded as its decoded text",
    "s30": "request 2 saw request 1's principal input (S30)",
    "s30_host_record_hop": "a host recording its own hop carried request 1's authority into request 2",
    "s2_circuit_open": "a circuit-open input did not end the previous request's implicit authority (S-2)",
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
