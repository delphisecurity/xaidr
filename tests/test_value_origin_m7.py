"""A2 M7: tool-result recording (ARCHITECTURE.md §1.2, §5 M7). Checks live in
tests/outside/drivers/m7_tool_result.py, run here in-process and from the
built wheel in tests/outside/test_m7_from_the_wheel.py."""
from __future__ import annotations

import importlib.util
import os

import pytest

import xaidr

_spec = importlib.util.spec_from_file_location(
    "m7_tool_result", os.path.join(os.path.dirname(__file__), "outside", "drivers", "m7_tool_result.py"))
m7 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m7)

EXPECT = {
    "public_tool_result_v26": "untrusted_source",
    "internal_result_seam": "untrusted_source",
    "s23_designated_trusted": "trusted_source",
    "protect_tools_result_position": "untrusted_source",
    "q18_io_backed_not_consumed": [True, 0],
    "fault_isolation": {"public": True, "internal": True, "protect_tools": True},
}
WHY = {
    "public_tool_result_v26": "public scan(direction='tool_result') recorded nothing (V-26)",
    "internal_result_seam": "the scanned result seam recorded nothing",
    "s23_designated_trusted": "a designated, principal-keyed, clean read did not give trusted_source (S23)",
    "protect_tools_result_position": "protect_tools has no result position (owed since M1)",
    "q18_io_backed_not_consumed": "recording consumed an I/O-backed response (Q18)",
    "fault_isolation": "a recorder fault reached the host",
}


@pytest.fixture(scope="module")
def seen():
    return m7.collect(xaidr)


def check(seen):
    bad = [f"{k}: got {seen[k]!r}, want {v!r} -- {WHY[k]}" for k, v in EXPECT.items() if seen[k] != v]
    action, w = seen["s24_monitor_blockworthy_designated"]
    if action == "allowed":
        bad.append(f"s24: precondition, the block-worthy result was allowed ({action})")
    elif w != "untrusted_source":
        bad.append(f"s24: a block-worthy designated read gave {w!r} under monitor; the pre-mode "
                   "verdict must make it untrusted (V-2)")
    assert not bad, "M7 tool results: " + "; ".join(bad)


def test_m7_tool_result(seen):
    check(seen)


def test_f7_one_recorder_protect_tools_inside_a_scanned_seam_keeps_designated_trust():
    """§1.2 item 3 (F7): exactly one seam records each tool invocation. A
    protect_tools-wrapped tool inside a scanned result seam (here the enclosing
    marker the LangChain/MCP patches set, then the outer seam's own record) must
    leave the read to the outer seam. Otherwise its unscanned, untrusted record
    lands first and pins a designated read at untrusted (C-18)."""
    import warnings
    from concurrent.futures import ThreadPoolExecutor
    from xaidr import _vo_seams
    from xaidr import provenance_chain as pc
    from xaidr.value_origin import MatchKind, SourceDesignation, Span, Writer
    d_ = SourceDesignation(tool="directory_lookup", match=MatchKind.ANY, key_args=("query",),
                           label="directory")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="m7-f7", value_origin="record", reporter=m7._Null(),
                         value_origin_sources=[d_])

    def directory_lookup(query: str):
        return m7.BOB
    inner = s.protect_tools([directory_lookup])[0]

    def outer_seam():                      # what the patched BaseTool.run does
        out = inner(query="Bob")
        s._scan_tool_result(out, tool="directory_lookup", arguments={"query": "Bob"}, raw_result=out)
    prompt = "email Bob the quarterly report"

    def run():
        pc.begin_flow(principal="alice")
        try:
            s.scan(prompt, direction="input", spans=[Span(text=prompt, writer=Writer.PRINCIPAL)])
            _vo_seams.enclosing_result_seam(outer_seam)()
            return s.scan_tool_call("send_email", {"to": m7.BOB}).value_origin.wire.value
        finally:
            pc.clear_flow()
    with ThreadPoolExecutor(max_workers=1) as pool:
        w = pool.submit(run).result()
    assert w == "trusted_source", (
        f"trusted_source expected, {w!r}: the inner protect_tools recorded first (F7)")


def test_the_patched_langchain_hook_records_the_read_and_protect_tools_inside_defers():
    """The real seam, through fake langchain_core (tests/fake_frameworks.py): a
    designated tool whose implementation is itself a protect_tools wrapper runs
    through the PATCHED BaseTool.run. The after-hook records the raw result with
    the tool's identity, its dict arguments and its pre-mode verdict. The inner
    protect_tools sees the enclosing marker and does not record, so the read
    stays trusted (F7, end to end)."""
    import sys
    import warnings
    from concurrent.futures import ThreadPoolExecutor
    import fake_frameworks as fakes
    from xaidr import provenance_chain as pc
    from xaidr.autopatch.manifest import XaidrProtectionWarning
    from xaidr.value_origin import MatchKind, SourceDesignation, Span, Writer
    fakes.install_langchain_core()
    d_ = SourceDesignation(tool="directory_lookup", match=MatchKind.ANY, key_args=("query",),
                           label="directory")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", XaidrProtectionWarning)
            warnings.simplefilter("ignore")
            p = xaidr.protect(targets=["langchain_core"], quiet=True, reporter=m7._Null(),
                              agent_id="m7-hook", value_origin="record", value_origin_sources=[d_])
        assert p.patched, "nothing patched: the assertions below would be void"
        sensor = getattr(p, "sensor", None) or getattr(p, "_sensor", None)
        assert sensor is not None, f"cannot reach the protect() sensor: {dir(p)}"

        def directory_lookup(query: str):
            return m7.BOB
        inner = sensor.protect_tools([directory_lookup])[0]
        tool = sys.modules["langchain_core.tools"].BaseTool("directory_lookup", inner)
        prompt = "email Bob the quarterly report"

        def run():
            pc.begin_flow(principal="alice")
            try:
                sensor.scan(prompt, direction="input", spans=[Span(text=prompt, writer=Writer.PRINCIPAL)])
                tool.run({"query": "Bob"})
                return sensor.scan_tool_call("send_email", {"to": m7.BOB}).value_origin.wire.value
            finally:
                pc.clear_flow()
        with ThreadPoolExecutor(max_workers=1) as pool:
            w = pool.submit(run).result()
        assert w == "trusted_source", (
            f"{w!r}: the patched hook did not record the designated read with its identity, "
            "or the inner protect_tools recorded first (F7)")
    finally:
        undo = getattr(p, "unpatch", None) or getattr(p, "undo", None) if "p" in dir() else None
        if callable(undo):
            undo()
        fakes.uninstall(("langchain_core", "langchain"))
