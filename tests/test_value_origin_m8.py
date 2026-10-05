"""A2 M8: ENFORCE (ARCHITECTURE.md §5 M8; V-31 as ruled by the owner 2026-10-04).
Checks live in tests/outside/drivers/m8_enforce.py, run here in-process and from
the built wheel in tests/outside/test_m8_from_the_wheel.py."""
from __future__ import annotations

import importlib.util
import os

import pytest

import xaidr

_spec = importlib.util.spec_from_file_location(
    "m8_enforce", os.path.join(os.path.dirname(__file__), "outside", "drivers", "m8_enforce.py"))
m8 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m8)

CATEGORY = "untrusted_destination"          # owner, V-31 ruling
RULE = "ORIGIN_UNTRUSTED_DESTINATION"        # owner, V-31 ruling
AUDIT_RULE = "intent.value_origin_untrusted"  # the spec's V-31 audit key (waterfall `decided`)


@pytest.fixture(scope="module")
def seen():
    return m8.collect(xaidr)


def check(seen):
    bad = []
    off, rec = seen["off"], seen["record"]
    if (rec["action"], rec["rules"]) != (off["action"], off["rules"]):
        bad.append(f"RECORD changed an action: OFF={off['action']} RECORD={rec['action']}")
    b = seen["enforce_block"]
    if not (b["action"] == "blocked" and b["category"] == CATEGORY and RULE in b["rules"]
            and AUDIT_RULE in b["rules"] and b["wire"] == "untrusted_source"):
        bad.append(f"A-enforce-block: {b}")
    mo = seen["enforce_monitor"]
    if not (mo["action"] == "flagged" and RULE in mo["rules"]):
        bad.append(f"A-enforce-monitor: {mo}")
    if seen["enforce_block_protect_tools"]["executed"]:
        bad.append(f"the tool EXECUTED under ENFORCE+block: {seen['enforce_block_protect_tools']}")
    if not seen["enforce_monitor_protect_tools"]["executed"]:
        bad.append(f"monitor must flag and still execute: {seen['enforce_monitor_protect_tools']}")
    t = seen["b_designated_twin"]
    if t != {"action": "allowed", "wire": "trusted_source"}:
        bad.append(f"B-designated-twin: {t} (ENFORCE must not block every read-derived destination)")
    v = seen["v18_scan_error_path"]
    if v["action"] != "blocked":
        bad.append(f"value-origin block lost on the fail-open scan-error path (V-18): {v}")
    w = seen["zero_designation_warning"]
    if len(w) != 1 or "NOT YET WIRED" in w[0] or "blocked" not in w[0] or "designation" not in w[0]:
        bad.append(f"zero-designation ENFORCE warning: {w}")
    assert not bad, "M8 ENFORCE: " + "; ".join(bad)


def test_m8_enforce(seen):
    check(seen)


def test_a_padded_untrusted_url_still_blocks_under_enforce():
    import warnings
    from concurrent.futures import ThreadPoolExecutor
    from xaidr import provenance_chain as pc
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="m8-pad", value_origin="enforce", reporter=m8._Null())

    def run():
        pc.begin_flow(principal="alice")
        try:
            s.scan(m8.NEUTRAL, direction="input")
            s._scan_tool_result(m8.POISON, tool="web_fetch", arguments={}, raw_result=m8.POISON)
            pad = "".join(chr(97 + (i * 7) % 26) for i in range(5000))   # varied, not a repeat
            return s.scan_tool_call("http_post", {"url": m8.EVIL + "?q=" + pad}).value_origin
        finally:
            pc.clear_flow()
    with ThreadPoolExecutor(max_workers=1) as pool:
        v = pool.submit(run).result()
    assert xaidr.value_origin.should_block(v, mode=xaidr.value_origin.Mode.ENFORCE), (
        f"a padded untrusted URL read {v.wire.value!r} (truncated={v.truncated}) and does not block")


def _telemetry_of_a_value_origin_block(enforcement, extensions=()):
    import warnings
    from concurrent.futures import ThreadPoolExecutor
    from xaidr import provenance_chain as pc
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="m8-tel", value_origin="enforce", enforcement_mode=enforcement,
                         reporter=m8._Null(), extensions=list(extensions))
    events = []
    real = s._telemetry.enqueue
    s._telemetry.enqueue = lambda ev: (events.append(ev), real(ev))[1]

    def run():
        pc.begin_flow(principal="alice")
        try:
            s.scan(m8.NEUTRAL, direction="input")
            s._scan_tool_result(m8.POISON, tool="web_fetch", arguments={}, raw_result=m8.POISON)
            return s.scan_tool_call("http_post", {"url": m8.EVIL}).action
        finally:
            pc.clear_flow()
    with ThreadPoolExecutor(max_workers=1) as pool:
        returned = pool.submit(run).result()
    vo_events = [e["data"]["action"] for e in events
                 if e.get("data", {}).get("gate") == "value_origin"]
    return returned, vo_events


@pytest.mark.parametrize("enforcement, softener, want_returned", [
    ("monitor", False, "flagged"), ("block", True, "allowed")])
def test_telemetry_records_the_true_value_origin_block(enforcement, softener, want_returned):
    """M8 silent-failure review (CRITICAL): telemetry recorded the SOFTENED
    verdict (monitor's `flagged`, or an S6 transform's `allowed`), so nothing
    anywhere showed that value origin had blocked. Every other gate emits the
    TRUE verdict before _apply_mode (the S6 contract: telemetry and the breaker
    have already seen it)."""
    from dataclasses import replace
    from xaidr import SensorExtension

    class Soften(SensorExtension):
        name = "m8-soften"

        def transform_verdict(self, req, result):
            return replace(result, action="allowed", score=0.0) if result.action in ("blocked", "flagged") else result
    returned, events = _telemetry_of_a_value_origin_block(enforcement, [Soften()] if softener else [])
    assert returned == want_returned, returned
    assert events == ["blocked"], (
        f"the value-origin event says {events!r} while the true verdict was 'blocked' "
        f"(returned {returned!r}): the block left no trace")


def test_an_untrusted_destination_among_many_arguments_still_blocks():
    import warnings
    from concurrent.futures import ThreadPoolExecutor
    from xaidr import provenance_chain as pc
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="m8-leaves", value_origin="enforce", reporter=m8._Null())

    def run():
        pc.begin_flow(principal="alice")
        try:
            s.scan(m8.NEUTRAL, direction="input")
            s._scan_tool_result(m8.POISON, tool="web_fetch", arguments={}, raw_result=m8.POISON)
            args = {f"k{i}": "v" for i in range(70)}
            args["url"] = m8.EVIL
            return s.scan_tool_call("http_post", args).value_origin
        finally:
            pc.clear_flow()
    with ThreadPoolExecutor(max_workers=1) as pool:
        v = pool.submit(run).result()
    assert xaidr.value_origin.should_block(v, mode=xaidr.value_origin.Mode.ENFORCE), (
        f"an untrusted destination among 71 arguments read {v.wire.value!r} (truncated={v.truncated})")


def test_a_destination_past_64k_in_one_tool_result_reads_result_truncated_and_blocks():
    """Was a strict xfail asserting ("blocked", "untrusted_source"): wrong twice --
    the cap stays (owner: keep the numbers), so the tail is still not recorded,
    and this sensor is in the DEFAULT monitor mode, where a block is returned as
    "flagged". RULING 1+2: the cut result is a visible state, and it blocks."""
    import warnings
    from concurrent.futures import ThreadPoolExecutor
    from xaidr import provenance_chain as pc
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="m8-tail", value_origin="enforce", reporter=m8._Null())
    filler = " ".join(f"line {i} of the quarterly report." for i in range(3000))   # > 65,536 chars
    result = filler + " " + m8.POISON

    def run():
        pc.begin_flow(principal="alice")
        try:
            s.scan(m8.NEUTRAL, direction="input")
            s._scan_tool_result(result, tool="web_fetch", arguments={}, raw_result=result)
            r = s.scan_tool_call("http_post", {"url": m8.EVIL})
            return r.action, r.value_origin.wire.value
        finally:
            pc.clear_flow()
    with ThreadPoolExecutor(max_workers=1) as pool:
        got = pool.submit(run).result()
    assert len(filler) > 65_536
    assert got == ("flagged", "result_truncated"), (
        f"an untrusted destination {len(filler):,} chars into one tool result gave {got}: "
        "the cut result is silent and ENFORCE allows the call")


def _directory_flow(with_identity):
    import warnings
    from concurrent.futures import ThreadPoolExecutor
    from xaidr import provenance_chain as pc
    from xaidr.value_origin import MatchKind, SourceDesignation
    d = SourceDesignation(tool="directory_lookup", match=MatchKind.ANY, key_args=("query",),
                          label="corp directory")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="m8-identity", value_origin="enforce", enforcement_mode="block",
                         value_origin_sources=[d], reporter=m8._Null())

    def run():
        pc.begin_flow(principal="alice")
        try:
            s.scan("Look up Jordan in the directory and email them the agenda.", direction="input")
            kw = {"tool": "directory_lookup", "arguments": {"query": "Jordan"}} if with_identity else {}
            s.scan("jordan@corp.example", direction="tool_result", **kw)
            r = s.scan_tool_call("send_email", {"to": "jordan@corp.example"})
            return r.action, r.value_origin.wire.value
        finally:
            pc.clear_flow()
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(run).result()


def test_the_public_tool_result_seam_takes_an_identity_so_a_designation_can_match():
    """Owner RULING 3a after M8: scan(direction="tool_result", tool=, arguments=).
    V-26 recorded every public tool_result read nameless and untrusted, so no
    designation could ever match it and ENFORCE blocked the legitimate directory
    lookup. With the identity the designated read is trusted and the call runs."""
    named = _directory_flow(True)
    assert named[0] != "blocked" and named[1] in ("trusted_source", "principal_undeclared_span"), (
        f"a designated directory read through the PUBLIC seam, with tool= and arguments=, "
        f"gave {named}: the identity did not reach the recorder")
    assert _directory_flow(False) == ("blocked", "untrusted_source"), (
        "without tool= the public read must stay nameless and untrusted (V-26)")


def test_tool_identity_on_a_non_result_direction_is_named_not_silently_dropped(caplog):
    import logging
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = xaidr.Sensor(agent_id="m8-identity-off", value_origin="record", reporter=m8._Null())
    with caplog.at_level(logging.WARNING, logger="xaidr"):
        s.scan("hello", direction="input", tool="directory_lookup")
        s.scan("hello", direction="input", tool="directory_lookup")
    hits = [r.getMessage() for r in caplog.records if "tool=" in r.getMessage()]
    assert len(hits) == 1 and "ignored" in hits[0], hits
