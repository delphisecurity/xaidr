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


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "FOR THE OWNER (found while explaining the benign_longform anomaly): the core never "
    "examines an argument string longer than 4,000 chars (S16: a walk_bound finding, "
    "wire unresolved), and unresolved never blocks. An untrusted URL padded past 4,000 "
    "chars therefore evades ENFORCE. Needs a ruling: block on a bound hit under ENFORCE, "
    "or a visible state like input_truncated"))
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
