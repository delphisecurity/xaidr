"""No verdict depends on machine load (owner, 2026-11-01).

What a scan reads is decided by work limits: the L1 rule loop runs every rule over
at most ``L1_MAX_SCAN_CHARS``, a long input is read in at most ``MAX_SCAN_WINDOWS``
windows, and a tool result's reading stops when its work meter
(``RESULT_READ_UNITS``) is spent. Wall-clock limits are backstops only, set far
above the worst case of that work, and each records its own reason when it fires.

Two kinds of check here:

* **The same reading on a slower machine.** ``time.perf_counter`` is made to run
  ten times fast, which is what a machine ten times slower (or loaded) looks like
  to every wall-clock limit in the package. The scan and the result's reading
  must come out identical. Until 2026-11-01 a 0.5 s rule-loop budget, a 1.0 s
  window budget and a 4.0 s per-result bound decided what was read, so they did
  not.
* **A backstop that fires says so.** With each backstop set to zero, every
  verdict that differs from the normal one carries the backstop's own reason:
  ``LLM04_scan_budget_exceeded`` or ``LLM04_pathological_pattern`` on the scan,
  ``CallVerdict.backstop`` and ``valueOriginBackstop`` on a tool call. Never a
  silent change.
"""
from __future__ import annotations

import contextvars
import os
import sys
import time
import warnings

import pytest

from xaidr import value_origin as vo

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import build_benign_longform as bl  # noqa: E402

_REAL = time.perf_counter


@pytest.fixture
def slow_machine(monkeypatch):
    """Every wall-clock limit sees ten seconds pass for each one of work."""
    t0 = _REAL()
    fast = lambda: t0 + 10 * (_REAL() - t0)  # noqa: E731
    monkeypatch.setattr(time, "perf_counter", fast)
    from xaidr.value_origin import _clock
    monkeypatch.setattr(_clock, "_now", fast)
    return fast


def _sensor():
    from xaidr.sensor import DelphiSensor
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return DelphiSensor(agent_id="det", enforcement_mode="block",
                            reporter=type("N", (), {"report": lambda *a, **k: None})())


def _scan(text):
    r = _sensor().scan(text)
    return r.action, round(r.score, 6), r.category, sorted(r.rules)


def _flood(n):
    return [" ".join(f"https://h{i}.example/" for i in range(j, min(j + 400, n)))
            for j in range(0, n, 400)]


def _reading(result):
    from xaidr.value_origin import _ledger
    out = _ledger._result_authorities(result)
    return sorted(a.key() for a in out[0] + out[3]), out[1]


def _docs():
    docs = list(bl.generate())
    under = next(d["text"] for d in docs if 80_000 < len(d["text"]) < 100_000)
    # Over the cap and inside the two windows: read whole, unless something stops
    # the windows early, which is what a slower machine did to it.
    over = next(d["text"] for d in docs if 140_000 < len(d["text"]) < 160_000)
    return under, over


# ── the same reading on a slower machine ─────────────────────────────────────
def test_a_results_reading_is_the_same_on_a_slower_machine(slow_machine, monkeypatch):
    result = _flood(10_400)                       # an ordinary large result, ~0.7 s here
    slow = _reading(result)
    monkeypatch.setattr(time, "perf_counter", _REAL)
    from xaidr.value_origin import _clock
    monkeypatch.setattr(_clock, "_now", _REAL)
    idle = _reading(result)
    assert slow == idle, (
        f"a tool result read differently on a slower machine: {len(slow[0])} keys, cut "
        f"{slow[1]}, against {len(idle[0])} keys, cut {idle[1]} idle; a call to a "
        "destination it named reads untrusted_source on one and unresolved on the other")


@pytest.mark.parametrize("which", ["under the cap", "over the cap"])
def test_a_scan_is_the_same_on_a_slower_machine(which, slow_machine, monkeypatch):
    under, over = _docs()
    text = under if which == "under the cap" else over
    slow = _scan(text)
    monkeypatch.setattr(time, "perf_counter", _REAL)
    idle = _scan(text)
    assert slow == idle, (
        f"a benign {len(text):,}-char document scanned {slow} on a slower machine and "
        f"{idle} idle: the machine decided the verdict")


def test_the_windows_read_are_the_same_on_a_slower_machine(slow_machine, monkeypatch):
    """The window walk itself, each window scanned by L1 as the tail scan does: a
    long input is read in MAX_SCAN_WINDOWS windows on any machine."""
    from xaidr.scanner import l1
    _, over = _docs()
    text = over * 3                              # past the two windows' coverage

    def walk():
        n = 0
        for _, window, _ in l1.iter_scan_windows(text, time.perf_counter()):
            l1.scan_l1(window)
            n += 1
        return n
    slow = walk()
    monkeypatch.setattr(time, "perf_counter", _REAL)
    idle = walk()
    assert slow == idle == l1.MAX_SCAN_WINDOWS, (
        f"a {len(text):,}-char input was read in {slow} window(s) on a slower machine "
        f"and {idle} idle (cap {l1.MAX_SCAN_WINDOWS}): the clock decided how much was read")


# ── a backstop that fires says so ────────────────────────────────────────────
def test_the_rule_loop_backstop_says_so(monkeypatch):
    from xaidr.scanner import l1
    under, _ = _docs()
    normal = _scan(under)
    monkeypatch.setattr(l1, "_L1_SCAN_BUDGET_SEC", 0.0)
    fired = _scan(under)
    assert l1.SCAN_DEGRADED_RULE in fired[3], f"the rule-loop backstop fired silently: {fired}"
    assert l1.SCAN_DEGRADED_RULE not in normal[3], "precondition: the backstop is not normal"


def test_the_slow_rule_backstop_says_so(monkeypatch):
    from xaidr.scanner import l1
    under, _ = _docs()
    monkeypatch.setattr(l1, "_L1_RULE_SLOW_SEC", 0.0)
    fired = _scan(under)
    assert l1.PATHOLOGICAL_PATTERN_RULE in fired[3], f"the slow-rule backstop fired silently: {fired}"


def test_the_window_backstop_says_so(monkeypatch):
    from xaidr.scanner import l1
    _, over = _docs()
    normal = _scan(over)
    monkeypatch.setitem(l1.iter_scan_windows.__kwdefaults__, "budget_sec", 0.0)
    fired = _scan(over)
    assert l1.SCAN_DEGRADED_RULE in fired[3], (
        f"the window backstop stopped the windows and said nothing: {fired} (normal {normal})")
    assert l1.SCAN_DEGRADED_RULE not in normal[3], "precondition: the backstop is not normal"


def test_the_result_backstop_says_so_on_the_call_and_the_event(monkeypatch):
    from xaidr import provenance_chain as pc
    from xaidr.value_origin import _ledger
    s = _sensor()
    events = []
    real = s._telemetry.enqueue
    s._telemetry.enqueue = lambda ev: (events.append(ev), real(ev))[1]
    url = "https://h5.example/"

    def flow(backstop):
        monkeypatch.setattr(_ledger, "RESULT_TIME_BACKSTOP_SECONDS", backstop)
        pc.begin_flow(principal="alice")
        try:
            s.scan("Summarise the report.", direction="input")
            s._scan_tool_result("fetched", tool="web_fetch", arguments={},
                                raw_result=_flood(400))
            events.clear()
            r = s.scan_tool_call("http_post", {"url": url})
            return (r.value_origin.wire.value, r.value_origin.backstop,
                    [e["data"].get("valueOriginBackstop") for e in events
                     if e.get("data", {}).get("direction") == "tool_call"])
        finally:
            pc.clear_flow()
    normal = contextvars.Context().run(flow, _ledger.RESULT_TIME_BACKSTOP_SECONDS)
    fired = contextvars.Context().run(flow, 0.0)
    assert normal == ("untrusted_source", None, [None]), f"precondition: {normal}"
    assert fired[1] == "result_time_backstop" and fired[2] == ["result_time_backstop"], (
        f"the result backstop cut the result and the call said nothing of it: {fired}")
