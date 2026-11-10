"""One scan id per scan: ``ScanResult.scan_id`` is the event's ``data.scanId``.

The gateway attestation names a ``scanId`` and Core joins it to the telemetry
row the sensor emitted for that scan. Every exit of ``scan``, ``scan_a2a`` and
``scan_tool_call`` mints the id ONCE and puts it on the event and on the result
it returns, so a caller holding the result can name the row.

Every exit, because an attestation built from a result whose id does not match
its event would name a row Core holds nothing for. The exits are: the main
path, an S5 gate, fail-closed, not-scannable, scan-error, circuit-open (block
mode), and a destination block raised as ``DelphiBlockedError``.

No attack string is written here; the inputs are plain text and a committed
corpus row.
"""

from __future__ import annotations

import json
import os

import pytest

from xaidr import DelphiBlockedError, Sensor, SensorExtension
from xaidr.circuit_breaker import CircuitBreaker
from xaidr.types import ScanResult

httpx = pytest.importorskip("httpx")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHELL = os.path.join(ROOT, "tests", "fixtures", "shell_corpus.json")


class _Sink:
    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch)

    def close(self):
        pass


def _events(sensor, sink):
    sensor.flush()
    return [e["data"] for e in sink.events if e.get("type") == "scan"]


def _sensor(**kw):
    sink = _Sink()
    s = Sensor(agent_id="scan-id", reporter=sink, **kw)
    return s, sink


def _check(result, sink, sensor, exit_name):
    events = _events(sensor, sink)
    assert len(events) == 1, f"{exit_name}: expected one event, got {len(events)}"
    event_id = events[0]["scanId"]
    assert isinstance(result.scan_id, str) and len(result.scan_id) == 12, (
        f"{exit_name}: the result carries no scan id ({result.scan_id!r})")
    assert result.scan_id == event_id, (
        f"{exit_name}: result.scan_id={result.scan_id!r} but the event says "
        f"{event_id!r}; the attestation would name a scanId Core holds no row for")


def _attack_command():
    """The first committed attack row a block sensor refuses on the tool path."""
    with open(SHELL, encoding="utf-8") as fh:
        attacks = json.load(fh)["attacks"]
    probe = Sensor(agent_id="probe", enforcement_mode="block", reporter=_Sink())
    for e in attacks:
        if probe.scan_tool_call("run_command", {"command": e["command"]}).action == "blocked":
            return e["command"]
    pytest.skip("no committed attack row blocks on the tool path")   # pragma: no cover


# ── main path, three entry points ────────────────────────────────────────────

def test_scan_main_path():
    s, sink = _sensor()
    _check(s.scan("hello there, a plain question", direction="input"), sink, s, "scan")


def test_scan_output_main_path():
    s, sink = _sensor()
    _check(s.scan_output("a plain answer"), sink, s, "scan_output")


def test_scan_a2a_main_path():
    s, sink = _sensor()
    _check(s.scan_a2a("a plain message", destination="peer"), sink, s, "scan_a2a")


def test_scan_tool_call_main_path():
    s, sink = _sensor()
    _check(s.scan_tool_call("get_ticket", {"ticket_id": "T-1"}), sink, s, "scan_tool_call")


def test_scan_tool_call_refused_in_block_mode():
    s, sink = _sensor(enforcement_mode="block")
    r = s.scan_tool_call("run_command", {"command": _attack_command()})
    assert r.action == "blocked", "precondition: the committed attack row blocks"
    _check(r, sink, s, "scan_tool_call(blocked)")


# ── refusal and fail-open exits ──────────────────────────────────────────────

class _Gate(SensorExtension):
    name = "gate"

    def gate(self, req):
        return ScanResult(action="blocked", score=1.0, category="quarantine", rules=["Q"])


@pytest.mark.parametrize("entry", ["scan", "scan_a2a", "scan_tool_call"])
def test_gate_exit(entry):
    s, sink = _sensor(extensions=[_Gate()])
    r = {"scan": lambda: s.scan("x y z", direction="input"),
         "scan_a2a": lambda: s.scan_a2a("x y z", destination="peer"),
         "scan_tool_call": lambda: s.scan_tool_call("t", {"a": "b"})}[entry]()
    assert r.action == "blocked"
    _check(r, sink, s, f"{entry} gate")


class _RaisingGate(SensorExtension):
    name = "raising-gate"

    def gate(self, req):
        raise RuntimeError("down")


@pytest.mark.parametrize("entry", ["scan", "scan_a2a", "scan_tool_call"])
def test_fail_closed_exit(entry):
    s, sink = _sensor(fail_closed=("controls",), extensions=[_RaisingGate()])
    r = {"scan": lambda: s.scan("x y z", direction="input"),
         "scan_a2a": lambda: s.scan_a2a("x y z", destination="peer"),
         "scan_tool_call": lambda: s.scan_tool_call("t", {"a": "b"})}[entry]()
    assert r.input_status == "fail_closed"
    _check(r, sink, s, f"{entry} fail_closed")


@pytest.mark.parametrize("entry", ["scan", "scan_a2a", "scan_tool_call"])
def test_not_scannable_exit(entry):
    s, sink = _sensor()
    r = {"scan": lambda: s.scan(12345, direction="input"),
         "scan_a2a": lambda: s.scan_a2a(12345, destination="peer"),
         "scan_tool_call": lambda: s.scan_tool_call(12345, {"a": "b"})}[entry]()
    assert r.input_status == "not_scannable", r
    _check(r, sink, s, f"{entry} not_scannable")


def test_scan_error_exit(monkeypatch):
    s, sink = _sensor()

    def boom(*a, **k):
        raise RuntimeError("scanner fault")

    monkeypatch.setattr(s._scanner, "scan", boom)
    r = s.scan("x y z", direction="input")
    assert r.input_status == "scan_error"
    _check(r, sink, s, "scan scan_error")


def test_circuit_open_exit_in_block_mode():
    s, sink = _sensor(enforcement_mode="block",
                      circuit_breaker=CircuitBreaker(violation_threshold=1,
                                                     violation_window_sec=60))
    first = s.scan_tool_call("run_command", {"command": _attack_command()})
    assert first.action == "blocked"
    assert s.circuit_state == "open", "precondition: one violation trips the breaker"
    sink.events.clear()
    r = s.scan("x y z", direction="input")
    assert "CIRCUIT_BREAKER_OPEN" in r.rules
    events = [e["data"] for e in _events_all(s, sink) if e["data"].get("direction") == "input"]
    assert len(events) == 1
    assert r.scan_id == events[0]["scanId"], (
        f"circuit-open: result.scan_id={r.scan_id!r} but the event says "
        f"{events[0]['scanId']!r}; the attestation would name a scanId Core holds no row for")


def _events_all(sensor, sink):
    sensor.flush()
    return [e for e in sink.events if e.get("type") == "scan"]


def test_destination_block_exit():
    s, sink = _sensor()
    s.block_urls(["denied.example"])
    client = s.protect_http(httpx.Client(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json={}))))
    with pytest.raises(DelphiBlockedError) as exc:
        client.post("https://denied.example/x", json={"message": "hello there"})
    r = exc.value.result
    events = _events(s, sink)
    assert len(events) == 1
    assert r.scan_id == events[0]["scanId"], (
        f"destination block: result.scan_id={r.scan_id!r} but the event says "
        f"{events[0]['scanId']!r}; the attestation would name a scanId Core holds no row for")


# ── the field itself ─────────────────────────────────────────────────────────

def test_scan_id_is_not_part_of_equality_or_repr():
    a = ScanResult(action="allowed", score=0.0, scan_id="abc")
    b = ScanResult(action="allowed", score=0.0)
    assert a == b
    assert "scan_id" not in repr(a)
    assert b.scan_id is None


def test_two_scans_get_two_ids():
    s, sink = _sensor()
    a = s.scan("one plain line", direction="input")
    b = s.scan("another plain line", direction="input")
    assert a.scan_id != b.scan_id
    ids = {e["scanId"] for e in _events(s, sink)}
    assert ids == {a.scan_id, b.scan_id}


def test_blocked_tool_verdict_keeps_the_scan_id():
    from xaidr.autopatch.core import tool_verdict

    s, sink = _sensor(blocked_tools=["rm_rf"])
    r = tool_verdict(s, "rm_rf", {"path": "/tmp"})
    assert r is not None and r.action == "blocked"
    _check(r, sink, s, "tool_verdict(blocked_tool)")


# ── the exits the M2 review found untested ───────────────────────────────────

class _Rebuild(SensorExtension):
    """An S6 transform that returns a FRESH result, carrying nothing over."""

    name = "rebuild"

    def transform_verdict(self, req, result):
        return ScanResult(action="allowed", score=0.0, category=None, rules=[])


def test_s6_transform_that_rebuilds_the_result_keeps_the_scan_id():
    s, sink = _sensor(extensions=[_Rebuild()])
    r = s.scan_tool_call("run_command", {"command": _attack_command()})
    assert r.action == "allowed", "precondition: the transform rebuilt the result"
    _check(r, sink, s, "scan_tool_call through an S6 rebuild")


class _DenyDestination(SensorExtension):
    name = "deny-dest"

    def destination_policy(self, dest):
        if dest.host == "denied.example":
            return ScanResult(action="blocked", score=1.0, category="policy", rules=["EXT_DENY"])
        return None


def test_destination_policy_extension_block_exit():
    s, sink = _sensor(extensions=[_DenyDestination()])
    client = s.protect_http(httpx.Client(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json={}))))
    with pytest.raises(DelphiBlockedError) as exc:
        client.get("https://denied.example/x")
    events = _events(s, sink)
    assert len(events) == 1 and events[0]["rules"] == ["EXT_DENY"]
    assert exc.value.result.scan_id == events[0]["scanId"], (
        "destination policy (extension): the raised result does not name its event")


def test_deny_destination_policy_file_block_exit():
    s, sink = _sensor()
    assert s.set_policy({
        "version": "1",
        "defaults": {"effect": "allow", "unclassified": "allow"},
        "rules": [{"id": "deny-denied", "effect": "block",
                   "match": {"destination_identifier": ["denied.example"]}}],
    }) is True
    client = s.protect_http(httpx.Client(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json={}))))
    with pytest.raises(DelphiBlockedError) as exc:
        client.post("https://denied.example/x", json={"message": "hello there"})
    events = _events(s, sink)
    assert len(events) == 1 and events[0]["category"] == "policy"
    assert exc.value.result.scan_id == events[0]["scanId"], (
        "destination policy (file): the raised result does not name its event")
