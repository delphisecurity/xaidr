"""B2: an MCP ``tools/call`` POST carries the tool-call scan that authorised it.

``scan_tool_call`` (which the MCP client seam runs before ``call_tool``) records
a pending entry keyed by tool name and an arguments hash, when an extension
attests. At egress, a body that parses as JSON-RPC ``tools/call`` with the same
``params.name`` and the same arguments hash takes the oldest matching entry,
once, and the request's ``EgressView`` carries that scan beside the scan of its
own bytes (B1). The scans are ordered strictest found first; on a tie the
tool-call scan comes first.

The table is per sensor, behind a lock, 256 entries, 300 s, consumed once; on
two entries whose found verdicts differ the strictest binds and the ambiguity
is logged once per tool; evictions and expiries are counted.

The MCP transport's POST leaves from the transport's writer task, not from the
task that called ``call_tool`` (READ §10.1, measured on mcp 1.30.0), which is
why the binding is a table and not a ContextVar. The real-client cases drive
the mcp 1.x API (``FastMCP``, ``streamablehttp_client``) and skip on mcp 2.x,
which ``tests/test_httpx2_mcp.py`` drives over httpx2.

Inputs: committed corpus rows and plain benign arguments. No attack string.
"""

from __future__ import annotations

import asyncio
import importlib.metadata as _md
import json
import logging
import os
import socket
import subprocess
import sys
import time

import pytest

import xaidr
from xaidr import Sensor, SensorExtension
from xaidr.types import safe_content_hash

httpx = pytest.importorskip("httpx")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHELL = os.path.join(ROOT, "tests", "fixtures", "shell_corpus.json")
URL = "https://mcp.example/mcp"


class _Sink:
    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch)

    def close(self):
        pass


class _Record(SensorExtension):
    name = "record-attest"

    def __init__(self):
        self.views = []

    def attest_egress(self, view):
        self.views.append(view)
        return {"x-delphi-attestation": "demo"}


@pytest.fixture(autouse=True)
def _unprotect_after():
    yield
    xaidr.unprotect()


def _rpc(name, args, rid=1):
    return {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
            "params": {"name": name, "arguments": args}}


def _sensor(mode="monitor", **kw):
    rec, sink = _Record(), _Sink()
    s = Sensor(agent_id="mcp-bind", enforcement_mode=mode, reporter=sink,
               extensions=[rec], **kw)
    return s, rec, sink


def _post(sensor, body):
    """One POST under protect(), as the MCP streamable-HTTP client's writer task
    sends it. Returns the headers the transport saw."""
    seen = {}

    def handler(request):
        seen["headers"] = dict(request.headers)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    xaidr.protect(sensor=sensor, targets=["httpx"], quiet=True)
    try:
        with httpx.Client(transport=httpx.MockTransport(handler)) as c:
            c.post(URL, json=body)
    finally:
        xaidr.unprotect()
    return seen["headers"]


def _tool_scan(view):
    tool = [sc for sc in view.scans if sc.direction == "tool_call"]
    return tool[0] if tool else None


def _tool_events(sensor, sink):
    sensor.flush()
    return [e["data"] for e in sink.events if e["data"].get("direction") == "tool_call"]


# ── binding ──────────────────────────────────────────────────────────────────

def test_a_tools_call_post_carries_the_tool_call_scan():
    s, rec, sink = _sensor()
    r = s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    _post(s, _rpc("get_ticket", {"ticket_id": "T-1"}))
    view = rec.views[-1]
    assert sorted(sc.direction for sc in view.scans) == ["a2a", "tool_call"], view.scans
    tool = _tool_scan(view)
    assert tool.scan_id == r.scan_id
    assert tool.scan_id == _tool_events(s, sink)[0]["scanId"]
    assert tool.found == tool.enforced == "allowed"
    assert tool.impact_class == _tool_events(s, sink)[0]["impactClass"]
    assert isinstance(tool.rules, tuple)


def test_two_calls_to_one_tool_each_carry_their_own_scan():
    s, rec, _ = _sensor()
    r1 = s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    r2 = s.scan_tool_call("get_ticket", {"ticket_id": "T-2"})
    _post(s, _rpc("get_ticket", {"ticket_id": "T-2"}))
    _post(s, _rpc("get_ticket", {"ticket_id": "T-1"}))
    second, first = rec.views[-2], rec.views[-1]
    assert _tool_scan(second).scan_id == r2.scan_id and _tool_scan(first).scan_id == r1.scan_id, (
        "two calls to one tool exchanged attestations")


def test_the_entry_is_consumed_once():
    s, rec, _ = _sensor()
    s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    _post(s, _rpc("get_ticket", {"ticket_id": "T-1"}))
    _post(s, _rpc("get_ticket", {"ticket_id": "T-1"}))
    assert _tool_scan(rec.views[-2]) is not None
    assert _tool_scan(rec.views[-1]) is None, "a consumed entry bound a second request"


def test_argument_order_does_not_matter_but_values_do():
    s, rec, _ = _sensor()
    r = s.scan_tool_call("search", {"query": "open", "limit": 5})
    _post(s, _rpc("search", {"limit": 5, "query": "open"}))
    assert _tool_scan(rec.views[-1]).scan_id == r.scan_id
    s.scan_tool_call("search", {"query": "open", "limit": 5})
    _post(s, _rpc("search", {"query": "open", "limit": 6}))
    assert _tool_scan(rec.views[-1]) is None, "different arguments bound the same scan"


def test_a_body_that_is_not_tools_call_binds_nothing():
    s, rec, _ = _sensor()
    s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    _post(s, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    _post(s, {"message": "hello there friend"})
    assert all(_tool_scan(v) is None for v in rec.views)


def test_nothing_is_recorded_without_an_attesting_extension():
    sink = _Sink()
    s = Sensor(agent_id="mcp-bind", reporter=sink)
    s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    assert len(s._pending_tool_calls) == 0


def test_the_table_holds_256_and_counts_evictions():
    s, rec, _ = _sensor()
    for i in range(300):
        s.scan_tool_call("get_ticket", {"ticket_id": f"T-{i}"})
    assert len(s._pending_tool_calls) == 256
    assert s._pending_tool_calls.evicted == 44
    # The oldest were evicted: T-0 no longer binds, T-299 does.
    _post(s, _rpc("get_ticket", {"ticket_id": "T-0"}))
    assert _tool_scan(rec.views[-1]) is None
    _post(s, _rpc("get_ticket", {"ticket_id": "T-299"}))
    assert _tool_scan(rec.views[-1]) is not None


def test_an_entry_older_than_300_seconds_does_not_bind(monkeypatch):
    s, rec, _ = _sensor()
    s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    table = s._pending_tool_calls
    monkeypatch.setattr(table, "_now", lambda: time.monotonic() + 301.0)
    _post(s, _rpc("get_ticket", {"ticket_id": "T-1"}))
    assert _tool_scan(rec.views[-1]) is None
    assert table.expired == 1


def test_ambiguity_binds_the_strictest_and_logs_once_per_tool(caplog):
    s, rec, _ = _sensor()
    s.scan_tool_call("issue_refund", {"amount": 10})            # allowed
    assert s.set_policy({
        "version": "1", "defaults": {"effect": "allow", "unclassified": "allow"},
        "rules": [{"id": "deny-refund", "effect": "block", "match": {"tools": ["issue_refund"]}}],
    }) is True
    s.scan_tool_call("issue_refund", {"amount": 10})            # found blocked
    with caplog.at_level(logging.INFO, logger="xaidr"):
        _post(s, _rpc("issue_refund", {"amount": 10}))
        tool = _tool_scan(rec.views[-1])
        assert tool.found == "blocked", "ambiguity bound the lenient scan"
        # the other entry stays and binds the next request
        _post(s, _rpc("issue_refund", {"amount": 10}))
        assert _tool_scan(rec.views[-1]).found == "allowed"
    hits = [r for r in caplog.records if "issue_refund" in r.getMessage()
            and "pending" in r.getMessage()]
    assert len(hits) == 1, f"expected one ambiguity line, got {len(hits)}"


def test_scans_are_ordered_strictest_found_first():
    with open(SHELL, encoding="utf-8") as fh:
        attacks = json.load(fh)["attacks"]
    s, rec, _ = _sensor("monitor")
    probe = Sensor(agent_id="probe", enforcement_mode="block", reporter=_Sink())
    cmd = next(e["command"] for e in attacks
               if probe.scan_tool_call("run_command", {"command": e["command"]}).action == "blocked")
    s.scan_tool_call("run_command", {"command": cmd})
    _post(s, _rpc("run_command", {"command": cmd}))
    view = rec.views[-1]
    assert view.scans[0].direction == "tool_call" and view.scans[0].found == "blocked"
    assert view.scans[0].enforced == "flagged"


# ── found on the MCP path: the M3 rule on the tool-call scan ─────────────────

def test_monitor_found_on_the_mcp_path_is_the_block_action():
    with open(SHELL, encoding="utf-8") as fh:
        shell = json.load(fh)
    rows = shell["attacks"][:60] + shell["benign"][:20]
    block = Sensor(agent_id="ref", enforcement_mode="block", reporter=_Sink())
    s, rec, _ = _sensor("monitor")
    hidden, guard = [], 0
    for i, e in enumerate(rows):
        args = {"command": e["command"]}
        reference = block.scan_tool_call("run_command", args).action
        s.scan_tool_call("run_command", args)
        _post(s, _rpc("run_command", args, rid=i))
        tool = _tool_scan(rec.views[-1])
        assert tool is not None, f"row {i}: the tools/call POST carried no tool-call scan"
        if tool.found != reference:
            hidden.append((i, reference, tool.found))
        if reference == "blocked" and tool.found == "blocked" and tool.enforced == "flagged":
            guard += 1
    assert not hidden, (
        f"mcp: monitor sensor attested {hidden[0][2]!r} for a call it found {hidden[0][1]!r} "
        f"({len(hidden)} rows): the gateway would not learn what the sensor found")
    print(f"mcp: rows with found=blocked and enforced=flagged: {guard}")
    assert guard >= 1, "vacuous: no row softened on the MCP path"


class _SoftenAll(SensorExtension):
    """An S6 transform that rebuilds every verdict as allowed and SAYS it found
    allowed: the bound tool-call scan must read the pre-mode record."""

    name = "soften-all"

    def transform_verdict(self, req, result):
        from xaidr.types import ScanResult
        return ScanResult(action="allowed", score=0.0, category=None, rules=[],
                          found_action="allowed")


def test_an_s6_transform_does_not_rewrite_the_bound_tool_call_scan():
    with open(SHELL, encoding="utf-8") as fh:
        attacks = json.load(fh)["attacks"][:40]
    block = Sensor(agent_id="ref", enforcement_mode="block", reporter=_Sink())
    rec, sink = _Record(), _Sink()
    s = Sensor(agent_id="mcp-bind", enforcement_mode="monitor", reporter=sink,
               extensions=[rec, _SoftenAll()])
    rewritten, guard = [], 0
    for i, e in enumerate(attacks):
        args = {"command": e["command"]}
        reference = block.scan_tool_call("run_command", args).action
        r = s.scan_tool_call("run_command", args)
        assert r.action == "allowed", "precondition: the transform softened"
        _post(s, _rpc("run_command", args, rid=i))
        tool = _tool_scan(rec.views[-1])
        if tool.found != reference:
            rewritten.append((i, reference, tool.found))
        if reference == "blocked" and tool.found == "blocked" and tool.enforced == "allowed":
            guard += 1
    assert not rewritten, (
        f"mcp: an S6 transform rewrote the attested found verdict ({len(rewritten)} rows)")
    assert guard >= 1, "vacuous: no refused row reached the MCP path"


# ── a halted call makes no POST, so it leaves no entry ───────────────────────

def test_a_call_the_host_halts_leaves_no_entry():
    """Block mode: a refused tool call never runs, so no tools/call POST follows
    it. Its entry must not bind the next call to the same tool with the same
    arguments that does leave."""
    rec, sink = _Record(), _Sink()
    s = Sensor(agent_id="mcp-bind", enforcement_mode="block", reporter=sink, extensions=[rec])
    assert s.set_policy({
        "version": "1", "defaults": {"effect": "allow", "unclassified": "allow"},
        "rules": [{"id": "deny-refund", "effect": "block", "match": {"tools": ["issue_refund"]}}],
    }) is True
    refused = s.scan_tool_call("issue_refund", {"amount": 10})
    assert refused.action == "blocked"
    assert len(s._pending_tool_calls) == 0, "a halted call left an entry behind"
    assert s.set_policy({"version": "1", "defaults": {"effect": "allow", "unclassified": "allow"},
                         "rules": []}) is True
    allowed = s.scan_tool_call("issue_refund", {"amount": 10})
    _post(s, _rpc("issue_refund", {"amount": 10}))
    tool = _tool_scan(rec.views[-1])
    assert tool.scan_id == allowed.scan_id and tool.enforced == "allowed", (
        "a halted call's entry bound the request that did leave")
    # a retry of the same body binds nothing: the entry was consumed
    _post(s, _rpc("issue_refund", {"amount": 10}))
    assert _tool_scan(rec.views[-1]) is None


def test_a_configured_blocked_tool_leaves_no_entry_in_either_mode():
    for mode in ("block", "monitor"):
        rec, sink = _Record(), _Sink()
        s = Sensor(agent_id="mcp-bind", enforcement_mode=mode, reporter=sink,
                   extensions=[rec], blocked_tools=["rm_rf"])
        s.scan_tool_call("rm_rf", {"path": "/tmp"})
        assert len(s._pending_tool_calls) == 0, f"{mode}: a blocked tool left an entry"


def test_a_monitor_sensor_records_a_call_it_found_blocked():
    """Monitor proceeds, so the POST follows; the entry carries found=blocked."""
    with open(SHELL, encoding="utf-8") as fh:
        attacks = json.load(fh)["attacks"]
    probe = Sensor(agent_id="probe", enforcement_mode="block", reporter=_Sink())
    cmd = next(e["command"] for e in attacks
               if probe.scan_tool_call("run_command", {"command": e["command"]}).action == "blocked")
    s, rec, _ = _sensor("monitor")
    s.scan_tool_call("run_command", {"command": cmd})
    assert len(s._pending_tool_calls) == 1
    _post(s, _rpc("run_command", {"command": cmd}))
    assert _tool_scan(rec.views[-1]).found == "blocked"


def test_the_bound_scan_carries_value_origin():
    s, rec, _ = _sensor()
    r = s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    assert r.value_origin is not None, "precondition: value origin records by default"
    _post(s, _rpc("get_ticket", {"ticket_id": "T-1"}))
    tool = _tool_scan(rec.views[-1])
    assert tool.value_origin == r.value_origin.wire.value, (
        f"the attested tool-call scan dropped value origin: {tool.value_origin!r}")


def test_no_arguments_and_empty_arguments_are_one_call():
    s, rec, _ = _sensor()
    r = s.scan_tool_call("ping", None)
    _post(s, {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "ping"}})
    assert _tool_scan(rec.views[-1]).scan_id == r.scan_id


# ── a real MCP client against a local streamable-HTTP server ─────────────────

_SERVER = r'''
import sys
from mcp.server.fastmcp import FastMCP
m = FastMCP("probe", host="127.0.0.1", port=int(sys.argv[1]))
@m.tool()
def echo(text: str) -> str:
    return text
m.run(transport="streamable-http")
'''


def _mcp_major():
    try:
        return int(_md.version("mcp").split(".")[0])
    except Exception:
        return None


@pytest.fixture(scope="module")
def mcp_server():
    pytest.importorskip("mcp")
    if (_mcp_major() or 0) >= 2:
        pytest.skip("drives the mcp 1.x client API (FastMCP, streamablehttp_client)")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    proc = subprocess.Popen([sys.executable, "-c", _SERVER, str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(200):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            pytest.fail("the MCP server did not start")
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def _call_tools(url, calls, wire=None):
    """Run ``calls`` over one real client session. ``wire``, when given, collects
    (attestation header value, tools/call arguments) for every POST that left,
    read by an httpx request hook on the client the transport uses."""
    import httpx as _httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    def factory(headers=None, timeout=None, auth=None, **kw):
        async def on_request(request):
            if wire is None:
                return
            try:
                body = json.loads(request.content)
            except Exception:
                return
            if isinstance(body, dict) and body.get("method") == "tools/call":
                wire.append((request.headers.get("x-delphi-attestation"),
                             body["params"].get("arguments") or {}))
        return _httpx.AsyncClient(headers=headers, timeout=timeout, auth=auth,
                                  event_hooks={"request": [on_request]}, **kw)

    async def go():
        async with streamablehttp_client(url, httpx_client_factory=factory) as (r, w, _):
            async with ClientSession(r, w) as session:
                await session.initialize()
                return await asyncio.gather(*(session.call_tool(n, a) for n, a in calls))
    return asyncio.run(go())


class _Numbered(_Record):
    """Returns a header naming the view, so a wire capture can be joined to it."""

    def attest_egress(self, view):
        self.views.append(view)
        return {"x-delphi-attestation": str(len(self.views) - 1)}


def test_real_mcp_call_tool_binds_the_tool_call_scan(mcp_server):
    s, rec, sink = _sensor()
    xaidr.protect(sensor=s, targets=["mcp", "httpx"], quiet=True)
    wire = []
    results = _call_tools(mcp_server, [("echo", {"text": "hello there"})], wire=wire)
    assert results[0].content[0].text == "hello there"
    views = [v for v in rec.views if _tool_scan(v) is not None]
    assert len(views) == 1, f"expected one attested tools/call POST, saw {len(views)}"
    tool = _tool_scan(views[0])
    events = _tool_events(s, sink)
    assert len(events) == 1 and tool.scan_id == events[0]["scanId"]
    assert tool.found == "allowed" and views[0].method == "POST"
    assert wire and wire[0][0] == "demo", "the header did not reach the wire"


def _echo_text_a_block_sensor_refuses():
    """A committed attack row that the tool path refuses when passed as the
    echo tool's text, so the two concurrent calls have DIFFERENT found verdicts:
    a table keyed by tool name alone would then bind the strict entry to the
    benign POST, whatever order the POSTs leave in."""
    with open(SHELL, encoding="utf-8") as fh:
        attacks = json.load(fh)["attacks"]
    probe = Sensor(agent_id="probe", enforcement_mode="block", reporter=_Sink())
    for e in attacks:
        if probe.scan_tool_call("echo", {"text": e["command"]}).action == "blocked":
            return e["command"]
    pytest.skip("no committed attack row blocks as the echo tool's text")   # pragma: no cover


def test_real_mcp_two_concurrent_calls_each_carry_their_own_scan(mcp_server):
    """Each tools/call POST that left the process carries the scan of ITS OWN
    arguments: the header on the wire names a view, the view names a scan, and
    that scan's event hashed the arguments the POST carried. The second call is
    one a block sensor refuses, so the two scans differ in found."""
    from xaidr.sensor import _canonical_arguments

    rec, sink = _Numbered(), _Sink()
    s = Sensor(agent_id="mcp-bind", reporter=sink, extensions=[rec])
    xaidr.protect(sensor=s, targets=["mcp", "httpx"], quiet=True)
    wire = []
    _call_tools(mcp_server, [("echo", {"text": "first plain text"}),
                             ("echo", {"text": _echo_text_a_block_sensor_refuses()})],
                wire=wire)
    assert len(wire) == 2, f"expected two tools/call POSTs on the wire, saw {len(wire)}"
    by_id = {e["scanId"]: e for e in _tool_events(s, sink)}
    assert len(by_id) == 2
    for header, args in wire:
        view = rec.views[int(header)]
        tool = _tool_scan(view)
        assert tool is not None, "a tools/call POST left with no tool-call scan"
        assert by_id[tool.scan_id]["promptHash"] == safe_content_hash(_canonical_arguments(args)), (
            "two calls to one tool exchanged attestations")
    assert {_tool_scan(rec.views[int(h)]).found for h, _ in wire} == {"allowed", "blocked"}
    assert len(s._pending_tool_calls) == 0, "an entry was left unconsumed"
