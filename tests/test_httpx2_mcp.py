"""S14 on httpx2 and the MCP 2.x ``tools/call`` binding (B2), under Q2, Q12 and Q14.

An MCP 2.x client sends every message over ``httpx2``. A ``tools/call`` POST
leaves from a transport task (``StreamableHTTPTransport._run_request_post``),
not from the task that called ``call_tool`` (measured on mcp 2.3.0), though
mcp 2.x runs that task in the caller's context, so a context value does arrive;
Q2 binds nothing by it, and the fresh-thread case below, where no context
arrives, is the one that shows the binding needs none. The binding
is the per-sensor table, never a context: ``scan_tool_call`` records an entry
keyed by tool name and arguments hash, and the POST whose body names the same
tool and arguments takes the oldest such entry, once (256 entries, 300 s, the
strictest found on ambiguity). A call the host halts records no entry. A
``tools/call`` POST refused on an httpx2 path before it leaves (by its
destination, its own scan, or a fail-closed header seam) drops a matching entry,
the least strict one when found verdicts differ, so the strictest stays for the
request that does leave (Q14) and a refused call never lends its scan. A body
that can only be read by consuming it is not read, so its entry stays.

Faults (Q12): an ``attest_egress`` fault drops that extension's headers, is
logged once, and the request proceeds; under ``fail_closed=("controls",)``
monitor records and proceeds, block refuses before anything is sent.

Parametrised over ``httpx`` and ``httpx2`` where the contract is the seam's.
The real-client cases need ``mcp`` 2.x; they skip on mcp 1.x, which
``tests/test_mcp_egress_binding.py`` drives. Inputs: committed corpus rows and
plain benign arguments. No attack string.
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
import threading
import time

import pytest

import xaidr
from xaidr import DelphiBlockedError, Sensor, SensorExtension
from xaidr.types import safe_content_hash

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHELL = os.path.join(ROOT, "tests", "fixtures", "shell_corpus.json")
URL = "https://mcp.example/mcp"
FAMILIES = ("httpx", "httpx2")


class _Sink:
    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch)

    def close(self):
        pass


class _Numbered(SensorExtension):
    """Returns a header naming the view, so a wire capture joins to its view."""

    name = "numbered-attest"

    def __init__(self):
        self.views = []

    def attest_egress(self, view):
        self.views.append(view)
        return {"x-delphi-attestation": str(len(self.views) - 1)}


class _Raise(SensorExtension):
    name = "raise-attest"

    def attest_egress(self, view):
        raise RuntimeError("signer down")


@pytest.fixture(params=FAMILIES)
def hx(request):
    return pytest.importorskip(request.param)


@pytest.fixture(autouse=True)
def _unprotect_after():
    yield
    xaidr.unprotect()


def _sensor(extensions=(), **kw):
    sink = _Sink()
    s = Sensor(agent_id="mcp2-bind", reporter=sink, extensions=list(extensions), **kw)
    return s, sink


def _protect(sensor, *targets):
    return xaidr.protect(sensor=sensor, targets=list(targets), quiet=True)


def _rpc(name, args, rid=1):
    return {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
            "params": {"name": name, "arguments": args}}


def _tool_scan(view):
    tool = [sc for sc in view.scans if sc.direction == "tool_call"]
    return tool[0] if tool else None


def _tool_events(sensor, sink):
    sensor.flush()
    return [e["data"] for e in sink.events if e["data"].get("direction") == "tool_call"]


def _echo_text_a_block_sensor_refuses():
    """A committed shell-corpus row that the tool path refuses as the echo tool's
    text, so two calls to one tool can differ in found."""
    with open(SHELL, encoding="utf-8") as fh:
        attacks = json.load(fh)["attacks"]
    probe = Sensor(agent_id="probe", enforcement_mode="block", reporter=_Sink())
    for e in attacks:
        if probe.scan_tool_call("echo", {"text": e["command"]}).action == "blocked":
            return e["command"]
    pytest.skip("no committed attack row blocks as the echo tool's text")   # pragma: no cover


# ── the table binds across threads and tasks, by tool name and arguments ─────

def test_a_tools_call_post_from_another_thread_carries_its_tool_call_scan(hx):
    """The scan runs on this thread; the POST leaves from a fresh thread, which
    inherits no context. The binding is the table, so it holds."""
    rec = _Numbered()
    s, sink = _sensor([rec])
    _protect(s, hx.__name__)
    r = s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    wire = []

    def post():
        with hx.Client(transport=hx.MockTransport(
                lambda q: wire.append(q.headers.get("x-delphi-attestation"))
                or hx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}}))) as c:
            c.post(URL, json=_rpc("get_ticket", {"ticket_id": "T-1"}))

    t = threading.Thread(target=post)
    t.start()
    t.join()
    tool = _tool_scan(rec.views[int(wire[0])])
    assert tool is not None and tool.scan_id == r.scan_id == _tool_events(s, sink)[0]["scanId"], (
        f"a tools/call POST over {hx.__name__} from another thread did not carry the "
        "tool-call scan that authorised it")
    assert len(s._pending_tool_calls) == 0


def test_two_async_posts_for_one_tool_each_carry_their_own_scan(hx):
    rec = _Numbered()
    s, _ = _sensor([rec])
    _protect(s, hx.__name__)
    r1 = s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    r2 = s.scan_tool_call("get_ticket", {"ticket_id": "T-2"})
    wire = {}

    async def handler(q):
        await asyncio.sleep(0)
        wire[json.loads(await q.aread())["params"]["arguments"]["ticket_id"]] = \
            q.headers.get("x-delphi-attestation")
        return hx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    async def go():
        async with hx.AsyncClient(transport=hx.MockTransport(handler)) as c:
            await asyncio.gather(c.post(URL, json=_rpc("get_ticket", {"ticket_id": "T-2"})),
                                 c.post(URL, json=_rpc("get_ticket", {"ticket_id": "T-1"})))
    asyncio.run(go())
    got = {k: _tool_scan(rec.views[int(v)]).scan_id for k, v in wire.items()}
    assert got == {"T-1": r1.scan_id, "T-2": r2.scan_id}, "two calls to one tool exchanged attestations"


# ── a refused tools/call POST takes its entry with it (httpx2) ───────────────

_HTTPX_KEEPS = pytest.mark.xfail(
    strict=True,
    reason="On httpx a tools/call POST refused before it leaves (at the send seam, or in a "
           "protect_http verb) keeps its tool-call entry pending, and the next identical POST "
           "binds it; the httpx2 paths drop it with the refusal. The httpx path keeps its "
           "1.22.0 behaviour here until that is ruled.")


def _refused_family(name):
    return pytest.param(name, marks=_HTTPX_KEEPS) if name == "httpx" else name


@pytest.mark.parametrize("family", [_refused_family(f) for f in FAMILIES])
@pytest.mark.parametrize("mode", ["block", "monitor"])
def test_a_tools_call_post_refused_at_its_destination_never_lends_its_scan(family, mode):
    hx = pytest.importorskip(family)
    rec = _Numbered()
    s, _ = _sensor([rec], enforcement_mode=mode)
    s.block_urls(["denied.example"])
    _protect(s, family)
    refused = s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    with hx.Client(transport=hx.MockTransport(
            lambda q: hx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}}))) as c:
        with pytest.raises(DelphiBlockedError):
            c.post("https://denied.example/mcp", json=_rpc("get_ticket", {"ticket_id": "T-1"}))
        left = len(s._pending_tool_calls)
        own = s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
        c.post(URL, json=_rpc("get_ticket", {"ticket_id": "T-1"}))
    bound = _tool_scan(rec.views[-1])
    assert left == 0 and bound.scan_id == own.scan_id != refused.scan_id, (
        f"a tools/call POST refused over {family} ({mode}) left its entry pending "
        f"({left}); the next identical POST carried the REFUSED call's scan")


@pytest.mark.parametrize("family", [_refused_family(f) for f in FAMILIES])
def test_protect_http_refusing_a_tools_call_never_lends_its_scan(family):
    hx = pytest.importorskip(family)
    rec = _Numbered()
    s, _ = _sensor([rec], enforcement_mode="block")
    s.block_urls(["denied.example"])
    refused = s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    client = s.protect_http(hx.Client(transport=hx.MockTransport(
        lambda q: hx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}}))))
    with pytest.raises(DelphiBlockedError):
        client.post("https://denied.example/mcp", json=_rpc("get_ticket", {"ticket_id": "T-1"}))
    own = s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    client.post(URL, json=_rpc("get_ticket", {"ticket_id": "T-1"}))
    bound = _tool_scan(rec.views[-1])
    assert bound.scan_id == own.scan_id != refused.scan_id, (
        f"protect_http over {family} refused a tools/call and the next identical POST "
        "carried the REFUSED call's scan")


def test_a_refused_post_drops_only_its_own_call(hx):
    """The refusal drops the entry of ITS tool and arguments, nothing else: the
    other call's entry is the OLDER one, so a drop keyed by tool name alone
    would take it."""
    rec = _Numbered()
    s, _ = _sensor([rec], enforcement_mode="block")
    s.block_urls(["denied.example"])
    _protect(s, hx.__name__)
    other = s.scan_tool_call("get_ticket", {"ticket_id": "T-2"})
    s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    with hx.Client(transport=hx.MockTransport(lambda q: hx.Response(200, json={}))) as c:
        with pytest.raises(DelphiBlockedError):
            c.post("https://denied.example/mcp", json=_rpc("get_ticket", {"ticket_id": "T-1"}))
        c.post(URL, json=_rpc("get_ticket", {"ticket_id": "T-2"}))
    bound = _tool_scan(rec.views[-1])
    assert bound is not None and bound.scan_id == other.scan_id, (
        f"a refused {hx.__name__} tools/call dropped ANOTHER call's entry: the T-2 POST left "
        "without its own tool-call scan")


def _view(found, scan_id):
    from xaidr.extensions import ScanView
    return ScanView(scan_id=scan_id, direction="tool_call", found=found, enforced=found,
                    rules=(), category=None, impact_class=None, value_origin=None,
                    parent_scan_id=None)


def test_a_refusal_keeps_the_strictest_entry_for_the_request_that_leaves():
    """Q14: when two pending entries match one body and their found verdicts
    differ, the strictest binds the request that leaves. A refusal of the first
    POST drops the LEAST strict, so the one that leaves still attests the
    strictest."""
    hx = pytest.importorskip("httpx2")
    from xaidr.sensor import _args_key
    rec = _Numbered()
    s, _ = _sensor([rec], enforcement_mode="block")
    s.block_urls(["denied.example"])
    _protect(s, "httpx2")
    key = _args_key({"ticket_id": "T-1"})
    s._pending_tool_calls.record("get_ticket", key, _view("allowed", "lenient"))
    s._pending_tool_calls.record("get_ticket", key, _view("blocked", "strict"))
    with hx.Client(transport=hx.MockTransport(lambda q: hx.Response(200, json={}))) as c:
        with pytest.raises(DelphiBlockedError):
            c.post("https://denied.example/mcp", json=_rpc("get_ticket", {"ticket_id": "T-1"}))
        c.post(URL, json=_rpc("get_ticket", {"ticket_id": "T-1"}))
    bound = _tool_scan(rec.views[-1])
    assert bound.scan_id == "strict" and bound.found == "blocked", (
        f"the refusal dropped the strictest entry, so the POST that left attested "
        f"found={bound.found!r}: Q14 binds the strictest")


class _FailingHeaders(SensorExtension):
    """Attests, and raises in the S12 header hook: a fail-closed refusal in
    ``protect_http`` lands after the scan and before the attestation."""

    name = "failing-headers"

    def __init__(self):
        self.views = []

    def outbound_headers(self, dest):
        raise RuntimeError("header backend down")

    def attest_egress(self, view):
        self.views.append(view)
        return {"x-delphi-attestation": str(len(self.views) - 1)}


@pytest.mark.parametrize("family", [_refused_family(f) for f in FAMILIES])
def test_a_fail_closed_header_refusal_in_protect_http_never_lends_its_scan(family):
    hx = pytest.importorskip(family)
    ext = _FailingHeaders()
    s, _ = _sensor([ext], enforcement_mode="block", fail_closed=("controls",))
    refused = s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    transport = hx.MockTransport(lambda q: hx.Response(200, json={}))
    with pytest.raises(DelphiBlockedError):
        s.protect_http(hx.Client(transport=transport)).post(
            URL, json=_rpc("get_ticket", {"ticket_id": "T-1"}))
    own = s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    _protect(s, family)
    with hx.Client(transport=transport) as c:
        c.post(URL, json=_rpc("get_ticket", {"ticket_id": "T-1"}))
    bound = _tool_scan(ext.views[-1])
    assert bound.scan_id == own.scan_id != refused.scan_id, (
        f"protect_http over {family} refused a tools/call on a fail-closed header fault and "
        "the next identical POST carried the REFUSED call's scan")


@pytest.mark.parametrize("family", [_refused_family(f) for f in FAMILIES])
def test_protect_http_refusing_a_data_bytes_tools_call_never_lends_its_scan(family):
    hx = pytest.importorskip(family)
    rec = _Numbered()
    s, _ = _sensor([rec], enforcement_mode="block")
    s.block_urls(["denied.example"])
    refused = s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    client = s.protect_http(hx.Client(transport=hx.MockTransport(
        lambda q: hx.Response(200, json={}))))
    body = json.dumps(_rpc("get_ticket", {"ticket_id": "T-1"})).encode()
    with pytest.raises(DelphiBlockedError):
        client.post("https://denied.example/mcp", data=body)
    own = s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
    client.post(URL, json=_rpc("get_ticket", {"ticket_id": "T-1"}))
    bound = _tool_scan(rec.views[-1])
    assert bound.scan_id == own.scan_id != refused.scan_id, (
        f"protect_http over {family} refused a data= tools/call and the next identical POST "
        "carried the REFUSED call's scan")


# ── faults (Q12) at the httpx2 seam ──────────────────────────────────────────

def test_an_attest_fault_drops_the_header_logs_once_and_the_request_proceeds(hx, caplog):
    s, _ = _sensor([_Raise()])
    _protect(s, hx.__name__)
    sent = []
    with caplog.at_level(logging.ERROR, logger="xaidr"):
        with hx.Client(transport=hx.MockTransport(
                lambda q: sent.append(dict(q.headers)) or hx.Response(200, json={}))) as c:
            for _ in range(3):
                c.post(URL, json={"message": "hello there friend"})
    assert len(sent) == 3, f"an attest_egress fault failed the host's {hx.__name__} request"
    assert all("x-delphi-attestation" not in h for h in sent)
    logged = [r for r in caplog.records if "attest_egress" in r.getMessage()]
    assert len(logged) == 1, f"the fault was logged {len(logged)} times, not once"


def test_fail_closed_controls_monitor_proceeds_and_records(hx):
    s, sink = _sensor([_Raise()], fail_closed=("controls",))
    _protect(s, hx.__name__)
    sent = []
    with hx.Client(transport=hx.MockTransport(
            lambda q: sent.append(1) or hx.Response(200, json={}))) as c:
        c.post(URL, json={"message": "hello there friend"})
    s.flush()
    assert sent == [1], "a monitor sensor refused the request on a hook fault"
    assert any(e["data"].get("inputStatus") == "fail_closed" or e["data"].get("category") == "fail_closed"
               for e in sink.events), "the fail-closed verdict was not recorded"


def test_fail_closed_controls_block_refuses_before_sending(hx):
    s, _ = _sensor([_Raise()], fail_closed=("controls",), enforcement_mode="block")
    _protect(s, hx.__name__)
    sent = []
    with hx.Client(transport=hx.MockTransport(
            lambda q: sent.append(1) or hx.Response(200, json={}))) as c:
        with pytest.raises(DelphiBlockedError):
            c.post(URL, json={"message": "hello there friend"})
    assert sent == [], f"a fail-closed block sensor sent the {hx.__name__} request it refused"


# ── a real MCP 2.x client against a local streamable-HTTP server ─────────────

_SERVER = r'''
import sys
from mcp.server.mcpserver import MCPServer
m = MCPServer("probe")
@m.tool()
def echo(text: str) -> str:
    return text
m.run(transport="streamable-http", host="127.0.0.1", port=int(sys.argv[1]))
'''


def _mcp_major():
    try:
        return int(_md.version("mcp").split(".")[0])
    except Exception:
        return None


@pytest.fixture(scope="module")
def mcp2_server():
    pytest.importorskip("mcp")
    pytest.importorskip("httpx2")
    if (_mcp_major() or 0) < 2:
        pytest.skip("drives the mcp 2.x API; mcp 1.x is tests/test_mcp_egress_binding.py")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    proc = subprocess.Popen([sys.executable, "-c", _SERVER, str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(300):
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
    """Run ``calls`` concurrently over one real mcp 2.x session. ``wire`` collects
    (attestation header, tools/call arguments) per POST that left, read by a
    request hook on the httpx2 client the transport uses."""
    import httpx2
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

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

    async def go():
        async with httpx2.AsyncClient(event_hooks={"request": [on_request]}) as client:
            async with streamable_http_client(url, http_client=client) as (r, w):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    return await asyncio.gather(*(session.call_tool(n, a) for n, a in calls))
    return asyncio.run(go())


def test_real_mcp2_call_tool_binds_the_tool_call_scan(mcp2_server):
    rec = _Numbered()
    s, sink = _sensor([rec])
    _protect(s, "mcp", "httpx2")
    wire = []
    results = _call_tools(mcp2_server, [("echo", {"text": "hello there"})], wire=wire)
    assert results[0].content[0].text == "hello there"
    assert len(wire) == 1, f"expected one tools/call POST on the wire, saw {len(wire)}"
    tool = _tool_scan(rec.views[int(wire[0][0])])
    events = _tool_events(s, sink)
    assert tool is not None, "the mcp 2.x tools/call POST left with no tool-call scan"
    assert len(events) == 1 and tool.scan_id == events[0]["scanId"]
    assert tool.found == "allowed" and rec.views[int(wire[0][0])].method == "POST"
    assert len(s._pending_tool_calls) == 0, "an entry was left unconsumed"


def test_real_mcp2_two_concurrent_calls_each_carry_their_own_scan(mcp2_server):
    """Each tools/call POST carries the scan of ITS OWN arguments; the second call
    is a committed row a block sensor refuses, so the two found verdicts differ."""
    from xaidr.sensor import _canonical_arguments

    rec = _Numbered()
    s, sink = _sensor([rec])
    _protect(s, "mcp", "httpx2")
    wire = []
    _call_tools(mcp2_server, [("echo", {"text": "first plain text"}),
                              ("echo", {"text": _echo_text_a_block_sensor_refuses()})], wire=wire)
    assert len(wire) == 2, f"expected two tools/call POSTs on the wire, saw {len(wire)}"
    by_id = {e["scanId"]: e for e in _tool_events(s, sink)}
    assert len(by_id) == 2
    for header, args in wire:
        tool = _tool_scan(rec.views[int(header)])
        assert tool is not None, "a tools/call POST left with no tool-call scan"
        assert by_id[tool.scan_id]["promptHash"] == safe_content_hash(_canonical_arguments(args)), (
            "two calls to one tool exchanged attestations")
    assert {_tool_scan(rec.views[int(h)]).found for h, _ in wire} == {"allowed", "blocked"}
    assert len(s._pending_tool_calls) == 0, "an entry was left unconsumed"


def test_real_mcp2_a_halted_call_records_nothing_and_never_binds(mcp2_server):
    """Block mode: the refused call is answered in band and never POSTed, and it
    leaves no entry, so the next call's POST carries its own scan."""
    rec = _Numbered()
    s, sink = _sensor([rec], enforcement_mode="block")
    _protect(s, "mcp", "httpx2")
    wire = []
    refused, = _call_tools(mcp2_server, [("echo", {"text": _echo_text_a_block_sensor_refuses()})],
                           wire=wire)
    assert refused.is_error and wire == [], "a halted call reached the server"
    assert len(s._pending_tool_calls) == 0, "a halted call left an entry that a later POST could bind"
    _call_tools(mcp2_server, [("echo", {"text": "hello there"})], wire=wire)
    events = _tool_events(s, sink)
    assert len(wire) == 1 and _tool_scan(rec.views[int(wire[0][0])]).scan_id == events[-1]["scanId"]


def test_real_mcp2_an_attest_fault_never_fails_the_call(mcp2_server):
    s, _ = _sensor([_Raise()])
    _protect(s, "mcp", "httpx2")
    wire = []
    results = _call_tools(mcp2_server, [("echo", {"text": "hello there"})], wire=wire)
    assert results[0].content[0].text == "hello there", "an attest_egress fault failed the MCP call"
    assert wire and wire[0][0] is None
