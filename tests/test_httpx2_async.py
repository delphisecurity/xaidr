"""httpx2 async egress: the httpx ``AsyncClient.send`` contract, including cancellation.

The async wrapper runs the same synchronous ``before`` as the sync one, in the
awaiting task and BEFORE the first await: the destination check, the scan of the
request's own bytes, the B2 ``take`` from the tool-call table, and the S14
headers written onto that request object. So a send cancelled at any point after
it started has consumed its table entry and written headers only to its own
request object: a later request carries its own scan and its own header. (That
same object sent again carries the headers it already has, under the add-only
rule, as on httpx.)

A send cancelled BEFORE it starts has done none of that, so the tool-call entry
its call recorded stays in the table, and under Q14 (oldest binds, 300 s) the
next identical call's POST takes it. That holds on httpx and httpx2 alike, and
changing it is a change to the MCP ``call_tool`` seam or to Q14, which both MCP
lines share; ``test_a_call_whose_send_never_started_lends_its_entry`` records it
as a strict xfail.

Parametrised over ``httpx`` and ``httpx2``; a family skips only where its
package is not installed. Inputs: committed corpus rows and plain benign text.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os

import pytest

import xaidr
from xaidr import DelphiBlockedError, Sensor, SensorExtension
from xaidr.autopatch import exempt
from xaidr.types import safe_content_hash

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHELL = os.path.join(ROOT, "tests", "fixtures", "shell_corpus.json")
ASI = os.path.join(ROOT, "asi_battery", "attacks.jsonl")
URL = "https://h.example/agents/peer/x"
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


@pytest.fixture(params=FAMILIES)
def hx(request):
    return pytest.importorskip(request.param)


@pytest.fixture(autouse=True)
def _unprotect_after():
    yield
    xaidr.unprotect()


def _sensor(extensions=(), **kw):
    sink = _Sink()
    s = Sensor(agent_id="httpx2-async", reporter=sink, extensions=list(extensions), **kw)
    return s, sink


def _protect(sensor, hx):
    return xaidr.protect(sensor=sensor, targets=[hx.__name__], quiet=True)


def _events(sensor, sink, direction):
    sensor.flush()
    return [e["data"] for e in sink.events if e["data"].get("direction") == direction]


def _b64u_sha256(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _rpc(name, args, rid=1):
    return {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
            "params": {"name": name, "arguments": args}}


def _tool_scan(view):
    tool = [sc for sc in view.scans if sc.direction == "tool_call"]
    return tool[0] if tool else None


def _benign_texts(n):
    with open(SHELL, encoding="utf-8") as fh:
        return [e["text"] for e in json.load(fh)["benign_prose"][:n]]


def _a2a_blocked_text():
    if not os.path.isfile(ASI):
        pytest.skip("asi_battery/ is not in the sdist")
    probe = Sensor(agent_id="probe", enforcement_mode="block", reporter=_Sink())
    with open(ASI, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            if row["boundary"] in ("input", "a2a") and \
                    probe.scan_a2a(row["text"], destination="peer").action == "blocked":
                return row["text"]
    pytest.skip("no committed battery row blocks on the a2a path")   # pragma: no cover


# ── the contract, async ──────────────────────────────────────────────────────

def test_an_async_post_is_scanned_then_attested_then_sent(hx):
    rec = _Numbered()
    s, sink = _sensor([rec])
    _protect(s, hx)
    wire = []

    async def handler(request):
        wire.append((dict(request.headers), await request.aread()))
        return hx.Response(200, json={})

    async def go():
        async with hx.AsyncClient(transport=hx.MockTransport(handler)) as c:
            await c.post(URL, json={"message": "hello there friend"})
    asyncio.run(go())
    a2a = _events(s, sink, "a2a")
    assert len(a2a) == 1, (
        f"an async {hx.__name__} POST under protect() produced {len(a2a)} a2a scan events, "
        "not 1: its body was not scanned at egress")
    assert wire[0][0].get("x-delphi-attestation") == "0", "the S14 header did not reach the wire"
    assert rec.views[0].body_sha256 == _b64u_sha256(wire[0][1])
    assert [sc.scan_id for sc in rec.views[0].scans] == [a2a[0]["scanId"]]


def test_concurrent_async_sends_each_carry_their_own_scan(hx):
    """Eight sends in eight tasks at once, each yielding inside the transport so
    they interleave: every request's header names the view of the scan whose
    event hashed THAT request's body."""
    texts = _benign_texts(8)
    rec = _Numbered()
    s, sink = _sensor([rec])
    _protect(s, hx)
    wire = []

    async def handler(request):
        await asyncio.sleep(0)
        wire.append((request.headers.get("x-delphi-attestation"),
                     json.loads(await request.aread())["message"]))
        await asyncio.sleep(0)
        return hx.Response(200, json={})

    async def go():
        async with hx.AsyncClient(transport=hx.MockTransport(handler)) as c:
            await asyncio.gather(*(c.post(URL, json={"message": t}) for t in texts))
    asyncio.run(go())
    by_id = {e["scanId"]: e for e in _events(s, sink, "a2a")}
    assert len(wire) == 8 and len(by_id) == 8, (
        f"eight concurrent async {hx.__name__} sends produced {len(by_id)} scans and "
        f"{len(wire)} requests on the wire, not eight each")
    for header, text in wire:
        view = rec.views[int(header)]
        assert by_id[view.scans[0].scan_id]["promptHash"] == safe_content_hash(text), (
            "request i carried the scan of request j's body")


def test_an_async_redirect_is_one_scan_and_one_attestation(hx):
    rec = _Numbered()
    s, sink = _sensor([rec])
    _protect(s, hx)
    hops = []

    async def handler(request):
        hops.append(request.headers.get("x-delphi-attestation"))
        if request.url.path.endswith("/x"):
            return hx.Response(307, headers={"location": "https://h.example/agents/peer/y"})
        return hx.Response(200, json={})

    async def go():
        async with hx.AsyncClient(transport=hx.MockTransport(handler), follow_redirects=True) as c:
            await c.post(URL, json={"message": "hello there friend"})
    asyncio.run(go())
    scans, views = len(_events(s, sink, "a2a")), len(rec.views)
    assert (scans, views) == (1, 1), (
        f"one async {hx.__name__} send across a redirect was scanned {scans} times and "
        f"attested {views} times; it must be exactly once each")
    assert hops == ["0", "0"], "a redirect hop left without the attestation the send carried"


def test_an_async_refused_body_never_reaches_the_transport(hx):
    text = _a2a_blocked_text()
    rec = _Numbered()
    s, _ = _sensor([rec], enforcement_mode="block")
    _protect(s, hx)
    reached = []

    async def handler(request):
        reached.append(1)
        return hx.Response(200, json={})

    async def go():
        async with hx.AsyncClient(transport=hx.MockTransport(handler)) as c:
            await c.post(URL, json={"message": text})
    with pytest.raises(DelphiBlockedError):
        asyncio.run(go())
    assert reached == [] and rec.views == [], (
        f"an async {hx.__name__} body a block sensor refuses reached the transport")


def test_an_async_exempt_client_is_not_scanned(hx):
    s, sink = _sensor()
    _protect(s, hx)

    async def go():
        async with exempt(hx.AsyncClient(transport=hx.MockTransport(
                lambda r: hx.Response(200, json={})))) as c:
            await c.post(URL, json={"message": "hello there friend"})
    asyncio.run(go())
    assert _events(s, sink, "a2a") == [], f"an exempt async {hx.__name__} client was scanned"


# ── cancellation ─────────────────────────────────────────────────────────────

def test_a_send_cancelled_in_flight_leaves_no_entry_and_no_header_for_a_later_request(hx):
    """A tools/call POST is cancelled while the transport holds it. Its pending
    tool-call entry is gone (it was taken before the first await), and a later
    POST for the same tool and arguments carries the scan of ITS OWN call and a
    header of its own, never the cancelled send's."""
    rec = _Numbered()
    s, _ = _sensor([rec])
    _protect(s, hx)
    wire = []
    hold = {"on": True}

    async def handler(request):
        wire.append(request.headers.get("x-delphi-attestation"))
        if hold["on"]:
            await asyncio.Event().wait()          # in flight until cancelled
        return hx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    async def go():
        first = s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
        assert len(s._pending_tool_calls) == 1
        async with hx.AsyncClient(transport=hx.MockTransport(handler)) as c:
            task = asyncio.create_task(c.post(URL, json=_rpc("get_ticket", {"ticket_id": "T-1"})))
            while not wire:
                await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            left = len(s._pending_tool_calls)
            hold["on"] = False
            second = s.scan_tool_call("get_ticket", {"ticket_id": "T-1"})
            await c.post(URL, json=_rpc("get_ticket", {"ticket_id": "T-1"}))
        return first, second, left

    first, second, left = asyncio.run(go())
    assert left == 0, (
        f"a {hx.__name__} send cancelled in flight left {left} tool-call entr(ies) in the "
        "table: a later request for the same call would carry the cancelled call's scan")
    assert len(wire) == 2 and wire[0] != wire[1], (
        "the later request left with the cancelled send's attestation header")
    later = _tool_scan(rec.views[int(wire[1])])
    assert later is not None and later.scan_id == second.scan_id != first.scan_id, (
        "the later request carried the cancelled send's tool-call scan, not its own")
    assert len(s._pending_tool_calls) == 0


def test_a_send_cancelled_at_any_point_is_all_or_nothing(hx):
    """Cancelled after ``ticks`` event-loop turns, a send has either not started
    (no view, no header written, its entry still pending) or has taken its entry
    and written its header in one step: never one without the other, never a
    header on a request object other than its own. Both outcomes must be seen
    across the sweep, so a seam that never runs cannot pass it."""

    async def handler(request):
        if b"tools/call" in await request.aread():
            await asyncio.Event().wait()      # the tools/call send is held until cancelled
        return hx.Response(200, json={})

    async def once(s, ticks):
        s.scan_tool_call("get_ticket", {"ticket_id": "T-9"})
        async with hx.AsyncClient(transport=hx.MockTransport(handler)) as c:
            req = c.build_request("POST", URL, json=_rpc("get_ticket", {"ticket_id": "T-9"}))
            task = asyncio.create_task(c.send(req))
            for _ in range(ticks):
                await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            other = c.build_request("POST", URL, json={"message": "an unrelated request"})
            await c.send(other)
        return req, other

    seen = set()
    for ticks in range(0, 8):
        rec = _Numbered()
        s, _ = _sensor([rec])
        _protect(s, hx)
        req, other = asyncio.run(once(s, ticks))
        xaidr.unprotect()
        cancelled_views = len(rec.views) - 1          # the unrelated send made the last one
        outcome = (cancelled_views, len(s._pending_tool_calls),
                   "x-delphi-attestation" in req.headers)
        assert outcome in {(0, 1, False), (1, 0, True)}, (
            f"cancelled after {ticks} turns: views={outcome[0]} pending={outcome[1]} "
            f"stamped={outcome[2]} — the entry was taken without its header, or the header "
            "written while the entry stayed bindable")
        later = rec.views[-1]
        assert other.headers.get("x-delphi-attestation") == str(len(rec.views) - 1) and \
            all(sc.direction != "tool_call" for sc in later.scans), (
            "the unrelated request after the cancelled send carried the cancelled send's header "
            "or its tool-call scan")
        seen.add(outcome)
    assert seen == {(0, 1, False), (1, 0, True)}, (
        f"the sweep saw only {sorted(seen)}: no cancelled {hx.__name__} send ever got as far as "
        "its scan and attestation, so nothing was tested")


_SEND_NEVER_STARTED = pytest.mark.xfail(
    strict=True,
    reason="A call whose send is cancelled before it starts keeps its tool-call entry, and "
           "the next identical call's POST takes it (Q14: oldest binds, 300 s). Same on httpx "
           "and httpx2; it is the MCP call_tool seam or Q14, shared by both MCP lines.")


@_SEND_NEVER_STARTED
def test_a_call_whose_send_never_started_lends_its_entry(hx):
    rec = _Numbered()
    s, _ = _sensor([rec])
    _protect(s, hx)

    async def handler(request):
        return hx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    async def go():
        first = s.scan_tool_call("get_ticket", {"ticket_id": "T-3"})
        async with hx.AsyncClient(transport=hx.MockTransport(handler)) as c:
            task = asyncio.create_task(c.post(URL, json=_rpc("get_ticket", {"ticket_id": "T-3"})))
            task.cancel()                         # before the send starts
            with pytest.raises(asyncio.CancelledError):
                await task
            second = s.scan_tool_call("get_ticket", {"ticket_id": "T-3"})
            await c.post(URL, json=_rpc("get_ticket", {"ticket_id": "T-3"}))
        return first, second

    first, second = asyncio.run(go())
    bound = _tool_scan(rec.views[-1])
    assert bound.scan_id == second.scan_id, (
        f"the later {hx.__name__} POST carried the scan of a call whose send never started "
        f"(it took {'that' if bound.scan_id == first.scan_id else 'another'} call's entry), "
        "not its own")
