"""httpx2 streams, responses, redirects and the header bound — the httpx path's rules.

* A generator or async-generator body is never read by the seam: the transport
  receives it untouched, it is not scanned and not named by a digest, and the
  destination check still runs. ``protect_http`` does the same.
* A ``stream=True`` response is never read by the seam; the caller reads it.
* A redirect followed inside one ``send`` is one scan and one attestation. A
  redirect an SDK follows by hand (MCP 2.x does) on a plain client is a new
  client-level send: its body is an unread stream, so it is not scanned or named,
  and the attestation headers copied from the first hop stay on it under the
  add-only rule. Through ``protect_http`` the copied request also carries the
  first hop's ``EgressMark``, so the seam neither attests that hop nor scans its
  response; ``test_a_hand_followed_hop_through_protect_http_is_scanned`` records
  that as a strict xfail (the marker is shared with httpx).
* An attestation header value is at most 10,923 characters (Core's bound): a
  value at the bound is sent, one past it drops that extension's headers and the
  request proceeds. The drop is logged once per extension per sensor, and a
  redirect's dropped duplicate header uses the same once; a strict xfail records
  that the later drop is then not logged (shared with httpx).

Parametrised over ``httpx`` and ``httpx2``; a family skips only where its
package is not installed. Inputs: plain benign text only.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

import xaidr
from xaidr import DelphiBlockedError, Sensor, SensorExtension
from xaidr import attestation as _att

URL = "https://h.example/agents/peer/x"
FAMILIES = ("httpx", "httpx2")


class _Sink:
    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch)

    def close(self):
        pass


class _Record(SensorExtension):
    name = "record-attest"

    def __init__(self, headers=None):
        self.views = []
        self._headers = headers if headers is not None else {"x-delphi-attestation": "demo"}

    def attest_egress(self, view):
        self.views.append(view)
        return dict(self._headers)


class _Numbered(_Record):
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
    s = Sensor(agent_id="httpx2-streams", reporter=sink, extensions=list(extensions), **kw)
    return s, sink


def _protect(sensor, hx):
    return xaidr.protect(sensor=sensor, targets=[hx.__name__], quiet=True)


def _events(sensor, sink, direction):
    sensor.flush()
    return [e["data"] for e in sink.events if e["data"].get("direction") == direction]


def _generator(consumed):
    def gen():
        consumed.append("first")
        yield b'{"message": "hello there, '
        consumed.append("second")
        yield b'a plain streamed body"}'
    return gen()


def _entry_transport(hx, consumed, at_entry):
    """A transport that records how much of the body was read BEFORE it was
    handed over (MockTransport reads the body first, so it cannot tell)."""
    class _Entry(hx.BaseTransport):
        def handle_request(self, request):
            at_entry.append(list(consumed))
            body = b"".join(request.stream)
            return hx.Response(200, json={"len": len(body)})
    return _Entry()


def _async_entry_transport(hx, consumed, at_entry):
    class _Entry(hx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            at_entry.append(list(consumed))
            body = b"".join([chunk async for chunk in request.stream])
            return hx.Response(200, json={"len": len(body)})
    return _Entry()


# ── non-replayable bodies ────────────────────────────────────────────────────

def test_a_generator_body_reaches_the_transport_untouched(hx):
    rec = _Record()
    s, sink = _sensor([rec])
    _protect(s, hx)
    consumed, at_entry = [], []
    with hx.Client(transport=_entry_transport(hx, consumed, at_entry)) as c:
        r = c.post(URL, content=_generator(consumed))
    assert at_entry == [[]], (
        f"the {hx.__name__} send seam read {at_entry[0]} of a generator body before the "
        "transport did: the body was consumed by the seam instead of streamed by the client")
    assert r.json()["len"] > 0 and consumed == ["first", "second"]
    assert _events(s, sink, "a2a") == [], "a generator body was scanned (it can only be read once)"
    assert len(rec.views) == 1 and rec.views[0].body_sha256 is None and rec.views[0].scans == (), (
        "a generator body was named by a digest of bytes the seam never read")


def test_an_async_generator_body_reaches_the_transport_untouched(hx):
    rec = _Record()
    s, sink = _sensor([rec])
    _protect(s, hx)
    consumed, at_entry = [], []

    async def agen():
        consumed.append("first")
        yield b"hello there, "
        consumed.append("second")
        yield b"a plain streamed body"

    async def go():
        async with hx.AsyncClient(transport=_async_entry_transport(hx, consumed, at_entry)) as c:
            await c.post(URL, content=agen())
    asyncio.run(go())
    assert at_entry == [[]], (
        f"the async {hx.__name__} send seam read {at_entry[0]} of an async generator body")
    assert consumed == ["first", "second"]
    assert _events(s, sink, "a2a") == [] and rec.views[0].body_sha256 is None


def test_a_generator_body_to_a_denied_destination_is_refused_unread(hx):
    s, _ = _sensor(enforcement_mode="block")
    s.block_urls(["denied.example"])
    _protect(s, hx)
    consumed, reached = [], []
    with hx.Client(transport=hx.MockTransport(lambda r: reached.append(1) or hx.Response(200))) as c:
        with pytest.raises(DelphiBlockedError):
            c.post("https://denied.example/x", content=_generator(consumed))
    assert reached == [] and consumed == [], (
        "a request with a generator body went to a denied destination, or was read to refuse it")


def test_protect_http_never_reads_a_generator_body(hx):
    rec = _Record()
    s, _ = _sensor([rec])
    consumed, at_entry = [], []
    s.protect_http(hx.Client(transport=_entry_transport(hx, consumed, at_entry))).post(
        URL, content=_generator(consumed))
    assert at_entry == [[]], f"protect_http over {hx.__name__} read a generator body before sending it"
    assert rec.views[0].body_sha256 is None


# ── responses ────────────────────────────────────────────────────────────────

def test_a_streamed_response_is_left_to_the_caller(hx):
    s, sink = _sensor()
    _protect(s, hx)
    chunks = [b'{"message": "hello there, ', b'a streamed answer"}']

    def handler(request):
        return hx.Response(200, content=iter(chunks))

    with hx.Client(transport=hx.MockTransport(handler)) as c:
        with c.stream("GET", URL) as r:
            assert not r.is_stream_consumed, "the send seam read a streamed response"
            got = b"".join(r.iter_bytes())
    assert got == b"".join(chunks)
    assert _events(s, sink, "output") == [], "a stream=True response was scanned by the seam"


def test_a_plain_response_is_scanned_once(hx):
    s, sink = _sensor()
    _protect(s, hx)
    with hx.Client(transport=hx.MockTransport(
            lambda r: hx.Response(200, json={"message": "hello there, a plain answer"}))) as c:
        c.get(URL)
    out = _events(s, sink, "output")
    assert len(out) == 1, f"a {hx.__name__} response was scanned {len(out)} times, not once"


# ── redirects an SDK follows by hand ─────────────────────────────────────────

def test_a_redirect_followed_by_hand_is_a_new_send_that_keeps_the_first_attestation(hx, caplog):
    """MCP 2.x follows a same-origin 307 itself: ``send(follow_redirects=False)``,
    then ``send(response.next_request)``. The second send is scanned at its own
    seam, but its body is an unread stream (not scanned, not named), and the
    header copied from the first hop stays: the second view's header is dropped
    under add-only and the drop is logged once."""
    rec = _Numbered()
    s, sink = _sensor([rec])
    _protect(s, hx)
    hops = []

    def handler(request):
        hops.append(request.headers.get("x-delphi-attestation"))
        if request.url.path.endswith("/x"):
            return hx.Response(307, headers={"location": "https://h.example/agents/peer/y"})
        return hx.Response(200, json={})

    with caplog.at_level(logging.ERROR, logger="xaidr"):
        with hx.Client(transport=hx.MockTransport(handler)) as c:
            first = c.post(URL, json={"message": "hello there friend"}, follow_redirects=False)
            assert first.status_code == 307
            c.send(first.next_request, follow_redirects=False)
    assert hops == ["0", "0"], f"hops carried {hops}: the hand-followed hop lost the first attestation"
    assert len(rec.views) == 2, f"two client-level sends were attested {len(rec.views)} times"
    assert rec.views[1].body_sha256 is None and rec.views[1].scans == (), (
        "the hand-followed hop's unread stream body was read, scanned or named by a digest")
    assert len(_events(s, sink, "a2a")) == 1, "the hand-followed hop's unread body was scanned"
    drops = [r for r in caplog.records if "attest_egress" in r.getMessage()]
    assert len(drops) == 1, "the dropped duplicate header was not logged exactly once"


# ── the header bound ─────────────────────────────────────────────────────────

def test_a_header_value_at_the_bound_is_sent_and_one_past_it_is_dropped(hx, caplog):
    at = "a" * _att.MAX_HEADER_VALUE
    assert len(at) == 10_923
    for value, kept in ((at, True), (at + "a", False)):
        s, sink = _sensor([_Record({"x-delphi-attestation": value})])
        _protect(s, hx)
        seen = []
        with caplog.at_level(logging.ERROR, logger="xaidr"):
            caplog.clear()
            with hx.Client(transport=hx.MockTransport(
                    lambda r: seen.append(r.headers.get("x-delphi-attestation"))
                    or hx.Response(200, json={}))) as c:
                c.post(URL, json={"message": "hello there friend"})
        xaidr.unprotect()
        assert len(seen) == 1, "the request did not proceed"
        if kept:
            assert seen[0] == value, f"a {len(value)}-character value at the bound was not sent"
        else:
            assert seen[0] is None, (
                f"a {len(value)}-character attestation value, past Core's 10,923 bound, "
                f"left over {hx.__name__}")
            assert any("attest_egress" in r.getMessage() for r in caplog.records), (
                "the over-bound value was dropped silently")


# ── recorded, shared with httpx: found, not changed here ─────────────────────

_SHARED = "the httpx path behaves the same, and changing it changes httpx too"


@pytest.mark.xfail(strict=True, reason="a redirect's dropped duplicate header uses the "
                   "extension's once-per-sensor log, so a later attest_egress fault on the "
                   "same sensor is dropped unlogged; " + _SHARED)
def test_a_redirects_dropped_duplicate_does_not_silence_a_later_fault(hx, caplog):
    rec = _Numbered()
    s, _ = _sensor([rec])
    _protect(s, hx)

    def handler(request):
        if request.url.path.endswith("/x"):
            return hx.Response(307, headers={"location": "https://h.example/agents/peer/y"})
        return hx.Response(200, json={})

    with hx.Client(transport=hx.MockTransport(handler)) as c:
        first = c.post(URL, json={"message": "hello there friend"}, follow_redirects=False)
        c.send(first.next_request, follow_redirects=False)
        rec.attest_egress = lambda view: {"x-delphi-attestation": "a" * (_att.MAX_HEADER_VALUE + 1)}
        with caplog.at_level(logging.ERROR, logger="xaidr"):
            caplog.clear()
            c.post(URL, json={"message": "hello there friend"})
    assert any("attest_egress" in r.getMessage() for r in caplog.records), (
        "an over-bound attestation value was dropped with no log, because a redirect's "
        "duplicate header had already used the extension's one log")


@pytest.mark.xfail(strict=True, reason="the hand-followed hop's request copies the first hop's "
                   "EgressMark, so the seam neither attests it nor scans its response; " + _SHARED)
def test_a_hand_followed_hop_through_protect_http_is_scanned(hx):
    rec = _Numbered()
    s, sink = _sensor([rec])
    _protect(s, hx)

    def handler(request):
        if request.url.path.endswith("/x"):
            return hx.Response(307, headers={"location": "https://h.example/agents/peer/y"})
        return hx.Response(200, json={"message": "hello there, a plain answer"})

    client = s.protect_http(hx.Client(transport=hx.MockTransport(handler)))
    first = client.post(URL, json={"message": "hello there friend"}, follow_redirects=False)
    hops = len(rec.views)
    client._client.send(first.next_request, follow_redirects=False)
    assert len(rec.views) == hops + 1, (
        "the hand-followed hop of a protect_http request left unattested: it carried the "
        "first hop's EgressMark")
