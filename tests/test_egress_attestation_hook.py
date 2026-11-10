"""S14 ``attest_egress``: the view, the bounds, the faults, and zero movement.

The hook runs once per outbound request on every HTTP path xaidr dispatches
(httpx sync and async under ``protect()``, requests under ``protect()``, and
``ProtectedHttpClient``'s five verbs), after the request's own scan and before
it is sent. It returns headers; open adds them under the add-only rule.

Nothing runs when no extension overrides the hook: no view, no digest, no
header. ``test_zero_movement_*`` is the gate for that, and it counts digest
calls because the corpus oracle cannot see an egress path.

A fault drops that extension's headers, is logged once per extension per
sensor, and never fails the host's request unless the operator closed
``controls``. Every check sits inside the ``try``. Bounds: at most 4 headers
per extension, names ``^[a-z0-9-]{1,64}$``, values printable ASCII of at most
10,923 characters (Core's header bound), at most 16 KiB per request.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import threading

import pytest

import xaidr
from xaidr import DelphiBlockedError, Sensor, SensorExtension
from xaidr import attestation as _att
from xaidr.extensions import EgressView, ScanView
from xaidr.types import ScanResult, safe_content_hash

httpx = pytest.importorskip("httpx")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHELL = os.path.join(ROOT, "tests", "fixtures", "shell_corpus.json")
URL = "https://h.example/agents/peer/x"
VERBS = ("post", "put", "patch", "get", "delete")


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
        return dict(self._headers) if isinstance(self._headers, dict) else self._headers


class _Raise(SensorExtension):
    name = "raise-attest"

    def attest_egress(self, view):
        raise RuntimeError("signer down")


class _Base(SensorExtension):
    """Overrides nothing: the base hook must be inert."""

    name = "base"


@pytest.fixture(autouse=True)
def _unprotect_after():
    yield
    xaidr.unprotect()


def _client(sent):
    def handler(request):
        sent.append((request.method, dict(request.headers), request.content))
        return httpx.Response(200, json={})
    return httpx.Client(transport=httpx.MockTransport(handler))


def _sensor(extensions, **kw):
    sink = _Sink()
    s = Sensor(agent_id="attest", reporter=sink, extensions=extensions, **kw)
    return s, sink


def _b64u_sha256(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


# ── the view ─────────────────────────────────────────────────────────────────

def test_view_shape_on_a_body_verb():
    rec = _Record()
    s, _ = _sensor([rec])
    sent = []
    s.protect_http(_client(sent)).post(URL, json={"message": "hello there friend"})
    assert len(rec.views) == 1
    v = rec.views[0]
    assert isinstance(v, EgressView)
    assert v.method == "POST" and v.host == "h.example"
    assert v.mode == "monitor" and v.value_origin_mode == "record"
    assert v.view_version == 1
    assert v.sensor_version == xaidr.__version__
    assert len(v.scans) == 1
    sc = v.scans[0]
    assert isinstance(sc, ScanView)
    assert sc.direction == "a2a"
    assert sc.found in ("allowed", "flagged", "blocked", "held")
    assert sc.enforced in ("allowed", "flagged", "blocked", "held")
    assert isinstance(sc.rules, tuple)
    assert sc.parent_scan_id is None and sc.impact_class is None
    # The digest names the exact bytes the request carried.
    assert v.body_sha256 == _b64u_sha256(sent[0][2])
    # No raw content anywhere on the view.
    assert "hello there" not in repr(v)


@pytest.mark.parametrize("verb", ("get", "delete"))
def test_get_and_delete_attest_with_no_scans(verb):
    rec = _Record()
    s, _ = _sensor([rec])
    sent = []
    getattr(s.protect_http(_client(sent)), verb)(URL)
    assert len(rec.views) == 1
    v = rec.views[0]
    assert v.scans == ()
    assert v.method == verb.upper()
    assert v.body_sha256 == _b64u_sha256(b"")
    assert sent[0][1]["x-delphi-attestation"] == "demo"


def test_the_scan_id_on_the_view_is_the_events():
    rec = _Record()
    s, sink = _sensor([rec])
    s.protect_http(_client([])).post(URL, json={"message": "hello there friend"})
    s.flush()
    ids = [e["data"]["scanId"] for e in sink.events if e["data"].get("direction") == "a2a"]
    assert ids == [rec.views[0].scans[0].scan_id]


def test_value_origin_mode_off_is_reported():
    rec = _Record()
    s, _ = _sensor([rec], value_origin="off")
    s.protect_http(_client([])).post(URL, json={"message": "hello there friend"})
    assert rec.views[0].value_origin_mode == "off"


def test_mode_is_the_policy_in_force_after_s7():
    from xaidr.enforcement import BLOCK

    class _Harden(SensorExtension):
        name = "harden"

        def enforcement_policy(self):
            return BLOCK

    rec = _Record()
    s, _ = _sensor([_Harden(), rec], enforcement_mode="monitor")
    s.protect_http(_client([])).post(URL, json={"message": "hello there friend"})
    assert rec.views[0].mode == "block"


# ── headers: add-only, bounds ────────────────────────────────────────────────

def test_headers_are_added_under_the_add_only_rule():
    rec = _Record({"x-delphi-attestation": "demo", "x-delphi-source-agent": "mallory",
                   "x-caller": "ext"})
    s, _ = _sensor([rec])
    sent = []
    s.protect_http(_client(sent)).post(URL, json={"message": "hello"},
                                       headers={"X-Caller": "mine"})
    h = sent[0][1]
    assert h["x-delphi-attestation"] == "demo"
    assert h["x-delphi-source-agent"] == "attest", "an attest header overwrote the sensor's"
    assert h["x-caller"] == "mine", "an attest header overwrote the caller's"


@pytest.mark.parametrize("bad", [
    "x-delphi-attestation: demo",          # str, truthy, no .items()
    42,
    {1: "v"},
    {"x-ok": 7},
    {"X-Upper": "v"},                      # the S14 name rule is lowercase
    {"x-" + "a" * 70: "v"},                # 64-char name bound
    {"x-ok": "café"},                 # printable ASCII only
    {"x-ok": "a" * 10_924},                # 10,923-char value bound
    {f"x-{i}": "v" for i in range(5)},     # 4 headers per extension
    {"x-ok": "v" * 10_000, "x-ok2": "v" * 7_000},   # 16 KiB per request
], ids=["str", "int", "int-key", "int-value", "upper", "long-name", "non-ascii",
        "long-value", "five", "total"])
def test_a_bad_return_drops_that_extensions_headers_and_the_request_proceeds(bad, caplog):
    other = _Record({"x-other": "ok"})
    s, _ = _sensor([_Record(bad), other])
    sent = []
    with caplog.at_level(logging.ERROR, logger="xaidr.sensor"):
        try:
            s.protect_http(_client(sent)).post(URL, json={"message": "hello there"})
        except Exception as exc:   # pragma: no cover - the defect under test
            pytest.fail(f"a malformed attest_egress return raised {type(exc).__name__} "
                        "into the host's request")
    h = sent[0][1]
    assert not any(k.startswith("x-delphi-attestation") or k == "x-ok" or k == "x-ok2"
                   or k.startswith("x-upper") or k.startswith("x-aaa") or k in
                   {f"x-{i}" for i in range(5)} for k in h), h
    assert h["x-other"] == "ok"
    hits = [r for r in caplog.records if "record-attest" in r.getMessage()
            and "attest_egress" in r.getMessage()]
    assert len(hits) == 1, f"expected one fault line, got {len(hits)}"


def test_a_value_at_the_bound_is_kept():
    rec = _Record({"x-delphi-attestation": "a" * 10_923})
    s, _ = _sensor([rec])
    sent = []
    s.protect_http(_client(sent)).post(URL, json={"message": "hello there"})
    assert len(sent[0][1]["x-delphi-attestation"]) == 10_923


def test_a_raise_is_logged_once_and_the_request_proceeds(caplog):
    s, _ = _sensor([_Raise(), _Record()])
    sent = []
    with caplog.at_level(logging.ERROR, logger="xaidr.sensor"):
        client = s.protect_http(_client(sent))
        for _ in range(3):
            client.post(URL, json={"message": "hello there"})
    assert len(sent) == 3
    assert all(h[1]["x-delphi-attestation"] == "demo" for h in sent)
    hits = [r for r in caplog.records if "raise-attest" in r.getMessage()]
    assert len(hits) == 1


def test_fail_closed_controls_monitor_proceeds_and_records():
    s, sink = _sensor([_Raise()], fail_closed=("controls",))
    sent = []
    s.protect_http(_client(sent)).post(URL, json={"message": "hello there"})
    assert len(sent) == 1
    s.flush()
    fc = [e for e in sink.events if e["data"].get("failClosedGroup") == "controls"]
    assert len(fc) == 1 and fc[0]["data"]["enforcementMode"] == "monitor"


def test_fail_closed_controls_block_refuses_in_band():
    s, _ = _sensor([_Raise()], fail_closed=("controls",), enforcement_mode="block")
    sent = []
    with pytest.raises(DelphiBlockedError) as exc:
        s.protect_http(_client(sent)).post(URL, json={"message": "hello there"})
    assert exc.value.result.action == "blocked"
    assert sent == []


# ── zero movement ────────────────────────────────────────────────────────────

def _headers_per_verb(extensions, monkeypatch=None):
    s, sink = _sensor(extensions)
    sent = []
    client = s.protect_http(_client(sent))
    for verb in ("post", "put", "patch"):
        getattr(client, verb)(URL, json={"message": "hello there friend"})
    client.get(URL)
    client.delete(URL)
    s.flush()
    verdicts = [(e["data"]["action"], e["data"]["score"], e["data"]["category"],
                 tuple(e["data"]["rules"])) for e in sink.events]
    return [(m, sorted(h.items())) for m, h, _ in sent], verdicts


@pytest.mark.parametrize("extensions", [[], [_Base()]], ids=["none", "base"])
def test_zero_movement_no_digest_no_view_identical_headers(extensions, monkeypatch):
    calls = []
    orig = _att._body_sha256
    monkeypatch.setattr(_att, "_body_sha256",
                        lambda data: calls.append(len(data)) or orig(data))
    with_ext, verdicts_ext = _headers_per_verb(extensions)
    bare, verdicts_bare = _headers_per_verb([])
    assert with_ext == bare, "attaching an inert extension changed an outbound header"
    assert verdicts_ext == verdicts_bare
    assert calls == [], f"a sensor with no S14 extension paid for a digest: {calls}"


def test_the_digest_is_computed_only_when_an_extension_attests(monkeypatch):
    calls = []
    orig = _att._body_sha256
    monkeypatch.setattr(_att, "_body_sha256",
                        lambda data: calls.append(len(data)) or orig(data))
    s, _ = _sensor([_Record()])
    s.protect_http(_client([])).post(URL, json={"message": "hello there friend"})
    assert len(calls) == 1


# ── the autopatch paths ──────────────────────────────────────────────────────

def test_httpx_sync_under_protect_carries_the_header():
    rec = _Record()
    s, _ = _sensor([rec])
    xaidr.protect(sensor=s, targets=["httpx"], quiet=True)
    sent = []
    with _client(sent) as c:
        c.post(URL, json={"message": "hello there friend"})
    assert sent[0][1]["x-delphi-attestation"] == "demo"
    assert rec.views[0].body_sha256 == _b64u_sha256(sent[0][2])
    assert rec.views[0].method == "POST"


def test_httpx_async_under_protect_carries_the_header():
    rec = _Record()
    s, _ = _sensor([rec])
    xaidr.protect(sensor=s, targets=["httpx"], quiet=True)
    sent = []

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(
                lambda r: (sent.append((r.method, dict(r.headers), r.content)),
                           httpx.Response(200, json={}))[1])) as c:
            await c.post(URL, json={"message": "hello there friend"})
    asyncio.run(go())
    assert sent[0][1]["x-delphi-attestation"] == "demo"
    assert rec.views[0].body_sha256 == _b64u_sha256(sent[0][2])


def test_requests_under_protect_carries_the_header():
    requests = pytest.importorskip("requests")
    if not hasattr(requests, "adapters"):
        pytest.skip("the real requests package is not importable here")
    rec = _Record()
    s, _ = _sensor([rec])
    sent = []

    class _Adapter(requests.adapters.BaseAdapter):
        def send(self, request, **kwargs):
            sent.append((request.method, dict(request.headers), request.body))
            resp = requests.Response()
            resp.status_code = 200
            resp._content = b"{}"
            resp.request = request
            resp.url = request.url
            return resp

        def close(self):
            pass

    xaidr.protect(sensor=s, targets=["requests"], quiet=True)
    sess = requests.Session()
    sess.mount("https://", _Adapter())
    sess.post(URL, json={"message": "hello there friend"})
    assert sent[0][1]["x-delphi-attestation"] == "demo"
    body = sent[0][2]
    body = body.encode() if isinstance(body, str) else body
    assert rec.views[0].body_sha256 == _b64u_sha256(body)


def test_protect_http_under_protect_scans_once_and_attests_once():
    """Ruling 13: protect_http plus protect() used to scan one request twice.
    One event, one view, one header."""
    rec = _Record()
    s, sink = _sensor([rec])
    xaidr.protect(sensor=s, targets=["httpx"], quiet=True)
    sent = []
    s.protect_http(_client(sent)).post(URL, json={"message": "hello there friend"})
    s.flush()
    a2a = [e for e in sink.events if e["data"].get("direction") == "a2a"]
    assert len(a2a) == 1, f"one request produced {len(a2a)} a2a events"
    assert len(rec.views) == 1
    assert len(sent) == 1 and sent[0][1]["x-delphi-attestation"] == "demo"


# ── binding: each request carries ITS scan ───────────────────────────────────

def test_eight_threads_each_carry_their_own_scan():
    """Binding is a return value, not shared state. Eight threads send eight
    distinct committed bodies at once, and every request's view names the scan
    whose event hashed THAT body. The S12 hook holds every thread at a barrier
    between its scan and its attestation, which is the interleaving a shared
    "last scan" would get wrong."""
    with open(SHELL, encoding="utf-8") as fh:
        texts = [e["text"] for e in json.load(fh)["benign_prose"][:8]]
    barrier = threading.Barrier(8)
    carried = {}
    lock = threading.Lock()

    class _Per(SensorExtension):
        name = "per-thread"

        def outbound_headers(self, dest):
            barrier.wait(timeout=10)      # every scan is done before any attests
            return {}

        def attest_egress(self, view):
            with lock:
                carried[threading.get_ident()] = view
            return {}

    s, sink = _sensor([_Per()])
    client = s.protect_http(_client([]))

    def worker(text):
        client.post(URL, json={"message": text})
        with lock:
            carried[threading.get_ident()] = (carried[threading.get_ident()], text)

    threads = [threading.Thread(target=worker, args=(t,)) for t in texts]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    s.flush()
    by_id = {e["data"]["scanId"]: e["data"] for e in sink.events
             if e["data"].get("direction") == "a2a"}
    assert len(carried) == 8 and len(by_id) == 8
    for view, text in carried.values():
        ev = by_id[view.scans[0].scan_id]
        assert ev["promptHash"] == safe_content_hash(text), (
            "request i carried the scan of request j's body")


def _a2a_blocked_text():
    """A committed battery text that a block sensor refuses on the a2a path."""
    asi = os.path.join(ROOT, "asi_battery", "attacks.jsonl")
    if not os.path.isfile(asi):
        pytest.skip("asi_battery/ is not in the sdist")
    probe = Sensor(agent_id="probe", enforcement_mode="block", reporter=_Sink())
    with open(asi, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            e = json.loads(line)
            if e["boundary"] in ("input", "a2a") and \
                    probe.scan_a2a(e["text"], destination="peer").action == "blocked":
                return e["text"]
    pytest.skip("no committed battery row blocks on the a2a path")   # pragma: no cover


def test_a_refused_request_is_not_attested():
    text = _a2a_blocked_text()
    rec = _Record()
    s, _ = _sensor([rec], enforcement_mode="block")
    sent = []
    with pytest.raises(DelphiBlockedError):
        s.protect_http(_client(sent)).post(URL, json={"message": text})
    assert sent == [] and rec.views == []


# ── what the M3 review found: the marker says only what the client did ───────

def _blocked_output_text():
    """A committed battery text a block sensor refuses on the output boundary."""
    asi = os.path.join(ROOT, "asi_battery", "attacks.jsonl")
    if not os.path.isfile(asi):
        pytest.skip("asi_battery/ is not in the sdist")
    probe = Sensor(agent_id="probe", enforcement_mode="block", reporter=_Sink())
    with open(asi, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            e = json.loads(line)
            if e["boundary"] == "output" and probe.scan_output(e["text"]).action == "blocked":
                return e["text"]
    pytest.skip("no committed battery row blocks on the output boundary")   # pragma: no cover


@pytest.mark.parametrize("verb", ("get", "delete"))
def test_get_and_delete_responses_are_still_scanned_under_protect(verb):
    """protect_http scans no GET/DELETE response itself; the send seam does, and
    the marker must leave that to it."""
    text = _blocked_output_text()
    s, sink = _sensor([], enforcement_mode="block")
    xaidr.protect(sensor=s, targets=["httpx"], quiet=True)
    client = s.protect_http(httpx.Client(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"message": text}))))
    with pytest.raises(DelphiBlockedError):
        getattr(client, verb)(URL)
    s.flush()
    assert [e["data"]["direction"] for e in sink.events if e["data"]["action"] == "blocked"] == ["output"]


def test_a_base_url_relative_request_is_still_destination_checked_under_protect():
    s, _ = _sensor([])
    s.block_urls(["denied.example"])
    xaidr.protect(sensor=s, targets=["httpx"], quiet=True)
    client = s.protect_http(httpx.Client(
        base_url="https://denied.example",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))))
    for call in (lambda: client.get("/agents/peer/x"),
                 lambda: client.post("/agents/peer/x", json={"message": "hello there"})):
        with pytest.raises(DelphiBlockedError):
            call()


def test_a_base_url_relative_request_is_destination_checked_without_protect():
    s, _ = _sensor([])
    s.block_urls(["denied.example"])
    client = s.protect_http(httpx.Client(
        base_url="https://denied.example",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))))
    with pytest.raises(DelphiBlockedError):
        client.get("/agents/peer/x")


def test_a_data_body_is_scanned_and_attested_at_the_send_seam():
    rec = _Record()
    s, sink = _sensor([rec])
    xaidr.protect(sensor=s, targets=["httpx"], quiet=True)
    sent = []
    s.protect_http(_client(sent)).post(URL, data={"message": "hello there friend"})
    s.flush()
    a2a = [e for e in sink.events if e["data"].get("direction") == "a2a"]
    assert len(a2a) == 1, "a data= body went unscanned"
    assert len(rec.views) == 1 and rec.views[0].body_sha256 == _b64u_sha256(sent[0][2]), (
        "the digest does not name the form body httpx sent")


def test_a_files_body_is_not_named_by_a_digest_of_other_bytes():
    """A multipart body is a stream httpx builds as it sends (a random boundary,
    files read on the way out). It is not read early, so it is not named: the
    digest is None, never the digest of bytes the request does not carry."""
    rec = _Record()
    s, _ = _sensor([rec])
    xaidr.protect(sensor=s, targets=["httpx"], quiet=True)
    sent = []
    s.protect_http(_client(sent)).post(URL, files={"f": ("a.txt", b"plain file text")})
    assert len(rec.views) == 1
    assert rec.views[0].body_sha256 is None
    assert sent[0][1]["x-delphi-attestation"] == "demo"


def test_a_data_body_without_protect_is_not_attested_with_a_wrong_digest():
    rec = _Record()
    s, _ = _sensor([rec])
    sent = []
    s.protect_http(_client(sent)).post(URL, data={"message": "hello there friend"})
    assert rec.views == [], "a digest was attested for bytes the client never saw"


def test_a_client_default_header_is_protected_from_an_extension():
    rec = _Record({"x-tenant": "from-extension", "x-delphi-attestation": "demo"})
    s, _ = _sensor([rec])
    sent = []

    def handler(request):
        sent.append(request.headers.get_list("x-tenant"))
        return httpx.Response(200, json={})

    client = s.protect_http(httpx.Client(headers={"X-Tenant": "caller-client-default"},
                                         transport=httpx.MockTransport(handler)))
    client.post(URL, json={"message": "hello there"})
    assert sent[0] == ["caller-client-default"], sent[0]


@pytest.mark.parametrize("value", ["value ", " value", "va lue\t"], ids=["trailing", "leading", "tab"])
def test_a_value_with_edge_whitespace_is_dropped_before_the_transport_sees_it(value):
    s, _ = _sensor([_Record({"x-delphi-attestation": value}), _Record({"x-other": "ok"})])
    sent = []
    s.protect_http(_client(sent)).post(URL, json={"message": "hello there"})
    assert "x-delphi-attestation" not in sent[0][1]
    assert sent[0][1]["x-other"] == "ok"


class _ScanningGate(SensorExtension):
    """A gate that runs a scan of its own first: that scan must not be the one
    attested for the request."""

    name = "scanning-gate"

    def __init__(self):
        self.sensor = None

    def on_attach(self, sensor):
        self.sensor = sensor

    def gate(self, req):
        if req.direction == "a2a" and req.destination != "side":
            self.sensor.scan_a2a("a side question", destination="side")
        return None


def test_a_gates_own_scan_is_not_the_one_attested():
    rec = _Record()
    s, sink = _sensor([_ScanningGate(), rec])
    s.protect_http(_client([])).post(URL, json={"message": "hello there friend"})
    s.flush()
    own = [e["data"] for e in sink.events
           if e["data"].get("direction") == "a2a" and e["data"].get("destinationAgent") != "side"]
    assert len(own) == 1
    assert rec.views[-1].scans[0].scan_id == own[0]["scanId"], (
        "the request was attested with a gate's side scan instead of its own")
