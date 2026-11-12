"""The M3 rule: on every HTTP path, a monitor sensor's attestation carries what a
block-mode sensor found.

S14 ``attest_egress`` hands an extension an ``EgressView`` once per outbound
request, after that request's own scan (B1) and before it is sent. The view's
``ScanView.found`` is the Core verdict for what the sensor FOUND, before monitor
softening and before any S6 transform; ``ScanView.enforced`` is the verdict for
the action the host received.

Three sensors drive every committed row down every path:

* a BLOCK sensor, whose action is the reference;
* a MONITOR sensor, whose ``found`` must equal the block action, and whose
  ``enforced`` is the softened one;
* a MONITOR sensor with an S6 transform that rewrites every verdict to
  ``allowed``, whose ``found`` must STILL equal the block action.

The vacuity guard: on every path at least one row has ``found == "blocked"``
and ``enforced == "flagged"``. Without it, a build that wrote the softened
verdict into ``found`` would pass on a corpus that never blocks.

Every input is a committed corpus row (the prose pool and the ASI battery's
input and a2a texts). No attack string is written here.
"""

from __future__ import annotations

import asyncio
import json
import os

import pytest

import xaidr
from xaidr import DelphiBlockedError, Sensor, SensorExtension
from xaidr.extensions import EgressView, ScanView
from xaidr.types import ScanResult

httpx = pytest.importorskip("httpx")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHELL = os.path.join(ROOT, "tests", "fixtures", "shell_corpus.json")
ASI = os.path.join(ROOT, "asi_battery")
URL = "https://h.example/agents/peer/x"

PATHS = ("httpx-sync", "httpx-async", "requests",
         "protect_http-post", "protect_http-put", "protect_http-patch")


class _Null:
    def report(self, *a, **k): pass
    def close(self, *a, **k): pass


class _Record(SensorExtension):
    """Records every EgressView and returns one demo header."""

    name = "record-attest"

    def __init__(self):
        self.views = []

    def attest_egress(self, view):
        self.views.append(view)
        return {"x-delphi-attestation": "demo"}


class _SoftenAll(SensorExtension):
    """An S6 transform that rebuilds every verdict as allowed, and SAYS it found
    allowed: the view must read a record no transform has seen."""

    name = "soften-all"

    def transform_verdict(self, req, result):
        return ScanResult(action="allowed", score=0.0, category=None, rules=[],
                          found_action="allowed")


def _texts():
    with open(SHELL, encoding="utf-8") as fh:
        shell = json.load(fh)
    out = [(f"shell.prose/{e['id']}", e["text"]) for e in shell["benign_prose"]]
    if os.path.isdir(ASI):
        with open(os.path.join(ASI, "attacks.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                e = json.loads(line)
                if e["boundary"] in ("input", "a2a"):
                    out.append((f"asi.attacks/{e['id']}", e["text"]))
    return out


@pytest.fixture(autouse=True)
def _unprotect_after():
    yield
    xaidr.unprotect()


def _requests_module():
    requests = pytest.importorskip("requests")
    if not hasattr(requests, "adapters"):           # a fake left by another module
        pytest.skip("the real requests package is not importable here")
    return requests


class _Sent:
    """What the listener saw: headers per request, in order."""

    def __init__(self):
        self.headers = []


def _drive(path, sensor, body, sent):
    """Send ``body`` down ``path`` with ``sensor``. Returns None, or the
    DelphiBlockedError the host saw."""
    def httpx_handler(request):
        sent.headers.append(dict(request.headers))
        return httpx.Response(200, json={})

    try:
        if path.startswith("protect_http-"):
            verb = path.split("-", 1)[1]
            client = sensor.protect_http(
                httpx.Client(transport=httpx.MockTransport(httpx_handler)))
            getattr(client, verb)(URL, json=body)
        elif path == "httpx-sync":
            xaidr.protect(sensor=sensor, targets=["httpx"], quiet=True)
            with httpx.Client(transport=httpx.MockTransport(httpx_handler)) as c:
                c.post(URL, json=body)
        elif path == "httpx-async":
            xaidr.protect(sensor=sensor, targets=["httpx"], quiet=True)

            async def go():
                async with httpx.AsyncClient(
                        transport=httpx.MockTransport(httpx_handler)) as c:
                    await c.post(URL, json=body)
            asyncio.run(go())
        elif path == "requests":
            requests = _requests_module()

            class _Adapter(requests.adapters.BaseAdapter):
                def send(self, request, **kwargs):
                    sent.headers.append(dict(request.headers))
                    resp = requests.Response()
                    resp.status_code = 200
                    resp._content = b"{}"
                    resp.request = request
                    resp.url = request.url
                    return resp

                def close(self):
                    pass

            xaidr.protect(sensor=sensor, targets=["requests"], quiet=True)
            s = requests.Session()
            s.mount("https://", _Adapter())
            s.post(URL, json=body)
        else:                                            # pragma: no cover
            raise ValueError(path)
    except DelphiBlockedError as exc:
        return exc
    finally:
        xaidr.unprotect()
    return None


def _run(path, extensions, mode):
    rec = _Record()
    sensor = Sensor(agent_id=f"attest-{mode}", enforcement_mode=mode,
                    reporter=_Null(), extensions=[rec] + list(extensions))
    sent = _Sent()
    out = {}
    for row_id, text in _texts():
        before = len(rec.views)
        exc = _drive(path, sensor, {"message": text}, sent)
        if exc is not None:
            out[row_id] = ("blocked", None)
            assert len(rec.views) == before, (
                f"{path}: a refused request was attested anyway ({row_id})")
            continue
        assert len(rec.views) == before + 1, (
            f"{path}: expected one view for one request, got {len(rec.views) - before} ({row_id})")
        view = rec.views[-1]
        assert isinstance(view, EgressView) and view.view_version == 1
        assert view.mode == mode
        assert len(view.scans) == 1 and isinstance(view.scans[0], ScanView), view.scans
        out[row_id] = (view.scans[0].enforced, view)
    assert sent.headers, f"{path}: nothing reached the listener"
    assert all(h.get("x-delphi-attestation") == "demo" for h in sent.headers), (
        f"{path}: a request left without the extension's header")
    return out


@pytest.fixture(scope="module", params=PATHS)
def path(request):
    return request.param


@pytest.fixture(scope="module")
def reference(path):
    """The block sensor's action per row, down this path."""
    return {row: outcome for row, (outcome, _) in _run(path, [], "block").items()}


def test_monitor_found_is_the_block_action_on_this_path(path, reference):
    got = _run(path, [], "monitor")
    found_hidden = []
    guard = 0
    for row_id, (enforced, view) in got.items():
        assert view is not None, f"{path}: monitor refused {row_id}; monitor never refuses"
        scan = view.scans[0]
        if scan.found != reference[row_id]:
            found_hidden.append((row_id, reference[row_id], scan.found))
        if reference[row_id] == "blocked" and scan.found == "blocked" and enforced == "flagged":
            guard += 1
    assert not found_hidden, (
        f"{path}: monitor sensor attested {found_hidden[0][2]!r} for a call it found "
        f"{found_hidden[0][1]!r} ({len(found_hidden)} rows, first {found_hidden[0][0]}): "
        "the gateway would not learn what the sensor found")
    print(f"{path}: rows with found=blocked and enforced=flagged: {guard}")
    assert guard >= 1, (
        f"{path}: vacuous, no row has found='blocked' with enforced='flagged', so "
        "this path never showed a softened verdict")


def test_monitor_enforced_is_the_softened_verdict(path, reference):
    got = _run(path, [], "monitor")
    for row_id, (enforced, view) in got.items():
        expected = "flagged" if reference[row_id] in ("blocked", "held") else reference[row_id]
        assert enforced == expected, (
            f"{path}: enforced={enforced!r} for {row_id}, block action {reference[row_id]!r}")


def test_s6_transform_does_not_rewrite_found(path, reference):
    got = _run(path, [_SoftenAll()], "monitor")
    rewritten = [(r, reference[r], v.scans[0].found) for r, (e, v) in got.items()
                 if v is not None and v.scans[0].found != reference[r]]
    assert not rewritten, (
        f"{path}: an S6 transform rewrote the attested found verdict "
        f"({len(rewritten)} rows, first {rewritten[0]})")
    # enforced is what the host received: the transform's allowed.
    assert all(e == "allowed" for e, _ in got.values()), (
        f"{path}: enforced is not the action the host received after the transform")
    assert any(v.scans[0].found == "blocked" for _, v in got.values() if v is not None), (
        f"{path}: vacuous, no softened row reached found='blocked'")


def test_block_mode_found_equals_enforced(path, reference):
    got = _run(path, [], "block")
    for row_id, (enforced, view) in got.items():
        if view is None:
            continue
        assert view.scans[0].found == enforced == reference[row_id], (row_id, view.scans[0])
