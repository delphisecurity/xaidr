"""The differential: the same requests through httpx and httpx2 under ``protect()``.

Every case below is run twice, once over ``httpx`` and once over ``httpx2``, each
time on a fresh sensor with a recording S14 extension, in monitor and in block
mode. The two runs must agree on everything the sensor decides and emits:

* whether the send was refused, and with which action;
* every telemetry event, less the fields that name a run rather than a decision
  (``scanId``, ``parentScanId``, ``timestamp``, ``scanTimeMs``);
* every ``EgressView`` the extension saw, less its scan ids, and so the S14 header
  value, which here is a digest of that view;
* the xaidr headers on the wire.

The client's own headers (``user-agent`` names the package) are not the sensor's
and are not compared.

ONE DECLARED DIFFERENCE. A ``tools/call`` refused before it leaves drops its
pending tool-call entry on httpx2 and keeps it on httpx (the httpx path keeps its
1.22.0 behaviour; ``tests/test_httpx2_mcp.py`` records it). The ``tools-denied``
cases assert everything else equal and that one difference exactly, so the
``pending`` comparison is exercised, not vacuous. Inputs are committed corpus rows: the prose pool and the
shell corpus (``tests/fixtures/shell_corpus.json``) and the ASI battery's input,
a2a and output texts when it is present. No attack string is written here.

Vacuity guard: across the cases, both families must have produced a refusal, a
flagged monitor verdict, a scanned response and a bound tool-call scan;
otherwise the agreement would be an agreement about nothing.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os

import pytest

import xaidr
from xaidr import DelphiBlockedError, Sensor, SensorExtension

httpx = pytest.importorskip("httpx")
httpx2 = pytest.importorskip("httpx2")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHELL = os.path.join(ROOT, "tests", "fixtures", "shell_corpus.json")
ASI = os.path.join(ROOT, "asi_battery", "attacks.jsonl")
URL = "https://peer.example/agents/peer/x"
_RUN_FIELDS = {"scanId", "parentScanId", "timestamp", "scanTimeMs"}


class _Sink:
    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch)

    def close(self):
        pass


def _view_summary(view):
    return {
        "method": view.method, "host": view.host, "mode": view.mode,
        "value_origin_mode": view.value_origin_mode, "body_sha256": view.body_sha256,
        "scans": [[sc.direction, sc.found, sc.enforced, list(sc.rules), sc.category,
                   sc.impact_class, sc.value_origin] for sc in view.scans],
    }


class _Digest(SensorExtension):
    """The header is a digest of the view less its scan ids: equal headers mean
    equal views, so the two families must produce byte-identical headers."""

    name = "digest-attest"

    def __init__(self):
        self.views = []

    def attest_egress(self, view):
        summary = _view_summary(view)
        self.views.append(summary)
        blob = json.dumps(summary, sort_keys=True, separators=(",", ":")).encode()
        return {"x-delphi-attestation": hashlib.sha256(blob).hexdigest()}


def _rows():
    with open(SHELL, encoding="utf-8") as fh:
        shell = json.load(fh)
    prose = [e["text"] for e in shell["benign_prose"][:12]]
    commands = [e["command"] for e in shell["attacks"][:12]]
    battery = {"in": [], "out": []}
    if os.path.isfile(ASI):
        with open(ASI, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    row = json.loads(line)
                    if row["boundary"] in ("input", "a2a"):
                        battery["in"].append(row["text"])
                    elif row["boundary"] == "output":
                        battery["out"].append(row["text"])
    return prose, commands, battery["in"][:16], battery["out"][:9]


PROSE, COMMANDS, BATTERY_IN, BATTERY_OUT = _rows()

#: (case id, kind, payload). Kinds: post (an A2A body), tools (a tools/call body
#: whose tool-call scan is pending), get (a response to scan), redirect, denied,
#: generator, async.
CASES = (
    [(f"post-prose-{i}", "post", t) for i, t in enumerate(PROSE)]
    + [(f"post-battery-{i}", "post", t) for i, t in enumerate(BATTERY_IN)]
    + [(f"tools-prose-{i}", "tools", t) for i, t in enumerate(PROSE[:6])]
    + [(f"tools-command-{i}", "tools", t) for i, t in enumerate(COMMANDS)]
    + [(f"get-battery-out-{i}", "get", t) for i, t in enumerate(BATTERY_OUT)]
    + [(f"get-prose-{i}", "get", t) for i, t in enumerate(PROSE[:4])]
    + [("redirect", "redirect", PROSE[0]), ("denied", "denied", PROSE[1]),
       ("generator", "generator", PROSE[2])]
    + [(f"tools-denied-{i}", "tools-denied", t) for i, t in enumerate(PROSE[:3])]
    + [(f"async-battery-{i}", "async", t) for i, t in enumerate(BATTERY_IN)]
    + [(f"async-tools-command-{i}", "async-tools", t) for i, t in enumerate(COMMANDS[:6])]
    + [(f"async-get-battery-out-{i}", "async-get", t) for i, t in enumerate(BATTERY_OUT)]
)


def _normal(event):
    data = {k: v for k, v in event["data"].items() if k not in _RUN_FIELDS}
    return {"type": event["type"], "data": data}


def _run(hx, mode, kind, payload):
    rec, sink = _Digest(), _Sink()
    sensor = Sensor(agent_id="differential", enforcement_mode=mode, reporter=sink,
                    extensions=[rec])
    sensor.block_urls(["denied.example"])
    xaidr.protect(sensor=sensor, targets=[hx.__name__], quiet=True)
    wire = []

    def respond(request):
        wire.append(sorted((k, v) for k, v in request.headers.items()
                           if k.lower().startswith("x-delphi")))
        if kind in ("get", "async-get"):
            return hx.Response(200, json={"message": payload})
        if kind == "redirect" and request.url.path.endswith("/x"):
            return hx.Response(307, headers={"location": "https://peer.example/agents/peer/y"})
        return hx.Response(200, json={"message": "a plain answer"})

    async def arespond(request):
        return respond(request)

    def rpc(url=URL):
        return {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": payload}}}

    refused = None
    try:
        if kind.startswith("async"):
            async def go():
                async with hx.AsyncClient(transport=hx.MockTransport(arespond)) as c:
                    if kind == "async":
                        await c.post(URL, json={"message": payload})
                    elif kind == "async-tools":
                        sensor.scan_tool_call("echo", {"text": payload})
                        await c.post(URL, json=rpc())
                    elif kind == "async-get":
                        await c.get(URL)
            asyncio.run(go())
        else:
            with hx.Client(transport=hx.MockTransport(respond), follow_redirects=True) as c:
                if kind in ("post", "redirect"):
                    c.post(URL, json={"message": payload})
                elif kind == "tools":
                    sensor.scan_tool_call("echo", {"text": payload})
                    c.post(URL, json=rpc())
                elif kind == "tools-denied":
                    sensor.scan_tool_call("echo", {"text": payload})
                    c.post("https://denied.example/mcp", json=rpc())
                elif kind == "get":
                    c.get(URL)
                elif kind == "denied":
                    c.post("https://denied.example/x", json={"message": payload})
                elif kind == "generator":
                    c.post(URL, content=iter([payload.encode()]))
    except DelphiBlockedError as exc:
        refused = getattr(exc.result, "action", "blocked")
    finally:
        xaidr.unprotect()
    sensor.flush()
    return {"refused": refused, "events": [_normal(e) for e in sink.events],
            "views": rec.views, "wire": wire,
            "pending": len(sensor._pending_tool_calls)}


_SEEN = {"refused": 0, "flagged": 0, "output": 0, "bound": 0,
         "async refused": 0, "async flagged": 0, "async output": 0, "async bound": 0}


@pytest.mark.parametrize("mode", ["monitor", "block"])
@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_httpx_and_httpx2_agree(case, mode):
    _, kind, payload = case
    a, b = _run(httpx, mode, kind, payload), _run(httpx2, mode, kind, payload)
    if kind == "tools-denied":
        # The declared difference, and only it: httpx keeps the refused call's
        # pending entry, httpx2 drops it.
        assert a["refused"] and b["refused"], "a tools/call to a denied destination left"
        assert (a["pending"], b["pending"]) == (1, 0), (
            f"the declared difference did not hold: pending httpx={a['pending']} "
            f"httpx2={b['pending']} (httpx keeps a refused call's entry, httpx2 drops it)")
        a["pending"] = b["pending"]
    for key in ("refused", "events", "views", "wire", "pending"):
        assert a[key] == b[key], (
            f"httpx and httpx2 disagree on {key} for the same {kind} request in {mode} mode:\n"
            f"httpx : {a[key]}\nhttpx2: {b[key]}")
    _SEEN["refused"] += a["refused"] is not None
    _SEEN["flagged"] += any(e["data"].get("action") == "flagged" for e in a["events"])
    _SEEN["output"] += any(e["data"].get("direction") == "output" for e in a["events"])
    _SEEN["bound"] += any(sc[0] == "tool_call" for v in a["views"] for sc in v["scans"])
    if kind.startswith("async"):
        _SEEN["async refused"] += a["refused"] is not None
        _SEEN["async flagged"] += any(e["data"].get("action") == "flagged" for e in a["events"])
        _SEEN["async output"] += any(e["data"].get("direction") == "output" for e in a["events"])
        _SEEN["async bound"] += any(sc[0] == "tool_call" for v in a["views"] for sc in v["scans"])


def test_the_differential_compared_something():
    """Runs after the cases (file order): the comparison saw each outcome."""
    if not BATTERY_IN:
        pytest.skip("asi_battery/ is not in the sdist")
    absent = [k for k, v in _SEEN.items() if v == 0]
    assert not absent, (
        f"the differential never produced {absent}: httpx and httpx2 agreed only "
        f"on requests that exercise nothing ({_SEEN})")
    print(f"differential outcomes: {_SEEN}")
