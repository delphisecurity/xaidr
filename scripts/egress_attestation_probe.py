#!/usr/bin/env python3
"""From outside the process: which egress paths carry an S14 attestation header.

Starts a local HTTP listener in a SUBPROCESS, attaches a demo extension that
returns ``x-delphi-attestation`` from ``attest_egress``, sends one request down
each path xaidr dispatches, and prints the header set the LISTENER received for
each path, with the ``EgressView`` the extension saw.

Paths: ``httpx-sync`` and ``httpx-async`` under ``protect()``, ``requests``
under ``protect()``, ``ProtectedHttpClient`` post, put, patch, get and delete;
and, when ``httpx2`` is installed (the OpenAI 3.x, Anthropic 2.x and MCP 2.x
SDKs send over it), ``httpx2-sync`` and ``httpx2-async`` under ``protect()``,
``ProtectedHttpClient`` over an ``httpx2.Client``, each verb, and
``httpx2-imported-after-protect``: a fresh interpreter that calls ``protect()``
before httpx2 is imported, as a host does when an SDK imports httpx2 for it. A path is reported PRESENT when the listener received the header and
ABSENT when it did not; GET and DELETE carry ``scans=()``.

Standard library, ``xaidr`` and the HTTP clients it wraps. No network beyond
loopback. The body is one benign sentence; no attack input.

    python scripts/egress_attestation_probe.py
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import select
import socket
import subprocess
import sys

# `bind` puts the repo root on sys.path, prints the resolved path and version
# FIRST, and under XAIDR_FROM_INSTALL=1 leaves sys.path alone and refuses a
# source tree (scripts/_provenance.py; tests/test_report_provenance.py).
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _provenance import bind  # noqa: E402

PROV = bind(__file__)

import xaidr  # noqa: E402
from xaidr import Sensor, SensorExtension  # noqa: E402

_LISTENER = r'''
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def _h(self):
        import base64, hashlib
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n) if n else b""
        digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
        print(json.dumps({"method": self.command, "path": self.path, "body_sha256": digest,
                          "headers": {k.lower(): v for k, v in self.headers.items()}}), flush=True)
        body = b"{}"
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _h
    def log_message(self, *a):
        pass

port = int(sys.argv[1])
print("READY", flush=True)
HTTPServer(("127.0.0.1", port), H).serve_forever()
'''


def _refused_row():
    """The first committed battery text a block-mode sensor refuses on the a2a
    path, or None when the battery is not present (it is not in the sdist)."""
    root = os.path.dirname(_HERE)
    path = os.path.join(root, "asi_battery", "attacks.jsonl")
    if not os.path.isfile(path):
        return None
    probe = Sensor(agent_id="probe", enforcement_mode="block",
                   reporter=type("N", (), {"report": lambda *a, **k: None,
                                            "close": lambda *a, **k: None})())
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            e = json.loads(line)
            if e["boundary"] in ("input", "a2a") and \
                    probe.scan_a2a(e["text"], destination="peer").action == "blocked":
                return e["text"]
    return None


_CHILD = r'''
import json, sys
import xaidr
from xaidr import Sensor, SensorExtension
views = []
class Demo(SensorExtension):
    name = "probe-attest"
    def attest_egress(self, view):
        views.append(view)
        return {"x-delphi-attestation": "probe"}
class Null:
    def report(self, *a, **k): pass
    def close(self, *a, **k): pass
sensor = Sensor(agent_id="probe", extensions=[Demo()], reporter=Null())
xaidr.protect(sensor=sensor, targets=["httpx2"], quiet=True)
assert "httpx2" not in sys.modules, "httpx2 was imported before the probe imported it"
import httpx2
httpx2.post(sys.argv[1], json=json.loads(sys.argv[2]))
v = views[-1] if views else None
print(json.dumps(None if v is None else {
    "method": v.method, "host": v.host, "mode": v.mode, "value_origin_mode": v.value_origin_mode,
    "body_sha256": v.body_sha256,
    "scans": [{"found": sc.found, "enforced": sc.enforced} for sc in v.scans]}))
'''


def _installed(name: str) -> bool:
    import importlib.util
    return importlib.util.find_spec(name) is not None


def _after_protect_child(url, body, srv):
    """``httpx2-imported-after-protect``: run ``_CHILD`` with the xaidr in use."""
    from types import SimpleNamespace
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.dirname(os.path.dirname(os.path.abspath(xaidr.__file__)))
    out = subprocess.run([sys.executable, "-c", _CHILD, url, json.dumps(body)],
                         capture_output=True, text=True, env=env, timeout=120)
    ready, _, _ = select.select([srv.stdout], [], [], 10)
    seen = json.loads(srv.stdout.readline()) if ready else {"headers": {}, "body_sha256": None}
    view = None
    if out.returncode == 0 and out.stdout.strip() not in ("", "null"):
        d = json.loads(out.stdout.strip().splitlines()[-1])
        d["scans"] = [SimpleNamespace(**sc) for sc in d["scans"]]
        view = SimpleNamespace(**d)
    return ("httpx2-imported-after-protect", seen, view)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    class _Demo(SensorExtension):
        name = "probe-attest"

        def __init__(self):
            self.views = []

        def attest_egress(self, view):
            self.views.append(view)
            return {"x-delphi-attestation": "probe"}

    port = _free_port()
    srv = subprocess.Popen([sys.executable, "-c", _LISTENER, str(port)],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        assert srv.stdout.readline().strip() == "READY"
        url = f"http://127.0.0.1:{port}/agents/peer/x"
        body = {"message": "hello there, a plain request body"}
        results = []

        def run(path, fn, body=body):
            demo = _Demo()
            sensor = Sensor(agent_id="probe", extensions=[demo],
                            reporter=type("N", (), {"report": lambda *a, **k: None,
                                                     "close": lambda *a, **k: None})())
            try:
                fn(sensor, body)
            finally:
                xaidr.unprotect()
            ready, _, _ = select.select([srv.stdout], [], [], 10)
            seen = json.loads(srv.stdout.readline()) if ready else {"headers": {}, "body_sha256": None}
            view = demo.views[-1] if demo.views else None
            results.append((path, seen, view))

        try:
            import httpx
        except ImportError:
            httpx = None
        try:
            import requests
        except ImportError:
            requests = None

        if httpx is not None:
            for verb in ("post", "put", "patch"):
                run(f"protect_http-{verb}",
                    lambda s, b, v=verb: getattr(s.protect_http(httpx.Client()), v)(url, json=b))
            for verb in ("get", "delete"):
                run(f"protect_http-{verb}",
                    lambda s, b, v=verb: getattr(s.protect_http(httpx.Client()), v)(url))

            def httpx_sync(s, b):
                xaidr.protect(sensor=s, targets=["httpx"], quiet=True)
                httpx.post(url, json=b)
            run("httpx-sync", httpx_sync)

            def httpx_async(s, b):
                xaidr.protect(sensor=s, targets=["httpx"], quiet=True)

                async def go():
                    async with httpx.AsyncClient() as c:
                        await c.post(url, json=b)
                asyncio.run(go())
            run("httpx-async", httpx_async)

            # A committed battery row the sensor refuses in block mode: the
            # monitor sensor's attestation must say found=blocked, enforced=flagged.
            refused = _refused_row()
            if refused is not None:
                run("protect_http-post (refused row)", 
                    lambda s, b: s.protect_http(httpx.Client()).post(url, json=b),
                    body={"message": refused})

        try:
            import httpx2
        except ImportError:
            httpx2 = None

        if httpx2 is not None:
            for verb in ("post", "put", "patch"):
                run(f"protect_http(httpx2)-{verb}",
                    lambda s, b, v=verb: getattr(s.protect_http(httpx2.Client()), v)(url, json=b))
            for verb in ("get", "delete"):
                run(f"protect_http(httpx2)-{verb}",
                    lambda s, b, v=verb: getattr(s.protect_http(httpx2.Client()), v)(url))

            def httpx2_sync(s, b):
                xaidr.protect(sensor=s, targets=["httpx2"], quiet=True)
                httpx2.post(url, json=b)
            run("httpx2-sync", httpx2_sync)

            def httpx2_async(s, b):
                xaidr.protect(sensor=s, targets=["httpx2"], quiet=True)

                async def go():
                    async with httpx2.AsyncClient() as c:
                        await c.post(url, json=b)
                asyncio.run(go())
            run("httpx2-async", httpx2_async)

        # protect() BEFORE httpx2 is imported, in a fresh interpreter: the order a
        # host writes when an SDK imports httpx2 for it. The import hook patches
        # httpx2 when it is imported; the child reports the view it attested.
        if _installed("httpx2"):
            results.append(_after_protect_child(url, body, srv))

        if requests is not None:
            def req(s, b):
                xaidr.protect(sensor=s, targets=["requests"], quiet=True)
                requests.post(url, json=b, timeout=5)
            run("requests", req)

        width = max(len(p) for p, _, _ in results) if results else 10
        print(f"{'path':<{width}}  header   scans  view")
        ok = True
        for path, seen, view in results:
            present = "x-delphi-attestation" in seen["headers"]
            digest_ok = view is not None and view.body_sha256 == seen.get("body_sha256")
            ok = ok and present and view is not None and digest_ok
            scans = "-" if view is None else len(view.scans)
            summary = "-" if view is None else (
                f"method={view.method} host={view.host} mode={view.mode} "
                f"vo={view.value_origin_mode} digest={'match' if digest_ok else 'DIFFERS'}"
                + (f" found={view.scans[0].found} enforced={view.scans[0].enforced}"
                   if view.scans else ""))
            print(f"{path:<{width}}  {'PRESENT' if present else 'ABSENT '}  {scans!s:<5}  {summary}")
        print("every path carries the header, and every digest names the bytes received"
              if ok else "a path carries no header, or a digest names other bytes")
        return 0 if ok else 1
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=10)
        except Exception:
            srv.kill()


if __name__ == "__main__":
    raise SystemExit(main())
