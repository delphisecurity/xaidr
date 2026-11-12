"""The real OpenAI 3.x and Anthropic 2.x SDKs, over httpx2, against a local server.

Each SDK is driven with its OWN default client (``openai.OpenAI`` builds an
``httpx2.Client`` subclass, so does ``anthropic.Anthropic``) and a ``base_url``
on a loopback listener this module starts: no network, no API key (the key is a
placeholder the listener never checks). Under ``protect()`` each call must be:

* scanned — the request's own bytes produce one ``a2a`` scan event;
* attested — the listener receives the S14 header, and the view's
  ``body_sha256`` names the exact bytes it received;
* bound — the view names that request's own scan (B1).

A retried call is one scan and one attestation per attempt (one per
client-level send). A streamed answer is never read by the seam. In a fresh
interpreter, ``protect()`` before ``import openai`` patches httpx2 when the SDK
imports it. MCP 2.x is driven in ``tests/test_httpx2_mcp.py``.

The SDKs are optional: each case skips where its package is absent, and the CI
job that installs them refuses a skip. Inputs: plain benign text only.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import subprocess
import sys
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import xaidr
from xaidr import Sensor, SensorExtension

pytest.importorskip("httpx2")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = "placeholder-key-the-listener-never-reads"
QUESTION = "hello there, a plain question about the weather"

CHAT = {"id": "c1", "object": "chat.completion", "created": 1, "model": "m",
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": "a plain answer"}}]}
CHAT_SSE = (b'data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m",'
            b'"choices":[{"index":0,"delta":{"content":"a plain answer"},"finish_reason":null}]}\n\n'
            b"data: [DONE]\n\n")
MESSAGE = {"id": "m1", "type": "message", "role": "assistant", "model": "m",
           "content": [{"type": "text", "text": "a plain answer"}],
           "stop_reason": "end_turn", "stop_sequence": None,
           "usage": {"input_tokens": 1, "output_tokens": 1}}


class _Listener:
    """A loopback HTTP server that answers like the two APIs and records what
    arrived: method, path, headers and the SHA-256 of the body."""

    def __init__(self):
        self.seen = []
        self.fail_next = 0
        listener = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(n) if n else b""
                listener.seen.append({
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body_sha256": base64.urlsafe_b64encode(
                        hashlib.sha256(body).digest()).rstrip(b"=").decode(),
                })
                if listener.fail_next:
                    listener.fail_next -= 1
                    return self._send(500, b'{"error": {"message": "try again"}}')
                payload = json.loads(body or b"{}")
                if self.path.endswith("/chat/completions"):
                    if payload.get("stream"):
                        return self._send(200, CHAT_SSE, "text/event-stream")
                    return self._send(200, json.dumps(CHAT).encode())
                if self.path.endswith("/messages"):
                    return self._send(200, json.dumps(MESSAGE).encode())
                return self._send(404, b"{}")

            def _send(self, status, body, ctype="application/json"):
                self.send_response(status)
                self.send_header("content-type", ctype)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture(scope="module")
def listener():
    server = _Listener()
    yield server
    server.close()


@pytest.fixture(autouse=True)
def _isolated(listener, monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    listener.seen.clear()
    listener.fail_next = 0
    yield
    xaidr.unprotect()


class _Sink:
    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch)

    def close(self):
        pass


class _Numbered(SensorExtension):
    name = "numbered-attest"

    def __init__(self):
        self.views = []

    def attest_egress(self, view):
        self.views.append(view)
        return {"x-delphi-attestation": str(len(self.views) - 1)}


def _protected():
    rec, sink = _Numbered(), _Sink()
    s = Sensor(agent_id="real-sdk", reporter=sink, extensions=[rec])
    xaidr.protect(sensor=s, targets=["httpx2"], quiet=True)
    return s, sink, rec


def _assert_scanned_attested_bound(s, sink, rec, listener, sdk, calls=1):
    s.flush()
    a2a = [e["data"] for e in sink.events if e["data"].get("direction") == "a2a"]
    assert len(a2a) == calls, (
        f"{calls} {sdk} call(s) over httpx2 produced {len(a2a)} a2a scan events: the "
        "request bytes were not scanned at egress")
    assert len(listener.seen) == calls
    for seen, event in zip(listener.seen, a2a):
        header = seen["headers"].get("x-delphi-attestation")
        assert header is not None, f"the {sdk} request reached the server with no S14 header"
        view = rec.views[int(header)]
        assert view.body_sha256 == seen["body_sha256"], (
            f"the {sdk} attestation names bytes other than the ones the server received")
        assert [sc.scan_id for sc in view.scans] == [event["scanId"]], (
            f"the {sdk} request's attestation names a scan other than its own")


# ── OpenAI 3.x ───────────────────────────────────────────────────────────────

def test_openai_default_client_call_is_scanned_attested_and_bound(listener):
    openai = pytest.importorskip("openai")
    s, sink, rec = _protected()
    client = openai.OpenAI(api_key=KEY, base_url=listener.url + "/v1", max_retries=0)
    assert isinstance(client._client, sys.modules["httpx2"].Client)
    out = client.chat.completions.create(model="m", messages=[{"role": "user", "content": QUESTION}])
    assert out.choices[0].message.content == "a plain answer"
    _assert_scanned_attested_bound(s, sink, rec, listener, "openai")


def test_openai_streamed_call_is_scanned_and_its_answer_left_to_the_caller(listener):
    openai = pytest.importorskip("openai")
    s, sink, rec = _protected()
    client = openai.OpenAI(api_key=KEY, base_url=listener.url + "/v1", max_retries=0)
    chunks = list(client.chat.completions.create(
        model="m", messages=[{"role": "user", "content": QUESTION}], stream=True))
    assert "".join(c.choices[0].delta.content or "" for c in chunks) == "a plain answer", (
        "the seam consumed the streamed answer")
    _assert_scanned_attested_bound(s, sink, rec, listener, "openai")
    assert not [e for e in sink.events if e["data"].get("direction") == "output"]


def test_openai_async_call_is_scanned_attested_and_bound(listener):
    openai = pytest.importorskip("openai")
    s, sink, rec = _protected()

    async def go():
        client = openai.AsyncOpenAI(api_key=KEY, base_url=listener.url + "/v1", max_retries=0)
        try:
            return await client.chat.completions.create(
                model="m", messages=[{"role": "user", "content": QUESTION}])
        finally:
            await client.close()
    assert asyncio.run(go()).choices[0].message.content == "a plain answer"
    _assert_scanned_attested_bound(s, sink, rec, listener, "openai async")


def test_openai_retry_is_one_scan_and_one_attestation_per_attempt(listener, monkeypatch):
    openai = pytest.importorskip("openai")
    monkeypatch.setattr("time.sleep", lambda *_: None)
    s, sink, rec = _protected()
    listener.fail_next = 1
    client = openai.OpenAI(api_key=KEY, base_url=listener.url + "/v1", max_retries=2)
    client.chat.completions.create(model="m", messages=[{"role": "user", "content": QUESTION}])
    _assert_scanned_attested_bound(s, sink, rec, listener, "openai (retried)", calls=2)
    assert len({v.scans[0].scan_id for v in rec.views}) == 2, "two attempts shared one scan"


# ── Anthropic 2.x ────────────────────────────────────────────────────────────

def test_anthropic_default_client_call_is_scanned_attested_and_bound(listener):
    anthropic = pytest.importorskip("anthropic")
    s, sink, rec = _protected()
    client = anthropic.Anthropic(api_key=KEY, base_url=listener.url, max_retries=0)
    assert isinstance(client._client, sys.modules["httpx2"].Client)
    out = client.messages.create(model="m", max_tokens=8,
                                 messages=[{"role": "user", "content": QUESTION}])
    assert out.content[0].text == "a plain answer"
    _assert_scanned_attested_bound(s, sink, rec, listener, "anthropic")


def test_anthropic_async_call_is_scanned_attested_and_bound(listener):
    anthropic = pytest.importorskip("anthropic")
    s, sink, rec = _protected()

    async def go():
        client = anthropic.AsyncAnthropic(api_key=KEY, base_url=listener.url, max_retries=0)
        try:
            return await client.messages.create(
                model="m", max_tokens=8, messages=[{"role": "user", "content": QUESTION}])
        finally:
            await client.close()
    assert asyncio.run(go()).content[0].text == "a plain answer"
    _assert_scanned_attested_bound(s, sink, rec, listener, "anthropic async")


# ── the order a host writes: protect() first, then the SDK ───────────────────

def test_protect_before_import_openai_covers_the_sdk(listener):
    pytest.importorskip("openai")
    code = textwrap.dedent(f'''
        import sys
        import xaidr
        from xaidr import Sensor, SensorExtension

        class Sink:
            def __init__(self): self.events = []
            def report(self, batch): self.events.extend(batch)
            def close(self): pass

        class Rec(SensorExtension):
            name = "rec"
            def attest_egress(self, view):
                return {{"x-delphi-attestation": "child"}}

        sink = Sink()
        sensor = Sensor(agent_id="child", reporter=sink, extensions=[Rec()])
        xaidr.protect(sensor=sensor, quiet=True)
        assert "httpx2" not in sys.modules and "openai" not in sys.modules
        import openai
        client = openai.OpenAI(api_key={KEY!r}, base_url={listener.url + "/v1"!r}, max_retries=0)
        client.chat.completions.create(model="m", messages=[{{"role": "user", "content": "hi there"}}])
        sensor.flush()
        assert len([e for e in sink.events if e["data"].get("direction") == "a2a"]) == 1, (
            "openai imported after protect() sent its call unscanned")
        print("order-ok")
    ''')
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env=env, cwd=ROOT, timeout=120)
    assert out.returncode == 0 and "order-ok" in out.stdout, out.stderr
    assert listener.seen and listener.seen[-1]["headers"].get("x-delphi-attestation") == "child", (
        "the call from an SDK imported after protect() reached the server unattested")
