"""Ruling 4 for servers (2026-10-21): each WSGI request, each ASGI request and each
``multiprocessing.pool.ThreadPool`` task is one request, so one user's principal
authority never reaches the next user served on the same thread."""
from __future__ import annotations

import asyncio
import contextvars
import multiprocessing.pool
import warnings

import xaidr

AUTHORITY = {"principal", "principal_undeclared_span", "trusted_source"}
ALICE = "alice@corp.example"


class _Null:
    def report(self, *a, **k):
        pass


def _sensor():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return xaidr.Sensor(agent_id="servers", value_origin="record", reporter=_Null())


def _wire(s):
    return s.scan_tool_call("send_email", {"to": ALICE}).value_origin.wire.value


def _app_for(s):
    """User A's request names alice; user B's request names nobody."""
    def app(environ, start_response):
        if environ["PATH_INFO"] == "/a":
            s.scan(f"Email {ALICE} the report.", direction="input")
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [_wire(s).encode()]
    return app


def _serve_wsgi(app, path):
    """One request as a WSGI server serves it: call, iterate the body, close it."""
    body = app({"PATH_INFO": path, "REQUEST_METHOD": "GET"}, lambda *a, **k: None)
    try:
        return b"".join(body).decode()
    finally:
        close = getattr(body, "close", None)
        if close is not None:
            close()


def test_a_wsgi_server_thread_keeps_each_users_request_to_itself():
    from xaidr.integrations.web import RequestScopeMiddleware
    s = _sensor()
    app = RequestScopeMiddleware(_app_for(s))

    def server_thread():                       # one thread, one request after another
        return _serve_wsgi(app, "/a"), _serve_wsgi(app, "/b")
    a, b = contextvars.Context().run(server_thread)
    assert a in AUTHORITY, a
    assert b == "no_flow", f"user B's request read {b!r}: user A's authority outlived A's request"


def test_an_asgi_app_keeps_each_users_request_to_itself():
    from xaidr.integrations.web import RequestScopeASGIMiddleware
    s = _sensor()

    async def inner(scope, receive, send):
        if scope["path"] == "/a":
            s.scan(f"Email {ALICE} the report.", direction="input")
        await send({"type": "http.response.body", "body": _wire(s).encode()})

    app = RequestScopeASGIMiddleware(inner)

    async def serve(path):
        sent = []

        async def send(msg):
            sent.append(msg)

        async def receive():
            return {"type": "http.request"}
        await app({"type": "http", "path": path}, receive, send)
        return sent[-1]["body"].decode()

    async def server_task():                   # one task serving one request after another
        return await serve("/a"), await serve("/b")
    a, b = contextvars.Context().run(lambda: asyncio.run(server_task()))
    assert a in AUTHORITY, a
    assert b == "no_flow", f"user B's request read {b!r}: user A's authority outlived A's request"


def test_an_asgi_lifespan_message_passes_through_untouched():
    from xaidr.integrations.web import RequestScopeASGIMiddleware
    seen = []

    async def inner(scope, receive, send):
        seen.append(scope["type"])

    asyncio.run(RequestScopeASGIMiddleware(inner)({"type": "lifespan"}, None, None))
    assert seen == ["lifespan"]


def test_a_multiprocessing_thread_pool_task_is_one_request():
    s = _sensor()

    def user_a():
        s.scan(f"Email {ALICE} the report.", direction="input")
        return _wire(s)

    with multiprocessing.pool.ThreadPool(1) as pool:      # one worker: B runs on A's thread
        a = pool.apply(user_a)
        b = pool.apply(_wire, (s,))
    assert a in AUTHORITY, a
    assert b == "no_flow", f"user B's task read {b!r}: user A's authority outlived A's task"
