"""WSGI and ASGI middleware: each request is one value-origin request.

A server that handles one request after another on one thread or task gives the
sensor no signal when the next request begins, so these wrap each request in
:func:`xaidr.request_scope`. Value origin's ledgers bound while the request runs
close when it ends, and the next request on that thread reads none of them::

    app = RequestScopeMiddleware(app)          # WSGI (Flask, Django, ...)
    app = RequestScopeASGIMiddleware(app)      # ASGI (Starlette, FastAPI, ...)

The WSGI scope stays open until the server closes the response body, so a
streamed body is part of its request. The ASGI scope covers the whole
application call; lifespan messages pass through untouched. Neither touches the
provenance chain, tiers or the inbound mark.
"""
from __future__ import annotations

import sys
from typing import Any, Callable, Iterable

from ..provenance_chain import request_scope

__all__ = ["RequestScopeMiddleware", "RequestScopeASGIMiddleware"]


class _ScopedBody:
    """A WSGI response body whose request ends when the server closes it."""

    def __init__(self, body: Iterable[bytes], scope) -> None:
        self._body = body
        self._scope = scope
        self._closed = False

    def __iter__(self):
        return iter(self._body)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            close = getattr(self._body, "close", None)
            if close is not None:
                close()
        finally:
            self._scope.__exit__(None, None, None)


class RequestScopeMiddleware:
    """WSGI middleware: each request runs in its own :func:`xaidr.request_scope`."""

    def __init__(self, app: Callable[..., Iterable[bytes]]) -> None:
        self.app = app

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        scope = request_scope()
        scope.__enter__()
        try:
            body = self.app(environ, start_response)
        except BaseException:
            scope.__exit__(*sys.exc_info())
            raise
        return _ScopedBody(body, scope)


class RequestScopeASGIMiddleware:
    """ASGI middleware: each HTTP or WebSocket connection runs in its own
    :func:`xaidr.request_scope`."""

    def __init__(self, app: Callable[..., Any]) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope.get("type") not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        async with request_scope():
            await self.app(scope, receive, send)
