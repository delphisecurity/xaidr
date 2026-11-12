#!/usr/bin/env python3
"""Count the 1.22.0 event keys on real framework runs, from the xaidr that answers.

Runs a pinned LangGraph agent (``langchain.agents.create_agent`` with a fake
chat model that calls one tool) under ``protect()``, and, when ``mcp`` 1.x is
importable, one MCP ``call_tool`` against a local streamable-HTTP server. Every
event goes to a JSONL file through a reporter that writes as it receives, and
the counts below are read back from that file:

    tool-call rows                      every tool_call event
    runTree=stamped                     tool-call rows the run tree placed
    parentScanId                        tool-call rows naming an input scan
    threats                             rows carrying the per-rule list
    traceParent                         tool-call rows with a trace parent (with --otel)
    bundleVersion                       rows carrying a bundle version (0 with no bundle)

It is the step-3 check for the run-tree keys and the new fields
(``docs/releasing.md``): run it from a clean clone, at a neutral cwd, under
``python -I`` with ``XAIDR_FROM_INSTALL=1`` against the installed wheel. Run the
same way against the published 1.21.0 wheel it prints 0 for every one of these
counts, which is what makes the 1.22.0 run a measurement and not a listing.

Only the committed benign text below is sent. No attack input.

    python scripts/release_fields_report.py --out /tmp/events.jsonl [--otel] [--no-mcp]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import subprocess
import sys
import time

# `bind` puts the repo root on sys.path, prints the resolved path and version
# FIRST, and under XAIDR_FROM_INSTALL=1 leaves sys.path alone and refuses a
# source tree (scripts/_provenance.py; tests/test_report_provenance.py).
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _provenance import bind  # noqa: E402

PROV = bind(__file__)

import xaidr  # noqa: E402
from xaidr import Sensor  # noqa: E402

_MCP_SERVER = r'''
import sys
from mcp.server.fastmcp import FastMCP
m = FastMCP("fields", host="127.0.0.1", port=int(sys.argv[1]))
@m.tool()
def echo(text: str) -> str:
    return text
m.run(transport="streamable-http")
'''


class _Jsonl:
    """A reporter that appends every event to a file as it receives it."""

    def __init__(self, path):
        self._fh = open(path, "a", encoding="utf-8")

    def report(self, batch):
        for e in batch:
            self._fh.write(json.dumps(e, sort_keys=True) + "\n")
        self._fh.flush()

    def close(self):
        self._fh.close()


def _langgraph_run(sensor) -> str:
    try:
        from langchain.agents import create_agent
        from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
        from langchain_core.messages import AIMessage
        from langchain_core.tools import tool
    except Exception as exc:                                    # pragma: no cover
        return f"skipped ({type(exc).__name__})"

    class _Model(FakeMessagesListChatModel):
        def bind_tools(self, tools, **kw):
            return self

    @tool
    def lookup(q: str) -> str:
        """Look something up."""
        return "result for " + q

    model = _Model(responses=[
        AIMessage(content="", tool_calls=[{"name": "lookup", "args": {"q": "the weather"}, "id": "c1"}]),
        AIMessage(content="done"),
    ])
    agent = create_agent(model, tools=[lookup])
    agent.invoke({"messages": [{"role": "user", "content": "what is the weather today"}]})
    import importlib.metadata as md
    return f"ran (langchain {md.version('langchain')}, langgraph {md.version('langgraph')})"


def _mcp_run(sensor) -> str:
    try:
        import importlib.metadata as md
        version = md.version("mcp")
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client
    except Exception as exc:                                    # pragma: no cover
        return f"skipped ({type(exc).__name__})"
    if int(version.split(".")[0]) >= 2:
        return f"skipped (mcp {version}: this report drives the mcp 1.x client API)"
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    proc = subprocess.Popen([sys.executable, "-c", _MCP_SERVER, str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(200):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)

        async def go():
            async with streamablehttp_client(f"http://127.0.0.1:{port}/mcp") as (r, w, _):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    sensor.scan("please echo a plain sentence", direction="input")
                    return await session.call_tool("echo", {"text": "a plain sentence"})
        asyncio.run(go())
        return f"ran (mcp {version})"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, help="JSONL file the events are appended to")
    ap.add_argument("--otel", action="store_true", help="run inside an active OpenTelemetry span")
    ap.add_argument("--no-mcp", action="store_true", help="skip the MCP run")
    a = ap.parse_args()

    if os.path.exists(a.out):
        os.remove(a.out)
    # protect() patches only what is ALREADY imported, so the frameworks are
    # imported first and the manifest below says which seams it found.
    for name in ("langchain", "langchain.agents", "langchain_core", "langgraph", "httpx", "mcp"):
        try:
            __import__(name)
        except Exception:
            pass
    sensor = Sensor(agent_id="release-fields", reporter=_Jsonl(a.out))
    manifest = xaidr.protect(sensor=sensor, quiet=True)
    token = None
    if a.otel:
        from opentelemetry import context as otel_context
        from opentelemetry import trace as otel_trace
        from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags
        span = NonRecordingSpan(SpanContext(
            trace_id=int("0af7651916cd43dd8448eb211c80319c", 16),
            span_id=int("b7ad6b7169203331", 16), is_remote=False,
            trace_flags=TraceFlags(TraceFlags.SAMPLED)))
        token = otel_context.attach(otel_trace.set_span_in_context(span))
    try:
        lg = _langgraph_run(sensor)
        mcp = "skipped (--no-mcp)" if a.no_mcp else _mcp_run(sensor)
    finally:
        if token is not None:
            otel_context.detach(token)
        sensor.flush()
        sensor.close_sync()
        xaidr.unprotect()

    rows = []
    with open(a.out, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                rows.append(json.loads(line))
    data = [r.get("data", {}) for r in rows if r.get("type") == "scan"]
    tool = [d for d in data if d.get("direction") == "tool_call"]
    counts = {
        "scan rows": len(data),
        "tool-call rows": len(tool),
        "runTree=stamped on tool-call rows": sum(1 for d in tool if d.get("runTree") == "stamped"),
        "parentScanId on tool-call rows": sum(1 for d in tool if d.get("parentScanId")),
        "threats on rows": sum(1 for d in data if isinstance(d.get("threats"), list)),
        "traceParent on tool-call rows": sum(1 for d in tool if d.get("traceParent")),
        "bundleVersion on rows": sum(1 for d in data if "bundleVersion" in d),
    }
    print(f"langgraph: {lg}")
    print(f"mcp:       {mcp}")
    try:
        print(f"patched:   {sorted(getattr(r, 'framework', getattr(r, 'target', '?')) for r in manifest.patched)}")
    except Exception:
        print("patched:   (manifest shape differs)")
    width = max(len(k) for k in counts)
    for k, v in counts.items():
        print(f"  {k:<{width}}  {v}")
    print(f"events: {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
