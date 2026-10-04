"""THE FAULT-ISOLATION SWEEP (owner, after M7).

Three milestones, three defects of one shape, each caught by review and not by
the build: M4's attach raised TypeError on a non-dataclass extension result,
M6's raising recorder reached the host, and M7's protect_tools crashed on a
tool with no implementation even with value origin OFF. New paths in this layer
defaulted to propagating faults. This file makes the opposite the default.

1. STRUCTURAL. Every call from outside xaidr/value_origin into the core's
   recording, evaluation, binding or parsing functions must sit lexically
   inside a ``try`` whose handler catches ``Exception``. That covers calls made
   through the ``_vo`` alias and calls to names imported directly. A new call
   site, like M8's should_block, fails here until it is guarded.
2. BEHAVIOURAL. Every public entry point that can reach those functions is
   driven with the function it reaches made to raise. Nothing may reach the
   caller, and the documented outcome must appear: a logged fault, the field
   omitted (never null), or the ledger_absent / no_flow row. Silence fails.
"""
from __future__ import annotations

import ast
import asyncio
import logging
import pathlib
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor

import pytest

import xaidr
from xaidr import value_origin as vo

ROOT = pathlib.Path(xaidr.__file__).parent
CORE_FNS = {"record_principal_input", "record_tool_result", "evaluate_call", "bind_fresh_ledger",
            "bind_ledger", "unbind_ledger", "should_block", "extract_destinations",
            "authority_of", "ledger_bound", "classify_value", "_host_authority", "_whatwg"}


def _catches_exception(handler):
    t = handler.type
    names = [t] if not isinstance(t, ast.Tuple) else list(t.elts)
    return t is None or any(isinstance(n, ast.Name) and n.id in ("Exception", "BaseException")
                            for n in names)


def _guarded(node, parents):
    child, p = node, parents.get(node)
    while p is not None:
        if isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return False                    # a try outside the def does not guard its calls
        if (isinstance(p, ast.Try) and any(child is b for b in p.body)
                and any(_catches_exception(h) for h in p.handlers)):
            return True
        child, p = p, parents.get(p)
    return False


def _module_aliases(tree):
    """Every name bound to the value_origin package or one of its submodules, by
    ANY import form (M-sweep review: matching only the literal `_vo` let
    `import xaidr.value_origin as v2` through)."""
    names = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if "value_origin" in a.name:
                    names.add(a.asname or a.name.split(".")[0])
        elif isinstance(n, ast.ImportFrom):
            for a in n.names:
                if a.name == "value_origin" or a.name.startswith("_") and n.module and "value_origin" in n.module and a.name not in CORE_FNS and a.name[1:2].islower() and a.name in ("_ledger", "_evaluate", "_extract", "_authority"):
                    names.add(a.asname or a.name)
    return names


def call_sites():
    """(site, function, guarded). A REFERENCE to a core function that is not
    the callee of a guarded call (stored in a variable, passed along, fetched by
    getattr) is reported unguarded too: it can be called from anywhere."""
    out = []
    for path in sorted(ROOT.rglob("*.py")):
        rel = path.relative_to(ROOT)
        if rel.parts[0] == "value_origin":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
        aliases = _module_aliases(tree) | {"_vo"}
        direct = {a.asname or a.name for n in ast.walk(tree)
                  if isinstance(n, ast.ImportFrom) and n.module and "value_origin" in n.module
                  for a in n.names if a.name in CORE_FNS}

        def refers(node):
            if (isinstance(node, ast.Attribute) and node.attr in CORE_FNS
                    and isinstance(node.value, ast.Name) and node.value.id in aliases):
                return node.attr
            if isinstance(node, ast.Name) and node.id in direct and isinstance(node.ctx, ast.Load):
                return node.id
            return None
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "getattr" \
                    and n.args and isinstance(n.args[0], ast.Name) and n.args[0].id in aliases:
                out.append((f"xaidr/{rel}:{n.lineno}", "getattr(value_origin, ...)", False))
            name = refers(n)
            if not name:
                continue
            parent = parents.get(n)
            if isinstance(parent, ast.Call) and parent.func is n:
                out.append((f"xaidr/{rel}:{n.lineno}", name, _guarded(parent, parents)))
            else:
                out.append((f"xaidr/{rel}:{n.lineno}", f"{name} (a reference, not a guarded call)", False))
    return out


def test_the_sweep_sees_every_call_site():
    """Non-vacuity: the sites this sweep was written against are all found."""
    sites = {(s.split(":")[0], n) for s, n, _ in call_sites()}
    for want in (("xaidr/sensor.py", "evaluate_call"), ("xaidr/sensor.py", "record_tool_result"),
                 ("xaidr/sensor.py", "record_principal_input"),
                 ("xaidr/provenance_chain.py", "bind_fresh_ledger"),
                 ("xaidr/provenance_chain.py", "unbind_ledger"),
                 ("xaidr/scanner/url_parse.py", "classify_value")):
        assert want in sites, (want, sorted(sites))


def test_every_call_into_the_core_is_fault_guarded():
    bad = [f"{site} {name}()" for site, name, ok in call_sites() if not ok]
    assert not bad, ("calls into the value-origin core that a fault would propagate from "
                     "into the host (wrap each in try/except Exception, log it): " + "; ".join(bad))


# ── 2 · behavioural: every public entry point, with the core function it reaches raising ──
class _Null:
    def report(self, *a, **k):
        pass

    def close(self, *a, **k):
        pass


def _sensor(mode="record", **kw):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return xaidr.Sensor(agent_id="sweep", value_origin=mode, reporter=_Null(), **kw)


def _isolated(fn):
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(fn).result()


def _p_scan(direction):
    return lambda: _sensor().scan("summarise the quarterly report", direction=direction)


def _p_a2a():
    import json
    msg = json.dumps({"jsonrpc": "2.0", "method": "message/send", "id": "1",
                      "params": {"message": {"role": "user", "parts": [{"kind": "text", "text": "hi"}]}}})
    return _sensor().scan_a2a(msg, "peer", received=True)


def _p_tool_call():
    r = _sensor().scan_tool_call("http_get", {"url": "https://api.example.com/"})
    assert r.value_origin is None, "an evaluate_call fault must OMIT the field, never fill it"
    return r


def _p_internal_result():
    return _sensor()._scan_tool_result("see https://evil.test/x", tool="web_fetch",
                                       arguments={"url": "https://news.example/"},
                                       raw_result="see https://evil.test/x")


def _p_protect_tools_sync():
    def fetch(url: str):
        return "see https://evil.test/x"
    assert _sensor().protect_tools([fetch])[0]("https://news.example/") == "see https://evil.test/x"


def _p_protect_tools_async():
    async def fetch(url: str):
        return "see https://evil.test/x"
    out = asyncio.run(_sensor().protect_tools([fetch])[0]("https://news.example/"))
    assert out == "see https://evil.test/x"


def _p_protect_tools_no_impl():
    class NoImpl:
        name = "noop_tool"
        description = "nothing"
    w = _sensor().protect_tools([NoImpl()])[0]
    call = getattr(w, "func", None) or getattr(w, "_run", None) or w
    assert call() is None


def _p_langchain_hook():
    import fake_frameworks as fakes
    from xaidr.autopatch.manifest import XaidrProtectionWarning
    fakes.install_langchain_core()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", XaidrProtectionWarning)
            warnings.simplefilter("ignore")
            p = xaidr.protect(targets=["langchain_core"], quiet=True, reporter=_Null(),
                              agent_id="sweep-lc", value_origin="record", enforcement_mode="monitor")
        tool = sys.modules["langchain_core.tools"].BaseTool("read_doc", lambda path: "see https://evil.test/x")
        return tool.run({"path": "ops.md"})
    finally:
        fakes.uninstall(("langchain_core", "langchain"))


def _p_mcp_hook():
    import fake_frameworks as fakes
    from xaidr.autopatch.manifest import XaidrProtectionWarning
    mcp = fakes.install_mcp()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", XaidrProtectionWarning)
            warnings.simplefilter("ignore")
            xaidr.protect(targets=["mcp"], quiet=True, reporter=_Null(), agent_id="sweep-mcp",
                          value_origin="record", enforcement_mode="monitor")
        session = mcp.ClientSession(handler=lambda name, args: "see https://evil.test/x")
        return asyncio.run(session.call_tool("fetch", {"url": "https://news.example/"}))
    finally:
        fakes.uninstall(("mcp",))


def _p_begin_flow():
    from xaidr import provenance_chain as pc
    pc.begin_flow(principal="alice")
    try:
        w = _sensor().scan_tool_call("http_get", {"url": "https://api.example.com/"}).value_origin
        assert w is not None and w.wire.value == "ledger_absent", (
            "a failed bind must surface as the ledger_absent row, not as silence", w)
    finally:
        pc.clear_flow()


def _p_extract_context():
    from xaidr import provenance_chain as pc
    try:
        pc.extract_context({})
        # the inbound mark, the security-critical half, must survive a bind fault
        assert pc.is_delegated("anyone") is True or pc._inbound_ctx.get() is True
    finally:
        pc.clear_flow()


def _p_clear_flow():
    from xaidr import provenance_chain as pc
    pc.begin_flow()
    pc.clear_flow()


def _p_record_hop():
    from xaidr import provenance_chain as pc
    pc.record_hop("agent-a")
    pc.clear_flow()


def _p_build_provenance():
    from xaidr import provenance_chain as pc
    pc.build_provenance("agent-a", on_behalf_of="u")
    pc.clear_flow()


# (id, core function made to raise, does the path REACH it?, entry point). Every
# PUBLIC entry point that can reach recording or evaluation; a new one belongs
# here. A path declared to reach the function must invoke it (so its row is
# not vacuous), and one declared not to must not (outputs record nothing, C-2;
# record_hop binds nothing since ruling 3.1 changed). M-sweep review: five rows
# had silently reached nothing and asserted nothing.
PATHS = [
    ("scan(input)", "record_principal_input", True, _p_scan("input")),
    ("scan(tool_result)", "record_tool_result", True, _p_scan("tool_result")),
    ("scan(output)", "record_principal_input", False, _p_scan("output")),
    ("scan_output", "record_principal_input", False, lambda: _sensor().scan_output("a reply")),
    ("scan_a2a(received)", "record_principal_input", True, _p_a2a),
    ("scan_tool_call", "evaluate_call", True, _p_tool_call),
    ("_scan_tool_result (LangChain/MCP verdict source)", "record_tool_result", True, _p_internal_result),
    ("protect_tools sync", "record_tool_result", True, _p_protect_tools_sync),
    ("protect_tools async", "record_tool_result", True, _p_protect_tools_async),
    ("protect_tools no implementation", "record_tool_result", False, _p_protect_tools_no_impl),
    ("protect() LangChain BaseTool.run hook", "record_tool_result", True, _p_langchain_hook),
    ("protect() MCP ClientSession.call_tool hook", "record_tool_result", True, _p_mcp_hook),
    ("begin_flow", "bind_fresh_ledger", True, _p_begin_flow),
    ("extract_context", "bind_fresh_ledger", True, _p_extract_context),
    ("clear_flow", "unbind_ledger", True, _p_clear_flow),
    ("record_hop", "bind_ledger", False, _p_record_hop),
    ("build_provenance", "bind_ledger", False, _p_build_provenance),
]


@pytest.mark.parametrize("pid, fn, reaches, path", PATHS, ids=[p[0] for p in PATHS])
def test_a_core_fault_never_reaches_the_caller(monkeypatch, caplog, pid, fn, reaches, path):
    calls = {"n": 0}

    def boom(*a, **k):
        calls["n"] += 1
        raise RuntimeError(f"sweep: injected {fn} fault")
    monkeypatch.setattr(vo, fn, boom)
    with caplog.at_level(logging.ERROR, logger="xaidr"):
        try:
            _isolated(path)
        except RuntimeError as e:
            if "sweep: injected" in str(e):
                pytest.fail(f"[{pid}] a raising {fn}() reached the caller: {e}", pytrace=False)
            raise
    if not reaches:
        assert calls["n"] == 0, f"[{pid}] was declared to reach no {fn}() and reached it"
        return
    assert calls["n"] > 0, (f"[{pid}] never invoked {fn}(): this row would assert nothing "
                            "(fix the row, not the code)")
    assert any(r.levelno >= logging.ERROR for r in caplog.records), (
        f"[{pid}] {fn}() raised and nothing was logged: a fault must never be silent")
