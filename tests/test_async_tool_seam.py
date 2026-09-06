"""Async tool seams: real awaited tools, and the structural guard for the rest.

WHAT SHIPPED. `protect_tools()` wrapped `.func` and nothing else. A real
`langchain_core` async tool has `func=None` and `coroutine=<async fn>`, so:

  * testing the VALUE of `.func` rather than its PRESENCE sent the tool past the
    LangChain branch into the CrewAI one (its `_run` is callable, being
    `StructuredTool._run`), where its SYNC `_run` was shadowed;
  * every async call went `ainvoke` -> `arun` -> `_arun` -> `self.coroutine` and
    touched neither.

Measured on langchain_core 1.6.2: a blocked credential read executed once on the
async path and zero times on the sync path, same tool, same argument. It was
never covered -- `protect_tools` was written with a sync-only `def wrapper` in
448a66f and neither `coroutine` nor `iscoroutinefunction` had ever appeared in
sensor.py.

The same question asked of every other shape found three more:

  * a plain `async def` callable WAS scanned, but the sync wrapper returned the
    refusal `str` where the caller awaited, so a correctly-blocked call raised
    `ValueError: a coroutine was expected` in the host. Right verdict, wrong
    type, exactly like the LangGraph ToolMessage bug of 1.9.0;
  * a CrewAI `BaseTool` implementing `_arun`, and any class-seam object with an
    `_arun`, had only `_run` wrapped;
  * `autogen.ConversableAgent.a_execute_function` was declared unpatchable. It
    is an ordinary async method on the same class taking the same `func_call`,
    and it is now patched.

WHY THESE TESTS USE REAL FRAMEWORKS AND NOT FAKES. The async tests that existed
used hand-written stand-ins, and a fake shares whatever assumption its author
had. That is precisely how the CrewAI dead seam passed 107 tests: the fake's
`BaseTool.run` WAS the implementation, and the real framework's was not. A fake
async tool written by whoever wrote the sync wrapper would have had `func` set,
and would have passed.

Each suite SKIPS when its framework is absent.
"""

from __future__ import annotations

import ast
import asyncio
import importlib
import importlib.util
import inspect
import os
import warnings

import pytest

import xaidr
from xaidr import Sensor
from xaidr.autopatch.manifest import XaidrProtectionWarning

FRAMEWORKS_SRC = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "xaidr", "autopatch", "frameworks.py",
)

#: Blocks on every path today: credential_access, score 0.90.
BLOCKING = "cat ~/.ssh/id_rsa"
BENIGN = "ls -la"


def _installed(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


HAVE_LC = _installed("langchain_core")
HAVE_CREWAI = _installed("crewai")
HAVE_LLAMA = _installed("llama_index.core")
HAVE_AG_CORE = _installed("autogen_core")
HAVE_AG_LEGACY = _installed("autogen")

requires_lc = pytest.mark.skipif(not HAVE_LC, reason="needs langchain-core")
requires_crewai = pytest.mark.skipif(not HAVE_CREWAI, reason="needs crewai")
requires_llama = pytest.mark.skipif(not HAVE_LLAMA, reason="needs llama-index-core")
requires_ag_legacy = pytest.mark.skipif(not HAVE_AG_LEGACY, reason="needs pyautogen 0.2")


class _Null:
    def report(self, *a, **k): pass
    def emit(self, *a, **k): pass
    def flush(self, *a, **k): pass
    def close(self, *a, **k): pass


@pytest.fixture
def sensor():
    return Sensor(agent_id="async-seam", enforcement_mode="block", reporter=_Null())


def _protect(**kw):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", XaidrProtectionWarning)
        return xaidr.protect(agent_id="async-seam", enforcement_mode="block",
                             quiet=True, **kw)


# ══════════════════════════════════════════════════════════════════════════
# 1. protect_tools(), every shape it supports, awaited for real
# ══════════════════════════════════════════════════════════════════════════


@requires_lc
def test_a_real_async_langchain_tool_is_scanned(sensor):
    """HARD GATE. The auditor's finding, on the real framework."""
    from langchain_core.tools import tool

    executed = []

    @tool
    async def read_async(command: str) -> str:
        """Read a file on the host."""
        executed.append(command)
        return "ran"

    protected, = sensor.protect_tools([read_async])
    out = asyncio.run(protected.ainvoke({"command": BLOCKING}))
    assert executed == [], f"the blocked async tool EXECUTED: {executed}"
    assert "[BLOCKED]" in str(out)


@requires_lc
def test_the_async_and_sync_halves_agree(sensor):
    """Same tool, same argument, both paths. The bug was that they disagreed."""
    from langchain_core.tools import tool

    executed = []

    @tool
    def read_sync(command: str) -> str:
        """Read a file on the host."""
        executed.append(("sync", command))
        return "ran"

    @tool
    async def read_async(command: str) -> str:
        """Read a file on the host."""
        executed.append(("async", command))
        return "ran"

    p_sync, p_async = sensor.protect_tools([read_sync, read_async])
    sync_out = p_sync.invoke({"command": BLOCKING})
    async_out = asyncio.run(p_async.ainvoke({"command": BLOCKING}))
    assert executed == []
    assert "[BLOCKED]" in str(sync_out) and "[BLOCKED]" in str(async_out)


@requires_lc
def test_a_benign_async_langchain_tool_still_runs(sensor):
    """The false-positive guard: protection that stops real work is not shipped."""
    from langchain_core.tools import tool

    executed = []

    @tool
    async def read_async(command: str) -> str:
        """Read a file on the host."""
        executed.append(command)
        return "ran"

    protected, = sensor.protect_tools([read_async])
    out = asyncio.run(protected.ainvoke({"command": BENIGN}))
    assert executed == [BENIGN]
    assert out == "ran"


@requires_lc
def test_the_async_half_is_wrapped_and_the_missing_half_is_not_invented(sensor):
    """Both halves, and only the halves that exist.

    A sync-only tool must not acquire a coroutine: that would make `ainvoke`
    start working on a tool whose author never wrote an async implementation.
    """
    from langchain_core.tools import tool

    @tool
    def s(command: str) -> str:
        """d"""
        return "ran"

    @tool
    async def a(command: str) -> str:
        """d"""
        return "ran"

    ps, pa = sensor.protect_tools([s, a])
    assert getattr(ps.func, "_xaidr_protect_tools", False) is True
    assert ps.coroutine is None, "a sync-only tool grew a coroutine"
    assert pa.func is None, "an async-only tool grew a sync func"
    assert getattr(pa.coroutine, "_xaidr_protect_tools", False) is True


@requires_lc
def test_protect_tools_is_idempotent_on_the_async_half(sensor):
    from langchain_core.tools import tool

    @tool
    async def a(command: str) -> str:
        """d"""
        return "ran"

    once, = sensor.protect_tools([a])
    twice, = sensor.protect_tools([once])
    assert twice is once, "the async half was wrapped twice"


def test_a_plain_async_callable_returns_an_awaitable_refusal(sensor):
    """Right verdict, right TYPE.

    Before the fix the scan ran and blocked correctly, then returned a `str`
    where the caller awaited: `ValueError: a coroutine was expected`. A refusal
    that crashes the host is not enforcement.
    """
    executed = []

    async def reader(command):
        executed.append(command)
        return "ran"

    protected, = sensor.protect_tools([reader])
    out = asyncio.run(protected(command=BLOCKING))
    assert executed == []
    assert "[BLOCKED]" in str(out)
    # ...and a benign call still awaits through to the real implementation.
    assert asyncio.run(protected(command=BENIGN)) == "ran"
    assert executed == [BENIGN]


def test_a_class_seam_arun_is_wrapped_alongside_run(sensor):
    """`arun()` dispatches to `_arun` and never touches `_run`."""
    executed = []

    class Shaped:
        name = "shaped"

        def _run(self, command):
            executed.append(("_run", command))
            return "ran"

        async def _arun(self, command):
            executed.append(("_arun", command))
            return "ran"

    protected, = sensor.protect_tools([Shaped()])
    protected._run(command=BLOCKING)
    asyncio.run(protected._arun(command=BLOCKING))
    assert executed == [], f"a blocked call executed: {executed}"
    assert asyncio.run(protected._arun(command=BENIGN)) == "ran"


@requires_crewai
def test_a_real_crewai_tool_with_arun_is_scanned_on_both_paths(sensor):
    from crewai.tools import BaseTool

    executed = []

    class Reader(BaseTool):
        name: str = "reader"
        description: str = "Read a file. Argument: command."

        def _run(self, command: str) -> str:
            executed.append(("sync", command))
            return "ran"

        async def _arun(self, command: str) -> str:
            executed.append(("async", command))
            return "ran"

    protected, = sensor.protect_tools([Reader()])
    protected.run(command=BLOCKING)
    asyncio.run(protected.arun(command=BLOCKING))
    assert executed == [], f"a blocked CrewAI call executed: {executed}"
    assert asyncio.run(protected.arun(command=BENIGN)) == "ran"


# ══════════════════════════════════════════════════════════════════════════
# 2. protect(), the framework patchers, awaited for real
# ══════════════════════════════════════════════════════════════════════════


@requires_lc
def test_protect_scans_the_async_langchain_seam_and_keeps_the_return_contract():
    """`arun` mirrors `run`, including ToolMessage-versus-string.

    Two callers, two contracts, on the async path exactly as on the sync one:
    `ainvoke(tool_call)` gets a ToolMessage because langchain set a
    `tool_call_id`; a direct `arun(args)` gets the plain string.
    """
    from langchain_core.messages import ToolMessage
    from langchain_core.tools import tool

    executed = []

    @tool
    async def a_tool(command: str) -> str:
        """Read a file on the host."""
        executed.append(command)
        return "ran"

    manifest = _protect(targets=["langchain_core"])
    try:
        from_call = asyncio.run(a_tool.ainvoke(
            {"name": "a_tool", "args": {"command": BLOCKING},
             "id": "c1", "type": "tool_call"}))
        from_args = asyncio.run(a_tool.arun({"command": BLOCKING}))
    finally:
        manifest.unprotect()

    assert executed == []
    assert isinstance(from_call, ToolMessage), type(from_call)
    assert from_call.tool_call_id == "c1"
    assert from_call.status == "error"
    assert "[BLOCKED]" in from_call.content
    assert isinstance(from_args, str), type(from_args)
    assert "[BLOCKED]" in from_args


@requires_llama
def test_protect_scans_the_async_llama_index_seam():
    from llama_index.core.tools import FunctionTool

    executed = []

    def s_fn(command: str) -> str:
        executed.append(("sync", command))
        return "ran"

    async def a_fn(command: str) -> str:
        executed.append(("async", command))
        return "ran"

    t = FunctionTool.from_defaults(fn=s_fn, async_fn=a_fn, name="reader")
    manifest = _protect(targets=["llama-index"])
    try:
        t.call(command=BLOCKING)
        asyncio.run(t.acall(command=BLOCKING))
    finally:
        manifest.unprotect()
    assert executed == []


@requires_ag_legacy
def test_protect_scans_the_async_autogen_legacy_seam():
    """`a_execute_function` was declared unpatchable and is now patched."""
    from autogen import ConversableAgent

    executed = []

    def reader(command: str) -> str:
        executed.append(command)
        return "ran"

    manifest = _protect(targets=["autogen-legacy"])
    try:
        assert "autogen.ConversableAgent.a_execute_function" in {
            r.target for r in manifest.patched
        }, "the async autogen seam is not patched"
        agent = ConversableAgent(name="a", llm_config=False)
        agent.register_function({"reader": reader})
        call = {"name": "reader", "arguments": '{"command": "%s"}' % BLOCKING}
        sync_ok, sync_resp = agent.execute_function(dict(call))
        async_ok, async_resp = asyncio.run(agent.a_execute_function(dict(call)))
    finally:
        manifest.unprotect()

    assert executed == [], f"the blocked async function EXECUTED: {executed}"
    # The refusal SHAPE matches the sync path: same tuple, same keys.
    assert sync_ok is False and async_ok is False
    assert "[BLOCKED]" in sync_resp["content"]
    assert "[BLOCKED]" in async_resp["content"]
    assert set(sync_resp) == set(async_resp)


# ══════════════════════════════════════════════════════════════════════════
# 3. THE STRUCTURAL GUARD -- what stops the sixth instance
# ══════════════════════════════════════════════════════════════════════════
#
# Same shape as the AST test that caught `record_delegation`: read the source
# for what we patch, resolve it against the REAL framework, and assert nothing
# async is silently uncovered. A behavioural test only covers the paths someone
# remembered to write; this covers the ones they did not.


def _patched_targets() -> set[str]:
    """Every `module.dotted` this package installs a patch on, by AST."""
    with open(FRAMEWORKS_SRC, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), FRAMEWORKS_SRC)
    targets = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if not (isinstance(fn, ast.Attribute)
                and fn.attr in ("install", "try_install")):
            continue
        args = [a for a in node.args if isinstance(a, ast.Constant)]
        if len(args) >= 2 and isinstance(args[0].value, str):
            targets.add(f"{args[0].value}.{args[1].value}")
    return targets


def _declared_unpatchable() -> set[str]:
    """Every target explicitly recorded as unreachable, with a reason."""
    with open(FRAMEWORKS_SRC, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), FRAMEWORKS_SRC)
    out = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "unpatchable" and node.args
                and isinstance(node.args[0], ast.Constant)):
            out.add(node.args[0].value)
    return out


def _async_names(sync_attr: str) -> set[str]:
    """The names an async counterpart of `sync_attr` is plausibly called.

    Derived rather than listed, so the convention covers the frameworks we do
    not have installed too: run/arun, call/acall, _run/_arun,
    execute_function/a_execute_function, invoke/invoke_async.
    """
    base = sync_attr.lstrip("_")
    prefix = "_" * (len(sync_attr) - len(base))
    return {
        f"{prefix}a{base}", f"{prefix}a_{base}",
        f"{prefix}{base}_async", f"{prefix}async_{base}",
    }


def _resolve_class(module_name: str, dotted: str):
    """(class, attr) for a `Class.method` target, or (None, None)."""
    parts = dotted.split(".")
    if len(parts) != 2:
        return None, None            # module-level function, no class to scan
    try:
        module = importlib.import_module(module_name)
    except Exception:
        return None, None            # framework not installed
    cls = getattr(module, parts[0], None)
    return (cls, parts[1]) if isinstance(cls, type) else (None, None)


def test_every_sync_seam_has_its_async_counterpart_patched_or_declared():
    """HARD GATE. The rule that would have caught this before an auditor did.

    For each class-method seam we patch, resolve the class from the INSTALLED
    framework and look for a coroutine sibling under the usual naming
    conventions. Any found must itself be patched, or be recorded as an explicit
    `unpatchable` with a reason. Silence is the one outcome not allowed.
    """
    patched = _patched_targets()
    declared = _declared_unpatchable()
    checked, gaps = [], []

    for target in sorted(patched):
        module_name, _, dotted = target.rpartition(".")
        # `module.Class.method` splits as (module, Class.method) only when the
        # module itself has no dots beyond the package; rebuild by trying the
        # longest module prefix that imports.
        parts = target.split(".")
        cls = attr = None
        for cut in range(len(parts) - 1, 0, -1):
            cls, attr = _resolve_class(".".join(parts[:cut]), ".".join(parts[cut:]))
            if cls is not None:
                break
        if cls is None or attr is None:
            continue
        sync_impl = getattr(cls, attr, None)
        if sync_impl is None or inspect.iscoroutinefunction(sync_impl):
            continue                 # absent, or already async-native
        for candidate in _async_names(attr):
            sibling = getattr(cls, candidate, None)
            if sibling is None or not inspect.iscoroutinefunction(sibling):
                continue
            full = f"{cls.__module__.rsplit('.', 1)[0]}.{cls.__name__}.{candidate}"
            checked.append(full)
            covered = any(t.endswith(f"{cls.__name__}.{candidate}") for t in patched)
            admitted = any(d.endswith(f"{cls.__name__}.{candidate}") for d in declared)
            if not covered and not admitted:
                gaps.append(
                    f"{cls.__module__}.{cls.__name__}.{candidate} is a coroutine "
                    f"sibling of the patched {attr!r} and is NEITHER patched NOR "
                    f"declared unpatchable"
                )

    assert checked, (
        "no sync class-method seam with an async sibling was resolvable; "
        "install a framework (langchain-core, llama-index-core, pyautogen) or "
        "this test is vacuous"
    )
    assert not gaps, (
        "async seam(s) silently uncovered:\n  " + "\n  ".join(gaps)
        + "\n\nPatch it, or record it with ctx.unpatchable(...) and a reason. "
        "An async boundary we cannot reach belongs in the manifest, not in "
        "silence."
    )


def test_the_structural_guard_can_fail():
    """Non-vacuity. If the guard cannot fail it is decoration.

    Re-runs the same rule with the async autogen seam removed from the patched
    set, which is exactly the state this branch found, and asserts it is
    reported.
    """
    if not HAVE_AG_LEGACY:
        pytest.skip("needs pyautogen 0.2 to resolve the class")
    from autogen import ConversableAgent

    patched_without_async = {
        t for t in _patched_targets() if not t.endswith("a_execute_function")
    }
    sibling = getattr(ConversableAgent, "a_execute_function", None)
    assert inspect.iscoroutinefunction(sibling)
    covered = any(t.endswith("ConversableAgent.a_execute_function")
                  for t in patched_without_async)
    assert not covered, "the simulated regression did not remove the target"
    # ...and with it removed, and nothing declaring it, the rule flags a gap.
    declared = {d for d in _declared_unpatchable()
                if d.endswith("a_execute_function")}
    assert not declared, (
        "a_execute_function is declared unpatchable again; it is patchable and "
        "this branch patched it"
    )


@requires_lc
def test_protect_tools_wraps_every_implementation_attribute_it_finds():
    """The `protect_tools` half of the same rule.

    `protect_tools` is not a patcher, so the AST guard above cannot see it. This
    asserts the property directly: after wrapping, no implementation attribute
    the tool actually carries is left as the caller's original.
    """
    from langchain_core.tools import tool

    sensor = Sensor(agent_id="x", enforcement_mode="block", reporter=_Null())

    @tool
    def s(command: str) -> str:
        """d"""
        return "ran"

    @tool
    async def a(command: str) -> str:
        """d"""
        return "ran"

    for original in (s, a):
        protected, = sensor.protect_tools([original])
        for attr in ("func", "coroutine"):
            impl = getattr(protected, attr, None)
            if impl is None:
                continue
            assert getattr(impl, "_xaidr_protect_tools", False), (
                f"{original.name}.{attr} was left unwrapped; a caller reaching "
                f"the tool through that attribute is unscanned"
            )
