"""Run-tree capture: every event emitted inside a LangChain/LangGraph run says
which flow it belongs to (docs/run-tree-spec.md, rulings Q-R1 and D1-D4).

The flow key is the ROOT run id LangChain minted. Two properties carry the
security weight and are asserted as such:

* **No synthesized root (D2).** An event outside any run carries
  ``runTree: "no_run"`` and no ids. A guessed root is how two flows end up
  sharing one.
* **No merged root.** Two flows that run at the same time never carry the same
  ``runRootId``, including when a caller hands both the same ``run_id``. One
  flow's principal input vouching for another flow's tool call is the failure
  value origin exists to prevent, so a merged root is a security failure, not a
  cosmetic one.

Real LangChain and LangGraph throughout: a fake framework would share whatever
assumption the handler was written under. Each test SKIPS when the stack is
absent; the real-frameworks CI job installs it at the pinned versions and
refuses an all-skipped run.
"""

from __future__ import annotations

import asyncio
import gc
import importlib.util
import json
import logging
import os
import subprocess
import sys
import threading
import time
import tracemalloc
import uuid
import warnings

import pytest

import xaidr
from xaidr.autopatch.manifest import XaidrProtectionWarning


def _installed(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


HAVE_STACK = all(_installed(m) for m in ("langchain_core", "langchain", "langgraph"))
requires_stack = pytest.mark.skipif(
    not HAVE_STACK, reason="needs langchain-core + langchain + langgraph")

#: LangChain sets the run config in a COPIED context and can hand that context
#: to async code only through ``asyncio.create_task(context=...)``, which
#: Python added in 3.11 (``langchain_core.runnables.utils.asyncio_accepts_context``).
#: On 3.10 an async node's events therefore cannot be placed in their run. They
#: must say so (``unknown_run``, no ids), never claim ``no_run`` or carry a root;
#: ``test_py310_async_events_are_unplaceable_never_rooted`` asserts exactly that.
ASYNC_CONTEXT = sys.version_info >= (3, 11)
async_needs_context = pytest.mark.xfail(
    not ASYNC_CONTEXT, strict=True,
    reason="Python < 3.11: asyncio.create_task takes no context, so LangChain cannot "
           "carry the run config into an async node; events there are unknown_run")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN_KEYS = ("runTree", "runRootId", "runTaskId", "runParentId", "runNode",
            "runNodePath", "runStep", "runSeq", "runSource", "toolCallId")


class _Capture:
    def __init__(self):
        self.events: list = []
        self._lock = threading.Lock()

    def report(self, batch):
        with self._lock:
            self.events.extend(batch)

    def close(self):
        pass

    def data(self):
        with self._lock:
            return [e["data"] for e in self.events if e.get("type") == "scan"]


def _protect(cap, **kwargs):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", XaidrProtectionWarning)
        return xaidr.protect(agent_id="run-tree", quiet=True, reporter=cap, **kwargs)


def _drain(manifest):
    manifest.sensor.flush()


def _brief(events):
    return [{k: e.get(k) for k in ("direction", "toolName", "runTree", "runRootId",
                                   "runNode", "toolCallId")} for e in events]


# ── the fixture graph: the 8 Oct experiment's shape, no network ─────────────


@pytest.fixture
def stack():
    """Build-a-graph helpers. ``create_agent`` is looked up at BUILD time, so a
    graph built after ``protect()`` gets the patched builder."""
    import langchain.agents
    import langchain.agents.middleware  # noqa: F401  (protect() needs it loaded)
    from langchain_core.documents import Document
    from langchain_core.language_models.fake_chat_models import (
        FakeMessagesListChatModel,
    )
    from langchain_core.messages import AIMessage, SystemMessage
    from langchain_core.retrievers import BaseRetriever
    from langchain_core.tools import tool
    from langgraph.graph import END, START, MessagesState, StateGraph

    gates: dict = {}

    @tool
    def lookup_customer(customer_id: str) -> str:
        """Look up a customer."""
        gate = gates.get("lookup_customer")
        if gate is not None:
            gate.wait(timeout=10)
        return f"Customer {customer_id}: plan Gold."

    @tool
    def record_note(customer_id: str, text: str) -> str:
        """Record a note on a customer account."""
        gate = gates.get("record_note")
        if gate is not None:
            gate.wait(timeout=10)
        return f"Note recorded for {customer_id}."

    class KB(BaseRetriever):
        def _get_relevant_documents(self, query, *, run_manager=None):
            return [Document(page_content="Resolution code: RC-DOA-14.",
                             metadata={"id": "kb-refund"})]

    class FakeModel(FakeMessagesListChatModel):
        def bind_tools(self, tools, **kwargs):
            return self

    def calls(*names):
        out = []
        for i, name in enumerate(names, start=1):
            args = {"customer_id": "C-1001"}
            if name == "record_note":
                args["text"] = "callback Friday"
            out.append(AIMessage(content="", tool_calls=[
                {"name": name, "args": args, "id": f"call_{i}"}]))
        return out + [AIMessage(content="Done.")]

    def agent(*tool_names, builder=None):
        build = builder or langchain.agents.create_agent
        return build(model=FakeModel(responses=calls(*tool_names)),
                     tools=[lookup_customer, record_note])

    def graph(*tool_names, builder=None):
        retriever = KB()

        def retrieve_context(state):
            docs = retriever.invoke(state["messages"][-1].content)
            return {"messages": [SystemMessage(content=docs[0].page_content)]}

        def support_agent(state):
            inner = agent(*tool_names, builder=builder)
            return {"messages": inner.invoke({"messages": state["messages"]})["messages"]}

        g = StateGraph(MessagesState)
        g.add_node("retrieve_context", retrieve_context)
        g.add_node("support_agent", support_agent)
        g.add_edge(START, "retrieve_context")
        g.add_edge("retrieve_context", "support_agent")
        g.add_edge("support_agent", END)
        return g.compile()

    def toolnode_graph(*tool_names):
        """model -> tools -> model, with a prebuilt ToolNode and an ASYNC model
        node: the BaseTool.arun / AsyncCallbackManager path."""
        from langgraph.prebuilt import ToolNode

        model = FakeModel(responses=calls(*tool_names))

        async def model_node(state):
            return {"messages": [await model.ainvoke(state["messages"])]}

        def route(state):
            last = state["messages"][-1]
            return "tools" if getattr(last, "tool_calls", None) else END

        g = StateGraph(MessagesState)
        g.add_node("model", model_node)
        g.add_node("tools", ToolNode([lookup_customer, record_note]))
        g.add_edge(START, "model")
        g.add_conditional_edges("model", route, ["tools", END])
        g.add_edge("tools", "model")
        return g.compile()

    class Bits:
        pass

    bits = Bits()
    bits.graph, bits.agent, bits.toolnode_graph = graph, agent, toolnode_graph
    bits.lookup_customer, bits.record_note, bits.gates = lookup_customer, record_note, gates
    return bits


def _user(text="Customer C-1001 asks about T-100. Note: callback Friday"):
    return {"messages": [("user", text)]}


# ══════════════════════════════════════════════════════════════════════════
# T1 · one graph run, one root, every event stamped
# ══════════════════════════════════════════════════════════════════════════


@requires_stack
class TestRealRunTree:

    def test_t1_every_event_in_one_graph_run_carries_one_root(self, stack):
        cap = _Capture()
        m = _protect(cap)
        try:
            stack.graph("lookup_customer", "record_note").invoke(_user())
            _drain(m)
        finally:
            m.unprotect()
        events = cap.data()
        assert len(events) >= 8, f"expected the 8 events the probe measured, got {_brief(events)}"
        unstamped = [e for e in events if e.get("runTree") != "stamped"]
        assert not unstamped, (
            "events emitted INSIDE a LangGraph run carry no flow key, so the Brain "
            f"cannot tell which flow they belong to: {_brief(unstamped)}")
        roots = {e["runRootId"] for e in events}
        assert len(roots) == 1, f"one invoke produced {len(roots)} roots: {_brief(events)}"
        root = roots.pop()
        assert str(uuid.UUID(root)) == root, f"runRootId is not a canonical UUID: {root!r}"
        assert all(e["runSource"] == "langchain" for e in events)
        assert all(e["runTaskId"] != root for e in events), (
            "an event's task is the run executing when it was emitted, never the root")
        seqs = [e["runSeq"] for e in events]
        assert sorted(seqs) == list(range(1, len(events) + 1)), (
            f"runSeq is not a gap-free in-flow order 1..n: {seqs}")
        calls = [e for e in events if e["direction"] == "tool_call"]
        assert {e["runNode"] for e in calls} == {"tools"}, _brief(calls)
        assert all(e["runNodePath"] == ["support_agent", "tools"] for e in calls), (
            f"the outer graph node is missing from the path: {[e['runNodePath'] for e in calls]}")
        assert all(isinstance(e["runStep"], int) and not isinstance(e["runStep"], bool)
                   for e in calls)

    # ══════════════════════════════════════════════════════════════════════
    # T2 · concurrent flows never share a root (and a reused run_id is a
    # collision, never a merge)
    # ══════════════════════════════════════════════════════════════════════

    def test_t2_two_concurrent_flows_never_share_a_root(self, stack):
        cap = _Capture()
        m = _protect(cap)
        errors: list = []

        def flow(tool_name):
            try:
                for _ in range(5):
                    stack.agent(tool_name).invoke(_user(f"flow {tool_name}"))
            except Exception as exc:  # surfaced below, never swallowed
                errors.append(exc)

        try:
            threads = [threading.Thread(target=flow, args=(n,))
                       for n in ("lookup_customer", "record_note")]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=60)
            _drain(m)
        finally:
            m.unprotect()
        assert not errors, errors
        events = cap.data()
        by_root: dict = {}
        for e in events:
            if e.get("runTree") == "stamped":
                by_root.setdefault(e["runRootId"], set()).add(e.get("toolName"))
        merged = {r: t - {None} for r, t in by_root.items() if len(t - {None}) > 1}
        assert not merged, (
            "SECURITY: two concurrent flows were stamped with ONE root, so one "
            f"flow's input could vouch for the other's tool call: {merged}")
        calls = [e for e in events if e["direction"] == "tool_call"]
        assert len(calls) == 10, _brief(calls)
        assert all(e.get("runTree") == "stamped" for e in calls), (
            f"concurrent flows lost their flow key: {_brief(calls)}")
        roots = {e["runRootId"] for e in calls}
        assert len(roots) == 10, f"10 invokes produced {len(roots)} roots"

    def test_t2_a_reused_run_id_is_a_collision_never_a_merged_root(self, stack):
        """A caller-supplied ``config["run_id"]`` reused by two live flows. The
        barrier holds both inside a tool at once, so they truly overlap."""
        cap = _Capture()
        m = _protect(cap)
        shared = uuid.uuid4()
        barrier = threading.Barrier(2)
        stack.gates["lookup_customer"] = barrier
        stack.gates["record_note"] = barrier
        errors: list = []

        def flow(tool_name):
            try:
                stack.agent(tool_name).invoke(
                    _user(f"flow {tool_name}"), config={"run_id": shared})
            except Exception as exc:
                errors.append(exc)

        try:
            threads = [threading.Thread(target=flow, args=(n,))
                       for n in ("lookup_customer", "record_note")]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=60)
            _drain(m)
        finally:
            m.unprotect()
            stack.gates.clear()
        assert not errors, errors
        events = cap.data()
        stamped_shared = [e for e in events
                          if e.get("runTree") == "stamped" and e.get("runRootId") == str(shared)]
        tools = {e["toolName"] for e in stamped_shared if e.get("toolName")}
        assert len(tools) <= 1, (
            "SECURITY: two live flows that reused one run_id were both stamped "
            f"with it, a merged root: {_brief(stamped_shared)}")
        assert any(e.get("runTree") == "collision" for e in events), (
            f"the reused run_id was never reported as a collision: {_brief(events)}")

    def test_t2_a_reused_child_run_id_in_two_concurrent_flows_never_merges(self, stack):
        """Each flow has its own LangChain-minted root, and inside it the caller
        invokes a sub-runnable with a FIXED ``run_id``. Both sub-runs are live at
        once. Neither flow's events may carry the other's root, and neither
        flow may be handed a key by ``current_root()``."""
        from langchain_core.runnables import RunnableLambda

        from xaidr import run_tree

        cap = _Capture()
        m = _protect(cap)
        fixed = uuid.uuid4()
        both_in = threading.Barrier(2)
        keys: dict = {}

        def inner(flow):
            both_in.wait(10)
            m.sensor.scan(f"hello from flow {flow}")
            keys[flow] = run_tree.current_root()
            both_in.wait(10)
            return flow

        sub = RunnableLambda(inner)
        outer = RunnableLambda(lambda flow: sub.invoke(flow, config={"run_id": fixed}))
        try:
            threads = [threading.Thread(target=outer.invoke, args=(f,)) for f in "AB"]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
            _drain(m)
        finally:
            m.unprotect()
        stamped = [e for e in cap.data() if e.get("runTree") == "stamped"]
        assert len({e["runRootId"] for e in stamped}) == len(stamped) or not stamped, (
            "SECURITY: two concurrent flows that reused one CHILD run_id were "
            f"stamped with one root: {_brief(cap.data())}")
        assert all(e.get("runTree") == "collision" for e in cap.data()), (
            f"a reused child run_id must be a collision for BOTH flows: {_brief(cap.data())}")
        assert keys == {"A": None, "B": None}, (
            f"SECURITY: current_root() handed a flow key across a collision: {keys}")

    def test_t2_a_collided_root_id_stays_collided_after_the_first_flow_ends(self, stack):
        """A and B start with one caller-supplied root id (a collision). A ends
        while B is live; C then starts with the same id. B and C overlap and
        must never be stamped with that root."""
        from langchain_core.runnables import RunnableLambda

        cap = _Capture()
        m = _protect(cap)
        shared = uuid.uuid4()
        b_started, a_done, c_started = threading.Event(), threading.Event(), threading.Event()
        b_go, c_scanned, b_scanned = threading.Event(), threading.Event(), threading.Event()

        def fa(x):
            b_started.wait(10)
            return x

        def fb(x):
            b_started.set()
            a_done.wait(10)
            c_started.wait(10)
            b_go.set()
            c_scanned.wait(10)
            m.sensor.scan("flow B event")
            b_scanned.set()
            return x

        def fc(x):
            c_started.set()
            b_go.wait(10)
            m.sensor.scan("flow C event")
            c_scanned.set()
            b_scanned.wait(10)
            return x

        def run(fn, arg):
            return RunnableLambda(fn).invoke(arg, config={"run_id": shared})

        try:
            ta = threading.Thread(target=lambda: (run(fa, "a"), a_done.set()))
            tb = threading.Thread(target=run, args=(fb, "b"))
            ta.start()
            time.sleep(0.2)
            tb.start()
            ta.join(timeout=30)
            tc = threading.Thread(target=run, args=(fc, "c"))
            tc.start()
            tb.join(timeout=30)
            tc.join(timeout=30)
            _drain(m)
        finally:
            m.unprotect()
        events = cap.data()
        assert len(events) == 2, _brief(events)
        merged = [e for e in events if e.get("runRootId") == str(shared)]
        assert not merged, (
            "SECURITY: a root id that had already collided was handed out again "
            f"once the first flow ended, merging two live flows: {_brief(events)}")
        assert all(e.get("runTree") == "collision" for e in events), _brief(events)

    def test_current_root_is_the_flow_key_in_process(self, stack):
        """What value origin will key its ledger on: the same root the events
        carry inside a run, and None where there is no trustworthy root."""
        from xaidr import run_tree

        seen: list = []
        original = stack.lookup_customer.func

        def spy(customer_id: str) -> str:
            seen.append(run_tree.current_root())
            return original(customer_id)

        cap = _Capture()
        m = _protect(cap)
        stack.lookup_customer.func = spy
        try:
            stack.graph("lookup_customer").invoke(_user())
            outside = run_tree.current_root()
            _drain(m)
        finally:
            stack.lookup_customer.func = original
            m.unprotect()
        roots = {e["runRootId"] for e in cap.data()}
        assert len(roots) == 1 and seen == [roots.pop()], (seen, roots)
        assert outside is None, f"current_root() outside any run is {outside!r}, not None"

    # ══════════════════════════════════════════════════════════════════════
    # T3 · a faulting handler never reaches the host, the log, or the verdict
    # ══════════════════════════════════════════════════════════════════════

    SECRET = "SECRET-PAYLOAD-7f3a91"

    def _verdicts(self, events):
        return [(e["direction"], e["action"], e.get("category"), tuple(e.get("rules") or ()))
                for e in events]

    def test_t3_a_faulting_handler_never_reaches_the_host_or_the_log(
            self, stack, monkeypatch, caplog):
        from xaidr import run_tree

        baseline = _Capture()
        m = _protect(baseline)
        try:
            stack.graph("lookup_customer").invoke(_user())
            _drain(m)
        finally:
            m.unprotect()

        def explode(*args, **kwargs):
            raise RuntimeError(self.SECRET)

        cap = _Capture()
        m = _protect(cap)
        monkeypatch.setattr(run_tree.INDEX, "start", explode)
        caplog.set_level(logging.DEBUG)
        try:
            out = stack.graph("lookup_customer").invoke(_user())
            _drain(m)
        finally:
            m.unprotect()
        assert out["messages"][-1].content == "Done.", "the host graph did not complete"
        events = cap.data()
        assert events and all(e.get("runTree") == "fault" for e in events), (
            f"a handler fault must surface as runTree='fault', not vanish: {_brief(events)}")
        leaked = [r for r in caplog.records
                  if self.SECRET in r.getMessage() or self.SECRET in (r.exc_text or "")]
        assert not leaked, (
            "an exception MESSAGE from the run-tree handler reached the log, and "
            f"a message can carry content: {[r.getMessage() for r in leaked]}")
        assert self._verdicts(events) == self._verdicts(baseline.data()), (
            "a faulting run-tree handler changed a verdict")

    def test_t3_a_faulting_stamp_never_costs_the_event_or_the_verdict(
            self, stack, monkeypatch, caplog):
        from xaidr import run_tree

        def explode(*args, **kwargs):
            raise RuntimeError(self.SECRET)

        cap = _Capture()
        m = _protect(cap)
        monkeypatch.setattr(run_tree.INDEX, "resolve", explode)
        caplog.set_level(logging.DEBUG)
        try:
            stack.graph("lookup_customer").invoke(_user())
            _drain(m)
        finally:
            m.unprotect()
        events = cap.data()
        assert len(events) >= 4, f"a stamp fault cost events: {_brief(events)}"
        assert all(e.get("runTree") == "fault" for e in events), _brief(events)
        assert all("action" in e and "scanId" in e for e in events)
        assert not any(self.SECRET in r.getMessage() for r in caplog.records)

    # ══════════════════════════════════════════════════════════════════════
    # T5 · degradation: no synthesized root, no keys without the handler,
    # idempotent install, clean uninstall
    # ══════════════════════════════════════════════════════════════════════

    def test_t5_a_direct_tool_run_is_no_run_and_never_a_synthesized_root(self, stack):
        cap = _Capture()
        m = _protect(cap)
        try:
            stack.lookup_customer.run({"customer_id": "C-9"})
            _drain(m)
        finally:
            m.unprotect()
        events = cap.data()
        assert {e["direction"] for e in events} >= {"tool_call", "tool_result"}, _brief(events)
        assert all(e.get("runTree") == "no_run" for e in events), (
            f"a call outside any LangChain run must say no_run: {_brief(events)}")
        minted = [e for e in events
                  if any(k in e for k in ("runRootId", "runTaskId", "runParentId", "runSeq"))]
        assert not minted, (
            "SECURITY: a root was synthesized for an event that has no framework "
            f"run; a guessed root is how two flows come to share one: {_brief(minted)}")

    def test_t5_protect_twice_is_idempotent_and_unprotect_detaches(self, stack):
        from langchain_core.callbacks import manager as lc_manager

        from xaidr import run_tree
        from xaidr.autopatch.core import is_xaidr_wrapper

        original_sync = lc_manager.CallbackManager.__dict__["configure"]
        original_async = lc_manager.AsyncCallbackManager.__dict__["configure"]
        cap = _Capture()
        first = _protect(cap)
        second = _protect(cap)
        try:
            again = [r for r in second.patched if r.target.endswith("CallbackManager.configure")]
            assert again and all(r.already_patched for r in again), (
                f"a second protect() re-wrapped configure: {[(r.target, r.already_patched) for r in again]}")
            assert is_xaidr_wrapper(lc_manager.CallbackManager.configure)
        finally:
            second.unprotect()
            first.unprotect()
        assert lc_manager.CallbackManager.__dict__["configure"] is original_sync
        assert lc_manager.AsyncCallbackManager.__dict__["configure"] is original_async
        fresh = lc_manager.CallbackManager.configure()
        assert not any(type(h).__name__ == "RunTreeHandler" for h in fresh.handlers), (
            "after unprotect() a newly configured manager still carries the handler")
        assert not run_tree.is_active(), (
            "unprotect() left run-tree stamping active: events would keep "
            "carrying run keys from an index no handler feeds any more")
        after = _Capture()
        sensor = xaidr.Sensor(agent_id="after", reporter=after)
        stack.graph("lookup_customer").invoke(_user())
        sensor.scan("hello")
        sensor.flush()
        leftover = [e for e in after.data() if any(k in e for k in RUN_KEYS)]
        assert not leftover, f"run keys after unprotect(): {_brief(leftover)}"

    def test_t5_unprotect_stops_indexing_runs_already_in_flight(self, stack):
        """A callback manager configured before ``unprotect()`` keeps the
        handler for the rest of its run. After ``unprotect()`` that handler must
        index nothing, or the index refills with runs no stamp will read."""
        from xaidr import run_tree

        cap = _Capture()
        m = _protect(cap)
        handler = run_tree._handler
        m.unprotect()
        for _ in range(100):
            handler.on_chain_start({}, {}, run_id=uuid.uuid4(), parent_run_id=None,
                                   name="LangGraph", metadata={})
        assert len(run_tree.INDEX) == 0, (
            f"after unprotect() the in-flight handler indexed {len(run_tree.INDEX)} runs")

    # ══════════════════════════════════════════════════════════════════════
    # T6 · THE CANARY: capture never goes silently dead
    # ══════════════════════════════════════════════════════════════════════

    def _canary(self, stack, monkeypatch, how):
        """If a LangChain release configures callbacks WITHOUT going through
        ``CallbackManager.configure`` / ``AsyncCallbackManager.configure``, the
        handler stops seeing runs and every event on this known run stops
        carrying a root. Checked against a reference handler LangChain itself
        delivers through ``config=``, so a run LangChain dispatched and the
        run-tree handler never saw is named, and an event that lost its key is
        named separately (the handler saw its run, the stamp could not place it)."""
        from langchain_core.callbacks import BaseCallbackHandler

        from xaidr import run_tree

        class Reference(BaseCallbackHandler):
            def __init__(self):
                self.tool_runs, self.node_runs = set(), set()

            def on_tool_start(self, *a, run_id, **k):
                self.tool_runs.add(run_id)

            def on_chain_start(self, *a, run_id, metadata=None, **k):
                if (metadata or {}).get("langgraph_node") == k.get("name"):
                    self.node_runs.add(run_id)

        seen: set = set()
        original_start = run_tree.INDEX.start

        def spy(run_id, *a, **k):
            seen.add(run_id)
            return original_start(run_id, *a, **k)

        ref, cap = Reference(), _Capture()
        m = _protect(cap)
        monkeypatch.setattr(run_tree.INDEX, "start", spy)
        try:
            cfg = {"callbacks": [ref]}
            if how == "ainvoke":
                g = stack.toolnode_graph("lookup_customer", "record_note")
                asyncio.run(g.ainvoke(_user(), config=cfg))
            else:
                stack.graph("lookup_customer", "record_note").invoke(_user(), config=cfg)
            _drain(m)
        finally:
            monkeypatch.setattr(run_tree.INDEX, "start", original_start)
            m.unprotect()
        events = cap.data()
        assert ref.tool_runs and ref.node_runs, "the reference handler saw nothing"
        missed = (ref.tool_runs | ref.node_runs) - seen
        assert not missed, (
            f"CANARY ({how}): LangChain delivered {len(missed)} run(s) the run-tree "
            "handler never saw. LangChain is configuring callbacks without going "
            "through CallbackManager.configure / AsyncCallbackManager.configure; "
            "run-tree capture is DEAD on this version, not degraded.")
        unstamped = [e for e in events if e.get("runTree") != "stamped"]
        assert not unstamped, (
            f"CANARY ({how}): the handler saw every run, but {len(unstamped)} "
            "event(s) could not be placed in theirs: the run config did not reach "
            f"the point the event was emitted: {_brief(unstamped)}")

    def test_t6_canary_sync_langchain_still_routes_through_configure(self, stack, monkeypatch):
        self._canary(stack, monkeypatch, "invoke")

    @async_needs_context
    def test_t6_canary_async_langchain_still_routes_through_configure(self, stack, monkeypatch):
        self._canary(stack, monkeypatch, "ainvoke")

    # ══════════════════════════════════════════════════════════════════════
    # T7 · a tool result joins its tool call
    # ══════════════════════════════════════════════════════════════════════

    def test_t7_a_tool_result_joins_its_tool_call_by_tool_call_id(self, stack):
        cap = _Capture()
        m = _protect(cap)
        try:
            stack.graph("lookup_customer", "record_note").invoke(_user())
            _drain(m)
        finally:
            m.unprotect()
        events = cap.data()
        calls = {e.get("toolCallId"): e["toolName"]
                 for e in events if e["direction"] == "tool_call"}
        results = [e for e in events if e["direction"] == "tool_result"]
        assert set(calls) == {"call_1", "call_2"}, (
            f"tool_call events do not carry LangChain's tool_call_id: {_brief(events)}")
        assert len(results) == 2 and all(e.get("toolCallId") in calls for e in results), (
            "a tool_result cannot be joined to the tool_call that produced it; with "
            f"parallel tool calls adjacency cannot recover it: {_brief(results)}")
        assert {calls[e["toolCallId"]] for e in results} == {"lookup_customer", "record_note"}

    # ══════════════════════════════════════════════════════════════════════
    # async: the AsyncCallbackManager path
    # ══════════════════════════════════════════════════════════════════════

    @async_needs_context
    def test_async_toolnode_graph_is_stamped_on_one_root(self, stack):
        cap = _Capture()
        m = _protect(cap)
        try:
            asyncio.run(stack.toolnode_graph("lookup_customer", "record_note").ainvoke(_user()))
            _drain(m)
        finally:
            m.unprotect()
        events = cap.data()
        assert len([e for e in events if e["direction"] == "tool_call"]) == 2, _brief(events)
        assert all(e.get("runTree") == "stamped" for e in events), (
            f"events from an ainvoke'd graph lost their flow key: {_brief(events)}")
        assert len({e["runRootId"] for e in events}) == 1, _brief(events)
        assert {e["toolCallId"] for e in events if e["direction"] == "tool_result"} == {
            "call_1", "call_2"}, _brief(events)

    @async_needs_context
    def test_async_create_agent_without_middleware_is_stamped(self, stack):
        """``create_agent`` bound BEFORE ``protect()``: no middleware is injected,
        so the async agent runs and only ``BaseTool.arun`` guards its tools."""
        import langchain.agents

        unpatched = langchain.agents.create_agent
        cap = _Capture()
        m = _protect(cap)
        try:
            agent = stack.agent("lookup_customer", "record_note", builder=unpatched)
            asyncio.run(agent.ainvoke(_user()))
            _drain(m)
        finally:
            m.unprotect()
        events = cap.data()
        assert len([e for e in events if e["direction"] == "tool_call"]) == 2, _brief(events)
        assert all(e.get("runTree") == "stamped" for e in events), (
            f"events from an ainvoke'd create_agent lost their flow key: {_brief(events)}")
        assert len({e["runRootId"] for e in events}) == 1, _brief(events)

    @pytest.mark.skipif(ASYNC_CONTEXT, reason="the Python < 3.11 degradation only")
    def test_py310_async_events_are_unplaceable_never_rooted(self, stack):
        cap = _Capture()
        m = _protect(cap)
        try:
            asyncio.run(stack.toolnode_graph("lookup_customer", "record_note").ainvoke(_user()))
            _drain(m)
        finally:
            m.unprotect()
        events = [e for e in cap.data() if e["direction"] in ("tool_call", "tool_result")]
        assert len(events) == 4, _brief(events)
        assert all(e.get("runTree") == "unknown_run" for e in events), (
            "on Python < 3.11 an async node's events cannot be placed in their run; "
            "they must say unknown_run, not no_run (which claims they ran outside "
            f"any run): {_brief(events)}")
        assert not [e for e in events if "runRootId" in e], _brief(events)

    @async_needs_context
    def test_async_create_agent_with_injected_middleware_is_stamped(self, stack):
        """An async create_agent under protect() runs its tool calls through the
        middleware's async tool hook, and every event is stamped (issue #38)."""
        cap = _Capture()
        m = _protect(cap)
        try:
            asyncio.run(stack.agent("lookup_customer").ainvoke(_user()))
            _drain(m)
        finally:
            m.unprotect()
        events = cap.data()
        assert events and all(e.get("runTree") == "stamped" for e in events), _brief(events)


# ══════════════════════════════════════════════════════════════════════════
# T4 + D4 · bounded, and inside the budget
# ══════════════════════════════════════════════════════════════════════════


def _never_stamped(index, *run_ids):
    out = {}
    for rid in run_ids:
        status, run = index.resolve(rid)
        out[rid] = status
        assert status != "stamped" and run is None, (
            f"SECURITY: run {rid} resolves to a stamped root after a run-id "
            f"reuse, so two flows can share one key: status={status}")
    return out


def test_t2_index_a_reused_child_id_collides_both_flows():
    from xaidr.run_tree import RunTreeIndex

    index = RunTreeIndex()
    ra, rb, x = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    index.start(ra, None, "LangGraph")
    index.start(rb, None, "LangGraph")
    index.start(x, ra, "sub")                 # flow A's child
    index.start(x, rb, "sub")                 # flow B's child, same id
    grandchild = uuid.uuid4()
    index.start(grandchild, x, "tool")
    statuses = _never_stamped(index, x, grandchild)
    assert set(statuses.values()) == {"collision"}, statuses


def test_t2_index_a_root_id_equal_to_a_live_child_collides():
    from xaidr.run_tree import RunTreeIndex

    index = RunTreeIndex()
    ra, x = uuid.uuid4(), uuid.uuid4()
    index.start(ra, None, "LangGraph")
    index.start(x, ra, "sub")
    index.start(x, None, "LangGraph")         # flow B's root = A's live child
    grandchild = uuid.uuid4()
    index.start(grandchild, x, "tools")       # flow B's run under its root id
    statuses = _never_stamped(index, x, grandchild)
    assert set(statuses.values()) == {"collision"}, statuses


def test_t2_index_a_collided_root_id_stays_collided_after_the_first_flow_ends():
    from xaidr.run_tree import RunTreeIndex

    index = RunTreeIndex()
    r = uuid.uuid4()
    index.start(r, None, "LangGraph")         # A
    index.start(r, None, "LangGraph")         # B: collision
    index.end(r)                              # A ends, B still live
    index.start(r, None, "LangGraph")         # C reuses the id
    child = uuid.uuid4()
    index.start(child, r, "tools")
    statuses = _never_stamped(index, r, child)
    assert set(statuses.values()) == {"collision"}, statuses


def test_t2_index_a_root_id_reused_after_its_flow_ended_is_a_collision():
    """A caller that passes the same ``run_id`` to every invoke: a straggler of
    flow 1 emitting while flow 2 runs would carry flow 2's root."""
    from xaidr.run_tree import RunTreeIndex

    index = RunTreeIndex()
    r = uuid.uuid4()
    index.start(r, None, "LangGraph")
    index.end(r)
    index.start(r, None, "LangGraph")
    assert _never_stamped(index, r) == {r: "collision"}


def test_t2_index_a_fresh_id_after_unrelated_traffic_is_still_stamped():
    """The control: the collision rules must not swallow ordinary flows."""
    from xaidr.run_tree import RunTreeIndex

    index = RunTreeIndex()
    for _ in range(50):
        r, kid = uuid.uuid4(), uuid.uuid4()
        index.start(r, None, "LangGraph")
        index.start(kid, r, "tools", "tools")
        status, run = index.resolve(kid)
        assert status == "stamped" and run.root == r.int, status
        index.end(kid)
        index.end(r)


def test_t4_abandoned_roots_are_evicted_under_the_cap():
    from xaidr.run_tree import RunTreeIndex

    index = RunTreeIndex(cap=4096)
    for _ in range(10_000):                      # roots whose end never fires
        root = uuid.uuid4()
        index.start(root, None, "LangGraph", None)
        index.start(uuid.uuid4(), root, "agent", "agent")
        index.start(uuid.uuid4(), root, "tools", "tools")
    assert len(index) <= 4096, (
        f"{len(index)} live entries after 10k abandoned roots: an end that never "
        "fires leaks without bound")
    done = RunTreeIndex(cap=4096)
    for _ in range(1000):                        # completed roots
        root, child = uuid.uuid4(), uuid.uuid4()
        done.start(root, None, "LangGraph", None)
        done.start(child, root, "tools", "tools")
        done.end(child)
        done.end(root)
    assert len(done) == 0, f"{len(done)} entries survive 1000 completed roots"


def _p99_us(samples_ns):
    s = sorted(samples_ns)
    return s[int(len(s) * 0.99)] / 1000


@requires_stack
def test_d4_budget_stamp_p99_at_most_10us():
    from langchain_core.callbacks.manager import CallbackManager
    from langchain_core.runnables.config import var_child_runnable_config

    from xaidr import run_tree

    root, task = uuid.uuid4(), uuid.uuid4()
    run_tree.INDEX.start(root, None, "LangGraph", None)
    run_tree.INDEX.start(task, root, "tools", "tools")
    token = var_child_runnable_config.set({
        "callbacks": CallbackManager(handlers=[], parent_run_id=task),
        "metadata": {"langgraph_node": "tools", "langgraph_step": 4}})
    was_active = run_tree.is_active()
    run_tree.activate()
    samples = []
    try:
        gc.disable()
        for _ in range(20_000):
            data = {"direction": "tool_call", "action": "allowed"}
            t0 = time.perf_counter_ns()
            run_tree.stamp(data)
            samples.append(time.perf_counter_ns() - t0)
        assert data["runTree"] == "stamped", data
    finally:
        gc.enable()
        var_child_runnable_config.reset(token)
        if not was_active:
            run_tree.deactivate()
        run_tree.INDEX.end(root)
    p99 = _p99_us(samples)
    print(f"stamp p99 {p99:.2f} us, median {sorted(samples)[len(samples)//2]/1000:.2f} us")
    assert p99 <= 10.0, f"stamp p99 {p99:.2f} us exceeds the 10 us per-event budget"


@requires_stack
def test_d4_budget_callback_p99_at_most_10us():
    from langchain_core.callbacks import BaseCallbackHandler

    from xaidr import run_tree

    handler = run_tree.handler_for(BaseCallbackHandler)
    was_active = run_tree.is_active()
    run_tree.activate()            # an inactive handler returns at once: time the real work
    samples = []
    try:
        gc.disable()
        for _ in range(10_000):
            root, child = uuid.uuid4(), uuid.uuid4()
            for call in (
                lambda: handler.on_chain_start({}, {}, run_id=root, parent_run_id=None,
                                               name="LangGraph", metadata={}),
                lambda: handler.on_tool_start({}, "x", run_id=child, parent_run_id=root,
                                              name="lookup", metadata={"langgraph_node": "tools"}),
                lambda: handler.on_tool_end("ok", run_id=child, parent_run_id=root),
                lambda: handler.on_chain_end({}, run_id=root, parent_run_id=None),
            ):
                t0 = time.perf_counter_ns()
                call()
                samples.append(time.perf_counter_ns() - t0)
        indexed = root.int in run_tree.INDEX._ended     # before deactivate() clears it
    finally:
        gc.enable()
        if not was_active:
            run_tree.deactivate()
    p99 = _p99_us(samples)
    print(f"callback p99 {p99:.2f} us, median {sorted(samples)[len(samples)//2]/1000:.2f} us")
    assert p99 <= 10.0, f"handler callback p99 {p99:.2f} us exceeds the 10 us budget"
    assert indexed, (
        "the benchmark timed callbacks that indexed nothing: the last root's end "
        "found no entry to remove")


def _retained_by(workload):
    """Bytes still allocated, in ANY file, after ``workload`` runs and its own
    locals are gone: what the index keeps alive, including the UUIDs and node
    names nothing else references."""
    import xaidr.run_tree as rt

    index = rt.RunTreeIndex()
    gc.collect()
    tracemalloc.start()
    try:
        base = tracemalloc.get_traced_memory()[0]
        workload(index)
        gc.collect()
        retained = tracemalloc.get_traced_memory()[0] - base
    finally:
        tracemalloc.stop()
    return index, retained


def _mixed(index):
    for i in range(50_000):
        root = uuid.uuid4()
        index.start(root, None, "LangGraph", None)
        parent, kids = root, []
        for j in range(4):
            kid = uuid.uuid4()
            index.start(kid, parent, f"node{j}", f"node{j}")
            kids.append(kid)
            parent = kid
        index.next_seq(root)
        if i % 3:
            for kid in reversed(kids):
                index.end(kid)
            index.end(root)


def _roots_only_abandoned(index):
    for _ in range(50_000):
        root = uuid.uuid4()
        index.start(root, None, "LangGraph", None)
        index.next_seq(root)


def _reuse_storm(index):
    for _ in range(20_000):
        root, kid = uuid.uuid4(), uuid.uuid4()
        index.start(root, None, "LangGraph", None)
        index.start(root, None, "LangGraph", None)        # collision
        index.start(kid, root, "tools", "tools")
        index.end(root)
        index.start(root, None, "LangGraph", None)        # reuse after end


@pytest.mark.parametrize("workload", [_mixed, _roots_only_abandoned, _reuse_storm],
                         ids=lambda w: w.__name__.strip("_"))
def test_d4_budget_index_stays_under_2mb_with_many_flows(workload):
    import xaidr.run_tree as rt

    index, retained = _retained_by(workload)
    print(f"{workload.__name__}: entries {len(index)}, retained {retained/1024:.0f} KiB (all files)")
    assert len(index) <= rt.MAX_LIVE_RUNS, (
        f"{len(index)} live entries: abandoned roots are not being evicted, so the "
        "index grows without bound")
    assert retained < 2 * 1024 * 1024, (
        f"the run index retains {retained/1024/1024:.2f} MB under {workload.__name__}; "
        "the budget is 2 MB")


# ══════════════════════════════════════════════════════════════════════════
# T5 · no LangChain in the process: no keys, and the manifest says so
# ══════════════════════════════════════════════════════════════════════════


def test_t5_without_langchain_no_run_keys_and_the_manifest_says_so():
    body = """
import json, sys, warnings
import xaidr
class Cap:
    def __init__(self): self.events = []
    def report(self, batch): self.events.extend(batch)
    def close(self): pass
cap = Cap()
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    m = xaidr.protect(agent_id="bare", quiet=True, reporter=cap)
m.sensor.scan("hello world")
m.sensor.scan_tool_call("lookup", {"customer_id": "C-1"})
m.sensor.flush()
print(json.dumps({
    "not_present": m.not_present,
    "keys": sorted({k for e in cap.events for k in e.get("data", {})}),
    "langchain_loaded": any(k.startswith("langchain") for k in sys.modules),
}))
"""
    out = subprocess.run([sys.executable, "-c", body], capture_output=True, text=True,
                         cwd=REPO, env={**os.environ, "PYTHONPATH": REPO}, timeout=60)
    assert out.returncode == 0, out.stderr
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert result["langchain_loaded"] is False, "the subprocess imported LangChain"
    assert "langchain-run-tree" in result["not_present"], (
        "the manifest does not name run-tree capture at all in a process without "
        f"LangChain, so its absence is silent: not_present={result['not_present']}")
    leaked = [k for k in result["keys"] if k in RUN_KEYS]
    assert not leaked, f"run keys on events in a process with no LangChain: {leaked}"


# ══════════════════════════════════════════════════════════════════════════
# the OpenA2A mapping carries the run keys, and omits them when absent
# ══════════════════════════════════════════════════════════════════════════


def test_schema_maps_the_run_keys_and_omits_them_when_absent():
    from xaidr.schema import SCHEMA_VERSION, to_openA2A

    root, task, parent = (str(uuid.uuid4()) for _ in range(3))
    mapped = to_openA2A({"type": "scan", "agentId": "a", "data": {
        "action": "allowed", "direction": "tool_call", "toolName": "lookup",
        "runTree": "stamped", "runRootId": root, "runTaskId": task,
        "runParentId": parent, "runNode": "tools", "runNodePath": ["agent", "tools"],
        "runStep": 4, "runSeq": 2, "runSource": "langchain", "toolCallId": "call_1"}})
    expected = {
        "gen_ai.security.run.status": "stamped",
        "gen_ai.security.run.root_id": root,
        "gen_ai.security.run.task_id": task,
        "gen_ai.security.run.parent_id": parent,
        "gen_ai.security.run.node": "tools",
        "gen_ai.security.run.node_path": ["agent", "tools"],
        "gen_ai.security.run.step": 4,
        "gen_ai.security.run.seq": 2,
        "gen_ai.security.run.source": "langchain",
        "gen_ai.tool.call.id": "call_1",
    }
    missing = {k: v for k, v in expected.items() if mapped.get(k) != v}
    assert not missing, (
        f"the OpenA2A form drops run keys a SIEM would join on: {missing}")
    bare = to_openA2A({"type": "scan", "agentId": "a",
                       "data": {"action": "allowed", "runTree": "no_run"}})
    assert bare["gen_ai.security.run.status"] == "no_run"
    assert not [k for k in bare if k.startswith("gen_ai.security.run.") and k != "gen_ai.security.run.status"]
    assert "gen_ai.tool.call.id" not in bare
    # 0.3.0 is valueOrigin's version (schema.py); the run keys are additive and add nothing to it.
    assert SCHEMA_VERSION == "0.3.0", "additive keys do not move the schema version"
