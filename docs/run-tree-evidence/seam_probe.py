"""Evidence for docs/run-tree-spec.md. NOT sensor code, not a test.

Run (PYTHONPATH must point at THIS tree, or the venv's own xaidr is measured):

    MODE=hook|patch PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=<this worktree> \\
        <venv with langchain 1.4.x + langgraph>/bin/python docs/run-tree-evidence/seam_probe.py

Questions, each answered from a live run, no network:
  V1  Does register_configure_hook(ContextVar(default=handler), inheritable=True)
      deliver callbacks on a plain graph.invoke() with NO config= callbacks,
      including when invoke runs on a fresh thread?
  V2  At xaidr's own enqueue seam (sensor._telemetry.enqueue, called on the
      caller's thread), what does var_child_runnable_config expose: the
      enclosing run id, langgraph_node, and can the handler's parent map walk
      it to the root?
  V3  A direct tool.run() outside any runnable: what is there to key on?
  V4  Same on ainvoke.
  V5  on_tool_start carries tool_call_id (join key tool_call event -> tool run).
  V6  Per-stamp cost.
  V7  Two flows concurrently in one process keep separate roots.

MODE=hook registers through register_configure_hook; MODE=patch wraps the
public CallbackManager.configure classmethods instead (spec Q-R1).
"""
from __future__ import annotations

import asyncio
import json
import sys
import threading
import time
from contextvars import ContextVar
from typing import Any

import xaidr
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.documents import Document
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage, SystemMessage
from langchain_core.retrievers import BaseRetriever
from langchain_core.tools import tool
from langchain_core.tracers.context import register_configure_hook, _configure_hooks
import langchain.agents  # noqa: F401  (so protect() patches create_agent)
import langchain.agents.middleware  # noqa: F401
from langgraph.graph import StateGraph, START, END, MessagesState

print("xaidr from:", xaidr.__file__)


class Tree(BaseCallbackHandler):
    """Minimal parent-pointer recorder; stands in for the proposed handler."""

    def __init__(self) -> None:
        self.parent: dict[Any, Any] = {}
        self.node: dict[Any, Any] = {}
        self.tool_call: dict[Any, Any] = {}
        self.name: dict[Any, Any] = {}
        self.events: list[tuple] = []

    def _rec(self, ev, run_id, parent_run_id, metadata=None, **kw):
        kw = {k: v for k, v in kw.items() if v is not None}
        self.parent[run_id] = parent_run_id
        self.name[run_id] = kw.get("name") or ev
        if metadata and metadata.get("langgraph_node"):
            self.node[run_id] = metadata.get("langgraph_node")
        self.events.append((ev, str(run_id)[-12:], str(parent_run_id)[-12:] if parent_run_id else None))

    def on_chain_start(self, serialized, inputs, *, run_id, parent_run_id=None, metadata=None, **kw):
        self._rec("chain", run_id, parent_run_id, metadata, name=kw.get("name"))

    def on_chat_model_start(self, serialized, messages, *, run_id, parent_run_id=None, metadata=None, **kw):
        self._rec("chat_model", run_id, parent_run_id, metadata)

    def on_tool_start(self, serialized, input_str, *, run_id, parent_run_id=None, metadata=None, **kw):
        self._rec("tool", run_id, parent_run_id, metadata, name=kw.get("name"))
        self.tool_call[run_id] = kw.get("tool_call_id")

    def on_retriever_start(self, serialized, query, *, run_id, parent_run_id=None, metadata=None, **kw):
        self._rec("retriever", run_id, parent_run_id, metadata)

    def root_of(self, rid, limit=64):
        hops = 0
        while rid is not None and hops < limit:
            p = self.parent.get(rid)
            if p is None:
                return rid, hops, rid in self.parent
            rid, hops = p, hops + 1
        return rid, hops, False


TREE = Tree()
import os  # noqa: E402
MODE = os.environ.get("MODE", "hook")
if MODE == "hook":
    _VAR: ContextVar = ContextVar("xaidr_run_tree_probe", default=TREE)
    register_configure_hook(_VAR, inheritable=True)
else:  # MODE=patch: wrap the public classmethod instead of using the registry
    from langchain_core.callbacks import manager as _m
    for cls in (_m.CallbackManager, _m.AsyncCallbackManager):
        orig = cls.__dict__["configure"].__func__
        def make(orig):
            def configure(klass, *a, **k):
                cm = orig(klass, *a, **k)
                if not any(h is TREE for h in cm.handlers):
                    cm.add_handler(TREE, True)
                return cm
            return classmethod(configure)
        cls.configure = make(orig)
print("MODE:", MODE)

from xaidr.reporters import FileReporter  # noqa: E402
handle = xaidr.protect(agent_id="probe", quiet=True, reporter=FileReporter("/dev/null"))
sensor = handle.sensor
from langchain_core.runnables import config as _rc  # noqa: E402

STAMPS: list[dict] = []
_orig_enqueue = sensor._telemetry.enqueue
STAMP_NS: list[int] = []


def stamping_enqueue(event: dict) -> None:
    t0 = time.perf_counter_ns()
    cfg = _rc.var_child_runnable_config.get()
    cb = cfg.get("callbacks") if cfg else None
    enclosing = getattr(cb, "parent_run_id", None)
    meta = (cfg or {}).get("metadata") or {}
    root, hops, closed = TREE.root_of(enclosing) if enclosing else (None, 0, False)
    STAMP_NS.append(time.perf_counter_ns() - t0)
    d = event.get("data", {})
    STAMPS.append({
        "dir": d.get("direction"), "tool": d.get("toolName"),
        "enclosing": str(enclosing)[-12:] if enclosing else None,
        "enclosing_known_to_handler": enclosing in TREE.parent if enclosing else None,
        "enclosing_name": TREE.name.get(enclosing), "root_name": TREE.name.get(root),
        "node": meta.get("langgraph_node"), "step": meta.get("langgraph_step"),
        "root": str(root)[-12:] if root else None, "hops": hops,
        "thread": threading.current_thread().name,
    })
    _orig_enqueue(event)


sensor._telemetry.enqueue = stamping_enqueue


@tool
def lookup_customer(customer_id: str) -> str:
    """Look up a customer."""
    return f"Customer {customer_id}: Dana Reyes, plan Gold."


@tool
def record_note(customer_id: str, text: str) -> str:
    """Record a note."""
    return f"Note recorded for {customer_id}."


class KB(BaseRetriever):
    def _get_relevant_documents(self, query, *, run_manager=None):
        return [Document(page_content="Resolution code: RC-DOA-14.", metadata={"id": "kb-refund"})]


class FakeModel(FakeMessagesListChatModel):
    def bind_tools(self, tools, **kw):
        return self


def model():
    return FakeModel(responses=[
        AIMessage(content="", tool_calls=[{"name": "lookup_customer", "args": {"customer_id": "C-1001"}, "id": "call_1"}]),
        AIMessage(content="", tool_calls=[{"name": "record_note", "args": {"customer_id": "C-1001", "text": "cb Fri"}, "id": "call_2"}]),
        AIMessage(content="Done."),
    ])


create_agent = langchain.agents.create_agent  # looked up AFTER protect()
retriever = KB()


def build():
    agent = create_agent(model=model(), tools=[lookup_customer, record_note])

    def retrieve_context(state):
        docs = retriever.invoke(state["messages"][-1].content)
        return {"messages": [SystemMessage(content="Retrieved: " + docs[0].page_content)]}

    def support_agent(state):
        return {"messages": agent.invoke({"messages": state["messages"]})["messages"]}

    g = StateGraph(MessagesState)
    g.add_node("retrieve_context", retrieve_context)
    g.add_node("support_agent", support_agent)
    g.add_edge(START, "retrieve_context")
    g.add_edge("retrieve_context", "support_agent")
    g.add_edge("support_agent", END)
    return g.compile()


def report(label):
    roots = {s["root"] for s in STAMPS}
    print(f"=== {label}: {len(STAMPS)} sensor events, handler saw {len(TREE.events)} callbacks, "
          f"{len(TREE.parent)} runs, distinct roots on events: {sorted(r or 'None' for r in roots)}")
    for s in STAMPS:
        print("  ", json.dumps(s))
    STAMPS.clear()


USER = "Customer C-1001 asks about T-100. Note: callback Friday"

# V1+V2: sync invoke on a FRESH thread, no config= at all.
t = threading.Thread(target=lambda: build().invoke({"messages": [("user", USER)]}), name="fresh-thread")
t.start(); t.join()
report("V1/V2 sync invoke on fresh thread, no config callbacks")
print("tool run -> tool_call_id (V5):", {str(k)[-12:]: v for k, v in TREE.tool_call.items()})
print("nodes seen by handler:", sorted(set(TREE.node.values())))

# V3: direct tool.run outside any runnable.
lookup_customer.run({"customer_id": "C-9"})
report("V3 direct tool.run()")

# V4: ainvoke.
TREE.__init__()
asyncio.run(build().ainvoke({"messages": [("user", USER)]}))
report("V4 ainvoke")

# V7: two flows concurrently in one process; each must keep its own root.
TREE.__init__()
def flow(tool_name, cid):
    def mk():
        return FakeModel(responses=[
            AIMessage(content="", tool_calls=[{"name": tool_name, "args": {"customer_id": cid, **({"text": "t"} if tool_name == "record_note" else {})}, "id": "c_" + cid}]),
            AIMessage(content="Done."),
        ])
    agent = create_agent(model=mk(), tools=[lookup_customer, record_note])
    for _ in range(5):
        agent.invoke({"messages": [("user", "go " + cid)]})
ts = [threading.Thread(target=flow, args=("lookup_customer", "A")), threading.Thread(target=flow, args=("record_note", "B"))]
[t.start() for t in ts]; [t.join() for t in ts]
by_root = {}
for st in STAMPS:
    if st["tool"]:
        by_root.setdefault(st["root"], set()).add(st["tool"])
mixed = [r for r, tools in by_root.items() if len(tools) > 1]
print(f"V7 concurrent: {len(by_root)} roots carrying tool_call events (10 invokes), roots mixing both flows' tools: {len(mixed)}, "
      f"tool_call events with no root: {sum(1 for st in STAMPS if st['tool'] and not st['root'])}")
STAMPS.clear()

# V6: stamp cost.
s = sorted(STAMP_NS)
print(f"V6 stamp cost over {len(s)} events: median {s[len(s)//2]/1000:.1f}us  max {s[-1]/1000:.1f}us")
print("configure hooks registered:", len(_configure_hooks))
