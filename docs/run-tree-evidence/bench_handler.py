"""Evidence for docs/run-tree-spec.md (D4). NOT sensor code, not a test.

Per-invoke cost of a parent-pointer handler registered through langchain_core's
configure-hook registry, and its memory growth with no eviction. No xaidr and no
protect(): this isolates the handler. Interleaves handler-off/handler-on rounds
so drift lands on both sides.

    PYTHONDONTWRITEBYTECODE=1 <venv with langchain 1.4.x + langgraph>/bin/python \
        docs/run-tree-evidence/bench_handler.py
"""
import statistics
import time
import tracemalloc
from contextvars import ContextVar

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.tracers.context import register_configure_hook, _configure_hooks
from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever
from langchain_core.tools import tool
from langchain_core.messages import SystemMessage, AIMessage
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain.agents import create_agent
from langgraph.graph import StateGraph, START, END, MessagesState

class H(BaseCallbackHandler):
    run_inline = True
    def __init__(self): self.parent = {}; self.n = 0
    def _r(self, run_id, parent_run_id, metadata):
        self.n += 1; self.parent[run_id] = (parent_run_id, (metadata or {}).get("langgraph_node"))
    def on_chain_start(self, s, i, *, run_id, parent_run_id=None, metadata=None, **k): self._r(run_id, parent_run_id, metadata)
    def on_chat_model_start(self, s, m, *, run_id, parent_run_id=None, metadata=None, **k): self._r(run_id, parent_run_id, metadata)
    def on_tool_start(self, s, i, *, run_id, parent_run_id=None, metadata=None, **k): self._r(run_id, parent_run_id, metadata)
    def on_retriever_start(self, s, q, *, run_id, parent_run_id=None, metadata=None, **k): self._r(run_id, parent_run_id, metadata)

@tool
def lookup_customer(customer_id: str) -> str:
    """Look up."""
    return "ok"

class KB(BaseRetriever):
    def _get_relevant_documents(self, query, *, run_manager=None):
        return [Document(page_content="x", metadata={"id": "kb"})]

class FM(FakeMessagesListChatModel):
    def bind_tools(self, tools, **kw): return self

def build():
    agent = create_agent(model=FM(responses=[AIMessage(content="", tool_calls=[{"name": "lookup_customer", "args": {"customer_id": "C"}, "id": "c1"}]), AIMessage(content="done")]), tools=[lookup_customer])
    kb = KB()
    def rc(s): return {"messages": [SystemMessage(content=kb.invoke("q")[0].page_content)]}
    def sa(s): return {"messages": agent.invoke({"messages": s["messages"]})["messages"]}
    g = StateGraph(MessagesState); g.add_node("rc", rc); g.add_node("sa", sa)
    g.add_edge(START, "rc"); g.add_edge("rc", "sa"); g.add_edge("sa", END); return g.compile()

def run(n=60):
    ts = []
    for _ in range(n):
        g = build(); t0 = time.perf_counter(); g.invoke({"messages": [("user", "hi")]}); ts.append(time.perf_counter() - t0)
    return statistics.median(ts[5:]) * 1000

run(10)  # warm
h = H(); entry = (ContextVar("xaidr_bench", default=h), True, None, None)
res = {"off": [], "on": []}
for rnd in range(4):
    res["off"].append(run(40))
    _configure_hooks.append(entry); res["on"].append(run(40)); _configure_hooks.remove(entry)
off = statistics.median(res["off"]); on = statistics.median(res["on"])
print(f"median invoke ms over 4 interleaved rounds x 40: no handler {off:.3f} | with handler {on:.3f} | delta {on-off:+.3f} ms ({(on-off)/off*100:+.1f}%)")
print(f"handler callbacks: {h.n} over {4*40} invokes = {h.n/160:.0f}/invoke; per-callback delta ~ {(on-off)*1000/(h.n/160):.1f} us")
h2 = H(); e2 = (ContextVar("xaidr_bench2", default=h2), True, None, None); _configure_hooks.append(e2)
tracemalloc.start(); s0 = tracemalloc.take_snapshot()
for _ in range(100): build().invoke({"messages": [("user", "hi")]})
s1 = tracemalloc.take_snapshot(); tracemalloc.stop(); _configure_hooks.remove(e2)
grow = sum(st.size_diff for st in s1.compare_to(s0, "filename") if "bench_handler" in str(st.traceback))
print(f"no-eviction parent map after 100 invokes: {len(h2.parent)} entries, ~{grow} bytes attributed to the handler's own lines (unbounded growth without root-end eviction)")
