"""Outside-the-process producer: a real LangGraph flow under protect(), from the
INSTALLED wheel, writing real telemetry to a JSONL file. Two concurrent flows,
a direct tool.run() outside any run, and one inbound scan carrying a W3C
traceparent header."""
import sys, threading, warnings
import langchain.agents, langchain.agents.middleware  # noqa: F401
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph
import xaidr
from xaidr.integrations.langchain import route_inbound_scan
from xaidr.reporters import FileReporter

out = sys.argv[1]
print("xaidr from", xaidr.__file__)
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    m = xaidr.protect(agent_id="e2e-agent", quiet=True, reporter=FileReporter(out))
TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

@tool
def lookup_customer(customer_id: str) -> str:
    """Look up a customer."""
    return f"Customer {customer_id}: plan Gold."

@tool
def record_note(customer_id: str, text: str) -> str:
    """Record a note."""
    return f"Note recorded for {customer_id}."

class FM(FakeMessagesListChatModel):
    def bind_tools(self, tools, **kw): return self

def graph(tool_name):
    args = {"customer_id": "C-1"} | ({"text": "t"} if tool_name == "record_note" else {})
    agent = langchain.agents.create_agent(model=FM(responses=[
        AIMessage(content="", tool_calls=[{"name": tool_name, "args": args, "id": "call_1"}]),
        AIMessage(content="Done.")]), tools=[lookup_customer, record_note])
    def inbound(state):  # an inbound message arriving with a W3C parent, inside the run
        route_inbound_scan(m.sensor, "inbound hello", "e2e-agent", headers={"traceparent": TRACEPARENT})
        return {}
    def support_agent(state):
        return {"messages": agent.invoke({"messages": state["messages"]})["messages"]}
    g = StateGraph(MessagesState)
    g.add_node("inbound", inbound); g.add_node("support_agent", support_agent)
    g.add_edge(START, "inbound"); g.add_edge("inbound", "support_agent"); g.add_edge("support_agent", END)
    return g.compile()

threads = [threading.Thread(target=lambda n=n: graph(n).invoke({"messages": [("user", f"go {n}")]}))
           for n in ("lookup_customer", "record_note")]
[t.start() for t in threads]; [t.join() for t in threads]
lookup_customer.run({"customer_id": "C-9"})            # outside any run
m.sensor.flush()
m.unprotect()
print("wrote", out)
