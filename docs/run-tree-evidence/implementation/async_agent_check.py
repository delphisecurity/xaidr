import asyncio, traceback
import langchain.agents, langchain.agents.middleware  # noqa
from langchain_core.messages import AIMessage
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.tools import tool
import xaidr
from xaidr.reporters import FileReporter
xaidr.protect(agent_id="a", quiet=True, reporter=FileReporter("/dev/null"))
@tool
def look(customer_id: str) -> str:
    """look"""
    return "ok"
class FM(FakeMessagesListChatModel):
    def bind_tools(self, tools, **kw): return self
agent = langchain.agents.create_agent(model=FM(responses=[AIMessage(content="", tool_calls=[{"name":"look","args":{"customer_id":"C"},"id":"c1"}]), AIMessage(content="done")]), tools=[look])
try:
    out = asyncio.run(agent.ainvoke({"messages":[("user","hi")]}))
    print("async create_agent OK:", out["messages"][-1].content)
except Exception as e:
    print("async create_agent CRASH:", type(e).__name__, str(e)[:200])
