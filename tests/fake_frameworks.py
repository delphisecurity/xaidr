"""Stand-in modules with the SHAPE of each framework ``xaidr.protect()`` patches.

WHY THESE ARE FAKES, stated plainly so nobody reads more into the green ticks
than is there: none of LangChain, LangGraph, the OpenAI Agents SDK, CrewAI,
AutoGen, LlamaIndex, ``requests`` or the MCP SDK is installed in this
environment, and it has no working package installer, so the real libraries
cannot be exercised here. Each module below reproduces the call site
``protect()`` patches — the class, the method name, the parameter order, the
sync/async-ness, the return type — taken from that library's public API.

What these tests therefore DO prove:
  * discovery, dispatch, idempotency, reversal, manifest content and the
    fail-open/fail-loud behaviour, on the exact seam shapes;
  * that every enforcement decision reaches the sensor and halts the call.

What they do NOT prove: that the real library still has that shape at the
version you are running. That is precisely why every patcher records a
``found_unpatchable`` entry on a shape mismatch instead of assuming — and why
the manifest is the thing to read after a framework upgrade.

``httpx`` is the exception: it IS installed, so its tests run against the real
library through ``httpx.MockTransport``.
"""

from __future__ import annotations

import json
import sys
import types
from typing import Any, Optional


# ── module plumbing ──────────────────────────────────────────────────────


def _install(name: str, mod: types.ModuleType) -> None:
    """Register ``mod`` under ``name`` and bind it on its parent package."""
    sys.modules[name] = mod
    if "." in name:
        parent, _, leaf = name.rpartition(".")
        if parent in sys.modules:
            setattr(sys.modules[parent], leaf, mod)


def _mod(name: str) -> types.ModuleType:
    mod = types.ModuleType(name)
    _install(name, mod)
    return mod


def uninstall(prefixes: tuple[str, ...]) -> None:
    """Remove every fake module under the given top-level names."""
    for key in list(sys.modules):
        if key in prefixes or any(key.startswith(p + ".") for p in prefixes):
            del sys.modules[key]


# ── langchain_core: the tool seam (also used by langgraph + crewai interop) ──


def install_langchain_core() -> types.ModuleType:
    """``langchain_core.tools.BaseTool.run`` / ``.arun``.

    Real signature: ``BaseTool.run(self, tool_input, verbose=None, ...)``.
    """
    _mod("langchain_core")
    tools = _mod("langchain_core.tools")
    messages = _mod("langchain_core.messages")

    class BaseTool:
        """Shaped like a langchain StructuredTool: name, .func, .model_copy.

        ``func`` and ``model_copy`` exist because ``Sensor.protect_tools`` looks
        for exactly those two — this fake has to take the same branch the real
        tool object does, or the double-wrap test would be testing the plain
        callable path instead.
        """

        def __init__(self, name: str, fn):
            self.name = name
            self.func = fn

        def model_copy(self, update=None):
            clone = BaseTool(self.name, self.func)
            for key, value in (update or {}).items():
                setattr(clone, key, value)
            return clone

        def run(self, tool_input, **kwargs):
            if isinstance(tool_input, dict):
                return self.func(**tool_input)
            return self.func(tool_input)

        async def arun(self, tool_input, **kwargs):
            return self.run(tool_input, **kwargs)

    class _Msg:
        def __init__(self, content="", **kwargs):
            self.content = content
            for k, v in kwargs.items():
                setattr(self, k, v)

    class AIMessage(_Msg):
        pass

    class HumanMessage(_Msg):
        pass

    class ToolMessage(_Msg):
        pass

    tools.BaseTool = BaseTool
    messages.AIMessage = AIMessage
    messages.HumanMessage = HumanMessage
    messages.ToolMessage = ToolMessage
    return tools


# ── langchain: create_agent + the middleware base class ──────────────────


def install_langchain(*, with_create_agent: bool = True) -> types.ModuleType:
    """``langchain.agents.create_agent`` and ``langchain.agents.middleware``.

    ``with_create_agent=False`` reproduces a pre-1.0 install: the package is
    importable but the middleware seam does not exist.
    """
    _mod("langchain")
    agents = _mod("langchain.agents")
    mw_mod = _mod("langchain.agents.middleware")

    class AgentMiddleware:
        def before_model(self, state, runtime):
            return None

        def after_model(self, state, runtime):
            return None

        def wrap_tool_call(self, request, handler):
            return handler(request)

    def hook_config(**kwargs):
        def deco(fn):
            return fn

        return deco

    mw_mod.AgentMiddleware = AgentMiddleware
    mw_mod.hook_config = hook_config

    class FakeAgent:
        """Just enough of a compiled agent to drive the three hooks."""

        def __init__(self, tools, middleware):
            self.tools = {t.name: t for t in (tools or ())}
            self.middleware = list(middleware or ())

        def invoke(self, state):
            messages = list(state.get("messages", []))
            for m in self.middleware:
                out = m.before_model({"messages": messages}, None)
                if out and out.get("jump_to") == "end":
                    return {"messages": messages + list(out["messages"]), "halted": "input"}
            return {"messages": messages}

        def call_tool(self, name, args):
            request = types.SimpleNamespace(tool_call={"name": name, "args": args, "id": "c1"})

            def handler(req):
                return self.tools[name].run(req.tool_call["args"])

            call = handler
            for m in reversed(self.middleware):
                call = (lambda mw, nxt: lambda req: mw.wrap_tool_call(req, nxt))(m, call)
            return call(request)

        def emit(self, text):
            AIMessage = sys.modules["langchain_core.messages"].AIMessage
            messages = [AIMessage(content=text)]
            for m in self.middleware:
                out = m.after_model({"messages": messages}, None)
                if out and out.get("jump_to") == "end":
                    return {"messages": list(out["messages"]), "halted": "output"}
            return {"messages": messages}

    if with_create_agent:
        def create_agent(model=None, tools=None, middleware=None, **kwargs):
            return FakeAgent(tools, middleware)

        agents.create_agent = create_agent
    agents.FakeAgent = FakeAgent
    return agents


def install_langgraph() -> types.ModuleType:
    langgraph = _mod("langgraph")
    graph = _mod("langgraph.graph")

    class StateGraph:
        pass

    graph.StateGraph = StateGraph
    return langgraph


# ── OpenAI Agents SDK ────────────────────────────────────────────────────


def install_openai_agents(*, with_runner: bool = True) -> types.ModuleType:
    """``agents.Runner.run`` (async classmethod) / ``.run_sync``.

    ``FunctionTool.on_invoke_tool`` is modelled as a per-instance field, which
    is exactly why it is reported unpatchable.
    """
    mod = _mod("agents")

    class RunResult:
        def __init__(self, final_output):
            self.final_output = final_output

    class FunctionTool:
        def __init__(self, name, on_invoke_tool):
            self.name = name
            self.on_invoke_tool = on_invoke_tool

    class Runner:
        handler = staticmethod(lambda agent, inp: f"echo: {inp}")

        @classmethod
        async def run(cls, starting_agent, input, **kwargs):
            return RunResult(cls.handler(starting_agent, input))

        @classmethod
        def run_sync(cls, starting_agent, input, **kwargs):
            return RunResult(cls.handler(starting_agent, input))

    class Agent:
        def __init__(self, name="a", tools=None):
            self.name = name
            self.tools = list(tools or ())

    mod.RunResult = RunResult
    mod.FunctionTool = FunctionTool
    # `Agent` is exported by every version of the SDK, so it is what the
    # identity check keys on. Keeping it here even when `Runner` is missing is
    # what makes with_runner=False the REAL "version moved the entrypoint" case
    # rather than "this is not the SDK at all".
    mod.Agent = Agent
    if with_runner:
        mod.Runner = Runner
    return mod


# ── CrewAI ───────────────────────────────────────────────────────────────


def install_crewai() -> types.ModuleType:
    mod = _mod("crewai")
    tools = _mod("crewai.tools")

    class BaseTool:
        def __init__(self, name, fn):
            self.name = name
            self.fn = fn

        def run(self, *args, **kwargs):
            return self.fn(*args, **kwargs)

    class Crew:
        def __init__(self, runner=None):
            self.runner = runner or (lambda inputs: f"ran with {inputs}")

        def kickoff(self, inputs=None):
            return self.runner(inputs)

    tools.BaseTool = BaseTool
    mod.Crew = Crew
    return mod


# ── AutoGen, both product lines ──────────────────────────────────────────


def install_autogen_core() -> types.ModuleType:
    _mod("autogen_core")
    tools = _mod("autogen_core.tools")

    class BaseTool:
        def __init__(self, name, fn):
            self.name = name
            self.fn = fn

        async def run_json(self, args, cancellation_token=None, call_id=None):
            return self.fn(args)

    tools.BaseTool = BaseTool
    return tools


def install_autogen_legacy() -> types.ModuleType:
    mod = _mod("autogen")

    class ConversableAgent:
        def __init__(self, functions=None):
            self.functions = functions or {}

        def execute_function(self, func_call, call_id=None, verbose=False):
            name = func_call["name"]
            args = json.loads(func_call.get("arguments") or "{}")
            out = self.functions[name](**args)
            return True, {"name": name, "role": "function", "content": out}

    mod.ConversableAgent = ConversableAgent
    return mod


# ── LlamaIndex ───────────────────────────────────────────────────────────


def install_llama_index() -> types.ModuleType:
    _mod("llama_index")
    _mod("llama_index.core")
    tools = _mod("llama_index.core.tools")

    class ToolMetadata:
        def __init__(self, name):
            self.name = name

    class FunctionTool:
        def __init__(self, name, fn):
            self.metadata = ToolMetadata(name)
            self.fn = fn

        def call(self, *args, **kwargs):
            return self.fn(*args, **kwargs)

        async def acall(self, *args, **kwargs):
            return self.fn(*args, **kwargs)

    class QueryEngineTool:
        pass

    tools.ToolMetadata = ToolMetadata
    tools.FunctionTool = FunctionTool
    tools.QueryEngineTool = QueryEngineTool
    return tools


# ── MCP client ───────────────────────────────────────────────────────────


def install_mcp(*, with_types: bool = True) -> types.ModuleType:
    mod = _mod("mcp")

    class TextContent:
        def __init__(self, type="text", text=""):
            self.type = type
            self.text = text

    class CallToolResult:
        def __init__(self, content=None, isError=False):
            self.content = list(content or ())
            self.isError = isError

    if with_types:
        types_mod = _mod("mcp.types")
        types_mod.TextContent = TextContent
        types_mod.CallToolResult = CallToolResult

    class ClientSession:
        def __init__(self, handler=None):
            self.handler = handler or (lambda name, args: "ok")

        async def call_tool(self, name, arguments=None, **kwargs):
            return CallToolResult(
                content=[TextContent(text=str(self.handler(name, arguments)))]
            )

    mod.ClientSession = ClientSession
    mod.CallToolResult = CallToolResult
    mod.TextContent = TextContent
    return mod


# ── requests ─────────────────────────────────────────────────────────────


def install_requests() -> types.ModuleType:
    mod = _mod("requests")

    class Response:
        def __init__(self, url, payload):
            self.url = url
            self._payload = payload
            self.status_code = 200

        def json(self):
            return self._payload

    class PreparedRequest:
        def __init__(self, method, url, body=None):
            self.method = method
            self.url = url
            self.body = body

    class Session:
        payload: Any = {"response": "ok"}

        def send(self, request, **kwargs):
            return Response(request.url, Session.payload)

    mod.Response = Response
    mod.PreparedRequest = PreparedRequest
    mod.Session = Session
    return mod
