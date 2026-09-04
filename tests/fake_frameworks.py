"""Stand-in modules with the SHAPE of each framework ``xaidr.protect()`` patches.

WHY THESE ARE FAKES, stated plainly so nobody reads more into the green ticks
than is there: none of LangChain, LangGraph, the OpenAI Agents SDK, CrewAI,
AutoGen, LlamaIndex, ``requests`` or the MCP SDK is a dependency of this
package, so the real libraries are not present in the default test environment.
Each module below reproduces the call site ``protect()`` patches — the class,
the method name, the parameter order, the sync/async-ness, the return type —
taken from that library's public API.

What these tests therefore DO prove:
  * discovery, dispatch, idempotency, reversal, manifest content and the
    fail-open/fail-loud behaviour, on the exact seam shapes;
  * that every enforcement decision reaches the sensor and halts the call.

What they do NOT prove: that the real library still has that shape at the
version you are running. That is precisely why every patcher records a
``found_unpatchable`` entry on a shape mismatch instead of assuming — and why
the manifest is the thing to read after a framework upgrade.

``httpx`` is the exception here: it IS installed (the ``[http]`` extra), so its
tests run against the real library through ``httpx.MockTransport``. For
LangChain and CrewAI, ``tests/test_real_frameworks.py`` runs against the real
library when it is installed and skips cleanly when it is not.

WHAT A FAKE COSTS WHEN IT IS WRONG, because this file has already paid it once.
The CrewAI fake defined ``BaseTool.run`` as the tool implementation. The real
framework binds ``CrewStructuredTool(func=self._run)`` and routes every
agent-driven call through ``_run``, stepping over ``run`` entirely. 107 tests
passed against that fiction while the shipped patch caught nothing and the
manifest claimed full coverage. A fake is worth exactly its fidelity to the
call path, and the question to ask of each one is not "does this method exist"
but "is it on the path the framework itself takes".

AUDIT, 2026-08-26 — every seam below checked against the real library at the
version named. "on-path" is the second question, asked explicitly:

  requests 2.34.2        Session.send exists; Session.request routes through
                         self.send(), so get/post/... all reach it.        OK
  langchain-core 1.6.0   BaseTool.run/.arun exist; BaseTool.invoke calls
                         self.run(), so the ToolNode agent path reaches it. OK
  langgraph 1.2.11       No own seam, by design; covered transitively via
                         langchain_core.BaseTool.run (ToolNode).           OK
  openai-agents 0.22.0   Runner.run/.run_sync present, both classmethods,
                         run async + run_sync sync as modelled;
                         RunResult.final_output is a dataclass FIELD (not a
                         class attribute — the fake models the instance);
                         FunctionTool.on_invoke_tool is a per-instance
                         dataclass field, which is why it is unpatchable.   OK
  autogen-core 0.7.5     BaseTool.run_json exists, async, and AssistantAgent
                         calls it.                                          OK
  llama-index-core       FunctionTool.call/.acall exist; the workflow agents
    0.14.24              call tool.acall(**input). GAP: CodeActAgent pulls
                         `tool.real_fn` and bypasses both (codeact_agent.py).
  mcp 2.1.1              ClientSession.call_tool exists, async. NOTE: the real
                         CallToolResult field is `is_error` with ALIAS
                         `isError`; the fake exposes `isError` as a plain
                         attribute. The production patch only ever CONSTRUCTS
                         with the alias (which works) and reads `.content[].text`
                         (which is right), so the patch is correct — but do not
                         read `.isError` off a real result.
  crewai 1.15.17         See install_crewai below. The seam MOVED; the tool
                         boundary is now the before_tool_call hook.
  autogen (legacy)       Verified against pyautogen==0.2.35, the version the
                         seam was written for: execute_function(self,
                         func_call, verbose=False) -> Tuple[bool, Dict], sync,
                         reads func_call["name"] and json.loads the arguments —
                         the fake matches (its extra `call_id=None` parameter
                         is harmless, the wrapper takes *args/**kwargs).
                         GAP: the ASYNC reply path
                         (a_generate_tool_calls_reply -> _a_execute_tool_call
                         -> a_execute_function) does NOT go through
                         execute_function, and a_execute_function is NOT
                         patched. Async legacy-AutoGen tool calls are
                         uninstrumented and the manifest does not say so.
                         NOT installable from current PyPI under that name:
                         `pyautogen` 0.10.0 is a shim over autogen-agentchat
                         with no `autogen` module, and `ag2` 1.0.2 no longer
                         exposes ConversableAgent. Verifying it means pinning
                         the old release.
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
            # `tool_call_id` is keyword-only on the real signature and is set by
            # langchain's own `_prep_run_args` when the caller passed a ToolCall.
            # It is modelled because it is the RETURN CONTRACT: real
            # `_format_output` returns a ToolMessage iff tool_call_id is not
            # None, and the raw content otherwise. Omitting it here would leave
            # the seam's type-discrimination untested in the default suite —
            # the same "fake with the wrong fidelity" trap the CrewAI seam fell
            # into. Verified against langchain-core 1.6.1.
            result = (
                self.func(**tool_input)
                if isinstance(tool_input, dict)
                else self.func(tool_input)
            )
            return _format_output(result, kwargs.get("tool_call_id"), self.name)

        async def arun(self, tool_input, **kwargs):
            return self.run(tool_input, **kwargs)

        def invoke(self, value, **kwargs):
            """The ToolCall-driven caller, which is the one that gets a message."""
            if isinstance(value, dict) and value.get("type") == "tool_call":
                # Mirrors _prep_run_args: the envelope is UNWRAPPED here, so
                # `run` only ever sees the tool's own arguments.
                return self.run(dict(value["args"]), tool_call_id=value["id"])
            return self.run(value)

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
        def __init__(self, content="", tool_call_id=None, name=None,
                     status="success", **kwargs):
            super().__init__(content, tool_call_id=tool_call_id, name=name,
                             status=status, **kwargs)

    def _format_output(content, tool_call_id, name, status="success"):
        """Shaped after langchain_core.tools.base._format_output."""
        if tool_call_id is None:
            return content
        return ToolMessage(content=content, tool_call_id=tool_call_id,
                           name=name, status=status)

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
    """CrewAI's REAL tool path — which does not go through ``BaseTool.run``.

    Shape verified by reading the installed ``crewai==1.15.17``, not the docs.
    The three facts that matter, and that an earlier version of this fake got
    wrong:

    1. ``BaseTool._run`` is the implementation; ``BaseTool.run`` is a public
       wrapper that only DEVELOPER code calls directly.
    2. ``BaseTool.to_structured_tool()`` binds ``CrewStructuredTool(func=self._run)``
       — note ``_run``, not ``run``. Every agent-driven call therefore goes
       ``CrewStructuredTool.invoke()`` -> ``func`` -> ``_run`` and steps straight
       over ``BaseTool.run``. A patch on ``BaseTool.run`` sees NONE of it.
    3. Before executing a tool for an agent, CrewAI builds a
       ``ToolCallHookContext(tool_name, tool_input, tool, agent, task, crew)``
       and runs the registered ``before_tool_call`` hooks. A hook returning
       ``False`` blocks execution (the dispatcher maps it to ``HookAborted``)
       and the executor returns a "blocked by hook" message instead of calling
       the tool. See ``crewai/utilities/tool_utils.py::execute_tool_and_check_finality``
       and ``crewai/hooks/tool_hooks.py::run_before_tool_call_hooks``.

    The previous fake defined ``BaseTool.run`` as the implementation and had no
    hook registry at all, so it modelled a CrewAI that has never existed. It
    certified the ``BaseTool.run`` patch green while ``rm -rf /`` ran on the
    real framework. Keeping the divergence written down here is the point: the
    fake is only worth what its fidelity to these call paths is worth.
    """
    mod = _mod("crewai")
    tools = _mod("crewai.tools")
    hooks = _mod("crewai.hooks")
    _mod("crewai.utilities")
    tool_utils = _mod("crewai.utilities.tool_utils")

    # ── the sanctioned hook seam (crewai.hooks) ──────────────────────────
    class HookAborted(Exception):
        """Raised inside the dispatcher when a before-hook returns False."""

        def __init__(self, reason: str = "") -> None:
            super().__init__(reason)
            self.reason = reason

    class ToolCallHookContext:
        """Field-for-field the real ``crewai.hooks.tool_hooks`` context.

        ``tool_input`` is a MUTABLE dict the hook may edit in place — that is
        the documented contract, and it is why this is a dict and not a frozen
        mapping.
        """

        def __init__(self, tool_name, tool_input, tool, agent=None, task=None,
                     crew=None, tool_result=None, raw_tool_result=None):
            self.tool_name = tool_name
            self.tool_input = tool_input
            self.tool = tool
            self.agent = agent
            self.task = task
            self.crew = crew
            self.tool_result = tool_result
            self.raw_tool_result = raw_tool_result

    _before_tool_call_hooks: list = []
    _after_tool_call_hooks: list = []

    def register_before_tool_call_hook(hook):
        _before_tool_call_hooks.append(hook)

    def unregister_before_tool_call_hook(hook) -> bool:
        try:
            _before_tool_call_hooks.remove(hook)
            return True
        except ValueError:
            return False

    def get_before_tool_call_hooks() -> list:
        return list(_before_tool_call_hooks)

    def clear_before_tool_call_hooks() -> None:
        _before_tool_call_hooks.clear()

    def register_after_tool_call_hook(hook):
        _after_tool_call_hooks.append(hook)

    def unregister_after_tool_call_hook(hook) -> bool:
        try:
            _after_tool_call_hooks.remove(hook)
            return True
        except ValueError:
            return False

    def get_after_tool_call_hooks() -> list:
        return list(_after_tool_call_hooks)

    def run_before_tool_call_hooks(context) -> bool:
        """True when a hook BLOCKED the call. Mirrors the real return polarity."""
        for hook in list(_before_tool_call_hooks):
            if hook(context) is False:
                return True
        return False

    def run_after_tool_call_hooks(context):
        """A hook returning a string REPLACES the result. Real reducer semantics."""
        for hook in list(_after_tool_call_hooks):
            replacement = hook(context)
            if isinstance(replacement, str):
                context.tool_result = replacement
        return context.tool_result

    hooks.HookAborted = HookAborted
    hooks.ToolCallHookContext = ToolCallHookContext
    hooks.register_before_tool_call_hook = register_before_tool_call_hook
    hooks.unregister_before_tool_call_hook = unregister_before_tool_call_hook
    hooks.get_before_tool_call_hooks = get_before_tool_call_hooks
    hooks.clear_before_tool_call_hooks = clear_before_tool_call_hooks
    hooks.register_after_tool_call_hook = register_after_tool_call_hook
    hooks.unregister_after_tool_call_hook = unregister_after_tool_call_hook
    hooks.get_after_tool_call_hooks = get_after_tool_call_hooks
    hooks.run_after_tool_call_hooks = run_after_tool_call_hooks

    # ── the tool objects ─────────────────────────────────────────────────
    class CrewStructuredTool:
        """What the executor actually holds. ``func`` is ``BaseTool._run``."""

        def __init__(self, name, func):
            self.name = name
            self.func = func

        def invoke(self, input=None, **kwargs):
            args = dict(input or {})
            args.update(kwargs)
            return self.func(**args)

    class BaseTool:
        """Deliberately NOT callable and with no ``.func``.

        The real one is a Pydantic model whose implementation is ``_run``; it
        exposes ``model_copy`` and nothing else ``protect_tools`` keys on. Both
        properties are load-bearing — they are what makes a CrewAI tool a third
        shape rather than a LangChain tool or a plain callable.
        """

        def __init__(self, name, fn):
            self.name = name
            self.fn = fn

        def _run(self, *args, **kwargs):
            return self.fn(*args, **kwargs)

        def run(self, *args, **kwargs):
            # Public wrapper. Reachable ONLY from developer code that calls the
            # tool itself — never from an agent, which uses to_structured_tool().
            return self._run(*args, **kwargs)

        def model_copy(self, update=None):
            clone = BaseTool(self.name, self.fn)
            for key, value in (update or {}).items():
                setattr(clone, key, value)
            return clone

        def to_structured_tool(self):
            structured = CrewStructuredTool(name=self.name, func=self._run)
            structured._original_tool = self
            return structured

    # ── the agent-driven execution path ──────────────────────────────────
    def execute_tool_and_check_finality(tool, tool_input=None, agent=None,
                                        task=None, crew=None):
        """Condensed ``crewai.utilities.tool_utils`` path: hooks, then invoke.

        Only the two behaviours ``protect()`` depends on are reproduced — the
        hook context is built before execution, and a blocking hook returns the
        blocked message WITHOUT invoking the tool.
        """
        tool_input = dict(tool_input or {})
        context = ToolCallHookContext(
            tool_name=tool.name, tool_input=tool_input, tool=tool,
            agent=agent, task=task, crew=crew,
        )
        if run_before_tool_call_hooks(context):
            result = f"Tool execution blocked by hook. Tool: {tool.name}"
        else:
            # NOTE: `.invoke()`, so `func` (= BaseTool._run) is what runs.
            result = tool.to_structured_tool().invoke(context.tool_input)
        # The after-hooks run even on a BLOCKED call — verified in all four of
        # the real executor's dispatch sites, which set the blocked message and
        # then fall through to run_after_tool_call_hooks. Monitoring hooks
        # therefore still fire, and a hook may restate the result.
        after_context = ToolCallHookContext(
            tool_name=tool.name, tool_input=context.tool_input, tool=tool,
            agent=agent, task=task, crew=crew,
            tool_result=result, raw_tool_result=result,
        )
        modified = run_after_tool_call_hooks(after_context)
        return modified if modified is not None else result

    tool_utils.execute_tool_and_check_finality = execute_tool_and_check_finality

    class Crew:
        """``kickoff`` is the real public entrypoint; ``tool_calls`` stands in
        for the tool calls an LLM would emit during the run."""

        def __init__(self, runner=None, agents=None, tasks=None, tool_calls=None):
            self.runner = runner or (lambda inputs: f"ran with {inputs}")
            self.agents = list(agents or ())
            self.tasks = list(tasks or ())
            self.tool_calls = list(tool_calls or ())
            self.tool_results: list = []

        def kickoff(self, inputs=None):
            for tool, args in self.tool_calls:
                self.tool_results.append(
                    execute_tool_and_check_finality(
                        tool, args,
                        agent=self.agents[0] if self.agents else None,
                        task=self.tasks[0] if self.tasks else None,
                        crew=self,
                    )
                )
            return self.runner(inputs)

    tools.BaseTool = BaseTool
    tools.CrewStructuredTool = CrewStructuredTool
    mod.Crew = Crew
    mod.BaseTool = BaseTool
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
