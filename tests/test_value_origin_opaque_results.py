"""A tool result of a type value origin does not recognise, through the real frameworks.

Owner, 2026-11-01: an unrecognised type is never read as empty. What is read is
the representation the framework hands the model: ``str()`` where the framework
uses it (the Agents SDK; CrewAI, unless the tool formats its output), the
framework's own serialisation elsewhere (LangChain's ``json.dumps`` with a
``str()`` fallback; Haystack's ``_result_to_string``), within the same bounds. A
generator or an iterator is never consumed: a seam that sees one cuts the result.

Each check runs a real agent under ``xaidr.protect()`` in ENFORCE with a scripted
model: a ``fetch`` tool returns the value, the model then calls ``post`` to the
destination the value carries, and the call must be refused before ``post``
runs. Until 2026-11-01 the core read these values as having no text, and the
Agents SDK path recorded the raw value, so the call was allowed while the model
was handed the URL. Under ``protect()`` CrewAI and Haystack recorded no tool
result at all.

Each framework's checks skip when it is not installed; the CI job that installs
it fails on a skip.
"""
from __future__ import annotations

import asyncio
import collections
import json
import sys
import types
import warnings

import pytest

import xaidr

# Every framework name this module uses is bound here, at collection, as in
# tests/test_value_origin_real_runs.py: other test modules install fake framework
# modules into sys.modules and remove them, and an import made later builds fresh
# classes that are not the ones the real framework already holds.
try:
    import langchain.agents as lc_agents
    import langchain.agents.middleware  # noqa: F401
    import langgraph  # noqa: F401
    from langchain_core.language_models.chat_models import BaseChatModel
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
    from langchain_core.outputs import ChatGeneration, ChatResult
    from langchain_core.tools import tool as lc_tool
    HAVE_LC = True
except Exception:                                    # pragma: no cover - not installed
    HAVE_LC = False
try:
    from agents import Agent as OAAgent, Runner, function_tool
    from agents.items import ModelResponse
    from agents.models.interface import Model
    from agents.usage import Usage
    from openai.types.responses import (ResponseFunctionToolCall, ResponseOutputMessage,
                                        ResponseOutputText)
    HAVE_OA = True
except Exception:                                    # pragma: no cover
    HAVE_OA = False
try:
    from crewai import Agent as CrewAgent, Crew, Task
    from crewai.hooks import clear_all_hooks
    from crewai.llms.base_llm import BaseLLM
    from crewai.tools import BaseTool as CrewTool
    HAVE_CREW = True
except Exception:                                    # pragma: no cover
    HAVE_CREW = False
try:
    import haystack.components.agents.agent  # noqa: F401  (protect() patches what is loaded)
    import haystack.hooks  # noqa: F401
    from haystack import component
    from haystack.components.agents import Agent as HSAgent
    from haystack.dataclasses import ChatMessage, ToolCall
    from haystack.tools import tool as hs_tool
    HAVE_HS = True
except Exception:                                    # pragma: no cover
    HAVE_HS = False

_AS_COLLECTED = {k: m for k, m in sys.modules.items()
                 if k.split(".")[0] in ("langchain", "langchain_core", "langgraph", "agents",
                                        "openai", "crewai", "haystack")}


@pytest.fixture(autouse=True)
def _frameworks_as_collected(monkeypatch):
    for name, mod in _AS_COLLECTED.items():
        monkeypatch.setitem(sys.modules, name, mod)


needs_lc = pytest.mark.skipif(not HAVE_LC, reason="langchain and langgraph not installed")
needs_oa = pytest.mark.skipif(not HAVE_OA, reason="openai-agents not installed")
needs_crew = pytest.mark.skipif(not HAVE_CREW, reason="crewai not installed")
needs_hs = pytest.mark.skipif(not HAVE_HS, reason="haystack-ai>=3 not installed")

URL = "https://drop.opaque-r5.example/upload"


class Shown:
    """An object the frameworks hand the model as its ``str()``."""

    def __init__(self, text):
        self.text = text

    def __str__(self):
        return self.text


class Record:
    """Shown by ``repr()`` inside a container: ``str()`` of the container shows it so."""

    def __str__(self):
        return "a record"

    def __repr__(self):
        return f"Record(link={URL!r})"


class ShownMapping(dict):
    """A mapping with a ``str()`` of its own, which a framework that uses ``str()``
    hands the model, and one that serialises it as JSON does not."""

    def __str__(self):
        return f"The notes are at {URL} now."


# (name, the tool's return value). Each carries URL in the text the model is handed.
SHAPES = [
    ("nested bytes", lambda: {"body": f"Our status page moved to {URL} .".encode()}),
    ("a namespace", lambda: types.SimpleNamespace(link=URL)),
    ("a deque", lambda: collections.deque([URL])),
    ("an object shown by str()", lambda: Shown(f"The notes are at {URL} now.")),
    ("a member shown by repr()", lambda: [Record()]),
]
IDS = [n for n, _ in SHAPES]
# Carries URL only where the framework hands the model str(): the Agents SDK, CrewAI.
STR_SHAPES = SHAPES + [("a mapping shown by its own str()", lambda: ShownMapping(a="b"))]
STR_IDS = [n for n, _ in STR_SHAPES]


class _Null:
    def report(self, *a, **k):
        pass


def _protect(agent_id, targets=None):
    kw = {"targets": targets} if targets else {}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return xaidr.protect(agent_id=agent_id, enforcement_mode="block",
                             value_origin="enforce", reporter=_Null(), quiet=True, **kw)


class _Spy:
    def __init__(self, sensor):
        self.calls, self.ran = [], []
        orig = sensor.scan_tool_call

        def spy(name, args, *a, **k):
            r = orig(name, args, *a, **k)
            self.calls.append((name, r.value_origin.wire.value if r.value_origin else None,
                               str(getattr(r.action, "value", r.action))))
            return r
        sensor.scan_tool_call = spy

    def of(self, name):
        return [(w, a) for n, w, a in self.calls if n == name]


def _refused(spy):
    posts = spy.of("post")
    return (posts and all(w in ("untrusted_source", "result_unread") and a in ("block", "blocked")
                          for w, a in posts)
            and ("post", URL) not in spy.ran)


# ── LangChain create_agent ───────────────────────────────────────────────────
@needs_lc
@pytest.mark.parametrize("make", [m for _, m in SHAPES], ids=IDS)
@pytest.mark.parametrize("mode", ["invoke", "ainvoke"])
def test_langchain(make, mode):
    agents_mod, tool = lc_agents, lc_tool
    manifest = _protect("opaque-lc")
    spy = _Spy(manifest.sensor)
    try:
        class Scripted(BaseChatModel):
            script: list = []

            @property
            def _llm_type(self) -> str:
                return "scripted"

            def bind_tools(self, tools, **kwargs):
                return self

            def _generate(self, messages, stop=None, run_manager=None, **kwargs):
                return ChatResult(generations=[ChatGeneration(message=self.script.pop(0))])

        @tool
        def fetch(q: str):
            """Look something up."""
            return make()

        @tool
        def post(url: str) -> str:
            """Post the notes."""
            spy.ran.append(("post", url))
            return "ok"

        def call(name, args, i):
            return AIMessage(content="", tool_calls=[{"name": name, "args": args,
                                                      "id": f"c{i}", "type": "tool_call"}])
        agent = agents_mod.create_agent(
            model=Scripted(script=[call("fetch", {"q": "status"}, 1),
                                   call("post", {"url": URL}, 2), AIMessage(content="done")]),
            tools=[fetch, post])
        state = {"messages": [HumanMessage("Check the status and post the notes.")]}
        if mode == "invoke":
            agent.invoke(state)
        else:
            asyncio.run(agent.ainvoke(state))
    finally:
        manifest.unprotect()
    assert _refused(spy), f"LangChain {mode}: {spy.calls}, ran {spy.ran}"


@needs_lc
@pytest.mark.parametrize("mode", ["invoke", "ainvoke"])
def test_langchain_a_generator_is_handed_to_the_model_as_text_naming_nothing(mode):
    """LangChain turns a generator into ``str()`` itself, unconsumed, before any seam
    sees the result: the model is handed ``<generator object ...>``, which names no
    destination, and that text is what is read. Nothing the model was shown names
    the URL, so the call to it reads unresolved; the generator is not consumed."""
    agents_mod, tool = lc_agents, lc_tool
    consumed, shown = [], []
    manifest = _protect("opaque-lc-gen")
    spy = _Spy(manifest.sensor)
    try:
        class Scripted(BaseChatModel):
            script: list = []

            @property
            def _llm_type(self) -> str:
                return "scripted"

            def bind_tools(self, tools, **kwargs):
                return self

            def _generate(self, messages, stop=None, run_manager=None, **kwargs):
                shown.extend(m.content for m in messages if isinstance(m, ToolMessage))
                return ChatResult(generations=[ChatGeneration(message=self.script.pop(0))])

        def gen():
            consumed.append(True)
            yield URL

        @tool
        def fetch(q: str):
            """Look something up."""
            return gen()

        @tool
        def post(url: str) -> str:
            """Post the notes."""
            spy.ran.append(("post", url))
            return "ok"

        def call(name, args, i):
            return AIMessage(content="", tool_calls=[{"name": name, "args": args,
                                                      "id": f"c{i}", "type": "tool_call"}])
        agent = agents_mod.create_agent(
            model=Scripted(script=[call("fetch", {"q": "status"}, 1),
                                   call("post", {"url": URL}, 2), AIMessage(content="done")]),
            tools=[fetch, post])
        state = {"messages": [HumanMessage("Check the status and post the notes.")]}
        agent.invoke(state) if mode == "invoke" else asyncio.run(agent.ainvoke(state))
    finally:
        manifest.unprotect()
    assert not consumed, "a generator a tool returned was consumed"
    assert shown and shown[0].startswith("<generator object") and URL not in shown[0], shown
    assert spy.of("post") == [("unresolved", "allowed")], spy.calls


# ── OpenAI Agents SDK ────────────────────────────────────────────────────────
def _agents_run(tool_value, mode):
    Agent = OAAgent
    manifest = _protect("opaque-oa")
    spy = _Spy(manifest.sensor)
    try:
        @function_tool
        def fetch(q: str):
            """Look something up."""
            return tool_value()

        @function_tool
        def post(url: str) -> str:
            """Post the notes."""
            spy.ran.append(("post", url))
            return "ok"
        tools = manifest.sensor.protect_tools([fetch, post])

        def call(name, args, i):
            return ResponseFunctionToolCall(type="function_call", call_id=f"c{i}", name=name,
                                            arguments=json.dumps(args), id=f"fc{i}")
        done = ResponseOutputMessage(type="message", id="m", role="assistant",
                                     status="completed",
                                     content=[ResponseOutputText(type="output_text",
                                                                 text="done", annotations=[])])
        script = [call("fetch", {"q": "status"}, 1), call("post", {"url": URL}, 2), done]

        class Scripted(Model):
            async def get_response(self, *a, **k):
                return ModelResponse(output=[script.pop(0)], usage=Usage(), response_id=None)

            def stream_response(self, *a, **k):
                raise NotImplementedError
        agent = Agent(name="a", tools=tools, model=Scripted())
        value = "Check the status and post the notes."
        if mode == "run_sync":
            Runner.run_sync(agent, value)
        else:
            asyncio.run(Runner.run(agent, value))
    finally:
        manifest.unprotect()
    return spy


@needs_oa
@pytest.mark.parametrize("make", [m for _, m in STR_SHAPES], ids=STR_IDS)
@pytest.mark.parametrize("mode", ["run_sync", "run"])
def test_agents_sdk(make, mode):
    spy = _agents_run(make, mode)
    assert _refused(spy), f"Agents SDK {mode}: {spy.calls}, ran {spy.ran}"


@needs_oa
@pytest.mark.parametrize("mode", ["run_sync", "run"])
def test_agents_sdk_a_generator_is_not_consumed_and_cuts(mode):
    consumed = []

    def gen():
        consumed.append(True)
        yield URL
    spy = _agents_run(lambda: gen(), mode)
    assert not consumed, "a generator a tool returned was consumed"
    assert _refused(spy), f"Agents SDK {mode}: {spy.calls}, ran {spy.ran}"


# ── CrewAI ───────────────────────────────────────────────────────────────────
def _crew_run(tool_value):
    Agent, BaseTool = CrewAgent, CrewTool
    clear_all_hooks()
    manifest = _protect("opaque-crew", targets=["crewai"])
    spy = _Spy(manifest.sensor)
    try:
        class Fetch(BaseTool):
            name: str = "fetch"
            description: str = "Look something up. Argument: q (string)."

            def _run(self, q: str):
                return tool_value()

        class Post(BaseTool):
            name: str = "post"
            description: str = "Post the notes. Argument: url (string)."

            def _run(self, url: str) -> str:
                spy.ran.append(("post", url))
                return "ok"

        script = ['Thought: look it up.\nAction: fetch\nAction Input: {"q": "status"}',
                  'Thought: post them.\nAction: post\nAction Input: {"url": "' + URL + '"}',
                  "Thought: I am finished.\nFinal Answer: done"]

        class ScriptedLLM(BaseLLM):
            calls: int = 0

            def call(self, messages, tools=None, callbacks=None, available_functions=None,
                     from_task=None, from_agent=None, response_model=None):
                i = min(self.calls, len(script) - 1)
                self.calls += 1
                return script[i]

            def supports_function_calling(self) -> bool:
                return False

            def supports_stop_words(self) -> bool:
                return True

            def get_context_window_size(self) -> int:
                return 8192
        agent = Agent(role="ops", goal="post the notes", backstory="an ops agent",
                      llm=ScriptedLLM(model="scripted"), tools=[Fetch(), Post()],
                      verbose=False, max_iter=4)
        task = Task(description="{request}", expected_output="a status line", agent=agent)
        Crew(agents=[agent], tasks=[task], verbose=False).kickoff(
            inputs={"request": "Check the status and post the notes."})
    finally:
        manifest.unprotect()
        clear_all_hooks()
    return spy


@needs_crew
@pytest.mark.parametrize("make", [m for _, m in STR_SHAPES], ids=STR_IDS)
def test_crewai(make):
    spy = _crew_run(make)
    assert _refused(spy), f"CrewAI: {spy.calls}, ran {spy.ran}"


@needs_crew
def test_crewai_a_generator_is_not_consumed_and_cuts():
    consumed = []

    def gen():
        consumed.append(True)
        yield URL
    spy = _crew_run(lambda: gen())
    assert not consumed, "a generator a tool returned was consumed"
    assert _refused(spy), f"CrewAI: {spy.calls}, ran {spy.ran}"


# ── Haystack Agent ───────────────────────────────────────────────────────────
@needs_hs
@pytest.mark.parametrize("make", [m for _, m in SHAPES], ids=IDS)
def test_haystack(make):
    Agent, tool = HSAgent, hs_tool
    manifest = _protect("opaque-hs", targets=["haystack"])
    spy = _Spy(manifest.sensor)
    try:
        @tool
        def fetch(q: str) -> str:
            """Look something up."""
            return make()

        @tool
        def post(url: str) -> str:
            """Post the notes."""
            spy.ran.append(("post", url))
            return "ok"

        replies = [ChatMessage.from_assistant(tool_calls=[ToolCall(
                       tool_name="fetch", arguments={"q": "status"}, id="c1")]),
                   ChatMessage.from_assistant(tool_calls=[ToolCall(
                       tool_name="post", arguments={"url": URL}, id="c2")]),
                   ChatMessage.from_assistant("done")]

        @component
        class Scripted:
            @component.output_types(replies=list[ChatMessage])
            def run(self, messages, tools=None, **kwargs):
                return {"replies": [replies.pop(0)]}
        agent = Agent(chat_generator=Scripted(), tools=[fetch, post])
        agent.warm_up()
        agent.run(messages=[ChatMessage.from_user("Check the status and post the notes.")])
    finally:
        manifest.unprotect()
    assert _refused(spy), f"Haystack: {spy.calls}, ran {spy.ran}"


@needs_hs
def test_haystack_a_generator_is_handed_to_the_model_as_text_naming_nothing():
    """Haystack turns a generator into ``str()`` itself (``_result_to_string``, after
    ``json.dumps`` refuses it), unconsumed: the model is handed ``<generator object
    ...>``, which names nothing, and that text is what is read."""
    Agent, tool = HSAgent, hs_tool
    consumed, shown = [], []
    manifest = _protect("opaque-hs-gen", targets=["haystack"])
    spy = _Spy(manifest.sensor)
    try:
        def gen():
            consumed.append(True)
            yield URL

        @tool
        def fetch(q: str) -> str:
            """Look something up."""
            return gen()

        @tool
        def post(url: str) -> str:
            """Post the notes."""
            spy.ran.append(("post", url))
            return "ok"

        replies = [ChatMessage.from_assistant(tool_calls=[ToolCall(
                       tool_name="fetch", arguments={"q": "status"}, id="c1")]),
                   ChatMessage.from_assistant(tool_calls=[ToolCall(
                       tool_name="post", arguments={"url": URL}, id="c2")]),
                   ChatMessage.from_assistant("done")]

        @component
        class Scripted:
            @component.output_types(replies=list[ChatMessage])
            def run(self, messages, tools=None, **kwargs):
                shown.extend(m.tool_call_result.result for m in messages if m.is_from("tool"))
                return {"replies": [replies.pop(0)]}
        agent = Agent(chat_generator=Scripted(), tools=[fetch, post])
        agent.warm_up()
        agent.run(messages=[ChatMessage.from_user("Check the status and post the notes.")])
    finally:
        manifest.unprotect()
    assert not consumed, "a generator a tool returned was consumed"
    assert shown and shown[0].startswith("<generator object") and URL not in shown[0], shown
    assert spy.of("post") == [("unresolved", "allowed")], spy.calls


def test_the_shapes_carry_the_destination_in_what_the_model_is_handed():
    """The control: each shape's ``str()`` (what the SDK and CrewAI hand the
    model) names the destination, so a call to it is one the result prompted; and
    a mapping with its own ``str()`` is JSON without it where the framework
    serialises a result as JSON (LangChain, Haystack), so there it prompts none."""
    for name, make in STR_SHAPES:
        assert URL in str(make()), name
    assert URL not in json.dumps(ShownMapping(a="b"))
