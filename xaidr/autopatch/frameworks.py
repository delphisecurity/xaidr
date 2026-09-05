"""One patcher per framework — the whole inventory of what ``protect()`` covers.

Every patcher receives a :class:`~xaidr.autopatch.core.PatchContext` and may
only touch modules that are ALREADY in ``sys.modules``. A patcher that finds an
unexpected shape raises ``PatchUnavailable`` (or calls ``ctx.unpatchable``) —
never ``pass``.

TWO SEAM KINDS, and the difference matters operationally:

* A **class-method** seam (``httpx.Client.send``, ``BaseTool.run``) is looked up
  on the class at every call, so it covers objects created before AND after
  ``protect()``, and it survives ``from x import Y``.
* A **module-function** seam (``langchain.agents.create_agent``) is a name
  rebind. Code that already did ``from langchain.agents import create_agent``
  before ``protect()`` holds the ORIGINAL and will not be instrumented. Every
  such seam adds a manifest note saying so.

Where a boundary genuinely has no seam, that is recorded as ``found_unpatchable``
with the concrete reason, not omitted.
"""

from __future__ import annotations

import contextvars
import json
import sys
from dataclasses import dataclass
from typing import Any, Callable, Optional

from ..types import DelphiBlockedError
from .core import (
    Halt,
    PatchContext,
    PatchUnavailable,
    is_exempt,
    is_xaidr_wrapper,
    make_wrapper,
    refusal_text,
    scan_text_boundary,
    scan_tool_boundary,
    strings_in,
    tool_verdict,
)

#: Set while the LangChain middleware's ``wrap_tool_call`` hook is running, so
#: the ``BaseTool.run`` patch underneath it does not scan the same call twice.
#: Falls back to double-scanning (safe, just noisier) if the guard cannot be
#: installed — which the manifest then says out loud.
_MW_TOOL_SCANNED: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "xaidr_mw_tool_scanned", default=False
)


@dataclass(frozen=True)
class FrameworkTarget:
    name: str
    detect: tuple[str, ...]
    apply: Callable[[PatchContext], None]
    summary: str
    #: Optional identity check for a module whose NAME is not distinctive.
    #: `agents` is a name anyone might use for their own package; claiming that
    #: module is the OpenAI Agents SDK and then warning that it is unprotected
    #: would be a false alarm, and false alarms are how a loud manifest stops
    #: being read. Returns False -> treated as not present at all.
    verify: Optional[Callable[[Any], bool]] = None

    def present(self) -> bool:
        """True if ANY detection key is imported AND looks like this framework.

        Reads sys.modules only — never imports.
        """
        for key in self.detect:
            mod = sys.modules.get(key)
            if mod is None:
                continue
            if self.verify is None:
                return True
            try:
                if self.verify(mod):
                    return True
            except Exception:
                continue
        return False


def _looks_like_openai_agents(mod: Any) -> bool:
    """Distinguish the OpenAI Agents SDK from someone's own ``agents`` package."""
    return any(hasattr(mod, attr) for attr in ("Runner", "Agent", "function_tool"))


# ─────────────────────────────────────────────────────────────────────────
# httpx — egress. Class-method seam, the most robust kind.
# ─────────────────────────────────────────────────────────────────────────


def _http_extractor(sensor: Any):
    """A ``ProtectedHttpClient`` used purely as an extractor/enforcer.

    ``_scan_request`` / ``_scan_response`` never touch ``self._client``, so a
    ``None`` client is fine — the sensor already instantiates it this way for
    A2A field extraction. Reusing it means the autopatch path and the explicit
    ``sensor.protect_http()`` path cannot drift apart in what they scan.
    """
    from ..sensor import ProtectedHttpClient

    return ProtectedHttpClient(None, sensor)


def _httpx_body(request: Any) -> tuple[Optional[dict], Any]:
    """(json_body, raw_content) for an httpx Request, without consuming a stream."""
    try:
        raw = request.content  # raises on an unread streaming request
    except Exception:
        return None, None
    if not raw:
        return None, None
    try:
        parsed = json.loads(raw)
    except Exception:
        return None, raw
    return (parsed, None) if isinstance(parsed, dict) else (None, raw)


def _patch_httpx(ctx: PatchContext) -> None:
    ctx.module("httpx")
    ext = _http_extractor(ctx.sensor)

    def factory(orig: Callable) -> Callable:
        def before(args: tuple, kwargs: dict) -> Optional[Halt]:
            if is_exempt(args):
                return None
            request = kwargs.get("request") or (args[1] if len(args) > 1 else None)
            if request is None:
                return None
            body, raw = _httpx_body(request)
            # Destination check runs for EVERY verb; body content scan only has
            # something to look at on a request that carries one.
            ext._scan_request(str(getattr(request, "url", "")), body, raw)
            return None

        def after(response: Any, args: tuple, kwargs: dict) -> Any:
            if is_exempt(args) or kwargs.get("stream"):
                # Reading the body here would consume the caller's stream.
                return response
            return ext._scan_response(response)

        return make_wrapper(orig, before=before, after=after)

    ctx.install(
        "httpx", "Client.send", "egress", factory,
        "outgoing request: destination blocklist + deny-destination policy on "
        "every verb, A2A/JSON body content scan, response output-DLP scan",
    )
    ctx.try_install(
        "httpx", "AsyncClient.send", "egress", factory,
        "same coverage on the async client",
    )
    ctx.note(
        "egress: a telemetry reporter that ships events over HTTP would otherwise "
        "scan its own POST, enqueue another event, and loop forever. xaidr's "
        "WebhookReporter is exempted automatically; if you wrote your own HTTP "
        "reporter, wrap its client in xaidr.autopatch.exempt()."
    )
    ctx.note(
        "httpx: patched at Client.send, so httpx.get()/post() module helpers and "
        "every Client instance — including ones built before protect() — are "
        "covered. Streaming responses (stream=True) are NOT body-scanned: "
        "reading them would consume the caller's stream."
    )


# ─────────────────────────────────────────────────────────────────────────
# requests — egress. Same seam shape.
# ─────────────────────────────────────────────────────────────────────────


def _patch_requests(ctx: PatchContext) -> None:
    ctx.module("requests")
    ext = _http_extractor(ctx.sensor)

    def factory(orig: Callable) -> Callable:
        def before(args: tuple, kwargs: dict) -> Optional[Halt]:
            if is_exempt(args):
                return None
            request = kwargs.get("request") or (args[1] if len(args) > 1 else None)
            if request is None:
                return None
            raw = getattr(request, "body", None)
            body = None
            if isinstance(raw, (str, bytes, bytearray)):
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        body, raw = parsed, None
                except Exception:
                    pass
            else:
                raw = None  # a generator/file body — do not consume it
            ext._scan_request(str(getattr(request, "url", "")), body, raw)
            return None

        def after(response: Any, args: tuple, kwargs: dict) -> Any:
            if is_exempt(args) or kwargs.get("stream"):
                return response
            return ext._scan_response(response)

        return make_wrapper(orig, before=before, after=after)

    ctx.install(
        "requests", "Session.send", "egress", factory,
        "outgoing request: destination blocklist + deny-destination policy on "
        "every verb, JSON body content scan, response output-DLP scan",
    )
    ctx.note(
        "requests: patched at Session.send, which requests.get()/post() and every "
        "Session route through. A generator/file upload body is not scanned — "
        "consuming it would break the upload."
    )


# ─────────────────────────────────────────────────────────────────────────
# langchain_core — the tool boundary for LangChain AND LangGraph AND any
# framework that executes a langchain tool (CrewAI's langchain interop does).
# ─────────────────────────────────────────────────────────────────────────


def _tool_seam_covered(ctx: PatchContext) -> bool:
    """True if this run already patched the langchain_core tool seam.

    Several frameworks execute langchain BaseTools, so their own gap notes must
    say whether the tool boundary is covered — a note that claims coverage from
    a patch that did not happen is worse than no note.
    """
    return any(
        r.framework == "langchain_core" and r.boundary == "tool"
        for r in ctx.manifest.patched
    )


def _langchain_refusal(text: str, name: str, kwargs: dict) -> Any:
    """Return the refusal in the TYPE this particular caller was promised.

    ``BaseTool.run`` has two callers with two different return contracts, and
    returning one contract's value to the other is not a cosmetic mismatch — it
    crashed the host. A LangGraph ``ToolNode`` calls ``tool.invoke(tool_call)``,
    which requires a ``ToolMessage`` back and raises
    ``TypeError: Tool <name> returned unexpected type: <class 'str'>`` on
    anything else; ToolNode's default ``handle_tool_errors`` re-raises it, so a
    correctly-blocked call took the whole graph down instead of handing the
    agent a refusal it could read. Direct ``tool.run(args)`` callers, meanwhile,
    have always received the plain string and must keep receiving it.

    THE DISCRIMINATOR IS ``tool_call_id``, NOT THE SHAPE OF THE INPUT, and the
    difference matters. It is tempting to sniff ``tool_input`` for a ToolCall —
    a dict with ``type == "tool_call"``. That test cannot work here and would be
    unsafe if it could: ``_prep_run_args`` has ALREADY unwrapped the envelope by
    the time ``run`` is entered (``tool_input = value["args"].copy()``), so what
    the seam sees is the tool's own ARGUMENTS and the ToolCall shape is simply
    not present. Sniffing would therefore only ever fire on a user tool whose
    arguments happen to look like a tool call — a replay, audit or router tool
    that takes one as its payload is an entirely ordinary thing to write — and
    that tool's caller would silently get a ToolMessage where it expected a
    string. There is no such ambiguity here: ``tool_call_id`` is set by
    langchain's own ``_prep_run_args`` from ``value["id"]`` and is keyword-only
    on ``run``/``arun``, so it can never be spoofed by a tool's arguments.

    This mirrors the library's own rule at the same decision point:
    ``_format_output`` returns a ``ToolMessage`` iff ``tool_call_id is not
    None`` and the raw content otherwise. Verified against langchain-core 1.6.1.

    Resolving ``ToolMessage`` from ``sys.modules`` rather than importing keeps
    rule 1 (never import a framework to instrument it). A ``tool_call_id`` only
    exists because a ToolCall came off an AIMessage, so ``langchain_core.messages``
    is necessarily imported by then; if it somehow is not, or construction
    fails, this falls back to the string — the pre-existing behaviour, never an
    exception out of a security wrapper.
    """
    tool_call_id = kwargs.get("tool_call_id")
    if tool_call_id is None:
        return text
    messages = sys.modules.get("langchain_core.messages")
    tool_message = getattr(messages, "ToolMessage", None) if messages else None
    if tool_message is None:
        return text
    try:
        return tool_message(
            content=text, tool_call_id=tool_call_id, name=name, status="error"
        )
    except Exception:
        return text


def _patch_langchain_core(ctx: PatchContext) -> None:
    ctx.module("langchain_core.tools")

    def factory(orig: Callable) -> Callable:
        def before(args: tuple, kwargs: dict) -> Optional[Halt]:
            if _MW_TOOL_SCANNED.get():
                # The delphi_middleware tool hook above us already scanned this
                # exact call. Scanning again would double the telemetry for one
                # action and make event counts lie.
                return None
            tool = args[0] if args else None
            name = getattr(tool, "name", None) or "unknown_tool"
            tool_input = kwargs.get("tool_input")
            if tool_input is None and len(args) > 1:
                tool_input = args[1]
            halt = scan_tool_boundary(ctx.sensor, name, tool_input)
            if halt is None:
                return None
            return Halt(_langchain_refusal(halt.value, name, kwargs))

        return make_wrapper(orig, before=before)

    ctx.install(
        "langchain_core.tools", "BaseTool.run", "tool", factory,
        "every sync tool invocation is scan_tool_call'd before it executes; a "
        "halting verdict returns the refusal instead of running the tool — as a "
        "ToolMessage when the caller passed a tool_call_id (a ToolNode or "
        "create_agent tool call), as the refusal string otherwise",
    )
    ctx.try_install(
        "langchain_core.tools", "BaseTool.arun", "tool", factory,
        "same coverage on the async tool path (ainvoke)",
    )
    ctx.note(
        "langchain_core: BaseTool.run/arun is a class-method seam, so it covers "
        "tools defined before protect(), tools executed by a LangGraph ToolNode, "
        "and tools called directly — not just tools inside create_agent()."
    )


# ─────────────────────────────────────────────────────────────────────────
# langchain — the input/output boundary, via the existing middleware.
# ─────────────────────────────────────────────────────────────────────────


def _build_middleware(ctx: PatchContext) -> Any:
    """Build one delphi_middleware bound to OUR sensor, guarded for re-entry."""
    # delphi_middleware imports these two. Requiring them to be in sys.modules
    # FIRST is what keeps rule 1 true: the import inside it then resolves from
    # the module cache and pulls in no framework code. Without this check,
    # building the middleware would import langchain.agents.middleware on a
    # process that had only imported langchain.agents.
    ctx.module("langchain.agents.middleware")
    ctx.module("langchain_core.messages")
    try:
        from ..integrations.langchain import delphi_middleware
    except Exception as exc:  # pragma: no cover - import of our own module
        raise PatchUnavailable(f"xaidr LangChain integration unavailable: {exc}") from exc
    try:
        mw = delphi_middleware(
            agent_id=ctx.sensor.agent_id,
            enforcement_mode=ctx.sensor.enforcement_mode,
            sensor=ctx.sensor,
        )
    except ImportError as exc:
        raise PatchUnavailable(
            f"langchain>=1.0 middleware API not importable: {exc}"
        ) from exc

    cls = type(mw)
    cls.__xaidr_middleware__ = True
    # Re-entrancy guard so BaseTool.run underneath does not rescan the same call.
    try:
        inner = cls.wrap_tool_call

        def guarded(self, request, handler):
            token = _MW_TOOL_SCANNED.set(True)
            try:
                return inner(self, request, handler)
            finally:
                _MW_TOOL_SCANNED.reset(token)

        cls.wrap_tool_call = guarded
    except Exception:
        ctx.note(
            "langchain: could not install the middleware/BaseTool re-entrancy "
            "guard, so a tool call inside create_agent() will be scanned at BOTH "
            "boundaries. The verdict is unchanged; telemetry double-counts."
        )
    return mw


def _patch_langchain(ctx: PatchContext) -> None:
    mod = ctx.module("langchain.agents")
    if not hasattr(mod, "create_agent"):
        tail = (
            "The tool boundary IS still covered via langchain_core.tools.BaseTool "
            "(patched above)."
            if _tool_seam_covered(ctx)
            else "The tool boundary is NOT covered either — langchain_core.tools "
                 "was not imported/patched."
        )
        raise PatchUnavailable(
            "langchain.agents.create_agent not found — this is langchain<1.0, "
            "which has no middleware= seam. " + tail + " For input/output, call "
            "sensor.scan()/scan_output() at your own entry points"
        )
    mw = _build_middleware(ctx)

    def factory(orig: Callable) -> Callable:
        def before(args: tuple, kwargs: dict) -> Optional[Halt]:
            existing = list(kwargs.get("middleware") or ())
            if not any(
                getattr(type(m), "__xaidr_middleware__", False) for m in existing
            ):
                kwargs["middleware"] = existing + [mw]
            return None

        return make_wrapper(orig, before=before)

    ctx.install(
        "langchain.agents", "create_agent", "input+output+tool", factory,
        "injects xaidr.integrations.langchain.delphi_middleware into every "
        "create_agent() call: before_model input scan, wrap_tool_call tool scan, "
        "after_model output scan — all on the same sensor",
    )
    ctx.note(
        "langchain: create_agent is a MODULE FUNCTION, so a module that already "
        "ran `from langchain.agents import create_agent` before protect() holds "
        "the unpatched original. Call protect() before importing your agent "
        "modules, or pass middleware=[delphi_middleware(...)] yourself."
    )


# ─────────────────────────────────────────────────────────────────────────
# langgraph — no seam of its own; report exactly what is and is not covered.
# ─────────────────────────────────────────────────────────────────────────


def _tool_tail(ctx: PatchContext) -> str:
    """What a seamless framework's gap note may truthfully say about tools.

    Shared by langgraph and deepagents: neither has a seam of its own, so for
    both the honest sentence depends on whether the langchain_core tool seam
    actually landed in THIS run.
    """
    if _tool_seam_covered(ctx):
        return (
            "Tool calls ARE covered: a LangGraph ToolNode executes langchain_core "
            "BaseTools, which protect() patched above."
        )
    return (
        "Tool calls are NOT covered either, because langchain_core.tools is "
        "not imported/patched — so this graph currently has NO instrumented "
        "boundary at all."
    )


def _patch_langgraph(ctx: PatchContext) -> None:
    ctx.module("langgraph")
    ctx.unpatchable(
        "langgraph.graph.StateGraph", "input+output",
        "a StateGraph's nodes are callables YOU supply; there is no library-owned "
        "call site between the graph and your node functions to wrap, and "
        "patching Pregel.invoke would scan opaque state dicts rather than "
        "messages. " + _tool_tail(ctx) + " For the graph's own input/output, use "
        "langchain.agents.create_agent (which protect() does instrument), add "
        "delphi_middleware(...).before_model / .after_model as graph nodes, or "
        "call sensor.scan()/scan_output() in your entry and exit nodes.",
    )


# ─────────────────────────────────────────────────────────────────────────
# deepagents — create_agent all the way down, so import ORDER decides.
# ─────────────────────────────────────────────────────────────────────────

#: The modules that bind ``create_agent`` at import time and therefore decide
#: whether a deep agent is instrumented. Checked, not assumed.
_DEEPAGENTS_BUILDERS = ("deepagents.graph", "deepagents.middleware.subagents")


def _patch_deepagents(ctx: PatchContext) -> None:
    """deepagents has no seam of its own: it builds every agent with create_agent.

    ``deepagents.graph`` (and the subagent middleware) run
    ``from langchain.agents import create_agent`` at IMPORT time, which is a name
    rebind — so whether ``protect()`` reaches a deep agent is decided entirely by
    whether ``protect()`` ran BEFORE ``import deepagents``. Nothing about that is
    visible at the call site, so it is checked here rather than assumed, and this
    reports what actually happened in THIS process.
    """
    ctx.module("deepagents")
    bound = {}
    for name in _DEEPAGENTS_BUILDERS:
        mod = sys.modules.get(name)
        if mod is not None and hasattr(mod, "create_agent"):
            bound[name] = is_xaidr_wrapper(mod.create_agent)

    if not bound:
        ctx.unpatchable(
            "deepagents.graph.create_agent", "input+output",
            "deepagents is imported but no module in it holds a create_agent "
            "reference, so this version's layout is not recognised and NOTHING "
            "can be claimed about its input/output coverage. " + _tool_tail(ctx),
        )
        return

    stale = sorted(name for name, patched in bound.items() if not patched)
    if stale:
        ctx.unpatchable(
            "deepagents.graph.create_agent", "input+output",
            "deepagents was imported BEFORE protect(), so "
            + ", ".join(stale)
            + " each hold the ORIGINAL langchain.agents.create_agent and the "
            "delphi_middleware injection never reaches a deep agent: the model "
            "input and the model output of every deep agent (and of every "
            "subagent) are UNSCANNED. Measured: an injected prompt reaches the "
            "model and a leaked AWS key reaches the caller verbatim. Fix by "
            "calling xaidr.protect() before `import deepagents`, or by passing "
            "middleware=[delphi_middleware(...)] to create_deep_agent() "
            "yourself. " + _tool_tail(ctx),
        )
        return

    ctx.note(
        "deepagents: no seam of its own — every deep agent and every subagent is "
        "built by langchain.agents.create_agent, which protect() patched BEFORE "
        "deepagents imported it, so the middleware is injected into all of them "
        "(input via before_model, output via after_model, tool args via "
        "wrap_tool_call — including deepagents' own built-in tools such as "
        "`task` and `write_file`). NOT covered: tool RESULTS. A subagent's answer "
        "comes back as a ToolMessage, which no boundary scans in the PARENT — it "
        "is scanned in the subagent's own after_model, and only because the "
        "subagent was built by the patched create_agent too."
    )


# ─────────────────────────────────────────────────────────────────────────
# OpenAI Agents SDK (`agents`) — entrypoint boundary only, and say why.
# ─────────────────────────────────────────────────────────────────────────


def _patch_openai_agents(ctx: PatchContext) -> None:
    ctx.module("agents")

    def factory(orig: Callable) -> Callable:
        def before(args: tuple, kwargs: dict) -> Optional[Halt]:
            # Runner.run is a classmethod: (cls, starting_agent, input, ...)
            value = kwargs.get("input")
            if value is None and len(args) > 2:
                value = args[2]
            for text in strings_in(value, limit=8):
                scan_text_boundary(ctx.sensor, text, "input")
            return None

        def after(result: Any, args: tuple, kwargs: dict) -> Any:
            scan_text_boundary(ctx.sensor, getattr(result, "final_output", None), "output")
            return result

        return make_wrapper(orig, before=before, after=after)

    ctx.try_install(
        "agents", "Runner.run", "input+output", factory,
        "scans the run input before the agent starts and result.final_output after",
    )
    ctx.try_install(
        "agents", "Runner.run_sync", "input+output", factory,
        "same coverage on the sync entrypoint",
    )
    # No framework-level raise when both sites failed: try_install already
    # recorded one loud entry per site, and a third summary entry for the same
    # problem dilutes the section a reader must not skim.
    ctx.unpatchable(
        "agents.FunctionTool.on_invoke_tool", "tool",
        "on_invoke_tool is a per-INSTANCE dataclass field on each FunctionTool, "
        "not a class method, so there is no single call site to wrap without "
        "walking every Agent's tool list — which protect() cannot do for agents "
        "it has never seen. Wrap your tools explicitly instead: "
        "handle.sensor.protect_tools([...]) before constructing the Agent.",
    )
    ctx.note(
        "openai-agents: Runner.run_streamed is NOT patched — its result is a "
        "streaming handle, so there is no final_output to scan at return time."
    )


# ─────────────────────────────────────────────────────────────────────────
# CrewAI — the sanctioned before_tool_call hook, plus the crew entrypoint.
#
# THE TOOL BOUNDARY IS A HOOK, NOT A PATCH, AND THAT IS A CORRECTION.
# xaidr <= 1.6.1 patched ``crewai.tools.BaseTool.run`` here and the manifest
# said "every CrewAI tool invocation is scan_tool_call'd before it executes".
# That claim was false. ``BaseTool.to_structured_tool()`` binds
# ``CrewStructuredTool(func=self._run)``, so an agent's tool call runs
# ``invoke()`` -> ``func`` -> ``_run`` and never touches ``BaseTool.run``.
# Measured against crewai 1.15.17: the patch fired on 0 of 3 agent-driven paths
# (Crew.kickoff, Crew.kickoff_async, Agent.kickoff) while a destructive command
# executed, and the manifest reported the boundary as covered throughout. The
# only path it uniquely saw was a developer calling ``tool.run()`` with no
# agent — not an agent boundary, and already covered by protect_tools().
# ─────────────────────────────────────────────────────────────────────────


def _patch_crewai(ctx: PatchContext) -> None:
    ctx.module("crewai")

    def kickoff_factory(orig: Callable) -> Callable:
        def before(args: tuple, kwargs: dict) -> Optional[Halt]:
            value = kwargs.get("inputs")
            if value is None and len(args) > 1:
                value = args[1]
            for text in strings_in(value, limit=32):
                scan_text_boundary(ctx.sensor, text, "input")
            return None

        return make_wrapper(orig, before=before)

    # ── TOOL boundary — crewai.hooks, the framework's own registry ───────
    # ctx.module() first so a build without the hook API is reported as
    # unpatchable rather than triggering an import (rule 1).
    try:
        ctx.module("crewai.hooks")
    except PatchUnavailable as exc:
        ctx.unpatchable(
            "crewai.hooks.register_before_tool_call_hook", "tool",
            f"{exc}. Without the hook registry there is NO usable tool seam on "
            "this build: BaseTool.run is bypassed by the agent path "
            "(to_structured_tool binds func=BaseTool._run), so patching it "
            "would report coverage that does not exist. Scan tool calls "
            "explicitly with sensor.protect_tools(...) instead.",
        )
    else:
        from ..integrations.crewai import install_tool_hooks

        ctx.install_registry_hook(
            "crewai.hooks.register_before_tool_call_hook", "tool",
            lambda: install_tool_hooks(ctx.sensor),
            "AGENT-DRIVEN tool calls are scan_tool_call'd before they execute "
            "(Crew.kickoff, Crew.kickoff_async and Agent.kickoff all dispatch "
            "this hook). Does NOT cover a direct tool.run() from your own code "
            "with no agent — wrap those with sensor.protect_tools(...).",
        )

    ctx.try_install(
        "crewai", "Crew.kickoff", "input", kickoff_factory,
        "scans the string values of the kickoff inputs before the crew runs",
    )
    ctx.note(
        "crewai: the tool boundary is a registered before_tool_call HOOK, not a "
        "patch. It covers agent-driven calls only; a direct tool.run() in your "
        "own code is not an agent boundary and is covered by protect_tools()."
    )
    ctx.note(
        "crewai: agent OUTPUT is not scanned by protect() — CrewAI's output "
        "seam is Task(guardrail=...), which is PER-TASK and has no registry, so "
        "protect() cannot install it for you. Pass "
        "xaidr.integrations.crewai.delphi_guardrail(handle.sensor) to every "
        "Task whose output you want scanned. Note CrewAI RAISES when a "
        "guardrail finally fails, rather than returning a refusal the agent can "
        "recover from."
    )


# ─────────────────────────────────────────────────────────────────────────
# AutoGen — two incompatible product lines under one brand.
# ─────────────────────────────────────────────────────────────────────────


def _patch_autogen_core(ctx: PatchContext) -> None:
    ctx.module("autogen_core.tools")

    def factory(orig: Callable) -> Callable:
        def before(args: tuple, kwargs: dict) -> Optional[Halt]:
            tool = args[0] if args else None
            name = getattr(tool, "name", None) or "unknown_tool"
            arguments = kwargs.get("args")
            if arguments is None and len(args) > 1:
                arguments = args[1]
            return scan_tool_boundary(ctx.sensor, name, dict(arguments or {}))

        return make_wrapper(orig, before=before)

    ctx.install(
        "autogen_core.tools", "BaseTool.run_json", "tool", factory,
        "every AgentChat 0.4+ tool dispatch is scanned before it executes",
    )


def _patch_autogen_legacy(ctx: PatchContext) -> None:
    ctx.module("autogen")

    def factory(orig: Callable) -> Callable:
        def before(args: tuple, kwargs: dict) -> Optional[Halt]:
            call = kwargs.get("func_call")
            if call is None and len(args) > 1:
                call = args[1]
            if not isinstance(call, dict):
                return None
            name = call.get("name") or "unknown_tool"
            raw = call.get("arguments")
            arguments: Any = raw
            if isinstance(raw, str):
                try:
                    arguments = json.loads(raw)
                except Exception:
                    arguments = {"arguments": raw}
            halt = scan_tool_boundary(ctx.sensor, name, arguments)
            if halt is None:
                return None
            # execute_function returns (is_exec_success, response_dict).
            return Halt((False, {"name": name, "role": "function", "content": halt.value}))

        return make_wrapper(orig, before=before)

    ctx.install(
        "autogen", "ConversableAgent.execute_function", "tool", factory,
        "SYNC function dispatch is scanned before it executes. The ASYNC path "
        "is NOT covered — see the note below.",
    )
    ctx.note(
        "autogen (0.2): this is the legacy pyautogen line. Its function-call "
        "shape has changed across 0.2.x minor releases; if the manifest stops "
        "listing this target after an upgrade, the boundary is uninstrumented."
    )
    # KNOWN GAP, stated because a manifest that is loud about a boundary it does
    # not have is the failure this package exists to avoid. Verified against
    # pyautogen 0.2.35.
    ctx.unpatchable(
        "autogen.ConversableAgent.a_execute_function", "tool",
        "ASYNC tool calls are UNINSTRUMENTED. The async reply path is "
        "a_generate_tool_calls_reply -> _a_execute_tool_call -> "
        "a_execute_function, which is a separate method that does NOT go "
        "through the patched execute_function. Only the sync path is covered. "
        "Scan async dispatches with handle.sensor.scan_tool_call(), or wrap the "
        "functions themselves with protect_tools().",
    )


# ─────────────────────────────────────────────────────────────────────────
# LlamaIndex
# ─────────────────────────────────────────────────────────────────────────


def _patch_llama_index(ctx: PatchContext) -> None:
    ctx.module("llama_index.core.tools")

    def factory(orig: Callable) -> Callable:
        def before(args: tuple, kwargs: dict) -> Optional[Halt]:
            tool = args[0] if args else None
            meta = getattr(tool, "metadata", None)
            name = getattr(meta, "name", None) or getattr(tool, "name", None) or "unknown_tool"
            arguments = dict(kwargs)
            for i, v in enumerate(args[1:]):
                arguments[f"arg{i}"] = v
            return scan_tool_boundary(ctx.sensor, name, arguments)

        return make_wrapper(orig, before=before)

    ctx.try_install(
        "llama_index.core.tools", "FunctionTool.call", "tool", factory,
        "every sync FunctionTool invocation is scanned before it executes",
    )
    ctx.try_install(
        "llama_index.core.tools", "FunctionTool.acall", "tool", factory,
        "same coverage on the async path",
    )
    ctx.unpatchable(
        "llama_index.core.tools.QueryEngineTool", "tool",
        "QueryEngineTool and the other non-FunctionTool tool types route through "
        "their own call() overrides rather than FunctionTool's, so patching "
        "FunctionTool does not reach them. Wrap them with "
        "handle.sensor.protect_tools([...]) if you use them.",
    )
    # KNOWN GAP. Verified against llama-index-core 0.14.24: the workflow agents
    # call tool.acall(**input) and ARE covered; this one agent is not.
    ctx.unpatchable(
        "llama_index.core.agent.workflow.codeact_agent", "tool",
        "CodeActAgent is UNINSTRUMENTED. It collects `tool.real_fn` and calls "
        "the underlying function directly, bypassing BOTH FunctionTool.call and "
        "FunctionTool.acall, so the patches above never see its tool calls. "
        "Wrap the functions with handle.sensor.protect_tools([...]) before "
        "building the tools if you use this agent.",
    )


# ─────────────────────────────────────────────────────────────────────────
# haystack (deepset) — Agent hooks, injected at construction.
#
# Haystack has no global hook registry (unlike CrewAI) and no middleware=
# parameter on a module function (unlike LangChain): its hooks are a
# CONSTRUCTOR ARGUMENT, ``Agent(hooks={...})``. So the seam is
# ``Agent.__init__`` itself, and what the patch does is merge this package's
# hooks into whatever the caller passed.
#
# WHY NOT ``Tool.invoke``, which is the obvious class-method seam and would be
# the more robust KIND of seam. Two reasons, both measured against
# haystack-ai 3.1.1 rather than assumed:
#
#   1. It is the wrong ARGUMENTS. The Agent calls ``tool.invoke(**args)`` where
#      ``args`` is ``_prepare_tool_args(...)`` output — the model's arguments
#      AFTER ``_inject_state_args`` has merged in State values and possibly a
#      streaming callback. Scanning that means scanning a live ``State`` object
#      alongside the model's text. ``before_tool`` sees ``tool_call.arguments``,
#      which is exactly what the model asked for and exactly ``scan_tool_call``'s
#      input, with nothing added and nothing lost.
#   2. It cannot BLOCK cleanly. ``Tool.invoke``'s only refusal channel is its
#      return value, which becomes the tool's result — the call is recorded as
#      having run. The ``before_tool`` hook removes the call before the executor
#      sees it, which is the framework's own documented rejection path and the
#      one its ``ConfirmationHook`` uses.
#
# ``Pipeline._run_component`` was considered and rejected too: it is
# ``instance.run(**inputs)`` over an arbitrary per-component input dict, with no
# notion of a user message, so a scan there would be scanning opaque state.
# ─────────────────────────────────────────────────────────────────────────


def _patch_haystack(ctx: PatchContext) -> None:
    module_name = "haystack.components.agents.agent"
    mod = ctx.module(module_name)
    if not hasattr(mod, "Agent"):
        raise PatchUnavailable(
            f"{module_name}.Agent not found — unexpected haystack layout. For "
            "input/output, call sensor.scan()/scan_output() at your own entry "
            "points; for tools, use sensor.protect_tools(...)"
        )
    # ctx.module() FIRST so a haystack without the 3.x hook API is reported as
    # unpatchable rather than triggering an import (rule 1). delphi_hooks()
    # imports haystack.hooks.protocol; requiring it in sys.modules here is what
    # keeps that import a module-cache lookup and not a framework import.
    ctx.module("haystack.hooks.protocol")
    try:
        from ..integrations.haystack import delphi_hooks, inject_hooks
    except Exception as exc:  # pragma: no cover - import of our own module
        raise PatchUnavailable(f"xaidr Haystack integration unavailable: {exc}") from exc
    try:
        hooks = delphi_hooks(sensor=ctx.sensor)
    except ImportError as exc:
        raise PatchUnavailable(f"haystack>=3.0 hook API not importable: {exc}") from exc

    def factory(orig: Callable) -> Callable:
        def before(args: tuple, kwargs: dict) -> Optional[Halt]:
            kwargs["hooks"] = inject_hooks(kwargs.get("hooks"), hooks)
            return None

        return make_wrapper(orig, before=before)

    ctx.install(
        module_name, "Agent.__init__", "input+output+tool", factory,
        "merges xaidr.integrations.haystack.delphi_hooks into every Agent(): "
        "before_run input scan (the chat generator is not called on a block), "
        "before_tool tool-argument scan (the call is removed before it "
        "executes), after_run output scan — all on the same sensor",
    )
    ctx.unpatchable(
        f"{module_name}.Agent.hooks['after_tool']", "tool result",
        "tool RESULTS are not scanned — only tool ARGUMENTS are. Haystack does "
        "offer the seam (the after_tool hook point runs once the result messages "
        "are in State); this build deliberately does not register there, so a "
        "tool returning an injected payload is not caught. Scan it yourself with "
        "sensor.scan(result, direction='input') in an after_tool hook of your own.",
    )
    ctx.note(
        "haystack: the seam is Agent.__init__, so an Agent CONSTRUCTED BEFORE "
        "protect() keeps the hooks it was built with and is NOT instrumented. "
        "Unlike deepagents there is no import-order trap — Agent.__init__ is a "
        "class attribute, so calling protect() again after importing your agent "
        "modules covers every Agent built from then on."
    )
    ctx.note(
        "haystack: a Pipeline with no Agent in it gets NOTHING from protect(). "
        "Pipeline._run_component calls instance.run(**inputs) on an arbitrary "
        "per-component dict, which is not a place a message-shaped scan can be "
        "made honestly. Call sensor.scan()/scan_output() at your own entry and "
        "exit points for those."
    )
    ctx.note(
        "haystack: a blocked INPUT stops the run by exhausting the Agent's step "
        "budget (the only mechanism a before_run hook has), so haystack logs "
        "'Agent reached maximum agent steps of N, stopping.' at WARNING on every "
        "block. The hooks rewrite exit_reason to 'xaidr_blocked' and restore "
        "step_count to 0, so the OUTPUT is honest; the log line is haystack's "
        "and cannot be suppressed from a hook."
    )


# ─────────────────────────────────────────────────────────────────────────
# MCP clients
# ─────────────────────────────────────────────────────────────────────────


def _mcp_error_result(message: str) -> Any:
    """A CallToolResult carrying the refusal, or None if the types are absent."""
    types_mod = sys.modules.get("mcp.types")
    if types_mod is None:
        return None
    try:
        return types_mod.CallToolResult(
            content=[types_mod.TextContent(type="text", text=message)],
            isError=True,
        )
    except Exception:
        return None


def _mcp_result_text(result: Any) -> str:
    parts: list[str] = []
    for item in getattr(result, "content", None) or ():
        text = getattr(item, "text", None)
        if isinstance(text, str) and text.strip():
            parts.append(text)
    return "\n".join(parts)


def _patch_mcp(ctx: PatchContext) -> None:
    ctx.module("mcp")

    def factory(orig: Callable) -> Callable:
        def before(args: tuple, kwargs: dict) -> Optional[Halt]:
            name = kwargs.get("name")
            if name is None and len(args) > 1:
                name = args[1]
            if not isinstance(name, str):
                return None
            arguments = kwargs.get("arguments")
            if arguments is None and len(args) > 2:
                arguments = args[2]
            result = tool_verdict(ctx.sensor, name, arguments)
            if result is None:
                return None
            message = refusal_text(name, result)
            error = _mcp_error_result(message)
            if error is None:
                # No way to answer in-band without mcp.types — raising is the
                # only honest option left. It is loud, and it does not let the
                # blocked call through.
                raise DelphiBlockedError(result)
            return Halt(error)

        def after(result: Any, args: tuple, kwargs: dict) -> Any:
            # An MCP server's RESULT is untrusted inbound content — tool-result
            # poisoning is the headline MCP attack, so it is scanned as input.
            text = _mcp_result_text(result)
            if not text:
                return result
            verdict = ctx.sensor.scan(text, direction="input")
            if not verdict.must_halt:
                return result
            name = kwargs.get("name") or (args[1] if len(args) > 1 else "unknown_tool")
            message = (
                f"[BLOCKED] The result returned by MCP tool '{name}' was blocked "
                f"by security policy ({verdict.category or 'policy'})."
            )
            error = _mcp_error_result(message)
            if error is None:
                raise DelphiBlockedError(verdict)
            return error

        return make_wrapper(orig, before=before, after=after)

    ctx.install(
        "mcp", "ClientSession.call_tool", "tool", factory,
        "scans the tool name + arguments before the call leaves the client, and "
        "scans the server's returned content as untrusted inbound text",
    )
    ctx.note(
        "mcp: only the CLIENT session is patched. If this process also RUNS an "
        "MCP server, its handlers are your own functions — scan them with "
        "handle.sensor.scan_tool_call() or wrap them with protect_tools()."
    )


# ─────────────────────────────────────────────────────────────────────────
# The registry. Order is the order the manifest renders in.
# ─────────────────────────────────────────────────────────────────────────

TARGETS: tuple[FrameworkTarget, ...] = (
    FrameworkTarget(
        "httpx", ("httpx",), _patch_httpx,
        "egress: destination policy, request body, response DLP",
    ),
    FrameworkTarget(
        "requests", ("requests",), _patch_requests,
        "egress: destination policy, request body, response DLP",
    ),
    FrameworkTarget(
        "langchain_core", ("langchain_core", "langchain_core.tools"), _patch_langchain_core,
        "tool boundary for every langchain BaseTool",
    ),
    FrameworkTarget(
        "langchain", ("langchain", "langchain.agents"), _patch_langchain,
        "input + output + tool via delphi_middleware injection into create_agent",
    ),
    FrameworkTarget(
        "langgraph", ("langgraph",), _patch_langgraph,
        "no seam of its own; tools covered via langchain_core",
    ),
    FrameworkTarget(
        "deepagents", ("deepagents",), _patch_deepagents,
        "no seam of its own; covered via create_agent iff protect() ran first",
    ),
    FrameworkTarget(
        "openai-agents", ("agents",), _patch_openai_agents,
        "input + output at Runner.run",
        verify=_looks_like_openai_agents,
    ),
    FrameworkTarget(
        "crewai", ("crewai",), _patch_crewai,
        "tool boundary + crew kickoff input",
    ),
    FrameworkTarget(
        "autogen-core", ("autogen_core", "autogen_core.tools"), _patch_autogen_core,
        "tool boundary for AgentChat 0.4+",
    ),
    FrameworkTarget(
        "autogen-legacy", ("autogen",), _patch_autogen_legacy,
        "tool boundary for pyautogen 0.2",
    ),
    FrameworkTarget(
        "llama-index", ("llama_index.core", "llama_index.core.tools"), _patch_llama_index,
        "tool boundary for FunctionTool",
    ),
    FrameworkTarget(
        "mcp", ("mcp",), _patch_mcp,
        "MCP client call_tool arguments + returned content",
    ),
    # Detected on the AGENTS module, not on `haystack`. Two reasons. A
    # Haystack Pipeline with no Agent in it has no boundary this can reach, and
    # warning that it is "present but unpatched" would be a false alarm — which
    # is how a loud manifest stops being read. And the name `haystack` is also
    # farm-haystack 1.x, which has no `components` package at all, so keying on
    # this module cannot mistake one for the other.
    FrameworkTarget(
        "haystack",
        ("haystack.components.agents", "haystack.components.agents.agent"),
        _patch_haystack,
        "input + output + tool via delphi_hooks injection into Agent.__init__",
    ),
)

TARGETS_BY_NAME = {t.name: t for t in TARGETS}
