"""Haystack integration for the OpenA2A (xaidr) Sensor — standalone, no backend.

Haystack has neither LangChain's middleware nor CrewAI's global hook registry, so
this is a mirror of NEITHER. It wires the seam Haystack actually sanctions: the
``Agent`` hook points introduced in Haystack 3.x
(``haystack.hooks.protocol.VALID_HOOK_POINTS``), passed per-Agent as
``Agent(hooks={...})``.

Measured against **haystack-ai 3.1.1** by reading the installed package and
running it, not the docs. What the read found, and why the wiring looks like this:

* **A Haystack ``Pipeline`` invokes a component as ``instance.run(**inputs)``**
  (``haystack/core/pipeline/pipeline.py::Pipeline._run_component``). ``Component``
  is a ``Protocol`` applied by the ``@component`` decorator, not a base class, so
  there is no library-owned method shared by every component to wrap — and the
  ``inputs`` are an arbitrary per-component dict with no notion of "the user's
  message". A pipeline is therefore NOT a security boundary here; see
  :func:`delphi_hooks` for what is.
* **Tool calls happen only inside the Agent's run loop.** Haystack 3.x removed
  the ``ToolInvoker`` component that 2.x had; ``Agent._run_step`` calls
  ``_run_tool(...)``, which reaches ``Tool.invoke(**args)`` per call
  (``haystack/components/agents/tool_calling.py``). So the Agent loop is the only
  place an agent tool call exists, and the ``before_tool`` hook point sits
  directly in front of it.

THE BLOCK CONTRACT, WHICH IS NOT A RETURN VALUE. Haystack's ``Hook`` protocol is
``run(state) -> None``: a hook "influences the run only by mutating ``State`` in
place". There is no ``return False`` to block with, as in CrewAI, and no
``jump_to`` as in LangChain. Each boundary below therefore blocks by rewriting
``State``, using the mechanism the Agent itself documents at that point:

* **INPUT** (``before_run``) — the Agent reads ``exe_context.counter =
  state.data.get("step_count", 0)`` immediately after the ``before_run`` hooks and
  loops ``while counter < max_agent_steps``. Setting ``step_count`` past any
  possible budget makes the loop body never execute, so **the chat generator is
  never called**. Verified: 0 generator calls on a blocked input.
* **TOOL CALL** (``before_tool``) — after these hooks the Agent RE-READS the
  pending calls from ``State`` (``_pending_tool_call_messages_from_state``) and
  executes only what is still on the last message. Removing a call removes its
  execution. This is the same mechanism Haystack's own ``ConfirmationHook`` uses
  to reject a tool call, and the refusal is shaped the same way it shapes one: an
  assistant message carrying the rejected call, followed by
  ``ChatMessage.from_tool(..., error=True)``.
* **OUTPUT** (``after_run``) — runs after the loop and before ``_public_outputs``
  builds the return value, so rewriting the last message rewrites both
  ``messages`` and ``last_message``.

TWO COSTS OF THE INPUT BOUNDARY, STATED HERE RATHER THAN DISCOVERED.
Exhausting the step budget is the only way to stop the loop from a ``before_run``
hook — a hook cannot ``break`` it — and that path is the one the Agent labels
``max_agent_steps``:

1. Haystack logs ``"Agent reached maximum agent steps of N, stopping."`` at
   WARNING on every blocked input. It comes from ``haystack.components.agents``,
   not from here, and it cannot be suppressed from a hook.
2. ``exit_reason`` would otherwise read ``"max_agent_steps"``, which is a lie
   about why the Agent stopped. The ``after_run`` hook rewrites it to
   :data:`EXIT_REASON_BLOCKED` and restores ``step_count`` to the honest ``0``.
   **That is a value outside Haystack's documented set** (``"text"``, a tool
   name, or ``"max_agent_steps"``), so a ``ConditionalRouter`` downstream that
   switches on ``exit_reason`` needs a branch for it. Reporting the block is
   worth more than blending into ``"text"``, but it is a routing change and you
   should know about it. The rewrite lives in the ``after_run`` hook, so a
   partial registration (``before_run`` without ``after_run``) leaves the
   ``max_agent_steps`` label in place — use :func:`delphi_hooks`, which always
   returns the full set.

Standalone: no api_key, no backend, no network. Scans locally via the sensor's
L0+L1+L2+compositional+DLP stack and emits through the sensor's reporter.
"""

from __future__ import annotations

import logging
from typing import Any

from ..sensor import DelphiSensor

logger = logging.getLogger("xaidr.haystack")

#: ``exit_reason`` this integration writes when it stopped the run at the INPUT
#: boundary. Deliberately NOT one of Haystack's own values — see the module
#: docstring: a block that renders as ``"text"`` is a block nothing downstream
#: can route on.
EXIT_REASON_BLOCKED = "xaidr_blocked"

#: The ``step_count`` the input hook writes to exhaust the Agent's loop budget.
#: Compared with ``max_agent_steps`` (an ``int``, default 100), so any value
#: beyond a plausible budget works; this one is far outside every plausible
#: budget AND recognisable on sight in a State dump. The ``after_run`` hook
#: detects it with ``>=`` and restores the honest count, so it never reaches a
#: caller — a bare ``==`` would miss a run that incremented past it.
_STOP_SENTINEL = 2 ** 62

#: Hook points this integration registers under, in run-loop order.
_POINTS = ("before_run", "before_tool", "after_run")


def _import_hooks() -> None:
    """Fail loudly, and with the version reason, when the hook API is absent.

    Haystack 2.x has an ``Agent`` but no ``haystack.hooks``, so a 2.x install
    would otherwise fail deep inside ``Agent.__init__`` with an unrelated
    ``TypeError`` about an unexpected ``hooks`` keyword.
    """
    try:
        import haystack  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "xaidr's Haystack integration requires haystack-ai>=3.0. "
            "Install with: pip install 'xaidr[haystack]'"
        ) from exc
    try:
        from haystack.hooks.protocol import VALID_HOOK_POINTS
    except ImportError as exc:
        raise ImportError(
            "haystack is installed but haystack.hooks is missing — this build "
            "predates the Agent hook API (added in haystack-ai 3.0). Upgrade "
            "haystack-ai, or scan tool calls explicitly with "
            "Sensor.protect_tools()."
        ) from exc
    missing = [p for p in _POINTS if p not in VALID_HOOK_POINTS]
    if missing:
        raise ImportError(
            "haystack.hooks does not offer the hook point(s) "
            + ", ".join(missing)
            + " this integration binds to (it offers: "
            + ", ".join(VALID_HOOK_POINTS)
            + "). Upgrade or downgrade haystack-ai, or scan explicitly with "
            "Sensor.protect_tools()."
        )


class _DelphiHook:
    """One xaidr boundary, shaped as a Haystack ``Hook``.

    One class, three instances: Haystack calls ``run(state)`` with no indication
    of WHICH hook point it is calling from, so a single object registered at
    several points could not tell an input scan from an output scan. Each
    instance is therefore bound to exactly one point and declares it in
    ``allowed_hook_points``, which makes the Agent itself raise if one is
    registered in the wrong place — a loud failure instead of a boundary that
    silently scans the wrong thing.

    Every hook fails OPEN: an internal fault returns without touching ``State``,
    so a bug here can never stop an agent from working. The sensor's scan
    wrappers are already fail-open internally; the guard here is belt-and-braces
    because this callable runs inside someone else's run loop.
    """

    def __init__(
        self,
        point: str,
        sensor: Any = None,
        *,
        agent_id: str = "haystack-agent",
        enforcement_mode: str = "monitor",
    ) -> None:
        if point not in _POINTS:
            raise ValueError(
                f"unknown xaidr hook point {point!r}; expected one of {_POINTS}"
            )
        self.point = point
        #: Read by Haystack's ``_validate_hooks``. Restricting each instance to
        #: its own point is what turns a mis-registration into an exception.
        self.allowed_hook_points = (point,)
        if sensor is None:
            sensor = DelphiSensor(agent_id=agent_id, enforcement_mode=enforcement_mode)
        self.sensor = sensor
        # Kept for to_dict(); the sensor itself is not serializable.
        self.agent_id = getattr(sensor, "agent_id", agent_id)
        self.enforcement_mode = getattr(sensor, "enforcement_mode", enforcement_mode)

    # ── Hook protocol ────────────────────────────────────────────────────

    def run(self, state: Any) -> None:
        try:
            getattr(self, f"_{self.point}")(state)
        except Exception as exc:
            # Fail open, but never SILENTLY: a boundary that has stopped working
            # and says nothing is the failure mode this package exists to
            # prevent. The exception TYPE only, never its message — a fault
            # raised while handling a prompt or a tool argument can interpolate
            # that content into what it says.
            logger.warning(
                "xaidr: the haystack %s boundary failed open (%s) "
                "[message suppressed: may contain agent content]",
                self.point, type(exc).__name__,
            )

    async def run_async(self, state: Any) -> None:
        """Async runs get the same scans.

        The scan stack is synchronous and CPU-bound with no I/O to await, so
        this defers to ``run`` rather than pretending to be async. Defined
        explicitly anyway: without it the Agent offloads the sync ``run`` to a
        worker thread per hook per step, which buys nothing here and costs a
        thread hop on every boundary.
        """
        self.run(state)

    # ── INPUT ────────────────────────────────────────────────────────────

    def _before_run(self, state: Any) -> None:
        from haystack.components.agents.state.state_utils import replace_values
        from haystack.dataclasses import ChatMessage

        messages = state.data.get("messages") or []
        # The LATEST user message, not every one of them — matching the
        # LangChain middleware's `before_model`. `Agent.run(messages=...)` is
        # normally handed the whole conversation each turn, so the earlier turns
        # are history this boundary already saw; rescanning them would grow the
        # scan without bound AND risk a false positive from juxtaposing turns
        # that are innocuous apart.
        last_user = next(
            (m for m in reversed(messages) if m.is_from("user") and m.text), None
        )
        if last_user is None or not last_user.text.strip():
            return

        result = self.sensor.scan(last_user.text, direction="input")
        if not getattr(result, "must_halt", False):
            return

        # Stop BEFORE the chat generator: the Agent re-reads step_count from
        # State on the very next line and loops `while counter < max_agent_steps`.
        state.set(
            "messages",
            list(messages) + [ChatMessage.from_assistant(_refusal_text(result))],
            handler_override=replace_values,
        )
        state.set("step_count", _STOP_SENTINEL)

    # ── TOOL CALL ────────────────────────────────────────────────────────

    def _before_tool(self, state: Any) -> None:
        from haystack.components.agents.state.state_utils import replace_values
        from haystack.dataclasses import ChatMessage

        from ..autopatch.core import refusal_text, tool_verdict

        history = state.data.get("messages") or []
        if not history:
            return
        last = history[-1]
        tool_calls = list(last.tool_calls or ())
        if not tool_calls:
            return

        kept, refusals = [], []
        for call in tool_calls:
            verdict = tool_verdict(self.sensor, call.tool_name, call.arguments)
            if verdict is None:
                kept.append(call)
            else:
                refusals.append((call, refusal_text(call.tool_name, verdict)))
        if not refusals:
            return

        # Rebuild the history exactly as Haystack's own ConfirmationHook does
        # (`_apply_tool_execution_decisions` + `_update_chat_history`): cut at
        # the last user/tool message, append a (call, error-result) PAIR per
        # refusal, then re-append whatever survived. The surviving calls must end
        # up on the LAST message, because that is the only message
        # `_pending_tool_call_messages_from_state` looks at.
        user_idx = [i for i, m in enumerate(history) if m.is_from("user")]
        tool_idx = [i for i, m in enumerate(history) if m.is_from("tool")]
        cut = max(max(user_idx, default=-1), max(tool_idx, default=-1))

        rebuilt = list(history[: cut + 1])
        for call, refusal in refusals:
            rebuilt.append(
                ChatMessage.from_assistant(
                    text=last.text, meta=last.meta, name=last.name,
                    tool_calls=[call], reasoning=last.reasoning,
                )
            )
            rebuilt.append(
                ChatMessage.from_tool(tool_result=refusal, origin=call, error=True)
            )
        if kept:
            rebuilt.append(
                ChatMessage.from_assistant(
                    text=last.text, meta=last.meta, name=last.name,
                    tool_calls=kept, reasoning=last.reasoning,
                )
            )
        state.set("messages", rebuilt, handler_override=replace_values)

    # ── OUTPUT ───────────────────────────────────────────────────────────

    def _after_run(self, state: Any) -> None:
        from haystack.components.agents.state.state_utils import replace_values
        from haystack.dataclasses import ChatMessage

        # The input boundary stopped this run by exhausting the step budget, so
        # the Agent has labelled it `max_agent_steps`. Restore the honest count
        # and say who actually stopped it. Returns immediately afterwards: the
        # last message is this package's own refusal, and re-scanning our own
        # refusal text is noise at best and a second verdict at worst.
        if state.data.get("step_count", 0) >= _STOP_SENTINEL:
            state.set("step_count", 0)
            state.set("exit_reason", EXIT_REASON_BLOCKED)
            return

        messages = state.data.get("messages") or []
        if not messages:
            return
        last = messages[-1]
        # Only a freshly generated assistant TEXT reply. A tool-result final
        # message (a tool exit condition) is a tool RESULT, which no boundary
        # here scans — see `delphi_hooks` for that gap, said out loud.
        if not last.is_from("assistant") or not last.text:
            return

        result = self.sensor.scan_output(last.text)
        if not getattr(result, "must_halt", False):
            return
        state.set(
            "messages",
            list(messages[:-1]) + [ChatMessage.from_assistant(_refusal_text(result))],
            handler_override=replace_values,
        )
        state.set("exit_reason", EXIT_REASON_BLOCKED)

    # ── serialization ────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialize for ``Agent.to_dict()`` / ``Pipeline.dumps()``.

        A live ``DelphiSensor`` is not serializable, so what round-trips is the
        two values that reconstruct an equivalent one. Everything else you passed
        (``reporter=``, ``policy_file=``, a circuit breaker) does NOT survive a
        round trip — rebuild those in the process that loads the pipeline and
        pass ``sensor=`` explicitly.
        """
        return {
            # Computed, not written down: a hardcoded path would keep
            # round-tripping to a class that had moved, and the failure would
            # surface as an unrelated ImportError at load time.
            "type": f"{type(self).__module__}.{type(self).__qualname__}",
            "init_parameters": {
                "point": self.point,
                "agent_id": self.agent_id,
                "enforcement_mode": self.enforcement_mode,
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "_DelphiHook":
        """Rebuild from :meth:`to_dict`.

        Haystack refuses to deserialize a class whose module is not on its
        trusted-module allowlist, and this module is not on it by default. To
        load a pipeline containing these hooks, opt in first::

            from haystack.core.serialization import allow_deserialization_module
            allow_deserialization_module("xaidr.integrations.haystack")

        (or set ``HAYSTACK_DESERIALIZATION_ALLOWLIST``). Serializing needs no
        opt-in; only loading does.
        """
        return cls(**data.get("init_parameters", {}))


def _refusal_text(result: Any) -> str:
    """The refusal an input/output boundary puts in the transcript.

    Word-for-word the LangChain middleware's text, because an operator reading a
    transcript must not have to learn two vocabularies for one verdict — and
    because a denial (final) and a pending approval (routable to a human) must
    never collapse into one message.
    """
    if getattr(result, "action", None) == "approval_required":
        return (
            "This action requires human approval and was not executed. "
            f"(xaidr:approval_required:{getattr(result, 'category', None) or 'policy'})"
        )
    return (
        "I can't help with that request. "
        f"(xaidr:{getattr(result, 'category', None) or 'policy'})"
    )


def delphi_hooks(
    agent_id: str = "haystack-agent",
    enforcement_mode: str = "monitor",
    reporter: Any = None,
    *,
    sensor: Any = None,
    **sensor_kwargs: Any,
) -> dict[str, list[Any]]:
    """Build the ``hooks=`` mapping for a Haystack ``Agent``.

    Returns a dict ready to hand straight to the Agent, covering three boundaries
    with ONE sensor (one agent_id, one reporter, one policy, one circuit
    breaker)::

        from haystack.components.agents import Agent
        from xaidr.integrations.haystack import delphi_hooks

        agent = Agent(
            chat_generator=OpenAIChatGenerator(),
            tools=[search, send_email],
            hooks=delphi_hooks(agent_id="support-agent", enforcement_mode="block"),
        )

    * ``before_run`` — INPUT. Scans the user messages via ``scan``. A halting
      verdict stops the run before the chat generator is called at all.
    * ``before_tool`` — TOOL CALL. Scans each pending call's name and arguments
      via ``scan_tool_call`` BEFORE it executes. A halting verdict removes that
      call and returns a refusal tool-result in its place; other calls in the
      same step still run, and the Agent loops on and can recover.
    * ``after_run`` — OUTPUT. Scans the final assistant text via ``scan_output``
      and replaces it on a halting verdict.

    Merge it with hooks of your own rather than replacing either::

        hooks = delphi_hooks(agent_id="a")
        hooks.setdefault("before_llm", []).append(my_compaction_hook)

    **THREE THINGS THIS IS NOT**, all of which matter before you rely on it.

    1. **It is per-Agent, not global.** Haystack's hooks are constructor
       arguments; there is no process-wide registry like CrewAI's. An ``Agent``
       you forget is an ``Agent`` that is not scanned. ``xaidr.protect()`` closes
       this by patching ``Agent.__init__`` to inject these hooks — see the
       manifest entry for what that does and does not reach.
    2. **A Haystack ``Pipeline`` is not a boundary.** These hooks are the
       ``Agent``'s, so a pipeline whose components are retrievers, builders and
       generators — with no ``Agent`` in it — gets NOTHING from this module.
       ``Pipeline._run_component`` calls ``instance.run(**inputs)`` on an
       arbitrary per-component input dict, which is not a place a message-shaped
       scan can be made honestly. Scan at your own entry point with
       ``sensor.scan()`` instead.
    3. **Tool RESULTS are not scanned.** Only tool ARGUMENTS are. Haystack does
       offer the seam for it — the ``after_tool`` hook point runs once the result
       messages are in ``State`` — and this module deliberately does not register
       there, so a tool that returns an injected payload is not caught. Pinned by
       a negative test so a change here fails loudly rather than silently
       widening the claim.

    Args:
        agent_id: identifier for this agent (appears in telemetry).
        enforcement_mode: "monitor" (default, never blocks) or "block".
        reporter: optional telemetry reporter; defaults to the sensor default.
        sensor: an EXISTING sensor to scan with, instead of constructing one.
            ``xaidr.protect()`` passes this so every boundary it instruments
            shares one sensor and one audit trail. When given, ``agent_id`` /
            ``enforcement_mode`` / ``reporter`` / ``**sensor_kwargs`` are
            ignored; the sensor's own values win.
        **sensor_kwargs: forwarded to DelphiSensor (e.g. policy_file=, schema=).
    """
    _import_hooks()
    if sensor is None:
        sensor = DelphiSensor(
            agent_id=agent_id,
            enforcement_mode=enforcement_mode,
            reporter=reporter,
            **sensor_kwargs,
        )
    return {point: [_DelphiHook(point, sensor=sensor)] for point in _POINTS}


def inject_hooks(existing: Any, hooks: dict[str, list[Any]]) -> dict[str, list[Any]]:
    """Merge ``hooks`` into a caller's own ``hooks=`` mapping, without duplicating.

    Used by ``xaidr.protect()``'s ``Agent.__init__`` patch, and safe to call
    yourself. A point that already carries one of this package's hooks is left
    exactly as it is, so constructing an Agent under two ``protect()`` calls — or
    passing ``hooks=delphi_hooks(...)`` explicitly under an active ``protect()``
    — does not scan the same boundary twice.
    """
    merged: dict[str, list[Any]] = {
        point: list(hook_list) for point, hook_list in (existing or {}).items()
    }
    for point, ours in hooks.items():
        current = merged.get(point, [])
        if any(isinstance(h, _DelphiHook) for h in current):
            continue
        merged[point] = current + list(ours)
    return merged
