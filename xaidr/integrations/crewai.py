"""CrewAI integration for the OpenA2A (xaidr) Sensor — standalone, no backend.

CrewAI has no middleware concept, so this is not a mirror of
``integrations/langchain.py``. It wires the two seams CrewAI actually sanctions:

* **TOOL boundary** — ``crewai.hooks.register_before_tool_call_hook``. The hook
  receives a ``ToolCallHookContext`` carrying ``tool_name: str`` and
  ``tool_input: dict``, which is exactly ``scan_tool_call``'s signature with no
  loss. Returning ``False`` blocks execution; CrewAI's dispatcher maps that to
  ``HookAborted`` and the executor returns a blocked message WITHOUT invoking
  the tool.
* **OUTPUT boundary** — ``Task(guardrail=...)``. Per-task, not global; see
  :func:`delphi_guardrail` for what that costs you.

WHY A HOOK AND NOT A PATCH, since this package patches internals elsewhere.
``BaseTool.to_structured_tool()`` binds ``CrewStructuredTool(func=self._run)``.
Every agent-driven call therefore runs ``CrewStructuredTool.invoke()`` ->
``func`` -> ``BaseTool._run`` and never touches ``BaseTool.run``. Measured
against crewai 1.15.17 across ``Crew.kickoff``, ``Crew.kickoff_async`` and
``Agent.kickoff``: the hook fired on all three, a patch on ``BaseTool.run``
fired on none. The only path the patch uniquely saw was a developer calling
``tool.run()`` with no agent, no task and no crew — which is not an agent
boundary, and which ``Sensor.protect_tools`` already covers.

Standalone: no api_key, no backend, no network. Scans locally via the sensor's
L0+L1+L2+compositional+DLP stack and emits through the sensor's reporter.
"""

from __future__ import annotations

import contextvars
from typing import Any, Callable, Optional

#: Set by the before-hook when IT blocked a call, read by the after-hook so the
#: refusal can be restated in this package's vocabulary. Keyed by tool name so a
#: block raised by somebody ELSE'S hook is never relabelled as ours. A
#: ContextVar rather than a module global because CrewAI runs tools on threads
#: and in async tasks, and a global would let one call's refusal leak into
#: another's.
_PENDING_REFUSAL: contextvars.ContextVar[Optional[tuple[str, str]]] = (
    contextvars.ContextVar("xaidr_crewai_pending_refusal", default=None)
)

#: CrewAI's own text for a hook-blocked call, in every one of the four executor
#: paths. Matched only as a guard — we rewrite on our OWN verdict, not on this.
_CREWAI_BLOCKED_PREFIX = "Tool execution blocked by hook."


def _import_hooks() -> Any:
    try:
        import crewai.hooks as hooks
    except ImportError as exc:  # pragma: no cover - exercised by the real-crewai test
        raise ImportError(
            "xaidr's CrewAI integration requires crewai>=1.0. "
            "Install with: pip install 'xaidr[crewai]'"
        ) from exc
    # `unregister_` is required, not optional: registering a hook we cannot
    # remove would leave instrumentation that ``unprotect()`` can never undo.
    missing = [
        name
        for name in (
            "register_before_tool_call_hook",
            "unregister_before_tool_call_hook",
            "ToolCallHookContext",
        )
        if not hasattr(hooks, name)
    ]
    if missing:
        raise ImportError(
            "crewai is installed but crewai.hooks does not expose "
            + ", ".join(missing)
            + " — this build predates the before_tool_call hook API. "
            "Upgrade crewai, or scan tool calls explicitly with "
            "Sensor.protect_tools()."
        )
    return hooks


def delphi_tool_hook(sensor: Any) -> Callable[[Any], Optional[bool]]:
    """A ``before_tool_call`` hook that scans a tool call before it executes.

    Returns ``False`` to block (CrewAI's documented contract) and ``None`` to
    allow. Fails OPEN: any internal fault returns ``None``, so a bug here can
    never stop an agent from working. ``scan_tool_call`` is already fail-open
    internally; the guard is belt-and-braces because this callable runs inside
    someone else's dispatcher.
    """
    from ..autopatch.core import refusal_text, tool_verdict

    def before_tool_call(context: Any) -> Optional[bool]:
        try:
            tool_name = getattr(context, "tool_name", None)
            if not isinstance(tool_name, str) or not tool_name:
                return None
            arguments = getattr(context, "tool_input", None)
            result = tool_verdict(sensor, tool_name, arguments)
            if result is None:
                return None
            _PENDING_REFUSAL.set((tool_name, refusal_text(tool_name, result)))
            return False
        except Exception:
            return None

    return before_tool_call


def delphi_after_tool_hook() -> Callable[[Any], Optional[str]]:
    """An ``after_tool_call`` hook that restates OUR block in OUR vocabulary.

    CrewAI writes ``"Tool execution blocked by hook. Tool: <name>"`` for any
    blocking hook, its own text and identical whoever blocked. Every other tool
    boundary in this package returns ``[BLOCKED]`` / ``[APPROVAL REQUIRED]``,
    and an operator reading a transcript must not have to learn two
    vocabularies for the same verdict. CrewAI runs the after-hooks even on a
    blocked call (verified in all four executor paths), so the rewrite lands
    everywhere the block does.

    Only rewrites a refusal THIS sensor produced, and only for the tool it
    produced it for. Somebody else's block keeps somebody else's words.
    """

    def after_tool_call(context: Any) -> Optional[str]:
        try:
            pending = _PENDING_REFUSAL.get()
            if pending is None:
                return None
            _PENDING_REFUSAL.set(None)
            tool_name, refusal = pending
            if getattr(context, "tool_name", None) != tool_name:
                return None
            current = getattr(context, "tool_result", None)
            if isinstance(current, str) and current.startswith(_CREWAI_BLOCKED_PREFIX):
                return refusal
            return None
        except Exception:
            return None

    return after_tool_call


def install_tool_hooks(sensor: Any) -> Callable[[], None]:
    """Register the tool-call hooks globally. Returns an uninstall callable.

    Global for the process, which is what CrewAI's registry offers: it covers
    every Crew, Agent and Task without touching any of them. ``xaidr.protect()``
    calls this and stores the returned callable so ``unprotect()`` can undo it.
    """
    hooks = _import_hooks()
    registered: list[tuple[Any, Any]] = []

    def uninstall() -> None:
        for unregister, hook in reversed(registered):
            try:
                unregister(hook)
            except Exception:
                pass
        registered.clear()

    # If ANY registration fails partway, unwind the ones that succeeded before
    # re-raising. The caller records an unpatchable boundary on the exception,
    # and a manifest that says "not instrumented" must not leave a live hook
    # behind that nothing can remove.
    try:
        before = delphi_tool_hook(sensor)
        hooks.register_before_tool_call_hook(before)
        registered.append((hooks.unregister_before_tool_call_hook, before))

        # The after-hook is presentation only — it restates OUR refusal in this
        # package's vocabulary. A build without the after-registry still gets
        # full enforcement, just in CrewAI's own words, so this stays optional.
        register_after = getattr(hooks, "register_after_tool_call_hook", None)
        unregister_after = getattr(hooks, "unregister_after_tool_call_hook", None)
        if callable(register_after) and callable(unregister_after):
            after = delphi_after_tool_hook()
            register_after(after)
            registered.append((unregister_after, after))
    except Exception:
        uninstall()
        raise

    return uninstall


def delphi_guardrail(sensor: Any) -> Callable[[Any], tuple[bool, Any]]:
    """A ``Task(guardrail=...)`` callable that DLP-scans the task's output.

    Usage::

        from xaidr.integrations.crewai import delphi_guardrail

        Task(description=..., expected_output=...,
             guardrail=delphi_guardrail(sensor))

    TWO THINGS THIS IS NOT, both of which matter before you rely on it.

    1. **It is per-Task, not global.** Unlike the tool hooks there is no
       registry — you attach it to every ``Task`` whose output you want
       scanned, and a Task you forget is a Task that is not scanned. This is
       CrewAI's shape, not a choice made here; ``protect()`` therefore cannot
       install it for you and does not pretend to.
    2. **CrewAI RAISES when a guardrail finally fails.** After
       ``guardrail_max_retries`` the crew does not return a refusal the agent
       can read and recover from — it raises ``Exception("Task failed guardrail
       validation after N retries...")``. That is a harder stop than the
       ``[BLOCKED]`` string the tool boundary returns, and than the refusal
       message the LangChain output boundary returns. Catch it at your
       ``kickoff()`` call site if a hard stop is not what you want.

    Fails OPEN on an internal fault: returns ``(True, output)`` unchanged.
    """

    def guardrail(output: Any) -> tuple[bool, Any]:
        try:
            text = getattr(output, "raw", None)
            if not isinstance(text, str):
                text = str(output)
            if not text.strip():
                return (True, output)
            result = sensor.scan_output(text)
            if getattr(result, "must_halt", False):
                return (
                    False,
                    f"Output blocked by xaidr security policy "
                    f"({result.category or 'policy'}; "
                    f"rules: {', '.join(result.rules) or 'none'}).",
                )
            return (True, output)
        except Exception:
            return (True, output)

    # CrewAI VALIDATES this annotation when the Task is CONSTRUCTED
    # (``crewai/task.py::_validate_guardrail``): it requires
    # ``get_origin(return_annotation) is tuple`` with args ``(bool, Any|str|
    # TaskOutput)``. This module uses ``from __future__ import annotations``, so
    # the annotation would otherwise be the STRING ``"tuple[bool, Any]"`` —
    # ``get_origin`` of a string is ``None``, and ``Task(guardrail=...)`` raises
    # a pydantic ValidationError before anything runs. Binding the real objects
    # keeps the annotation both accurate documentation and valid input.
    #
    # Found by tests/test_real_frameworks.py, not by review: an unannotated
    # stand-in passes this validator, so only the real Task constructor could
    # surface it.
    guardrail.__annotations__["return"] = tuple[bool, Any]
    return guardrail
