"""LangChain middleware for the OpenA2A (xaidr) Sensor — standalone, no backend.

Usage::

    from langchain.agents import create_agent
    from xaidr.integrations.langchain import delphi_middleware

    agent = create_agent(
        model="anthropic:claude-sonnet-4-5",
        tools=[...],
        middleware=[delphi_middleware(agent_id="my-agent")],
    )

The middleware scans the latest user message before it reaches the model. In
the default monitor mode nothing is blocked (events are still emitted); in
block mode a ``blocked`` verdict short-circuits to ``end`` with a refusal.

Standalone: no api_key, no backend, no network. Scans locally via the sensor's
L0+L1+L2+compositional+DLP stack and emits through the sensor's reporter.

This middleware is synchronous (per LangChain's recommended pattern). LangChain
auto-wraps sync middleware for async agent invocations (agent.ainvoke) via an
executor, so sync-first gives maximum compatibility across invoke()/ainvoke().
"""

from __future__ import annotations

from typing import Any, Optional

from ..sensor import DelphiSensor
from ..trace_context import resolve_parent
from ._a2a_detect import looks_like_a2a


def route_inbound_scan(
    sensor: Any,
    content: str,
    agent_id: str,
    headers: Optional[dict] = None,
) -> tuple[Any, bool]:
    """Route one inbound message to the right scan based on its shape.

    Single source of truth for receive-side routing — the middleware and the
    routing oracle (``tests/test_a2a_routing.py``) both call this so the
    decision can never drift.

    A serialized JSON-RPC A2A envelope (detected by :func:`looks_like_a2a`)
    routes to ``sensor.scan_a2a(message=<parsed dict>)`` so the A2A field
    extractor and structural/id checks run. (The open ``scan_a2a`` accepts a
    dict envelope directly and parses it internally.) Anything else routes to
    ``sensor.scan(content, direction="input")``.

    INTERIM GAP: pure in-process LangChain delegation (function-call hops)
    carries NO envelope and NO headers, so there is nothing to shape-detect —
    such hops fall through to the generic ``scan`` here. Content is still
    scanned (SAFE), but the A2A-specific structural/id checks do not run on
    that path. This is an accepted, documented interim gap; the proper fix (the
    integration layer explicitly carrying A2A context for known in-process
    delegations) is a separate follow-up. Do NOT reintroduce a timing heuristic
    to cover it.

    W3C Trace Context (READING HALF): if the host provided a parent — an inbound
    ``traceparent`` header or an active OTel span — it is resolved and attached
    as OPTIONAL, additive telemetry metadata (``parent_context``). It never
    changes the routing decision or the scan verdict; absent a parent this is a
    no-op and behavior is byte-identical.

    Returns ``(result, is_a2a)``.
    """
    parent = resolve_parent(headers)
    is_a2a, parsed_body = looks_like_a2a(content, headers)
    if is_a2a:
        # Open scan_a2a accepts the dict envelope directly (parses internally).
        # This is the RECEIVE side (an inbound A2A message), so mark it received
        # -> telemetry records interaction.direction "inbound", not "outbound".
        result = sensor.scan_a2a(
            parsed_body, destination=agent_id, parent_context=parent, received=True
        )
    else:
        result = sensor.scan(content, direction="input", parent_context=parent)
    return result, is_a2a


def delphi_middleware(
    agent_id: str = "langchain-agent",
    enforcement_mode: str = "monitor",
    reporter: Any = None,
    *,
    sensor: Any = None,
    **sensor_kwargs: Any,
) -> Any:
    """Factory returning a full-boundary LangChain middleware.

    Returns a SINGLE ``AgentMiddleware`` instance that covers all three agent
    boundaries with one sensor (so the usual ``middleware=[delphi_middleware(...)]``
    call site is unchanged — it is one middleware object, not a list of hooks):

    * INPUT (``before_model``): scans the latest user message before it hits the
      model. A ``blocked`` verdict jumps to ``end`` with a refusal AIMessage.
    * TOOL CALL (``wrap_tool_call``): scans each tool name + arguments via
      ``scan_tool_call`` BEFORE the tool executes. A ``blocked`` verdict
      short-circuits with a refusal ToolMessage — the tool is NOT invoked.
    * OUTPUT (``after_model``): scans the model's generated text via
      ``scan_output``. A ``blocked`` verdict jumps to ``end`` with a refusal.

    All scans emit telemetry via the sensor's reporter regardless of mode; in
    monitor mode nothing blocks (block verdicts are downgraded by the sensor).
    Every boundary fails OPEN — a scan fault lets the agent proceed (the sensor's
    scan wrappers already return a safe allow on internal error), so the
    middleware never crashes the agent.

    Usage::

        agent = create_agent(model=..., tools=[...],
                              middleware=[delphi_middleware(agent_id="a",
                                                            enforcement_mode="block")])

    Args:
        agent_id: identifier for this agent (appears in telemetry).
        enforcement_mode: "monitor" (default, never blocks) or "block".
        reporter: optional telemetry reporter; defaults to the sensor default.
        sensor: an EXISTING sensor to scan with, instead of constructing one.
            ``xaidr.protect()`` passes this so the middleware boundary and every
            other boundary it instruments share one sensor — one agent_id, one
            reporter, one policy, one circuit breaker. Without it, a
            ``protect()`` that also injected this middleware would emit under a
            second sensor and split the audit trail in two. When given,
            ``agent_id`` / ``enforcement_mode`` / ``reporter`` /
            ``**sensor_kwargs`` are ignored; the sensor's own values win.
        **sensor_kwargs: forwarded to DelphiSensor (e.g. policy_file=, schema=).
    """
    try:
        from langchain.agents.middleware import AgentMiddleware, hook_config
        from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
    except ImportError as exc:
        raise ImportError(
            "delphi_middleware requires langchain>=1.0. "
            "Install with: pip install 'xaidr[langchain]'"
        ) from exc

    if sensor is None:
        sensor = DelphiSensor(
            agent_id=agent_id,
            enforcement_mode=enforcement_mode,
            reporter=reporter,
            **sensor_kwargs,
        )
    else:
        agent_id = sensor.agent_id

    # Both "blocked" and "approval_required" HALT the turn, but they are
    # different states and must read differently: a block is a denial, an
    # approval gate is a pending human decision on an action that was not
    # executed. Collapsing them would leave the operator unable to tell one
    # from the other in transcripts.
    _HALTING_ACTIONS = ("blocked", "approval_required")

    def _refusal_text(result: Any) -> str:
        if getattr(result, "action", None) == "approval_required":
            return (
                "This action requires human approval and was not executed. "
                f"(xaidr:approval_required:{result.category or 'policy'})"
            )
        return (
            "I can't help with that request. "
            f"(xaidr:{result.category or 'policy'})"
        )

    class DelphiMiddleware(AgentMiddleware):
        """xaidr full-boundary middleware: input + tool-call + output."""

        # ── INPUT boundary ───────────────────────────────────────────────
        @hook_config(can_jump_to=["end"])
        def before_model(self, state: dict[str, Any], runtime: Any) -> dict[str, Any] | None:
            messages = state.get("messages", [])
            if not messages:
                return None

            last_user = next(
                (m for m in reversed(messages) if isinstance(m, HumanMessage)),
                None,
            )
            if last_user is None:
                return None

            content = last_user.content
            if not isinstance(content, str) or not content:
                return None

            # ── A2A detection via message shape (A2A spec / JSON-RPC) ────
            # Shape-based, transport-independent routing (route_inbound_scan):
            # a serialized JSON-RPC A2A envelope → scan_a2a (so the A2A field
            # extractor + structural/id checks run); anything else → generic
            # scan. No transport headers are available on the LangChain path,
            # so this decides on payload shape alone. The old 15s thread-local
            # timing heuristic is gone — unsound across processes/containers.
            result, is_a2a = route_inbound_scan(sensor, content, agent_id)

            print(
                f"[xaidr] scan action={result.action} score={result.score:.2f} "
                f"category={result.category} rules={result.rules} "
                f"latency_ms={result.latency_ms}"
                f"{' [A2A]' if is_a2a else ''}"
            )

            if result.action in _HALTING_ACTIONS:
                return {
                    "messages": [AIMessage(content=_refusal_text(result))],
                    "jump_to": "end",
                }
            return None

        # ── TOOL-CALL boundary ───────────────────────────────────────────
        def wrap_tool_call(self, request: Any, handler: Any) -> Any:
            """Scan a tool call before execution; block → tool NOT invoked."""
            tool_call = getattr(request, "tool_call", None) or {}
            tool_name = tool_call.get("name") if isinstance(tool_call, dict) else None
            arguments = tool_call.get("args") if isinstance(tool_call, dict) else None
            call_id = tool_call.get("id") if isinstance(tool_call, dict) else None

            if tool_name:
                # scan_tool_call is fail-open internally (an internal fault
                # returns a safe allow, never raises), so a scan error lets the
                # tool proceed.
                result = sensor.scan_tool_call(tool_name, arguments or {})
                print(
                    f"[xaidr] tool_call action={result.action} "
                    f"score={result.score:.2f} category={result.category} "
                    f"rules={result.rules} tool={tool_name}"
                )
                if result.action in _HALTING_ACTIONS:
                    # Short-circuit: return a refusal ToolMessage WITHOUT calling
                    # the handler, so the tool is never executed. An approval gate
                    # gets its own message — the action is pending a human, not
                    # denied.
                    if result.action == "approval_required":
                        content = (
                            f"[APPROVAL REQUIRED] Tool '{tool_name}' requires "
                            f"human approval and was NOT executed "
                            f"({result.category or 'policy'}). Route this action "
                            "to a human approver."
                        )
                    else:
                        content = (
                            f"[BLOCKED] Tool '{tool_name}' blocked by security "
                            f"policy ({result.category or 'policy'})."
                        )
                    return ToolMessage(
                        content=content,
                        tool_call_id=call_id or "",
                        name=tool_name,
                        status="error",
                    )

            return handler(request)

        # ── OUTPUT boundary ──────────────────────────────────────────────
        @hook_config(can_jump_to=["end"])
        def after_model(self, state: dict[str, Any], runtime: Any) -> dict[str, Any] | None:
            messages = state.get("messages", [])
            if not messages:
                return None

            last = messages[-1]
            # Only scan a freshly generated assistant TEXT message (a tool-call
            # AIMessage carries no prose to DLP-scan; its args are covered by the
            # tool-call boundary above).
            if not isinstance(last, AIMessage):
                return None
            content = last.content
            if not isinstance(content, str) or not content:
                return None

            result = sensor.scan_output(content)
            print(
                f"[xaidr] output action={result.action} score={result.score:.2f} "
                f"category={result.category} rules={result.rules}"
            )
            if result.action in _HALTING_ACTIONS:
                return {
                    "messages": [AIMessage(content=_refusal_text(result))],
                    "jump_to": "end",
                }
            return None

    return DelphiMiddleware()
