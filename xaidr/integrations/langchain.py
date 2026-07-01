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
        result = sensor.scan_a2a(
            parsed_body, destination=agent_id, parent_context=parent
        )
    else:
        result = sensor.scan(content, direction="input", parent_context=parent)
    return result, is_a2a


def delphi_middleware(
    agent_id: str = "langchain-agent",
    enforcement_mode: str = "monitor",
    reporter: Any = None,
    **sensor_kwargs: Any,
) -> Any:
    """Factory returning a LangChain ``before_model`` middleware.

    Scans the latest user message before it hits the model. On a ``blocked``
    verdict (only possible in block mode) it jumps to ``end`` with a refusal
    AIMessage; otherwise it passes through. All scans emit telemetry via the
    sensor's reporter regardless of mode.

    Args:
        agent_id: identifier for this agent (appears in telemetry).
        enforcement_mode: "monitor" (default, never blocks) or "block".
        reporter: optional telemetry reporter; defaults to the sensor default.
        **sensor_kwargs: forwarded to DelphiSensor (e.g. policy_file=, schema=).
    """
    try:
        from langchain.agents.middleware import before_model
        from langchain_core.messages import AIMessage, HumanMessage
    except ImportError as exc:
        raise ImportError(
            "delphi_middleware requires langchain>=1.0. "
            "Install with: pip install 'xaidr[langchain]'"
        ) from exc

    sensor = DelphiSensor(
        agent_id=agent_id,
        enforcement_mode=enforcement_mode,
        reporter=reporter,
        **sensor_kwargs,
    )

    @before_model(can_jump_to=["end"])
    def delphi_scan(state: dict[str, Any], runtime: Any) -> dict[str, Any]:
        messages = state.get("messages", [])
        if not messages:
            return {}

        last_user = next(
            (m for m in reversed(messages) if isinstance(m, HumanMessage)),
            None,
        )
        if last_user is None:
            return {}

        content = last_user.content
        if not isinstance(content, str) or not content:
            return {}

        # ── A2A detection via message shape (A2A spec / JSON-RPC) ────────
        # Shape-based, transport-independent routing (see route_inbound_scan):
        # a serialized JSON-RPC A2A envelope → scan_a2a (so the A2A field
        # extractor + structural/id checks run); anything else → generic scan.
        # No transport headers are available on the LangChain middleware path,
        # so this decides on payload shape alone. The old 15s thread-local
        # timing heuristic is gone — it was unsound across processes/containers.
        result, is_a2a = route_inbound_scan(sensor, content, agent_id)

        print(
            f"[xaidr] scan action={result.action} score={result.score:.2f} "
            f"category={result.category} rules={result.rules} "
            f"latency_ms={result.latency_ms}"
            f"{' [A2A]' if is_a2a else ''}"
        )

        if result.action == "blocked":
            return {
                "messages": [
                    AIMessage(
                        content=(
                            "I can't help with that request. "
                            f"(xaidr:{result.category or 'policy'})"
                        )
                    )
                ],
                "jump_to": "end",
            }

        return {}

    return delphi_scan
