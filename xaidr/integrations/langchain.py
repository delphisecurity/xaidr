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

import threading
from typing import Any, Optional

from ..sensor import DelphiSensor

# Thread-local map for tracking the parent agent in intra-process delegation.
# When agent A's middleware fires and then calls agent B (via a function call),
# B's middleware sees A as the parent and reports the A2A edge. LangGraph runs
# each step inside context.run() which isolates contextvars, so a plain dict
# keyed by thread id is used here.
#
# NOTE: the open sensor also ships a richer provenance module
# (xaidr.provenance_chain) with multi-hop chains + W3C propagation. A future
# version of this adapter can call begin_flow()/build_provenance() to populate
# full provenance automatically. For now the lightweight parent-edge tracking
# below is preserved unchanged.
_delphi_parent_agents: dict[int, tuple[str, float]] = {}  # tid -> (agent_id, ts)


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

        # ── A2A edge detection via thread-local parent tracking ──────────
        import time as _time
        tid = threading.get_ident()
        now = _time.time()

        parent_agent = None
        for other_tid, (other_agent, ts) in list(_delphi_parent_agents.items()):
            if other_agent != agent_id and (now - ts) < 15:
                parent_agent = other_agent
                break
            elif (now - ts) > 30:
                _delphi_parent_agents.pop(other_tid, None)

        is_a2a = parent_agent is not None

        if is_a2a:
            # Firing inside another agent's call stack: scan as A2A and report
            # the edge (source = parent, destination = us).
            result = sensor.scan_a2a(content, destination=agent_id)
            import hashlib
            from uuid import uuid4
            sensor._telemetry.enqueue({
                "type": "a2a",
                "agentId": agent_id,
                "data": {
                    "scanId": uuid4().hex[:12],
                    "agentId": agent_id,
                    "sourceAgent": parent_agent,
                    "destinationAgent": agent_id,
                    "direction": "a2a",
                    "action": result.action,
                    "score": result.score,
                    "category": result.category,
                    "rules": result.rules,
                    "scanTimeMs": result.latency_ms,
                    "promptLength": len(content),
                    "promptHash": hashlib.sha256(content.encode()).hexdigest()[:16],
                },
            })
        else:
            result = sensor.scan(content, direction="input")

        # Mark ourselves as the parent for any sub-agents called from here.
        _delphi_parent_agents[tid] = (agent_id, _time.time())

        print(
            f"[xaidr] scan action={result.action} score={result.score:.2f} "
            f"category={result.category} rules={result.rules} "
            f"latency_ms={result.latency_ms}"
            f"{f' [A2A: {parent_agent} -> {agent_id}]' if is_a2a else ''}"
        )

        if result.action == "blocked":
            _delphi_parent_agents.pop(tid, None)
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
