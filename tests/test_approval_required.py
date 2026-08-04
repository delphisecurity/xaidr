"""approval_required is a HALTING verdict, not a soft flag.

``local_policy.compose`` returns a FOURTH action — ``approval_required`` — for
``require_approval`` policies. Branch sites that only tested ``action ==
"blocked"`` let the gated action execute anyway, which is the whole failure this
file guards against.

Canary discipline: the wrapped tool sets a real side-effect flag when it runs, so
"the tool did not execute" is asserted on OBSERVED behavior, not on a mock's call
count (a mock can be satisfied by a wrapper that swallows the call).
"""
from __future__ import annotations

from xaidr.sensor import DelphiSensor

# Benign tool name + benign args: detection alone returns "allowed", so the
# verdict under test comes purely from the policy overlay.
TOOL = "issue_refund"
ARGS = {"customer": "acct-42", "amount": 25}


def _approval_policy() -> dict:
    return {
        "version": "1",
        "defaults": {"effect": "allow", "unclassified": "allow"},
        "rules": [
            {
                "id": "refund-needs-approval",
                "effect": "require_approval",
                "match": {"tools": [TOOL]},
            }
        ],
    }


def _block_policy() -> dict:
    return {
        "version": "1",
        "defaults": {"effect": "allow", "unclassified": "allow"},
        "rules": [
            {
                "id": "refund-denied",
                "effect": "block",
                "match": {"tools": [TOOL]},
            }
        ],
    }


class _Tool:
    """Minimal LangChain-tool stand-in: has .name and .func."""

    def __init__(self, name, func):
        self.name = name
        self.func = func


class _Canary:
    """Real side effect: flips when the underlying tool actually executes."""

    def __init__(self):
        self.ran = False

    def tool(self, name=TOOL):
        def _run(*args, **kwargs):
            self.ran = True
            return "tool executed"
        return _Tool(name, _run)


def _sensor(mode: str, policy: dict) -> DelphiSensor:
    s = DelphiSensor(agent_id="approval-test", enforcement_mode=mode)
    assert s.set_policy(policy) is True, "policy failed to parse"
    return s


# (a) the verdict itself ───────────────────────────────────────────────────
def test_require_approval_policy_yields_approval_required_action():
    s = _sensor("block", _approval_policy())
    r = s.scan_tool_call(TOOL, ARGS)
    assert r.action == "approval_required", f"got {r.action!r}"
    # The convenience property is separate from is_blocked on purpose.
    assert r.requires_approval is True
    assert r.is_blocked is False
    assert r.is_allowed is False


# (b) the tool must NOT run ────────────────────────────────────────────────
def test_protect_tools_does_not_invoke_tool_on_approval_required():
    canary = _Canary()
    s = _sensor("block", _approval_policy())
    wrapped = s.protect_tools([canary.tool()])[0]

    out = wrapped(**ARGS)

    assert canary.ran is False, "tool EXECUTED despite approval_required — gap is open"
    assert "APPROVAL REQUIRED" in out
    assert "tool executed" not in out


# (c) monitor mode downgrades, tool DOES run ───────────────────────────────
def test_monitor_mode_downgrades_approval_required_to_flagged():
    s = _sensor("monitor", _approval_policy())
    r = s.scan_tool_call(TOOL, ARGS)
    assert r.action == "flagged", f"monitor mode must never halt, got {r.action!r}"

    canary = _Canary()
    s2 = _sensor("monitor", _approval_policy())
    out = s2.protect_tools([canary.tool()])[0](**ARGS)

    assert canary.ran is True, "monitor mode halted execution — it must only observe"
    assert out == "tool executed"


def test_monitor_downgrade_keeps_true_verdict_in_telemetry():
    """The returned action is softened; the emitted event keeps the real one."""
    events = []

    class _Cap:
        def report(self, batch):
            events.extend(batch)

        def close(self):
            pass

    s = DelphiSensor(
        agent_id="approval-telemetry", enforcement_mode="monitor", reporter=_Cap()
    )
    assert s.set_policy(_approval_policy()) is True
    r = s.scan_tool_call(TOOL, ARGS)
    s.close_sync()

    assert r.action == "flagged"
    tool_events = [
        e for e in events
        if e.get("data", {}).get("direction") == "tool_call"
    ]
    assert tool_events, "no tool_call telemetry emitted"
    assert tool_events[-1]["data"]["action"] == "approval_required", (
        "telemetry lost the true pre-downgrade verdict"
    )


# (d) the two refusals must read differently ───────────────────────────────
def test_blocked_and_approval_required_messages_differ():
    blocked_canary = _Canary()
    s_block = _sensor("block", _block_policy())
    blocked_msg = s_block.protect_tools([blocked_canary.tool()])[0](**ARGS)

    approval_canary = _Canary()
    s_appr = _sensor("block", _approval_policy())
    approval_msg = s_appr.protect_tools([approval_canary.tool()])[0](**ARGS)

    # Neither executes...
    assert blocked_canary.ran is False
    assert approval_canary.ran is False
    # ...but an operator must be able to tell a denial from a pending approval.
    assert blocked_msg != approval_msg, "denial and pending approval read identically"
    assert "[BLOCKED]" in blocked_msg
    assert "APPROVAL REQUIRED" in approval_msg
    assert "APPROVAL REQUIRED" not in blocked_msg
    assert "approval" in approval_msg.lower()
    assert "not executed" in approval_msg.lower()


# (e) control: no policy, tool runs ────────────────────────────────────────
def test_policy_free_tool_call_executes_normally():
    canary = _Canary()
    s = DelphiSensor(agent_id="approval-control", enforcement_mode="block")
    r = s.scan_tool_call(TOOL, ARGS)
    assert r.action == "allowed", f"benign call was not allowed: {r.action!r} {r.rules}"

    out = s.protect_tools([canary.tool()])[0](**ARGS)
    assert canary.ran is True
    assert out == "tool executed"
