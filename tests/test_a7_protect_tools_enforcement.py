"""A-7: protect_tools must run REAL enforcement (scan args + blocked-tools +
local policy) before invoking a wrapped tool — not gate on an always-allow stub.

Canary discipline: the wrapped tool DELETES a real temp file when it runs. A
closed hole means the canary survives; no real destructive command is executed.
"""
import os
import tempfile

import pytest

from xaidr.sensor import DelphiSensor


class _Tool:
    """Minimal LangChain-tool stand-in: has .name and .func."""

    def __init__(self, name, func):
        self.name = name
        self.func = func


def _canary():
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".canary")
    f.write(b"x")
    f.close()
    return f.name


def _deleting_tool(name, path):
    def _run(**kwargs):
        os.unlink(path)
        return "ran"
    return _Tool(name, _run)


def test_destructive_payload_blocked_canary_survives():
    c = _canary()
    try:
        s = DelphiSensor(agent_id="t", enforcement_mode="block")
        out = s.protect_tools([_deleting_tool("run_command", c)])[0](
            command="rm -rf /"
        )
        assert os.path.exists(c), "tool ran — hole is open"
        assert "[BLOCKED]" in out
    finally:
        if os.path.exists(c):
            os.unlink(c)


@pytest.mark.parametrize(
    "payload",
    [
        "chmod 777 /etc/passwd && dd if=/dev/zero of=/dev/sda",  # Batch A
        "echo cm0= | base64 -d | bash",                          # Batch B
    ],
)
def test_tool_arg_detection_applies_via_wrapper(payload):
    c = _canary()
    try:
        s = DelphiSensor(agent_id="t", enforcement_mode="block")
        out = s.protect_tools([_deleting_tool("shell", c)])[0](command=payload)
        assert os.path.exists(c)
        assert "[BLOCKED]" in out
    finally:
        if os.path.exists(c):
            os.unlink(c)


def test_benign_tool_still_runs():
    s = DelphiSensor(agent_id="t", enforcement_mode="block")
    calls = []
    out = s.protect_tools([_Tool("read_file", lambda **k: calls.append(k) or "ok")])[0](
        path="/home/u/notes.txt"
    )
    assert calls == [{"path": "/home/u/notes.txt"}]
    assert out == "ok"


def test_plain_callable_is_invoked():
    # Regression: plain (non-LangChain) callables were silently no-op'd before.
    s = DelphiSensor(agent_id="t", enforcement_mode="block")

    def add(a, b):
        return a + b

    assert s.protect_tools([add])[0](3, 4) == 7


def test_block_tools_setter_and_unblock():
    s = DelphiSensor(agent_id="t", enforcement_mode="block")
    calls = []
    tool = _Tool("send_email", lambda **k: calls.append(k) or "sent")

    s.block_tools(["send_email"])
    out = s.protect_tools([tool])[0](to="a@b.com")
    assert calls == [] and "[BLOCKED]" in out

    s.unblock_tools(["send_email"])
    out = s.protect_tools([tool])[0](to="a@b.com")
    assert calls == [{"to": "a@b.com"}] and out == "sent"


def test_blocked_tools_constructor_arg():
    s = DelphiSensor(
        agent_id="t", enforcement_mode="block", blocked_tools=["danger"]
    )
    out = s.protect_tools([_Tool("danger", lambda **k: "ran")])[0]()
    assert "[BLOCKED]" in out


def test_local_policy_deny_enforced_via_wrapper():
    c = _canary()
    try:
        s = DelphiSensor(agent_id="t", enforcement_mode="block")
        assert s.set_policy({
            "version": "1",
            "defaults": {"effect": "allow"},
            "rules": [
                {"id": "no-wire", "effect": "block",
                 "match": {"tools": ["wire_transfer"]}},
            ],
        })
        out = s.protect_tools([_deleting_tool("wire_transfer", c)])[0](amount=1000)
        assert os.path.exists(c)
        assert "[BLOCKED]" in out
    finally:
        if os.path.exists(c):
            os.unlink(c)


def test_scan_fault_fails_open(monkeypatch):
    c = _canary()
    try:
        s = DelphiSensor(agent_id="t", enforcement_mode="block")
        import xaidr.sensor as sm

        def boom(*a, **k):
            raise RuntimeError("injected")

        monkeypatch.setattr(sm, "classify", boom)
        # Fail open: the tool runs (canary deleted), no exception propagates.
        s.protect_tools([_deleting_tool("read_file", c)])[0](path="/x")
        assert not os.path.exists(c)
    finally:
        if os.path.exists(c):
            os.unlink(c)


def test_monitor_mode_observes_but_explicit_block_enforces():
    # Detection block downgraded to observe in monitor mode -> tool runs.
    c = _canary()
    try:
        s = DelphiSensor(agent_id="t", enforcement_mode="monitor")
        s.protect_tools([_deleting_tool("run_command", c)])[0](command="rm -rf /")
        assert not os.path.exists(c)
    finally:
        if os.path.exists(c):
            os.unlink(c)

    # But an explicit operator block is enforced even in monitor mode.
    c = _canary()
    try:
        s = DelphiSensor(agent_id="t", enforcement_mode="monitor")
        s.block_tools(["run_command"])
        out = s.protect_tools([_deleting_tool("run_command", c)])[0](command="ls")
        assert os.path.exists(c) and "[BLOCKED]" in out
    finally:
        if os.path.exists(c):
            os.unlink(c)
