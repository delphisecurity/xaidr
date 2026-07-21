"""A-9 (widened json.loads catches) + A-5 (received-A2A direction) guards.

A-9: looks_like_a2a and the A2A field extractor must not propagate a json.loads
fault (e.g. RecursionError on a runtime whose json raises at depth) — the
"never raises" guarantee must not depend on the runtime. BaseException must
still propagate (not over-widened).

A-5: a RECEIVED A2A message maps to interaction.direction "inbound"; a SENT one
to "outbound".
"""
import json

import pytest

from xaidr import Sensor
from xaidr.integrations._a2a_detect import looks_like_a2a
from xaidr.integrations.langchain import route_inbound_scan
from xaidr.schema import to_openA2A

A2A_ENVELOPE = (
    '{"jsonrpc":"2.0","method":"message/send",'
    '"params":{"message":{"parts":[{"text":"hello peer"}]}}}'
)


# ── A-9 ──────────────────────────────────────────────────────────────────────

def test_looks_like_a2a_survives_json_recursionerror(monkeypatch):
    monkeypatch.setattr(json, "loads",
                        lambda *a, **k: (_ for _ in ()).throw(RecursionError()))
    # Must fall through to the safe not-A2A path, not propagate.
    assert looks_like_a2a('{"jsonrpc":"2.0"}') == (False, None)


def test_scan_a2a_extractor_survives_json_recursionerror(monkeypatch):
    monkeypatch.setattr(json, "loads",
                        lambda *a, **k: (_ for _ in ()).throw(RecursionError()))
    s = Sensor(agent_id="a9")
    # scan_a2a wraps _scan_a2a_impl fail-open; the widened extractor catch means
    # the json fault degrades to raw-text scanning, no crash.
    r = s.scan_a2a(A2A_ENVELOPE, destination="peer")
    assert r.action in ("allowed", "flagged", "blocked")


def test_base_exception_still_propagates(monkeypatch):
    monkeypatch.setattr(json, "loads",
                        lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        looks_like_a2a('{"jsonrpc":"2.0"}')


def test_normal_a2a_still_detected():
    is_a2a, parsed = looks_like_a2a(A2A_ENVELOPE)
    assert is_a2a and isinstance(parsed, dict)


# ── A-5 ──────────────────────────────────────────────────────────────────────

def test_received_a2a_maps_to_inbound():
    out = to_openA2A({"direction": "a2a_inbound", "action": "allowed", "score": 0.0})
    assert out["gen_ai.security.interaction.direction"] == "inbound"
    assert out["gen_ai.security.interaction.type"] == "a2a"


def test_sent_a2a_maps_to_outbound():
    out = to_openA2A({"direction": "a2a", "action": "allowed", "score": 0.0})
    assert out["gen_ai.security.interaction.direction"] == "outbound"
    assert out["gen_ai.security.interaction.type"] == "a2a"


def test_receive_path_emits_inbound_direction():
    events = []

    class Cap:
        def report(self, b):
            events.extend(b)

        def close(self):
            pass

    s = Sensor(agent_id="recv-agent", reporter=Cap())
    route_inbound_scan(s, A2A_ENVELOPE, "recv-agent")
    s.flush()
    dirs = [e["data"]["direction"] for e in events
            if str(e.get("data", {}).get("direction", "")).startswith("a2a")]
    assert dirs == ["a2a_inbound"], dirs


def test_send_path_emits_outbound_direction():
    events = []

    class Cap:
        def report(self, b):
            events.extend(b)

        def close(self):
            pass

    s = Sensor(agent_id="send-agent", reporter=Cap())
    s.scan_a2a(A2A_ENVELOPE, destination="billing")  # default received=False
    s.flush()
    dirs = [e["data"]["direction"] for e in events
            if str(e.get("data", {}).get("direction", "")).startswith("a2a")]
    assert dirs == ["a2a"], dirs
