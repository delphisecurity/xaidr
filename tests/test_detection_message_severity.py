"""Guard tests for the derived detection.message + detection.severity fields.

Both are ADDITIVE and composed from names already on the event (action,
category, agent, rules, score) — never from raw content. These tests lock:
  - message composition (full shape + primary/many-rule suffix),
  - the no-raw-content privacy invariant,
  - graceful degradation (missing category / missing rules),
  - the severity mapping across every action/score band,
  - the raw score field surviving alongside the derived severity.
"""

from __future__ import annotations

from xaidr.schema import (
    _detection_message,
    _detection_severity,
    to_openA2A,
)


def _event(**data):
    return {"type": "scan", "agentId": data.get("agentId"), "data": data}


# --- message composition ----------------------------------------------------


def test_message_full_shape():
    msg = _detection_message(
        "blocked", "code_execution", "siem-agent-block", ["LLM08_os_exec"], 0.99
    )
    assert msg == "blocked code_execution on siem-agent-block via LLM08_os_exec"


def test_message_imperative_action_alias_normalized():
    msg = _detection_message("block", "code_execution", "a", ["R1"], 0.99)
    assert msg.startswith("blocked code_execution on a via R1")


def test_message_many_rules_collapses_to_count():
    msg = _detection_message(
        "flagged", "injection", "agent-x", ["R1", "R2", "R3"], 0.5
    )
    assert msg == "flagged injection on agent-x via R1 (+2 more)"


def test_message_no_rules_omits_via():
    msg = _detection_message("blocked", "dlp", "agent-x", [], 0.97)
    assert msg == "blocked dlp on agent-x"
    assert "via" not in msg


def test_message_missing_category_degrades_to_score_form():
    msg = _detection_message("blocked", None, "agent-x", ["R1"], 0.80)
    assert msg == "blocked on agent-x (score 0.80) via R1"


def test_message_missing_category_and_score_still_valid():
    msg = _detection_message("blocked", None, "agent-x", None, None)
    assert msg == "blocked on agent-x"


def test_message_missing_agent_uses_placeholder_not_broken_string():
    msg = _detection_message("flagged", "injection", None, ["R1"], 0.9)
    assert msg == "flagged injection on unknown-agent via R1"


def test_message_no_action_omits_cleanly():
    assert _detection_message(None, "cat", "agent", ["R1"], 0.9) is None


def test_message_allowed_benign_form():
    msg = _detection_message("allowed", None, "agent-x", None, 0.0)
    assert msg == "allowed on agent-x (score 0.00)"


def test_message_never_contains_raw_content_only_names():
    secret = "supersecret-token-abc123"
    # A rule/category/agent are NAMES; raw content is never an input to message.
    msg = _detection_message(
        "blocked", "code_execution", "agent", ["LLM08_os_exec"], 0.99
    )
    assert secret not in msg


# --- severity mapping -------------------------------------------------------


def test_severity_block_critical_band():
    assert _detection_severity("blocked", 0.95) == "critical"
    assert _detection_severity("blocked", 0.99) == "critical"
    assert _detection_severity("blocked", 1.0) == "critical"


def test_severity_block_high_band():
    assert _detection_severity("blocked", 0.94) == "high"
    assert _detection_severity("blocked", 0.0) == "high"
    assert _detection_severity("blocked", None) == "high"


def test_severity_flag_high_band():
    assert _detection_severity("flagged", 0.90) == "high"
    assert _detection_severity("flagged", 0.999) == "high"


def test_severity_flag_medium_band():
    assert _detection_severity("flagged", 0.89) == "medium"
    assert _detection_severity("flagged", 0.0) == "medium"


def test_severity_allow_info():
    assert _detection_severity("allowed", 0.0) == "info"
    assert _detection_severity("allowed", 0.99) == "info"


def test_severity_unknown_or_absent_omits():
    assert _detection_severity(None, 0.9) is None
    assert _detection_severity("", 0.9) is None
    assert _detection_severity("weird", 0.9) is None


def test_severity_accepts_imperative_aliases():
    assert _detection_severity("block", 0.96) == "critical"
    assert _detection_severity("flag", 0.5) == "medium"
    assert _detection_severity("allow", 0.0) == "info"


# --- end-to-end through the mapper ------------------------------------------


def test_mapped_event_carries_both_fields_and_keeps_raw_score():
    mapped = to_openA2A(
        _event(
            agentId="siem-agent-block",
            action="blocked",
            score=0.99,
            category="code_execution",
            rules=["LLM08_os_exec"],
        )
    )
    assert (
        mapped["gen_ai.security.detection.message"]
        == "blocked code_execution on siem-agent-block via LLM08_os_exec"
    )
    assert mapped["gen_ai.security.detection.severity"] == "critical"
    # severity is additive — the raw score field must still be present.
    assert mapped["gen_ai.security.detection.score"] == 0.99


def test_mapped_allowed_event_severity_info():
    mapped = to_openA2A(_event(agentId="a", action="allowed", score=0.0))
    assert mapped["gen_ai.security.detection.severity"] == "info"


def test_mapped_no_detection_omits_both_fields():
    mapped = to_openA2A(_event(agentId="a", direction="input"))
    assert "gen_ai.security.detection.message" not in mapped
    assert "gen_ai.security.detection.severity" not in mapped


def test_mapped_message_has_no_raw_content_for_secret_bearing_scan():
    secret = "zz-unique-secret-marker-99"
    mapped = to_openA2A(
        _event(
            agentId="dlp-agent",
            action="blocked",
            score=0.97,
            category="pii",
            rules=["DLP_SECRET"],
            prompt=f"here is my api key {secret}",
        )
    )
    msg = mapped["gen_ai.security.detection.message"]
    assert secret not in msg
    # and the content is present only as a hash, never as the message.
    assert secret not in str(mapped.values())
