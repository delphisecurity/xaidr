"""schema.py — OpenA2A telemetry mapping (gen_ai.security.*).

Maps the sensor's internal event dict to the OpenA2A schema: a vendor-neutral,
OpenTelemetry-aligned shape under the `gen_ai.security.*` namespace. Any reporter
can call `to_openA2A(event)` to emit the standard form instead of the raw
internal field names.

Design:
- Reuses existing OTel attributes where they exist (`gen_ai.agent.id`,
  `gen_ai.tool.name`) rather than re-minting them.
- Adds new attributes only under `gen_ai.security.*`.
- Flat, dotted keys (OTel attribute style) so the result maps directly onto an
  OTel span/log record OR stands alone as JSON.
- Missing fields are OMITTED, never guessed. A consumer treats an absent
  provenance/identity field as "unknown", never as "safe".

Spec: openA2A-schema-spec.md (schema_version 0.1.0).

Provenance/OBO fields (gen_ai.security.provenance.*) are defined by the spec but
populated in a later phase; the mapper already passes them through if present on
the internal event, so this is forward-compatible.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .types import safe_content_hash

SCHEMA_VERSION = "0.1.0"

# Map the sensor's internal `direction` to the spec's interaction.type +
# interaction.direction. interaction.type is the surface; direction is the way.
_INTERACTION_TYPE = {
    "input": "a2user",
    "output": "a2user",
    "a2a": "a2a",
    "a2a_inbound": "a2a",   # a RECEIVED A2A message (same surface, inbound flow)
    "tool_call": "a2tool",
    "mcp": "a2mcp",
    "llm": "a2llm",
}
_INTERACTION_DIRECTION = {
    "input": "inbound",
    "output": "outbound",
    # A SENT A2A message is outbound; a RECEIVED one is inbound. The receive path
    # tags its events "a2a_inbound" so a received message is no longer mislabelled
    # outbound in the SIEM.
    "a2a": "outbound",
    "a2a_inbound": "inbound",
    "tool_call": "outbound",
}


def _hash(text: str | None) -> str | None:
    if not text:
        return None
    # Route through the centralized fail-open helper (surrogatepass) so a
    # malformed-unicode content_hash never raises (B1). None/empty stays None.
    return safe_content_hash(text)


# Internal action values are past-tense ("blocked"/"flagged"/"allowed"). Accept
# the imperative aliases too so the derived fields are robust to either form.
_ACTION_ALIASES = {"block": "blocked", "flag": "flagged", "allow": "allowed"}


def _norm_action(action: Any) -> str | None:
    if not isinstance(action, str) or not action:
        return None
    return _ACTION_ALIASES.get(action, action)


def _fmt_score(score: Any) -> str | None:
    # bool is an int subclass — reject it so True doesn't render as "1.00".
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return None
    return f"{score:.2f}"


def _detection_severity(action: Any, score: Any) -> str | None:
    """Map (action, score) to a stable severity enum SOCs can alert on.

    Pure and additive — it does NOT replace the raw score. Cut points live here
    so they are trivial to tune later. Returns None for unknown/absent action so
    the caller omits.
    """
    act = _norm_action(action)
    if act is None:
        return None
    s = score if isinstance(score, (int, float)) and not isinstance(score, bool) else 0.0
    if act == "blocked":
        return "critical" if s >= 0.95 else "high"
    if act == "flagged":
        return "high" if s >= 0.90 else "medium"
    if act == "allowed":
        return "info"
    return None


def _detection_message(
    action: Any,
    category: Any,
    agent_id: Any,
    rules: Any,
    score: Any,
) -> str | None:
    """Compose a one-line, analyst-friendly summary from fields already present.

    Shape: "<action> <category> on <agent> via <primary_rule>". Built ONLY from
    NAMES (action/category/agent/rule) — never from raw content, so the privacy
    invariant (content stays hashed) is preserved by construction. Degrades
    gracefully: no category -> "(score X)" form; no rules -> omit " via ...".
    Returns None (omit cleanly) when there is no action to describe.
    """
    act = _norm_action(action)
    if act is None:
        return None
    agent = agent_id if isinstance(agent_id, str) and agent_id else "unknown-agent"

    # rule suffix: single rule name, or first + count when many. Never content.
    rule_suffix = ""
    if rules:
        rule_list = [r for r in rules if isinstance(r, str) and r]
        if len(rule_list) == 1:
            rule_suffix = f" via {rule_list[0]}"
        elif len(rule_list) > 1:
            rule_suffix = f" via {rule_list[0]} (+{len(rule_list) - 1} more)"

    if isinstance(category, str) and category:
        base = f"{act} {category} on {agent}"
    else:
        fs = _fmt_score(score)
        base = f"{act} on {agent} (score {fs})" if fs is not None else f"{act} on {agent}"
    return base + rule_suffix


def to_openA2A(event: dict[str, Any]) -> dict[str, Any]:
    """Convert one internal event dict to the OpenA2A gen_ai.security.* shape.

    The internal event is `{type, agentId, data: {...}}`. Returns a flat dict of
    dotted attribute keys. Unknown/missing fields are omitted.
    """
    data = event.get("data", event)  # tolerate flat or nested
    out: dict[str, Any] = {}

    # --- envelope -----------------------------------------------------------
    out["gen_ai.security.schema_version"] = SCHEMA_VERSION
    out["gen_ai.security.event_id"] = data.get("scanId") or uuid4().hex[:12]
    out["gen_ai.security.timestamp"] = _now_rfc3339()

    # --- reused OTel attribute (do NOT re-mint) -----------------------------
    agent_id = data.get("agentId") or event.get("agentId")
    if agent_id:
        out["gen_ai.agent.id"] = agent_id

    # --- interaction --------------------------------------------------------
    direction = data.get("direction")
    if direction:
        itype = _INTERACTION_TYPE.get(direction)
        if itype:
            out["gen_ai.security.interaction.type"] = itype
        idir = _INTERACTION_DIRECTION.get(direction)
        if idir:
            out["gen_ai.security.interaction.direction"] = idir

    dest_type = data.get("destinationType")
    if dest_type:
        out["gen_ai.security.interaction.destination_type"] = dest_type
    dest_id = data.get("destinationIdentifier") or data.get("destinationAgent")
    if dest_id:
        out["gen_ai.security.interaction.destination_id"] = dest_id

    tool_name = data.get("toolName")
    if tool_name:
        out["gen_ai.tool.name"] = tool_name  # reused OTel attribute
    mcp_server = data.get("mcpServer")
    if mcp_server:
        out["gen_ai.security.interaction.destination_id"] = mcp_server

    # content: carry the hash, never the raw text as an attribute
    phash = data.get("promptHash") or _hash(data.get("prompt"))
    if phash:
        out["gen_ai.security.interaction.content_hash"] = phash
    plen = data.get("promptLength")
    if plen is not None:
        out["gen_ai.security.interaction.content_length"] = plen

    # --- detection ----------------------------------------------------------
    action = data.get("action")
    if action is not None:
        out["gen_ai.security.detection.action"] = action
    score = data.get("score")
    if score is not None:
        out["gen_ai.security.detection.score"] = score
    category = data.get("category")
    if category:
        out["gen_ai.security.detection.category"] = category
    rules = data.get("rules")
    if rules:
        out["gen_ai.security.detection.rules"] = list(rules)
    mode = data.get("enforcementMode") or data.get("enforcement_mode")
    if mode:
        out["gen_ai.security.detection.enforcement_mode"] = mode
    latency = data.get("scanTimeMs")
    if latency is not None:
        out["gen_ai.security.detection.latency_ms"] = latency
    # Degraded-scan signal: when an internal scan fault made the sensor fail open
    # (allow + emit), carry the degraded flag and the fault's exception type so a
    # SIEM sees the reduced-assurance verdict instead of a clean "allowed".
    degraded = data.get("degraded")
    if degraded:
        out["gen_ai.security.detection.degraded"] = True
        error_type = data.get("errorType") or data.get("error_type")
        if error_type:
            out["gen_ai.security.detection.error_type"] = error_type

    # --- nano (the optional ML signal), when it ran -------------------------
    # Emitted with an EXPLICIT calibration attribute beside it, not as two bare
    # numbers. M1 (see ScanResult.nano_score) says this reading is a detection
    # signal and NOT calibrated confidence, and that a reviewer must not rank a
    # queue by it; a SIEM is exactly where somebody ranks by whatever numeric
    # field is present, and the warning lived only in a Python docstring that no
    # SIEM ever reads. `calibrated=false` travels with the value so the caveat
    # arrives at the same place and time as the number it is about.
    nano_score = data.get("nanoScore")
    if nano_score is not None:
        out["gen_ai.security.detection.nano_score"] = nano_score
        out["gen_ai.security.detection.nano_calibrated"] = False
        nano_raw = data.get("nanoRaw")
        if nano_raw is not None:
            out["gen_ai.security.detection.nano_raw"] = nano_raw

    # derived + additive (no raw content): a human-readable one-line summary and
    # a stable severity enum. Both are composed from the NAMES above (action,
    # category, agent, rules, score) so the content-stays-hashed invariant holds
    # by construction. The raw score field above is kept, not replaced.
    message = _detection_message(action, category, agent_id, rules, score)
    if message:
        out["gen_ai.security.detection.message"] = message
    severity = _detection_severity(action, score)
    if severity:
        out["gen_ai.security.detection.severity"] = severity

    # --- authz (impact data, when present) ----------------------------------
    # impact_class sits beside impact_tier in the same authz namespace, because
    # it is the same fact at a different granularity and a consumer reads them
    # together. It matters more than a missing field looks: the classify-only
    # classes (infra_destruction above all) never block, so telemetry is their
    # ONLY output. Without this attribute a `terraform destroy` reaches a SIEM
    # as an ordinary allowed scan with nothing naming it as teardown, and the
    # whole control-not-detection design becomes invisible to the mapped schema.
    #
    # "unknown" is the classifier's SENTINEL for "nothing matched", not a class,
    # so it is omitted rather than emitted. That keeps the schema's omit-don't-
    # guess contract intact — an absent attribute already means unknown, and
    # emitting the literal string would be a placeholder dressed as an answer.
    impact_class = data.get("impactClass")
    if impact_class and impact_class != "unknown":
        out["gen_ai.security.authz.impact_class"] = impact_class
    impact_tier = data.get("impactTier")
    if impact_tier:
        out["gen_ai.security.authz.impact_tier"] = impact_tier
    authz_decision = data.get("authzDecision")
    if authz_decision:
        out["gen_ai.security.authz.decision"] = authz_decision
    authz_policy = data.get("authzPolicyId")
    if authz_policy:
        out["gen_ai.security.authz.policy_id"] = authz_policy

    # --- provenance (forward-compatible: emitted when present) --------------
    # Populated in the provenance phase. If the internal event already carries
    # any of these (e.g. an origin_context was supplied), pass them through.
    _passthrough_provenance(data, out)

    return out


def _passthrough_provenance(data: dict[str, Any], out: dict[str, Any]) -> None:
    """Emit provenance attributes if the internal event carries them.

    The sensor now captures provenance (set_origin / origin_scope and the
    cross-process multi-hop chain resolved via W3C Trace Context), so events may
    carry an ``on_behalf_of`` / actor / correlation_id / origin_agent /
    delegation chain block. This maps whatever is present onto the
    ``gen_ai.security.provenance.*`` attributes; when a field is absent it is
    simply not emitted (a plain scan with no origin context is unaffected).
    """
    prov = data.get("provenance")
    if not isinstance(prov, dict):
        return
    if prov.get("origin_agent"):
        out["gen_ai.security.provenance.origin_agent"] = prov["origin_agent"]
    if prov.get("on_behalf_of"):
        out["gen_ai.security.provenance.on_behalf_of"] = prov["on_behalf_of"]
    if prov.get("actor"):
        out["gen_ai.security.provenance.actor"] = prov["actor"]
    if prov.get("correlation_id"):
        out["gen_ai.security.provenance.correlation_id"] = prov["correlation_id"]
    if prov.get("delegation_depth") is not None:
        out["gen_ai.security.provenance.delegation_depth"] = prov["delegation_depth"]
    if prov.get("delegation_chain"):
        out["gen_ai.security.provenance.delegation_chain"] = prov["delegation_chain"]


def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
