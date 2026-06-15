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

import hashlib
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

SCHEMA_VERSION = "0.1.0"

# Map the sensor's internal `direction` to the spec's interaction.type +
# interaction.direction. interaction.type is the surface; direction is the way.
_INTERACTION_TYPE = {
    "input": "a2user",
    "output": "a2user",
    "a2a": "a2a",
    "tool_call": "a2tool",
    "mcp": "a2mcp",
    "llm": "a2llm",
}
_INTERACTION_DIRECTION = {
    "input": "inbound",
    "output": "outbound",
    "a2a": "outbound",
    "tool_call": "outbound",
}


def _hash(text: str | None) -> str | None:
    if not text:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


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

    # --- authz (impact data, when present) ----------------------------------
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

    No-op today (the sensor does not yet capture provenance). Present so that
    when the provenance phase adds capture, emission needs no mapper change.
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
