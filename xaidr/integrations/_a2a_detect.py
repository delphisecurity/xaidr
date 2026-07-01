"""Shape-based A2A (agent-to-agent) detection for receive-side routing.

The receive integration must decide, per inbound message, whether it is an A2A
delegation (route to ``sensor.scan_a2a`` so the A2A field extractor +
structural/id checks run) or a plain user prompt (route to ``sensor.scan``).

This detection is based on the **message shape**, per the A2A protocol spec
(JSON-RPC 2.0 over HTTP), NOT on any timing/coincidence heuristic. It is
transport-independent: the authoritative signal is the payload, so it works the
same in-process, across containers, and on Bedrock/Vertex. Transport headers
(Content-Type) are used only as a corroborating fast-path hint when present.

A single importable ``looks_like_a2a`` is the one source of truth — both the
integration layer and the tests call it, so routing and its oracle can never
drift. Extraction is NOT re-implemented here; it lives in ``scan_a2a`` already.
"""

from __future__ import annotations

import json
from typing import Optional, Union


def _content_type_is_a2a_hint(headers: Optional[dict]) -> bool:
    """True when transport headers *hint* at a JSON-RPC/A2A payload.

    A hint only — never the sole signal (in-process delegation carries no
    headers). Looks for ``application/json`` / ``text/event-stream`` content
    types or any ``a2a-`` prefixed param/header (A2A service marker).
    """
    if not isinstance(headers, dict):
        return False
    for key, value in headers.items():
        k = str(key).lower()
        v = str(value).lower()
        if k == "content-type" and (
            "application/json" in v or "text/event-stream" in v
        ):
            return True
        # A2A service params/headers are prefixed ``a2a-``.
        if k.startswith("a2a-"):
            return True
    return False


def _is_a2a_shape(body: dict) -> bool:
    """Authoritative payload-shape check against the A2A/JSON-RPC signature.

    A2A iff the dict has the JSON-RPC marker (``jsonrpc == "2.0"`` AND a
    ``method``) OR a real A2A ``parts[]`` / ``messages`` path. We require the
    JSON-RPC marker OR a genuine ``parts[]`` list — NOT merely the presence of
    a key named ``parts`` / ``message`` on arbitrary JSON (false-positive
    guard).
    """
    # --- JSON-RPC 2.0 marker (primary signal) --------------------------------
    if body.get("jsonrpc") == "2.0" and isinstance(body.get("method"), str):
        return True

    # --- Real A2A content paths (transport-independent, no JSON-RPC marker) ---
    params = body.get("params")
    if isinstance(params, dict):
        # Request shape: params.message.parts[] (list).
        msg = params.get("message")
        if isinstance(msg, dict) and isinstance(msg.get("parts"), list):
            return True
        # Variant: params.messages[] (list of message dicts).
        messages = params.get("messages")
        if isinstance(messages, list) and any(
            isinstance(m, dict) for m in messages
        ):
            return True

    # --- Response shape: result.artifacts[].parts[] --------------------------
    result = body.get("result")
    if isinstance(result, dict):
        rmsg = result.get("message")
        if isinstance(rmsg, dict) and isinstance(rmsg.get("parts"), list):
            return True
        artifacts = result.get("artifacts")
        if isinstance(artifacts, list):
            for art in artifacts:
                if isinstance(art, dict) and isinstance(art.get("parts"), list):
                    return True

    return False


def looks_like_a2a(
    body: Union[dict, str, None],
    headers: Optional[dict] = None,
) -> tuple[bool, Optional[dict]]:
    """Decide whether ``body`` is an A2A (JSON-RPC) message.

    Hybrid: Content-Type header is a fast-path *hint*; the authoritative check
    is payload shape (see :func:`_is_a2a_shape`). A header hint alone never
    classifies arbitrary JSON as A2A — the shape must match.

    Returns ``(is_a2a, parsed_body)`` where ``parsed_body`` is the parsed dict
    when A2A (so the caller can pass ``json_body=parsed`` to ``scan_a2a``), else
    ``None``. Never raises on malformed input — unparseable strings fail safe to
    ``(False, None)``.
    """
    # ``headers`` is a corroborating hint we compute but never treat as the sole
    # signal; payload shape below is authoritative.
    _ = _content_type_is_a2a_hint(headers)

    parsed: Optional[dict] = None
    if isinstance(body, dict):
        parsed = body
    elif isinstance(body, str):
        try:
            loaded = json.loads(body)
        except (ValueError, TypeError):
            loaded = None
        if isinstance(loaded, dict):
            parsed = loaded

    if parsed is None:
        return False, None

    if _is_a2a_shape(parsed):
        return True, parsed
    return False, None
