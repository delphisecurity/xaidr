"""A2AStructuralValidator — Tier A structural checks for A2A JSON-RPC traffic.

Inspects the *wire format* of an A2A message — envelope shape, part
discriminators, role field, metadata surface — for protocol-level anomalies.
This is deliberately content-blind: it never reads prose for intent (that is
the job of L1/L2 content scanners and the message extractor). It only asks
"is this message shaped the way the A2A protocol says it should be?".

Pure and stateless: ``validate`` is a function of its inputs alone.

Every check runs on EVERY A2A object in the body, not only the top-level
message. A2A nests Messages and Artifacts inside task containers
(``result.status.message``, ``result.history[]``, ``result.artifacts[]``,
``result.artifact``, ``result.tasks[]``), and those containers are
attacker-controlled, so the walk that reaches them is bounded in depth,
node count and list length — see ``_walk_a2a_nodes``.

Each fired check contributes a flag-level confidence in the 0.15–0.40 range.
Nothing here is a hard block — a structural anomaly is a signal that a higher
layer (policy) decides what to do with. The returned shape matches the
compositional scanner::

    {"score": float, "signals": [str], "details": [{rule, category,
     confidence, layer}]}

where ``score`` is the max confidence across fired checks.
"""

from __future__ import annotations

import re
import threading
import time

# Wire/structural layer. Sits below L1 (content rules, layer 1) and L2
# (compositional, layer 2) — it runs on the envelope, not the text.
_LAYER = 0

# ACP-style scoped agent role, e.g. "agent/billing".
_SCOPED_AGENT_ROLE = re.compile(r"^agent/[\w.-]+$")

# Roles the A2A protocol expects on a message.
_VALID_ROLES = frozenset({"user", "agent"})

_PRIVILEGED_PART_ROLES = frozenset(
    {"system", "assistant", "tool", "developer", "function"}
)

# Metadata string longer than this is prose, not a routing hint — a place to
# smuggle instructions past content scanners that only read parts[].text.
_METADATA_PROSE_LEN = 200

# -- id-field CONTENT validation (ASI07) -------------------------------------
# An A2A id (messageId/taskId/contextId/any *Id) is an OPAQUE IDENTIFIER — a
# UUID, hash, prefixed token, or namespaced ref. It is provenance-checked by
# A2AIdTracker but its STRING CONTENT was never validated: a path-traversal or
# command-injection payload smuggled into an id field passed unseen (the field
# is filtered out of the content scan as routing noise). These patterns fire on
# TRAVERSAL / INJECTION SHAPES only — NOT on every non-UUID id, and NOT on prose
# (an id carrying words but no dangerous shape stays a filtered noise field).
#
# All patterns are anchored or single-pass with no nested/overlapping
# quantifiers, so they are linear-time on the short id strings they scan
# (ReDoS-safe).
#
# A ".." path SEGMENT — literal traversal — bounded by a separator or an end.
# Distinguishes traversal ("../", "/..") from a legitimate namespaced single
# slash ("AGENT-SVC/checkout-flow"), which has no ".." component: THE FP CRUX.
_ID_TRAVERSAL_SEG = re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|$)")
# URL-encoded traversal / null: encoded dot, slash, backslash, or NUL. A normal
# opaque id never percent-encodes, so these building blocks are unambiguous.
_ID_ENCODED = re.compile(r"(?i)%00|%2e|%2f|%5c")
# Leading absolute path ("/etc/shadow", "\\host") or a Windows drive path
# ("C:\\..."). A leading separator is never an identifier shape.
_ID_ABSOLUTE = re.compile(r"^(?:[/\\]|[A-Za-z]:[/\\])")
# Control characters incl. the NUL byte and DEL — never in a legitimate id.
_ID_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# Shell / command-injection metacharacters. Keyed on METACHARACTERS, not on
# spaces: "id; rm -rf /" (has ';') is injection, but prose like "ignore all
# previous instructions" (only spaces and words) is NOT flagged — it stays a
# filtered noise field, preserving the id-as-noise contract.
_ID_INJECTION = re.compile(r"[;|&$`<>()\n\r\t]")


# -- BOUNDED NESTED WALK ------------------------------------------------------
# A2A does not put every Message at the top level. Per the canonical spec
# (`specification/a2a.proto` @ v1.0.1, and the v0.3.0 JSON Schema, which agree
# field-for-field on this), a Message is reachable through TASK CONTAINERS:
#
#   MessageSendParams.message          -> params.message          (top level)
#   TaskStatus.message                 -> result.status.message
#   Task.history[]                     -> result.history[]
#   TaskStatusUpdateEvent.status       -> result.status.message   (streaming)
#   ListTasksResponse.tasks[]          -> result.tasks[].{status.message,history[]}
#
# and a Part — the thing the OneOf and part-role checks read — is reachable
# through every one of those PLUS:
#
#   Artifact.parts[]                   -> result.artifacts[]
#   TaskArtifactUpdateEvent.artifact   -> result.artifact          (streaming)
#
# Inspecting only the top-level message left all of the above unexamined: the
# identical Message object scored 0.40 at `params.message` and 0.0 inside
# `result.status.message` or `result.history[0]`, so a forged role, an id
# traversal or a part-role forgery was a matter of WHERE the attacker put it.
#
# The walk follows SPEC-NAMED EDGES ONLY — it is not a generic deep scan of
# attacker JSON. It is ITERATIVE (explicit stack, never recursion), because a
# recursive walk over an attacker-controlled nesting depth is how this path
# previously produced a RecursionError that failed a scan open.
#
# Depth, node count and list length are all bounded. EXCEEDING A BOUND FIRES A
# SIGNAL — it never silently drops the unwalked remainder. Structure we could
# not examine is reported as structure we could not examine.
_MAX_NEST_DEPTH = 8       # edges followed from the root (real A2A needs <= 4)
_MAX_NEST_NODES = 64      # container nodes visited in one body
_MAX_LIST_ITEMS = 32      # items read from any one history[]/artifacts[]/tasks[]
_MAX_METADATA_NODES = 512  # values visited by the metadata prose scan

# Confidence for a truncated walk. Flag-level, same band as the other
# structural checks — "we could not finish looking here" is a review signal,
# not an assertion of attack.
_BOUND_CONFIDENCE = 0.35

# Child edges as (field, is_list, child_kind). "auto" resolves by shape.
_CONTAINER_EDGES = (
    ("message", False, "message"),      # MessageSendParams.message, TaskStatus.message
    ("status", False, "container"),     # Task.status, TaskStatusUpdateEvent.status
    ("task", False, "auto"),            # 0.x/impl-side task wrapper
    ("tasks", True, "auto"),            # ListTasksResponse.tasks[]
    ("history", True, "message"),       # Task.history[]
    ("artifacts", True, "artifact"),    # Task.artifacts[]
    ("artifact", False, "artifact"),    # TaskArtifactUpdateEvent.artifact
)
# A JSON-RPC envelope reaches A2A objects only through params/result.
_ENVELOPE_EDGES = (
    ("params", False, "container"),
    ("result", False, "auto"),
)
_EDGES_BY_KIND = {
    "envelope": _ENVELOPE_EDGES,
    "container": _CONTAINER_EDGES,
    "message": (),      # parts are checked in place, not walked as nodes
    "artifact": (),
}


def _is_task_node(node) -> bool:
    """``kind: "task"``, or a Task's required ``id`` + ``status`` pair.

    Used only to decide whether an UNENVELOPED root dict is a bare Task (the
    in-process shape, the Task analogue of :func:`_is_bare_message`). A
    JSON-RPC envelope has neither, so this never reclassifies wire traffic.
    """
    if not isinstance(node, dict):
        return False
    if node.get("kind") == "task":
        return True
    return isinstance(node.get("status"), dict) and isinstance(node.get("id"), str)


def _root_kind(body: dict) -> str:
    """Classify the ROOT dict. Envelope roots are NOT id-checked.

    A JSON-RPC ``id`` is a transport correlation value, not an A2A identifier,
    and it was never read by the id-content check. Keeping the envelope out of
    the id scan preserves that exactly; a bare Message or bare Task root is a
    real A2A object and is checked, which is also the pre-existing behavior for
    the bare-Message case.
    """
    if _is_bare_message(body):
        return "message"
    if _is_task_node(body):
        return "container"
    return "envelope"


def _walk_a2a_nodes(body: dict) -> tuple[list[tuple[str, dict]], set[str]]:
    """Every A2A node in ``body`` reachable via spec-named edges, bounded.

    Returns ``(nodes, bounds)`` where ``nodes`` is a list of ``(kind, node)``
    and ``bounds`` is the set of bounds that were EXCEEDED — ``"depth"`` when a
    node still had unwalked children at the depth limit, ``"breadth"`` when the
    node cap or a list cap truncated the walk. The caller turns each into a
    signal; nothing is dropped quietly.
    """
    nodes: list[tuple[str, dict]] = []
    bounds: set[str] = set()
    if not isinstance(body, dict):
        return nodes, bounds

    seen = {id(body)}          # cycle guard: a dict body may be self-referential
    stack = [(body, _root_kind(body), 0)]
    while stack:
        node, kind, depth = stack.pop()
        if len(nodes) >= _MAX_NEST_NODES:
            bounds.add("breadth")
            break
        nodes.append((kind, node))

        edges = _EDGES_BY_KIND.get(kind, ())
        if not edges:
            continue
        if depth >= _MAX_NEST_DEPTH:
            # Only flag if something was actually left unwalked.
            if any(
                isinstance(node.get(f), dict)
                or (is_list and isinstance(node.get(f), list) and node.get(f))
                for f, is_list, _ in edges
            ):
                bounds.add("depth")
            continue

        for field, is_list, child_kind in edges:
            value = node.get(field)
            if is_list:
                if not isinstance(value, list):
                    continue
                if len(value) > _MAX_LIST_ITEMS:
                    bounds.add("breadth")
                items = value[:_MAX_LIST_ITEMS]
            else:
                items = [value]
            for item in items:
                if not isinstance(item, dict) or id(item) in seen:
                    continue
                seen.add(id(item))
                resolved = child_kind
                if resolved == "auto":
                    resolved = "message" if _is_bare_message(item) else "container"
                stack.append((item, resolved, depth + 1))

    return nodes, bounds


def _a2a_message(body: dict):
    """The A2A ``Message`` object inside ``body``, wherever it sits.

    Three placements, all real:

    * ``params.message`` — a JSON-RPC REQUEST (``message/send``).
    * ``result`` — a JSON-RPC RESPONSE, whose result IS a Message.
    * ``body`` itself — a BARE Message with no envelope, which is what a
      framework holds in process before serialization. CrewAI's A2A client
      builds one of these (a2a-sdk ``Message``) and hands it to the transport.

    The bare case was previously invisible here: ``_message`` only read
    ``params.message``, so a top-level Message reached the scanner with its
    parts, role, metadata and ``taskId``/``contextId`` unexamined. Content was
    still scanned by the text extractor, so nothing failed loudly — the
    structural and id-smuggling checks just never ran, which is the worst way
    for a control to be absent.
    """
    params = body.get("params")
    if isinstance(params, dict):
        message = params.get("message")
        if isinstance(message, dict):
            return message
    if _is_bare_message(body):
        return body
    result = body.get("result")
    if _is_bare_message(result):
        return result
    return None


def _is_bare_message(node) -> bool:
    """``kind: "message"`` plus a real ``parts`` list — the A2A Message shape.

    Both conditions required, for the same false-positive reason as the
    matching check in ``xaidr/integrations/_a2a_detect.py``.
    """
    return (
        isinstance(node, dict)
        and node.get("kind") == "message"
        and isinstance(node.get("parts"), list)
    )


class A2AStructuralValidator:
    """Stateless structural/wire-format validator for A2A JSON-RPC messages."""

    def validate(self, json_body: dict, direction: str) -> dict:
        """Validate the structure of an A2A message body.

        Args:
            json_body: the parsed JSON-RPC body (request or response shape).
            direction: traffic direction — "a2a" denotes OUTBOUND traffic from
                our own agent; "input"/"output" denote inbound/response.

        Returns:
            {"score", "signals", "details"} — see module docstring.
        """
        details: list[dict] = []

        def fire(rule: str, category: str, confidence: float) -> None:
            details.append(
                {
                    "rule": rule,
                    "category": category,
                    "confidence": confidence,
                    "layer": _LAYER,
                }
            )

        if not isinstance(json_body, dict):
            # Nothing structural to assert about a non-object body.
            return {"score": 0.0, "signals": [], "details": []}

        self._check_envelope(json_body, fire)

        # Every Message / Artifact / task container in the body, not just the
        # top-level one. See `_walk_a2a_nodes` for the spec-derived edge list
        # and the bounds.
        nodes, bounds = _walk_a2a_nodes(json_body)
        metadata_fired = False
        for kind, node in nodes:
            if kind == "envelope":
                # JSON-RPC transport shell — it carries no A2A identifier and
                # no content of its own.
                continue
            if kind in ("message", "artifact"):
                self._check_parts(node.get("parts"), fire, bounds)
                if not metadata_fired:
                    metadata_fired = self._check_metadata_surface(node, fire, bounds)
            if kind == "message":
                self._check_role(node, direction, fire)
            self._check_id_content(node, fire)

        # A truncated walk is REPORTED, never silently dropped: the unwalked
        # remainder is attacker-controlled structure we did not inspect.
        if "depth" in bounds:
            fire("a2a_nested_depth_exceeded", "structural_nesting", _BOUND_CONFIDENCE)
        if "breadth" in bounds:
            fire("a2a_nested_breadth_exceeded", "structural_nesting", _BOUND_CONFIDENCE)

        score = round(max((d["confidence"] for d in details), default=0.0), 4)
        # Order-preserving dedup: one body can now legitimately reach dozens of
        # nodes, and N identical rule names in the verdict's `rules` list is
        # noise. `details` keeps every occurrence for diagnosis.
        signals: list[str] = []
        for d in details:
            if d["rule"] not in signals:
                signals.append(d["rule"])
        return {"score": score, "signals": signals, "details": details}

    # -- 1. MALFORMED ENVELOPE (0.30) --------------------------------------
    def _check_envelope(self, body: dict, fire) -> None:
        looks_jsonrpc = any(k in body for k in ("jsonrpc", "method", "params"))
        if not looks_jsonrpc:
            return

        if "jsonrpc" in body and body.get("jsonrpc") != "2.0":
            fire("envelope_jsonrpc_version", "structural_envelope", 0.30)

        method = body.get("method")
        if "method" in body and not isinstance(method, str):
            fire("envelope_method_not_string", "structural_envelope", 0.30)

        params = body.get("params")
        if "params" in body and not isinstance(params, dict):
            fire("envelope_params_not_object", "structural_envelope", 0.30)

        # Method-specific required fields. message/send requires params.message.
        if method == "message/send":
            if not isinstance(params, dict) or not isinstance(params.get("message"), dict):
                fire("envelope_missing_required", "structural_envelope", 0.30)

    # -- 2. PART ONEOF VIOLATION (0.35) ------------------------------------
    # A2A v1.0 (Appendix A.2.1) REMOVED the `kind` discriminator: a Part is a
    # OneOf distinguished by WHICH content field is present — exactly one of
    # text / file(raw bytes) / data. We validate by PRESENCE, which is correct
    # for v1.0 parts (no `kind`) AND 0.x parts (with `kind`): zero content fields
    # or more than one (the old "text part smuggling a data object" case) is the
    # anomaly. When a legacy `kind` IS present we additionally flag a
    # kind/content mismatch — a 0.x smuggling signal v1.0 expresses via the OneOf.
    def _check_parts(self, parts, fire, bounds) -> None:
        if not isinstance(parts, list):
            return
        # parts[] is attacker-sized too. Bound it like every other list, and
        # RECORD the truncation so it becomes a signal rather than a silent
        # shortening of what was inspected.
        if len(parts) > _MAX_LIST_ITEMS:
            bounds.add("breadth")
        for part in parts[:_MAX_LIST_ITEMS]:
            if not isinstance(part, dict):
                continue
            kind = part.get("kind")
            raw_text = part.get("text")
            has_text = isinstance(raw_text, str) and bool(raw_text.strip())
            has_data = isinstance(part.get("data"), dict)
            # File part: v1.0 `file` object (FileWithBytes/FileWithUri) or 0.x/ACP
            # top-level file reference.
            has_file = isinstance(part.get("file"), (dict, str)) or any(
                isinstance(part.get(k), str) for k in ("fileId", "url", "uri")
            )
            present = (has_text, has_data, has_file)
            n_present = sum(present)

            # Presence-based OneOf: exactly one content field is required.
            if n_present == 0:
                fire("part_oneof_no_content", "structural_part", 0.35)
            elif n_present > 1:
                # Multiple content fields — ambiguous which the receiver trusts,
                # and the classic "text part also carries a data object" smuggle.
                fire("part_oneof_multiple_content", "structural_part", 0.35)

            # Backward-compat: a legacy `kind` that names a content field which
            # is absent is a 0.x kind/content mismatch (e.g. kind=text, no text).
            if isinstance(kind, str) and n_present >= 1:
                expected_present = {
                    "text": has_text, "data": has_data, "file": has_file,
                }.get(kind)
                if expected_present is False:
                    fire("part_kind_content_mismatch", "structural_part", 0.35)

            # Part-level ROLE forgery (ADI class). `role` is a MESSAGE field in
            # the A2A spec — a part carrying its own role asserts an identity the
            # protocol gives it no right to. A privileged value is the forged-
            # trust injection shape; any other part-level role is still an
            # anomaly. Flag-level only: surfaces for review, never blocks alone.
            part_role = part.get("role")
            if part_role is not None:
                if (
                    isinstance(part_role, str)
                    and part_role.strip().lower() in _PRIVILEGED_PART_ROLES
                ):
                    fire("part_role_forgery", "structural_part", 0.40)
                else:
                    fire("part_unexpected_role", "structural_part", 0.30)

    # -- 3. ROLE ANOMALY (0.25 / 0.30) -------------------------------------
    def _check_role(self, message: dict, direction: str, fire) -> None:
        if not isinstance(message, dict) or "role" not in message:
            return
        role = message.get("role")

        valid = isinstance(role, str) and (
            role in _VALID_ROLES or bool(_SCOPED_AGENT_ROLE.match(role))
        )
        if not valid:
            fire("role_unexpected_value", "structural_role", 0.25)

        # NOTE: per the A2A spec, the CLIENT side of an exchange is labeled
        # role="user" even when the client is itself an agent (the client may be
        # "an application or agent that initiates requests on behalf of a user").
        # So role="user" on an OUTBOUND (agent-as-client) message is the correct,
        # spec-compliant value -- NOT an anomaly. We therefore do not flag it.
        # The genuine structural anomaly is an invalid/unknown role VALUE, caught
        # above by role_unexpected_value.

    # -- 4. METADATA/EXTENSIONS INSTRUCTION SURFACE (0.20) -----------------
    def _check_metadata_surface(self, node: dict, fire, bounds) -> bool:
        """True if the prose-surface flag fired for ``node``.

        Runs on every Message AND Artifact the walk finds — both carry
        ``metadata``/``extensions``, and both are instruction surfaces a
        content scanner reading only ``parts[].text`` would miss.
        """
        if not isinstance(node, dict):
            return False
        for field in ("metadata", "extensions"):
            found, truncated = self._scan_long_string(node.get(field))
            if truncated:
                bounds.add("breadth")
            if found:
                fire("metadata_prose_surface", "structural_metadata", 0.20)
                # One flag per body is enough; the extractor scans the text.
                return True
        return False

    # -- 5. ID-FIELD MALICIOUS CONTENT (0.40) — ASI07 ----------------------
    # id fields are provenance-checked by A2AIdTracker but never validated for
    # STRING CONTENT. Scan the VALUES of id fields (messageId/taskId/contextId
    # and any *Id) for traversal/injection shapes. Fires only on those shapes,
    # not on every non-UUID id and not on prose — an id carrying words but no
    # dangerous shape remains a filtered routing-noise field.
    def _check_id_content(self, node: dict, fire) -> None:
        for value in self._iter_id_values(node):
            category = self._id_content_category(value)
            if category is not None:
                fire(category, "structural_id", 0.40)

    @staticmethod
    def _id_content_category(value: str) -> str | None:
        """Return a signal name if ``value`` carries a malicious id shape.

        ``id_field_traversal`` for path-traversal / encoded-traversal /
        absolute-path payloads; ``id_field_malicious_content`` for NUL/control
        bytes and command-injection metacharacters. ``None`` when the value is
        a benign opaque id — INCLUDING a legitimate namespaced single slash
        (no ".." segment, no leading separator), the FP crux.
        """
        if (
            _ID_TRAVERSAL_SEG.search(value)
            or _ID_ENCODED.search(value)
            or _ID_ABSOLUTE.match(value)
        ):
            return "id_field_traversal"
        if _ID_CONTROL.search(value) or _ID_INJECTION.search(value):
            return "id_field_malicious_content"
        return None

    def _iter_id_values(self, node: dict):
        """Yield the string values of id fields DIRECTLY on ``node``.

        An id field is any key equal to ``id`` or ending in ``Id`` (messageId,
        taskId, contextId, artifactId, referenceTaskId, ...). Reads only the
        node's own keys — never a data part's payload, which may legitimately
        hold a path. Empty strings are skipped. The caller supplies the nodes;
        which ones are in scope is decided by the walk, not here.
        """
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            if not isinstance(value, str) or not value:
                continue
            if key == "id" or key.endswith("Id"):
                yield value

    # -- helpers -----------------------------------------------------------
    # NOTE: there is deliberately no `_message` alias here any more. Resolving
    # "THE message" was the defect: the validator drives off `_walk_a2a_nodes`,
    # which yields every message. `_a2a_message` survives for A2AIdTracker,
    # whose question really is singular (which task id is THIS body claiming).

    @staticmethod
    def _scan_long_string(node) -> tuple[bool, bool]:
        """``(found, truncated)`` for a prose-length string under ``node``.

        ITERATIVE and node-bounded. This was a plain recursive ``any()`` over
        an attacker-controlled ``metadata`` object — the exact shape that
        produced a RecursionError failing a scan open on this path. An explicit
        stack cannot blow the interpreter stack, and the visit cap reports
        truncation to the caller instead of returning a quiet ``False``.
        """
        stack = [node]
        visited = 0
        while stack:
            cur = stack.pop()
            visited += 1
            if visited > _MAX_METADATA_NODES:
                return False, True
            if isinstance(cur, str):
                if len(cur) > _METADATA_PROSE_LEN:
                    return True, False
            elif isinstance(cur, dict):
                stack.extend(cur.values())
            elif isinstance(cur, (list, tuple)):
                stack.extend(cur)
        return False, False


# Default lifetime of a recorded id and per-store size cap.
_DEFAULT_TTL_SECONDS = 3600
_DEFAULT_MAX_SIZE = 10000


class A2AIdTracker:
    """Stateful task/context-id tracker that detects ID smuggling.

    Our agent should only reference a ``taskId``/``contextId`` that was
    legitimately issued to it by a peer (recorded via :meth:`record_issued`
    from inbound responses). An outbound message referencing an id we were
    never issued is *smuggling* — e.g. an injected instruction telling our
    agent to resume or hijack someone else's task/context.

    State is bounded in-memory with a TTL and a size cap, purged lazily on
    each operation (no background thread). Stores are guarded by a lock so the
    sensor can scan concurrently; critical sections are kept tiny.

    Returns the same ``{"score", "signals", "details"}`` shape as
    :class:`A2AStructuralValidator`. Nothing here hard-blocks — policy at a
    higher layer decides what to do with a smuggling signal.
    """

    def __init__(
        self,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
        max_size: int = _DEFAULT_MAX_SIZE,
    ):
        self._ttl = ttl_seconds
        self._max_size = max_size
        # id -> expiry_timestamp (epoch seconds)
        self.known_task_ids: dict[str, float] = {}
        self.known_context_ids: dict[str, float] = {}
        self._lock = threading.Lock()

    # -- issuance path (inbound responses) ---------------------------------
    def record_issued(self, json_body: dict) -> None:
        """Record ids legitimately issued to us by a peer's response.

        Call on INBOUND responses. Every task id found is stored in
        ``known_task_ids`` and every context id in ``known_context_ids`` with
        a fresh expiry.
        """
        if not isinstance(json_body, dict):
            return
        task_ids, context_ids = self._collect_issued_ids(json_body)
        if not task_ids and not context_ids:
            return
        now = time.time()
        expiry = now + self._ttl
        with self._lock:
            self._purge_expired(now)
            for tid in task_ids:
                self.known_task_ids[tid] = expiry
            for cid in context_ids:
                self.known_context_ids[cid] = expiry
            self._enforce_cap(self.known_task_ids)
            self._enforce_cap(self.known_context_ids)

    # -- enforcement path (outbound a2a messages) --------------------------
    def check_outbound(self, json_body: dict) -> dict:
        """Check an outbound a2a message for id smuggling."""
        details: list[dict] = []

        def fire(rule: str, confidence: float, note: str) -> None:
            details.append(
                {
                    "rule": rule,
                    "category": "agentic_abuse",
                    "confidence": confidence,
                    "layer": _LAYER,
                    "note": note,
                }
            )

        if not isinstance(json_body, dict):
            return {"score": 0.0, "signals": [], "details": []}

        task_id = self._outbound_task_id(json_body)
        context_id = self._outbound_context_id(json_body)
        is_followup = self._is_followup_shape(json_body)

        # Classify against the store BEFORE purging, so an aged-out id is still
        # distinguishable from one we never saw (purge would erase that).
        now = time.time()
        with self._lock:
            task_status = self._classify(self.known_task_ids, task_id, now)
            ctx_status = self._classify(self.known_context_ids, context_id, now)
            self._purge_expired(now)

        # --- taskId ---
        # First-reference exemption: no taskId means this is a new-task
        # creation, never a smuggled reference.
        if task_id is not None:
            if task_status == "known":
                pass  # legitimate follow-up
            elif task_status == "expired":
                # Aged out — may be a slow but legitimate follow-up, so score
                # low rather than asserting an attack.
                fire("expired_task_reference", 0.20, "task id known but expired")
            else:  # unknown
                # We cannot tell a smuggled id from a client-minted new-task id
                # by wire format alone. Only assert smuggling (0.45) when the
                # message is a FOLLOW-UP shape (a JSON-RPC method referencing an
                # existing task). Otherwise default to the SAFER behavior: a
                # lower 0.25 "unverified" flag that escalates for review instead
                # of asserting an attack on a possibly-legitimate new id.
                if is_followup:
                    fire("task_id_smuggling", 0.45, "follow-up references unissued task id")
                else:
                    fire("unverified_task_reference", 0.25, "task id not issued to us; create/follow-up ambiguous")

        # --- contextId ---
        if context_id is not None:
            if ctx_status == "known":
                pass
            elif ctx_status == "expired":
                fire("expired_context_reference", 0.20, "context id known but expired")
            else:  # unknown
                fire("context_id_smuggling", 0.40, "references unissued context id")

        score = round(max((d["confidence"] for d in details), default=0.0), 4)
        signals = [d["rule"] for d in details]
        return {"score": score, "signals": signals, "details": details}

    # -- store maintenance -------------------------------------------------
    def _purge_expired(self, now: float) -> None:
        """Drop expired entries. Caller holds the lock."""
        for store in (self.known_task_ids, self.known_context_ids):
            expired = [k for k, exp in store.items() if exp <= now]
            for k in expired:
                del store[k]

    def _enforce_cap(self, store: dict[str, float]) -> None:
        """Evict soonest-to-expire entries until within cap. Caller holds lock."""
        excess = len(store) - self._max_size
        if excess <= 0:
            return
        # Ascending expiry => already-expired and soonest-to-expire go first.
        for k in sorted(store, key=store.get)[:excess]:
            del store[k]

    @staticmethod
    def _classify(store: dict[str, float], id_: str | None, now: float) -> str:
        """known | expired | unknown for an id, reading the timestamp directly."""
        if id_ is None:
            return "unknown"
        exp = store.get(id_)
        if exp is None:
            return "unknown"
        if exp <= now:
            return "expired"
        return "known"

    # -- extraction helpers ------------------------------------------------
    @staticmethod
    def _str_or_none(value) -> str | None:
        return value if isinstance(value, str) and value else None

    def _collect_issued_ids(self, body: dict) -> tuple[set[str], set[str]]:
        """Gather task ids and context ids from an inbound response body."""
        task_ids: set[str] = set()
        context_ids: set[str] = set()

        def add_from(obj, task_keys=("taskId", "id"), ctx_keys=("contextId",)):
            if not isinstance(obj, dict):
                return
            for k in task_keys:
                v = self._str_or_none(obj.get(k))
                if v:
                    task_ids.add(v)
            for k in ctx_keys:
                v = self._str_or_none(obj.get(k))
                if v:
                    context_ids.add(v)

        result = body.get("result")
        if isinstance(result, dict):
            # result.id / result.taskId / result.contextId
            add_from(result)
            # result.status / result.task
            add_from(result.get("status"))
            add_from(result.get("task"))
            # result.artifacts[*]
            artifacts = result.get("artifacts")
            if isinstance(artifacts, list):
                for art in artifacts:
                    # An artifact's own "id" is an artifactId, not a task id —
                    # only honor explicit taskId/contextId here.
                    add_from(art, task_keys=("taskId",))

        # params.taskId / params.contextId (streamed task updates)
        params = body.get("params")
        if isinstance(params, dict):
            add_from(params, task_keys=("taskId",))

        return task_ids, context_ids

    def _outbound_task_id(self, body: dict) -> str | None:
        msg = self._message(body)
        if isinstance(msg, dict):
            tid = self._str_or_none(msg.get("taskId"))
            if tid:
                return tid
        params = body.get("params")
        if isinstance(params, dict):
            return self._str_or_none(params.get("taskId"))
        return None

    def _outbound_context_id(self, body: dict) -> str | None:
        msg = self._message(body)
        if isinstance(msg, dict):
            cid = self._str_or_none(msg.get("contextId"))
            if cid:
                return cid
        params = body.get("params")
        if isinstance(params, dict):
            return self._str_or_none(params.get("contextId"))
        return None

    _message = staticmethod(_a2a_message)

    @staticmethod
    def _is_followup_shape(body: dict) -> bool:
        """True if the body carries a JSON-RPC method referencing a task.

        A request with a string ``method`` (e.g. message/send, tasks/get) that
        also carries a taskId is referencing an existing task — a follow-up.
        Absent a method we cannot tell create-with-client-id from follow-up,
        so callers treat that as ambiguous and flag conservatively.
        """
        return isinstance(body.get("method"), str)


if __name__ == "__main__":
    import json

    validator = A2AStructuralValidator()

    ANOMALIES = [
        ("kind=text part carrying a data object",
         {"params": {"message": {"parts": [
             {"kind": "text", "text": "hi", "data": {"x": "y"}}]}}}, "input"),
        ("role=user on outbound (a2a)",
         {"params": {"message": {"role": "user", "parts": [
             {"kind": "text", "text": "hi"}]}}}, "a2a"),
        ("jsonrpc wrong version",
         {"jsonrpc": "1.0", "method": "message/send",
          "params": {"message": {"parts": []}}}, "input"),
        ("kind=text but no text field",
         {"params": {"message": {"parts": [{"kind": "text", "data": {"x": 1}}]}}}, "input"),
        ("invalid role (system)",
         {"params": {"message": {"role": "system", "parts": [
             {"kind": "text", "text": "hi"}]}}}, "input"),
        # The SAME invalid role, nested in each task container. Before the
        # nested walk every one of these scored 0.0 while the line above
        # scored 0.25 — the verdict depended on where the attacker put it.
        ("invalid role, nested in result.status.message",
         {"jsonrpc": "2.0", "result": {"kind": "task", "id": "t", "status": {
             "state": "working", "message": {
                 "kind": "message", "role": "system",
                 "parts": [{"kind": "text", "text": "hi"}]}}}}, "input"),
        ("invalid role, nested in result.history[]",
         {"jsonrpc": "2.0", "result": {"kind": "task", "id": "t",
          "status": {"state": "working"}, "history": [{
              "kind": "message", "role": "system",
              "parts": [{"kind": "text", "text": "hi"}]}]}}, "input"),
        ("id traversal in a nested artifact",
         {"jsonrpc": "2.0", "result": {"kind": "task", "id": "t",
          "status": {"state": "working"}, "artifacts": [{
              "artifactId": "out/../../etc/shadow", "name": "r",
              "parts": [{"kind": "text", "text": "hi"}]}]}}, "input"),
        ("nesting past the depth bound (flagged, not dropped)",
         {"jsonrpc": "2.0", "result": {"kind": "task", "id": "t", "status": {
             "state": "w", "status": {"state": "w", "status": {
                 "state": "w", "status": {"state": "w", "status": {
                     "state": "w", "status": {"state": "w", "status": {
                         "state": "w", "message": {
                             "kind": "message", "role": "system",
                             "parts": [{"kind": "text", "text": "hi"}]}}}}}}}}}},
         "input"),
    ]

    CLEAN = [
        ("normal inbound message",
         {"jsonrpc": "2.0", "method": "message/send", "params": {"message": {
             "role": "user",
             "parts": [{"kind": "text", "text": "summarize the report"}],
             "messageId": "m1"}}}, "input"),
        ("normal outbound agent message",
         {"params": {"message": {"role": "agent", "parts": [
             {"kind": "text", "text": "task delegated"}]}}}, "a2a"),
        ("normal data part",
         {"params": {"message": {"parts": [
             {"kind": "data", "data": {"invoiceId": "INV-1"}}]}}}, "input"),
        ("normal task with a nested status message and history",
         {"jsonrpc": "2.0", "result": {"kind": "task", "id": "task_a1b2c3",
          "contextId": "AGENT-SVC/checkout-flow", "status": {
              "state": "input-required", "message": {
                  "kind": "message", "role": "agent", "messageId": "m2",
                  "parts": [{"kind": "text", "text": "which account id?"}]}},
          "history": [{"kind": "message", "role": "user", "messageId": "m1",
                       "parts": [{"kind": "text", "text": "pull the invoice"}]}]}},
         "input"),
        ("normal artifact response",
         {"jsonrpc": "2.0", "result": {"kind": "task", "id": "t2",
          "status": {"state": "completed"}, "artifacts": [{
              "artifactId": "art-1", "name": "summary",
              "parts": [{"kind": "text", "text": "done"}]}]}}, "input"),
    ]

    def show(group, cases):
        print(f"\n===== {group} =====")
        for label, body, direction in cases:
            r = validator.validate(body, direction=direction)
            print(f"\n{label}  (direction={direction})")
            print(f"  body: {json.dumps(body)}")
            print(f"  score={r['score']}  signals={r['signals']}")
            for d in r["details"]:
                print(f"    - {d}")

    show("ANOMALIES (expect score > 0)", ANOMALIES)
    show("CLEAN (expect score 0)", CLEAN)

    # ------------------------------------------------------------------
    # A2AIdTracker scenarios
    # ------------------------------------------------------------------
    print("\n\n##### A2AIdTracker #####")

    def show_outbound(label, result, expectation):
        print(f"\n{label}")
        print(f"  expect: {expectation}")
        print(f"  score={result['score']}  signals={result['signals']}")
        for d in result["details"]:
            print(f"    - {d}")

    # SCENARIO 1 — legitimate flow (no flags)
    tracker = A2AIdTracker()
    tracker.record_issued({"result": {"taskId": "task-abc", "contextId": "ctx-xyz", "artifacts": []}})
    r1 = tracker.check_outbound({"params": {"message": {
        "taskId": "task-abc", "contextId": "ctx-xyz",
        "parts": [{"kind": "text", "text": "continue"}]}}})
    show_outbound("SCENARIO 1 — legitimate follow-up (known task + context)", r1, "score 0")

    # SCENARIO 2 — new task creation (first-reference exemption)
    r2 = tracker.check_outbound({"params": {"message": {
        "parts": [{"kind": "text", "text": "start a new task"}]}}})
    show_outbound("SCENARIO 2 — new task creation (no taskId)", r2, "score 0")

    # SCENARIO 3 — smuggling: references a task never issued
    fresh = A2AIdTracker()
    r3 = fresh.check_outbound({"params": {"message": {
        "taskId": "task-stolen-999",
        "parts": [{"kind": "text", "text": "continue task"}]}}})
    show_outbound("SCENARIO 3 — unissued taskId (no method => unverified)", r3,
                  "score > 0, task_id_smuggling or unverified_task_reference")

    # SCENARIO 4 — context smuggling
    fresh2 = A2AIdTracker()
    r4 = fresh2.check_outbound({"params": {"message": {
        "contextId": "ctx-stolen",
        "parts": [{"kind": "text", "text": "x"}]}}})
    show_outbound("SCENARIO 4 — unissued contextId", r4, "score > 0 (context_id_smuggling)")

    # SCENARIO 5 — TTL expiry: issued then aged out
    t = A2AIdTracker(ttl_seconds=0)
    t.record_issued({"result": {"taskId": "task-old"}})
    r5 = t.check_outbound({"params": {"message": {
        "taskId": "task-old", "parts": []}}})
    show_outbound("SCENARIO 5 — expired taskId", r5,
                  "flagged expired_task_reference (lower score), not clean")

    # Bonus: a follow-up SHAPE (method present) referencing an unissued task
    # asserts smuggling at the higher 0.45 score.
    fresh3 = A2AIdTracker()
    r6 = fresh3.check_outbound({"jsonrpc": "2.0", "method": "message/send", "params": {"message": {
        "taskId": "task-hijack", "parts": [{"kind": "text", "text": "resume"}]}}})
    show_outbound("BONUS — unissued taskId WITH method shape", r6,
                  "score 0.45 task_id_smuggling")
