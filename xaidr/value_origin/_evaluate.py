"""The call verdict, its wire value and its row (§1.4 evaluate_call, verdict_of,
should_block, row_text; §3.4)."""
from __future__ import annotations

import logging
from typing import List, Mapping, Optional, Tuple

from . import _ledger
from ._extract import extract_destinations
from ._types import (
    WIRE_STRENGTH,
    CallVerdict,
    DestinationFinding,
    Mode,
    Origin,
    RowState,
    Verdict,
    WireValue,
)

_log = logging.getLogger("xaidr.value_origin")

_VERDICT = {
    WireValue.PRINCIPAL: Verdict.AUTHORIZED,
    WireValue.PRINCIPAL_UNDECLARED_SPAN: Verdict.AUTHORIZED,
    WireValue.TRUSTED_SOURCE: Verdict.AUTHORIZED,
    WireValue.UNTRUSTED_SOURCE: Verdict.UNAUTHORIZED,
    WireValue.UNRESOLVED: Verdict.UNRESOLVED,
    WireValue.NO_DESTINATION: Verdict.NOT_EVALUATED,
    WireValue.NO_FLOW: Verdict.NOT_EVALUATED,
    WireValue.LEDGER_ABSENT: Verdict.NOT_EVALUATED,
    WireValue.LEDGER_SATURATED: Verdict.NOT_EVALUATED,
    WireValue.INPUT_TRUNCATED: Verdict.NOT_EVALUATED,
}


def verdict_of(wire: WireValue) -> Verdict:
    """Total over the ten wire values (V-3; input_truncated added after A2 M6). ``CallVerdict.verdict`` is always
    ``verdict_of(wire)``; paid's L2 driver and the Brain derive the verdict
    from the wire value only through this function. Never raises: a string
    outside the nine is NOT_EVALUATED, matching ``row_text``'s not_recorded row
    for an unrecognised value."""
    try:
        return _VERDICT[WireValue(wire)]
    except (ValueError, KeyError, TypeError):
        return Verdict.NOT_EVALUATED


def should_block(verdict: CallVerdict, *, mode: Mode) -> bool:
    """True iff ``mode is Mode.ENFORCE`` and the verdict is UNAUTHORIZED.
    UNRESOLVED never blocks. The only effect value origin has on an action."""
    try:
        return mode is Mode.ENFORCE and verdict.verdict is Verdict.UNAUTHORIZED
    except Exception:
        return False


# §3.4, normative. The Brain's src/value-origin.ts and blank-canvas's waterfall
# are checked against a JSON export of this table (row_text.json).
_ROWS = {
    "no_flow": (RowState.NOT_RECORDED,
                "Intent: not evaluated — no flow context was visible to this call "
                "(none was started, or it did not reach this thread)."),
    "ledger_absent": (RowState.NOT_RECORDED,
                      "Intent: not evaluated — a flow was active but its provenance "
                      "ledger was never bound; the sensor's flow entry is not wired."),
    "ledger_saturated": (RowState.NOT_RECORDED,
                         "Intent: not evaluated — this flow's ledger was full; an "
                         "unmatched destination cannot be called novel."),
    "input_truncated": (RowState.NOT_RECORDED,
                        "Intent: not evaluated — the principal's input was longer than "
                        "value origin records; a destination past that point cannot be "
                        "traced."),
    "no_destination": (RowState.NOT_APPLICABLE,
                       "Intent: not applicable — this call carries no "
                       "destination-shaped value."),
    "principal_undeclared_span": (
        RowState.RAN_CLEAN,
        "Intent: destination traces to the principal's input — assuming the whole "
        "input was the principal's own; no span structure was declared, so quoted "
        "content would read the same."),
    "unresolved": (RowState.RAN_EVIDENCE,
                   "Intent: destination origin unresolved — it traces to no "
                   "recorded source."),
    "untrusted_source": (RowState.RAN_EVIDENCE,
                         "Intent: destination traces to an untrusted source."),
    "trusted_source": (RowState.RAN_CLEAN,
                       "Intent: destination traces to a designated trusted source."),
    "principal": (RowState.RAN_CLEAN,
                  "Intent: destination traces to the principal's own input "
                  "(a declared principal span)."),
}
_NOT_TOOL_CALL = (RowState.NOT_APPLICABLE,
                  "Intent: not applicable — value origin is evaluated on tool calls only.")
_NOT_REPORTED = (RowState.NOT_RECORDED,
                 "Intent: not recorded — this sensor did not report value origin.")
_UNRECOGNISED_MAX = 64


def row_text(wire: str | None, scan_mode: str | None) -> tuple[RowState, str]:
    """The normative §3.4 mapping, including ``None`` (the field is absent) and
    any other string (V-29: truncated to 64 chars FIRST, then backticks escaped,
    so an escape is never cut in half)."""
    if scan_mode != "tool_call":
        return _NOT_TOOL_CALL
    if wire is None:
        return _NOT_REPORTED
    w = wire.value if isinstance(wire, WireValue) else wire
    if not isinstance(w, str):
        w = str(w)
    if w in _ROWS:
        return _ROWS[w]
    shown = w[:_UNRECOGNISED_MAX].replace("`", "\\`")
    return (RowState.NOT_RECORDED, f"Intent: not recorded — unrecognised value `{shown}`.")


def _verdict(wire: WireValue, findings: Tuple[DestinationFinding, ...],
             truncated: bool) -> CallVerdict:
    state, detail = row_text(wire.value, "tool_call")
    return CallVerdict(wire=wire, verdict=verdict_of(wire), row_state=state,
                       detail=detail, findings=findings, truncated=truncated)


def _finding_wire(f: DestinationFinding) -> WireValue:
    if f.origin is Origin.PRINCIPAL:
        return WireValue.PRINCIPAL if f.span_declared else WireValue.PRINCIPAL_UNDECLARED_SPAN
    if f.origin is Origin.TRUSTED_SOURCE:
        # C-3a: a trusted read authorized only by an undeclared span is undeclared.
        return (WireValue.TRUSTED_SOURCE if f.span_declared
                else WireValue.PRINCIPAL_UNDECLARED_SPAN)
    if f.origin is Origin.UNTRUSTED_SOURCE:
        return WireValue.UNTRUSTED_SOURCE
    return WireValue.UNRESOLVED


def evaluate_call(tool_name: str, arguments: Mapping[str, object] | None, *,
                  flow_active: bool) -> CallVerdict | None:
    """Pure with respect to the ledger — reads only, never writes (C-10).
    ``flow_active`` is the host's own ``is_flow_active()``. Returns None ONLY on
    an internal fault; the seam then omits the wire field.

    Resolution order, first match wins:
      1. no ledger bound, not flow_active  -> NO_FLOW
      2. no ledger bound, flow_active      -> LEDGER_ABSENT
      3. no finding and walk not truncated -> NO_DESTINATION
      4. each finding's origin is the ledger's entry; a miss is UNRESOLVED
         (LEDGER_SATURATED if the ledger has dropped an emission); a finding
         with no destination (walk bound / parse failure) is UNRESOLVED
      5. wire = the weakest per-finding wire by WIRE_STRENGTH, except that a
         saturated miss makes it LEDGER_SATURATED unless some destination is
         UNTRUSTED_SOURCE (a positive finding outranks a blind spot)
    """
    try:
        lg = _ledger._current()
        if lg is None:
            return _verdict(WireValue.LEDGER_ABSENT if flow_active else WireValue.NO_FLOW,
                            (), False)
        found, truncated = extract_destinations(arguments)
        if not found:
            return _verdict(WireValue.NO_DESTINATION, (), truncated)
        auths = [f.destination for f in found if f.destination is not None]
        entries, saturated, input_truncated = _ledger.lookup(lg, auths)
        it = iter(entries)
        out: List[DestinationFinding] = []
        saturated_miss = False
        truncated_miss = False
        for f in found:
            if f.destination is None:
                out.append(DestinationFinding(path=f.path, destination=None, reason=f.reason,
                                              origin=Origin.UNRESOLVED, span_declared=None,
                                              source_label=None))
                continue
            e = next(it)
            if e is None:
                saturated_miss = saturated_miss or saturated
                truncated_miss = truncated_miss or input_truncated
                out.append(DestinationFinding(path=f.path, destination=f.destination,
                                              reason=None, origin=Origin.UNRESOLVED,
                                              span_declared=None, source_label=None))
                continue
            origin, declared, label = e
            out.append(DestinationFinding(
                path=f.path, destination=f.destination, reason=None, origin=origin,
                span_declared=declared if origin in (Origin.PRINCIPAL,
                                                     Origin.TRUSTED_SOURCE) else None,
                source_label=label if origin is Origin.TRUSTED_SOURCE else None))
        findings = tuple(out)
        wires = [_finding_wire(f) for f in findings]
        wire = min(wires, key=WIRE_STRENGTH.__getitem__)
        if truncated_miss and WireValue.UNTRUSTED_SOURCE not in wires:
            wire = WireValue.INPUT_TRUNCATED      # owner, after M6: never a silent unresolved
        elif saturated_miss and WireValue.UNTRUSTED_SOURCE not in wires:
            wire = WireValue.LEDGER_SATURATED
        return _verdict(wire, findings, truncated)
    except Exception:
        _log.exception("value origin: evaluate_call faulted")
        return None
