"""xaidr.value_origin — where a tool call's destination came from.

The value-origin core, built ONCE here and vendored byte-identically by its
consumers at a pinned commit. Pure: no seams, no
I/O, no network, no dependency outside the standard library and this package
(tests/value_origin_conformance/test_self_contained.py enforces that).

``__all__`` IS the interface. Consumers import nothing else; changing it is a
breaking change and is called out as one in the PR that makes it.
Deliberately absent: any accessor that returns ledger contents, any way to write
an origin directly, any function that takes a correlation id — each is a
laundering or disclosure primitive.

The rulings this build follows beyond the doc are in docs/value-origin-rulings.md.
"""
from __future__ import annotations

from ._authority import authority_of
from ._designations import validate_designations, validate_mode
from ._evaluate import evaluate_call, row_text, should_block, verdict_of
from ._extract import extract_destinations
from ._ledger import (
    bind_fresh_ledger,
    bind_ledger,
    ledger_bound,
    record_principal_input,
    record_tool_result,
    unbind_ledger,
)
from ._types import (
    LEDGER_MAX_ENTRIES,
    MAX_ARG_DEPTH,
    MAX_ARG_LEAVES,
    MAX_KEY_TOKENS,
    MAX_LEAF_CHARS,
    ORIGIN_STRENGTH,
    PSL_SNAPSHOT_DATE,
    WIRE_STRENGTH,
    Authority,
    CallVerdict,
    DestinationFinding,
    Finding,
    MatchKind,
    Mode,
    Origin,
    RecordOutcome,
    RowState,
    SourceDesignation,
    Span,
    UnresolvedReason,
    Verdict,
    WireValue,
    Writer,
)

__all__ = [
    # enums
    "Origin", "WIRE_STRENGTH", "ORIGIN_STRENGTH", "Verdict", "WireValue", "RowState",
    "Writer", "Mode", "MatchKind", "RecordOutcome", "UnresolvedReason",
    # value types
    "Span", "Authority", "SourceDesignation", "Finding", "DestinationFinding",
    "CallVerdict",
    # constants
    "LEDGER_MAX_ENTRIES", "MAX_ARG_LEAVES", "MAX_ARG_DEPTH", "MAX_LEAF_CHARS",
    "MAX_KEY_TOKENS", "PSL_SNAPSHOT_DATE",
    # functions
    "validate_designations", "validate_mode", "bind_ledger", "bind_fresh_ledger",
    "unbind_ledger", "ledger_bound", "record_principal_input", "record_tool_result",
    "evaluate_call", "should_block", "authority_of", "extract_destinations",
    "verdict_of", "row_text",
]
