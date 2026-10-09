"""The value-origin core's enums, value types and constants (§1.1-§1.3).

Every name here is part of the interface paid vendors. Changing one is a
breaking change to paid and is called out in the PR that makes it (§4.5).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, Mapping

from ._psl_data import PSL_SNAPSHOT_DATE as _PSL_SNAPSHOT_DATE


class Origin(str, enum.Enum):
    PRINCIPAL = "principal"
    TRUSTED_SOURCE = "trusted_source"
    UNTRUSTED_SOURCE = "untrusted_source"
    UNRESOLVED = "unresolved"


class Verdict(str, enum.Enum):
    AUTHORIZED = "authorized"          # every destination: principal | trusted_source
    UNAUTHORIZED = "unauthorized"      # >=1 destination: untrusted_source
    UNRESOLVED = "unresolved"          # none untrusted, >=1 unresolved
    NOT_EVALUATED = "not_evaluated"    # an absence state (see WireValue)


class WireValue(str, enum.Enum):
    """The complete value set of ``valueOrigin`` (§2). Fifteen, case-sensitive
    (INPUT_TRUNCATED added by the owner, A2 after M6: truncation is its own
    state, never a silent unresolved; ARGUMENT_BOUND and RESULT_TRUNCATED added
    by the owner's RULING 1+2 after M8: every bound is a visible state, and under
    ENFORCE a bounded value blocks -- NARROWED 2026-10-05: only RESULT_UNREAD
    blocks; the rest are visible states, and atom extraction finds what a bound
    used to hide. Two, not one: argument_bound is a fact about
    THIS CALL, result_truncated a fact about the LEDGER; RESULT_UNREAD under the
    same ruling, 2026-10-05: Q18's unread I/O-backed result is a bound too)."""

    PRINCIPAL = "principal"                                   # a DECLARED principal span
    PRINCIPAL_UNDECLARED_SPAN = "principal_undeclared_span"   # rests on C-1's default
    TRUSTED_SOURCE = "trusted_source"
    UNTRUSTED_SOURCE = "untrusted_source"
    UNRESOLVED = "unresolved"
    NO_DESTINATION = "no_destination"      # call carries no destination-shaped value
    NO_FLOW = "no_flow"                    # no flow context visible to this call
    LEDGER_ABSENT = "ledger_absent"        # flow visible, ledger not bound
    LEDGER_SATURATED = "ledger_saturated"  # ledger dropped an emission AND lookup missed
    INPUT_TRUNCATED = "input_truncated"    # principal input was capped AND lookup missed
    ARGUMENT_BOUND = "argument_bound"      # this call's argument walk hit a bound (C-8, V-11)
    RESULT_TRUNCATED = "result_truncated"  # a recorded tool result was cut AND lookup missed
    RESULT_UNREAD = "result_unread"        # an I/O-backed result was skipped unread (Q18) AND lookup missed
    EXTRACTION_INCOMPLETE = "extraction_incomplete"  # the atom pass hit its WORK budget (owner, 2026-10-06)
    WRITE_DROPPED = "write_dropped"        # a DESTINATION write the full ledger could not accept, AND lookup missed


class RowState(str, enum.Enum):
    """Exactly blank-canvas StageState's spellings."""

    DECIDED = "decided"
    RAN_EVIDENCE = "ran_evidence"
    RAN_CLEAN = "ran_clean"
    NOT_REACHED = "not_reached"
    NOT_APPLICABLE = "not_applicable"
    NOT_RECORDED = "not_recorded"


class Writer(str, enum.Enum):
    """Who wrote a span of principal-direction input."""

    PRINCIPAL = "principal"
    UNTRUSTED = "untrusted"


class Mode(str, enum.Enum):
    OFF = "off"          # no ledger writes, no evaluation, no wire field
    RECORD = "record"    # evaluate and report; never changes an action (DEFAULT)
    ENFORCE = "enforce"  # UNAUTHORIZED may block (see should_block)


class MatchKind(str, enum.Enum):
    """How a designation matches a read's source argument (V-17)."""

    ANY = "any"                # the tool itself is the source (e.g. order_lookup)
    URL_PREFIX = "url_prefix"  # scheme + exact host + port + segment-wise path prefix
    PATH_GLOB = "path_glob"    # fnmatchcase over a normalised absolute path
    EXACT = "exact"            # string equality after .strip()


class RecordOutcome(str, enum.Enum):
    RECORDED = "recorded"
    NO_LEDGER = "no_ledger"    # nothing bound; nothing written; NOT an error
    SATURATED = "saturated"    # ledger at cap; this emission (unit) dropped
    FAULT = "fault"            # internal exception caught, or a mis-split; nothing written


class UnresolvedReason(str, enum.Enum):
    """Why extraction produced a finding with no destination (ruling 3.3)."""

    WALK_BOUND = "walk_bound"        # the argument walk hit a bound (C-8, V-11)
    PARSE_FAILURE = "parse_failure"  # destination-shaped, but did not parse (V-4, 3.2)
    ATOM_BUDGET = "atom_budget"      # past a bound, the atom pass hit its WORK budget (2026-10-06)


# Wire strength, weakest first (ruling 2026-09-24). The wire is the weakest
# per-destination value, so an authorization that rests on the undeclared-span
# assumption is never hidden behind a stronger one on the same call.
WIRE_STRENGTH: Mapping[WireValue, int] = MappingProxyType({
    WireValue.UNTRUSTED_SOURCE: 0,
    WireValue.UNRESOLVED: 1,
    WireValue.PRINCIPAL_UNDECLARED_SPAN: 2,
    WireValue.TRUSTED_SOURCE: 3,
    WireValue.PRINCIPAL: 4,
})

# Weakest-first.
ORIGIN_STRENGTH: Mapping[Origin, int] = MappingProxyType({
    Origin.UNTRUSTED_SOURCE: 0,   # a positive finding of an unauthorized origin
    Origin.UNRESOLVED: 1,         # the ledger does not know
    Origin.TRUSTED_SOURCE: 2,
    Origin.PRINCIPAL: 3,
})


_DC = dict(frozen=True, slots=True, kw_only=True)


@dataclass(**_DC)
class Span:
    text: str
    writer: Writer


@dataclass(**_DC)
class Authority:
    """The normalised authority of a destination (§6 C-6). The ONLY
    representation of a destination the core exposes; the raw argument value
    is never stored on any returned object (C-12)."""

    scheme: Literal["mailto", "dns", "ip", "tel"]
    value: str

    def key(self) -> str:
        """``f"{scheme}:{value}"`` — the ONLY string ever digested."""
        return f"{self.scheme}:{self.value}"


@dataclass(**_DC)
class SourceDesignation:
    tool: str                              # exact tool name, case-sensitive
    match: MatchKind
    source_arg: str | None = None          # required unless match is ANY
    pattern: str | None = None             # required unless match is ANY
    key_args: tuple[str, ...] = ()         # arguments whose VALUES select what is read (C-3)
    label: str                             # operator-facing name; appears in row detail


@dataclass(**_DC)
class Finding:
    """One destination-shaped value found by the argument walk (ruling 3.3).

    ``destination`` is None iff extraction itself could not resolve it, and then
    ``reason`` says why; otherwise ``reason`` is None."""

    path: tuple[str | int, ...]
    destination: Authority | None
    reason: UnresolvedReason | None


@dataclass(**_DC)
class DestinationFinding:
    """A Finding after the ledger lookup."""

    path: tuple[str | int, ...]            # where in the arguments the value sat
    destination: Authority | None          # None iff unresolved by extraction (3.3)
    reason: UnresolvedReason | None        # set iff destination is None
    origin: Origin
    span_declared: bool | None             # PRINCIPAL / TRUSTED_SOURCE: declared basis? else None
    source_label: str | None               # designation.label when origin is TRUSTED_SOURCE


@dataclass(**_DC)
class CallVerdict:
    wire: WireValue
    verdict: Verdict
    row_state: RowState
    detail: str                                    # the normative row text, §3.4
    findings: tuple[DestinationFinding, ...]       # empty for every absence state
    truncated: bool                                # argument walk hit its bound (C-8)


# (No per-feature generation constant — ruling 2026-09-24; see C-21.)
LEDGER_MAX_ENTRIES: int = 10_000      # destinations (owner, 2026-10-06: kept)
LEDGER_MAX_NGRAMS: int = 65_536       # the principal's key n-grams, their OWN budget (approved)
# The atom pass past a bound is bounded by WORK, not position (owner, 2026-10-06):
# each scanned char costs 1, each extracted atom ATOM_COST. Per seam call. Hitting
# it is visible (extraction_incomplete), never a block.
ATOM_WORK_BUDGET: int = 500_000
# A result's EXAMINED pass (up to 64 leaves of 64 KiB) is budgeted by work too, with
# the same charging: 1/char, ATOM_COST/candidate examined. Spending it is visible
# (extraction_incomplete), never a block. The value is deliberate.
EXAMINED_WORK_BUDGET: int = 1_000_000
MAX_WALK_NODES: int = 65_536    # the EXAMINED walk's node budget: width cannot escape it (review)
ATOM_COST: int = 64
ATOM_CHUNK_CHARS: int = 16_384
MAX_ARG_LEAVES: int = 64      # same bound as open's strings_in(..., limit=64)
MAX_ARG_DEPTH: int = 6
MAX_LEAF_CHARS: int = 4_000   # same ceiling as url_parse.MAX_URL_CHARS
MAX_KEY_TOKENS: int = 4       # §6 C-3
MAX_INPUT_NGRAM_CHARS: int = 65_536   # key n-grams from the first 64 KiB of principal input;
                                      # destination atoms from ALL of it (owner, 2026-10-05)
MAX_RESULT_LEAF_CHARS: int = 65_536   # V-15: candidates from the first 64 KiB of a result leaf
PSL_SNAPSHOT_DATE: str = _PSL_SNAPSHOT_DATE
