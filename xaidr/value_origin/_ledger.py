"""The flow-scoped ledger: binding, the write rule, key provenance, the cap.

THE STORE (§0 settled 1). One mutable ledger per flow, held in a ContextVar and
bound once at flow entry. Writes are mutations of that ledger, never a re-set of
the ContextVar, so sibling tasks that share a flow share its ledger (C-16 row N)
and concurrent flows that each bound their own do not (row P).

BINDING (ruling 3.1). A ledger is EXPLICIT or IMPLICIT (an internal attribute):

    bind_fresh_ledger()        explicit, unconditionally      begin_flow, extract_context
    bind_ledger()              explicit iff nothing is bound  (no caller: record_hop stopped
                                                              binding when ruling 3.1 changed,
                                                              2026-10-04); never rebinds
    record_principal_input()   nothing bound  -> fresh implicit
                               implicit bound -> REPLACED by a fresh implicit
                               explicit bound -> kept
    unbind_ledger()            clear_flow

An implicit ledger lives for one request. Replacing it at the next input scan
is the V-27 fix: a thread-reusing server that never begins a flow must not carry
user A's principal authority into user B's request.

WHAT IS STORED (C-12). ``HMAC-SHA256(k, authority.key())`` and the same for
principal n-grams, ``k`` 32 random bytes drawn once per process. Nothing here can
be reversed, and digests are not comparable across processes, by design.

THE WRITE RULE (C-18, ruled 2026-09-24), one compound operation per authority,
under the lock:

    existing                 new emission              result
    none                     any                       the new entry
    untrusted / trusted      principal                 principal (the raise)
    principal, undeclared    principal, declared       principal, declared
    principal                anything else             unchanged — principal persists
    untrusted                trusted                   unchanged — a read never raises
    trusted                  untrusted                 unchanged — nothing lowers

A principal emission is a candidate from a ``Writer.PRINCIPAL`` span of an input
whose scan was clean (``input_clean is True``, V-9). A flagged input records
every candidate untrusted and NO n-grams (ruling 3.5).

THE LOCK (C-15, D4). One ``threading.Lock`` per ledger. First-emission-wins is
check-then-set, which races under the GIL too, and the raise makes every write a
compare-then-set, so no single atomic dict operation implements it. Every
compound operation — each write unit, a read's trust decision together with its
write, and every lookup — runs under it. It is never held across host code: the
result is normalised (which may call ``model_dump``) and every candidate is
extracted BEFORE it is taken, and logging happens after it is released. The
core has no ``async`` function, so it is never held across an ``await``. After
``fork()`` a ledger from another pid counts as not bound, checked BEFORE the
lock is touched, so a child never waits on a lock held mid-write in the parent.

THE CAP (C-14, V-16). 10,000 digests per ledger, n-grams included. Each write
unit is all-or-none; a unit that would exceed the cap is dropped whole and the
ledger becomes SATURATED — "saturated" means a drop has occurred, not that the
ledger is full. ``record_principal_input`` writes two units in order, its
destinations and then its n-grams (V-16(d), settled 2026-09-24), so a long
prompt's n-grams can be dropped without dropping the principal's addresses.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import threading
from contextvars import ContextVar
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ._authority import classify_value, prose_candidates
from ._designations import source_matches
from ._extract import argument_value, key_authority, key_ngram, result_leaves, span_ngrams
from ._types import (
    LEDGER_MAX_ENTRIES,
    Authority,
    Origin,
    RecordOutcome,
    SourceDesignation,
    Span,
    Writer,
)

_log = logging.getLogger("xaidr.value_origin")

_KEY = secrets.token_bytes(32)

# The lock factory, a module attribute so the D4 proof can remove the lock
# from the REAL core (tests/value_origin_conformance, R4).
_new_lock = threading.Lock

Entry = Tuple[Origin, bool, Optional[str]]      # (origin, span_declared, source_label)


def _digest_authority(a: Authority) -> bytes:
    return hmac.new(_KEY, b"a\x00" + a.key().encode("utf-8", "surrogatepass"),
                    hashlib.sha256).digest()


def _digest_ngram(g: str) -> bytes:
    return hmac.new(_KEY, b"n\x00" + g.encode("utf-8", "surrogatepass"),
                    hashlib.sha256).digest()


class _Ledger:
    __slots__ = ("lock", "pid", "explicit", "entries", "ngrams", "saturated", "sat_logged")

    def __init__(self, *, explicit: bool) -> None:
        self.lock = _new_lock()
        self.pid = os.getpid()
        self.explicit = explicit
        self.entries: Dict[bytes, Entry] = {}
        self.ngrams: Dict[bytes, bool] = {}
        self.saturated = False
        self.sat_logged = False

    def __repr__(self) -> str:                  # discloses nothing (C-12)
        return (f"<value-origin ledger {'explicit' if self.explicit else 'implicit'} "
                f"{len(self.entries) + len(self.ngrams)} digests>")


_LEDGER: ContextVar[Optional[_Ledger]] = ContextVar("xaidr_value_origin_ledger", default=None)


def _current() -> Optional[_Ledger]:
    lg = _LEDGER.get()
    if lg is None or lg.pid != os.getpid():     # V-32: another pid's ledger is not bound
        return None
    return lg


# ── binding (ruling 3.1) ─────────────────────────────────────────────────────
def bind_ledger() -> None:
    """Bind a new empty EXPLICIT ledger iff none is bound. Never rebinds."""
    try:
        if _current() is None:
            _LEDGER.set(_Ledger(explicit=True))
    except Exception:
        _log.exception("value origin: bind_ledger faulted")


def bind_fresh_ledger() -> None:
    """Bind a new empty EXPLICIT ledger unconditionally. For exactly two
    callers: ``begin_flow()`` and ``extract_context()`` — an inbound flow must
    not inherit the caller-process's ledger."""
    try:
        _LEDGER.set(_Ledger(explicit=True))
    except Exception:
        _log.exception("value origin: bind_fresh_ledger faulted")


def unbind_ledger() -> None:
    """For ``clear_flow()`` only."""
    try:
        _LEDGER.set(None)
    except Exception:
        _log.exception("value origin: unbind_ledger faulted")


def ledger_bound() -> bool:
    try:
        return _current() is not None
    except Exception:
        return False


def _bind_for_input() -> _Ledger:
    lg = _current()
    if lg is not None and lg.explicit:
        return lg
    lg = _Ledger(explicit=False)
    _LEDGER.set(lg)
    return lg


# ── the write rule (C-18) ────────────────────────────────────────────────────
def _merge(old: Optional[Entry], new: Entry) -> Entry:
    """The C-18 table, for one authority. Returns the entry to store."""
    if old is None:
        return new
    if old[0] is Origin.PRINCIPAL:
        if new[0] is Origin.PRINCIPAL and new[1] and not old[1]:
            return (Origin.PRINCIPAL, True, None)      # the assumption is discharged
        return old                                     # principal persists
    if new[0] is Origin.PRINCIPAL:
        return new                                     # the principal raise
    return old                                         # a read never raises; nothing lowers


def _merge_ngram(old: Optional[bool], declared: bool) -> bool:
    if old is None:
        return declared
    return old or declared                             # a declared mention discharges


def _apply_unit(lg: _Ledger, entries: List[Tuple[bytes, Entry]],
                ngrams: List[Tuple[bytes, bool]]) -> bool:
    """All-or-none write of one unit. Caller holds the lock. False = dropped."""
    new_digests = {d for d, _ in entries if d not in lg.entries}
    new_digests |= {d for d, _ in ngrams if d not in lg.ngrams}
    if len(lg.entries) + len(lg.ngrams) + len(new_digests) > LEDGER_MAX_ENTRIES:
        lg.saturated = True
        return False
    for d, e in entries:
        lg.entries[d] = _merge(lg.entries.get(d), e)
    for d, decl in ngrams:
        lg.ngrams[d] = _merge_ngram(lg.ngrams.get(d), decl)
    return True


def _log_saturation_once(lg: _Ledger) -> None:
    """Called OUTSIDE the lock."""
    if lg.saturated and not lg.sat_logged:
        lg.sat_logged = True
        _log.warning("value origin: this flow's ledger reached %d digests and "
                     "dropped an emission; unmatched destinations now report "
                     "ledger_saturated, not unresolved", LEDGER_MAX_ENTRIES)


# ── principal input ──────────────────────────────────────────────────────────
def _principal_clean(input_clean: Optional[bool]) -> bool:
    """V-9: only an input whose pre-mode scan verdict was ``allowed`` donates
    principal authority. ``False`` (flagged/blocked/approval) and ``None`` (no
    verdict earned) do not."""
    return input_clean is True


def record_principal_input(text: str, spans: Sequence[Span] | None = None, *,
                           input_clean: bool | None) -> RecordOutcome:
    """Record every destination candidate in a principal-direction input.

    Binds per ruling 3.1 FIRST (a new input is a new request even when its
    recording then faults). ``spans=None`` means no span structure was declared:
    the whole text is one PRINCIPAL span whose entries carry
    ``span_declared=False`` (C-1). Given spans must concatenate to ``text``
    exactly, else nothing is recorded and FAULT is returned. Unless
    ``input_clean is True``, every candidate is UNTRUSTED_SOURCE and no n-gram is
    recorded (V-9, ruling 3.5). Called AFTER the input scan.
    """
    try:
        lg = _bind_for_input()
        if not isinstance(text, str):
            return RecordOutcome.FAULT
        if spans is None:
            span_list = [(text, Writer.PRINCIPAL)]
            declared = False
        else:
            span_list = []
            for s in spans:
                if (not isinstance(s, Span) or not isinstance(s.text, str)
                        or not isinstance(s.writer, Writer)):
                    return RecordOutcome.FAULT
                span_list.append((s.text, s.writer))
            if "".join(t for t, _ in span_list) != text:
                return RecordOutcome.FAULT     # a mis-split is not repaired by guessing
            declared = True
        clean = _principal_clean(input_clean)
        dests: List[Tuple[bytes, Entry]] = []
        grams: List[Tuple[bytes, bool]] = []
        for span_text, writer in span_list:            # left to right (V-24)
            is_principal = writer is Writer.PRINCIPAL and clean
            origin = Origin.PRINCIPAL if is_principal else Origin.UNTRUSTED_SOURCE
            for _, a in prose_candidates(span_text):   # per span: no straddling
                dests.append((_digest_authority(a), (origin, declared, None)))
            if is_principal:
                for g in span_ngrams(span_text):
                    grams.append((_digest_ngram(g), declared))
        if lg.pid != os.getpid():
            return RecordOutcome.NO_LEDGER
        with lg.lock:
            ok_dest = _apply_unit(lg, dests, [])
            ok_gram = _apply_unit(lg, [], grams) if grams else True
        _log_saturation_once(lg)
        return RecordOutcome.RECORDED if (ok_dest and ok_gram) else RecordOutcome.SATURATED
    except Exception:
        _log.exception("value origin: record_principal_input faulted")
        return RecordOutcome.FAULT


# ── tool results (C-2, C-3, C-3a, V-8, V-15) ─────────────────────────────────
class _KeyPlan:
    __slots__ = ("present", "ngram", "authority")

    def __init__(self, present: bool, value: Any) -> None:
        self.present = present
        g = key_ngram(value) if present else None
        a = key_authority(value) if present else None
        self.ngram = _digest_ngram(g) if g is not None else None
        self.authority = _digest_authority(a) if a is not None else None


def _key_basis(lg: _Ledger, k: _KeyPlan) -> Optional[bool]:
    """None if the key is unauthorized; else whether a DECLARED basis
    authorizes it (C-3a). Caller holds the lock."""
    if not k.present:
        return None                                    # V-8(b)
    bases = []
    if k.ngram is not None and k.ngram in lg.ngrams:
        bases.append(lg.ngrams[k.ngram])
    if k.authority is not None:
        e = lg.entries.get(k.authority)
        if e is not None and e[0] in (Origin.PRINCIPAL, Origin.TRUSTED_SOURCE):
            bases.append(e[1])
    return None if not bases else any(bases)


def _read_declared(bases: List[bool]) -> bool:
    """C-3a: a trusted read is only as declared as its weakest key."""
    return all(bases)


def _keys_authorized(lg: _Ledger, keys: List[_KeyPlan]) -> Tuple[bool, bool]:
    """(every key authorized, declared). Caller holds the lock."""
    bases = []
    for k in keys:
        b = _key_basis(lg, k)
        if b is None:
            return False, True
        bases.append(b)
    return True, _read_declared(bases)


def _read_trust(lg: _Ledger, plans: List[Tuple[SourceDesignation, List[_KeyPlan]]],
                result_blocked: Optional[bool]) -> Entry:
    """The origin of this read's emissions. TRUSTED iff a designation matches
    AND every one of its key args is authorized AND the result scan ran and did
    not block (C-3). Several matching designations: ANY that authorizes; the
    first such in the operator's order supplies the label (V-8f)."""
    if result_blocked is not False:
        return (Origin.UNTRUSTED_SOURCE, True, None)
    for d, keys in plans:
        ok, declared = _keys_authorized(lg, keys)
        if ok:
            return (Origin.TRUSTED_SOURCE, declared, d.label)
    return (Origin.UNTRUSTED_SOURCE, True, None)


def result_authorities(result: Any) -> List[Authority]:
    """Every destination candidate in a raw result: each leaf tried whole, and
    scanned as prose (C-7). May run host code (V-15)."""
    out: List[Authority] = []
    seen = set()
    for leaf in result_leaves(result):
        found: List[Authority] = []
        whole = classify_value(leaf, arg_mode=False)
        if isinstance(whole, Authority):
            found.append(whole)
        elif isinstance(whole, list):
            found.extend(whole)
        found.extend(a for _, a in prose_candidates(leaf))
        for a in found:
            if a not in seen:
                seen.add(a)
                out.append(a)
    return out


def record_tool_result(tool_name: str, arguments: Mapping[str, object] | None,
                       result: object, *, designations: Sequence[SourceDesignation],
                       result_blocked: bool | None) -> RecordOutcome:
    """Record every destination candidate in a tool's RAW result at the origin
    C-2/C-3 give it. ``result_blocked``: False = scanned as ``tool_result`` and
    neither blocked nor approval_required (pre-mode); True = it was; None = not
    scanned, which can never produce a trusted source. Does not bind."""
    try:
        lg = _current()
        if lg is None:
            return RecordOutcome.NO_LEDGER
        # Everything that can run host code, BEFORE the lock (C-15).
        auths = result_authorities(result)
        plans = []
        for d in designations:
            if source_matches(d, tool_name, arguments):
                keys = [_KeyPlan(*argument_value(arguments, k)) for k in d.key_args]
                plans.append((d, keys))
        digests = [_digest_authority(a) for a in auths]
        if lg.pid != os.getpid():
            return RecordOutcome.NO_LEDGER
        with lg.lock:
            entry = _read_trust(lg, plans, result_blocked)
            ok = _apply_unit(lg, [(d, entry) for d in digests], [])
        _log_saturation_once(lg)
        return RecordOutcome.RECORDED if ok else RecordOutcome.SATURATED
    except Exception:
        _log.exception("value origin: record_tool_result faulted")
        return RecordOutcome.FAULT


# ── lookup (for evaluate_call) ───────────────────────────────────────────────
def lookup(lg: _Ledger, auths: List[Authority]) -> Tuple[List[Optional[Entry]], bool]:
    """Entries for ``auths`` in one lock acquisition, plus whether the ledger
    is saturated — a read racing a multi-entry write sees all or none of it."""
    digests = [_digest_authority(a) for a in auths]
    with lg.lock:
        return [lg.entries.get(d) for d in digests], lg.saturated
