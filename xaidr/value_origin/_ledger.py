"""The flow-scoped ledger: binding, the write rule, key provenance, the cap.

THE STORE. One mutable ledger per flow, held in a ContextVar and
bound once at flow entry. Writes are mutations of that ledger, never a re-set of
the ContextVar, so sibling tasks that share a flow share its ledger,
and concurrent flows that each bound their own do not.

BINDING (ruling 3.1). A ledger is EXPLICIT or IMPLICIT (an internal attribute):

    bind_fresh_ledger()        explicit, unconditionally      begin_flow, extract_context
    bind_ledger()              explicit iff nothing is bound  (no caller: record_hop stopped
                                                              binding when ruling 3.1 changed,
                                                              2026-10-04); never rebinds
    record_principal_input()   nothing bound  -> fresh implicit
                               implicit bound -> REPLACED by a fresh implicit
                               explicit bound -> kept
    unbind_ledger()            clear_flow
    ledger_get()/ledger_set()  xaidr.flow(): saved on enter, put back on exit (return OR
                               raise), so a scope ends its ledger and hands back the one
                               bound before it (owner, D1, 2026-10-08)

THE REQUEST (ruling 4, 2026-10-21). A ledger belongs to the request it was bound
in, and ends with it. ``request_enter()`` opens a request record in this context
and hides any ledger no live request owns; every ledger bound while the record is
live is registered with it; ``request_exit()`` CLOSES each of them and puts back
what was there before. A closed ledger reads as not bound everywhere, including
in a context copied from the request (a worker task, an executor job), so no
later request reads its authority. A request opened inside a live one, or inside
a host's own flow, joins it and changes nothing. The record holds no tier state:
the provenance chain, tiers and inbound mark are untouched.

    sensor's executor seam     each ThreadPoolExecutor work item is a request
    framework entry hooks      each CrewAI kickoff and Agents SDK run is a request
    xaidr.request_scope()      the host marks one request
    xaidr.flow()               a fresh scope is a request too

An implicit ledger lives for one request. Replacing it at the next input scan
keeps authority per request too.

WHAT IS STORED. ``HMAC-SHA256(k, authority.key())`` and the same for
principal n-grams, ``k`` 32 random bytes drawn once per process. Nothing here can
be reversed, and digests are not comparable across processes, by design.

THE WRITE RULE, one compound operation per authority,
under the lock:

    existing                 new emission              result
    none                     any                       the new entry
    untrusted / trusted      principal                 principal (the raise)
    principal, undeclared    principal, declared       principal, declared
    principal                anything else             unchanged — principal persists
    untrusted                trusted                   unchanged — a read never raises
    trusted                  untrusted                 unchanged — nothing lowers

A principal emission is a candidate from a ``Writer.PRINCIPAL`` span of an input
whose scan was clean (``input_clean is True``). A flagged input records
every candidate untrusted and NO n-grams (ruling 3.5).

THE LOCK. One ``threading.Lock`` per ledger. First-emission-wins is
check-then-set, which races under the GIL too, and the raise makes every write a
compare-then-set, so no single atomic dict operation implements it. Every
compound operation — each write unit, a read's trust decision together with its
write, and every lookup — runs under it. It is never held across host code: the
result is normalised (which may call ``model_dump``) and every candidate is
extracted BEFORE it is taken, and logging happens after it is released. The
core has no ``async`` function, so it is never held across an ``await``. After
``fork()`` a ledger from another pid counts as not bound, checked BEFORE the
lock is touched, so a child never waits on a lock held mid-write in the parent.

THE CAP. 10,000 digests per ledger, n-grams included. Each write
unit is all-or-none; a unit that would exceed the cap is dropped whole and the
ledger becomes SATURATED — "saturated" means a drop has occurred, not that the
ledger is full. ``record_principal_input`` writes two units in order, its
destinations and then its n-grams, so a long
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
from ._extract import (AtomBudget, argument_value, budgeted_atoms, key_authority, key_ngram,
                       result_leaves_bounded, span_ngrams)
from ._types import (
    LEDGER_MAX_ENTRIES,
    LEDGER_MAX_NGRAMS,
    ATOM_COST,
    EXAMINED_WORK_BUDGET,
    MAX_INPUT_NGRAM_CHARS,
    Authority,
    Origin,
    RecordOutcome,
    SourceDesignation,
    Span,
    Writer,
)

_log = logging.getLogger("xaidr.value_origin")

_KEY = secrets.token_bytes(32)

# The lock factory, a module attribute so the race test can remove the lock
# from the REAL core (tests/value_origin_conformance/test_race.py).
_new_lock = threading.Lock

Entry = Tuple[Origin, bool, Optional[str]]      # (origin, span_declared, source_label)


def _digest_authority(a: Authority) -> bytes:
    return hmac.new(_KEY, b"a\x00" + a.key().encode("utf-8", "surrogatepass"),
                    hashlib.sha256).digest()


def _digest_ngram(g: str) -> bytes:
    return hmac.new(_KEY, b"n\x00" + g.encode("utf-8", "surrogatepass"),
                    hashlib.sha256).digest()


class _Ledger:
    __slots__ = ("lock", "pid", "explicit", "entries", "ngrams", "saturated", "sat_logged",
                 "input_truncated", "result_truncated", "result_unread", "atoms_incomplete",
                 "dests_dropped", "closed")

    def __init__(self, *, explicit: bool) -> None:
        self.lock = _new_lock()
        self.pid = os.getpid()
        self.explicit = explicit
        self.entries: Dict[bytes, Entry] = {}
        self.ngrams: Dict[bytes, bool] = {}
        self.saturated = False
        self.input_truncated = False     # a principal input exceeded the 64 KiB key n-gram window
        self.result_truncated = False    # a tool result hit a bound before recording (RULING 1+2)
        self.result_unread = False       # an I/O-backed result was skipped unread (Q18)
        self.atoms_incomplete = False    # an atom pass hit its WORK budget (2026-10-06)
        self.dests_dropped = False       # a DESTINATION write was dropped: blocks (owner, 2026-10-06)
        self.sat_logged = False
        self.closed = False              # its request ended: read as not bound, everywhere

    def __repr__(self) -> str:                  # discloses nothing
        return (f"<value-origin ledger {'explicit' if self.explicit else 'implicit'} "
                f"{len(self.entries) + len(self.ngrams)} digests>")


_LEDGER: ContextVar[Optional[_Ledger]] = ContextVar("xaidr_value_origin_ledger", default=None)


def _current() -> Optional[_Ledger]:
    lg = _LEDGER.get()
    if lg is None or lg.closed or lg.pid != os.getpid():   # ended, or another pid's
        return None
    return lg


# ── the request (ruling 4) ───────────────────────────────────────────────────
class _Request:
    __slots__ = ("live", "ledgers", "saved_ledger", "saved_request")

    def __init__(self, saved_ledger, saved_request) -> None:
        self.live = True
        self.ledgers: List[_Ledger] = []
        self.saved_ledger = saved_ledger
        self.saved_request = saved_request


_REQUEST: ContextVar[Optional[_Request]] = ContextVar("xaidr_value_origin_request", default=None)


def _bound(lg: _Ledger) -> _Ledger:
    """Bind ``lg`` and register it with this context's live request, if any."""
    _LEDGER.set(lg)
    rec = _REQUEST.get()
    if rec is not None and rec.live:
        rec.ledgers.append(lg)
    return lg


def request_enter() -> Optional[_Request]:
    """Open a request in this context. Returns its record, or None when it JOINS:
    inside a live request, or inside a host's own flow (a live explicit ledger no
    request owns). Otherwise any ledger bound here belongs to no live request in
    this context, so it is hidden for the request's duration. Never raises."""
    try:
        rec = _REQUEST.get()
        if rec is not None and rec.live:
            return None
        lg = _LEDGER.get()
        if lg is not None and lg.explicit and not lg.closed and lg.pid == os.getpid():
            return None
        new = _Request(lg, rec)
        _REQUEST.set(new)
        _LEDGER.set(None)
        return new
    except Exception:
        _log.exception("value origin: opening a request faulted")
        return None


def request_exit(rec: Optional[_Request]) -> None:
    """End ``rec``: close every ledger bound in it and, in the context it was
    opened in, put back what was there before. Never raises."""
    if rec is None:
        return
    try:
        # A request opened inside this one and still open ends with it: no record
        # of this request can outlive it into the next one in this context.
        inner, chain = _REQUEST.get(), []
        while inner is not None and inner is not rec and len(chain) < 1024:
            chain.append(inner)
            inner = inner.saved_request
        found = inner is rec
        for r in (chain if found else []) + [rec]:
            r.live = False
            for lg in r.ledgers:
                lg.closed = True
            r.ledgers = []
        if found:
            _LEDGER.set(rec.saved_ledger)
            _REQUEST.set(rec.saved_request)
    except Exception:
        _log.exception("value origin: ending a request faulted")


# ── binding (ruling 3.1) ─────────────────────────────────────────────────────
def bind_ledger() -> None:
    """Bind a new empty EXPLICIT ledger iff none is bound. Never rebinds."""
    try:
        if _current() is None:
            _bound(_Ledger(explicit=True))
    except Exception:
        _log.exception("value origin: bind_ledger faulted")


def bind_fresh_ledger() -> None:
    """Bind a new empty EXPLICIT ledger unconditionally. For exactly two
    callers: ``begin_flow()`` and ``extract_context()`` — an inbound flow must
    not inherit the caller-process's ledger."""
    try:
        _bound(_Ledger(explicit=True))
    except Exception:
        _log.exception("value origin: bind_fresh_ledger faulted")


def unbind_ledger() -> None:
    """For ``clear_flow()`` only."""
    try:
        _LEDGER.set(None)
    except Exception:
        _log.exception("value origin: unbind_ledger faulted")


def ledger_get():
    """For ``xaidr.flow()`` only: the bound ledger object as it is, or None. Raw,
    so a scope saves and puts back exactly what was there (V-32's pid check is
    applied where the ledger is READ, not here)."""
    return _LEDGER.get()


def ledger_set(ledger) -> None:
    """For ``xaidr.flow()`` only: put back what ``ledger_get`` saved."""
    _LEDGER.set(ledger)


def ledger_bound() -> bool:
    try:
        return _current() is not None
    except Exception:
        return False


def _bind_for_input() -> _Ledger:
    lg = _current()
    if lg is not None and lg.explicit:
        return lg
    return _bound(_Ledger(explicit=False))


# ── the write rule ───────────────────────────────────────────────────────────
def _merge(old: Optional[Entry], new: Entry) -> Entry:
    """The write-rule table (module docstring), for one authority. Returns the entry to store."""
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
    # Separate budgets (owner, approved 2026-10-06): key n-grams can no longer
    # starve destination recording -- a 17 KB prompt filled the shared 10,000.
    new_e = {d for d, _ in entries if d not in lg.entries}
    new_g = {d for d, _ in ngrams if d not in lg.ngrams}
    over_e = len(lg.entries) + len(new_e) > LEDGER_MAX_ENTRIES
    if over_e or len(lg.ngrams) + len(new_g) > LEDGER_MAX_NGRAMS:
        lg.saturated = True
        if over_e:
            # Owner, 2026-10-06: a write the ledger could not accept means the
            # system does not know what it just saw -- unexaminable, not benign.
            lg.dests_dropped = True
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
        _log.warning("value origin: this flow's ledger is FULL (%d destinations or %d "
                     "key n-grams) and dropped a write. A dropped DESTINATION write means "
                     "value origin does not know what that input or result named: an "
                     "unmatched destination now reports write_dropped, which BLOCKS under "
                     "ENFORCE (owner, 2026-10-06); a dropped key-n-gram write reports "
                     "ledger_saturated, which does not.", LEDGER_MAX_ENTRIES,
                     LEDGER_MAX_NGRAMS)


# ── principal input ──────────────────────────────────────────────────────────
def _principal_clean(input_clean: Optional[bool]) -> bool:
    """Only an input whose pre-mode scan verdict was ``allowed`` donates
    principal authority. ``False`` (flagged/blocked/approval) and ``None`` (no
    verdict earned) do not."""
    return input_clean is True


def _lost() -> RecordOutcome:
    """A write the ledger did not accept because recording FAULTED (or refused a
    mis-split): the system does not know what it just saw, so a later miss reads
    write_dropped and blocks (owner, ruling 4, 2026-10-06; the silent-failure and
    milestone reviews: a faulted write set no flag and laundered like a full one)."""
    try:
        lg = _current()
        if lg is not None:
            lg.dests_dropped = True
    except Exception:
        _log.exception("value origin: could not mark a lost write")
    return RecordOutcome.FAULT


def record_principal_input(text: str, spans: Sequence[Span] | None = None, *,
                           input_clean: bool | None, truncated: bool = False) -> RecordOutcome:
    """Record every destination candidate in a principal-direction input.

    Binds per ruling 3.1 FIRST (a new input is a new request even when its
    recording then faults). ``spans=None`` means no span structure was declared:
    the whole text is one PRINCIPAL span whose entries carry
    ``span_declared=False``. Given spans must concatenate to ``text``
    exactly, else nothing is recorded and FAULT is returned. Unless
    ``input_clean is True``, every candidate is UNTRUSTED_SOURCE and no n-gram is
    recorded (ruling 3.5). Called AFTER the input scan.
    """
    try:
        lg = _bind_for_input()
        if truncated and lg is not None:
            lg.input_truncated = True     # owner, after M6: a miss here is input_truncated
        if not isinstance(text, str):
            return _lost()
        if spans is None:
            span_list = [(text, Writer.PRINCIPAL)]
            declared = False
        else:
            span_list = []
            for s in spans:
                if (not isinstance(s, Span) or not isinstance(s.text, str)
                        or not isinstance(s.writer, Writer)):
                    return _lost()
                span_list.append((s.text, s.writer))
            if "".join(t for t, _ in span_list) != text:
                return _lost()     # a mis-split is not repaired by guessing
            declared = True
        clean = _principal_clean(input_clean)
        dests: List[Tuple[bytes, Entry]] = []
        grams: List[Tuple[bytes, bool]] = []
        late: List[Tuple[bytes, Entry]] = []   # atoms past the examined window
        atom_budget = AtomBudget()             # one call's WORK budget (2026-10-06)
        budget = MAX_INPUT_NGRAM_CHARS   # key n-grams: the 64 KiB window; atoms past it: the WORK budget
        if lg is not None and len(text) > MAX_INPUT_NGRAM_CHARS:
            lg.input_truncated = True     # visible; it no longer blocks
        for span_text, writer in span_list:            # left to right (V-24)
            is_principal = writer is Writer.PRINCIPAL and clean
            origin = Origin.PRINCIPAL if is_principal else Origin.UNTRUSTED_SOURCE
            window = span_text[:max(budget, 0)]
            for _, a in prose_candidates(window):      # the examined window: per span
                dests.append((_digest_authority(a), (origin, declared, None)))
            if len(span_text) > len(window):
                # Past the window: the WORK-bounded atom pass (2026-10-06), from the
                # last whitespace before the cut so a straddling atom is whole; its
                # atoms go in their OWN write, last (milestone review).
                cut = span_text.rfind(" ", max(0, len(window) - 2048), len(window))
                # No whitespace near the cut: overlap 2,048 chars anyway, so an atom
                # straddling it is still whole (silent-failure review, LOW).
                tail = span_text[cut + 1 if cut >= 0 else max(0, len(window) - 2048):]
                for _, a in budgeted_atoms([((), tail)], atom_budget):
                    late.append((_digest_authority(a), (origin, declared, None)))
            if is_principal and budget > 0:
                for g in span_ngrams(span_text[:budget]):
                    grams.append((_digest_ngram(g), declared))
            budget -= len(span_text)
        if lg.pid != os.getpid():
            return RecordOutcome.NO_LEDGER
        with lg.lock:
            ok_dest = _apply_unit(lg, dests, [])
            ok_gram = _apply_unit(lg, [], grams) if grams else True
            ok_late = _apply_unit(lg, late, []) if late else True
            if atom_budget.hit:
                lg.atoms_incomplete = True     # visible (extraction_incomplete), never a block
        _log_saturation_once(lg)
        return (RecordOutcome.RECORDED if (ok_dest and ok_gram and ok_late)
                else RecordOutcome.SATURATED)
    except Exception:
        _log.exception("value origin: record_principal_input faulted")
        return _lost()


# ── tool results ─────────────────────────────────────────────────────────────
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
    authorizes it. Caller holds the lock."""
    if not k.present:
        return None                                    # an absent key authorizes nothing
    bases = []
    if k.ngram is not None and k.ngram in lg.ngrams:
        bases.append(lg.ngrams[k.ngram])
    if k.authority is not None:
        e = lg.entries.get(k.authority)
        if e is not None and e[0] in (Origin.PRINCIPAL, Origin.TRUSTED_SOURCE):
            bases.append(e[1])
    return None if not bases else any(bases)


def _read_declared(bases: List[bool]) -> bool:
    """A trusted read is only as declared as its weakest key."""
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
    not block. Several matching designations: ANY that authorizes; the
    first such in the operator's order supplies the label."""
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
    out, _, _, late, _ = _result_authorities(result)
    return out + late


def _result_authorities(result: Any) -> Tuple[List[Authority], bool]:
    """(examined candidates, whether the result walk hit a bound, whether it
    skipped an I/O-backed node unread, atoms from past the bound). The last are
    kept apart so the recorder writes them separately (milestone review)."""
    out: List[Authority] = []
    seen = set()
    leaves, truncated, unread, extra, budget = result_leaves_bounded(result)
    examined = AtomBudget(EXAMINED_WORK_BUDGET)   # the EXAMINED pass, by work (2026-10-06)
    for leaf in leaves:
        if examined.left <= 0:
            examined.hit = True                    # visible (extraction_incomplete); no block
            break
        found: List[Authority] = []
        whole = classify_value(leaf, arg_mode=False)
        if isinstance(whole, Authority):
            found.append(whole)
        elif isinstance(whole, list):
            found.extend(whole)
        counted = [0]
        found.extend(a for _, a in prose_candidates(leaf, counted))
        examined.left -= len(leaf) + ATOM_COST * counted[0]
        for a in found:
            if a not in seen:
                seen.add(a)
                out.append(a)
    late: List[Authority] = []               # past the bound: WORK-bounded, one budget
    for _, a in budgeted_atoms([((), leaf) for leaf in extra], budget):
        if a not in seen:
            seen.add(a)
            late.append(a)
    return out, truncated, unread, late, budget.hit or examined.hit


def record_tool_result(tool_name: str, arguments: Mapping[str, object] | None,
                       result: object, *, designations: Sequence[SourceDesignation],
                       result_blocked: bool | None) -> RecordOutcome:
    """Record every destination candidate in a tool's RAW result at the origin
    ``_read_trust`` gives it. ``result_blocked``: False = scanned as ``tool_result`` and
    neither blocked nor approval_required (pre-mode); True = it was; None = not
    scanned, which can never produce a trusted source. Does not bind."""
    try:
        lg = _current()
        if lg is None:
            return RecordOutcome.NO_LEDGER
        # Everything that can run host code, BEFORE the lock (C-15).
        auths, cut, unread, late, incomplete = _result_authorities(result)
        plans = []
        for d in designations:
            if source_matches(d, tool_name, arguments):
                keys = [_KeyPlan(*argument_value(arguments, k)) for k in d.key_args]
                plans.append((d, keys))
        digests = [_digest_authority(a) for a in auths]
        late_digests = [_digest_authority(a) for a in late]
        if lg.pid != os.getpid():
            return RecordOutcome.NO_LEDGER
        with lg.lock:
            if cut:
                lg.result_truncated = True   # RULING 1+2: a miss here is result_truncated
            if unread:
                lg.result_unread = True      # Q18 under the bounds ruling: never silent
            if incomplete:
                lg.atoms_incomplete = True   # the atom pass hit its WORK budget: visible
            entry = _read_trust(lg, plans, result_blocked)
            ok = _apply_unit(lg, [(d, entry) for d in digests], [])
            # Past-the-bound atoms in their OWN write, after the examined part, so
            # they can never drop it (milestone review, 2026-10-05).
            ok_late = (_apply_unit(lg, [(d, entry) for d in late_digests], [])
                       if late_digests else True)
        _log_saturation_once(lg)
        return RecordOutcome.RECORDED if (ok and ok_late) else RecordOutcome.SATURATED
    except Exception:
        _log.exception("value origin: record_tool_result faulted")
        return _lost()


# ── lookup (for evaluate_call) ───────────────────────────────────────────────
def lookup(lg: _Ledger, auths: List[Authority]
           ) -> Tuple[List[Optional[Entry]], bool, bool, bool, bool, bool, bool]:
    """Entries for ``auths`` in one lock acquisition, plus whether the ledger
    is saturated, whether a principal input was cut, and whether a tool result
    was cut, and whether one was skipped unread — a read racing a multi-entry
    write sees all or none of it."""
    digests = [_digest_authority(a) for a in auths]
    with lg.lock:
        return ([lg.entries.get(d) for d in digests], lg.saturated, lg.input_truncated,
                lg.result_truncated, lg.result_unread, lg.atoms_incomplete, lg.dests_dropped)
