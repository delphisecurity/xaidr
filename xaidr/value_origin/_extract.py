"""The argument walk, result normalisation and key tokens.

VALUE-BASED, NOT KEY-BASED. The argument key is ignored when deciding what is a
destination, per ``url_parse``: "a key allowlist here would be a gate the
attacker chooses the combination to".

THE WALK, exactly. Depth-first in insertion order; a dict's KEYS are
walked as leaves before its values; list elements in index order. Only ``str``
counts as a leaf, including empty and whitespace-only strings; other scalars are
ignored and not counted. The arguments mapping is the container at depth 1, so
leaves sit at most 6 deep. ``truncated`` is True iff a 65th string leaf exists,
or a container sits at depth > 6, or a leaf exceeds 4,000 chars — and then one
``walk_bound`` finding is emitted, so a bound hit is never ``no_destination``
(S16: otherwise leaf 65 is a bypass); the evaluator names it ``argument_bound``
(RULING 1+2; this said ``unresolved`` until then). Exactly 64 leaves is not
truncated. Findings within the bound still count.

Sets are walked in a sorted order, because their iteration order changes with
hash randomisation and the 64-leaf bound would otherwise select different
leaves in different processes.
"""
from __future__ import annotations

import array
import collections
import dataclasses
import numbers
import re
from collections.abc import (AsyncIterator, Awaitable, MappingView, Sequence,
                             Set as _AbcSet)
from collections.abc import Iterator as _AbcIterator
from typing import Any, Iterator, List, Mapping, Tuple

from ._authority import ParseFailure, classify_value
from . import _clock, _ucd
from ._idna import pinned_casefold
from ._types import (
    ATOM_COST,
    MAX_ARG_DEPTH,
    MAX_ARG_LEAVES,
    MAX_KEY_TOKENS,
    MAX_LEAF_CHARS,
    MAX_RESULT_LEAF_CHARS,
    Authority,
    Finding,
    UnresolvedReason,
)

Path = Tuple[Any, ...]


def _children(node: Any, *, result: bool = False):
    """(is_container, iterator of (path_step, child)) for one node. In a result
    (``result``) a key of any type is walked, as a str key is, and so is every
    other container Python's ABCs name a sequence, a set or a mapping view,
    child by child without copying it."""
    if isinstance(node, Mapping):
        def it():
            for k, v in list(node.items()):
                if isinstance(k, str) or result:
                    yield k, k, True       # the key itself, as a leaf
                yield k, v, False
        return True, it()
    if isinstance(node, (list, tuple)):
        return True, ((i, v, False) for i, v in enumerate(list(node)))
    if isinstance(node, (set, frozenset)) or (result and isinstance(node, _AbcSet)):
        items = sorted(node, key=lambda x: (type(x).__name__, repr(x)))
        return True, ((i, v, False) for i, v in enumerate(items))
    if result and isinstance(node, (Sequence, MappingView)):
        return True, ((i, v, False) for i, v in enumerate(node))
    return False, iter(())


# A result node value origin must NOT read (Q18), returned by the normaliser so the
# walk can say a read was skipped instead of dropping it silently (bounds ruling).
_UNREAD = object()
# A result node that cannot be read without consuming it (an iterator, a generator,
# an awaitable): never consumed, and the result is cut (2026-11-01).
_CUT = object()


def _host(normalise, node):
    """``normalise(node)``, host code, with the time bound suspended (it is never
    interrupted), then the bound checked."""
    token = _clock.suspend()
    try:
        out = normalise(node)
    finally:
        _clock.restore(token)
    _clock.check()
    return out


def _prepend(first, rest):
    yield first
    yield from rest


class _Rest:
    """The children of a container a walk stopped taking -- still unconsumed, so
    the next walk pays for each one it takes (silent-failure review, 2026-10-06:
    building a container's whole child list in one uncounted step let width alone
    choose how long the scan takes)."""
    __slots__ = ("path", "it")

    def __init__(self, path, it) -> None:
        self.path, self.it = path, it


def _walk(root: Any, *, leaf_cap: int, char_cap: int, truncate_long: bool,
          normalise=None, skipped: list | None = None
          ) -> Tuple[List[Tuple[Path, str]], bool, bool, bool]:
    """Bounded DFS. Returns (leaves, truncated, unread, cut). ``normalise`` maps a
    non-container, non-str node to something walkable (V-15, results only); a
    node it returns as ``_UNREAD`` sets ``unread`` and is not walked. Given a
    ``skipped`` list, every node a bound kept from examination is appended to it
    as (path, node) -- an over-length leaf WHOLE, so a destination straddling the
    cut is still whole -- for ``_all_strings`` and atom extraction (owner,
    2026-10-05; since 2026-10-06 extraction is bounded by WORK, not position).
    In a result (``normalise``) a node returned as ``_CUT``, and a node whose host
    code raised, is not read and sets ``cut``: the walk goes on with the rest."""
    from ._types import MAX_WALK_NODES
    leaves: List[Tuple[Path, str]] = []
    truncated = False
    unread = False
    cut = False
    count = 0
    visited = 1
    # Explicit stack: (path, node, depth_of_node_if_container)
    stack: List[Tuple[Path, Any, int]] = [((), root, 1)]
    while stack:
        _clock.tick()
        path, node, depth = stack.pop()
        if isinstance(node, str):
            count += 1
            if count > leaf_cap:
                truncated = True
                if skipped is not None:
                    skipped.append((path, node))
                    skipped.extend((p, n) for p, n, _ in stack)
                break
            if len(node) > char_cap:
                truncated = True           # a bound hit, cut or not (RULING 1+2 after M8)
                if skipped is not None:
                    if truncate_long:
                        # Results: the prefix WAS examined. Hand on only the tail,
                        # from the last whitespace before the cut so a straddling
                        # atom is whole (milestone review: re-scanning the prefix
                        # spent the budget before the cut).
                        lo = max(0, char_cap - 2048)
                        at = max(node.rfind(c, lo, char_cap) for c in " \n\t")
                        skipped.append((path, node[at + 1 if at >= 0 else lo:]))
                    else:
                        skipped.append((path, node))   # arguments: unexamined, whole
                if truncate_long:          # results: the first 64 KiB are still recorded
                    leaves.append((path, node[:char_cap]))
                continue                   # arguments: an over-length leaf is not examined
            leaves.append((path, node))
            continue
        if normalise is not None:
            try:
                node = _host(normalise, node)
            except Exception:
                cut = True                    # host code raised: this node is not read
                continue
            if node is _UNREAD:
                unread = True
                continue
            if node is _CUT:
                cut = True
                continue
            if isinstance(node, str):
                stack.append((path, node, depth))
                continue
        batch = []
        rest = None
        try:
            is_container, kids = _children(node, result=normalise is not None)
            if not is_container:
                continue
            if depth > MAX_ARG_DEPTH:
                truncated = True
                if skipped is not None:
                    skipped.append((path, node))
                continue
            for step, child, flag in kids:    # one at a time, each one counted
                visited += 1
                if visited > MAX_WALK_NODES:
                    rest = _prepend((step, child, flag), kids)
                    break
                batch.append((path + (step,), child, depth + 1))
        except Exception:
            if normalise is None:
                raise                         # an argument: a PARSE_FAILURE, as before
            cut = True                        # a result: what it gave so far is still read
        stack.extend(reversed(batch))
        if rest is not None:                  # the node budget is spent: visible
            truncated = True
            if skipped is not None:
                skipped.extend((p, n) for p, n, _ in reversed(stack))
                skipped.append((path, _Rest(path, rest)))
            break
    return leaves, truncated, unread, cut


class _Path:
    """A path the unbounded pass builds one step at a time: a link to its parent,
    so a node thousands deep costs one link and not a copy of every step above it
    (memory in proportion to the work, never to the square of the depth). Turned
    into a tuple only for a finding, and that is charged to the work budget."""
    __slots__ = ("parent", "step", "depth")

    def __init__(self, parent, step) -> None:
        self.parent, self.step = parent, step
        self.depth = (parent.depth if isinstance(parent, _Path) else len(parent)) + 1


def path_len(p) -> int:
    return p.depth if isinstance(p, _Path) else len(p)


def path_tuple(p) -> Path:
    if not isinstance(p, _Path):
        return p
    steps = []
    while isinstance(p, _Path):
        steps.append(p.step)
        p = p.parent
    return tuple(p) + tuple(reversed(steps))


def _all_strings(items, normalise=None, budget: "AtomBudget | None" = None
                 ) -> Tuple[List[Tuple[Path, str]], bool, bool, bool]:
    """Every string under ``items`` ((path, node) pairs) with no leaf, length or
    depth bound, but bounded by WORK: each node and child it takes is charged to
    ``budget``, the SAME budget the atom pass then spends (milestone review: the
    walk had its own), and it stops when that runs out (owner, 2026-10-06).
    (strings, whether a node could not be examined -- an unread I/O node, or, in
    an argument, host code that RAISED, confined to its node: silent-failure
    review --, whether it stopped at the budget with nodes left, whether a result
    node was cut: one returned as ``_CUT``, or one whose host code raised)."""
    budget = budget if budget is not None else AtomBudget()
    out: List[Tuple[Path, str]] = []
    unread = False
    cut = False
    # The ids of objects that live for the whole walk: those reached without
    # passing through a normaliser's temporary (a model_dump() dict, an asdict()).
    # Only those ids are recorded, so no id is ever reused by another object and
    # nothing is kept alive for it: a temporary and what it alone holds are freed
    # as the walk moves on (memory follows the stack, not the result). Everything
    # else is looked up, never recorded: a node met again under a temporary costs
    # a node of the WORK budget, which ends any cycle through temporaries.
    seen: set = set()
    held = 0      # chars of strings only a temporary held, kept here for the atom pass
    stack = [(path, node, isinstance(node, _Rest)) for path, node in reversed(items)]

    def take(path, text, owned) -> bool:
        """Keep ``text`` for the atom pass. One a temporary alone held is kept only
        while the budget could still scan it: past that it could never be read, and
        holding it would let a result's model_dump() strings fill memory."""
        nonlocal held
        if owned:
            if held > budget.left:
                budget.hit = True
                return False
            held += len(text)
        out.append((path, text))     # its chars are charged when the atom pass scans them
        return True

    while stack:
        _clock.tick()
        if budget.left <= 0:
            budget.hit = True
            return out, unread, True, cut
        path, node, owned = stack.pop()
        budget.left -= 1
        if isinstance(node, str):
            if not take(path, node, owned):
                return out, unread, True, cut
            continue
        try:
            if isinstance(node, _Rest):
                kids, base, owned = node.it, node.path, True
            else:
                if id(node) in seen:
                    continue                 # this very object, met again (a cycle, a share)
                if not owned:
                    seen.add(id(node))
                if normalise is not None:
                    raw, node = node, _host(normalise, node)
                    if node is _UNREAD:
                        unread = True
                        continue
                    if node is _CUT:
                        cut = True
                        continue
                    owned = owned or node is not raw
                    if isinstance(node, str):
                        if not take(path, node, owned):
                            return out, unread, True, cut
                        continue
                is_container, kids = _children(node, result=normalise is not None)
                if not is_container:
                    continue
                base = path
            batch = []
            for step, child, _ in kids:      # one at a time, each one charged
                budget.left -= 1
                if budget.left <= 0:
                    budget.hit = True
                    return out, unread, True, cut
                batch.append((_Path(base, step), child, owned))
        except Exception:
            if normalise is None:
                unread = True                # an argument: a node that could not be examined
            else:
                cut = True                   # a result: the node is cut
            continue
        stack.extend(reversed(batch))
    return out, unread, False, cut


class AtomBudget:
    """One seam call's WORK budget for the atom pass (owner, 2026-10-06)."""
    __slots__ = ("left", "hit")

    def __init__(self, left: "int | None" = None) -> None:
        from ._types import ATOM_WORK_BUDGET
        self.left = ATOM_WORK_BUDGET if left is None else left
        self.hit = False


def _chunks(s: str):
    """``s`` in ATOM_CHUNK_CHARS pieces, cut at whitespace where there is any in
    the last half of a piece, so an atom is rarely split."""
    from ._types import ATOM_CHUNK_CHARS
    i, n = 0, len(s)
    while i < n:
        j = min(i + ATOM_CHUNK_CHARS, n)
        if j < n:
            k = max(s.rfind(c, i + ATOM_CHUNK_CHARS // 2, j) for c in " \n\t")
            if k > i:
                j = k + 1
        yield s[i:j]
        i = j


def budgeted_atoms(strings, budget: AtomBudget, reader=None):
    """(path, Authority) for each destination atom (C-7's prose pass) in WHOLE
    strings, chunk by chunk, charging 1 per char and ATOM_COST per candidate EXAMINED, until the
    budget is spent; then ``budget.hit`` is True and the rest is not scanned.
    ``reader`` is ``prose_candidates`` unless given (a result's text is read with
    ``result_candidates``)."""
    from ._authority import prose_candidates
    from ._types import ATOM_COST
    reader = reader or prose_candidates
    for path, s in strings:
        for chunk in _chunks(s):
            _clock.tick()
            if budget.left <= 0:
                budget.hit = True
                return
            examined = [0]
            found = reader(chunk, examined)
            budget.left -= len(chunk) + ATOM_COST * examined[0]   # every candidate, kept or not
            for _, a in found:
                yield path, a


def extract_destinations(arguments: Mapping[str, object] | None
                         ) -> tuple[tuple[Finding, ...], bool]:
    """The value-based argument walk. Returns (findings, truncated).

    A leaf yields a finding iff its WHOLE value is one destination or a
    comma/semicolon list of mailboxes. A destination-shaped value that does not
    parse yields ``Finding(destination=None, reason=PARSE_FAILURE)`` (ruling
    3.2), followed by one finding per mailbox-list part that did parse, so an
    untrusted part decides the wire; a walk that hits a
    bound yields exactly one
    ``Finding(destination=None, reason=WALK_BOUND)``. Never raises: an internal
    fault is one PARSE_FAILURE finding, because an unparseable call is not a
    call with no destination.
    """
    found, truncated, _ = extract_with_observed(arguments)
    return found, truncated


def extract_with_observed(arguments: Mapping[str, object] | None
                          ) -> tuple[tuple[Finding, ...], bool, tuple[Finding, ...]]:
    """``extract_destinations`` plus the OBSERVED findings: the destination atoms
    in a value the walk examined whole that is not wholly one destination (prose,
    a command line, a mailbox part that does not parse). They are recorded and
    never decide the wire (record only). Past a bound the atoms decide, as
    the value's whole reading does there, so a value names the same destinations
    wherever it sits."""
    try:
        if arguments is None:
            return (), False, ()
        skipped: list = []
        leaves, truncated, _, _ = _walk(arguments, leaf_cap=MAX_ARG_LEAVES,
                                     char_cap=MAX_LEAF_CHARS, truncate_long=False,
                                     skipped=skipped)
        out: List[Finding] = []
        seen: set = set()
        budget = AtomBudget()        # ONE budget: the atoms, the walk past a bound, the reads there
        atoms: List[Tuple[Path, str]] = []
        short: List[Tuple[Path, str]] = []
        for path, leaf in leaves:
            if not _read_whole(out, seen, path, classify_value(leaf, arg_mode=True)):
                short.append((path, leaf))
        if truncated:
            # Owner, 2026-10-05: what the bound kept from examination is still
            # searched for destination ATOMS, so a padded destination is found;
            # and a value there short enough to read whole is read whole, so it
            # names what it names as a leaf of its own.
            strings, faulted, exhausted, _ = _all_strings(skipped, budget=budget)
            stripped: dict = {}      # id -> the value stripped: a repeat is not stripped again
            for path, s in strings:
                # Read whole only what fits once stripped. Measuring that strips the
                # value once per object, charged for the whitespace the strip scanned;
                # the atom pass is handed what is left, so no character is charged
                # twice, and a value repeated past the bound costs its strip once.
                # The read, when there is one, is charged in full, and a path a
                # finding carries is charged by its length.
                if budget.left <= 0:
                    n = MAX_LEAF_CHARS + 1
                elif len(s) <= MAX_LEAF_CHARS:
                    n = len(s)
                else:
                    t = stripped.get(id(s))
                    if t is None:
                        t = stripped[id(s)] = s.strip(_ucd.WHITESPACE)
                        budget.left -= len(s) - len(t) + 2
                    n = len(t)
                    if n > MAX_LEAF_CHARS:
                        atoms.append((path, t))
                        continue
                if n <= MAX_LEAF_CHARS and budget.left > 0:
                    budget.left -= len(s) + ATOM_COST     # the read strips all of it
                    res = classify_value(s, arg_mode=True)
                    if res is not None:
                        budget.left -= path_len(path)
                        path = path_tuple(path)
                    if _read_whole(out, seen, path, res):
                        continue
                atoms.append((path, s))
        made: dict = {}
        for path, a in budgeted_atoms(atoms, budget):
            if a not in seen:
                seen.add(a)
                if id(path) not in made:
                    budget.left -= path_len(path)
                    made[id(path)] = path_tuple(path)
                out.append(Finding(path=made[id(path)], destination=a, reason=None))
        # Every value the walk examined whole that is not wholly one destination
        # is scanned for atoms too, and what that finds is OBSERVED (record only).
        observed: List[Finding] = []
        obs_budget = AtomBudget()
        for path, a in budgeted_atoms(short, obs_budget):
            if a not in seen:
                seen.add(a)
                observed.append(Finding(path=path, destination=a, reason=None))
        if truncated:
            if faulted:     # a node past the bound could not be examined: visible
                out.append(Finding(path=(), destination=None,
                                   reason=UnresolvedReason.PARSE_FAILURE))
            if exhausted or budget.hit:   # the WORK budget ran out: visible, not a block
                out.append(Finding(path=(), destination=None,
                                   reason=UnresolvedReason.ATOM_BUDGET))
            out.append(Finding(path=(), destination=None,
                               reason=UnresolvedReason.WALK_BOUND))
        return tuple(out), truncated, tuple(observed)
    except Exception:
        return (Finding(path=(), destination=None,
                        reason=UnresolvedReason.PARSE_FAILURE),), False, ()


def _read_whole(out: List[Finding], seen: set, path: Path, res) -> bool:
    """Append a value's whole-value reading to ``out``; True iff the value is
    wholly one destination (or one address list), so it needs no atom scan."""
    if res is None:
        return False
    if isinstance(res, ParseFailure):
        out.append(Finding(path=path, destination=None, reason=UnresolvedReason.PARSE_FAILURE))
        found = list(res.parsed)
    elif isinstance(res, list):
        found = res
    else:
        found = [res]
    for a in found:
        seen.add(a)
        out.append(Finding(path=path, destination=a, reason=None))
    return not isinstance(res, ParseFailure)


# ── results (V-15) ───────────────────────────────────────────────────────────
# Q18: a result node from these modules may hold an unread stream; V-15's
# `.content` read would consume it, a host-behaviour change no verdict sees.
_IO_BACKED_MODULES = frozenset({"httpx", "requests", "urllib3", "aiohttp"})


# The byte-order marks a bytes value is decoded by; without one it is UTF-8.
_BOMS = ((b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe\x00\x00", "utf-32"),
         (b"\x00\x00\xfe\xff", "utf-32"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"))


def _bytes_text(node) -> str:
    """A bytes-like value as text: decoded by its byte-order mark, else as UTF-8,
    a bad byte replaced, as the sensor reads a bytes result."""
    data = bytes(node)
    for bom, codec in _BOMS:
        if data.startswith(bom):
            return data.decode(codec, "replace")
    return data.decode("utf-8", "replace")


def _normalise_result_node(node: Any) -> Any:
    """What a result node is read as (2026-11-01: nothing is read as empty).

    str, a Mapping, list, tuple, set or frozenset: walked. A number or None: it
    names no destination. bytes, bytearray, memoryview, a text ``array``: its
    text. A node from an I/O-backed module: ``_UNREAD`` (Q18). An iterator, a
    generator or an awaitable: ``_CUT``, never consumed. An object with a str
    ``.content``: that content (V-15). ``model_dump()``: its dict. A dataclass
    instance: its fields, as they are. Another sequence, set or mapping view:
    walked. Anything else: ``str(node)``, the text Python and the frameworks
    print it as, read as a leaf within the same bounds. May run host code, so it
    is only ever called OUTSIDE the ledger lock; a fault in it cuts the node."""
    if isinstance(node, (str, Mapping, list, tuple, set, frozenset)):
        return node
    if node is None or isinstance(node, numbers.Number):
        return None
    if isinstance(node, (bytes, bytearray, memoryview)):
        return _bytes_text(node)
    if isinstance(node, array.array) and node.typecode in ("u", "w"):
        return node.tounicode()
    if type(node).__module__.split(".")[0] in _IO_BACKED_MODULES:
        return _UNREAD   # Q18: never read (it would consume a stream), never silent either
    if isinstance(node, (_AbcIterator, AsyncIterator, Awaitable)):
        return _CUT      # reading it would consume it
    content = getattr(node, "content", None)
    if isinstance(content, str):
        return content
    dump = getattr(node, "model_dump", None)
    if callable(dump):
        return dump()
    if dataclasses.is_dataclass(node) and not isinstance(node, type):
        return {f.name: getattr(node, f.name) for f in dataclasses.fields(node)}
    if isinstance(node, collections.UserString):
        return str(node)
    if isinstance(node, (Sequence, _AbcSet, MappingView)):
        return node
    text = str(node)
    if not isinstance(text, str):
        raise TypeError("str() gave no text")
    return text


def result_leaves(result: Any) -> List[str]:
    """The string leaves of a raw tool result, each capped at 65,536 chars,
    walked with the argument walk's leaf and depth bounds. Host code that raises
    is confined to its node, which is cut (2026-11-01: it raised here, and the
    caller reported FAULT)."""
    return result_leaves_bounded(result)[0]


def result_leaves_bounded(result: Any) -> Tuple[List[str], bool, bool, List[str], "AtomBudget"]:
    """``result_leaves`` plus whether the walk stopped before reading all of the
    result: a leaf cut at 65,536 chars, more than 64 leaves, nesting deeper than
    6, the walk's node budget, a node it must not consume (an iterator), or host
    code that raised (2026-11-01: every way the walk stops early cuts). The
    recorder marks the ledger, so the result cannot vouch (owner, RULING 1+2 after
    M8; 2026-10-25). The third value: an I/O-backed node was skipped unread (Q18),
    so a later miss reads result_unread."""
    skipped: list = []
    leaves, truncated, unread, cut = _walk(result, leaf_cap=MAX_ARG_LEAVES,
                                           char_cap=MAX_RESULT_LEAF_CHARS, truncate_long=True,
                                           normalise=_normalise_result_node, skipped=skipped)
    budget = AtomBudget()                   # ONE budget: this walk, then the caller's atoms
    extra, unread_extra, _, cut_extra = _all_strings(skipped, normalise=_normalise_result_node,
                                                     budget=budget)
    # Fourth value (owner, 2026-10-05): the WHOLE strings the bound kept from
    # examination, for atom extraction only; fifth: the call's WORK budget, already
    # charged for this walk (2026-10-06), for the caller's atom pass to spend.
    return ([s for _, s in leaves], truncated or cut or cut_extra, unread or unread_extra,
            [s for _, s in extra], budget)


def argument_value(arguments: Mapping[str, object] | None, name: str):
    """(present, value) for a named argument."""
    if arguments is None or not isinstance(arguments, Mapping):
        return False, None
    if name not in arguments:
        return False, None
    return True, arguments[name]


# ── key tokens ───────────────────────────────────────────────────────────────
# A trailing full stop is not part of a token.
# The specified token pattern, exactly. Unambiguous (every repetition opens with "."), so linear.
_TOKEN_RE = _ucd.compile(r"[\w@+-]+(?:\.[\w@+-]+)*")


def tokens(text: str) -> List[str]:
    folded, scan = pinned_casefold(text)
    return [folded[m.start():m.end()] for m in _TOKEN_RE.finditer(scan)]


def span_ngrams(text: str) -> Iterator[str]:
    """Every contiguous 1..MAX_KEY_TOKENS token n-gram of ONE span, joined by a
    single space. A span boundary is a token boundary: the caller calls
    this per span."""
    toks = tokens(text)
    for i in range(len(toks)):
        for n in range(1, MAX_KEY_TOKENS + 1):
            if i + n > len(toks):
                break
            yield " ".join(toks[i:i + n])


def key_ngram(value: Any):
    """The normalised n-gram a key value must equal, or None when
    the key can never be authorized by a principal n-gram."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, str) or value == "":
        return None
    toks = tokens(value)
    if not toks or len(toks) > MAX_KEY_TOKENS:
        return None
    joined = " ".join(toks)
    if joined != " ".join(_ucd.split(pinned_casefold(value)[0])):
        return None                        # O'Brien, Bob* — refused
    return joined


def key_authority(value: Any):
    """A key value that is itself a destination: its authority, else None."""
    if not isinstance(value, str):
        return None
    res = classify_value(value, arg_mode=True)
    if isinstance(res, list):
        return res[0] if len(res) == 1 else None
    return res if isinstance(res, Authority) else None
