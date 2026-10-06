"""The argument walk (C-8, V-11), result normalisation (V-15) and key tokens (C-3, V-8).

VALUE-BASED, NOT KEY-BASED. The argument key is ignored when deciding what is a
destination, per ``url_parse``: "a key allowlist here would be a gate the
attacker chooses the combination to".

THE WALK, exactly (V-11). Depth-first in insertion order; a dict's KEYS are
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

import dataclasses
import re
from typing import Any, Iterator, List, Mapping, Tuple

from ._authority import ParseFailure, classify_value
from ._types import (
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


def _children(node: Any):
    """(is_container, iterator of (path_step, child)) for one node."""
    if isinstance(node, Mapping):
        def it():
            for k, v in list(node.items()):
                if isinstance(k, str):
                    yield k, k, True       # the key itself, as a leaf
                yield k, v, False
        return True, it()
    if isinstance(node, (list, tuple)):
        return True, ((i, v, False) for i, v in enumerate(list(node)))
    if isinstance(node, (set, frozenset)):
        items = sorted(node, key=lambda x: (type(x).__name__, repr(x)))
        return True, ((i, v, False) for i, v in enumerate(items))
    return False, iter(())


# A result node value origin must NOT read (Q18), returned by the normaliser so the
# walk can say a read was skipped instead of dropping it silently (bounds ruling).
_UNREAD = object()


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
          ) -> Tuple[List[Tuple[Path, str]], bool, bool]:
    """Bounded DFS. Returns (leaves, truncated, unread). ``normalise`` maps a
    non-container, non-str node to something walkable (V-15, results only); a
    node it returns as ``_UNREAD`` sets ``unread`` and is not walked. Given a
    ``skipped`` list, every node a bound kept from examination is appended to it
    as (path, node) -- an over-length leaf WHOLE, so a destination straddling the
    cut is still whole -- for ``_all_strings`` and atom extraction (owner,
    2026-10-05; since 2026-10-06 extraction is bounded by WORK, not position)."""
    from ._types import MAX_WALK_NODES
    leaves: List[Tuple[Path, str]] = []
    truncated = False
    unread = False
    count = 0
    visited = 1
    # Explicit stack: (path, node, depth_of_node_if_container)
    stack: List[Tuple[Path, Any, int]] = [((), root, 1)]
    while stack:
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
                        cut = max(node.rfind(c, lo, char_cap) for c in " \n\t")
                        skipped.append((path, node[cut + 1 if cut >= 0 else lo:]))
                    else:
                        skipped.append((path, node))   # arguments: unexamined, whole
                if truncate_long:          # results: the first 64 KiB are still recorded
                    leaves.append((path, node[:char_cap]))
                continue                   # arguments: an over-length leaf is not examined
            leaves.append((path, node))
            continue
        if normalise is not None:
            node = normalise(node)
            if node is _UNREAD:
                unread = True
                continue
            if isinstance(node, str):
                stack.append((path, node, depth))
                continue
        is_container, kids = _children(node)
        if not is_container:
            continue
        if depth > MAX_ARG_DEPTH:
            truncated = True
            if skipped is not None:
                skipped.append((path, node))
            continue
        batch = []
        rest = None
        for step, child, flag in kids:        # one at a time, each one counted
            visited += 1
            if visited > MAX_WALK_NODES:
                rest = _prepend((step, child, flag), kids)
                break
            batch.append((path + (step,), child, depth + 1))
        stack.extend(reversed(batch))
        if rest is not None:                  # the node budget is spent: visible
            truncated = True
            if skipped is not None:
                skipped.extend((p, n) for p, n, _ in reversed(stack))
                skipped.append((path, _Rest(path, rest)))
            break
    return leaves, truncated, unread


def _all_strings(items, normalise=None, budget: "AtomBudget | None" = None
                 ) -> Tuple[List[Tuple[Path, str]], bool, bool]:
    """Every string under ``items`` ((path, node) pairs) with no leaf, length or
    depth bound, but bounded by WORK: each node and child it takes is charged to
    ``budget``, the SAME budget the atom pass then spends (milestone review: the
    walk had its own), and it stops when that runs out (owner, 2026-10-06).
    (strings, whether a node could not be examined -- an unread I/O node, or host
    code that RAISED, confined to its node: silent-failure review --, whether it
    stopped at the budget with nodes left)."""
    budget = budget if budget is not None else AtomBudget()
    out: List[Tuple[Path, str]] = []
    unread = False
    seen = set()
    stack = list(reversed(items))
    while stack:
        if budget.left <= 0:
            budget.hit = True
            return out, unread, True
        path, node = stack.pop()
        budget.left -= 1
        if isinstance(node, str):
            out.append((path, node))     # its chars are charged when the atom pass scans them
            continue
        try:
            if isinstance(node, _Rest):
                kids, base = node.it, node.path
            else:
                if normalise is not None:
                    node = normalise(node)
                    if node is _UNREAD:
                        unread = True
                        continue
                    if isinstance(node, str):
                        out.append((path, node))
                        continue
                is_container, kids = _children(node)
                if not is_container or id(node) in seen:
                    continue
                seen.add(id(node))
                base = path
            batch = []
            for step, child, _ in kids:      # one at a time, each one charged
                budget.left -= 1
                if budget.left <= 0:
                    budget.hit = True
                    return out, unread, True
                batch.append((base + (step,), child))
        except Exception:
            unread = True
            continue
        stack.extend(reversed(batch))
    return out, unread, False


class AtomBudget:
    """One seam call's WORK budget for the atom pass (owner, 2026-10-06)."""
    __slots__ = ("left", "hit")

    def __init__(self) -> None:
        from ._types import ATOM_WORK_BUDGET
        self.left = ATOM_WORK_BUDGET
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


def budgeted_atoms(strings, budget: AtomBudget):
    """(path, Authority) for each destination atom (C-7's prose pass) in WHOLE
    strings, chunk by chunk, charging 1 per char and ATOM_COST per candidate EXAMINED, until the
    budget is spent; then ``budget.hit`` is True and the rest is not scanned."""
    from ._authority import prose_candidates
    from ._types import ATOM_COST
    for path, s in strings:
        for chunk in _chunks(s):
            if budget.left <= 0:
                budget.hit = True
                return
            examined = [0]
            found = prose_candidates(chunk, examined)
            budget.left -= len(chunk) + ATOM_COST * examined[0]   # every candidate, kept or not
            for _, a in found:
                yield path, a


def extract_destinations(arguments: Mapping[str, object] | None
                         ) -> tuple[tuple[Finding, ...], bool]:
    """The value-based argument walk (§6 C-8). Returns (findings, truncated).

    A leaf yields a finding iff its WHOLE value is one destination or a
    comma/semicolon list of mailboxes. A destination-shaped value that does not
    parse yields ``Finding(destination=None, reason=PARSE_FAILURE)`` (V-4,
    ruling 3.2), followed by one finding per mailbox-list part that did parse
    (R1, 2026-10-03), so an untrusted part decides the wire; a walk that hits a
    bound yields exactly one
    ``Finding(destination=None, reason=WALK_BOUND)``. Never raises: an internal
    fault is one PARSE_FAILURE finding, because an unparseable call is not a
    call with no destination.
    """
    try:
        if arguments is None:
            return (), False
        skipped: list = []
        leaves, truncated, _ = _walk(arguments, leaf_cap=MAX_ARG_LEAVES,
                                  char_cap=MAX_LEAF_CHARS, truncate_long=False, skipped=skipped)
        out: List[Finding] = []
        for path, leaf in leaves:
            res = classify_value(leaf, arg_mode=True)
            if res is None:
                continue
            if isinstance(res, ParseFailure):
                out.append(Finding(path=path, destination=None,
                                   reason=UnresolvedReason.PARSE_FAILURE))
                out.extend(Finding(path=path, destination=a, reason=None)
                           for a in res.parsed)
            elif isinstance(res, list):
                out.extend(Finding(path=path, destination=a, reason=None) for a in res)
            else:
                out.append(Finding(path=path, destination=res, reason=None))
        if truncated:
            # Owner, 2026-10-05: what the bound kept from examination is still
            # searched for destination ATOMS, so a padded destination is found.
            seen = {f.destination for f in out if f.destination is not None}
            budget = AtomBudget()               # ONE budget: the walk, then the atoms
            strings, faulted, exhausted = _all_strings(skipped, budget=budget)
            for path, a in budgeted_atoms(strings, budget):
                if a not in seen:
                    seen.add(a)
                    out.append(Finding(path=path, destination=a, reason=None))
            if faulted:     # a node past the bound could not be examined: visible
                out.append(Finding(path=(), destination=None,
                                   reason=UnresolvedReason.PARSE_FAILURE))
            if exhausted or budget.hit:   # the WORK budget ran out: visible, not a block
                out.append(Finding(path=(), destination=None,
                                   reason=UnresolvedReason.ATOM_BUDGET))
            out.append(Finding(path=(), destination=None,
                               reason=UnresolvedReason.WALK_BOUND))
        return tuple(out), truncated
    except Exception:
        return (Finding(path=(), destination=None,
                        reason=UnresolvedReason.PARSE_FAILURE),), False


# ── results (V-15) ───────────────────────────────────────────────────────────
# Q18: a result node from these modules may hold an unread stream; V-15's
# `.content` read would consume it, a host-behaviour change no verdict sees.
_IO_BACKED_MODULES = frozenset({"httpx", "requests", "urllib3", "aiohttp"})


def _normalise_result_node(node: Any) -> Any:
    """V-15: str → leaf; Mapping/Sequence → walk; an object with a str
    ``.content`` → that content; ``model_dump()`` → its dict; a dataclass
    instance → ``asdict``; anything else → no leaves. May run host code, so it
    is only ever called OUTSIDE the ledger lock."""
    if isinstance(node, (str, Mapping, list, tuple, set, frozenset)):
        return node
    if isinstance(node, (bytes, bytearray, int, float, bool)) or node is None:
        return None
    if type(node).__module__.split(".")[0] in _IO_BACKED_MODULES:
        return _UNREAD   # Q18: never read (it would consume a stream), never silent either
    content = getattr(node, "content", None)
    if isinstance(content, str):
        return content
    dump = getattr(node, "model_dump", None)
    if callable(dump):
        return dump()
    if dataclasses.is_dataclass(node) and not isinstance(node, type):
        return dataclasses.asdict(node)
    return None


def result_leaves(result: Any) -> List[str]:
    """The string leaves of a raw tool result, each capped at 65,536 chars,
    walked with the C-8 leaf and depth bounds. Raises only on a host fault
    (e.g. a ``model_dump`` that raises); the caller reports FAULT."""
    return result_leaves_bounded(result)[0]


def result_leaves_bounded(result: Any) -> Tuple[List[str], bool, bool, List[str], "AtomBudget"]:
    """``result_leaves`` plus whether any bound was hit (a leaf cut at 65,536
    chars, more than 64 leaves, nesting deeper than 6). The recorder marks the
    ledger, so a later miss reads result_truncated, never a silent unresolved
    (owner, RULING 1+2 after M8). The third value: an I/O-backed node was
    skipped unread (Q18), so a later miss reads result_unread."""
    skipped: list = []
    leaves, truncated, unread = _walk(result, leaf_cap=MAX_ARG_LEAVES,
                                      char_cap=MAX_RESULT_LEAF_CHARS, truncate_long=True,
                                      normalise=_normalise_result_node, skipped=skipped)
    budget = AtomBudget()                   # ONE budget: this walk, then the caller's atoms
    extra, unread_extra, _ = _all_strings(skipped, normalise=_normalise_result_node, budget=budget)
    # Fourth value (owner, 2026-10-05): the WHOLE strings the bound kept from
    # examination, for atom extraction only; fifth: the call's WORK budget, already
    # charged for this walk (2026-10-06), for the caller's atom pass to spend.
    return ([s for _, s in leaves], truncated, unread or unread_extra,
            [s for _, s in extra], budget)


def argument_value(arguments: Mapping[str, object] | None, name: str):
    """(present, value) for a named argument."""
    if arguments is None or not isinstance(arguments, Mapping):
        return False, None
    if name not in arguments:
        return False, None
    return True, arguments[name]


# ── key tokens (C-3, V-8) ────────────────────────────────────────────────────
# A trailing full stop is not part of a token.
# Exactly C-3's pattern. Unambiguous (every repetition opens with "."), so linear.
_TOKEN_RE = re.compile(r"[\w@+-]+(?:\.[\w@+-]+)*")


def tokens(text: str) -> List[str]:
    return _TOKEN_RE.findall(text.casefold())


def span_ngrams(text: str) -> Iterator[str]:
    """Every contiguous 1..MAX_KEY_TOKENS token n-gram of ONE span, joined by a
    single space. A span boundary is a token boundary (V-8e): the caller calls
    this per span."""
    toks = tokens(text)
    for i in range(len(toks)):
        for n in range(1, MAX_KEY_TOKENS + 1):
            if i + n > len(toks):
                break
            yield " ".join(toks[i:i + n])


def key_ngram(value: Any):
    """V-8 (a)-(d): the normalised n-gram a key value must equal, or None when
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
    if joined != " ".join(value.casefold().split()):
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
