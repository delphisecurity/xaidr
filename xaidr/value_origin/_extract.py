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
``walk_bound`` finding is emitted, so a bound hit is ``unresolved``, never
``no_destination`` (S16: otherwise leaf 65 is a bypass). Exactly 64 leaves is not
truncated. Findings within the bound still count.

Sets are walked in a sorted order, because their iteration order changes with
hash randomisation and the 64-leaf bound would otherwise select different
leaves in different processes.
"""
from __future__ import annotations

import dataclasses
import re
from typing import Any, Iterator, List, Mapping, Tuple

from ._authority import PARSE_FAILURE, classify_value
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


def _walk(root: Any, *, leaf_cap: int, char_cap: int, truncate_long: bool,
          normalise=None) -> Tuple[List[Tuple[Path, str]], bool]:
    """Bounded DFS. Returns (leaves, truncated). ``normalise`` maps a non-container,
    non-str node to something walkable (V-15, results only)."""
    leaves: List[Tuple[Path, str]] = []
    truncated = False
    count = 0
    # Explicit stack: (path, node, depth_of_node_if_container)
    stack: List[Tuple[Path, Any, int]] = [((), root, 1)]
    while stack:
        path, node, depth = stack.pop()
        if isinstance(node, str):
            count += 1
            if count > leaf_cap:
                truncated = True
                break
            if len(node) > char_cap:
                if truncate_long:
                    leaves.append((path, node[:char_cap]))
                else:
                    truncated = True       # an over-length leaf is not examined
                continue
            leaves.append((path, node))
            continue
        if normalise is not None:
            node = normalise(node)
            if isinstance(node, str):
                stack.append((path, node, depth))
                continue
        is_container, kids = _children(node)
        if not is_container:
            continue
        if depth > MAX_ARG_DEPTH:
            truncated = True
            continue
        batch = [(path + (step,), child, depth + 1) for step, child, _ in kids]
        stack.extend(reversed(batch))
    return leaves, truncated


def extract_destinations(arguments: Mapping[str, object] | None
                         ) -> tuple[tuple[Finding, ...], bool]:
    """The value-based argument walk (§6 C-8). Returns (findings, truncated).

    A leaf yields a finding iff its WHOLE value is one destination or a
    comma/semicolon list of mailboxes. A destination-shaped value that does not
    parse yields ``Finding(destination=None, reason=PARSE_FAILURE)`` (V-4,
    ruling 3.2); a walk that hits a bound yields exactly one
    ``Finding(destination=None, reason=WALK_BOUND)``. Never raises: an internal
    fault is one PARSE_FAILURE finding, because an unparseable call is not a
    call with no destination.
    """
    try:
        if arguments is None:
            return (), False
        leaves, truncated = _walk(arguments, leaf_cap=MAX_ARG_LEAVES,
                                  char_cap=MAX_LEAF_CHARS, truncate_long=False)
        out: List[Finding] = []
        for path, leaf in leaves:
            res = classify_value(leaf, arg_mode=True)
            if res is None:
                continue
            if res is PARSE_FAILURE:
                out.append(Finding(path=path, destination=None,
                                   reason=UnresolvedReason.PARSE_FAILURE))
            elif isinstance(res, list):
                out.extend(Finding(path=path, destination=a, reason=None) for a in res)
            else:
                out.append(Finding(path=path, destination=res, reason=None))
        if truncated:
            out.append(Finding(path=(), destination=None,
                               reason=UnresolvedReason.WALK_BOUND))
        return tuple(out), truncated
    except Exception:
        return (Finding(path=(), destination=None,
                        reason=UnresolvedReason.PARSE_FAILURE),), False


# ── results (V-15) ───────────────────────────────────────────────────────────
def _normalise_result_node(node: Any) -> Any:
    """V-15: str → leaf; Mapping/Sequence → walk; an object with a str
    ``.content`` → that content; ``model_dump()`` → its dict; a dataclass
    instance → ``asdict``; anything else → no leaves. May run host code, so it
    is only ever called OUTSIDE the ledger lock."""
    if isinstance(node, (str, Mapping, list, tuple, set, frozenset)):
        return node
    if isinstance(node, (bytes, bytearray, int, float, bool)) or node is None:
        return None
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
    leaves, _ = _walk(result, leaf_cap=MAX_ARG_LEAVES, char_cap=MAX_RESULT_LEAF_CHARS,
                      truncate_long=True, normalise=_normalise_result_node)
    return [s for _, s in leaves]


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
