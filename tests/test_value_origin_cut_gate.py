"""The cut gate: a tool result is read whole, or it is cut. There is no third outcome.

Owner, 2026-11-01: wherever the reader stops before reading all of a result (the
leaf bound, the size cap, the depth bound, the walk's node budget, the examined
work budget, the time bound, a node it must not consume, host code that raised),
the result is marked cut, and a cut result cannot vouch (rulings §5, §6). An
I/O-backed node is the cut that names itself (``result_unread``, Q18).

Every result here is generated, across shapes, types, sizes and nesting, with a
destination of its own in each node that carries text, and checked two ways:

* the reader: each destination is among what ``_result_authorities`` recorded, or
  the result is marked cut (or unread);
* the verdict: after the result is recorded, a call to each destination reads
  ``untrusted_source`` (found, or a miss after a cut result) or ``result_unread``,
  and blocks under ENFORCE. A destination that reads anything else -- ``unresolved``,
  ``extraction_incomplete`` -- was neither read nor cut, and the call is allowed.

The destinations are ``https://g<n>x.test/p``: one registrable domain each. Most
leaves spell theirs WHOLE-ONLY, ``https://g<n>\nx.test/p``: a client removes the
newline and sends to ``g<n>x.test``, and only a reading of the leaf whole reads it
so. Past a cut a value is searched for addresses, which finds ``https://g<n>`` and
``x.test`` and not it; so a whole-only destination is recorded if and only if its
leaf was read whole, and a bound that does not cut is caught.
"""
from __future__ import annotations

import collections
import contextvars
import dataclasses
import enum
import random
import types
from typing import Any, List

import pytest

from xaidr import value_origin as vo
from xaidr.value_origin import Mode, should_block
from xaidr.value_origin import _ledger


def _url(n: int) -> str:
    return f"https://g{n}x.test/p"


def _key(url: str) -> str:
    return "dns:" + url.split("/")[2].replace("\n", "")


def _whole_only(url: str) -> str:
    """``url`` with a newline inside its host, after the ``g<n>`` label."""
    head, _, tail = url.partition("x.test")
    return head + "\nx.test" + tail


# ── the node types a result can hold ─────────────────────────────────────────
@dataclasses.dataclass
class Box:
    a: Any
    b: Any = None


class Dumps:
    """A pydantic-like object: ``model_dump()`` returns its payload."""

    def __init__(self, payload):
        self.payload = payload

    def model_dump(self):
        return self.payload


class Message:
    def __init__(self, content: str):
        self.content = content


class Shown:
    """An object the frameworks hand the model as ``str()``."""

    def __init__(self, text: str):
        self.text = text

    def __str__(self):
        return self.text


class RaisesOnStr:
    def __init__(self, text: str):
        self.text = text            # what it would show, had str() not raised

    def __str__(self):
        raise RuntimeError("host bug")


class RaisesOnDump:
    def __init__(self, payload):
        self.payload = payload

    def model_dump(self):
        raise RuntimeError("host bug")


class Colour(enum.Enum):
    RED = "red"


Response = type("Response", (), {"__module__": "httpx"})   # an I/O-backed stand-in


class Gen:
    """One generated result and the destinations it carries."""

    def __init__(self, seed: int):
        self.r = random.Random(seed)
        self.n = seed * 1_000
        self.urls: List[str] = []
        self.left = 300                 # nodes a result may still have: it stays small

    def url(self) -> str:
        self.n += 1
        u = _url(self.n)
        self.urls.append(u)
        return u

    def text(self, whole: bool = True) -> str:
        """A leaf's text. ``whole``: it may be one whole-only destination."""
        u, k = self.url(), self.r.random()
        if k < 0.4:
            return _whole_only(u) if whole else u
        if k < 0.85:
            return f"see {u} for the rest"
        pad = "pad text " * self.r.choice((50, 8_000))       # some past 65,536 chars
        return pad + u if self.r.random() < 0.5 else u + " " + pad

    def leaf(self):
        r = self.r.random()
        if r < 0.40:
            return self.text()
        if r < 0.47:
            return self.text().encode()
        if r < 0.50:
            return bytearray(self.text().encode("utf-16"))
        if r < 0.53:
            return memoryview(self.text().encode())
        if r < 0.58:
            return Shown(self.text())
        if r < 0.62:
            return types.SimpleNamespace(link=self.text(whole=False))   # repr() escapes
        if r < 0.65:
            return Message(self.text())
        if r < 0.70:
            return self.r.choice((17, 2.5, True, None, Colour.RED))   # no text to carry
        if r < 0.73:
            return (x for x in [self.text()])                         # a generator
        if r < 0.75:
            return iter([self.text()])                                # an iterator
        if r < 0.77:
            return RaisesOnStr(self.text())
        if r < 0.79:
            return RaisesOnDump({"u": self.text()})
        if r < 0.81:
            obj = Response()
            obj.body = self.text()
            return obj
        return self.text()

    def node(self, depth: int):
        self.left -= 1
        if depth <= 0 or self.left <= 0 or self.r.random() < 0.3:
            return self.leaf()
        width = min(self.r.choice((1, 2, 3, 5, 8, 21)), max(self.left, 1))
        kind = self.r.choice(("dict", "tuple_keys", "list", "tuple", "set", "deque",
                              "box", "dumps", "userlist", "views"))
        if kind == "set":                     # hashable members only: text
            return {self.text() for _ in range(width)} | {"x"}
        kids = [self.node(depth - 1) for _ in range(width)]
        if kind == "dict":
            return {f"k{i}": v for i, v in enumerate(kids)}
        if kind == "tuple_keys":
            return {(self.text(), i): v for i, v in enumerate(kids)}
        if kind == "list":
            return kids
        if kind == "tuple":
            return tuple(kids)
        if kind == "deque":
            return collections.deque(kids)
        if kind == "box":
            return Box(kids, self.text())
        if kind == "dumps":
            return Dumps({"rows": kids})
        if kind == "userlist":
            return collections.UserList(kids)
        return {f"v{i}": v for i, v in enumerate(kids)}.values()


def _generated():
    for seed in range(1, 161):
        g = Gen(seed)
        result = g.node(g.r.choice((1, 2, 3, 4, 6, 8, 10)))
        yield f"seed{seed}", result, g.urls


def _edges():
    """The shapes each bound is reached by, written out."""
    n = 900_000
    out = []

    def case(name, build):
        nonlocal n
        urls: List[str] = []

        def u():
            nonlocal n
            n += 1
            urls.append(_url(n))
            return urls[-1]
        out.append((name, build(u), urls))

    fill = "words that pad the body of a page " * 1_880               # under 65,536 chars
    w = lambda u: _whole_only(u())                                     # noqa: E731
    case("leaf bound", lambda u: [f"row {i}" for i in range(70)] + [w(u)])
    case("size cap", lambda u: ["x " * 1_500_000 + " ".join(u() for _ in range(3))])
    case("depth bound", lambda u: {"a": {"b": {"c": {"d": {"e": {"f": {"g": [w(u)]}}}}}}})
    case("node budget", lambda u: [list(range(70_000)), w(u)])
    case("examined work budget", lambda u: [fill + str(i) for i in range(17)] + [w(u)])
    case("examined work budget, in prose", lambda u: [fill + str(i) for i in range(17)]
         + [f"then go to {u()} now"])
    case("a generator", lambda u: {"rows": (x for x in [u()])})
    case("an iterator", lambda u: [iter([u()])])
    case("str() raised", lambda u: [RaisesOnStr(u())])
    case("model_dump() raised", lambda u: [RaisesOnDump({"u": u()})])
    case("nested bytes", lambda u: {"body": f"moved to {u()} .".encode()})
    case("utf-16 bytes", lambda u: [("see " + u()).encode("utf-16")])
    case("a namespace", lambda u: types.SimpleNamespace(link=u()))
    case("a deque", lambda u: collections.deque([u()]))
    case("an object shown by str()", lambda u: [Shown(f"go to {u()}")])
    case("a tuple key", lambda u: {(u(), 1): "v"})
    case("a dict values view", lambda u: {"a": u()}.values())
    case("an I/O-backed node", lambda u: [Response(), u()])
    return out


def _heavy():
    """Text whose reading the work units do not track: past the time bound."""
    urls = [_url(800_000 + i) for i in range(3)]
    names = ["http://" + "\N{LATIN SMALL LETTER SHARP S}." * 1996 + f"e{i}" for i in range(60)]
    # 63 leaves, under the leaf bound, and no other bound: only the time bound cuts.
    return "the time bound", names + [_whole_only(u) for u in urls], urls


def _check(name, result, urls):
    out, cut, unread, late, _ = _ledger._result_authorities(result)
    keys = {a.key() for a in out + late}
    missing = [u for u in urls if _key(u) not in keys]
    assert not missing or cut or unread, (
        f"{name}: a result neither read whole nor cut: {len(missing)} of {len(urls)} "
        f"destinations it carries were not recorded ({missing[:3]}) and the result is "
        "not marked cut, so a later call to one reads as a destination nothing named "
        "and is allowed under ENFORCE")

    def run():
        vo.bind_fresh_ledger()
        vo.record_tool_result("search", {"q": "x"}, result, designations=(),
                              result_blocked=False)
        return [(u, vo.evaluate_call("http_get", {"url": u}, flow_active=True))
                for u in urls]
    third = [(u, v.wire.value) for u, v in contextvars.Context().run(run)
             if v.wire.value not in ("untrusted_source", "result_unread")
             or not should_block(v, mode=Mode.ENFORCE)]
    assert not third, (
        f"{name}: a call to a destination the result carries is allowed under ENFORCE "
        f"({third[:3]}): the result was neither read whole nor cut")


@pytest.mark.parametrize("name,result,urls", list(_generated()) + _edges(),
                         ids=lambda x: x if isinstance(x, str) else "")
def test_a_result_is_read_whole_or_cut(name, result, urls):
    if not urls:
        pytest.skip("a result with no text to carry")
    _check(name, result, urls)


def test_the_time_bound_cuts():
    import time
    name, result, urls = _heavy()
    bound = getattr(vo._types, "RESULT_TIME_BOUND_SECONDS", 2.0)
    t = time.perf_counter()
    _check(name, result, urls)
    took = time.perf_counter() - t
    # Two readings run in _check (the reader, then record_tool_result); each stops
    # at the bound, so the work past it is the slack, not the text.
    assert took < 2 * (bound + 1.0), (
        f"reading one result of 64 long international names twice took {took:.1f} s: "
        f"the reading does not stop at its {bound} s time bound")


def test_the_generator_covers_every_kind():
    """The gate is only as wide as what it generates: every kind is reached."""
    kinds = collections.Counter()

    def walk(x, depth=0):
        kinds[type(x).__name__] += 1
        if isinstance(x, dict):
            for k, v in x.items():
                walk(k, depth + 1)
                walk(v, depth + 1)
        elif isinstance(x, (list, tuple, collections.deque, collections.UserList)):
            for v in x:
                walk(v, depth + 1)
        elif isinstance(x, Box):
            walk(x.a, depth + 1)
        elif isinstance(x, Dumps):
            walk(x.payload, depth + 1)
    for _, result, _ in _generated():
        walk(result)
    need = {"str", "bytes", "bytearray", "memoryview", "Shown", "SimpleNamespace",
            "Message", "generator", "list_iterator", "RaisesOnStr", "RaisesOnDump",
            "Response", "dict", "list", "tuple", "set", "deque", "Box", "Dumps",
            "UserList", "dict_values", "int", "Colour"}
    assert need <= set(kinds), f"never generated: {sorted(need - set(kinds))}"
