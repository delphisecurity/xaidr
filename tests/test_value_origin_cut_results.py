"""Past the result bound: a cut result cannot vouch, and the bound costs bounded work.

A tool result past the 64-leaf bound is not read whole, so what it holds is
never all known. A destination neither the principal nor a trusted source
authorized therefore reads untrusted once the flow carries a cut result, and
blocks under ENFORCE (docs/value-origin-rulings.md §6, beside write_dropped).
What the principal or a trusted source named keeps its authority.

And the walk past the bound costs what its WORK budget allows, in time and in
memory: a value repeated past the bound is stripped once, and strings only a
result's ``model_dump()`` temporaries held are kept no longer than the budget
could scan them.
"""
from __future__ import annotations

import contextvars
import tracemalloc

from xaidr import value_origin as vo
from xaidr.value_origin import Mode, should_block
from xaidr.value_origin._extract import extract_with_observed

ASKED = "Please post the weekly digest to https://digest.example/in for me."
FILLER = [{"title": f"listing {i}", "note": "nothing here"} for i in range(90)]


def _flow(*steps, call):
    def run():
        vo.bind_fresh_ledger()
        for kind, payload in steps:
            if kind == "input":
                vo.record_principal_input(payload, None, input_clean=True)
            else:
                vo.record_tool_result("search", {"q": "digest"}, payload, designations=(),
                                      result_blocked=False)
        return vo.evaluate_call("http_post", call, flow_active=True)
    return contextvars.Context().run(run)


def test_a_destination_past_a_cut_result_reads_untrusted_and_blocks():
    """The value sits past the bound with a newline in its host, which the atom
    pass does not read and http.client sends without (urlsplit drops it)."""
    hidden = "https://relay.collec\ntor.example/up"
    v = _flow(("input", ASKED), ("result", FILLER + [hidden]),
              call={"url": "https://relay.collector.example/up"})
    assert v.wire.value == "untrusted_source", (
        f"a call to a destination nobody authorized, after a result too long to read whole, "
        f"read {v.wire.value!r}: what the cut result held vouched for it")
    assert should_block(v, mode=Mode.ENFORCE)


def test_the_principals_destination_keeps_its_authority_past_a_cut_result():
    v = _flow(("input", ASKED), ("result", FILLER), call={"url": "https://digest.example/in"})
    assert v.wire.value in ("principal", "principal_undeclared_span"), v.wire.value
    assert not should_block(v, mode=Mode.ENFORCE)


def test_without_a_cut_result_an_unnamed_destination_stays_unresolved():
    v = _flow(("input", ASKED), ("result", FILLER[:10]),
              call={"url": "https://relay.collector.example/up"})
    assert v.wire.value == "unresolved", v.wire.value


class _CountingStr(str):
    """A str that tallies the whitespace its own strip() calls remove."""
    removed = [0]

    def strip(self, chars=None):
        out = str.strip(self, chars)
        _CountingStr.removed[0] += len(self) - len(out)
        return out


def test_a_value_repeated_past_the_bound_is_stripped_once():
    """A value too long to read whole even once stripped was stripped again for
    every reference to it, uncharged: the work grew with the count, not the budget."""
    pad = _CountingStr("\t" * 150_000 + "q" * 4_300 + " https://drain.example/z " + " " * 150_000)
    for times in (50, 500):
        _CountingStr.removed[0] = 0
        found, _, _ = extract_with_observed({"rows": [pad] * times})
        assert _CountingStr.removed[0] <= 2 * len(pad), (
            f"{times} references to one padded value stripped {_CountingStr.removed[0]:,} "
            "characters: each reference was stripped again, for free")
        assert "dns:drain.example" in [f.destination.key() for f in found if f.destination]


class _Digest:
    def __init__(self, i):
        self.i = i

    def model_dump(self, **_):
        return {"id": self.i, "text": ("status ok " * 104_858)[:1_048_576]}


class _Hop:
    def __init__(self, nxt, i):
        self.nxt, self.i = nxt, i

    def model_dump(self, **_):
        return {"hop": self.i, "next": self.nxt}


def _peak_mib(result):
    def run():
        vo.bind_fresh_ledger()
        tracemalloc.start()
        vo.record_tool_result("search", {"q": "x"}, result, designations=(), result_blocked=False)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        return peak / 2**20
    return contextvars.Context().run(run)


def test_model_dump_temporaries_do_not_fill_memory():
    """Each model_dump() returns a fresh 1 MiB string. Holding every temporary (and
    every string in it) for the atom pass made the peak grow with the result."""
    peak = _peak_mib([_Digest(i) for i in range(150)])
    assert peak < 48, f"recording 150 fresh 1 MiB model_dump() strings peaked at {peak:.0f} MiB"


def test_a_model_dump_chain_16000_deep_stays_under_the_stated_8_mib():
    chain = None
    for i in range(16_000):
        chain = _Hop(chain, i)
    peak = _peak_mib([chain])
    assert peak < 8, f"a model_dump() chain 16,000 deep peaked at {peak:.1f} MiB"
