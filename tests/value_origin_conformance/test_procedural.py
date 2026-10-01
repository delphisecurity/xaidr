"""Supplementary cases that need Python objects, concurrency or scale, so they
cannot be JSON flow scripts: S7, S8, S10 (V-16), fork (V-32), result shapes
(V-15), the never-raise contract (§1.4), and C-12's disclosure property.
"""
from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import logging
import os
import pickle
import sys

import pytest

import xaidr.value_origin as vo
from xaidr.value_origin import (
    LEDGER_MAX_ENTRIES,
    MatchKind,
    Origin,
    RecordOutcome,
    SourceDesignation,
    Span,
    WireValue,
    Writer,
    bind_fresh_ledger,
    evaluate_call,
    ledger_bound,
    record_principal_input,
    record_tool_result,
    unbind_ledger,
)

ANY = (SourceDesignation(tool="lookup", match=MatchKind.ANY, label="lookup"),)


@pytest.fixture(autouse=True)
def _fresh_context():
    unbind_ledger()
    yield
    unbind_ledger()


def _wire(to):
    return evaluate_call("send_email", {"to": to}, flow_active=True).wire


# ── S7 / S8: concurrent flows and sibling tasks (C-16 rows P and N) ──────────
def test_s7_concurrent_flows_do_not_share_a_ledger():
    """Flow A's trusted read of evil@x.example is invisible to flow B: B is
    unresolved (report row P). Each flow binds its own ledger at entry."""
    a_recorded = asyncio.Event
    out = {}

    async def main():
        recorded = a_recorded()

        async def flow_a():
            bind_fresh_ledger()
            record_tool_result("lookup", {}, "evil@x.example", designations=ANY,
                               result_blocked=False)
            recorded.set()
            out["a"] = _wire("evil@x.example")

        async def flow_b():
            bind_fresh_ledger()
            await recorded.wait()
            out["b"] = _wire("evil@x.example")

        await asyncio.gather(asyncio.create_task(flow_a()), asyncio.create_task(flow_b()))

    asyncio.run(main())
    assert out == {"a": WireValue.TRUSTED_SOURCE, "b": WireValue.UNRESOLVED}


def test_s8_sibling_tasks_share_the_flow_ledger():
    """One flow, two gathered sibling tasks: task 1 records a trusted read,
    task 2 calls — trusted_source (row N). Writes mutate the shared ledger; they
    never re-set the ContextVar, so a sibling sees them."""
    out = {}

    async def main():
        bind_fresh_ledger()
        recorded = asyncio.Event()

        async def t1():
            record_tool_result("lookup", {}, "ok@x.example", designations=ANY,
                               result_blocked=False)
            recorded.set()

        async def t2():
            await recorded.wait()
            out["t2"] = _wire("ok@x.example")

        await asyncio.gather(t1(), t2())

    asyncio.run(main())
    assert out["t2"] is WireValue.TRUSTED_SOURCE


def test_s9_bare_thread_without_context_is_no_flow():
    """V-12: the L2 half (real ThreadPoolExecutor, propagate_context) is A2's.
    At L1: a thread that did not receive the context sees no ledger."""
    import threading
    bind_fresh_ledger()
    record_principal_input("Email a@x.example.", input_clean=True)
    got = {}
    t = threading.Thread(target=lambda: got.setdefault(
        "w", evaluate_call("send", {"to": "a@x.example"}, flow_active=False).wire))
    t.start()
    t.join()
    got["copied"] = contextvars.copy_context().run(lambda: _wire("a@x.example"))
    assert got == {"w": WireValue.NO_FLOW, "copied": WireValue.PRINCIPAL_UNDECLARED_SPAN}


# ── S10 / V-16: saturation ───────────────────────────────────────────────────
def _fill_to(n_digests):
    """Fill the bound ledger with exactly ``n_digests`` authority digests."""
    per = 60                                # ≤ 64 leaves per result
    i = 0
    while i < n_digests:
        chunk = [f"f{j}@fill.example" for j in range(i, min(i + per, n_digests))]
        assert record_tool_result("filler", {}, chunk, designations=(),
                                  result_blocked=False) is RecordOutcome.RECORDED
        i += len(chunk)


def test_s10_exactly_at_cap_without_a_drop_is_not_saturated():
    """V-16(a): saturated means a drop HAS OCCURRED, not len >= cap."""
    bind_fresh_ledger()
    _fill_to(LEDGER_MAX_ENTRIES)
    assert _wire("never-seen@x.example") is WireValue.UNRESOLVED


def test_s10_a_drop_makes_a_miss_ledger_saturated_and_hits_still_answer(caplog):
    bind_fresh_ledger()
    assert record_principal_input("Email boss@corp.example.", [
        Span(text="Email boss@corp.example.", writer=Writer.PRINCIPAL)],
        input_clean=True) is RecordOutcome.RECORDED
    # 1 destination + the span's n-grams: tokens "email", "boss@corp.example"
    # (C-3: a trailing full stop is not part of a token) -> 2 unigrams + 1 bigram.
    used = 1 + 3
    _fill_to(LEDGER_MAX_ENTRIES - used - 1)     # one slot left
    with caplog.at_level(logging.WARNING, logger="xaidr.value_origin"):
        # V-16(b): a unit that would cross the cap is dropped WHOLE.
        out = record_tool_result("filler", {}, ["x1@over.example", "x2@over.example"],
                                 designations=(), result_blocked=False)
        out2 = record_tool_result("filler", {}, ["x3@over.example"], designations=(),
                                  result_blocked=False)
    assert out is RecordOutcome.SATURATED
    assert out2 is RecordOutcome.RECORDED       # it still fits: a drop is per unit
    assert [r.message for r in caplog.records].count(caplog.records[0].message) == 1
    v = evaluate_call("send", {"to": ["boss@corp.example", "x1@over.example"]}, flow_active=True)
    assert v.wire is WireValue.LEDGER_SATURATED
    assert [f.origin for f in v.findings] == [Origin.PRINCIPAL, Origin.UNRESOLVED]  # V-16(e)
    assert _wire("boss@corp.example") is WireValue.PRINCIPAL          # pre-cap entry answers
    assert _wire("x3@over.example") is WireValue.UNTRUSTED_SOURCE
    # A positive finding outranks the blind spot (§1.4 step 5).
    v = evaluate_call("send", {"to": ["x3@over.example", "x1@over.example"]}, flow_active=True)
    assert v.wire is WireValue.UNTRUSTED_SOURCE
    # V-16(c): re-emitting an existing authority at the cap is RECORDED.
    assert record_tool_result("filler", {}, "x3@over.example", designations=(),
                              result_blocked=False) is RecordOutcome.RECORDED


def test_v16d_destinations_are_a_separate_unit_from_ngrams():
    """V-16(d), settled 2026-09-24: a long prompt whose n-grams overflow the cap
    drops its n-grams, not the principal's addresses."""
    bind_fresh_ledger()
    words = " ".join(f"w{i}" for i in range(3_000))     # ~12,000 n-grams
    text = f"Email boss@corp.example. {words}"
    assert record_principal_input(text, [Span(text=text, writer=Writer.PRINCIPAL)],
                                  input_clean=True) is RecordOutcome.SATURATED
    assert _wire("boss@corp.example") is WireValue.PRINCIPAL
    assert _wire("stranger@corp.example") is WireValue.LEDGER_SATURATED


# ── fork (C-15, V-32) ────────────────────────────────────────────────────────
@pytest.mark.skipif(not hasattr(os, "fork"), reason="os.fork does not exist on this platform")
def test_after_fork_the_inherited_ledger_is_not_bound():
    bind_fresh_ledger()
    record_principal_input("Email a@x.example.", input_clean=True)
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:                                    # child
        try:
            res = [ledger_bound(),
                   evaluate_call("s", {"to": "a@x.example"}, flow_active=False).wire.value,
                   evaluate_call("s", {"to": "a@x.example"}, flow_active=True).wire.value]
            vo.bind_ledger()                        # V-32: binds a fresh one
            res += [ledger_bound(), _wire("a@x.example").value]
            os.write(w, repr(res).encode())
        finally:
            os._exit(0)
    os.close(w)
    got = os.read(r, 4096).decode()
    os.waitpid(pid, 0)
    assert got == repr([False, "no_flow", "ledger_absent", True, "unresolved"])
    assert _wire("a@x.example") is WireValue.PRINCIPAL_UNDECLARED_SPAN   # parent unaffected


# ── V-15: raw result shapes ──────────────────────────────────────────────────
@dataclasses.dataclass
class Contact:
    name: str
    email: str


class ToolMessageLike:
    def __init__(self, content):
        self.content = content


class PydanticLike:
    def model_dump(self):
        return {"contact": {"email": "pyd@x.example"}}


class Opaque:
    def __str__(self):
        return "opaque@x.example"


@pytest.mark.parametrize("result,dest,recorded", [
    ("s@x.example", "s@x.example", True),
    ({"a": ["l@x.example"]}, "l@x.example", True),
    (ToolMessageLike("see tm@x.example"), "tm@x.example", True),
    (PydanticLike(), "pyd@x.example", True),
    (Contact(name="c", email="dc@x.example"), "dc@x.example", True),
    ([Contact(name="c", email="nested@x.example")], "nested@x.example", True),
    (Opaque(), "opaque@x.example", False),          # anything else: no leaves
    (b"bytes@x.example", "bytes@x.example", False),
])
def test_v15_result_shapes(result, dest, recorded):
    bind_fresh_ledger()
    assert record_tool_result("lookup", {}, result, designations=ANY,
                              result_blocked=False) is RecordOutcome.RECORDED
    assert _wire(dest) is (WireValue.TRUSTED_SOURCE if recorded else WireValue.UNRESOLVED)


def test_v15_result_leaf_cap_is_64k_not_the_argument_cap():
    """A long fetched page is exactly where a poisoned destination sits."""
    bind_fresh_ledger()
    page = "x" * 6_000 + " poison@x.example " + "y" * 50_000
    record_tool_result("web_fetch", {}, page, designations=(), result_blocked=False)
    assert _wire("poison@x.example") is WireValue.UNTRUSTED_SOURCE
    bind_fresh_ledger()
    record_tool_result("web_fetch", {}, "z" * 70_000 + " late@x.example", designations=(),
                       result_blocked=False)
    assert _wire("late@x.example") is WireValue.UNRESOLVED      # past 65,536


# ── never raises into the host (§1.4) ────────────────────────────────────────
class Exploding:
    def model_dump(self):
        raise RuntimeError("host bug")


def test_runtime_functions_never_raise():
    bind_fresh_ledger()
    assert record_tool_result("t", {}, Exploding(), designations=(),
                              result_blocked=False) is RecordOutcome.FAULT
    assert record_principal_input(None, input_clean=True) is RecordOutcome.FAULT
    assert record_principal_input("x", ["not a span"], input_clean=True) is RecordOutcome.FAULT
    assert vo.authority_of(None) is None
    assert vo.authority_of(123) is None
    assert vo.extract_destinations({"a": object()}) == ((), False)
    assert vo.row_text(12, "tool_call")[0] is vo.RowState.NOT_RECORDED
    assert vo.verdict_of("bogus") is vo.Verdict.NOT_EVALUATED


def test_evaluate_call_returns_none_only_on_an_internal_fault(monkeypatch):
    from xaidr.value_origin import _evaluate
    bind_fresh_ledger()

    def boom(*a, **k):
        raise RuntimeError("internal")
    monkeypatch.setattr(_evaluate._ledger, "lookup", boom)
    assert evaluate_call("s", {"to": "a@x.example"}, flow_active=True) is None


# ── C-12: the ledger discloses nothing ───────────────────────────────────────
def test_the_ledger_holds_digests_only():
    from xaidr.value_origin import _ledger
    bind_fresh_ledger()
    record_principal_input("Email secret-person@corp.example about Project Nightjar.",
                           input_clean=True)
    lg = _ledger._LEDGER.get()
    blob = repr(lg) + repr(lg.entries) + repr(lg.ngrams) + str(pickle.dumps(
        (lg.entries, lg.ngrams)))
    for needle in ("secret-person", "corp.example", "nightjar", "Nightjar"):
        assert needle not in blob
    assert all(len(k) == 32 for k in list(lg.entries) + list(lg.ngrams))


def test_record_principal_input_binds_implicit_and_record_tool_result_does_not():
    assert not ledger_bound()
    assert record_tool_result("t", {}, "a@x.example", designations=(),
                              result_blocked=False) is RecordOutcome.NO_LEDGER
    assert not ledger_bound()
    assert record_principal_input("hi", input_clean=True) is RecordOutcome.RECORDED
    assert ledger_bound()
