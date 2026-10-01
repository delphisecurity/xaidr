"""S22 — the ledger lock (D4, C-15, V-13), through the public interface only.

First-emission-wins is check-then-set, and the principal raise makes every
write a compare-then-set. Check-then-set races UNDER THE GIL too (D4: 525-574
of 15,000 keys written twice, measured on 3.12 and 3.14). So:

32 writer threads race opposite-origin first emissions — 16 untrusted (an
undesignated read), 16 trusted (a designated read) — of the same 1,000
authorities in the same order, each checking what it wrote, while 2 reader
threads call ``evaluate_call`` over them continuously. The property: NO READER EVER SEES AN AUTHORITY'S ORIGIN CHANGE
after it first became non-``unresolved``, and every authority's final origin is
the first one any reader saw. No ledger accessor is needed (§1 forbids one).
Principal emissions are excluded: a raise is a legitimate change.

The PR body pastes this test RED with ``_ledger._new_lock`` replaced by a no-op
lock in the source, and GREEN restored, on 3.12 and 3.14 locally; 3.10 and 3.11
run in CI's matrix.
"""
from __future__ import annotations

import contextvars
import sys
import threading

import pytest

from xaidr.value_origin import (
    MatchKind,
    SourceDesignation,
    bind_fresh_ledger,
    evaluate_call,
    record_tool_result,
    unbind_ledger,
)

N_AUTH = 1_000
N_WRITERS = 32
N_READERS = 2
BATCH = 50           # authorities per sweep call (≤ 64 leaves with the key)
TRUSTED = (SourceDesignation(tool="designated_read", match=MatchKind.ANY, label="race"),)


def race():
    """Run the race once; returns the list of violations (empty = the property held).

    Writers walk the authorities in the SAME order (D4's measurement set-up: a
    shared frontier is where check-then-set collides) and each evaluates the
    authority it just wrote, so a writer that overwrote another's first emission
    and the writer it overwrote both report what they saw. Two readers also
    sweep continuously. Every observation of every authority must agree.
    """
    auths = [f"u{i}@race.example" for i in range(N_AUTH)]
    holder = {}

    def setup():
        bind_fresh_ledger()
        holder["ctx"] = contextvars.copy_context()

    contextvars.copy_context().run(setup)
    flow = holder["ctx"]            # every thread runs in a copy of this: one shared ledger
    start = threading.Barrier(N_WRITERS + N_READERS)
    writers_done = threading.Event()
    seen = [[] for _ in range(N_WRITERS + N_READERS)]

    def observe(i, batch):
        v = evaluate_call("send_email", {"to": batch}, flow_active=True)
        for f in v.findings:
            if f.origin.value != "unresolved":
                seen[i].append((f.destination.value, f.origin.value))

    def writer(i):
        trusted = i % 2 == 0
        start.wait()
        for a in auths:
            record_tool_result("designated_read" if trusted else "undesignated_read",
                               {}, a, designations=TRUSTED, result_blocked=False)
            observe(i, [a])

    def reader(i):
        batches = [auths[j:j + BATCH] for j in range(0, N_AUTH, BATCH)]
        start.wait()
        while not writers_done.is_set():
            for b in batches:
                observe(i, b)
        for b in batches:
            observe(i, b)

    threads = [threading.Thread(target=flow.copy().run, args=(writer, i))
               for i in range(N_WRITERS)]
    threads += [threading.Thread(target=flow.copy().run, args=(reader, N_WRITERS + i))
                for i in range(N_READERS)]
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        for t in threads:
            t.start()
        for t in threads[:N_WRITERS]:
            t.join()
        writers_done.set()
        for t in threads[N_WRITERS:]:
            t.join()
    finally:
        sys.setswitchinterval(old)
    origins = {}
    for obs in seen:
        for k, o in obs:
            origins.setdefault(k, set()).add(o)
    violations = [f"{k}: observed as {sorted(v)}" for k, v in sorted(origins.items()) if len(v) > 1]
    if len(origins) != N_AUTH:
        violations.append(f"only {len(origins)} of {N_AUTH} authorities were ever "
                          "resolved — the race did not run as written")
    return violations


@pytest.fixture(autouse=True)
def _fresh_context():
    unbind_ledger()
    yield
    unbind_ledger()


def test_s22_no_reader_sees_a_first_emission_overwritten():
    violations = race()
    assert not violations, (
        f"S22: {len(violations)} origin change(s) observed under racing first "
        "emissions — the ledger let a second first-emission overwrite the first "
        "(check-then-set without the lock, D4). A laundered untrusted destination "
        "is exactly this:\n  " + "\n  ".join(violations[:10]))


UNITS = 160          # x 60 authorities = 9,600 digests, under the 10,000 cap
UNIT = 60
READERS = 4


def visibility_race():
    """C-15: "a read racing a multi-entry write must see all or none of that
    write". One writer records results of 60 fresh authorities each; readers
    evaluate the 60 of the result being written, continuously. Returns how many
    PARTIAL views (some but not all 60 resolved) any reader saw."""
    holder = {}

    def setup():
        bind_fresh_ledger()
        holder["ctx"] = contextvars.copy_context()

    contextvars.copy_context().run(setup)
    flow = holder["ctx"]
    units = [[f"n{u}k{k}@vis.example" for k in range(UNIT)] for u in range(UNITS)]
    current = [0]
    done = threading.Event()
    partial = []

    def writer():
        for u in range(UNITS):
            current[0] = u
            record_tool_result("undesignated_read", {}, units[u], designations=(),
                               result_blocked=False)

    def reader():
        while not done.is_set():
            u = current[0]
            v = evaluate_call("send_email", {"to": units[u]}, flow_active=True)
            n = sum(1 for f in v.findings if f.origin.value != "unresolved")
            if 0 < n < UNIT:
                partial.append(f"result {u}: a reader saw {n} of its {UNIT} authorities")

    readers = [threading.Thread(target=flow.copy().run, args=(reader,)) for _ in range(READERS)]
    w = threading.Thread(target=flow.copy().run, args=(writer,))
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-5)
    try:
        for t in readers:
            t.start()
        w.start()
        w.join()
        done.set()
        for t in readers:
            t.join()
    finally:
        sys.setswitchinterval(old)
    return partial


def test_s22_a_multi_entry_write_is_seen_all_or_none():
    """The lock's other half, and the reliable R4 detector: with the lock
    removed this goes red on every measured run (partial views seen), where the
    first-emission race above is caught only occasionally — its unlocked window
    is one _merge call inside a much longer extraction. Both are the same lock."""
    partial = visibility_race()
    assert not partial, (
        f"S22 (visibility): {len(partial)} partial view(s) of a single result's "
        "write — a lookup ran inside another thread's multi-entry write, so a "
        "reader could act on half a read (C-15: reads take the lock too):\n  "
        + "\n  ".join(partial[:10]))


if __name__ == "__main__":             # python -m ... for the R4 red-rate measurement
    runs = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    which = sys.argv[2] if len(sys.argv) > 2 else "visibility"
    fn = visibility_race if which == "visibility" else race
    red = 0
    for _ in range(runs):
        unbind_ledger()
        v = fn()
        red += bool(v)
        print(f"violations={len(v)}", (v[:1] or [""])[0])
    print(f"{sys.version.split()[0]} {which}: red in {red}/{runs} runs")
