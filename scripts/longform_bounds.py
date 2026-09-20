"""Measure the long-form pool by the WINDOW COUNT, not by how busy the box is.

WHY THIS MODULE EXISTS. `benign_longform/README.md` already carried the caveat
that made the gate on this pool unreliable:

    **The boundary is a wall-clock budget, not a length.** ... for anything
    between roughly 150 KB and 800 KB it is the clock that decides, not the
    window count. ... So the same document can be refused on a loaded host and
    allowed on an idle one.

That was written as a property an OPERATOR needs to know, which it is. It is
also a property a REGRESSION GATE cannot be built on, and building one on it
anyway is what turned six CI jobs red: on GitHub's runners — a loaded host —
every over-cap item blew `TOTAL_SCAN_BUDGET_SEC`, so no item was "over the cap
and fully read", and `test_oversized_and_tail_unread_are_different_signals`
failed its own vacuity guard. Correctly: on that machine the pool genuinely
could not tell the two signals apart. A 90 000-character item — UNDER the cap,
the control case — blew the separate 0.5 s rule-loop budget and was refused
under `bounds`, which is the false positive the group's design notes warn about,
observed in the wild.

The three bounds below are wall-clock, and a wall-clock bound measures the
MACHINE. The claim these tests exist to pin — that "this input is long" and "we
never read part of it" are different facts, and only the second is a bound fault
— is a property of the CODE. Pinning the clocks removes the machine from the
measurement so what is left is the code.

WHAT IS STILL UNDER TEST. Everything except the clock. `MAX_SCAN_WINDOWS` stays
at its shipped value, so the tail-unread case is still produced by the real
window cap on real input, and `_BOUND_SIGNAL_RULES` still decides the verdict.
What changes is that WHICH items land in which bucket stops depending on the
runner, and becomes a function of length and `MAX_SCAN_WINDOWS` alone — the two
things the manifest pins.

WHAT IS NO LONGER UNDER TEST, said plainly: the wall-clock degradation paths
(`LLM04_scan_budget_exceeded`, `LLM04_pathological_pattern`) do not fire under
this context manager. They are not measurable on this pool without measuring the
runner instead, and they have their own deterministic coverage in
`tests/test_truncation_bypass.py` and the ReDoS invariants.
"""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Large enough that no runner reaches it, finite so a genuine hang still ends.
_EFFECTIVELY_UNBOUNDED_SEC = 1e9


@contextmanager
def deterministic_scan_bounds():
    """Neutralise every wall-clock bound in the L1 scan for the duration.

    Restores the previous values on exit, including on exception, so a test
    using this cannot leak a relaxed bound into the rest of the session.
    """
    from xaidr.scanner import l1

    saved = (l1._L1_SCAN_BUDGET_SEC, l1._L1_RULE_SLOW_SEC)
    # `budget_sec` is a KEYWORD-ONLY DEFAULT, bound at def time, so patching the
    # module constant `TOTAL_SCAN_BUDGET_SEC` would do nothing — the callers in
    # scanner/local.py and sensor.py both invoke iter_scan_windows without it.
    kwdefaults = l1.iter_scan_windows.__kwdefaults__
    saved_budget = kwdefaults["budget_sec"]

    l1._L1_SCAN_BUDGET_SEC = _EFFECTIVELY_UNBOUNDED_SEC
    l1._L1_RULE_SLOW_SEC = _EFFECTIVELY_UNBOUNDED_SEC
    kwdefaults["budget_sec"] = _EFFECTIVELY_UNBOUNDED_SEC
    try:
        yield
    finally:
        l1._L1_SCAN_BUDGET_SEC, l1._L1_RULE_SLOW_SEC = saved
        kwdefaults["budget_sec"] = saved_budget


def windowed_coverage_limit() -> int:
    """Characters the windowed scan covers once the clock is not the bound.

    Derived from `iter_scan_windows`' own arithmetic rather than restated: the
    last window it yields starts at ``(max_windows - 1) * (window - overlap)``
    and covers ``window`` characters from there. Text longer than this has a
    tail nothing was run against, on every machine.
    """
    from xaidr.scanner.l1 import (
        L1_MAX_SCAN_CHARS, MAX_SCAN_WINDOWS, SCAN_WINDOW_OVERLAP,
    )

    step = max(1, L1_MAX_SCAN_CHARS - SCAN_WINDOW_OVERLAP)
    return (MAX_SCAN_WINDOWS - 1) * step + L1_MAX_SCAN_CHARS
