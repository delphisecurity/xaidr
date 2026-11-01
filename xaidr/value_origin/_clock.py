"""The time bound on reading one tool result.

A result's reading is bounded by work (``EXAMINED_WORK_BUDGET``, ``ATOM_WORK_BUDGET``)
and, because work units do not track time for every kind of text, by time as well:
``RESULT_TIME_BOUND_SECONDS`` of wall-clock time per result. The reader calls
``tick()`` in each of its loops, down to one host label; once the bound has passed,
``tick()`` raises ``TimeBound`` and the result is marked cut, so what it still held
cannot vouch (``_ledger._result_authorities``). The clock is read every
``_EVERY`` ticks, so the work past the bound is a few labels' worth.

Outside a result's reading no bound is set and ``tick()`` returns at once: an
argument, a principal input and host code are never bounded here. Host code the
reader calls (``model_dump()``, ``str()``) runs with the bound suspended, so it is
never interrupted, and its time counts against the bound once it returns.
"""
from __future__ import annotations

import time
from contextvars import ContextVar
from typing import Optional

_now = time.perf_counter
_EVERY = 64


class TimeBound(BaseException):
    """The result's time bound has passed. A BaseException, so no ``except
    Exception`` in the reading code can take it for a reading that failed."""


class _Bound:
    __slots__ = ("at", "n")

    def __init__(self, seconds: float) -> None:
        self.at = _now() + seconds
        self.n = 0


_BOUND: ContextVar[Optional[_Bound]] = ContextVar("xaidr_value_origin_result_bound",
                                                   default=None)


def tick() -> None:
    b = _BOUND.get()
    if b is None:
        return
    b.n += 1
    if b.n % _EVERY == 0 and _now() > b.at:
        raise TimeBound


def check() -> None:
    """Read the clock now (after host code returns)."""
    b = _BOUND.get()
    if b is not None and _now() > b.at:
        raise TimeBound


def start(seconds: float):
    return _BOUND.set(_Bound(seconds))


def suspend():
    return _BOUND.set(None)


def restore(token) -> None:
    _BOUND.reset(token)
