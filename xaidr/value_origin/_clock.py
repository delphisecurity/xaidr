"""The work limit on reading one tool result, and its wall-clock backstop.

A result's reading is bounded by work (``EXAMINED_WORK_BUDGET``, ``ATOM_WORK_BUDGET``)
and, because those units do not count the work some text takes (a long non-ASCII
host is encoded label by label, for every encoder and case reading), by a meter
as well: ``RESULT_READ_UNITS`` per result. The reader charges it in each of its
loops, down to one host label, in proportion to the work done there; once it is
spent, ``charge()`` raises ``WorkBound`` and the result is cut. The meter counts
work, never time, so the same result is cut at the same place on every machine,
idle or loaded.

``RESULT_TIME_BACKSTOP_SECONDS`` of wall-clock time is the backstop, set far above
the documented worst case of the meter, for work no unit counts (host code the
reader calls, a machine stalled outright). It raises ``TimeBackstop``; the result
is cut and the ledger records that the backstop fired, so a call that reads past
it says so on its event (``CallVerdict.backstop``), distinct from the work limit.
The clock is read every ``_EVERY`` charges.

Outside a result's reading no meter is set and ``charge()`` returns at once: an
argument, a principal input and host code are never metered here. Host code the
reader calls (``model_dump()``, ``str()``) runs with the meter suspended, and only
the backstop sees its time.
"""
from __future__ import annotations

import time
from contextvars import ContextVar
from typing import Optional

_now = time.perf_counter
_EVERY = 64
#: What one host label costs to read beyond its characters (validation, the
#: normalization check, one encoder's pass), in the meter's units: measured, so a
#: result of many short labels is charged as a result of few long ones is.
LABEL_UNITS = 256


class WorkBound(BaseException):
    """The result's work limit is spent. A BaseException, so no ``except
    Exception`` in the reading code can take it for a reading that failed."""


class TimeBackstop(BaseException):
    """The result's wall-clock backstop fired (see the module docstring)."""


class _Meter:
    __slots__ = ("left", "at", "n")

    def __init__(self, units: int, seconds: float) -> None:
        self.left = units
        self.at = _now() + seconds
        self.n = 0


_METER: ContextVar[Optional[_Meter]] = ContextVar("xaidr_value_origin_result_meter",
                                                   default=None)


def charge(units: int = 1) -> None:
    m = _METER.get()
    if m is None:
        return
    m.left -= units
    if m.left < 0:
        raise WorkBound
    m.n += 1
    if m.n % _EVERY == 0 and _now() > m.at:
        raise TimeBackstop


def tick() -> None:
    charge(1)


def check() -> None:
    """Read the clock now (after host code returns)."""
    m = _METER.get()
    if m is not None and _now() > m.at:
        raise TimeBackstop


def start(units: int, seconds: float):
    return _METER.set(_Meter(units, seconds))


def suspend():
    return _METER.set(None)


def restore(token) -> None:
    _METER.reset(token)
