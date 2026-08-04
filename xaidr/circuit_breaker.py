"""Opt-in circuit breaker for the xaidr sensor.

The sensor's normal discipline is fail-OPEN: an internal fault returns a safe
``allowed`` and never takes the host agent down. This module is the deliberate
exception — when it trips it HALTS the agent. That inversion is why it is
entirely opt-in (``circuit_breaker=None``, the default, is a no-op) and why every
code path here is itself wrapped so a fault inside the breaker degrades to "no
breaker" rather than breaking a scan.

What it counts, and nothing more:

* **Violations** — verdicts whose TRUE (pre-downgrade) action is ``blocked``.
  "True" is load-bearing: in monitor mode a block-worthy verdict is downgraded to
  ``flagged`` before the caller sees it, so a breaker that counted the RETURNED
  action could never trip in monitor mode, defeating measure-before-enforcing.
* **Tool-call rate** — ``scan_tool_call`` invocations only. A merely chatty agent
  making many ``scan()`` calls must not trip it.

It does NOT model "erratic", anomalous, or novel behavior. Two counters.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional

logger = logging.getLogger("xaidr.circuit_breaker")

# Verdict surfaced by every scan while the circuit is open in block mode.
CIRCUIT_OPEN_CATEGORY = "circuit_breaker_open"
CIRCUIT_OPEN_RULE = "CIRCUIT_BREAKER_OPEN"

# Trip reasons (also the value of the "reason" key handed to on_trip).
REASON_VIOLATIONS = "violation_threshold"
REASON_RATE = "rate_threshold"

# Hard cap on retained timestamps per counter. Timestamps are pruned to the
# window on every access; this cap is the second, independent bound so a
# high-volume agent cannot grow the deques without limit between prunes (and so
# a misconfigured enormous window is still bounded). No background thread.
_MIN_RETAINED = 4096


@dataclass
class CircuitBreaker:
    """Circuit-breaker configuration. Passed to ``Sensor(circuit_breaker=...)``.

    A trigger with a ``None`` threshold is DISABLED, so you can configure the
    violation trigger, the rate trigger, or both. Either one alone opens the
    circuit.

    Args:
        violation_threshold: open after this many blocked verdicts within
            ``violation_window_sec``. None disables the violation trigger.
        violation_window_sec: sliding window for the violation count.
        rate_threshold: open after this many ``scan_tool_call`` invocations
            within ``rate_window_sec``. None disables the rate trigger.
        rate_window_sec: sliding window for the tool-call count.
        cooldown_sec: auto-close this long after the trip. ``None`` means the
            circuit stays open until ``reset_circuit()`` — the kill-switch form.
            There is no half-open state.
        on_trip: called EXACTLY ONCE per trip with one dict argument:
            ``{"reason", "violations", "tool_calls", "agent_id",
            "enforcement_mode"}``. Exceptions raised by the callback are logged
            and swallowed — your callback cannot take the agent down.
        time_source: monotonic clock, injectable for testing. Defaults to
            ``time.monotonic``. Must be monotonic: a wall-clock jump would
            corrupt the windows.
    """

    violation_threshold: Optional[int] = None
    violation_window_sec: float = 60.0
    rate_threshold: Optional[int] = None
    rate_window_sec: float = 60.0
    cooldown_sec: Optional[float] = 300.0
    on_trip: Optional[Callable] = None
    time_source: Callable[[], float] = time.monotonic

    def __post_init__(self):
        for name in ("violation_threshold", "rate_threshold"):
            val = getattr(self, name)
            if val is not None and (not isinstance(val, int) or val < 1):
                raise ValueError(f"{name} must be a positive int or None, got {val!r}")
        for name in ("violation_window_sec", "rate_window_sec"):
            val = getattr(self, name)
            if val is None or float(val) <= 0:
                raise ValueError(f"{name} must be > 0, got {val!r}")
        if self.cooldown_sec is not None and float(self.cooldown_sec) < 0:
            raise ValueError(
                f"cooldown_sec must be >= 0 or None, got {self.cooldown_sec!r}"
            )
        if self.on_trip is not None and not callable(self.on_trip):
            raise ValueError("on_trip must be callable or None")
        if not callable(self.time_source):
            raise ValueError("time_source must be callable")

    @property
    def enabled(self) -> bool:
        """True when at least one trigger is configured."""
        return self.violation_threshold is not None or self.rate_threshold is not None


@dataclass
class _Counters:
    """Retained timestamps for one sliding window, pruned on access."""

    window_sec: float
    maxlen: int
    stamps: deque = field(default_factory=deque)

    def __post_init__(self):
        self.stamps = deque(maxlen=self.maxlen)

    def add(self, now: float) -> int:
        self.stamps.append(now)
        return self.count(now)

    def count(self, now: float) -> int:
        cutoff = now - self.window_sec
        stamps = self.stamps
        # Prune from the left: the deque is append-ordered, so everything at the
        # front is oldest. Bounded work amortized over appends.
        while stamps and stamps[0] < cutoff:
            stamps.popleft()
        return len(stamps)

    def clear(self) -> None:
        self.stamps.clear()


class _CircuitRuntime:
    """Mutable breaker state for one sensor. Lock-guarded; no background thread.

    Every mutation and read goes through ``self._lock`` (an RLock, so the trip
    path can call back into ``_snapshot`` while holding it). The sensor is used
    concurrently, so a torn read of {state, counters} would be a real bug.
    """

    def __init__(self, config: CircuitBreaker, agent_id: str, enforcement_mode: str):
        self.config = config
        self.agent_id = agent_id
        self.enforcement_mode = enforcement_mode
        self._lock = threading.RLock()
        self._open = False
        self._opened_at: Optional[float] = None
        self._trip_reason: Optional[str] = None
        self._violations = _Counters(
            window_sec=float(config.violation_window_sec),
            maxlen=_retained_cap(config.violation_threshold),
        )
        self._tool_calls = _Counters(
            window_sec=float(config.rate_window_sec),
            maxlen=_retained_cap(config.rate_threshold),
        )

    # ── clock ────────────────────────────────────────────────────────────
    def _now(self) -> float:
        return float(self.config.time_source())

    # ── state ────────────────────────────────────────────────────────────
    def state(self) -> str:
        """Current state, applying an elapsed cooldown first.

        Returns "closed" or "open". Reading the state is what advances an
        expired cooldown, so there is no background timer.
        """
        with self._lock:
            closed_event = self._maybe_cooldown(self._now())
        if closed_event is not None:
            self._emit(closed_event)
        return "open" if self._open else "closed"

    def _maybe_cooldown(self, now: float) -> Optional[dict]:
        """Close the circuit if the cooldown has elapsed. Caller holds the lock.

        Returns the close event to emit (outside the lock), or None.
        """
        if not self._open:
            return None
        cooldown = self.config.cooldown_sec
        if cooldown is None:
            return None  # kill-switch form: only reset_circuit() closes it
        if self._opened_at is None or (now - self._opened_at) < float(cooldown):
            return None
        return self._close_locked(now, "cooldown_elapsed")

    def _close_locked(self, now: float, how: str) -> dict:
        """Close + clear counters. Caller holds the lock. Returns a close event."""
        reason = self._trip_reason
        self._open = False
        self._opened_at = None
        self._trip_reason = None
        self._violations.clear()
        self._tool_calls.clear()
        return {
            "event": "close",
            "how": how,
            "tripReason": reason,
            "violations": 0,
            "toolCalls": 0,
        }

    def reset(self) -> None:
        """Manual close. Clears counters whether or not the circuit was open."""
        with self._lock:
            was_open = self._open
            now = self._now()
            event = self._close_locked(now, "manual_reset")
        if was_open:
            self._emit(event)

    # ── counting ─────────────────────────────────────────────────────────
    def record_violation(self) -> None:
        """Count one TRUE (pre-downgrade) blocked verdict; trip if over."""
        if self.config.violation_threshold is None:
            return
        self._record(self._violations, self.config.violation_threshold, REASON_VIOLATIONS)

    def record_tool_call(self) -> None:
        """Count one scan_tool_call invocation; trip if over."""
        if self.config.rate_threshold is None:
            return
        self._record(self._tool_calls, self.config.rate_threshold, REASON_RATE)

    def _record(self, counters: _Counters, threshold: int, reason: str) -> None:
        trip_event = None
        callback_payload = None
        with self._lock:
            now = self._now()
            self._maybe_cooldown(now)  # an expired cooldown closes before counting
            count = counters.add(now)
            if not self._open and count >= threshold:
                self._open = True
                self._opened_at = now
                self._trip_reason = reason
                snap = self._snapshot_locked(now)
                trip_event = {
                    "event": "trip",
                    "reason": reason,
                    "violations": snap["violations"],
                    "toolCalls": snap["toolCalls"],
                    "violationThreshold": self.config.violation_threshold,
                    "rateThreshold": self.config.rate_threshold,
                    "cooldownSec": self.config.cooldown_sec,
                }
                callback_payload = {
                    "reason": reason,
                    "violations": snap["violations"],
                    "tool_calls": snap["toolCalls"],
                    "agent_id": self.agent_id,
                    "enforcement_mode": self.enforcement_mode,
                }
        # Emit and call back OUTSIDE the lock: a slow or reentrant callback must
        # not hold the scan path. Both are fired exactly once per trip, because
        # only the transition above builds them.
        if trip_event is not None:
            self._emit(trip_event)
            self._fire_on_trip(callback_payload)

    def _snapshot_locked(self, now: float) -> dict:
        return {
            "violations": self._violations.count(now),
            "toolCalls": self._tool_calls.count(now),
        }

    # ── side effects ─────────────────────────────────────────────────────
    def _fire_on_trip(self, payload: dict) -> None:
        cb = self.config.on_trip
        if cb is None:
            return
        try:
            cb(payload)
        except Exception as exc:
            logger.warning(
                "xaidr: circuit_breaker on_trip callback raised (%s: %s)",
                type(exc).__name__, exc,
            )

    # Set by the sensor so trip/close events reach telemetry. Left as a no-op
    # hook so this module has no dependency on the sensor.
    _emit_hook: Optional[Callable[[dict], None]] = None

    def _emit(self, event: dict) -> None:
        hook = self._emit_hook
        if hook is None:
            return
        try:
            hook(event)
        except Exception as exc:
            logger.warning(
                "xaidr: circuit_breaker telemetry failed (%s: %s)",
                type(exc).__name__, exc,
            )


def _retained_cap(threshold: Optional[int]) -> int:
    """Deque cap: generous vs the threshold, but hard-bounded.

    Must exceed the threshold or the counter could never reach it; ``_MIN_RETAINED``
    is the floor and a threshold larger than that scales it by 2 so a legitimately
    huge threshold still trips.
    """
    if threshold is None:
        return _MIN_RETAINED
    return max(_MIN_RETAINED, int(threshold) * 2)
