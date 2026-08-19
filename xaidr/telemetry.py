"""Background telemetry queue.

Batches scan events and hands them to a pluggable Reporter. Fails open:
if the reporter raises, events are dropped with a warning so the caller's
request path is never blocked. Where events actually go (stdout, file,
webhook, OTel, ...) is the Reporter's concern, not the queue's.
"""

from __future__ import annotations

import logging
import queue
import threading
import weakref
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .reporters import Reporter

logger = logging.getLogger("xaidr.telemetry")

# Poison pill: enqueued by close_sync so a worker blocked in queue.get() wakes
# immediately instead of waiting out its full flush_interval. Never reported.
_STOP = object()


class _WorkerState:
    """Everything the flush worker touches, held separately from the queue.

    LIFETIME, and why this class exists at all. The worker thread and the
    shutdown hook must not reference the SyncTelemetryQueue that owns them.
    A thread whose target is a bound method, or an ``atexit.register(self.…)``
    callback, is itself a strong reference to the queue — and the queue is the
    only thing the thread's own loop waits on, so nothing ever drops that
    reference. The result was an immortal worker per queue: a Sensor that went
    out of scope without ``close_sync`` left ``xaidr-telemetry`` running for the
    life of the process, and a caller that constructed sensors in a loop piled
    up one live thread per sensor.

    So the thread closes over THIS object, and the queue keeps only a finalizer.
    When the last reference to the queue goes away, the finalizer drains and
    stops the worker, which releases this state in turn.
    """

    __slots__ = (
        "reporter",
        "queue",
        "batch_size",
        "flush_interval",
        "stop_event",
        "thread",
        "started",
    )

    def __init__(self, reporter, batch_size: int, flush_interval: float):
        self.reporter = reporter
        self.queue: queue.Queue = queue.Queue(maxsize=1000)
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.started = False


class SyncTelemetryQueue:
    """Synchronous telemetry queue using threading.

    Designed for use with LocalScanner and sync middleware (LangChain).
    Collects events and hands batches to a Reporter from a background thread
    every flush_interval seconds. Defaults to StdoutReporter so the sensor is
    useful with no backend and no configuration.

    Dropping the last reference to a queue (e.g. an unclosed Sensor going out of
    scope) stops its worker — see ``_WorkerState``. Explicit ``close_sync`` is
    still the way to shut down deterministically; the finalizer is the safety
    net, not the intended path.
    """

    def __init__(
        self,
        reporter: Optional["Reporter"] = None,
        batch_size: int = 50,
        flush_interval_sec: float = 5.0,
    ):
        if reporter is None:
            from .reporters import StdoutReporter
            reporter = StdoutReporter()
        self._state = _WorkerState(reporter, batch_size, flush_interval_sec)
        self._finalizer: Optional[weakref.finalize] = None
        self._atexit_registered = False

    # The worker lives on _WorkerState now; these keep the historical read-only
    # view of it for callers (and guard tests) that inspect worker liveness.
    @property
    def _thread(self) -> Optional[threading.Thread]:
        return self._state.thread

    @property
    def _started(self) -> bool:
        return self._state.started

    def start(self) -> None:
        """Start the background flush thread."""
        state = self._state
        if state.started:
            return
        state.started = True
        state.stop_event.clear()
        state.thread = threading.Thread(
            target=SyncTelemetryQueue._run,
            args=(state,),
            name="xaidr-telemetry",
            daemon=True,
        )
        state.thread.start()
        # Exactly once per queue, even across close/restart cycles — a second
        # registration would make shutdown drain the same queue repeatedly.
        #
        # weakref.finalize replaces the old atexit.register(self.close_sync):
        # it runs at interpreter exit exactly like atexit did (so the at-exit
        # flush guarantee is unchanged) AND when this queue is garbage
        # collected, WITHOUT holding the queue alive the way an atexit callback
        # bound to it did. _shutdown is a staticmethod for the same reason: a
        # bound method here would pin the queue and re-create the leak.
        if not self._atexit_registered:
            self._finalizer = weakref.finalize(
                self, SyncTelemetryQueue._shutdown, state
            )
            self._atexit_registered = True

    def enqueue(self, event: dict) -> None:
        """Add an event to the queue. Auto-starts the flush thread on first call."""
        state = self._state
        if not state.started:
            self.start()
        try:
            state.queue.put_nowait(event)
        except queue.Full:
            logger.warning("telemetry queue full, dropping event")

    @staticmethod
    def _run(state: _WorkerState) -> None:
        """Background thread: collect batches and flush."""
        while not state.stop_event.is_set():
            batch = SyncTelemetryQueue._collect_batch(state)
            if batch:
                SyncTelemetryQueue._flush(state, batch)

    @staticmethod
    def _collect_batch(state: _WorkerState) -> list:
        """Collect up to batch_size events, waiting up to flush_interval."""
        batch: list = []
        try:
            first = state.queue.get(timeout=state.flush_interval)
        except queue.Empty:
            return batch
        if first is _STOP:
            # Wake-up pill from close_sync (or stale from a previous close):
            # return so the run loop re-checks the stop event.
            return batch
        batch.append(first)

        while len(batch) < state.batch_size:
            try:
                item = state.queue.get_nowait()
            except queue.Empty:
                break
            if item is _STOP:
                break
            batch.append(item)
        return batch

    @staticmethod
    def _flush(state: _WorkerState, batch: list) -> None:
        """Hand the batch to the reporter. Fail-open: never raises to caller."""
        try:
            state.reporter.report(batch)
            logger.debug("reported %d telemetry events", len(batch))
        except Exception as exc:
            logger.warning("reporter failed, dropping %d events: %s", len(batch), exc)

    @staticmethod
    def _drain_and_stop(state: _WorkerState) -> None:
        """Quiesce the worker and report every pending event. No reporter.close().

        Shared by flush_sync (keep the reporter open), close_sync (then close
        it), and the finalizer. Bounded: sentinel first (wakes a worker blocked
        in get()), then join with a timeout; the daemon flag is the backstop if
        the worker is wedged. Leaves ``started`` False so the next ``enqueue``
        restarts a fresh worker.

        Takes the worker state rather than ``self`` so the finalizer can call it
        without a reference to the queue — a reference the finalizer must not
        hold, since holding one is what kept abandoned workers alive.
        """
        state.stop_event.set()
        remaining: list = []
        while not state.queue.empty():
            try:
                item = state.queue.get_nowait()
            except queue.Empty:
                break
            if item is not _STOP:
                remaining.append(item)
        if remaining:
            SyncTelemetryQueue._flush(state, remaining)
        thread = state.thread
        if thread is not None and thread.is_alive():
            try:
                state.queue.put_nowait(_STOP)
            except queue.Full:
                pass  # queue non-empty => the worker isn't blocked on get()
            # A gc-triggered finalizer can run on any thread, including this
            # worker itself; joining the current thread would raise.
            if thread is not threading.current_thread():
                thread.join(timeout=2.0)
        state.started = False

    @staticmethod
    def _close_reporter(state: _WorkerState) -> None:
        """Release the reporter's sink. Fail-open, and safe to repeat."""
        try:
            state.reporter.close()
        except Exception:
            pass

    @staticmethod
    def _shutdown(state: _WorkerState) -> None:
        """Full shutdown driven by the finalizer (gc or interpreter exit).

        Same two steps as close_sync, minus the instance: drain to the reporter,
        then close it.
        """
        SyncTelemetryQueue._drain_and_stop(state)
        SyncTelemetryQueue._close_reporter(state)

    def flush_sync(self) -> None:
        """Flush pending events synchronously WITHOUT closing the reporter.

        The working sync flush for a sync caller that wants prior events emitted
        before it reads the sink (e.g. tailing a FileReporter's file). The worker
        is quiesced and the queue drained to the reporter; the reporter stays
        open, and the next ``enqueue`` transparently restarts the worker. Bounded
        and idempotent.
        """
        self._drain_and_stop(self._state)

    def close_sync(self) -> None:
        """Flush remaining events, close the reporter, and stop the thread.

        Idempotent — safe to call more than once (the finalizer can fire even
        after a manual close). Full shutdown: drains like flush_sync, then closes
        the reporter (releasing files/sockets), so it is NOT the method to call
        if you intend to keep emitting — use flush_sync for that.
        """
        state = self._state
        self._drain_and_stop(state)
        self._close_reporter(state)
        # Retire the finalizer: the reporter is closed and the worker is
        # stopped, so there is nothing left for gc or exit to do. Detaching also
        # releases the last reference the finalize registry held to the pending
        # queue and the reporter.
        if self._finalizer is not None:
            self._finalizer.detach()
            self._finalizer = None
            self._atexit_registered = False

    async def close(self) -> None:
        """Async-compatible close (calls sync close)."""
        self.close_sync()
