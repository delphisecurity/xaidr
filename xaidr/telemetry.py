"""Background telemetry queue.

Batches scan events and hands them to a pluggable Reporter. Fails open:
if the reporter raises, events are dropped with a warning so the caller's
request path is never blocked. Where events actually go (stdout, file,
webhook, OTel, ...) is the Reporter's concern, not the queue's.
"""

from __future__ import annotations

import atexit
import logging
import queue
import threading
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .reporters import Reporter

logger = logging.getLogger("xaidr.telemetry")

# Poison pill: enqueued by close_sync so a worker blocked in queue.get() wakes
# immediately instead of waiting out its full flush_interval. Never reported.
_STOP = object()


class SyncTelemetryQueue:
    """Synchronous telemetry queue using threading.

    Designed for use with LocalScanner and sync middleware (LangChain).
    Collects events and hands batches to a Reporter from a background thread
    every flush_interval seconds. Defaults to StdoutReporter so the sensor is
    useful with no backend and no configuration.
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
        self._reporter = reporter
        self._batch_size = batch_size
        self._flush_interval = flush_interval_sec
        self._queue: queue.Queue = queue.Queue(maxsize=1000)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._started = False
        self._atexit_registered = False

    def start(self) -> None:
        """Start the background flush thread."""
        if self._started:
            return
        self._started = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="xaidr-telemetry", daemon=True
        )
        self._thread.start()
        # Exactly once per queue, even across close/restart cycles — a second
        # registration would make shutdown join the same queue repeatedly.
        if not self._atexit_registered:
            atexit.register(self.close_sync)
            self._atexit_registered = True

    def enqueue(self, event: dict) -> None:
        """Add an event to the queue. Auto-starts the flush thread on first call."""
        if not self._started:
            self.start()
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            logger.warning("telemetry queue full, dropping event")

    def _run(self) -> None:
        """Background thread: collect batches and flush."""
        while not self._stop_event.is_set():
            batch = self._collect_batch()
            if batch:
                self._flush(batch)

    def _collect_batch(self) -> list:
        """Collect up to batch_size events, waiting up to flush_interval."""
        batch: list = []
        try:
            first = self._queue.get(timeout=self._flush_interval)
        except queue.Empty:
            return batch
        if first is _STOP:
            # Wake-up pill from close_sync (or stale from a previous close):
            # return so the run loop re-checks the stop event.
            return batch
        batch.append(first)

        while len(batch) < self._batch_size:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            if item is _STOP:
                break
            batch.append(item)
        return batch

    def _flush(self, batch: list) -> None:
        """Hand the batch to the reporter. Fail-open: never raises to caller."""
        try:
            self._reporter.report(batch)
            logger.debug("reported %d telemetry events", len(batch))
        except Exception as exc:
            logger.warning("reporter failed, dropping %d events: %s", len(batch), exc)

    def close_sync(self) -> None:
        """Flush remaining events and stop the thread.

        Idempotent — safe to call more than once (atexit fires even after a
        manual close). Shutdown is bounded: sentinel first (wakes a worker
        blocked in get()), then join with a timeout; the daemon flag is the
        backstop if the worker is wedged past the timeout.
        """
        self._stop_event.set()
        remaining: list = []
        while not self._queue.empty():
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            if item is not _STOP:
                remaining.append(item)
        if remaining:
            self._flush(remaining)
        if self._thread and self._thread.is_alive():
            try:
                self._queue.put_nowait(_STOP)
            except queue.Full:
                pass  # queue non-empty => the worker isn't blocked on get()
            self._thread.join(timeout=2.0)
        try:
            self._reporter.close()
        except Exception:
            pass
        self._started = False

    async def close(self) -> None:
        """Async-compatible close (calls sync close)."""
        self.close_sync()
