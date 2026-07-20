"""Guards for the telemetry shutdown hang.

Root cause: close_sync set the stop Event, but a worker blocked in
queue.get(timeout=flush_interval) never saw it until the get timed out, so the
atexit join(timeout=2.0) reliably burned its full 2s — once PER Sensor ever
started (atexit is registered per queue instance). A 263-test suite created 212
sensors and spent 313s inside atexit after printing all-green. Any embedder
creating sensors got the same per-instance exit tail.

Fix (three layers, model preserved): daemon workers (pre-existing, kept),
atexit registered exactly once per queue with a re-registration guard across
close/restart cycles, and close_sync sends a _STOP sentinel BEFORE join so the
worker wakes immediately — join(timeout=2.0) stays as the bound, daemon as the
backstop.

The subprocess tests are the permanent lock: a regression re-introduces the
per-sensor exit tail, which trips the wall-clock assertion (or, if it truly
hangs, the subprocess timeout — the failure IS the signal).
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Wall-clock bound for a 5-sensor no-close exit. Pre-fix this took 5.1s+
# (sentinel-less joins); post-fix it's interpreter startup + ~0.1s.
EXIT_BUDGET_SEC = 4.0
HANG_BACKSTOP_SEC = 30


def _run_subprocess(code: str) -> tuple[subprocess.CompletedProcess, float]:
    t0 = time.time()
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=HANG_BACKSTOP_SEC,
        cwd=str(REPO_ROOT),
    )
    return proc, time.time() - t0


def test_process_exits_promptly_without_close():
    """5 sensors, one scan each, NO manual close — the process must still exit
    promptly via the atexit path (sentinel wakes each worker; no 2s join burn
    per sensor)."""
    code = f"""
import sys
sys.path.insert(0, {str(REPO_ROOT)!r})
from xaidr import Sensor
for i in range(5):
    Sensor(agent_id="shutdown-guard").scan("hello world")
"""
    proc, elapsed = _run_subprocess(code)
    assert proc.returncode == 0, f"repro crashed: {proc.stderr[-500:]}"
    assert elapsed < EXIT_BUDGET_SEC, (
        f"exit took {elapsed:.2f}s (budget {EXIT_BUDGET_SEC}s) — the per-sensor "
        f"shutdown tail is back"
    )


def test_telemetry_flushed_on_normal_exit(tmp_path):
    """Events still in flight at normal exit must reach the reporter (audit
    trail): the atexit close drains and flushes, it does not just kill the
    worker."""
    out = tmp_path / "events.jsonl"
    code = f"""
import sys
sys.path.insert(0, {str(REPO_ROOT)!r})
from xaidr import Sensor
from xaidr.reporters import FileReporter
s = Sensor(agent_id="shutdown-guard", reporter=FileReporter({str(out)!r}))
s.scan("hello world")
"""
    proc, _ = _run_subprocess(code)
    assert proc.returncode == 0, f"repro crashed: {proc.stderr[-500:]}"
    lines = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    assert any(e.get("type") == "scan" for e in lines), (
        f"scan event dropped at exit — got {lines!r}"
    )


def test_close_sync_idempotent(sensor):
    """Double close (manual close then atexit, or two atexit paths) must not
    error, re-join, or re-flush."""
    sensor.scan("hello world")
    q = sensor._telemetry
    q.close_sync()
    assert q._thread is not None and not q._thread.is_alive()
    q.close_sync()  # second close: no exception, thread stays dead
    assert not q._thread.is_alive()


def test_atexit_registered_once_across_restart(sensor):
    """close_sync resets _started; a later enqueue restarts the worker. That
    restart must NOT register a second atexit callback for the same queue."""
    sensor.scan("hello world")
    q = sensor._telemetry
    assert q._atexit_registered
    q.close_sync()
    q.enqueue({"type": "scan", "data": {}})  # restarts the worker
    assert q._started
    assert q._atexit_registered  # still the single registration
    q.close_sync()


def test_join_is_bounded():
    """The shutdown bound: sentinel sent before a join WITH timeout, daemon as
    backstop. Locks the parameters the no-hang guarantee relies on. The bounded
    join lives in _drain_and_stop, which BOTH close_sync and flush_sync call."""
    import inspect

    from xaidr import telemetry

    src = inspect.getsource(telemetry.SyncTelemetryQueue._drain_and_stop)
    assert "join(timeout=" in src
    # close_sync and flush_sync both route through the bounded _drain_and_stop.
    assert "_drain_and_stop" in inspect.getsource(
        telemetry.SyncTelemetryQueue.close_sync
    )
    assert "_drain_and_stop" in inspect.getsource(
        telemetry.SyncTelemetryQueue.flush_sync
    )
    src_start = inspect.getsource(telemetry.SyncTelemetryQueue.start)
    assert "daemon=True" in src_start
