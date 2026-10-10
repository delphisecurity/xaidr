"""Shared fixtures for the base regression suite.

Everything here encodes REAL, observed behavior of the current engine — the
tests exist so a future change that alters that behavior gets caught.

Two things to know about the sensor under test:
  * Telemetry is delivered from a per-sensor BACKGROUND thread, so event-based
    assertions must wait for delivery (``wait_events``), never assume order.
  * Provenance uses process/context-global state (contextvars + module globals),
    so every test is isolated via the autouse ``_clean_provenance_state`` fixture
    — otherwise a ``begin_flow`` in one test leaks into the next.
"""
from __future__ import annotations

# Standing rule (ARCHITECTURE.md §5), FIRST, before anything imports xaidr:
# this run neither reads nor writes in-tree bytecode. sys.pycache_prefix points
# both at a fresh empty directory, so a stale __pycache__/*.pyc left by a
# sabotage cannot be read even when the restored source has the same size and
# mtime. dont_write_bytecode alone stops writes, not reads (M5 milestone review).
import sys as _sys
import tempfile as _tempfile
_sys.dont_write_bytecode = True
_sys.pycache_prefix = _tempfile.mkdtemp(prefix="xaidr-nopyc-")

import time
from pathlib import Path

import pytest

from xaidr import Sensor, clear_flow, clear_origin


def pytest_configure(config):
    # Tests that need the dev extra's oracles or build tooling REFUSE when it is
    # missing (Q3): they never skip. The `base` CI config, which installs no
    # third-party package by design, deselects them explicitly by this marker.
    config.addinivalue_line(
        "markers",
        "requires_dev_extra: needs '.[dev]' (urllib3, ada-url, hatchling); refuses, "
        "never skips, without it")
    # One hook for both markers: two module-level pytest_configure functions would
    # leave only the second, and the first marker would silently go unregistered.
    config.addinivalue_line(
        "markers",
        "asi_battery: reads asi_battery/, which the sdist does not ship; skipped "
        "in an extracted sdist and run everywhere else")


class CapturingReporter:
    """A reporter that just collects delivered events for inspection."""

    def __init__(self):
        self.events = []

    def report(self, batch):
        self.events.extend(batch)

    def close(self):
        pass


def _wait_events(cap, n, timeout=5.0):
    """Block until >= n events are delivered to ``cap`` (bg thread), or fail."""
    t0 = time.perf_counter()
    while len(cap.events) < n and time.perf_counter() - t0 < timeout:
        time.sleep(0.005)
    assert len(cap.events) >= n, f"only {len(cap.events)}/{n} events delivered"
    return cap.events


def _make_envelope(parts):
    """A real A2A JSON-RPC message/send envelope carrying the given text parts."""
    return {
        "jsonrpc": "2.0",
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "parts": [{"kind": "text", "text": t} for t in parts],
            }
        },
    }


@pytest.fixture(autouse=True)
def _clean_provenance_state():
    """Isolate global provenance/flow state around every test."""
    clear_flow()
    clear_origin()
    yield
    clear_flow()
    clear_origin()


@pytest.fixture
def cap():
    return CapturingReporter()


@pytest.fixture
def sensor(cap):
    """Default monitor-mode sensor with a capturing reporter."""
    return Sensor(agent_id="test-agent", reporter=cap)


@pytest.fixture
def block_sensor(cap):
    """Block-mode sensor with a capturing reporter."""
    return Sensor(agent_id="test-block", enforcement_mode="block", reporter=cap)


@pytest.fixture
def wait_events():
    return _wait_events


@pytest.fixture
def make_envelope():
    return _make_envelope


def pytest_make_parametrize_id(config, val, argname):
    """Keep generated payloads out of test IDs.

    Several bounds tests parametrize on multi-hundred-kilobyte strings so the
    input cap and scan budget are exercised on real volume. Pytest renders the
    parameter value into the test ID, so one case can print a million
    characters during collection and on every failure line.

    Long values get a short descriptor. Returning None for everything else
    leaves pytest's default naming untouched, so no other test ID moves.
    """
    if isinstance(val, (str, bytes)) and len(val) > 32:
        return "{}_{}chars".format(argname, len(val))
    return None


_REPO = Path(__file__).resolve().parent.parent

#: True only in an extracted sdist: pyproject.toml leaves asi_battery/ out of the
#: distribution. A git checkout always has the directory, because it is tracked,
#: so the `.git` half keeps a checkout from ever skipping. A deleted battery in a
#: clone fails loudly instead of skipping, which would read as a pass.
_NO_ASI_BATTERY = not (_REPO / "asi_battery").is_dir() and not (_REPO / ".git").exists()


def pytest_collection_modifyitems(config, items):
    if not _NO_ASI_BATTERY:
        return
    skip = pytest.mark.skip(reason=(
        "asi_battery/ is not in the sdist (excluded in pyproject.toml); run "
        "this from a git checkout"))
    for item in items:
        if item.get_closest_marker("asi_battery"):
            item.add_marker(skip)
