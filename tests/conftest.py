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
    config.addinivalue_line(
        "markers",
        "value_origin_enforce: the module tests value-origin ENFORCE, which 1.22.0 "
        "holds back from every public option; it runs inside the test-only switch "
        "(xaidr/value_origin/_hold.py)")


@pytest.fixture(autouse=True, scope="module")
def _value_origin_enforce_for_tests(request):
    """A module marked ``value_origin_enforce`` runs inside the test-only switch, so
    the kept enforcement code stays tested. Module-scoped and autouse, so it is in
    force before the module's own fixtures build their sensors."""
    if request.node.get_closest_marker("value_origin_enforce") is None:
        yield
        return
    from xaidr.value_origin import _hold
    with _hold._enforce_for_tests():
        yield


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


class L1Work:
    """What each L1 rule examined: one ``(rule_id, characters)`` per call. Work,
    counted, never timed: the same input gives the same list on every machine."""

    def __init__(self):
        self.calls = []
        self.dlp_calls = []      # the same, for DLP_PATTERNS

    def clear(self):
        self.calls.clear()
        self.dlp_calls.clear()

    def per_rule(self):
        """``{rule_id: [characters examined, one per call]}``."""
        out = {}
        for rid, n in self.calls:
            out.setdefault(rid, []).append(n)
        return out


class _CountingPattern:
    def __init__(self, rid, pattern, calls):
        self._rid, self._pattern, self._calls = rid, pattern, calls

    def search(self, text, *a, **k):
        self._calls.append((self._rid, len(text)))
        return self._pattern.search(text, *a, **k)

    def findall(self, text, *a, **k):
        self._calls.append((self._rid, len(text)))
        return self._pattern.findall(text, *a, **k)

    def finditer(self, text, *a, **k):
        self._calls.append((self._rid, len(text)))
        return self._pattern.finditer(text, *a, **k)

    def __getattr__(self, name):
        return getattr(self._pattern, name)


@pytest.fixture
def l1_work(monkeypatch):
    """Count the characters every L1 input and output rule, and every DLP pattern,
    examines (``L1Work``). Each pattern or detector is wrapped for the test; the
    rules themselves are unchanged."""
    from xaidr.scanner import dlp, l1

    work = L1Work()

    def wrap(rules):
        out = []
        for r in rules:
            r = dict(r)
            if r["detector"] is not None:
                det, rid = r["detector"], r["id"]
                r["detector"] = (lambda t, det=det, rid=rid:
                                 (work.calls.append((rid, len(t))), det(t))[1])
            elif r.get("pattern") is not None:
                r["pattern"] = _CountingPattern(r["id"], r["pattern"], work.calls)
            out.append(r)
        return out
    monkeypatch.setattr(l1, "INPUT_RULES", wrap(l1.INPUT_RULES))
    monkeypatch.setattr(l1, "OUTPUT_RULES", wrap(l1.OUTPUT_RULES))
    monkeypatch.setattr(dlp, "DLP_PATTERNS", [
        dict(p, pattern=_CountingPattern(p["id"], p["pattern"], work.dlp_calls))
        for p in dlp.DLP_PATTERNS])
    return work


@pytest.fixture(scope="session")
def scan_paths():
    """scripts/scan_paths.py: the paths' timing inputs and ``assert_timed``."""
    scripts = str(Path(__file__).resolve().parents[1] / "scripts")
    if scripts not in _sys.path:
        _sys.path.insert(0, scripts)
    import scan_paths as sp
    return sp


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
