"""Rule assets must load from a SHALLOW stack, and exactly once.

Two guards, both written against a defect that shipped.

THE DEFECT. ``scanner/normalizer.py`` re-read ``typo-keywords.json`` on every
``TypoNormalizer()``, i.e. every ``LocalScanner``, i.e. every ``Sensor``. The
read went through ``json.load``, which is a thin wrapper that calls the MODULE
GLOBAL ``json.loads`` — so each Sensor construction re-entered whatever
``json.loads`` was bound to at that instant. The loader's ``except Exception``
then turned any fault in that window into "normalization disabled", recorded in
the process-global registry in ``failclosed`` that nothing ever clears.

One transient fault therefore disabled the typo normaliser for the REST OF THE
PROCESS, and made every later Sensor report a degradation it had nothing to do
with. On CI, where the whole suite is a single process,
``tests/test_cleanup_a9_a5.py`` (which patches ``json.loads`` to raise, to prove
the A2A extractor survives it, and builds a Sensor inside the patched window)
poisoned ``test_open_posture_is_the_default_and_unchanged`` several thousand
tests later — reporting a ``RecursionError`` that nothing in the scanner raised.

WHAT DISABLING THE NORMALISER COSTS, measured by running the suite with
``_TYPO_CONFIG`` emptied: 36 tests fail, including 12 obfuscated-attack
detections lost across BOTH the ``scan`` and ``scan_a2a`` surfaces — leetspeak,
dot/underscore/dash separator evasion, and homoglyph+separator evasion. It is a
silent, total loss of the de-obfuscation layer, so it must not be reachable by
accident.
"""

from __future__ import annotations

import glob
import json
import os
import sys
from contextlib import contextmanager

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(ROOT, "xaidr", "rules")

# The headroom a rule asset must parse within, in stack frames.
#
# NOT a tuning knob and NOT a limit to raise. xaidr is a library: it is called
# from inside host frameworks, recursive document walkers and deep middleware
# stacks, so the frames left when our loader runs are the HOST's business, not
# ours. An asset that needs a deep stack to parse is an asset that fails on
# somebody else's call graph and nowhere in our tests.
#
# `typo-keywords.json` needs 3 (it nests 3 deep: object -> "keywords" object ->
# tier array). 20 leaves ordinary room for a config-shaped asset while failing
# loudly on one that has grown genuinely deep nesting.
RECURSION_BUDGET_FRAMES = 20

# The matching structural bound, asserted directly so the failure message can
# say WHICH asset got deep rather than only that something ran out of stack.
MAX_ASSET_NESTING_DEPTH = 12


def _assets() -> list:
    return sorted(glob.glob(os.path.join(RULES_DIR, "*.json")))


def _stack_depth() -> int:
    n, f = 0, sys._getframe()
    while f is not None:
        n += 1
        f = f.f_back
    return n


@contextmanager
def recursion_headroom(frames: int):
    """Run the body with only ``frames`` stack frames left before the limit.

    LOWERS the limit for the duration — the opposite of the fix nobody should
    reach for. Raising ``sys.setrecursionlimit`` moves the cliff; this walks up
    to the cliff on purpose so a deep asset falls off it here, in CI, instead of
    on a user's stack.
    """
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(_stack_depth() + frames)
    try:
        yield
    finally:
        sys.setrecursionlimit(old)


def _nesting_depth(text: str) -> int:
    """Max bracket nesting of a JSON document, ignoring brackets inside strings."""
    depth = best = 0
    in_str = esc = False
    for ch in text:
        if esc:
            esc = False
            continue
        if in_str:
            if ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            best = max(best, depth)
        elif ch in "]}":
            depth -= 1
    return best


# ── the guard the next deeply-nested asset trips ─────────────────────────────

def test_the_asset_set_is_not_empty():
    """The vacuity guard. A glob that matches nothing passes every test below."""
    found = _assets()
    assert len(found) >= 7, (
        f"only {len(found)} JSON assets under {RULES_DIR} — this gate has "
        "stopped covering the rule assets it exists for."
    )


@pytest.mark.parametrize("path", _assets(), ids=lambda p: os.path.basename(p))
def test_asset_parses_within_a_conservative_recursion_budget(path):
    """Every shipped rule asset must parse from a nearly-exhausted stack."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        with recursion_headroom(RECURSION_BUDGET_FRAMES):
            json.loads(text)
    except RecursionError:
        pytest.fail(
            f"{os.path.basename(path)} nests {_nesting_depth(text)} deep and "
            f"cannot be parsed with {RECURSION_BUDGET_FRAMES} stack frames "
            "available. xaidr is called from inside host stacks, so this asset "
            "would fail to load on a deep caller and silently degrade the "
            "layer that reads it. FLATTEN THE ASSET — do not raise "
            "sys.setrecursionlimit, which moves the cliff instead of removing it."
        )


@pytest.mark.parametrize("path", _assets(), ids=lambda p: os.path.basename(p))
def test_asset_nesting_depth_is_bounded(path):
    """The structural half, so the failure names the asset and its depth."""
    with open(path, encoding="utf-8") as fh:
        depth = _nesting_depth(fh.read())
    assert depth <= MAX_ASSET_NESTING_DEPTH, (
        f"{os.path.basename(path)} nests {depth} deep, over the "
        f"{MAX_ASSET_NESTING_DEPTH} bound. Deep nesting in a rule asset is a "
        "load-time hazard on a deep host stack; flatten it."
    )


# ── the loader must not be re-enterable by a caller's json ───────────────────

def test_the_asset_is_read_once_at_import_not_per_sensor():
    """A Sensor construction must not touch the parser at all.

    This is the property that makes the poisoning above impossible: if building
    a Sensor never calls ``json.loads``, then nothing a caller has done to the
    json module can disable normalization.
    """
    import xaidr.scanner.normalizer as nz

    sentinel = {"all_keywords": ["ignore"], "denylist": []}
    original = nz._TYPO_CONFIG
    nz._TYPO_CONFIG = sentinel
    try:
        assert nz._load_typo_config() is sentinel, (
            "_load_typo_config() re-read the asset instead of returning the "
            "config parsed at import — the per-construction read is back."
        )
    finally:
        nz._TYPO_CONFIG = original


def test_building_a_sensor_under_a_broken_json_does_not_disable_normalization():
    """THE REGRESSION. Reproduces the CI failure in one test.

    A caller whose ``json.loads`` raises — a test patching it, an
    ``orjson``-style monkeypatch, a tracing shim — must not cost us the
    normaliser, and must not record an asset fault against a file that is fine.
    """
    from xaidr import Sensor
    from xaidr.failclosed import asset_faults

    class _NullReporter:
        def report(self, *a, **k): pass
        def close(self, *a, **k): pass

    before = len(asset_faults())
    real = json.loads
    json.loads = lambda *a, **k: (_ for _ in ()).throw(RecursionError())
    try:
        s = Sensor(agent_id="asset-load", reporter=_NullReporter())
    finally:
        json.loads = real

    try:
        new = asset_faults()[before:]
        assert not new, (
            "building a Sensor while json.loads was broken recorded "
            f"{[f.reason for f in new]}. The asset is read once at import; a "
            "construction must not re-enter the parser."
        )
        assert s.degradations == [], (
            f"Sensor reports {s.degradations} — a transient fault in the "
            "caller's json module disabled the typo normaliser."
        )
        # And the normaliser is genuinely live, not merely unrecorded.
        assert s._scanner._normalizer.keywords, (
            "the normaliser loaded an EMPTY keyword set — normalization is off "
            "while reporting no degradation, which is worse than the original "
            "defect."
        )
    finally:
        s.close_sync()
