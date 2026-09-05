"""A failed artifact hash must say what the operator LOSES, not just what differs.

`_verify` already refused to load on a hash mismatch. What it did not do was name
the consequence: the operator asked for the ML layer, and from the moment this
raises every scan is rules-only. An exception that reports two hex strings
describes the cause of a coverage outage without describing the outage, and the
person reading it at 3am has to know the architecture to work out that their
scanner just got quieter.

The missing-artifact message in `resolve_model_dir` already reads the right way —
it names the path, what is absent, and the exact remedy — so this is the same
message shape applied to the sibling failure.

TWO LEVELS, deliberately:

  * the message contract (no artifact needed — synthetic bytes in a tmpdir).
    This is the part that must run everywhere, so it is NOT gated: gating it
    would mean the assertion is skipped in every environment that does not
    carry a 130 MB model, which is all of CI.
  * the end-to-end refusal (artifact-gated, like tests/test_nano_containment.py).
    Only the real artifact can show that a TAMPERED copy of a good directory
    fails the scanner's construction rather than silently degrading it, because
    only then is everything else about the load path real.
"""
from __future__ import annotations

import os
import shutil
import tempfile

import pytest

nano = pytest.importorskip("xaidr.scanner.nano", reason="nano is an optional extra")

ARTIFACTS = os.environ.get("XAIDR_NANO_TEST_ARTIFACTS")
_needs_artifacts = pytest.mark.skipif(
    not ARTIFACTS or not os.path.isdir(ARTIFACTS),
    reason="set XAIDR_NANO_TEST_ARTIFACTS to the pinned nano artifact directory")


def _runtime_present() -> bool:
    """The nano EXTRA, not the nano module.

    `importorskip("xaidr.scanner.nano")` cannot answer this: the module imports
    fine without onnxruntime because DelphiNano imports its runtime lazily, in
    __init__ — and it does so BEFORE it resolves or verifies anything, so a
    construction test on a box without the extra fails on ImportError long
    before it reaches the hash check it means to exercise.
    """
    try:
        import onnxruntime  # noqa: F401
        import tokenizers  # noqa: F401
    except Exception:
        return False
    return True


_needs_runtime = pytest.mark.skipif(
    not _runtime_present(), reason="nano runtime extra not installed")


@pytest.fixture
def broken_dir(request):
    """A directory that fails _verify, one way or the other.

    ONE fixture, parametrised by the test, rather than an `empty_dir` and a
    `wrong_bytes_dir`: two fixtures where the second populates the first share a
    directory, so a test naming both gets a populated "empty" dir and the
    missing-artifact branch is never exercised at all.
    """
    d = tempfile.mkdtemp()
    if request.param == "wrong_bytes":
        for name in nano.PINNED_SHA256:
            with open(os.path.join(d, name), "wb") as fh:
                fh.write(b"these are not the accepted bytes")
    yield request.param, d
    shutil.rmtree(d, ignore_errors=True)


def _message(dirpath):
    with pytest.raises(nano.NanoArtifactMismatch) as excinfo:
        nano._verify(dirpath)
    return str(excinfo.value)


# ── the consequence, on both failure branches ────────────────────────────────
# Asserted as separate claims rather than one string compare: a message test
# that pins the whole sentence fails on every wording change and teaches nobody
# anything. These are the facts the message has to carry.

@pytest.mark.parametrize("broken_dir", ["missing", "wrong_bytes"], indirect=True)
def test_the_failure_names_the_coverage_it_costs(broken_dir):
    _, path = broken_dir
    msg = _message(path)
    assert "rules-only" in msg, msg
    assert "nano will NOT load" in msg, msg


@pytest.mark.parametrize("broken_dir", ["missing", "wrong_bytes"], indirect=True)
def test_the_failure_names_a_remedy_this_package_actually_ships(broken_dir):
    """The remedy has to be reachable from here. The upstream text points at a
    `python -m xaidr.scanner.nano --fetch` CLI that this package does not have;
    naming it would send the operator somewhere the package cannot take them."""
    _, path = broken_dir
    msg = _message(path)
    assert "resolve_model_dir(auto_download=True)" in msg, msg
    assert "XAIDR_NANO_MODEL" in msg, msg
    assert "--fetch" not in msg, msg
    assert hasattr(nano, "resolve_model_dir")


@pytest.mark.parametrize("broken_dir", ["missing", "wrong_bytes"], indirect=True)
def test_the_failure_still_identifies_the_artifact_and_the_pin(broken_dir):
    """The new consequence text is ADDITIVE. The forensic detail that was there
    before — which file, which revision, which hashes — must survive it."""
    which, path = broken_dir
    msg = _message(path)
    first = next(iter(nano.PINNED_SHA256))
    assert first in msg, msg
    assert nano.PINNED_SHA256[first] in msg, msg
    assert nano.DEFAULT_REVISION in msg, msg
    if which == "wrong_bytes":
        assert "actual   SHA256" in msg, msg


@pytest.mark.parametrize("broken_dir", ["wrong_bytes"], indirect=True)
def test_a_hash_failure_raises_rather_than_returning_a_degraded_verify(broken_dir):
    """The guard is only worth anything because it RAISES. A `_verify` that
    returned a partial dict would let the load continue on unevaluated bytes."""
    _, path = broken_dir
    with pytest.raises(nano.NanoArtifactMismatch):
        nano._verify(path)


def test_verify_returns_the_hashes_when_the_artifacts_are_good(tmp_path):
    """NON-VACUITY for the raise above: _verify does not raise unconditionally.
    Built by hashing bytes and pinning them, so it needs no real artifact."""
    payload = b"deterministic content"
    fake_pin = {}
    for name in nano.PINNED_SHA256:
        p = tmp_path / name
        p.write_bytes(payload + name.encode())
        fake_pin[name] = nano._sha256(str(p))
    real, nano.PINNED_SHA256 = nano.PINNED_SHA256, fake_pin
    try:
        assert nano._verify(str(tmp_path)) == fake_pin
    finally:
        nano.PINNED_SHA256 = real


# ── the end-to-end refusal, against the real artifact ────────────────────────

@_needs_artifacts
@_needs_runtime
def test_a_tampered_real_artifact_fails_construction_instead_of_degrading(tmp_path):
    """The whole point: an operator who asked for nano gets an ERROR, never a
    scanner that quietly runs rules-only. Everything but the last byte of the
    model is the genuine artifact, so nothing about the load path is simulated.
    """
    from xaidr.scanner.local import LocalScanner

    staged = tmp_path / "artifacts"
    shutil.copytree(ARTIFACTS, staged)
    target = staged / "model.onnx"
    data = bytearray(target.read_bytes())
    data[-1] ^= 0xFF                      # one bit, one file
    target.write_bytes(bytes(data))

    with pytest.raises(nano.NanoArtifactMismatch) as excinfo:
        LocalScanner(nano_enabled=True, nano_model_dir=str(staged))
    assert "rules-only" in str(excinfo.value)


@_needs_artifacts
@_needs_runtime
def test_the_untampered_real_artifact_still_loads(tmp_path):
    """NON-VACUITY for the test above: the staging copy itself is not what fails."""
    from xaidr.scanner.local import LocalScanner

    staged = tmp_path / "artifacts"
    shutil.copytree(ARTIFACTS, staged)
    scanner = LocalScanner(nano_enabled=True, nano_model_dir=str(staged))
    assert scanner._nano is not None
