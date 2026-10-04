"""C-11 from OUTSIDE the process: the built wheel, a fresh venv, ``python -I``.

The in-tree gate (tests/test_value_origin_c11.py) runs the passes on the
source tree in pytest's own process. This runs the SAME passes
(drivers/c11_oracle.py) against the artifact a user installs, and asserts
RECORD ≡ OFF there. The driver refuses a wheel that lacks
``Sensor(value_origin=...)``, so a build that lost the parameter cannot be
compared as default against default.

The cross-commit half, comparing a wheel built from base 25dc9de with HEAD, uses
the same driver with ``--base``. It needs git history that a depth-1 CI checkout
lacks, so it is milestone evidence in PROGRESS.md.
"""
from __future__ import annotations

import pytest

from .harness import ROOT, build_wheel, fresh_venv, run_driver

pytestmark = pytest.mark.requires_dev_extra

PASSES = ("P-input", "P-flow-I", "P-flow-R", "P-seam", "P-fault",
          "A-flow-I", "A-flow-R", "A-calls", "A-steps")       # A-*: the §3.3 adversarial corpora


@pytest.fixture(scope="module")
def installed(tmp_path_factory):
    try:
        import hatchling  # noqa: F401
    except ImportError:
        pytest.fail("REFUSING: hatchling (dev extra) is not installed, so no wheel can "
                    "be built and C-11 cannot be checked from outside the process.",
                    pytrace=False)
    work = tmp_path_factory.mktemp("c11")
    py = fresh_venv(work / "venv", build_wheel(ROOT, work / "dist"))
    out = run_driver(py, "c11_oracle.py", work)
    assert "site-packages" in out["xaidr_file"], out["xaidr_file"]
    return out


@pytest.fixture(scope="module")
def digests(installed):
    return installed["digests"]


def test_the_installed_wheel_rejects_a_bad_mode_naming_it(installed):
    msg = installed["construction"]["enforec_rejected"]
    assert msg and "enforec" in msg, msg


def test_the_installed_wheel_warns_only_for_enforce(installed):
    w = installed["construction"]["warnings"]
    assert {k: len(v) for k, v in w.items()} == {
        "default": 0, "off": 0, "record": 0, "enforce": 1, "enforce+designation": 1}, w
    assert "NOT YET WIRED" in w["enforce"][0] and "designation" in w["enforce"][0]
    assert "designation" not in w["enforce+designation"][0]


@pytest.mark.parametrize("enforcement", ("block", "monitor"))
@pytest.mark.parametrize("p", PASSES)
def test_the_installed_wheel_moves_no_action_in_record_mode(digests, p, enforcement):
    off, rec = digests[f"off/{enforcement}"][p], digests[f"record/{enforcement}"][p]
    assert rec == off, (f"C-11 in the BUILT WHEEL: RECORD moved an action in {p} "
                        f"({enforcement} mode): OFF {off[:12]} != RECORD {rec[:12]}")
