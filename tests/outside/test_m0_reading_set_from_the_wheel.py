"""M0 (finding 1, Q1) from OUTSIDE the process: the built wheel, a fresh venv,
the installed core's public interface — nothing imported from the source tree.

The in-tree conformance cases prove the core's code; this proves the artifact.
A packaging omission, a stale build or a tree that shadows the wheel would
pass every in-tree test and fail here (V-5's reason, applied to Q1).
"""
from __future__ import annotations

import pytest

from .harness import ROOT, build_wheel, fresh_venv, run_driver

pytestmark = pytest.mark.requires_dev_extra


@pytest.fixture(scope="module")
def installed(tmp_path_factory):
    try:
        import hatchling  # noqa: F401
    except ImportError:
        pytest.fail("REFUSING: hatchling (dev extra) is not installed, so no wheel can "
                    "be built and nothing can be checked from outside the process. "
                    "pip install '.[dev]'.", pytrace=False)
    work = tmp_path_factory.mktemp("m0")
    wheel = build_wheel(ROOT, work / "dist")
    return run_driver(fresh_venv(work / "venv", wheel), "core_reading_set.py", work)


def test_the_driver_ran_the_installed_wheel(installed):
    assert "site-packages" in installed["xaidr_file"], installed["xaidr_file"]


def test_finding_1_is_closed_in_the_built_wheel(installed):
    case = installed["cases"]["bypass"]
    assert case["wire"] == "untrusted_source" and case["blocks_under_enforce"], (
        f"the INSTALLED core authorizes {case['url']!r} (wire {case['wire']}, findings "
        f"{case['findings']}) while httpx sends it to the untrusted evil.test")
    assert case["findings"] == ["dns:corp.example", "dns:evil.test"]


def test_the_mirror_and_a_plain_call_still_block_and_one_authority_does_not(installed):
    c = installed["cases"]
    assert c["mirror"]["blocks_under_enforce"] and c["plain-untrusted"]["blocks_under_enforce"]
    assert c["benign-one-authority"] == {**c["benign-one-authority"],
                                         "wire": "principal", "blocks_under_enforce": False,
                                         "findings": ["dns:corp.example"]}
