"""A2 M4 from OUTSIDE the process: the same driver, run against the built wheel."""
from __future__ import annotations

import pytest

from .harness import ROOT, build_wheel, fresh_venv, run_driver

pytestmark = pytest.mark.requires_dev_extra


@pytest.fixture(scope="module")
def seen(tmp_path_factory):
    try:
        import hatchling  # noqa: F401
    except ImportError:
        pytest.fail("REFUSING: hatchling (dev extra) is not installed, so no wheel can "
                    "be built and nothing can be checked from outside the process.",
                    pytrace=False)
    work = tmp_path_factory.mktemp("m4")
    return run_driver(fresh_venv(work / "venv", build_wheel(ROOT, work / "dist")),
                      "m4_tool_call_eval.py", work)


def test_the_driver_ran_the_installed_wheel(seen):
    assert "site-packages" in seen["xaidr_file"], seen["xaidr_file"]


def test_m4_from_the_wheel(seen):
    from tests.test_value_origin_m4 import check_flow, check_paths, check_q6
    check_paths(seen)
    check_flow(seen)
    check_q6(seen)
