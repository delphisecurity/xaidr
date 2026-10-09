"""A2 P1 from OUTSIDE the process: ``xaidr.flow()`` checked against the built wheel."""
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
    work = tmp_path_factory.mktemp("p1")
    return run_driver(fresh_venv(work / "venv", build_wheel(ROOT, work / "dist")),
                      "flow_scope.py", work)


def test_the_driver_ran_the_installed_wheel(seen):
    assert "site-packages" in seen["xaidr_file"], seen["xaidr_file"]


def test_p1_from_the_wheel(seen):
    from tests.test_value_origin_flow_scope import (
        check_cross_context_exit, check_nested, check_refusals, check_scope_that_raises,
        check_threads)
    check_scope_that_raises(seen)
    check_nested(seen)
    check_threads(seen)
    check_refusals(seen)
    check_cross_context_exit(seen)
