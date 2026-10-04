"""M3 (url_parse onto the core) from OUTSIDE the process: the built wheel, a
fresh venv, the installed sensor's tool-call path.

The HEAD half of ``drivers/url_parse_deltas.py``. The base half (the same
spellings against the pre-M3 wheel, and the moved set == the declared set) is
evidence run once per milestone: CI checks out at depth 1, so no base commit is
there to build.
"""
from __future__ import annotations

import importlib.util

import pytest

from .harness import DRIVERS, ROOT, build_wheel, fresh_venv, run_driver

pytestmark = pytest.mark.requires_dev_extra

_spec = importlib.util.spec_from_file_location("url_parse_deltas", DRIVERS / "url_parse_deltas.py")
_deltas = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_deltas)          # the module body imports no xaidr
SPELLINGS = _deltas.SPELLINGS


@pytest.fixture(scope="module")
def installed(tmp_path_factory):
    try:
        import hatchling  # noqa: F401
    except ImportError:
        pytest.fail("REFUSING: hatchling (dev extra) is not installed, so no wheel can "
                    "be built and nothing can be checked from outside the process. "
                    "pip install '.[dev]'.", pytrace=False)
    work = tmp_path_factory.mktemp("m3")
    wheel = build_wheel(ROOT, work / "dist")
    return run_driver(fresh_venv(work / "venv", wheel), "url_parse_deltas.py", work)


def test_the_driver_ran_the_installed_wheel(installed):
    assert "site-packages" in installed["xaidr_file"], installed["xaidr_file"]
    assert set(installed["lines"]) == set(SPELLINGS)


@pytest.mark.parametrize("url", [u for u, (moves, why) in SPELLINGS.items()
                                 if moves and "no consumer" not in why])
def test_a_link_local_spelling_a_consumer_reaches_is_classified_link_local(installed, url):
    line = installed["lines"][url]
    assert "net.metadata_link_local" in line and not line.startswith("allowed"), (
        f"{url!r} ({SPELLINGS[url][1]}) reaches 169.254.169.254 and the INSTALLED "
        f"sensor gives {line!r}")


def test_arabic_indic_digits_are_no_longer_an_address(installed):
    url = "http://١٦٩.٢٥٤.١٦٩.٢٥٤/latest"
    assert installed["lines"][url].startswith("allowed"), installed["lines"][url]


def test_the_fullwidth_digit_form_url_parse_caught_before_m3_stays_caught(installed):
    url = "http://１６９.２５４.１６９.２５４/latest"
    assert "net.metadata_link_local" in installed["lines"][url], installed["lines"][url]
