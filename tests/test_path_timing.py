"""One timing check per path (owner, 2026-11-02).

What a scan or a reading examines is work, and the correctness tests assert it as
counts. How long that work takes is a performance figure: measured on the CI
runners, the slowest reference, and stated in docs/performance.md. Each path keeps
ONE timing check here, at about 1.5 times the runners' measured worst case
(``scripts/scan_paths.py``: ``BOUNDS``, with ``RUNNER_WORST`` its basis). A path
that fails here got slower than the code measured on the runners when the bound was
set; re-measure (``python scripts/scan_paths.py`` prints every path's figure in
each CI pytest cell) before changing a bound, and change it with its figure.

CPU time (``time.process_time``), for the reason set out in scan_paths: a busy
neighbour does not move it. An input over its path's bound is run again, up to
twice, and keeps its best, so one descheduled sample does not fail the check.
"""
from __future__ import annotations

import time

import pytest


@pytest.fixture(scope="module")
def sp(scan_paths):
    return scan_paths


@pytest.mark.parametrize("path", ["input_scan", "output_scan", "tool_call", "l1_rule",
                                  "normalizer", "text_detectors", "parsers", "a2a",
                                  "result_read"])
def test_the_path_stays_within_its_measured_bound(sp, path):
    bound = sp.BOUNDS[path]
    if bound is None:
        pytest.skip(f"{path}: not yet measured on the CI runners")
    worst, name, _ = sp.measure(path, bound=bound)
    assert worst <= bound, (
        f"{path}: {name} took {worst:.4f} s of CPU against a bound of {bound} s, 1.5 "
        f"times the {sp.RUNNER_WORST[path]} s the runners measured: this path is slower "
        "than when the bound was set")


def test_every_path_has_a_timing_check(sp):
    assert set(sp.BOUNDS) == {"input_scan", "output_scan", "tool_call", "l1_rule",
                              "normalizer", "text_detectors", "parsers", "a2a",
                              "result_read"}
    for path in sp.BOUNDS:
        assert sp.cases(path), f"{path} times nothing"


def test_the_rule_check_moves_with_one_costly_rule(sp, monkeypatch):
    """The rule path's figure is ONE rule on ONE input, so a single rule that costs
    far more than its peers moves it, however many rules there are. A rule that
    burns more CPU than the bound must read over it."""
    bound = sp.BOUNDS["l1_rule"] or 0.2
    burn = 2 * bound

    def costly(text):
        end = time.process_time() + burn
        while time.process_time() < end:
            pass

    hog = {"id": "TEST_costly_rule", "pattern": None, "detector": costly, "score": 0.0,
           "category": "prompt_injection", "filter_reserved_email": False}
    monkeypatch.setattr(sp, "ALL_RULES", [hog])
    worst, name, _ = sp.measure("l1_rule", bound=bound, retries=0)
    assert worst > bound and name.startswith("TEST_costly_rule:"), (
        f"a rule burning {burn:.2f} s read {worst:.4f} s ({name}): the check cannot fire")


def test_each_bound_is_its_runner_figure_times_one_and_a_half(sp):
    """A bound is set from a measurement, never raised to turn a red run green:
    each is 1.5 times the runners' worst (or the floor, for a figure too small for
    a shared runner to tell apart from its noise)."""
    for path, bound in sp.BOUNDS.items():
        if bound is None:
            continue
        figure = sp.RUNNER_WORST[path]
        assert figure is not None, f"{path}: a bound with no runner figure behind it"
        assert bound == sp.bound_for(figure), (
            f"{path}: bound {bound} s is not 1.5 x the runners' {figure} s "
            f"(or the {sp.FLOOR_S} s floor): {sp.bound_for(figure)} s")
