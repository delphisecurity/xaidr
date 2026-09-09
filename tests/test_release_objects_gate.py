"""The release-objects gate: does it actually discriminate?

WHY THIS FILE EXISTS. The gate it tests is the fix for a state this repository
was genuinely in -- fifteen tags, zero release objects, and a green CI run the
whole time, because nothing in CI could see server-side state. A guard written
for that failure is itself a running system whose output is a verdict about
other systems, and this repo's recent history is mostly guards that passed
while constraining nothing: one that compared a constant to a constant, one
that always refused, one that passed vacuously on an empty set.

So the cases below are chosen to be the ones that FAIL a decorative
implementation, not the ones that pass an obvious one:

  * a DRAFT release must not count      -- a draft is what an interrupted
                                           release leaves behind, and it
                                           notifies nobody
  * an empty in-scope set must FAIL     -- the vacuous pass, spelled out
  * the floor must SKIP, not silently
    drop                                -- so the report cannot read as full
                                           coverage over a filtered set

`audit()` is pure -- it takes the two lists rather than fetching them -- so
every case here runs with no network. The network half is not testable in
pytest by construction, and is verified by running the script against the live
API; see docs/releasing.md.
"""

import importlib.util
import pathlib

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "release_objects_gate",
    pathlib.Path(__file__).resolve().parents[1] / "scripts" / "release_objects_gate.py",
)
gate = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gate)


def test_a_tag_with_a_published_release_is_covered():
    missing, covered, skipped, ignored = gate.audit(
        ["v1.10.0"], {"v1.10.0"}, floor="v1.10.0"
    )
    assert (missing, covered, skipped, ignored) == ([], ["v1.10.0"], [], [])


def test_a_tag_with_no_release_is_the_finding():
    missing, covered, _, _ = gate.audit(
        ["v1.10.0", "v1.11.0"], {"v1.10.0"}, floor="v1.10.0"
    )
    assert missing == ["v1.11.0"]
    assert covered == ["v1.10.0"]


def test_a_draft_release_does_not_count_as_cut(monkeypatch):
    """The discriminating case, tested through the FILTER rather than around it.

    Passing a pre-filtered set to `audit()` would prove nothing about drafts --
    it would just re-test "a tag with no release". So this drives
    `fetch_published_release_tags` with a payload shaped like the API's, one
    published and one draft, and asserts the draft's tag does not come back.

    An implementation that took every release object would report a drafted
    release as cut, and a maintainer interrupted between `--draft` and
    publishing would be told the release shipped when nobody can see it.
    """
    payload = [
        {"tag_name": "v1.15.0", "draft": False},
        {"tag_name": "v1.14.0", "draft": True},
        {"tag_name": "v1.13.0"},  # key absent entirely: the API omits it sometimes
    ]
    monkeypatch.setattr(gate, "_paginate", lambda *a, **k: payload)

    published = gate.fetch_published_release_tags("o/r", None)
    assert published == {"v1.15.0", "v1.13.0"}

    missing, covered, _, _ = gate.audit(
        ["v1.13.0", "v1.14.0", "v1.15.0"], published, floor="v1.10.0"
    )
    assert missing == ["v1.14.0"]
    assert covered == ["v1.13.0", "v1.15.0"]


def test_tags_below_the_floor_are_skipped_and_reported_not_dropped():
    missing, covered, skipped, _ = gate.audit(
        ["v1.9.0", "v1.10.0"], {"v1.10.0"}, floor="v1.10.0"
    )
    assert missing == []
    assert covered == ["v1.10.0"]
    # v1.9.0 genuinely has no release object. The gate does not fail on it, but
    # it MUST hand it back so the caller prints it. A filter that returned only
    # `missing` would print "OK" over a repository with six uncut releases.
    assert skipped == ["v1.9.0"]


def test_a_non_version_tag_is_ignored_and_reported():
    missing, _, _, ignored = gate.audit(
        ["scratch", "v1.10.0"], {"v1.10.0"}, floor="v1.10.0"
    )
    assert missing == []
    assert ignored == ["scratch"]


def test_ordering_is_by_version_not_lexical():
    """`sorted()` on strings puts v1.9.0 after v1.10.0. The report is read by a
    human deciding which release to cut first, and a list that claims 1.9 is
    newer than 1.10 is a list they have to re-sort in their head."""
    missing, _, _, _ = gate.audit(
        ["v1.9.0", "v1.10.0", "v1.11.0"], set(), floor="v1.0.0"
    )
    assert missing == ["v1.9.0", "v1.10.0", "v1.11.0"]


def test_a_bad_floor_is_an_error_not_a_pass():
    with pytest.raises(gate.CheckError):
        gate.audit(["v1.10.0"], set(), floor="1.10")


def test_single_tag_scope_ignores_every_other_tag():
    missing, covered, _, _ = gate.audit(
        ["v1.10.0", "v1.11.0"], {"v1.11.0"}, floor="v1.10.0", only_tag="v1.11.0"
    )
    assert missing == []
    assert covered == ["v1.11.0"]


def test_empty_scope_is_reported_as_no_coverage(capsys, monkeypatch):
    """The vacuous pass, pinned at the exit-code level.

    With no tag at or above the floor there is nothing to check, and the
    tempting implementation returns 0 because `missing` is empty. That is the
    shape that let a green suite hide seven CANCELLED tests. `main()` must
    treat an empty covered set as a FAILURE.
    """
    monkeypatch.setattr(
        gate, "run_once", lambda *a, **k: ((([], [], ["v1.9.0"], [])), 1, 0)
    )
    rc = gate.main(["--repo", "o/r", "--floor", "v1.10.0"])
    assert rc == 1
    assert "nothing was checked" in capsys.readouterr().out


def test_a_check_that_could_not_run_exits_2_not_0(capsys, monkeypatch):
    """Network failure, auth failure and rate-limiting must not look like a
    pass. Exit 2 is distinct from both 0 and 1 so CI cannot confuse "nothing is
    missing" with "nothing was checked"."""
    def boom(*a, **k):
        raise gate.CheckError("HTTP 403: rate limit exceeded")

    monkeypatch.setattr(gate, "run_once", boom)
    rc = gate.main(["--repo", "o/r"])
    assert rc == 2
    assert "not a pass" in capsys.readouterr().err
