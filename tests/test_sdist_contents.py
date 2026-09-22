"""The sdist must carry the pools and the scripts that regenerate the figures.

U-1 requires every published figure to have a regenerator. Until 1.18.0 the
sdist's include list was

    include = ["xaidr", "README.md", "pyproject.toml"]

so it carried no pool, no script and no test. Every regenerator could therefore
run from a git clone and from nowhere else, which is the opposite of what
"verified from the built artifact" claims.

THE PART THAT MAKES THIS A TEST AND NOT A CHANGELOG ENTRY. The old list did not
merely omit the pools — it produced a listing that looked like it had them.
Hatchling's include patterns are gitignore-style, so a bare `README.md` with no
slash matches AT ANY DEPTH, and the built sdist listed

    xaidr-1.18.0/asi_battery/README.md
    xaidr-1.18.0/benign_a2a/README.md
    xaidr-1.18.0/benign_longform/README.md
    xaidr-1.18.0/benign_toolcalls/README.md
    xaidr-1.18.0/heldout/README.md

Five pool directories, every one of them empty of data. That listing is what the
1.16.0 body read to conclude the pools were present "measured from the built
files". The check did not fail. It passed on evidence that meant nothing, which
is the failure mode this file is shaped against: both halves below refuse to be
satisfied by a directory name.

TWO CHECKS, DELIBERATELY DIFFERENT IN KIND:

  1. `test_every_sdist_include_pattern_is_anchored` reads pyproject.toml and
     runs everywhere, with no build backend. It pins the SHAPE of the defect —
     an unanchored pattern — and it is the one that cannot skip.
  2. `test_the_built_sdist_carries_every_committed_pool_and_regenerator` builds
     a real sdist (or inspects one CI already built, via `XAIDR_SDIST`) and
     reads the bytes. It pins the CONSEQUENCE. It needs hatchling, which the
     `dev` extra now installs for exactly this reason.

Check 2 is the one that matters and check 1 is the one that always runs. Neither
substitutes for the other: an anchored pattern list can still name the wrong
directories, and a passing build here says nothing about a list someone rewrites
tomorrow in the shape that caused this.
"""
from __future__ import annotations

import importlib
import io
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

# Directories whose every tracked file must reach the sdist. Named as
# directories, then ENUMERATED from git below — a list of directories is a
# statement of scope, a list of files is a thing that goes stale. The pools are
# the data every published figure is measured over; scripts/ holds the
# regenerators; tests/ holds the suite that gates them.
_MUST_SHIP_DIRS = [
    "xaidr",
    "scripts",
    "tests",
    "asi_battery",
    "benign_a2a",
    "benign_longform",
    "benign_toolcalls",
    "heldout",
]

# A floor that does not depend on git, so the enumeration below cannot pass
# vacuously in a tree where `git ls-files` returns nothing (an extracted sdist,
# a shallow export, a runner without git). Each entry is a file a published
# figure is read off.
_FLOOR = [
    "tests/fixtures/shell_corpus.json",   # 167 of 186, 165 of 277, the policy table
    "asi_battery/attacks.jsonl",          # the ASI battery baseline
    "asi_battery/benign.jsonl",           # its register-matched mirror
    "heldout/attacks.jsonl",              # the held-out nano figures
    "heldout/benign.jsonl",
    "benign_toolcalls/corpus.jsonl",      # the production-shaped FP bar
    "benign_a2a/nested.jsonl",
    "benign_longform/manifest.json",      # pins the generated long-form corpus
    "scripts/corpus_report.py",
    "scripts/intent_metrics.py",
    "scripts/policy_width_report.py",
    "scripts/asi_battery_report.py",
    "scripts/corpus_diff.py",
]


def _sdist_include_patterns():
    """The sdist `include` list, via a real TOML parser.

    Same parser dance as tests/test_install_hints.py: `tomllib` is stdlib only
    from 3.11 and this project claims 3.10, where pytest's own `tomli>=1`
    dependency covers it.
    """
    for name in ("tomllib", "tomli"):
        try:
            parser = importlib.import_module(name)
        except ModuleNotFoundError:
            continue
        with open(REPO / "pyproject.toml", "rb") as fh:
            data = parser.load(fh)
        return data["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    pytest.skip("neither tomllib nor tomli is importable")


def test_every_sdist_include_pattern_is_anchored():
    """No include pattern may match at a depth it was not written for.

    `README.md` is not a request for the README. It is a request for every file
    named README.md anywhere in the tree, and that is how five empty pool
    directories ended up in a listing that was then read as proof the pools
    shipped. `/README.md` is the request that was meant.
    """
    patterns = _sdist_include_patterns()
    assert patterns, "the sdist target declares no include list at all"
    floating = [p for p in patterns if not p.startswith("/")]
    assert not floating, (
        "unanchored sdist include patterns:\n  " + "\n  ".join(floating) + "\n"
        "These are gitignore-style globs, so a pattern with no leading slash "
        "matches at ANY DEPTH. That is how `README.md` pulled "
        "asi_battery/README.md, heldout/README.md and three more into the sdist "
        "listing while none of those directories' data shipped — a listing that "
        "reads as coverage and carries none. Anchor each one with `/`."
    )


def test_the_sdist_include_list_names_every_pool_and_regenerator_directory():
    """Anchoring is half the fix; naming the directories is the other half."""
    named = {p.lstrip("/").rstrip("/") for p in _sdist_include_patterns()}
    missing = [d for d in _MUST_SHIP_DIRS if d not in named]
    assert not missing, (
        "directories holding committed pools or the scripts that regenerate "
        "published figures, absent from the sdist include list: "
        f"{missing}. A figure whose regenerator is not in the distribution can "
        "only be reproduced from a git clone, so no claim about it can be "
        "'verified from the built artifact'."
    )


def _tracked_files():
    """Every git-tracked file under the must-ship directories.

    ENUMERATED, not listed — `git ls-files` also excludes the run outputs
    .gitignore already names (heldout/last_run.json and friends), which are
    regenerated and have no business in a distribution.
    """
    git = subprocess.run(
        ["git", "ls-files", "-z", *_MUST_SHIP_DIRS],
        capture_output=True, text=True, cwd=str(REPO))
    if git.returncode != 0:
        return None
    return sorted(p for p in git.stdout.split("\0") if p.strip())


def _build_sdist(tmp_path):
    """A real sdist: the one CI already built, or one built here with hatchling.

    `XAIDR_SDIST` lets the packaging CI job point this at `dist/*.tar.gz` from
    its own `python -m build` run, so the bytes under test are the bytes that
    would be uploaded rather than a second build of the same tree.
    """
    prebuilt = os.environ.get("XAIDR_SDIST")
    if prebuilt:
        assert os.path.exists(prebuilt), f"XAIDR_SDIST={prebuilt} does not exist"
        return prebuilt

    try:
        from hatchling.build import build_sdist
    except ModuleNotFoundError:
        pytest.skip(
            "hatchling is not importable, so no sdist can be built here. It is "
            "in the `dev` extra for this test; `pip install '.[dev]'` runs it. "
            "The anchoring and directory checks above ran and do not skip."
        )

    cwd = os.getcwd()
    os.chdir(REPO)
    try:
        name = build_sdist(str(tmp_path))
    finally:
        os.chdir(cwd)
    return str(tmp_path / name)


def test_the_built_sdist_carries_every_committed_pool_and_regenerator(tmp_path):
    """Read the tarball. Not the include list, not the directory names."""
    path = _build_sdist(tmp_path)
    with tarfile.open(path) as tf:
        members = tf.getnames()

    # Strip the `xaidr-1.18.0/` prefix every sdist member carries.
    roots = {m.split("/", 1)[0] for m in members if "/" in m}
    assert len(roots) == 1, f"sdist has more than one root directory: {roots}"
    root = roots.pop()
    inside = {m[len(root) + 1:] for m in members if m.startswith(root + "/")}

    missing_floor = [f for f in _FLOOR if f not in inside]
    assert not missing_floor, (
        f"the built sdist ({os.path.basename(path)}) does not contain:\n  "
        + "\n  ".join(missing_floor) + "\n"
        "Each of these is a pool a published figure is measured over or the "
        "script that measures it. Without them `pip download xaidr` yields an "
        "artifact that can reproduce none of the numbers it ships prose about."
    )

    tracked = _tracked_files()
    if tracked is None:
        pytest.skip(
            "`git ls-files` did not run (not a checkout?), so only the floor "
            "above was checked. The floor is not empty, so this is a narrower "
            "check, not an absent one."
        )
    assert tracked, "`git ls-files` returned nothing for the must-ship dirs"
    absent = sorted(set(tracked) - inside)
    assert not absent, (
        f"{len(absent)} tracked file(s) under {_MUST_SHIP_DIRS} are missing "
        f"from the built sdist, e.g.:\n  " + "\n  ".join(absent[:20]) + "\n"
        "Every one of these is committed evidence that does not reach anyone "
        "who obtains this project from PyPI rather than from GitHub."
    )


def test_the_wheel_does_not_grow_the_pools(tmp_path):
    """The pools belong in the sdist and nowhere near site-packages.

    The cheap way to satisfy the test above would be to widen the wheel too.
    That would put a 190-case benign tool-call corpus and the whole pytest
    suite on the import path of every `pip install xaidr`, which is a cost paid
    by people who will never run a regenerator.
    """
    try:
        from hatchling.build import build_wheel
    except ModuleNotFoundError:
        pytest.skip("hatchling is not importable; cannot build a wheel here")

    import zipfile

    cwd = os.getcwd()
    os.chdir(REPO)
    try:
        name = build_wheel(str(tmp_path))
    finally:
        os.chdir(cwd)

    with zipfile.ZipFile(tmp_path / name) as zf:
        names = zf.namelist()

    strays = [n for n in names
              if n.startswith(("tests/", "scripts/", "asi_battery/", "heldout/",
                               "benign_a2a/", "benign_longform/",
                               "benign_toolcalls/"))
              or n.endswith(".jsonl")]
    assert not strays, (
        "pool or test files leaked into the WHEEL:\n  " + "\n  ".join(strays[:20])
        + "\nThese ship to every `pip install xaidr`. They belong in the sdist."
    )
