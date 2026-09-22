#!/usr/bin/env python3
"""One answer to "which xaidr produced this table?", printed by every report.

NOT A REPORT. Import-only; running it directly does nothing useful.

THE DEFECT THIS EXISTS TO CLOSE. Eleven scripts in this directory did

    REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, REPO)
    from xaidr.sensor import DelphiSensor

and printed nothing about it. The insert is not wrong — run as documented,
`sys.path[0]` is `scripts/`, the repo root never reaches the path, and an
unrelated `xaidr` in site-packages answers instead. What is wrong is that the
insert is SILENT and UNCONDITIONAL, so the script measures the working tree no
matter which interpreter you point at it.

That turns every one of these into an instrument that cannot be used for the one
job a release needs it for. Measured 2026-09-20 while cutting 1.18.0:
`benign_a2a_report.py` run under the published 1.17.0 wheel printed the same
`A2A nodes walked: 274` as under 1.18.0 — from a wheel whose `a2a_structural.py`
contains no `_walk_a2a_nodes` at all. The two runs agreeing was the only tell,
and the 1.18.0 body named two scripts as having this property when eleven did.
`benign_toolcall_report.py`, cited as a U-1 regenerator, was one of the nine
unnamed: under the 1.14.1 wheel it reports the 1.18.0 tree, silently.

THE RULE. A report script may resolve `xaidr` however it likes, but it must say
which one answered. So `bind()` prints the banner ITSELF, once per process, at
import time — before any table, before any argparse, before anything that can
raise. A main() that forgets is not a failure mode that exists, and a script
that dies halfway has still said what it was measuring.

TWO MODES:

    python scripts/foo_report.py                 # measures the WORKING TREE
    XAIDR_FROM_INSTALL=1 python scripts/foo.py   # measures the INSTALLED wheel

The default stays the tree because that is what every committed figure was
measured against and what a contributor editing a rule needs. `XAIDR_FROM_INSTALL`
is the release path: it does NOT touch `sys.path`, and it REFUSES to run if what
it imported is a source tree — the same refusal `corpus_diff.py` and
`fail_closed_cost.py` already implement, which is where the idea comes from. Run
it at a neutral cwd with `-I`, or Python will import `./xaidr/` and the refusal
is the whole point.

The pools are NOT affected by the mode. They are read from the repo root either
way, which is the same separation `corpus_diff.py --pools` draws on purpose:
code from the interpreter, data from the tree.

WHAT "A SOURCE TREE" MEANS HERE, AND WHY IT IS NOT "MY REPO". The refusal used
to ask `commonpath([xaidr.__file__, repo_root]) == repo_root` — is the package
under THIS checkout. That accepts every source tree except one. Measured
2026-09-22 on the dev machine, whose venv holds an editable install pointing at
a DIFFERENT checkout:

    $ XAIDR_FROM_INSTALL=1 python scripts/benign_a2a_report.py
    xaidr    : /Users/…/opena2a/xaidr/__init__.py
    version  : 1.17.0
    measuring: an INSTALLED package — not the tree at /Users/…/worktrees/xaidr/main

`XAIDR_FROM_INSTALL` was set, the resolved `xaidr` was a source tree at 1.17.0,
and the banner called it an installed package and ran. That is the substitution
the flag exists to prevent, arriving through the door the check left open: the
question "is this MY tree" has a false negative for every tree that is not, and
an editable install, a `PYTHONPATH` entry and a sibling worktree all produce
one. So the test below is POSITIVE — is this package installed — and anything
answering from a directory that looks like a checkout is refused wherever it
lives.
"""
from __future__ import annotations

import os
import sys

__all__ = ["Provenance", "bind", "banner_lines", "repo_root_of",
           "source_tree_root_of", "FROM_INSTALL_ENV"]

FROM_INSTALL_ENV = "XAIDR_FROM_INSTALL"

# Printed once per process. `benign_toolcall_report.py` imports
# `asi_boundary_candidates.py`, which binds too; one process, one banner.
_ANNOUNCED = False


class Provenance:
    """Where the measured `xaidr` came from. Never raises on the reporting path.

    `is_repo_copy` is "under THIS checkout" and is what the corpus scripts
    render as their `NOT this repository` warning. `source_tree_root` is the
    stricter, and different, question the release mode turns on: the root of
    whatever checkout answered, ANY checkout, or None when the package is
    genuinely installed. A foreign tree makes the first False and the second
    non-None, and that combination is exactly the case the old single flag
    could not express.
    """

    __slots__ = ("path", "version", "is_repo_copy", "repo_root", "forced",
                 "source_tree_root")

    def __init__(self, path, version, is_repo_copy, repo_root, forced,
                 source_tree_root=None):
        self.path = path
        self.version = version
        self.is_repo_copy = is_repo_copy
        self.repo_root = repo_root
        self.forced = forced
        self.source_tree_root = source_tree_root

    def __repr__(self):  # pragma: no cover - diagnostics only
        where = "source tree" if self.source_tree_root else "installed package"
        return f"<Provenance {self.version} {where} {self.path}>"


def repo_root_of(script_file):
    """The repository root, from a script living in `scripts/`."""
    return os.path.dirname(os.path.dirname(os.path.abspath(script_file)))


# A directory holding an INSTALLED package. Named so an unusual layout can
# never make the check refuse a genuine wheel — the failure mode that would
# turn this guard into the always-refuses kind, which is as useless as the
# always-passes kind and harder to notice.
_INSTALL_DIRS = ("site-packages", "dist-packages")

# A directory holding a SOURCE CHECKOUT. A built distribution never carries
# these next to the package; a tree you can edit always does.
_SOURCE_TREE_MARKERS = ("pyproject.toml", "setup.py", "setup.cfg")


def source_tree_root_of(package_file):
    """The checkout root above an imported package, or None if it is installed.

    Structural, not name-based: look at the directory the package directory
    sits in. For a wheel that is `site-packages`, which has no project file.
    For any checkout — this repo, a sibling worktree, an editable install's
    target — it is the project root, which has one by definition.
    """
    if not package_file:
        return None
    package_dir = os.path.dirname(os.path.abspath(package_file))
    parent = os.path.dirname(package_dir)
    if not parent or parent == package_dir:
        return None
    if os.path.basename(parent) in _INSTALL_DIRS:
        return None
    for marker in _SOURCE_TREE_MARKERS:
        if os.path.isfile(os.path.join(parent, marker)):
            return parent
    return None


def _resolve(repo_root):
    """(path, version, is_repo_copy, source_tree_root) for the imported `xaidr`."""
    try:
        import xaidr
        raw = getattr(xaidr, "__file__", None)
        version = getattr(xaidr, "__version__", "unknown")
    except Exception as exc:  # pragma: no cover - caller imports it first
        return f"<unresolvable: {exc}>", "unknown", False, None
    if not raw:
        # abspath("") is the CWD, which would name the repo by accident.
        return "<no __file__>", version, False, None
    path = os.path.abspath(raw)
    try:
        # commonpath raises across Windows drive letters; a mismatch is the
        # answer we want there anyway.
        is_repo_copy = os.path.commonpath([path, repo_root]) == repo_root
    except ValueError:
        is_repo_copy = False
    return path, version, is_repo_copy, source_tree_root_of(path)


def banner_lines(prov):
    """The lines every report leads with. Returned as well as printed so a test
    can assert on them without parsing a terminal."""
    lines = [
        f"xaidr    : {prov.path}",
        f"version  : {prov.version}",
    ]
    if prov.is_repo_copy:
        lines.append(
            f"measuring: THE WORKING TREE at {prov.repo_root} — not an installed "
            f"wheel. Set {FROM_INSTALL_ENV}=1 (neutral cwd, python -I) to measure "
            f"a published artifact instead."
        )
    elif prov.source_tree_root:
        # The case the old two-way banner stated falsely. Not this checkout, so
        # `is_repo_copy` is False — but a checkout all the same, so calling it
        # "an INSTALLED package" was the substitution the mode exists to stop,
        # printed as fact. An editable install or a PYTHONPATH entry lands here.
        lines.append(
            f"measuring: ANOTHER SOURCE TREE at {prov.source_tree_root} — not an "
            f"installed wheel, and not the tree at {prov.repo_root} either. "
            f"Whatever is checked out there is what the numbers below describe."
        )
    else:
        lines.append(
            f"measuring: an INSTALLED package — not the tree at {prov.repo_root}. "
            f"The pools below still come from that tree."
        )
    return lines


def bind(script_file, *, extra_paths=(), stream=None):
    """Resolve `xaidr`, announce it, and return the `Provenance`.

    Call this BEFORE the first `import xaidr` in the script — the `sys.path`
    shadowing has to happen first, and the banner has to come out before
    anything that can fail.

    `extra_paths` are additional directories to put on `sys.path` regardless of
    mode (a script importing a sibling in `scripts/` needs this and it has
    nothing to do with which `xaidr` answers).
    """
    global _ANNOUNCED

    root = repo_root_of(script_file)
    from_install = bool(os.environ.get(FROM_INSTALL_ENV, "").strip())

    for p in extra_paths:
        if p and p not in sys.path:
            sys.path.insert(0, p)

    if not from_install and root not in sys.path:
        sys.path.insert(0, root)

    try:
        import xaidr  # noqa: F401
    except ImportError as exc:
        sys.exit(
            f"cannot import xaidr: {exc}\n"
            f"{FROM_INSTALL_ENV} is "
            f"{'set, so the repo root was deliberately kept off sys.path' if from_install else 'unset'}."
        )

    path, version, is_repo_copy, tree_root = _resolve(root)
    prov = Provenance(path, version, is_repo_copy, root,
                      forced=not from_install, source_tree_root=tree_root)

    # ANY source tree, not just this one. See the module docstring: "is it my
    # repo" is a question with a false negative for every checkout that is not,
    # and an editable install produces one silently.
    if from_install and tree_root is not None:
        whose = (
            "the tree you were just editing"
            if is_repo_copy
            else f"a DIFFERENT checkout ({tree_root}), reached through an "
                 f"editable install or PYTHONPATH"
        )
        sys.exit(
            f"{FROM_INSTALL_ENV} is set but xaidr resolved to a source tree:\n"
            f"  {path}\n"
            f"  source tree root: {tree_root}\n"
            f"  this repository : {root}\n"
            f"Python imports ./xaidr/ in preference to the installed wheel when "
            f"the cwd is a checkout, and an editable install redirects "
            f"site-packages into one from any cwd at all. So every number this "
            f"script would print is a claim about {whose}, wearing the version "
            f"of the artifact. Run it against a real install at a neutral cwd "
            f"with -I:\n"
            f"  cd / && /path/to/venv/bin/python -I "
            f"{os.path.abspath(script_file)}"
        )

    if not _ANNOUNCED:
        _ANNOUNCED = True
        out = stream if stream is not None else sys.stdout
        for line in banner_lines(prov):
            print(line, file=out)
        print("", file=out)

    return prov
