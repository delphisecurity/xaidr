"""Every runnable report in `scripts/` must say which `xaidr` answered it.

THE DEFECT. Eleven scripts in `scripts/` did

    REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, REPO)
    from xaidr.sensor import DelphiSensor

and printed nothing about it. The insert itself is right — run as documented,
`sys.path[0]` is `scripts/`, the repo root never reaches the path, and an
unrelated site-packages `xaidr` answers instead. What was wrong is that it was
SILENT and UNCONDITIONAL: point any interpreter at these scripts and they
measure the working tree regardless, while the table says nothing about it.

That makes every one of them useless for the job a release needs them for.
Measured 2026-09-20: `benign_a2a_report.py` under the published 1.17.0 wheel
printed the same `A2A nodes walked: 274` as under 1.18.0 — from a wheel whose
`a2a_structural.py` has no `_walk_a2a_nodes` at all. The 1.18.0 body named TWO
scripts as having this property. Eleven did, and `benign_toolcall_report.py` —
cited in the same body as a U-1 regenerator — was among the nine it did not
name.

WHY THIS FILE IS ENUMERATED AND NOT A LIST. "Two, when it was eleven" is the
same failure as tests/test_install_hints.py's "nine, when it was ten" and the
five the detectors have had: a count that is a property of a hand-kept list
rather than of the thing being counted. So the scope here is derived — every
`scripts/*.py` that BOTH touches `xaidr` and is runnable (`__main__`) — and a
script added tomorrow is covered the day it lands.

`scripts/_provenance.py` and `scripts/longform_bounds.py` fall out of scope
without being excepted: neither has a `__main__` block, because neither prints
anything. They are libraries the runnable scripts import, and the banner their
caller prints is the one that describes the `xaidr` they will also resolve.
"""
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = REPO / "scripts"

# The first line `_provenance.banner_lines` emits.
_BANNER = re.compile(r"^xaidr\s*:\s*\S")


def _module_source(path):
    return path.read_text(encoding="utf-8")


def _touches_xaidr(tree):
    """Any `import xaidr` / `from xaidr… import …`, at any nesting depth.

    Walked rather than read off `tree.body` on purpose: several of these
    scripts import xaidr lazily inside a function, and a lazy import resolves
    through exactly the same shadowed `sys.path`.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(a.name == "xaidr" or a.name.startswith("xaidr.")
                   for a in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod == "xaidr" or mod.startswith("xaidr."):
                return True
    return False


def _is_runnable(source):
    return '__name__ == "__main__"' in source or "__name__ == '__main__'" in source


def _in_scope():
    """(path, source) for every runnable script that touches xaidr."""
    out = []
    for path in sorted(SCRIPTS.glob("*.py")):
        source = _module_source(path)
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:  # pragma: no cover - a broken script is a bug
            pytest.fail(f"{path.name} does not parse: {exc}")
        if _touches_xaidr(tree) and _is_runnable(source):
            out.append((path, source))
    return out


IN_SCOPE = _in_scope()
IN_SCOPE_IDS = [p.name for p, _ in IN_SCOPE]


def test_the_scope_is_not_empty():
    """A derived scope can derive to nothing; that must fail, not pass.

    The whole file is parametrized over `IN_SCOPE`. If the glob, the AST walk
    or the `__main__` test ever stops matching, pytest reports zero collected
    cases as a green run — a check that constrains nothing, reported as
    coverage. Eleven is the number that existed when this was written; the
    floor is deliberately lower so ordinary churn does not trip it.
    """
    assert len(IN_SCOPE) >= 10, (
        f"only {len(IN_SCOPE)} runnable xaidr-touching script(s) found in "
        f"{SCRIPTS}: {IN_SCOPE_IDS}. Eleven had the defect this file exists to "
        f"prevent, so a scope this small means the enumeration broke, not that "
        f"the scripts went away."
    )


@pytest.mark.parametrize("path,source", IN_SCOPE, ids=IN_SCOPE_IDS)
def test_each_report_resolves_or_announces_its_package(path, source):
    """The rule, in full: announce which code answered, or refuse to guess.

    Two acceptable shapes, and a script may use either:

      ANNOUNCE  it calls `_provenance.bind()`, which prints the resolved path
                and version at import time — before argparse, before the first
                table, before anything that can raise.
      REFUSE    it asserts `site-packages` is in `xaidr.__file__` and exits
                otherwise, which is what `corpus_diff.py` and
                `fail_closed_cost.py` already do because they are cross-version
                instruments and a source tree would make both sides equal.

    What is NOT acceptable is the third shape, which is what eleven of these
    were: put the repo root on `sys.path` and say nothing.
    """
    announces = "_provenance" in source and re.search(r"\bbind\(", source)
    refuses = "site-packages" in source
    assert announces or refuses, (
        f"{path.name} imports xaidr and is runnable, but neither announces "
        f"which copy answered nor refuses a source tree.\n"
        f"Add the four-line bind from scripts/_provenance.py:\n"
        f"    _HERE = os.path.dirname(os.path.abspath(__file__))\n"
        f"    if _HERE not in sys.path:\n"
        f"        sys.path.insert(0, _HERE)\n"
        f"    from _provenance import bind, repo_root_of\n"
        f"    PROV = bind(__file__)\n"
        f"Without it this script measures the working tree under every "
        f"interpreter, including a venv holding a published wheel, and its "
        f"output gives the reader no way to tell."
    )


@pytest.mark.parametrize("path,source", IN_SCOPE, ids=IN_SCOPE_IDS)
def test_each_report_prints_the_banner_on_import(path, source):
    """Externally: import the module in a fresh interpreter and read stdout.

    IMPORTING, NOT RUNNING. The banner has to come out of the module body, not
    out of `main()`, and this is the assertion that pins the difference: a
    script whose provenance line lives in its report header prints nothing here
    and fails. That matters because a report that dies halfway — no nano extra,
    a missing pool, a bad argument — has still told you what it was measuring,
    and because a `main()` is a thing someone can forget to wire up.

    Scripts that REFUSE instead of announcing are checked by the test above and
    skipped here; their contract is an exit code, not a line of output.
    """
    if "site-packages" in source and "_provenance" not in source:
        pytest.skip(f"{path.name} refuses a source tree instead of announcing")

    p = subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, {str(SCRIPTS)!r}); "
         f"__import__({path.stem!r})"],
        capture_output=True, text=True, cwd=str(REPO), timeout=300,
    )
    assert p.returncode == 0, (
        f"importing {path.name} failed:\n{p.stderr[-2000:]}"
    )
    first = (p.stdout.splitlines() or [""])[0]
    assert _BANNER.match(first), (
        f"{path.name} printed no provenance banner when imported. First line "
        f"of stdout was {first!r}.\n"
        f"`_provenance.bind()` prints it, so this means bind() is not called "
        f"at module level — it is inside main(), or behind a condition. A "
        f"reader of this script's output would have no way to tell whether the "
        f"numbers came from this tree or from an installed wheel."
    )


sys.path.insert(0, str(SCRIPTS))
import _provenance  # noqa: E402

REPORT = SCRIPTS / "benign_a2a_report.py"


def _stub_source_tree(root, version="0.0.0-stub"):
    """A directory that IS a checkout: a project file beside an `xaidr` package.

    Only `bind()` runs before the refusal — it does `import xaidr` and nothing
    deeper — so the package does not need to be functional to exercise the
    guard. It needs to be a source tree, which is a fact about the directory.
    """
    (root / "xaidr").mkdir(parents=True)
    (root / "xaidr" / "__init__.py").write_text(
        f'__version__ = "{version}"\n', encoding="utf-8"
    )
    (root / "pyproject.toml").write_text(
        '[project]\nname = "xaidr"\nversion = "0.0.0"\n', encoding="utf-8"
    )
    return root


def _source_tree_root_line(output):
    """The `source tree root:` the refusal names, or None."""
    for line in output.splitlines():
        if line.strip().startswith("source tree root:"):
            return line.split(":", 1)[1].strip()
    return None


def test_from_install_refuses_the_cwd_shadowing_a_checkout_creates():
    """The other half of the rule: `XAIDR_FROM_INSTALL=1` must not guess.

    Setting the variable is not enough on its own — with a checkout on
    `sys.path`, Python imports `./xaidr/` in preference to the installed wheel,
    and a mode that trusted the variable would print the version of the
    artifact over a measurement of the tree. That is the 1.17.0-vs-1.18.0
    failure one layer up, so the refusal is checked, not the flag.

    THE INVOCATION IS LOAD-BEARING, and this test used to get it wrong. It ran
    `python scripts/benign_a2a_report.py` with `cwd=REPO` and asserted a
    refusal, on the stated grounds that "Python imports ./xaidr/ ahead of
    site-packages here". It does not. For a script run BY PATH, `sys.path[0]`
    is the script's own directory — `scripts/` — and the repo root never
    reaches the path at all. Measured on 3.12.14 in a container with a plain
    `pip install .`:

        $ XAIDR_FROM_INSTALL=1 python scripts/benign_a2a_report.py
        xaidr    : /usr/local/lib/python3.12/site-packages/xaidr/__init__.py
        measuring: an INSTALLED package — not the tree at /w

    The wheel genuinely answered, so exiting 0 was CORRECT and the assertion
    was wrong about its own setup. It only passed on a dev machine because the
    venv there holds an editable install, i.e. for a reason unrelated to what
    it claimed to test. `python -c` is the form that actually puts the cwd on
    `sys.path` (`sys.path[0]` is `''`), which is why the banner test above uses
    it and why this one now does too.
    """
    env = dict(os.environ, XAIDR_FROM_INSTALL="1")
    p = subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, {str(SCRIPTS)!r}); "
         f"__import__({REPORT.stem!r})"],
        capture_output=True, text=True, cwd=str(REPO), env=env, timeout=300,
    )
    combined = p.stdout + p.stderr
    assert p.returncode != 0, (
        "XAIDR_FROM_INSTALL=1 with the repo root on sys.path exited 0. Python "
        "imports ./xaidr/ ahead of site-packages here, so the script measured "
        "the working tree while claiming to measure an installed artifact — "
        f"the exact substitution the flag exists to prevent. Output:\n"
        f"{combined[-1500:]}"
    )
    assert "source tree" in combined, (
        f"the refusal does not say what went wrong. Output was:\n{combined[-1500:]}"
    )
    assert _source_tree_root_line(combined) == str(REPO), (
        f"the refusal should name this checkout as the tree that answered. "
        f"Output was:\n{combined[-1500:]}"
    )


def test_from_install_refuses_a_checkout_that_is_not_this_one(tmp_path):
    """THE DISCRIMINATING CASE, and the one the guard used to let through.

    The refusal used to ask `commonpath([xaidr.__file__, repo_root]) ==
    repo_root` — is the package under THIS checkout. That question has a false
    negative for every checkout that is not, and an editable install, a
    PYTHONPATH entry or a sibling worktree each produce one. Measured
    2026-09-22 on the dev machine, whose venv holds an editable install
    pointing at a different checkout:

        $ XAIDR_FROM_INSTALL=1 python -m pytest …
        xaidr    : /Users/…/opena2a/xaidr/__init__.py
        version  : 1.17.0
        measuring: an INSTALLED package — not the tree at /Users/…/xaidr/main

    A source tree at 1.17.0, under the release flag, announced as an installed
    package, and not refused. The old test could not see it: the tree it
    reasoned about was this one, and this one was not the problem.

    So the tree here is deliberately FOREIGN — a fresh checkout in tmp_path
    with nothing to do with REPO — and the assertion is that the refusal
    happens anyway and names it.

    THE SUBJECT IS `bind()`, NOT THE REPORT. Driving the guard directly is
    what makes the EXIT CODE discriminating. Run through
    `benign_a2a_report.py`, the stub tree has no `xaidr.scanner`, so an
    un-refusing guard still dies — on ModuleNotFoundError, three lines after
    announcing the tree as installed. The test would go red against the old
    guard while the returncode assertion passed for a reason that has nothing
    to do with provenance, and it would break the day the report's imports
    change. `bind()` is the unit that decides; a run that reaches the print
    after it is a run the guard permitted.
    """
    foreign = _stub_source_tree(tmp_path / "elsewhere")
    neutral = tmp_path / "neutral"
    neutral.mkdir()

    env = dict(os.environ, XAIDR_FROM_INSTALL="1", PYTHONPATH=str(foreign))
    p = subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, {str(SCRIPTS)!r}); "
         f"from _provenance import bind; bind({str(REPORT)!r}); "
         f"print('NOT REFUSED')"],
        capture_output=True, text=True, cwd=str(neutral), env=env, timeout=300,
    )
    combined = p.stdout + p.stderr

    assert "NOT REFUSED" not in combined, (
        f"bind() returned normally with a source tree at {foreign} ahead of "
        f"site-packages under XAIDR_FROM_INSTALL=1. A checkout answered and "
        f"the script was told it had measured an installed artifact. "
        f"Output:\n{combined[-1500:]}"
    )
    assert p.returncode != 0, (
        f"XAIDR_FROM_INSTALL=1 exited 0 with a source tree at {foreign} ahead "
        f"of site-packages. A checkout answered and the script reported it as "
        f"an installed artifact. Output:\n{combined[-1500:]}"
    )
    assert "source tree" in combined, (
        f"the refusal does not say what went wrong. Output was:\n{combined[-1500:]}"
    )
    named = _source_tree_root_line(combined)
    assert named is not None and named != str(REPO), (
        f"the refusal must name the FOREIGN tree that actually answered, not "
        f"this repository — naming {str(REPO)!r} would mean the old "
        f"is-it-my-repo test is still what is running. Got {named!r} from:\n"
        f"{combined[-1500:]}"
    )
    assert "an INSTALLED package" not in combined, (
        f"a source tree was announced as an installed package. Output:\n"
        f"{combined[-1500:]}"
    )


# ── the negative direction: the guard must not simply always refuse ──────────
#
# A guard that refuses everything passes every test above while making the
# release mode unusable, and this workstream has already shipped one of those.
# The classification is therefore asserted in BOTH directions, on constructed
# layouts so the answer does not depend on how the ambient venv was installed.


def test_an_installed_layout_is_not_classified_as_a_source_tree(tmp_path):
    """site-packages has no project file beside the package; a checkout does."""
    installed = tmp_path / "lib" / "site-packages" / "xaidr"
    installed.mkdir(parents=True)
    (installed / "__init__.py").write_text("", encoding="utf-8")
    assert _provenance.source_tree_root_of(str(installed / "__init__.py")) is None

    # Same layout, but the parent is not a recognised install dir AND carries
    # no project file — still installed, by absence of any checkout marker.
    plain = tmp_path / "somewhere" / "xaidr"
    plain.mkdir(parents=True)
    (plain / "__init__.py").write_text("", encoding="utf-8")
    assert _provenance.source_tree_root_of(str(plain / "__init__.py")) is None


def test_a_checkout_layout_is_classified_as_a_source_tree(tmp_path):
    """Any directory holding a project file beside the package is a tree."""
    tree = _stub_source_tree(tmp_path / "checkout")
    got = _provenance.source_tree_root_of(str(tree / "xaidr" / "__init__.py"))
    assert got == str(tree)

    # And this repository, which is the layout the release path runs against.
    assert _provenance.source_tree_root_of(str(REPO / "xaidr" / "__init__.py")) \
        == str(REPO)


def test_a_real_install_under_the_flag_is_allowed_to_run():
    """End to end, in CI's configuration: a genuine wheel must NOT be refused.

    Skipped when the ambient `xaidr` is itself a checkout — an editable dev
    venv cannot demonstrate this, and asserting it there would be asserting
    something false. The classification's negative direction is covered
    unconditionally by the two tests above; this adds the end-to-end half in
    the environment that has a real install, which is exactly the CI job where
    `pip install .` puts a built copy in site-packages.
    """
    ambient = _provenance.source_tree_root_of(
        subprocess.run(
            [sys.executable, "-c",
             "import xaidr, sys; sys.stdout.write(xaidr.__file__ or '')"],
            capture_output=True, text=True, cwd=str(SCRIPTS), timeout=300,
        ).stdout.strip() or None
    )
    if ambient is not None:
        pytest.skip(
            f"the installed xaidr is a checkout at {ambient} (editable "
            f"install); no real install here to run the negative against"
        )

    env = dict(os.environ, XAIDR_FROM_INSTALL="1")
    env.pop("PYTHONPATH", None)
    p = subprocess.run(
        [sys.executable, str(REPORT)],
        capture_output=True, text=True, cwd=str(REPO), env=env, timeout=300,
    )
    combined = p.stdout + p.stderr
    assert p.returncode == 0, (
        f"XAIDR_FROM_INSTALL=1 refused a genuinely installed xaidr. The guard "
        f"has become the always-refuses kind, which makes the release path "
        f"unusable. Output:\n{combined[-1500:]}"
    )
    assert "an INSTALLED package" in combined, (
        f"an installed wheel answered but the banner did not say so. Output:\n"
        f"{combined[-1500:]}"
    )
