"""Every `pip install xaidr[...]` the package PRINTS must be runnable as printed.

An install hint is an instruction handed to an operator at the moment a feature
refused to work. It has two ways to be wrong and only one of them is obvious:

  1. NAMES AN EXTRA THAT DOES NOT EXIST.  `pip install 'xaidr[polcy]'` errors
     out and the operator knows immediately.
  2. NAMES A REAL EXTRA IN A FORM THE SHELL EATS.  `pip install xaidr[policy]`
     is a glob. zsh — the default macOS shell and the one these are read in —
     refuses it with `no matches found: xaidr[policy]` and never reaches pip.
     bash expands it to the literal only because no file matches; `set -f` or a
     stray `xaidr[policy]` file changes the answer.

(2) is the one that ships, because the string looks right in review and the
person who wrote it had the dependency installed already. The three framework
integrations quote — `pip install 'xaidr[crewai]'`, `'xaidr[langchain]'`,
`'xaidr[haystack]'` — and nothing else in the package does. The policy hint is
the one 1.17.0 fixes; the remaining TEN occurrences are recorded as a strict
xfail at the bottom of this file rather than left to be found again.

TEN, NOT NINE. This file said nine for three releases because it scanned a
hand-typed list of six files rather than the package. `xaidr/types.py:117` was
not on the list and so was not counted. The list is gone — `_emitting_files()`
walks `xaidr/` — and `test_the_hint_scan_reaches_every_file_in_the_package`
cross-checks that walk against an independent `grep`, so the scope of this file
can no longer be a thing someone remembered to update.
"""
from __future__ import annotations

import importlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

# `pip install` followed by an xaidr extra, quoted or not. Group 1 is the quote
# character (empty when absent), group 2 is the extra name.
_HINT = re.compile(r"""pip install\s+(['"]?)xaidr\[([a-z,]+)\]\1""")


def _parsed_extras():
    """Extras via a real TOML parser, or (None, None) when none is importable.

    `tomllib` is stdlib only from 3.11 and pyproject.toml claims 3.10, which is
    what broke both py3.10 jobs in 1.17.0.

    `tomli` covers 3.10 in practice, and for a reason worth writing down: pytest
    itself declares `tomli>=1; python_version<"3.11"`, so any environment that
    can RUN this test already has it. Measured on the py3.10 base job, whose
    install is `pip install .` plus `pip install pytest` and nothing else:

        Collecting tomli>=1 (from pytest)
        Installing collected packages: ... tomli, ... pytest

    So this returns a parser on all six CI jobs and `_scanned_extras` is not the
    path any of them take. It is kept anyway — the guarantee above is a
    transitive dependency of a test runner, which is not ours to rely on — and
    it is executed directly on every job by the agreement test below, so it
    cannot rot unnoticed while unused.
    """
    for name in ("tomllib", "tomli"):
        try:
            parser = importlib.import_module(name)
        except ModuleNotFoundError:
            continue
        with open(REPO / "pyproject.toml", "rb") as fh:
            return set(parser.load(fh)["project"]["optional-dependencies"]), name
    return None, None


# A top-level `key =` line. Extras in this file are one per line; the scan below
# stops at the next table header so nothing outside the section is picked up.
_EXTRA_KEY = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9_.-]*)\s*=", re.M)


def _scanned_extras():
    """Extras read WITHOUT a TOML parser — the last resort, per `_parsed_extras`.

    Deliberately dumb, and its failure direction is the safe one: a declaration
    shape this misses drops an extra from the set, which makes a hint naming
    that extra look UNDECLARED and fails the test loudly. It cannot invent an
    extra and turn a real defect green.

    No CI job reaches it as the fallback (pytest supplies tomli on 3.10), so the
    thing keeping it honest is `test_the_parserless_scan_agrees_with_a_real_toml
    _parse`, which calls it DIRECTLY on all six and diffs it against the parser.
    """
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    header = "[project.optional-dependencies]"
    body = text[text.index(header) + len(header):]
    nxt = re.search(r"^\[", body, re.M)
    if nxt:
        body = body[:nxt.start()]
    body = "\n".join(
        ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))
    return set(_EXTRA_KEY.findall(body))


def _declared_extras():
    """The extra names pyproject.toml actually declares."""
    parsed, _ = _parsed_extras()
    return parsed if parsed is not None else _scanned_extras()


def _hints_in(relpath):
    text = (REPO / relpath).read_text(encoding="utf-8")
    return [(m.group(1), m.group(2), m.group(0)) for m in _HINT.finditer(text)]


# ── the hint this release fixes ──────────────────────────────────────────────

def test_policy_install_hint_names_a_declared_extra():
    """`xaidr[policy]` must be a thing pip can resolve, not a thing we meant."""
    hints = [h for h in _hints_in("xaidr/local_policy.py") if h[1] == "policy"]
    assert hints, "local_policy.py no longer prints a policy install hint"
    assert "policy" in _declared_extras(), (
        "local_policy.py tells the operator to run `pip install xaidr[policy]` "
        "and pyproject.toml declares no `policy` extra; the command errors out"
    )


def test_policy_install_hint_survives_the_shell():
    """The command as PRINTED, run through zsh and bash, must reach pip."""
    quote, extra, whole = next(
        h for h in _hints_in("xaidr/local_policy.py") if h[1] == "policy")
    assert quote, (
        f"the hint is printed as `{whole}` — unquoted. zsh treats xaidr[{extra}] "
        f"as a glob and answers `no matches found: xaidr[{extra}]`; the operator "
        f"is told to run a command that never reaches pip"
    )


# `sh` leads because it is the one that cannot be absent: POSIX requires it, and
# it is present on the Linux runners and on macOS. zsh is the shell the hints are
# READ in, so it stays; it is simply no longer the only one that can catch this.
_SHELLS = ["sh", "bash", "zsh"]


@pytest.mark.parametrize("shell", _SHELLS)
def test_the_printed_policy_command_is_not_a_glob(shell, tmp_path):
    """Externally, in a real shell: the hint must survive word expansion.

    `printf` ignores everything but its arguments, so this measures expansion
    only — no network, no pip, no install.

    THE DECOY FILE IS THE TEST. Run in an empty directory, `xaidr[policy]`
    matches nothing, and the two shells disagree about what that means: zsh
    fails the command outright (`no matches found`) while bash and sh hand the
    unmatched pattern through as a literal and look fine. A version of this test
    that ran in an empty cwd therefore only ever caught the defect via zsh, and
    on a runner without zsh it asserted nothing — a green bash case over a hint
    that zsh would refuse.

    So the cwd gets a file the pattern MATCHES, which is the case the module
    docstring names as changing the answer. Now every shell expands the
    unquoted form to that filename, the argument visibly stops being
    `xaidr[policy]`, and each shell catches the defect on its own. zsh being
    absent costs a shell, not the coverage.
    """
    exe = shutil.which(shell)
    if exe is None:
        assert shell != "sh", "no `sh` on PATH; this is not a POSIX environment"
        pytest.skip(
            f"{shell} is not installed here (GitHub's Linux runners have no "
            f"zsh). The remaining shells run the same assertion against the "
            f"same decoy file and catch the same defect."
        )

    _, extra, whole = next(
        h for h in _hints_in("xaidr/local_policy.py") if h[1] == "policy")

    # `xaidr[policy]` is a bracket expression: one character from p,o,l,i,c,y.
    # Any single one of them makes a matching filename.
    decoy = f"xaidr{extra[0]}"
    (tmp_path / decoy).write_text("")

    cmd = whole.replace("pip install", "printf '%s\\n'")
    p = subprocess.run(
        [exe, "-c", cmd], capture_output=True, text=True, cwd=str(tmp_path))
    assert p.returncode == 0, (
        f"{shell} rejected the printed command `{whole}`: {p.stderr.strip()}"
    )
    assert p.stdout.strip() == f"xaidr[{extra}]", (
        f"{shell} expanded the printed argument to {p.stdout.strip()!r} — it is "
        f"a glob, and it matched the file {decoy!r} that happened to be in the "
        f"operator's directory. pip would be asked to install {p.stdout.strip()!r}, "
        f"which is not a package, instead of the extra xaidr[{extra}]"
    )


def test_at_least_one_shell_actually_ran():
    """A skip must not be able to empty this file of its external check.

    Every shell in `_SHELLS` is skipped when absent, so in principle all three
    could skip and the suite would stay green having run no shell at all. `sh`
    cannot be absent on any platform this package supports; asserting it here
    means the all-skipped outcome is a failure rather than a silent pass.
    """
    present = [s for s in _SHELLS if shutil.which(s)]
    assert present, (
        f"none of {_SHELLS} is on PATH, so the shell-expansion check above "
        f"skipped entirely and this file no longer tests the shell at all"
    )


def test_the_parserless_scan_agrees_with_a_real_toml_parse():
    """Pin the parserless scan to a real parser wherever one exists.

    This runs on all six CI jobs — tomllib on 3.11/3.12, tomli (via pytest) on
    3.10 — so the scan is diffed against a real parse everywhere, and the skip
    below is for environments outside CI rather than a hole in it.
    """
    parsed, module = _parsed_extras()
    if parsed is None:
        pytest.skip(
            "neither tomllib nor tomli is importable; nothing to compare the "
            "parserless scan against"
        )
    assert _scanned_extras() == parsed, (
        f"the parserless extra scan disagrees with {module}: scan found "
        f"{sorted(_scanned_extras())}, {module} found {sorted(parsed)}. "
        f"pyproject.toml declares extras in a shape the 3.10 fallback misreads"
    )


# ── every other hint: declared, always ───────────────────────────────────────

PACKAGE = REPO / "xaidr"


def _emitting_files():
    """Every `.py` file in the SHIPPED PACKAGE, walked — not a list.

    This used to be six paths typed out by hand, and the list was short by two:
    `xaidr/sensor.py` (bolted onto the xfail at the bottom and nowhere else) and
    `xaidr/types.py`, which nothing looked at. So this file reported NINE
    unquoted hints over a package that has ten.

    The scope is the package because the package is what an operator installs:
    a hint is wrong exactly when it ships, and everything under `xaidr/` ships.
    A hint added to a module invented tomorrow is covered the day it is written,
    with nothing to remember.
    """
    return sorted(
        p.relative_to(REPO).as_posix()
        for p in PACKAGE.rglob("*.py")
        if "__pycache__" not in p.parts
    )


_EMITTING_FILES = _emitting_files()


def _grepped_hint_files():
    """The files that print a hint, enumerated by `grep` instead of by Python.

    A SECOND, INDEPENDENT ENUMERATION — the same device as
    `test_the_parserless_scan_agrees_with_a_real_toml_parse` above, applied to
    the other question this file asks. `_EMITTING_FILES` answers "which files do
    we look at"; this answers "which files is there anything to look at in", and
    the two must agree or the scan has a blind spot.

    The pattern is deliberately a SUPERSET of `_HINT`: no backreference, so a
    mismatched-quote site (`pip install 'xaidr[nano]`) matches here and not
    there. That direction is the safe one — a superset can only ever accuse the
    scan of missing something, never excuse it for missing something.
    """
    grep = shutil.which("grep")
    assert grep, "no `grep` on PATH; this is not a POSIX environment"
    p = subprocess.run(
        [grep, "-rlE", r"pip install +['\"]?xaidr\[[a-z,]+\]",
         "xaidr", "--include=*.py"],
        capture_output=True, text=True, cwd=str(REPO))
    # grep exits 1 for "no matches", which is a real answer, not an error.
    assert p.returncode in (0, 1), f"grep failed: {p.stderr.strip()}"
    return sorted(ln for ln in p.stdout.splitlines() if ln.strip())


def test_the_hint_scan_reaches_every_file_in_the_package():
    """The scan must be ENUMERATED from the package, never a hand-kept list.

    This is the defect, not a hypothetical: `_EMITTING_FILES` was six paths
    typed out by hand, so this file reported NINE unquoted hints and there were
    ten. The tenth is `xaidr/types.py:117`, which teaches the broken form in the
    one comment a human is most likely to read it in — the explanation of the
    nano false-positive range, sitting on the dataclass field that carries it.

    A hand-kept list of the places a defect can occur is the same enumeration
    failure the detectors in this repo have had five times. It cannot be fixed
    by adding the tenth entry; it is fixed by not keeping a list.
    """
    grepped = _grepped_hint_files()
    assert grepped, (
        "grep found NO file in xaidr/ printing an install hint. Either the "
        "pattern stopped matching or the package moved — in both cases every "
        "assertion in this file is now passing over an empty set"
    )
    missed = sorted(set(grepped) - set(_EMITTING_FILES))
    assert not missed, (
        "files that print a `pip install xaidr[...]` hint and are NOT scanned "
        "by this file:\n  " + "\n  ".join(missed) + "\n"
        "Every assertion below runs over `_EMITTING_FILES`, so a hint in one of "
        "these is unchecked: it can name an extra pyproject.toml does not "
        "declare, or print a form zsh refuses, and this suite stays green. "
        "Enumerate the package instead of listing it."
    )


def test_every_emitted_hint_names_a_declared_extra():
    declared = _declared_extras()
    bad = []
    for relpath in _EMITTING_FILES:
        for _, extra, whole in _hints_in(relpath):
            for name in extra.split(","):
                if name not in declared:
                    bad.append(f"{relpath}: {whole} (no `{name}` extra)")
    assert not bad, "install hints naming an extra pyproject.toml does not declare:\n" + "\n".join(bad)


# ── found, not fixed: the same defect at five more sites ─────────────────────

@pytest.mark.xfail(strict=True, reason=(
    "FOUND, NOT FIXED. TEN sibling occurrences are unquoted for the same reason "
    "the policy one was — reporters.py x3 ([http] x2, [otel]), nano.py x4 "
    "([nano]), sensor.py x2 ([nano], [http]), types.py x1 ([nano]). Three of "
    "those are raised at the operator (reporters.py:388/447, nano.py:701/741); "
    "the rest are prose that teaches the broken form. Every named extra is "
    "real; each is printed in a shape zsh refuses. Out of scope for 1.17.0, "
    "which changed one line as asked; recorded so it is not rediscovered from "
    "scratch. strict=True, so this flips to a hard failure the moment they are "
    "fixed and the marker is then deleted.\n"
    "\n"
    "THE COUNT WAS NINE UNTIL THE SCAN WAS ENUMERATED. It said nine because "
    "the list above it named six files and this line bolted on a seventh; "
    "`xaidr/types.py:117` was in none of them. The number was a property of "
    "the list, not of the package — which is the reason the list is gone."
))
def test_todo_every_emitted_hint_survives_the_shell():
    unquoted = []
    for relpath in _EMITTING_FILES:
        for quote, extra, whole in _hints_in(relpath):
            if not quote:
                unquoted.append(f"{relpath}: {whole}")
    assert not unquoted, (
        "install hints zsh answers with `no matches found`:\n" + "\n".join(unquoted))
