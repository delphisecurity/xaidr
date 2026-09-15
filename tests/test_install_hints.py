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
the one 1.17.0 fixes; the remaining nine occurrences are recorded as a strict
xfail at the bottom of this file rather than left to be found again.
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

_EMITTING_FILES = [
    "xaidr/local_policy.py",
    "xaidr/reporters.py",
    "xaidr/scanner/nano.py",
    "xaidr/integrations/crewai.py",
    "xaidr/integrations/langchain.py",
    "xaidr/integrations/haystack.py",
]


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
    "FOUND, NOT FIXED. Nine sibling occurrences are unquoted for the same reason "
    "the policy one was — reporters.py x3 ([http] x2, [otel]), nano.py x4 "
    "([nano]), sensor.py x2 ([nano], [http]). Three of those are raised at the "
    "operator (reporters.py:388/447, nano.py:701/741); the rest are prose that "
    "teaches the broken form. Every named extra is real; each is printed in a "
    "shape zsh refuses. Out of scope for 1.17.0, which changed one line as "
    "asked; recorded so it is not rediscovered from scratch. strict=True, so "
    "this flips to a hard failure the moment they are fixed and the marker is "
    "then deleted."
))
def test_todo_every_emitted_hint_survives_the_shell():
    unquoted = []
    for relpath in _EMITTING_FILES + ["xaidr/sensor.py"]:
        for quote, extra, whole in _hints_in(relpath):
            if not quote:
                unquoted.append(f"{relpath}: {whole}")
    assert not unquoted, (
        "install hints zsh answers with `no matches found`:\n" + "\n".join(unquoted))
