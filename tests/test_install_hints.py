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

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

# `pip install` followed by an xaidr extra, quoted or not. Group 1 is the quote
# character (empty when absent), group 2 is the extra name.
_HINT = re.compile(r"""pip install\s+(['"]?)xaidr\[([a-z,]+)\]\1""")


def _declared_extras():
    """The extra names pyproject.toml actually declares."""
    import tomllib

    with open(REPO / "pyproject.toml", "rb") as fh:
        return set(tomllib.load(fh)["project"]["optional-dependencies"])


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


@pytest.mark.parametrize("shell", ["zsh", "bash"])
def test_the_printed_policy_command_is_not_a_glob(shell):
    """Externally, in the real shell: the hint must survive word expansion.

    `:` ignores its arguments, so this measures expansion only — no network, no
    pip, no install. zsh fails an unmatched glob outright; the assertion is that
    the argument arrives intact.
    """
    _, _, whole = next(
        h for h in _hints_in("xaidr/local_policy.py") if h[1] == "policy")
    cmd = whole.replace("pip install", "printf '%s\\n'")
    p = subprocess.run([shell, "-c", cmd], capture_output=True, text=True)
    assert p.returncode == 0, f"{shell} rejected the printed command: {p.stderr.strip()}"
    assert p.stdout.strip() == "xaidr[policy]", (
        f"{shell} expanded the printed argument to {p.stdout.strip()!r}; "
        f"pip would receive something other than xaidr[policy]"
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
