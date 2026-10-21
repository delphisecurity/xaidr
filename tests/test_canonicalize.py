"""The shell canonicalization stage: normalize deterministically, flag or block
the unresolvable, never execute.

These assert the stage in isolation (the sensor-level verdicts live in
test_shell_classification.py and test_guardfall_shell_classes.py). The first
pins the division of labour: `reconstruct` removes quotes and does not
word-split `$IFS`; the stage does.
"""
from __future__ import annotations

import pytest

from xaidr.scanner.command_parse import reconstruct
from xaidr.scanner.canonicalize import canonicalize

T = "/tmp/xaidr-scratch/guardfall-target"


def _rules(text):
    return {f["rule"] for f in canonicalize(text, "shell").findings}


# ── reconstruct does not expand $IFS; the stage does ─────────────────────────

def test_reconstruct_does_not_collapse_ifs_word_splitting():
    """shlex removes quotes, it does not word-split, so the IFS form is one
    token and comes back unchanged. Expansion is the stage's job."""
    out = reconstruct(f"rm$IFS-rf$IFS{T}")
    assert "$IFS" in out                       # not expanded
    assert out != f"rm -rf {T}"                # not the plain form


def test_canonicalize_collapses_ifs_word_splitting():
    """What reconstruct cannot do, the stage does."""
    assert canonicalize(f"rm$IFS-rf$IFS{T}", "shell").text == f"rm -rf {T}"
    assert canonicalize(f"rm${{IFS}}-rf${{IFS}}{T}", "shell").text == f"rm -rf {T}"


# ── deterministic rewrites (normalize, then the classifier decides) ──────────

def test_ifs_separators_expand_when_ifs_is_not_reassigned():
    c = canonicalize(f"rm$IFS-rf$IFS{T}", "shell")
    assert "ifs_to_space" in c.applied
    assert c.findings == []                    # the real target decides downstream


def test_in_line_literal_variable_is_substituted():
    c = canonicalize(f"x=rm; $x -rf {T}", "shell")
    assert "literal_var_substituted" in c.applied
    assert f"rm -rf {T}" in c.text


def test_literal_value_that_is_itself_an_expansion_is_not_substituted():
    """`TAG=$(date)` is not a literal binding; the use is left unresolved."""
    c = canonicalize('TAG=$(date +%F); echo "$TAG"', "shell")
    assert "literal_var_substituted" not in c.applied
    assert "$TAG" in c.text


def test_single_quoted_use_is_not_substituted():
    c = canonicalize("x=rm; echo '$x'", "shell")
    assert "'$x'" in c.text


# ── unresolvable constructs: verdict-table verdicts ──────────────────────────

def test_ifs_reassigned_is_out_of_scope_and_not_expanded():
    c = canonicalize("IFS=,; x=rm,-rf,/etc; $x", "shell")
    assert "ifs_to_space" not in c.applied     # reassigned -> not expanded
    assert "ifs_reassigned" in c.applied


@pytest.mark.parametrize("cmd", [
    f"$(echo rm) -rf {T}",
    f"`echo rm` -rf {T}",
])
def test_command_substitution_in_a_destructive_slot_blocks(cmd):
    assert "canon.substitution_in_destructive_position" in _rules(cmd)


def test_command_substitution_with_no_destructive_signal_passes():
    assert _rules("docker build -t app:$(git rev-parse --short HEAD) .") == set()
    assert _rules('TAG=$(date +%F); echo "$TAG"') == set()


def test_unresolved_verb_flags_never_blocks():
    assert _rules("$EDITOR notes.txt") == {"canon.unresolved_verb"}


def test_unresolved_destructive_target_flags_never_blocks():
    assert _rules('rm -rf "$BUILD_DIR"') == {"canon.unresolved_destructive_target"}


def test_safe_in_project_target_has_no_finding():
    for cmd in ["rm -rf ./build", "rm -r -f build/", "rm --recursive --force dist"]:
        assert _rules(cmd) == set(), cmd


# ── robustness ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("value", ["", "   ", "\x00", "rm", "'unbalanced"])
def test_never_raises_and_always_returns_canonical(value):
    c = canonicalize(value, "shell")
    assert isinstance(c.text, str)


def test_unknown_language_returns_input_unchanged():
    c = canonicalize("SELECT 1", "sql")
    assert c.text == "SELECT 1" and c.applied == [] and c.findings == []


# ── string values: literals joined, base64 decoded, nothing evaluated ────────

def _s(text):
    return canonicalize(text, "string")


@pytest.mark.parametrize("text,joined", [
    ('"ab" + "cd"', '"abcd"'),
    ("'ab' + 'cd' + 'ef'", "'abcdef'"),
    ('"ab" "cd"', '"abcd"'),
    ('"ab" . "cd"', '"abcd"'),
    ("'ab' || 'cd'", "'abcd'"),
    ('"ab" .. "cd"', '"abcd"'),
])
def test_adjacent_quoted_literals_are_joined(text, joined):
    c = _s(text)
    assert c.text == joined and "literals_joined" in c.applied


def test_a_name_between_literals_is_not_joined():
    """`"a" + name + "b"` is not two literals of one concatenation; the value of
    `name` is unknown and is never looked up."""
    assert _s('"Hello " + name + "!"').text == '"Hello " + name + "!"'


def test_base64_run_that_decodes_to_text_is_decoded():
    import base64
    run = base64.b64encode(b"plain text inside").decode()
    c = _s(f"payload={run}")
    assert c.text == "payload=plain text inside" and "base64_decoded" in c.applied


def test_base64url_run_without_padding_is_decoded():
    import base64
    run = base64.urlsafe_b64encode(b"plain text inside??>>").decode().rstrip("=")
    assert _s(run).text == "plain text inside??>>"


@pytest.mark.parametrize("text", [
    "sha256:" + __import__("hashlib").sha256(b"xaidr").hexdigest(),
    "ghp_" + "Ab3" * 12,                      # an inline token is left as written
    "src/components/NavigationBarContainer.tsx",
    __import__("base64").b64encode(b"\x89PNG\r\n\x1a\n" + bytes(range(256))).decode(),
])
def test_identifiers_and_binary_base64_are_left_unchanged(text):
    """A run that decodes to bytes that are not printable text (a PNG, a hash,
    an identifier) is not text, so it is left exactly as written."""
    assert _s(text).text == text


def test_decoded_text_is_never_executed():
    """D5: the decoded form is a string handed to a scanner. A decoded command
    is returned as text; nothing runs it."""
    import base64
    run = base64.b64encode(b"touch /tmp/xaidr-scratch/must-not-exist").decode()
    assert _s(run).text == "touch /tmp/xaidr-scratch/must-not-exist"
    import os
    assert not os.path.exists("/tmp/xaidr-scratch/must-not-exist")


@pytest.mark.parametrize("value", ["", "'", '"a" +', "=" * 5000, "A" * 20000, '"x" + ' * 3000])
def test_string_never_raises(value):
    assert isinstance(_s(value).text, str)
