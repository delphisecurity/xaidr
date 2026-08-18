"""The ORDERING discipline of the command-classifier ruleset.

`classify_command_findings` and `_classify_segment` are both FIRST-MATCH-WINS per
segment. Order is therefore not cosmetic: it decides which rule attributes a
segment, and — because only rules carrying a `detect` block enforce — it can
decide whether a segment blocks at all. A `detect` added to a rule that a
broader rule already shadows is dead code, and a coverage gate measured against
it measures nothing.

The escalate family documented this discipline and followed it (`escalate.
setuid_bit` ahead of the general `escalate.privileged_wrapper`). The exec family
was ordered the other way round, so three rules were unreachable for exactly the
commands that motivated them:

    perl -e 'system("id")'          interpreter_payload shadowed code_in_args
    socat exec:'bash -li' …         tool_exec_flag      shadowed remote_shell
    exec /bin/bash                  bare_shell          shadowed wrapper_exec

These tests pin the fix so a future insertion cannot silently re-shadow. They
assert on the RULESET's order and on the winner for a witness command, not on
scores — reordering classify-only rules must never move a score, and
tests/test_shell_classes_stage3.py already holds that line.
"""
from __future__ import annotations

import json
import os

import pytest

from xaidr.authz.classifier import _RULESET, _segment_matches
from xaidr.scanner.command_parse import parse_command

_CORPUS_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "shell_corpus.json")

RULES = _RULESET["command_classifiers"]["rules"]
INDEX = {r["id"]: i for i, r in enumerate(RULES)}


def _matching(command):
    """Every rule that matches any non-degraded segment, in ruleset order."""
    out = []
    for seg in parse_command(command):
        if seg.parse_degraded:
            continue
        for rule in RULES:
            block = rule.get("match")
            if isinstance(block, dict) and _segment_matches(block, seg):
                out.append(rule["id"])
    return out


def _winner(command):
    """The rule that first-match-wins would attribute, per segment."""
    winners = []
    for seg in parse_command(command):
        if seg.parse_degraded:
            continue
        for rule in RULES:
            block = rule.get("match")
            if isinstance(block, dict) and _segment_matches(block, seg):
                winners.append(rule["id"])
                break
    return winners


# ── (1) the shadowing pairs, each with the witness that proves the overlap ────
# (specific, general, witness, why the specific rule is the sharper fact)
SHADOW_PAIRS = [
    (
        "exec.code_in_args", "exec.interpreter_payload",
        "perl -e 'system(\"id\")'",
        "the payload CALLS a process spawner; the -e flag alone only says a "
        "payload is present, and `python -c 'print(1)'` has one too",
    ),
    (
        "exec.remote_shell", "exec.tool_exec_flag",
        "socat exec:'bash -li' tcp-listen:4444",
        "a network binary bound to a shell is a reverse/bind shell; "
        "tool_exec_flag only sees that SOME operand looks like an exec flag",
    ),
    (
        "exec.wrapper_exec", "exec.bare_shell",
        "exec /bin/bash",
        "`exec` REPLACES the current process; bare_shell would report it as an "
        "ordinary interactive spawn",
    ),
]


@pytest.mark.parametrize("specific,general,witness,reason",
                         SHADOW_PAIRS, ids=[p[0] for p in SHADOW_PAIRS])
def test_the_specific_rule_precedes_the_rule_that_would_shadow_it(
        specific, general, witness, reason):
    assert INDEX[specific] < INDEX[general], (
        f"{specific} (index {INDEX[specific]}) must precede {general} "
        f"(index {INDEX[general]}) — {reason}"
    )


@pytest.mark.parametrize("specific,general,witness,reason",
                         SHADOW_PAIRS, ids=[p[0] for p in SHADOW_PAIRS])
def test_the_shadowing_pair_still_actually_overlaps(
        specific, general, witness, reason):
    """NON-VACUITY. An ordering constraint between two rules that no longer match
    the same command is a rule about nothing — it would keep passing while the
    protection it describes had evaporated. If this fails, the patterns changed
    and the pair above needs re-deriving, not re-ordering.
    """
    matched = _matching(witness)
    assert specific in matched and general in matched, (
        f"{witness!r} no longer matches both {specific} and {general} "
        f"(matched: {matched}) — the ordering constraint is now vacuous"
    )


@pytest.mark.parametrize("specific,general,witness,reason",
                         SHADOW_PAIRS, ids=[p[0] for p in SHADOW_PAIRS])
def test_the_witness_is_attributed_to_the_specific_rule(
        specific, general, witness, reason):
    assert specific in _winner(witness), (
        f"{witness!r} attributed to {_winner(witness)}, expected {specific}"
    )


# ── (2) the position the privilege wrappers must keep ────────────────────────

def test_the_privilege_wrappers_keep_their_documented_position():
    """`escalate.privileged_wrapper` states its own position requirement in its
    `comment`, and both halves of the reorder depend on it holding:

      after  exec.interpreter_payload — so `su -c '<payload>'` classifies by its
                                        PAYLOAD (execute) rather than by sudo
      before exec.bare_shell          — so `sudo bash` is the escalation it is
                                        rather than a generic shell spawn
    """
    assert INDEX["exec.interpreter_payload"] < INDEX["escalate.privileged_wrapper"]
    assert INDEX["escalate.privileged_wrapper"] < INDEX["exec.bare_shell"]
    assert INDEX["escalate.privileged_wrapper_stripped"] < INDEX["exec.bare_shell"]


# ── (3) the invariant that makes reordering the exec block safe ──────────────
# Reordering rules is only safe while no classify-only rule sits in front of an
# ENFORCING rule it can shadow: that would silently turn a block into a
# classification. Exactly one such pair exists and it is deliberate — the whole
# reason escalate.sudoers_edit is positioned where it is.

DOCUMENTED_SHADOWS_OF_AN_ENFORCING_RULE = {
    # winner (classify-only)      shadowed (enforcing)
    ("escalate.sudoers_edit", "cred.sensitive_file"),
}


def test_no_classify_only_rule_shadows_an_enforcing_rule():
    """A classify-only rule that outranks a `detect` rule downgrades a block to a
    classification, silently. Checked over the whole corpus rather than a
    hand-list so a new rule cannot introduce one unnoticed.
    """
    with open(_CORPUS_PATH, encoding="utf-8") as fh:
        corpus = json.load(fh)
    pool = ([a["command"] for a in corpus["attacks"]]
            + [b["command"] for b in corpus["benign"]])

    violations = set()
    for command in pool:
        for seg in parse_command(command):
            if seg.parse_degraded:
                continue
            matched = [r for r in RULES
                       if isinstance(r.get("match"), dict)
                       and _segment_matches(r["match"], seg)]
            if not matched or matched[0].get("detect"):
                continue
            for shadowed in matched[1:]:
                if shadowed.get("detect"):
                    violations.add((matched[0]["id"], shadowed["id"]))

    assert violations <= DOCUMENTED_SHADOWS_OF_AN_ENFORCING_RULE, (
        f"undocumented shadowing of an enforcing rule: "
        f"{sorted(violations - DOCUMENTED_SHADOWS_OF_AN_ENFORCING_RULE)}"
    )


def test_the_documented_enforcing_shadow_is_still_real():
    """NON-VACUITY for the exception list: if escalate.sudoers_edit stops
    shadowing cred.sensitive_file, the entry is stale and must be deleted rather
    than left as a standing permission.
    """
    matched = _matching("sudo visudo -f /etc/sudoers.d/backdoor")
    assert "escalate.sudoers_edit" in matched and "cred.sensitive_file" in matched, (
        "the documented exception no longer occurs — drop it from "
        "DOCUMENTED_SHADOWS_OF_AN_ENFORCING_RULE"
    )
