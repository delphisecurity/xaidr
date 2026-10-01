"""The discriminating reds, against the REAL core (§5.4; ruling 2026-09-24).

``reference_ledger.py`` in delphi-sentinel is an executable spec of C-18 and C-3
alone. Its gate step 9 proves each probe class goes red under one sabotage —
against the ORACLE. That proves the corpus can discriminate, not that this core
does. So each sabotage here breaks exactly one rule inside ``xaidr.value_origin``
itself (one private function replaced for the duration of a test) and requires:

  (a) every case of the probe classes the sabotage targets CHANGES wire;
  (b) no other case changes — including all 390 original cases;
  (c) the core agrees with the oracle's committed answer (oracle.jsonl) on every
      case in scope, unsabotaged and sabotaged. Disagreement is a red: otherwise
      the oracle becomes what is tested and the core never is.

Scope of (c): the oracle does no normalisation, so it answers ``unresolved`` for
``format_variance`` and ``subdomain_path_drift`` where the core's §5.2
expectation differs by design; gate step 9's ORACLE_EXPECT says so for exactly
those two classes, and they are the only ones excluded.

These tests go GREEN when the probes discriminate. The PR body pastes the other
direction: the same sabotages applied to the core's SOURCE, and test_core.py
going red with messages.
"""
from __future__ import annotations

import collections
from contextlib import contextmanager

import pytest

from xaidr.value_origin import Origin, unbind_ledger
from xaidr.value_origin import _ledger as L

from .harness import load_jsonl, run_corpus_flow

FLOWS = load_jsonl("flows.jsonl")
ORACLE = {(r["case_id"], r["config"], r["sabotage"]): r["wire"] for r in load_jsonl("oracle.jsonl")}
ORACLE_BLIND = {"format_variance", "subdomain_path_drift"}   # gate step 9's own note
ORIGINAL_CLASSES = {"contact_resolution", "id_resolution", "url_templating", "pagination",
                    "alias_expansion", "subdomain_path_drift", "format_variance",
                    "trivial_control", "injected_recipient", "exfil_url",
                    "quoted_hostile_destination", "a2a_authorized", "a2a_broken",
                    "a2a_laundering"}
# Gate step 9's SABOTAGE_RED, verbatim.
SABOTAGE_RED = {
    "last_wins": {"tiebreak_principal_first", "tiebreak_no_lowering", "tiebreak_read_no_raise"},
    "never_raise": {"tiebreak_principal_raise"},
    "any_raise": {"tiebreak_read_no_raise"},
    "ignore_input_scan": {"tiebreak_flagged_no_raise"},
    "ignore_key_args": {"attacker_keyed_lookup"},
}
_RANK = {Origin.UNTRUSTED_SOURCE: 1, Origin.TRUSTED_SOURCE: 2, Origin.PRINCIPAL: 3}


def _last_wins(old, new):
    return new


def _never_raise(old, new):
    if old is None:
        return new
    if old[0] is Origin.PRINCIPAL and new[0] is Origin.PRINCIPAL and new[1] and not old[1]:
        return (Origin.PRINCIPAL, True, None)
    return old


def _any_raise(old, new):
    kept = _REAL_MERGE(old, new)
    if kept is old and old is not None and _RANK[new[0]] > _RANK[old[0]]:
        return new
    return kept


SABOTAGES = {
    "last_wins": ("_merge", _last_wins),
    "never_raise": ("_merge", _never_raise),
    "any_raise": ("_merge", _any_raise),
    "ignore_input_scan": ("_principal_clean", lambda input_clean: True),
    "ignore_key_args": ("_keys_authorized", lambda lg, keys: (True, True)),
    # C-3a: the read inherits its weakest key's flag. Removed: every read declared.
    "c3a_propagation": ("_read_declared", lambda bases: True),
}
_REAL_MERGE = L._merge


@contextmanager
def sabotaged(name):
    attr, fn = SABOTAGES[name]
    real = getattr(L, attr)
    setattr(L, attr, fn)
    try:
        yield
    finally:
        setattr(L, attr, real)


@pytest.fixture(autouse=True)
def _fresh_context():
    unbind_ledger()
    yield
    unbind_ledger()


def _wires(config):
    return {f["case_id"]: run_corpus_flow(f, config)[0].wire.value for f in FLOWS}


@pytest.fixture(scope="module")
def baseline():
    return {cfg: _wires(cfg) for cfg in ("A", "B")}


CLASS = {f["case_id"]: f["class"] for f in FLOWS}
BY_CLASS = collections.Counter(CLASS.values())


def _oracle_disagreements(wires, config, sabotage):
    return [f"{cid} [{CLASS[cid]}]: core {w}, oracle {ORACLE[(cid, config, sabotage)]}"
            for cid, w in wires.items()
            if CLASS[cid] not in ORACLE_BLIND and w != ORACLE[(cid, config, sabotage)]]


@pytest.mark.parametrize("config", ["A", "B"])
def test_core_agrees_with_the_oracle_unsabotaged(baseline, config):
    bad = _oracle_disagreements(baseline[config], config, None)
    assert not bad, (f"config {config}: the real core and reference_ledger.py disagree "
                     f"on {len(bad)} case(s):\n  " + "\n  ".join(bad[:20]))


@pytest.mark.parametrize("sab", sorted(SABOTAGE_RED))
def test_each_probe_class_goes_red_under_its_sabotage_in_the_real_core(baseline, sab):
    with sabotaged(sab):
        got = _wires("A")
    must = SABOTAGE_RED[sab]
    still = [c for c in got if CLASS[c] in must and got[c] == baseline["A"][c]]
    collateral = [c for c in got if CLASS[c] not in must and got[c] != baseline["A"][c]]
    orig = [c for c in collateral if CLASS[c] in ORIGINAL_CLASSES]
    disagree = _oracle_disagreements(got, "A", sab)
    n_red = sum(BY_CLASS[k] for k in must)
    print(f"\n{sab:18s} real core: red {n_red - len(still)}/{n_red} = {', '.join(sorted(must))}")
    assert not still, (f"{sab}: {len(still)} case(s) of {sorted(must)} did NOT change in "
                       f"the REAL core, e.g. {still[:3]} — the probe does not discriminate "
                       "this core's rule")
    assert not collateral, (f"{sab}: {len(collateral)} case(s) outside {sorted(must)} "
                            f"changed ({len(orig)} original), e.g. {collateral[:3]} — the "
                            "sabotage breaks more than one rule, or the 390 were not blind to it")
    assert not disagree, (f"{sab}: the sabotaged core and the sabotaged oracle disagree:\n  "
                          + "\n  ".join(disagree[:20]))


def test_c3a_propagation_is_what_labels_config_b_d1(baseline):
    """C-3a in the real core: remove the propagation and config B's 30
    attacker_keyed_lookup report plain trusted_source — D1, unlabelled."""
    with sabotaged("c3a_propagation"):
        got = _wires("B")
    d1 = {c: w for c, w in got.items() if CLASS[c] == "attacker_keyed_lookup"}
    assert set(baseline["B"][c] for c in d1) == {"principal_undeclared_span"}
    assert set(d1.values()) == {"trusted_source"}, d1
    changed = {CLASS[c] for c in got if got[c] != baseline["B"][c]}
    # Every designated-read authorization in B loses its label too — that is the
    # same missing propagation, seen on the benign reads.
    assert changed == {"attacker_keyed_lookup", "contact_resolution", "id_resolution",
                       "alias_expansion", "a2a_authorized", "designated_read_recipient",
                       "designated_read_url", "principal_keyed_lookup",
                       "tiebreak_no_lowering"}, changed


@pytest.mark.parametrize("sab", sorted(SABOTAGE_RED))
def test_the_oracle_itself_discriminates_on_the_committed_answers(sab):
    """The committed oracle.jsonl still carries gate step 9's property — so a
    stale or truncated oracle file cannot make (c) above pass vacuously."""
    moved = {CLASS[c] for (c, cfg, s), w in ORACLE.items()
             if cfg == "A" and s == sab and w != ORACLE[(c, "A", None)]}
    assert moved == SABOTAGE_RED[sab]
