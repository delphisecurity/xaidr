"""Acceptance 4: each of the 34 verifier findings (docs/value-origin-architecture.md
Appendix A) has a test here, or a "not testable in A1, because" line.

The table is checked, not trusted: every named test must exist (a function in
this suite, or a supplementary case id), so a renamed or deleted test turns this
red instead of leaving a finding silently uncovered.
"""
from __future__ import annotations

import importlib

import pytest

from .harness import load_jsonl

T = "test"
N = "not testable in A1, because"

APPENDIX_A = {
    1: (T, ["S26b", "S23 is L2 (A2)"], "the core half: a missing source/key argument is untrusted; "
        "binding arguments to parameter names happens in the seams, which are A2"),
    2: (T, ["S11", "S11-unscanned", "S11-clean"], "result_blocked True/None can never be trusted"),
    3: (T, ["test_interface.test_verdict_of_is_total", "S14",
            "test_procedural.test_s10_a_drop_makes_a_miss_ledger_saturated_and_hits_still_answer"], ""),
    4: (T, ["S20", "R32-one-bad-part", "R32-display-name",
            "test_authority.test_authority_of_accepts"],
        "the core's own grammar; L1 runs on 3.12 and 3.14 locally and 3.10-3.12 in CI"),
    5: (T, ["test_built_wheel.test_the_built_wheel_answers_from_its_own_psl",
            "test_self_contained.test_no_package_data_outside_python_modules"], ""),
    6: (T, ["test_interface.test_positional_construction_is_refused",
            "test_interface.test_value_type_is_frozen_slotted_kw_only"], ""),
    7: (T, ["S5", "R31-bind-ledger-noop-on-implicit", "R31-fresh-replaces"],
        "the core half (ledger_absent iff flow visible and nothing bound; the binding "
        "primitives). Which host paths call them — record_hop, extract_context's first "
        "statement, paid's build_provenance — is A2"),
    8: (T, ["S26a-apostrophe", "S26a-wildcard", "S26a-five-tokens", "S26a-ok", "S26b",
            "S26c-int", "S26c-bool", "S26c-float", "S26d", "S26e", "S26f"], ""),
    9: (T, ["S2c", "R35-flagged-ngrams", "R35-unscanned-input"], ""),
    10: (T, ["S27", "S27-single-label"], ""),
    11: (T, ["S16", "S16-64-exact", "S16-overlength", "S16-dict-key", "S16-int-padding",
             "S16-depth", "S16-depth-6-ok", "S16-untrusted-inside-bound"], ""),
    12: (T, ["S9-L1", "test_procedural.test_s9_bare_thread_without_context_is_no_flow"],
         "the L1 line; the real ThreadPoolExecutor / propagate_context half is L2 (A2)"),
    13: (T, ["test_race.test_s22_no_reader_sees_a_first_emission_overwritten",
             "test_race.test_s22_a_multi_entry_write_is_seen_all_or_none"],
         "public interface only; no ledger accessor"),
    14: (N, [], "P1 is paid's vendoring gate (tests/test_value_origin_pin.py in paid). Open's "
         "part — no generated files inside the vendored dirs — is test_self_contained"),
    15: (T, ["test_procedural.test_v15_result_shapes",
             "test_procedural.test_v15_result_leaf_cap_is_64k_not_the_argument_cap"],
         "the core normalises the RAW result; passing the raw result is the seams' (A2)"),
    16: (T, ["test_procedural.test_s10_exactly_at_cap_without_a_drop_is_not_saturated",
             "test_procedural.test_s10_a_drop_makes_a_miss_ledger_saturated_and_hits_still_answer",
             "test_procedural.test_v16d_destinations_are_a_separate_unit_from_ngrams"], ""),
    17: (T, ["S28a-userinfo", "S28a-backslash-userinfo", "S28b-segment", "S28b-dot-segment",
             "S28c-port", "S28c-default-port", "S28-ok", "S28d-relative", "S28d-abs",
             "S28d-dotdot", "S28-exact-strip", "S28-exact-nonstring"], ""),
    18: (N, [], "should_block's placement in scan_tool_call (V-18) is seam wiring, A2. The "
         "core half — should_block itself — is test_interface.test_should_block_only_on_enforce_unauthorized"),
    19: (T, ["V19-int-string", "V19-dotted-3", "V19-bare-host", "V19-version-path",
             "V19-strict-ip", "V19-ipv6", "V19-implied-scheme", "V19-bare-host-reserved",
             "test_authority.test_authority_of_rejects"], ""),
    20: (T, ["S29"], ""),
    21: (T, ["S13-mapped", "S13", "S13-decimal", "S13-octal"], ""),
    22: (T, ["V22-spaced", "V22-trunk-zero", "V22-national"], ""),
    23: (T, ["V23-backslash", "V23-trailing-punct", "V23-idna-failure-arg",
             "V23-local-part-lower", "R36-homoglyph-read", "R36-unicode-principal"],
         "IDNA per ruling 3.6 (UTS-46 nontransitional, Unicode 13.0), not the stdlib codec"),
    24: (T, ["S2", "S2-two-inputs", "S2-read-first", "S26e"], ""),
    25: (N, [], "L3 is paid's differential over two L2 drivers; neither driver exists "
         "until A2 (V-25's `python -m tests.value_origin_seams_driver`)"),
    26: (T, ["C2-no-designation"], "the core half: a read no designation can match is "
         "untrusted. Which directions call record_* at all (manual tool_result, outbound "
         "a2a, output) is the seams' (A2)"),
    27: (T, ["R31-implicit-replaced", "R31-explicit-persists"],
         "ruling 3.1 at the core; S30 (two requests on one worker thread) is L2 (A2)"),
    28: (N, [], "the waterfall row is blank-canvas code (C-27). What open owes it — the "
         "row_text.json it is checked against — is test_core.test_row_text_matches_the_committed_export"),
    29: (T, ["test_core.test_row_text_matches_the_committed_export"],
         "row_text.json carries three unrecognised samples (V-29)"),
    30: (N, [], "R1 sabotages paid's protect_tools wiring; there is no paid wiring in A1"),
    31: (N, [], "the rule id intent.value_origin_untrusted is added by the seam's block path "
         "(V-31), A2"),
    32: (T, ["test_procedural.test_after_fork_the_inherited_ledger_is_not_bound"], ""),
    33: (T, ["test_interface.test_strength_tables"], "the §1.1 half; the §4.3 half is paid's pin "
         "file placement, not testable in open"),
    34: (T, ["test_interface.test_all_is_exactly_the_interface"],
         "the core's surface; Sensor(value_origin=, value_origin_sources=) and "
         "ScanResult.value_origin are A2; the vendoring script is paid's"),
}

SUPPLEMENTARY_IDS = {c["id"] for c in load_jsonl("supplementary.jsonl")}


def test_all_34_findings_are_accounted_for():
    assert sorted(APPENDIX_A) == list(range(1, 35))
    for n, (kind, tests, why) in APPENDIX_A.items():
        assert kind in (T, N), n
        if kind == N:
            assert why, f"finding {n}: a 'not testable' line must say why"
        else:
            assert tests, f"finding {n}: names no test"


@pytest.mark.parametrize("n", sorted(APPENDIX_A))
def test_every_named_test_exists(n):
    kind, tests, _ = APPENDIX_A[n]
    for name in tests:
        if " (A2)" in name:
            continue                      # a pointer to A2, not a test here
        if "." in name and name.startswith("test_"):
            mod, fn = name.split(".", 1)
            m = importlib.import_module(f"{__package__}.{mod}")
            assert callable(getattr(m, fn, None)), f"finding {n}: {name} does not exist"
        else:
            assert name in SUPPLEMENTARY_IDS, f"finding {n}: supplementary case {name} does not exist"
