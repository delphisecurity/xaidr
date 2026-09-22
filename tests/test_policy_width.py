"""The README's policy-width table must equal what the sensor actually does.

    | policy                       | attacks gated | ordinary DevOps gated |
    | none (shipped default)       | 165 of 277    | 0 of 38               |
    | impact_tier: [critical]      | 188 of 277    | 0 of 38               |
    | impact_tier: [critical, high]| 253 of 277    | 4 of 38               |
    | impact_class: all ten        | 265 of 277    | 5 of 38               |

Eight published figures, plus "benign commands stay at 0 of 78 under every
policy width above". Until `scripts/policy_width_report.py` they had no
regenerator at all: they arrived in `ab09cb3`, a commit that touched four
markdown files and nothing else, and the word "Measured" in its body was the
entire provenance. Nothing in `tests/` or `scripts/` could recompute any of
them, and the attack denominator later drifted 281 -> 277 with nothing
re-deriving the DevOps column beside it.

THE DIRECTION THIS TEST RUNS IN MATTERS. It does not hardcode the numbers; it
PARSES THEM OUT OF THE README and compares them to a live measurement. So it
fails in both directions, and the second is the one that gets skipped:

  * a rule change that moves a figure and leaves the README alone -> red
  * a README edit that changes a figure without re-measuring        -> red

A test holding its own copy of the expected numbers would catch only the first,
and would let the prose and the code drift apart exactly the way they already
did once.

Four policy widths over 277 attacks + 78 benign + 38 DevOps commands is ~1,570
tool-call scans and takes under a second; the sweep is a module-scoped fixture
so it happens once for the three tests that need it.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"

sys.path.insert(0, str(REPO / "scripts"))


@pytest.fixture(scope="module")
def measured():
    """One sweep, shared by every assertion below — it is not a cheap one."""
    import policy_width_report
    return policy_width_report.measure()


# `| impact_tier: [critical] | 188 of 277 | 0 of 38 |`, and the "none" row whose
# attacks cell carries a trailing clause.
_ROW = re.compile(
    r"^\|\s*(?P<policy>[^|]+?)\s*\|\s*(?:\*\*)?(?P<a>\d+) of (?P<an>\d+)"
    r"(?P<tail>[^|]*?)\s*\|\s*(?:\*\*)?(?P<d>\d+) of (?P<dn>\d+)(?:\*\*)?\s*\|\s*$",
    re.M,
)


def _readme_rows():
    """The policy-width table, read out of README.md.

    Keyed on the row shape (`N of M | N of M`) rather than on a heading or a
    line number, so moving the section does not silently empty this.
    """
    text = README.read_text(encoding="utf-8")
    rows = {}
    for m in _ROW.finditer(text):
        policy = m.group("policy").strip().strip("`").replace("**", "")
        rows[policy] = {
            "attacks_gated": int(m.group("a")), "attacks_n": int(m.group("an")),
            "devops_gated": int(m.group("d")), "devops_n": int(m.group("dn")),
        }
    return rows


def _key(label):
    """Normalise a policy label so the README's and the script's rows meet."""
    return re.sub(r"[`*\s]+", "", label).lower()


def test_the_readme_still_contains_a_policy_width_table():
    """A parse that finds nothing must fail, not pass over an empty set."""
    rows = _readme_rows()
    assert len(rows) >= 4, (
        f"parsed {len(rows)} policy-width row(s) out of README.md; expected the "
        f"four-row table. Either the table moved/changed shape or this regex "
        f"stopped matching it — and a comparison against zero rows passes "
        f"vacuously, which is worse than the drift it exists to catch. "
        f"Found: {sorted(rows)}"
    )


def test_every_published_policy_width_figure_is_what_the_sensor_does(measured):
    published = {_key(k): v for k, v in _readme_rows().items()}
    wrong = []
    for row in measured["rows"]:
        want = published.get(_key(row["policy"]))
        if want is None:
            wrong.append(
                f"{row['policy']}: measured {row['attacks_gated']} of "
                f"{row['attacks_n']} attacks / {row['devops_gated']} of "
                f"{row['devops_n']} DevOps, and the README publishes NO row for "
                f"this policy width"
            )
            continue
        for field, unit in (("attacks_gated", "attacks gated"),
                            ("attacks_n", "attack denominator"),
                            ("devops_gated", "DevOps gated"),
                            ("devops_n", "DevOps denominator")):
            if want[field] != row[field]:
                wrong.append(
                    f"{row['policy']}: {unit} — README says {want[field]}, "
                    f"scripts/policy_width_report.py measures {row[field]}"
                )
    assert not wrong, (
        "the README's policy-width table does not describe this sensor:\n  "
        + "\n  ".join(wrong) + "\n"
        "Regenerate with `python scripts/policy_width_report.py` and either "
        "update the prose or explain the change. These eight figures are what "
        "a deployer reads to decide whether to write the policy at all."
    )


def test_benign_commands_stay_at_zero_under_every_policy_width(measured):
    """The README's "0 of 78 under every policy width above", measured.

    This is the claim a deployer bets on when widening a policy: the gate costs
    approvals on real DevOps work (4, then 5 of 38, all named in the report) and
    costs NOTHING on ordinary benign commands. It is a separate assertion from
    the table because it is a separate promise, and because a false positive on
    this pool is the failure that gets a security tool switched off.
    """
    noisy = [(r["policy"], r["benign_hits"]) for r in measured["rows"]
             if r["benign_gated"]]
    assert not noisy, (
        "benign shell commands gated by a policy width the README says costs "
        f"0 of {measured['rows'][0]['benign_n']}:\n  "
        + "\n  ".join(f"{p}: {cmds}" for p, cmds in noisy)
    )


def test_the_widest_policy_names_three_classes_the_classifier_cannot_emit(
        measured):
    """A documented inertness, pinned so it cannot become undocumented.

    "impact_class: all ten" binds the ten classes the CORPUS labels families
    with. `classify()` returns a different set, and three of the ten —
    exfiltration, obfuscation, discovery — are not in it, so those clauses match
    nothing. README.md says this ("the sensor's classifier emits eight classes
    against the corpus's ten, so three corpus families cannot be emitted at
    all") and it is open work.

    Asserted rather than left implicit for a specific reason: if the mapping is
    improved, the 265-of-277 figure moves, and the thing that would otherwise
    notice is a reader comparing two numbers in prose. This goes red instead,
    at the place the count lives.
    """
    assert measured["inert"] == ["exfiltration", "obfuscation", "discovery"], (
        f"the set of corpus classes `classify()` cannot emit has changed: "
        f"{measured['inert']}. If the classifier mapping improved, the widest "
        f"policy now binds clauses that were inert, the 'X of 277' figure moves "
        f"with it, and README.md's 'eight classes against the corpus's ten' "
        f"sentence is stale."
    )
