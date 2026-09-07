"""The four HIGH bypasses from the September 2026 independent audit.

WHAT THESE TESTS DO DIFFERENTLY, because the suite that missed all four had
thousands of passes. Every case here asserts THE UNDERLYING FUNCTION DID NOT
RUN, not that a scanner returned "blocked". A canary list is the oracle. The
audit's own framing: "use side-effect canaries and actual framework return
types as the oracle" -- a scanner verdict is a claim about a string, and the
thing that matters is whether the tool executed.

The SQL cases go further and use a REAL SQLite database as a semantic oracle:
each statement is executed against a disposable three-row in-memory table,
independently of the verdict, so "this deletes every row" is a measured fact
rather than a reading of a regex. That is how the false positives were found as
well as the bypasses: DELETE FROM records WHERE note='1=1' was blocked as a
tautological mutation and removes zero rows.

  F2  positional calling bypassed a loaded structural policy
  F3  the first SQL/URL argument won, hiding later dangerous values
  F4  SQL was lexically unsound in both directions
  F6  lost provenance made a delegated action look local
"""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from xaidr import (
    Sensor,
    begin_flow,
    clear_flow,
    extract_context,
    inject_context,
    propagate_context,
)


class _Null:
    def report(self, *a, **k): pass
    def emit(self, *a, **k): pass
    def flush(self, *a, **k): pass
    def close(self, *a, **k): pass


def _sensor(policy=None, **kw):
    s = Sensor(agent_id="audit", enforcement_mode="block", reporter=_Null(), **kw)
    if policy is not None:
        assert s.set_policy(policy) is True, "policy was rejected at load"
    return s


def _policy(match, effect, conditions=None):
    rule = {"id": "gate", "effect": effect, "match": match}
    if conditions:
        rule["conditions"] = conditions
    return {"version": "1", "defaults": {"effect": "allow", "unclassified": "allow"},
            "rules": [rule]}


@pytest.fixture(autouse=True)
def _clean_flow():
    clear_flow()
    yield
    clear_flow()


# ══════════════════════════════════════════════════════════════════════════
# F2  positional calling bypassed a loaded structural policy
# ══════════════════════════════════════════════════════════════════════════

TERRAFORM = "terraform destroy -auto-approve"


def test_f2_positional_and_keyword_calls_are_equivalent():
    """HARD GATE, with a canary. Measured on 1.10.0: keyword 0 executions,
    positional 1."""
    executed = []

    def run_command(command):
        executed.append(command)
        return "executed"

    s = _sensor(_policy({"impact_class": ["infra_destruction"]}, "require_approval"))
    protected, = s.protect_tools([run_command])

    kw = protected(command=TERRAFORM)
    assert executed == [], f"the keyword call EXECUTED: {executed}"
    positional = protected(TERRAFORM)
    assert executed == [], f"the POSITIONAL call executed: {executed}"
    assert "[APPROVAL REQUIRED]" in str(kw)
    assert "[APPROVAL REQUIRED]" in str(positional)


def test_f2_a_dangerous_default_is_scanned():
    """`apply_defaults` is not decoration: an argument the caller omits still
    reaches the tool, so it still has to be scanned."""
    executed = []

    def run_command(command=TERRAFORM):
        executed.append(command)
        return "executed"

    s = _sensor(_policy({"impact_class": ["infra_destruction"]}, "require_approval"))
    protected, = s.protect_tools([run_command])
    out = protected()
    assert executed == [], f"the defaulted dangerous argument EXECUTED: {executed}"
    assert "[APPROVAL REQUIRED]" in str(out)


def test_f2_keyword_only_semantics_survive():
    executed = []

    def run_command(*, command):
        executed.append(command)
        return "executed"

    s = _sensor(_policy({"impact_class": ["infra_destruction"]}, "require_approval"))
    protected, = s.protect_tools([run_command])
    protected(command=TERRAFORM)
    assert executed == []


def test_f2_benign_positional_calls_still_run():
    """The false-positive guard: binding must not stop ordinary work."""
    executed = []

    def run_command(command):
        executed.append(command)
        return "ok"

    s = _sensor(_policy({"impact_class": ["infra_destruction"]}, "require_approval"))
    protected, = s.protect_tools([run_command])
    assert protected("ls -la") == "ok"
    assert executed == ["ls -la"]


def test_f2_unbindable_callables_are_reported_not_silently_degraded():
    """Explicit coverage degradation. A callable whose signature cannot be read
    falls back to positional labels, and that fact is retrievable."""
    import time as _time

    # `time.time` is a C builtin whose signature genuinely cannot be read
    # (`inspect.signature` raises ValueError). `len` and `print` CAN be read on
    # CPython 3.12, so they would not exercise this path -- the first draft of
    # this test used `len` and passed for the wrong reason.
    s = _sensor()
    protected, = s.protect_tools([_time.time])
    protected()
    assert "time" in s.binding_degraded(), (
        "an unbindable callable was degraded silently; binding_degraded() must "
        "name it so the loss of structural coverage is visible"
    )


# ══════════════════════════════════════════════════════════════════════════
# F3  the first SQL/URL argument won
# ══════════════════════════════════════════════════════════════════════════

SQL_TAUTOLOGY = "DELETE FROM records WHERE 1=1"
METADATA_URL = "https://2852039166/latest/meta-data/iam/security-credentials/"


@pytest.mark.parametrize("args", [
    {"first": "SELECT 1", "query": SQL_TAUTOLOGY},
    {"query": SQL_TAUTOLOGY, "first": "SELECT 1"},
])
def test_f3_sql_enforcement_does_not_depend_on_key_order(args):
    s = _sensor()
    assert s.scan_tool_call("run_sql", args).action == "blocked", (
        f"key order {list(args)} changed the verdict"
    )


@pytest.mark.parametrize("args", [
    {"first": "https://example.com/docs", "url": METADATA_URL},
    {"url": METADATA_URL, "first": "https://example.com/docs"},
])
def test_f3_url_enforcement_does_not_depend_on_key_order(args):
    s = _sensor()
    assert s.scan_tool_call("http_get", args).action == "blocked", (
        f"key order {list(args)} changed the verdict"
    )


def test_f3_nested_arguments_are_reached():
    """`{"body": {"query": ...}}` is an ordinary argument shape."""
    s = _sensor()
    assert s.scan_tool_call(
        "run_sql", {"body": {"query": SQL_TAUTOLOGY}}).action == "blocked"


def test_f3_a_canary_tool_with_a_benign_first_argument_does_not_run():
    executed = []

    def run_sql(first, query):
        executed.append(query)
        return "rows"

    s = _sensor()
    protected, = s.protect_tools([run_sql])
    protected(first="SELECT 1", query=SQL_TAUTOLOGY)
    assert executed == [], f"the dangerous second argument EXECUTED: {executed}"


def test_f3_all_benign_values_still_allow():
    """The cost side: scanning every value must not start blocking ordinary
    multi-argument calls."""
    s = _sensor()
    assert s.scan_tool_call("run_sql", {
        "first": "SELECT 1", "query": "SELECT name FROM users WHERE id = 7",
        "note": "quarterly report", "url": "https://example.com/docs",
    }).action == "allowed"


# ══════════════════════════════════════════════════════════════════════════
# F4  SQL, against a real SQLite oracle
# ══════════════════════════════════════════════════════════════════════════


def _rows_after(statement: str) -> int:
    """Execute against a disposable three-row in-memory table. Rows remaining.

    The semantic ground truth. Not a user database, never networked, discarded
    at return.
    """
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, note TEXT)")
    db.executemany("INSERT INTO records VALUES (?,?)", [(1, "a"), (7, "b"), (9, "c")])
    db.commit()
    db.executescript(statement)
    db.commit()
    return db.execute("SELECT COUNT(*) FROM records").fetchone()[0]


#: Each deletes EVERY row, and each returned allowed at score 0.00 on 1.10.0.
UNRESTRICTED_DELETES = [
    "DELETE FROM records RETURNING 'where id=7'",
    "WITH x AS (SELECT 1) DELETE FROM records",
    "SELECT '--'; DELETE FROM records WHERE 1=1",
    "DELETE FROM records",
]

#: Each deletes at most one row, and each was gated on 1.10.0.
BOUNDED_DELETES = [
    "DELETE FROM records WHERE note='1=1'",
    "DELETE FROM records WHERE id=7 AND 1=1",
    "DELETE FROM records WHERE id=7",
]


@pytest.mark.parametrize("statement", UNRESTRICTED_DELETES)
def test_f4_unrestricted_deletes_are_gated_and_really_delete_everything(statement):
    remaining = _rows_after(statement)
    assert remaining == 0, (
        f"the oracle says this leaves {remaining} rows, so it is not the "
        f"unrestricted case this test claims: {statement!r}"
    )
    s = _sensor(_policy({"impact_tier": ["critical"]}, "require_approval"))
    action = s.scan_tool_call("run_sql", {"query": statement}).action
    assert action in ("blocked", "approval_required"), (
        f"{statement!r} deletes every row and returned {action}"
    )


@pytest.mark.parametrize("statement", BOUNDED_DELETES)
def test_f4_bounded_deletes_are_not_gated_and_really_are_bounded(statement):
    remaining = _rows_after(statement)
    assert remaining >= 2, (
        f"the oracle says this leaves {remaining} rows, so it is not the "
        f"bounded case this test claims: {statement!r}"
    )
    s = _sensor(_policy({"impact_tier": ["critical"]}, "require_approval"))
    action = s.scan_tool_call("run_sql", {"query": statement}).action
    assert action == "allowed", (
        f"{statement!r} deletes at most one row and returned {action}"
    )


def test_f4_a_string_literal_cannot_change_the_structural_reading():
    from xaidr.scanner.sql_parse import parse_sql

    assert [s.predicate for s in parse_sql(
        "DELETE FROM records RETURNING 'where id=7'")] == ["none"]
    assert [s.predicate for s in parse_sql(
        "DELETE FROM records WHERE note='1=1'")] == ["bounded"]


def test_f4_every_statement_is_inspected_not_only_the_first():
    from xaidr.scanner.sql_parse import parse_sql

    shapes = parse_sql("SELECT '--'; DELETE FROM records WHERE 1=1")
    assert [(s.statement, s.predicate) for s in shapes] == [
        ("select", "none"), ("delete", "tautology")]


def test_f4_a_tautology_in_one_conjunct_does_not_unbind_the_predicate():
    """The auditor's criterion, as boolean structure rather than a longer regex."""
    from xaidr.scanner.sql_parse import parse_sql

    assert parse_sql(
        "DELETE FROM records WHERE id=7 AND 1=1")[0].predicate == "bounded"
    assert parse_sql(
        "DELETE FROM records WHERE 1=1 OR id=7")[0].predicate == "tautology"


def test_f4_the_lexer_gets_boundaries_right():
    from xaidr.scanner.sql_parse import tokenize

    kinds = [t.kind for t in tokenize("SELECT '--' /* x */ -- y\nFROM t")]
    assert "str" in kinds and kinds.count("comment") == 2


def test_f4_an_unsettleable_predicate_fails_closed():
    """"unknown" rather than "bounded": the recogniser may say it does not know,
    it may not say bounded when it means that."""
    from xaidr.scanner.sql_parse import parse_sql

    assert parse_sql("DELETE FROM records WHERE")[0].predicate == "unknown"


# ══════════════════════════════════════════════════════════════════════════
# F6  lost provenance made a delegated action look local
# ══════════════════════════════════════════════════════════════════════════

TIER_POLICY = _policy({"tools": ["deploy_prod"]}, "require_approval",
                      conditions={"min_chain_tier_above": 2})


def _delegation_headers():
    clear_flow()
    sender = Sensor(agent_id="sender", enforcement_mode="block", reporter=_Null(),
                    privilege_tier=4)
    begin_flow(principal="alice")
    sender.scan("please deploy", direction="input")
    headers = inject_context()
    clear_flow()
    return headers


def _receiver_verdict(headers):
    clear_flow()
    recv = Sensor(agent_id="recv", enforcement_mode="block", reporter=_Null(),
                  privilege_tier=1)
    assert recv.set_policy(TIER_POLICY) is True
    extract_context(headers)
    action = recv.scan_tool_call("deploy_prod", {"env": "production"}).action
    clear_flow()
    return action


def test_f6_valid_headers_gate_the_action():
    """The positive control. Without it the tests below prove nothing."""
    assert _receiver_verdict(dict(_delegation_headers())) == "approval_required"


@pytest.mark.parametrize("strip", ["tiers", "correlation", "everything"])
def test_f6_stripping_provenance_never_weakens_the_verdict(strip):
    """THREAT_MODEL's guarantee, as a test: removing evidence must tighten.

    Stripping everything, or just the correlation id, used to return allowed --
    an attacker who deleted the headers ended up better off than one who left
    them alone.
    """
    headers = _delegation_headers()
    if strip == "tiers":
        headers = {k: v for k, v in headers.items() if "tiers" not in k.lower()}
    elif strip == "correlation":
        headers = {k: v for k, v in headers.items()
                   if "correlation" not in k.lower() and k.lower() != "traceparent"}
    else:
        headers = {}
    assert _receiver_verdict(headers) == "approval_required", (
        f"stripping {strip!r} made the delegated action look local"
    )


def test_f6_a_non_delegated_call_is_still_local():
    """The other half, and the reason this cannot just always gate: an agent
    doing its OWN work must not be gated by an absent upstream that never
    existed."""
    clear_flow()
    recv = Sensor(agent_id="recv", enforcement_mode="block", reporter=_Null(),
                  privilege_tier=1)
    assert recv.set_policy(TIER_POLICY) is True
    assert recv.scan_tool_call(
        "deploy_prod", {"env": "production"}).action == "allowed"
    clear_flow()


def test_f6_context_survives_a_thread_only_when_propagated():
    """Both halves stated, because the honest answer is a helper, not a claim.

    `contextvars` do not cross a raw thread; that is Python, not this package.
    So the plain form is asserted to lose the context (which is why the README
    no longer says threads propagate automatically) and the helper is asserted
    to keep it.
    """
    headers = _delegation_headers()
    clear_flow()
    recv = Sensor(agent_id="recv", enforcement_mode="block", reporter=_Null(),
                  privilege_tier=1)
    recv.set_policy(TIER_POLICY)
    extract_context(dict(headers))

    def call():
        return recv.scan_tool_call("deploy_prod", {"env": "production"}).action

    assert call() == "approval_required"
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(call).result() == "allowed", (
            "a raw thread preserved the context; if contextvars changed, the "
            "README's threading guidance needs re-reading"
        )
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(propagate_context(call)).result() == "approval_required", (
            "propagate_context did not carry the delegation context"
        )
    clear_flow()


# ══════════════════════════════════════════════════════════════════════════
# STEP 4  the denominator claim the audit found false
# ══════════════════════════════════════════════════════════════════════════

#: Measured, not asserted from memory: these four are marked `INTENDED` — a
#: deliberate decision not to fire — while `classify()` returns `unknown`, so
#: they carry no impact class and no policy can match them. "Recognised and
#: handed to your policy" was true of 91 of the 95, not all 95.
NEITHER_DETECTED_NOR_CLASSIFIED = {
    "aws sts get-caller-identity",
    "netstat -antp",
    "ss -tulpn",
    "docker ps -a",
}


def _corpus():
    import json
    import os

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "tests/fixtures/shell_corpus.json"),
              encoding="utf-8") as fh:
        return json.load(fh)


def test_step4_exactly_four_exclusions_classify_unknown():
    """The count is derived, never written down twice.

    If a rule later classifies one of these, this fails and the README's
    "91 of the 95" sentence has to move with it.
    """
    from xaidr.authz.classifier import classify

    exclusions = [e for e in _corpus()["attacks"]
                  if e.get("detection_intent") == "INTENDED"]
    assert len(exclusions) == 95, len(exclusions)
    unknown = {e["command"] for e in exclusions
               if classify("run_command", {"command": e["command"]})[0] == "unknown"}
    assert unknown == NEITHER_DETECTED_NOR_CLASSIFIED, (
        f"the set of unclassifiable exclusions moved: {sorted(unknown)}"
    )


def test_step4_the_readme_no_longer_claims_all_95_are_recognised():
    import os
    import re

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "README.md"), encoding="utf-8") as fh:
        readme = " ".join(fh.read().split())
    for false_claim in (
        "95 corpus attacks are recognised and deliberately left",
        "95 are recognised and deliberately left",
        "ones that are recognised and deliberately not caught",
    ):
        assert false_claim not in readme, (
            f"the README claims again that all 95 are recognised: {false_claim!r}"
        )
    assert "91 of the 95, not all 95, are recognised" in readme


def test_step4_the_four_would_hold_the_benign_gate():
    """The evidence for the reclassification recommendation.

    They score zero on both paths, so moving them into the benign pool would not
    break the gate that pool exists to enforce. Recorded as a measurement; the
    move itself is a corpus-curation decision and is NOT made here.
    """
    s = _sensor()
    for command in sorted(NEITHER_DETECTED_NOR_CLASSIFIED):
        tool = s.scan_tool_call("run_command", {"command": command})
        content = s.scan(command, direction="input")
        assert tool.score == 0.0 and content.score == 0.0, (
            f"{command!r} scores {tool.score}/{content.score}; it could not move "
            f"into the 74-command benign pool without failing that gate"
        )
