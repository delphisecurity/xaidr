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


class _UnreadableSignature:
    """A callable whose signature genuinely cannot be read, on every version.

    DO NOT replace this with a C builtin. Two drafts of this test tried that and
    both were wrong for the same reason: which builtins expose
    `__text_signature__` is a CPython implementation detail that moves between
    releases. `len` is readable on 3.12, so the first draft passed vacuously.
    `time.time` raises ValueError on 3.12 and returns `()` on 3.14, so the second
    draft passed on the development interpreter and FAILED on the newer end of
    the CI matrix, which is how it was caught. The behaviour under test is what
    the wrapper does when a signature cannot be read, so the fixture should
    guarantee that condition rather than borrow it from the interpreter.
    """

    __name__ = "unreadable_tool"

    @property
    def __signature__(self):
        raise ValueError("signature unavailable")

    def __call__(self, *args, **kwargs):
        return "executed"


def test_f2_unbindable_callables_are_reported_not_silently_degraded():
    """Explicit coverage degradation. A callable whose signature cannot be read
    falls back to positional labels, and that fact is retrievable."""
    import inspect

    tool = _UnreadableSignature()
    with pytest.raises(ValueError):
        inspect.signature(tool)          # the premise, asserted not assumed

    s = _sensor()
    protected, = s.protect_tools([tool])
    assert protected("ls -la") == "executed", "a benign call must still run"
    assert "unreadable_tool" in s.binding_degraded(), (
        "an unbindable callable was degraded silently; binding_degraded() must "
        "name it so the loss of structural coverage is visible"
    )


def test_f2_binding_degraded_names_only_the_tools_that_failed():
    """The other half, so the test above cannot pass on a list that is always
    populated.

    Asserted as DISCRIMINATION rather than as emptiness: binding_degraded() is a
    staticmethod over a process-wide set that is deliberately never cleared, so
    a bare `== []` here would pass or fail on test ORDER rather than on
    behaviour. What has to be true is that a tool which binds cleanly never
    appears in it, whatever else has run first.
    """
    def a_tool_that_binds(command):
        return "executed"

    s = _sensor()
    protected, = s.protect_tools([a_tool_that_binds])
    protected("ls -la")
    protected(command="ls -la")
    assert "a_tool_that_binds" not in s.binding_degraded(), (
        "a tool whose signature reads fine was reported as degraded, so "
        f"binding_degraded() cannot distinguish: {s.binding_degraded()}"
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


def test_step4_every_remaining_exclusion_is_actually_classified():
    """What the audit finding became once the corpus was corrected.

    The finding was that four INTENDED entries returned `unknown` from
    classify(), so they carried no impact class, nothing existed for a policy to
    match, and calling them "recognised and handed to your policy" was false.
    1.12.0 resolved that by MOVING them rather than by rewording it: they are
    benign commands now, not attacks.

    So the invariant is no longer "exactly four are unclassifiable". It is the
    stronger one that the move was supposed to buy: EVERY exclusion that remains
    is genuinely recognised. If a future entry is excluded on the strength of a
    classification it does not have, this fails.
    """
    from xaidr.authz.classifier import classify

    exclusions = [e for e in _corpus()["attacks"]
                  if e.get("detection_intent") == "INTENDED"]
    assert len(exclusions) == 91, len(exclusions)
    unknown = sorted(e["command"] for e in exclusions
                     if classify("run_command", {"command": e["command"]})[0] == "unknown")
    assert not unknown, (
        "these entries are excluded from the denominator as 'recognised and left "
        "to policy', but classify() returns unknown for them, so there is no "
        f"impact class for a policy to match: {unknown}"
    )


def test_step4_the_four_are_now_benign_and_stay_silent():
    """The other half of the move, asserted where it now lives.

    They were reclassified into the benign pool because they score zero, so the
    thing to hold is that they keep scoring zero. That is a real assertion: it
    fails if a future discovery rule starts firing on ordinary operational
    inspection, which is the false positive the benign gate exists to catch.
    """
    corpus = _corpus()
    benign = {b["command"] for b in corpus["benign"]}
    attacks = {a["command"] for a in corpus["attacks"]}
    assert NEITHER_DETECTED_NOR_CLASSIFIED <= benign, (
        "the reclassified four are not in the benign pool: "
        f"{sorted(NEITHER_DETECTED_NOR_CLASSIFIED - benign)}"
    )
    assert not (NEITHER_DETECTED_NOR_CLASSIFIED & attacks), (
        "a reclassified command is still carried as an attack: "
        f"{sorted(NEITHER_DETECTED_NOR_CLASSIFIED & attacks)}"
    )
    s = _sensor()
    for command in sorted(NEITHER_DETECTED_NOR_CLASSIFIED):
        tool = s.scan_tool_call("run_command", {"command": command})
        content = s.scan(command, direction="input")
        assert tool.score == 0.0 and content.score == 0.0, (
            f"{command!r} now scores {tool.score}/{content.score}; it is in the "
            f"benign pool, so this breaks the false-positive gate"
        )


def test_step4_the_published_exclusion_count_matches_the_corpus():
    """The number in the documentation is the number in the fixture.

    This guard exists because the merge that brought 1.11.0's README onto this
    branch silently reintroduced "95 corpus attacks are recognised", a sentence
    that was false when it was written and false again when it came back. A
    claim about the corpus that is typed rather than derived will drift every
    time a branch crosses another, so it is pinned here in both directions: the
    stale count must be absent, and the live one must be present.
    """
    import os

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    docs = [os.path.join(root, "README.md")]
    docs_dir = os.path.join(root, "docs")
    if os.path.isdir(docs_dir):
        docs += [os.path.join(docs_dir, f) for f in sorted(os.listdir(docs_dir))
                 if f.endswith(".md")]

    live = sum(1 for e in _corpus()["attacks"]
               if e.get("detection_intent") == "INTENDED")
    assert live == 91, live

    for path in docs:
        with open(path, encoding="utf-8") as fh:
            text = " ".join(fh.read().split())
        for stale in ("95 corpus attacks are recognised",
                      "95 are recognised and deliberately left",
                      "ones that are recognised and deliberately not caught",
                      "281 attacks in the corpus"):
            assert stale not in text, (
                f"{os.path.basename(path)} carries a corpus count that the "
                f"fixture no longer supports: {stale!r}"
            )

    with open(docs[0], encoding="utf-8") as fh:
        readme = " ".join(fh.read().split())
    assert f"{live} corpus attacks are recognised" in readme, (
        f"the README does not state the live exclusion count ({live})"
    )


# ── THE MERGE CASE: async AND positional AND dangerous ───────────────────────
# This is the case that neither branch could have written, and it is the reason
# the 1.12.0 merge was resolved rather than decided.
#
#   1.11.0 fixed the ASYNC half: protect_tools had never wrapped a coroutine
#          function, so an async tool ran unscanned.
#   The audit fixed the POSITIONAL half: arguments were labelled arg0/arg1, and
#          every structural extractor keys on the parameter name, so a policy
#          matched run_command(command=...) and missed run_command(...).
#
# On 1.11.0 the async+positional call is unscanned because it is async. On the
# audit branch it is unscanned because... there is no async wrapper at all. Only
# a tree carrying both fixes can even reach the question, and the answer is only
# correct if they compose in the right ORDER: bind the arguments, then decide.
# Bind after deciding, or in only one of the two wrappers, and this file goes
# red while every other test in the suite stays green.

_DANGEROUS = "terraform destroy -auto-approve"
_BENIGN = "terraform plan"


def _infra_policy():
    return _policy({"impact_class": ["infra_destruction"]}, "require_approval")


def _sync_and_async_tools(ran):
    """One sync tool and one async tool with identical signatures and canaries."""
    def run_command(command):
        ran.append(("sync", command))
        return "executed"

    async def run_command_async(command):
        ran.append(("async", command))
        return "executed"

    return run_command, run_command_async


@pytest.mark.parametrize("positional", [True, False], ids=["positional", "keyword"])
def test_merge_sync_tool_is_gated_either_calling_convention(positional):
    ran = []
    sync_tool, _ = _sync_and_async_tools(ran)
    protected, = _sensor(_infra_policy()).protect_tools([sync_tool])

    out = protected(_DANGEROUS) if positional else protected(command=_DANGEROUS)

    assert ran == [], f"the tool EXECUTED: {ran}"
    assert "[APPROVAL REQUIRED]" in out, out
    assert isinstance(out, str)


@pytest.mark.parametrize("positional", [True, False], ids=["positional", "keyword"])
def test_merge_async_tool_is_gated_either_calling_convention(positional):
    """The composition case. Async, positional, dangerous, zero executions."""
    import asyncio
    import inspect

    ran = []
    _, async_tool = _sync_and_async_tools(ran)
    protected, = _sensor(_infra_policy()).protect_tools([async_tool])

    # inspect, not asyncio: asyncio.iscoroutinefunction is deprecated in 3.14
    # and removed in 3.16, and this suite runs the whole classifier matrix.
    assert inspect.iscoroutinefunction(protected), (
        "protect_tools returned a SYNC wrapper for a coroutine function; a "
        "refusal would then be a str where the caller awaits"
    )

    async def call():
        return await (protected(_DANGEROUS) if positional
                      else protected(command=_DANGEROUS))

    out = asyncio.run(call())

    assert ran == [], f"the async tool EXECUTED: {ran}"
    assert "[APPROVAL REQUIRED]" in out, out
    assert isinstance(out, str), (
        f"refusal type is {type(out).__name__}; the caller awaited and must get "
        "the same string the sync path returns"
    )


def test_merge_the_gate_is_not_simply_refusing_everything():
    """Non-vacuity. A benign call on both paths must still execute and return
    the tool's own value, or the two tests above would pass on a wrapper that
    blocked unconditionally."""
    import asyncio

    ran = []
    sync_tool, async_tool = _sync_and_async_tools(ran)
    sensor = _sensor(_infra_policy())
    p_sync, = sensor.protect_tools([sync_tool])
    p_async, = sensor.protect_tools([async_tool])

    assert p_sync(_BENIGN) == "executed"
    assert asyncio.run(p_async(_BENIGN)) == "executed"
    assert ran == [("sync", _BENIGN), ("async", _BENIGN)], ran


def test_merge_both_paths_produce_the_identical_refusal():
    """The two wrappers share one decision function, so the refusal a caller
    matches on cannot differ by calling convention or by sync/async-ness."""
    import asyncio

    ran = []
    sync_tool, async_tool = _sync_and_async_tools(ran)
    sensor = _sensor(_infra_policy())
    p_sync, = sensor.protect_tools([sync_tool])
    p_async, = sensor.protect_tools([async_tool])

    # The refusal names the tool, and the two tools must have distinct names for
    # protect_tools to treat them as distinct, so the tool name is normalised out
    # before comparing. Everything else -- the verdict, the category, the wording
    # and the type -- has to be identical across all four paths.
    def shape(text, tool):
        assert isinstance(text, str), f"{tool} refusal is {type(text).__name__}"
        return text.replace(tool, "<tool>")

    refusals = {
        shape(p_sync(_DANGEROUS), "run_command"),
        shape(p_sync(command=_DANGEROUS), "run_command"),
        shape(asyncio.run(p_async(_DANGEROUS)), "run_command_async"),
        shape(asyncio.run(p_async(command=_DANGEROUS)), "run_command_async"),
    }
    assert len(refusals) == 1, f"the four paths disagree: {sorted(refusals)}"
    assert ran == [], f"a tool executed: {ran}"
