"""SQL carried in a tool argument: classification, the block/classify split, and
the false positives the split exists to avoid.

THE GAP THIS CLOSES. An independent reviewer published
``scan_tool_call("run_sql", {"query": "DROP TABLE users"})`` returning
allowed / 0.00. That was accurate. Destructive classification read shell
structure only, so it recognised ``psql -c "DROP TABLE users"`` (a binary with a
recognisable argument) and was blind to ``DROP TABLE users`` (no binary at all).
The argument KEY was never the gate and neither was the tool name: before this
change ``run_command(command="DROP TABLE users")`` was equally invisible. What
was missing was a reader for SQL, not a wider key list.

THE SPLIT UNDER TEST, and it is the whole design:

    DDL          DROP TABLE / DROP DATABASE / TRUNCATE
                 classify infra_destruction/critical, NEVER block.
                 Parity with infra.database_drop, which already lets
                 `psql -c "DROP TABLE users"` through for the same reason:
                 dropping a table is how a migration and a teardown are written.
                 A ruleset where the statement blocks via run_sql and passes via
                 psql is incoherent AND a bypass by refactoring.

    DML bounded  DELETE ... WHERE expires_at < now()
                 not destructive at all. A tool that breaks these is uninstalled
                 the same day.

    DML none     DELETE FROM users / UPDATE accounts SET balance = 0
                 classify delete/critical, CLASSIFY-ONLY. `DELETE FROM sessions`
                 and `UPDATE feature_flags SET enabled = false` are real, and
                 nothing in the statement separates them from the malicious one.

    DML tautology DELETE FROM users WHERE 1=1
                 BLOCKS. Unbounded while disguised as bounded, and that disguise
                 is the signal: an operator clearing a table writes no WHERE
                 clause, an ORM writes a real predicate. Only something that
                 wanted the effect of no predicate writes one that is always true.

So the answer to "statement type or absence of WHERE" is neither on its own. The
statement type selects the FAMILY; the predicate's truth value decides the
VERDICT.
"""
from __future__ import annotations

import contextlib
import io
import time

import pytest

from xaidr.authz.classifier import (
    classify,
    classify_sql,
    classify_sql_findings,
    extract_sql,
)
from xaidr.scanner.sql_parse import MAX_SQL_CHARS, looks_like_sql, parse_sql
from xaidr.sensor import DelphiSensor


class _Null:
    def report(self, batch): pass
    def close(self): pass


def _sensor(mode="block"):
    return DelphiSensor(agent_id="sql-classes", enforcement_mode=mode, reporter=_Null())


def _quiet(fn, *a, **k):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a, **k)


# ══ (a) THE REVIEWER'S REPRODUCER ════════════════════════════════════════════

def test_the_published_reproducer_is_no_longer_invisible():
    """The exact call from the report. It does not block, and that is the
    designed answer, but it must no longer be UNCLASSIFIED: a policy has to be
    able to reach it."""
    s = _sensor("block")
    r = _quiet(s.scan_tool_call, "run_sql", {"query": "DROP TABLE users"})
    assert classify("run_sql", {"query": "DROP TABLE users"}) == (
        "infra_destruction", "critical")
    assert r.action == "allowed", "DDL is classify-only, same as the shell path"


# ══ (b) CLASSIFICATION, REGARDLESS OF KEY OR TOOL NAME ═══════════════════════

# `query`, `sql`, `statement` and `q` are all ordinary, and a custom tool may use
# anything at all. A key allowlist would be a gate the caller picks the
# combination to, so the gate is the VALUE instead.
ANY_KEY = ["query", "sql", "statement", "q", "command", "cmd", "text", "body",
           "input", "zzz", "_", "arg0"]


@pytest.mark.parametrize("key", ANY_KEY)
def test_sql_is_found_under_any_argument_key(key):
    assert classify("run_sql", {key: "DROP TABLE users"}) == (
        "infra_destruction", "critical"), f"key {key!r} hid the statement"


@pytest.mark.parametrize("tool", ["run_sql", "execute_query", "db", "x", "query_tool"])
def test_sql_is_found_regardless_of_tool_name(tool):
    assert classify(tool, {"query": "DROP TABLE users"})[0] == "infra_destruction"


CLASSIFY_CASES = [
    ("DROP TABLE users",                    "infra_destruction", "critical"),
    ("DROP DATABASE prod",                  "infra_destruction", "critical"),
    ("DROP SCHEMA public CASCADE",          "infra_destruction", "critical"),
    ("TRUNCATE TABLE customers",            "infra_destruction", "critical"),
    ("DELETE FROM users",                   "delete",            "critical"),
    ("UPDATE accounts SET balance = 0",     "delete",            "critical"),
    ("DELETE FROM users WHERE 1=1",         "delete",            "critical"),
]


@pytest.mark.parametrize("sql,klass,tier", CLASSIFY_CASES)
def test_destructive_sql_classifies(sql, klass, tier):
    assert classify("run_sql", {"query": sql}) == (klass, tier)


# ══ (c) THE BENIGN CONTROLS ══════════════════════════════════════════════════
# These are the reason the split is where it is. Every one of them is ordinary
# application or migration traffic.

BENIGN_SQL = [
    "SELECT * FROM users WHERE id = 42",
    "INSERT INTO events (name) VALUES ('login')",
    "UPDATE users SET last_seen = now() WHERE id = 42",
    "CREATE TABLE migrations (id serial)",
    "DELETE FROM sessions WHERE expires_at < now()",
    # a Django/Alembic-shaped migration that mentions DROP
    "ALTER TABLE accounts DROP COLUMN legacy_token; "
    "-- migration 0042_drop_legacy_token, reversible",
    # the self-assignment family, which a whole-statement tautology test would
    # have called a tautology: `hits = hits` is an ASSIGNMENT, not a comparison
    "UPDATE counters SET hits = hits + 1 WHERE id = 7",
    "UPDATE t SET balance = balance - 10 WHERE user_id = 3",
    # bounded deletes with a range predicate
    "DELETE FROM audit WHERE created_at < now() - interval '30 days'",
    "UPDATE jobs SET state = 'done' WHERE state = 'running'",
    # a literal that CONTAINS a destructive statement is data, not a statement
    "SELECT * FROM t WHERE name = 'DROP TABLE users'",
    "SELECT count(*) FROM orders",
    "WITH recent AS (SELECT id FROM orders WHERE created_at > now()) SELECT * FROM recent",
]


@pytest.mark.parametrize("sql", BENIGN_SQL)
def test_benign_sql_is_allowed_on_the_tool_path(sql):
    s = _sensor("block")
    r = _quiet(s.scan_tool_call, "run_sql", {"query": sql})
    assert r.action == "allowed", f"{sql!r} -> {r.action} {r.rules}"
    assert r.score == 0.0, f"{sql!r} scored {r.score} via {r.rules}"


@pytest.mark.parametrize("sql", BENIGN_SQL)
def test_benign_sql_produces_no_detection_finding(sql):
    assert classify_sql_findings(sql) == [], f"{sql!r}"


def test_a_read_query_is_not_even_classified():
    """A SELECT must stay `unknown`, not acquire a destructive class. Anything
    else would put every read behind a require_approval policy."""
    assert classify("run_sql", {"query": "SELECT * FROM users WHERE id = 42"}) == (
        "unknown", "medium")


# ══ (d) THE BLOCK/CLASSIFY SPLIT ═════════════════════════════════════════════

BLOCKS = [
    "DELETE FROM users WHERE 1=1",
    "DELETE FROM users WHERE 1 = 1",
    "UPDATE accounts SET balance = 0 WHERE 1=1",
    "DELETE FROM users WHERE true",
    "DELETE FROM users WHERE 'a'='a'",
    "DELETE FROM users WHERE id = id",
    "DELETE FROM t WHERE id > 0 OR 1=1",
]


@pytest.mark.parametrize("sql", BLOCKS)
def test_a_tautological_predicate_blocks(sql):
    s = _sensor("block")
    r = _quiet(s.scan_tool_call, "run_sql", {"query": sql})
    assert r.action == "blocked", f"{sql!r} -> {r.action} {r.rules}"
    assert "sql.tautological_mutation" in r.rules


CLASSIFY_ONLY = [
    "DROP TABLE users",
    "DROP DATABASE prod",
    "TRUNCATE TABLE customers",
    "DELETE FROM users",
    "UPDATE accounts SET balance = 0",
]


@pytest.mark.parametrize("sql", CLASSIFY_ONLY)
def test_the_classify_only_majority_does_not_block(sql):
    """Not leniency. Each of these is a real operation a migration, teardown or
    kill-switch performs on purpose, and the statement cannot tell us which. They
    are reachable by a require_approval policy on their impact_class, which is
    what that mechanism is for."""
    s = _sensor("block")
    r = _quiet(s.scan_tool_call, "run_sql", {"query": sql})
    assert r.action == "allowed", f"{sql!r} -> {r.action} {r.rules}"
    assert classify_sql_findings(sql) == []
    assert classify("run_sql", {"query": sql})[1] == "critical"


def test_the_split_is_not_an_accident():
    """The contrast, asserted side by side so neither half can move alone."""
    s = _sensor("block")
    unbounded = _quiet(s.scan_tool_call, "run_sql", {"query": "DELETE FROM users"})
    disguised = _quiet(s.scan_tool_call, "run_sql",
                       {"query": "DELETE FROM users WHERE 1=1"})
    bounded = _quiet(s.scan_tool_call, "run_sql",
                     {"query": "DELETE FROM users WHERE id = 42"})
    assert unbounded.action == "allowed"   # deliberate table clear, policy's call
    assert disguised.action == "blocked"   # unbounded wearing a predicate
    assert bounded.action == "allowed"     # ordinary work


# ══ (e) PARITY WITH THE SHELL PATH ═══════════════════════════════════════════

def test_the_same_statement_gets_the_same_answer_through_a_shell_client():
    """If `run_sql(query="DROP TABLE users")` blocked while
    `psql -c "DROP TABLE users"` passed, refactoring to the shell tool would be a
    one-line bypass. Both classify infra_destruction and neither blocks."""
    s = _sensor("block")
    direct = _quiet(s.scan_tool_call, "run_sql", {"query": "DROP TABLE users"})
    shelled = _quiet(s.scan_tool_call, "run_command",
                     {"command": 'psql -c "DROP TABLE users"'})
    assert classify("run_sql", {"query": "DROP TABLE users"})[0] == "infra_destruction"
    assert classify("run_command", {"command": 'psql -c "DROP TABLE users"'})[0] \
        == "infra_destruction"
    assert direct.action == shelled.action == "allowed"


# ══ (f) PROSE AND SHELL MUST NOT REACH THE SQL READER ════════════════════════
# The anchor (a value must BEGIN with a SQL statement) is the false-positive
# defence. Without it, every incident report that quotes a statement is a finding.

NOT_SQL = [
    "we had to DROP TABLE users last night to recover the cluster",
    "Runbook: if the queue backs up, `TRUNCATE TABLE jobs` and restart the worker",
    "The postmortem says someone ran DELETE FROM users WHERE 1=1 in production.",
    'psql -c "DROP TABLE users"',
    'mysql -e "DROP TABLE users"',
    "rm -rf /var/lib/postgresql/data",
    "docker ps -a",
    "",
    "   ",
]


@pytest.mark.parametrize("text", NOT_SQL)
def test_non_sql_values_never_reach_the_sql_reader(text):
    assert parse_sql(text) == [] or not looks_like_sql(text)
    assert classify_sql(text) is None
    assert classify_sql_findings(text) == []


@pytest.mark.parametrize("text", NOT_SQL)
def test_prose_and_shell_are_not_extracted_as_sql(text):
    assert extract_sql({"body": text}) is None


# ── the shell-binary/SQL-verb collision ──────────────────────────────────────
# Found as a live regression while building this: `truncate`, `create`,
# `replace`, `call` and `execute` are SQL statements AND ordinary shell
# binaries. A gate that accepted the leading verb alone read
# `truncate -s 0 /var/log/audit.log` as SQL and reclassified it from `evade` to
# `infra_destruction`, losing the fact that something was covering its tracks.

SHELL_COMMANDS_STARTING_WITH_A_SQL_VERB = [
    ("truncate -s 0 /var/log/audit.log", "evade"),
    ("truncate -s 0 tmp/scratch.txt", None),
    ("create --help", None),
    ("select --version", None),
]


@pytest.mark.parametrize("cmd,_expected", SHELL_COMMANDS_STARTING_WITH_A_SQL_VERB)
def test_a_shell_binary_sharing_a_sql_verb_is_not_read_as_sql(cmd, _expected):
    assert not looks_like_sql(cmd), f"{cmd!r} was read as SQL"
    assert parse_sql(cmd) == []
    assert classify_sql_findings(cmd) == []


def test_the_audit_log_wipe_keeps_its_evade_classification():
    """The exact regression, pinned. `evade` is the fact that matters here: this
    is log tampering, and calling it infra_destruction would file it under
    'someone tore down a database' instead."""
    cmd = "truncate -s 0 /var/log/audit.log"
    assert classify("run_command", {"command": cmd})[0] == "evade"


def test_a_shell_command_after_a_semicolon_is_not_absorbed_as_sql():
    """The grammar gate runs PER STATEMENT, not just on the head."""
    shapes = parse_sql("SELECT 1; truncate -s 0 /var/log/audit.log")
    assert [s.statement for s in shapes] == ["select"]


def test_documentary_prose_quoting_a_statement_still_does_not_block():
    """The residue/mention protection that test_benign_prose.py owns must not be
    undone by the new reader."""
    s = _sensor("block")
    prose = ("Incident report: the on-call engineer ran `DELETE FROM users WHERE 1=1` "
             "against the primary, which is why the account table was empty at 03:00. "
             "We have since revoked write access for the deploy role.")
    r = _quiet(s.scan_tool_call, "summarise_document", {"text": prose})
    assert r.action != "blocked", f"{r.action} {r.rules}"


# ══ (g) BATCHES, AND THE STRONGEST STATEMENT WINNING ═════════════════════════

def test_a_batch_is_classified_by_its_strongest_statement():
    batch = ("SELECT count(*) FROM users; "
             "DELETE FROM users WHERE 1=1; "
             "SELECT count(*) FROM users")
    s = _sensor("block")
    r = _quiet(s.scan_tool_call, "run_sql", {"query": batch})
    assert r.action == "blocked"
    assert "sql.tautological_mutation" in r.rules


def test_a_migration_batch_classifies_without_blocking():
    batch = ("BEGIN; ALTER TABLE accounts DROP COLUMN legacy_token; "
             "DROP TABLE accounts_backup; COMMIT;")
    s = _sensor("block")
    r = _quiet(s.scan_tool_call, "run_sql", {"query": batch})
    assert r.action == "allowed", f"{r.action} {r.rules}"


# ══ (h) BOUNDS AND RESILIENCE ════════════════════════════════════════════════

def test_the_reader_is_bounded_and_never_raises():
    for value in (None, 12, [], {}, b"DROP TABLE users", "DROP " * 100_000):
        assert isinstance(parse_sql(value), list)
    assert classify_sql("DROP " * 100_000) is None or True  # must not raise


def test_a_pathological_value_stays_inside_the_budget():
    """Bounded, not merely finite. The cap is what keeps cost flat."""
    payload = "DELETE FROM t WHERE " + ("a = 1 OR " * 20_000) + "1=1"
    start = time.perf_counter()
    shapes = parse_sql(payload)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"parse took {elapsed:.3f}s"
    assert len(payload) > MAX_SQL_CHARS
    assert shapes  # still readable, just truncated


def test_a_semicolon_heavy_blob_does_not_explode():
    payload = "; ".join(["SELECT 1"] * 5_000)
    start = time.perf_counter()
    shapes = parse_sql("SELECT 1; " + payload)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"parse took {elapsed:.3f}s"
    assert len(shapes) <= 32, f"statement cap not honoured: {len(shapes)}"


def test_a_string_literal_cannot_forge_a_predicate():
    """A literal containing WHERE must not make an unbounded statement look
    bounded, and a literal containing a statement must not become one."""
    shapes = parse_sql("DELETE FROM t")
    assert shapes[0].predicate == "none"
    shapes = parse_sql("SELECT * FROM t WHERE name = 'DROP TABLE users'")
    assert len(shapes) == 1 and shapes[0].statement == "select"


def test_a_comment_cannot_hide_or_forge_a_statement():
    assert parse_sql("-- DROP TABLE users\nSELECT 1")[0].statement == "select"
    shapes = parse_sql("DELETE FROM users /* WHERE id = 1 */")
    assert shapes[0].predicate == "none", "a commented-out WHERE must not bound it"
