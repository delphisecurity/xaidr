"""Structural shape of a SQL statement, for impact classification.

WHY THIS EXISTS, and why it is not part of command_parse. An agent that runs SQL
does not run it through a shell. It calls a tool, `run_sql(query=...)`,
`execute_query(sql=...)`, `db(statement=...)`, and hands the statement over as a
plain argument value. `command_parse` tokenizes with shell rules and asks "what
binary is this", which is the right question for `psql -c "DROP TABLE users"` and
the wrong question for `DROP TABLE users`: shlex reports a binary named `DROP`,
mangles `'string literals'` into bare words, and cannot see a WHERE clause at
all. So SQL gets its own reader, sitting ALONGSIDE the shell one rather than
inside it.

WHAT IT EXTRACTS, and nothing more. This is not a SQL parser and must never grow
into one. It answers four questions a classification rule needs:

    statement   the leading verb: drop, truncate, delete, update, insert,
                select, create, alter, grant, ...
    object_kind what the verb acts on when the grammar names it: table,
                database, schema, index, column, ...
    object      the identifier, when there is an obvious one
    predicate   "none" | "bounded" | "tautology"  -- see below

PREDICATE IS THE LOAD-BEARING FIELD. For DDL there is no WHERE clause and the
statement type is the whole signal. For DML the statement type is nearly
worthless on its own (`DELETE` is how a session cache is cleared) and the
BOUNDING PREDICATE is what separates routine work from a table-wipe:

    DELETE FROM sessions WHERE expires_at < now()   bounded    routine
    DELETE FROM users                               none       unbounded
    DELETE FROM users WHERE 1=1                     tautology  unbounded, disguised

The third is its own state rather than a flavour of the first because it is a
STRONGER signal than a missing WHERE, not a weaker one. Someone clearing a table
on purpose writes no WHERE clause; an ORM writes `WHERE id = ?`. A predicate that
is always true is what you get when something wanted the effect of no predicate
while looking like it had one.

SAFETY. Every pattern here is bounded and has no nested quantifier, because this
runs on attacker-controlled argument values (see the ReDoS invariants in the test
suite). Input is capped, comments and string literals are removed before any
structural question is asked, and the module never raises: an unparseable value
is simply not SQL.
"""
from __future__ import annotations

import re
from typing import NamedTuple, Optional

# Hard input ceiling. A statement longer than this is not something we can say
# anything useful about, and the cap keeps the scan cost flat regardless of what
# a caller passes. Real migrations are comfortably under it.
MAX_SQL_CHARS = 20_000

# Cap on statements per value, so a pathological semicolon-heavy blob cannot turn
# one classification into thousands.
MAX_STATEMENTS = 32

# The leading verbs we recognise. A value whose first meaningful token is not one
# of these is NOT SQL as far as this module is concerned, which is the whole
# false-positive defence: prose that merely mentions a statement ("we had to DROP
# TABLE users last night") does not start with the verb, and a shell command
# (`psql -c "DROP TABLE users"`) starts with a binary name.
_STATEMENTS = (
    "select", "insert", "update", "delete", "drop", "truncate", "create",
    "alter", "grant", "revoke", "merge", "replace", "call", "execute", "with",
    # Transaction control. These never match a rule; they are listed so that a
    # migration batch wrapped in BEGIN/COMMIT is still READ as SQL rather than
    # rejected at the first token, which would hide the statements inside it.
    "begin", "commit", "rollback", "start",
)

_STATEMENT_RE = re.compile(
    r"^\s*(" + "|".join(_STATEMENTS) + r")\b", re.IGNORECASE
)

# THE LEADING VERB IS NOT ENOUGH, and finding that out cost a real regression.
# `truncate`, `create`, `replace`, `call` and `execute` are SQL statements AND
# ordinary shell binaries. `truncate -s 0 /var/log/audit.log` is how an audit log
# is wiped; it begins with a SQL verb and is not remotely SQL. Reading it as SQL
# reclassified it from `evade` to `infra_destruction` and lost the fact that
# something was covering its tracks.
#
# So a value has to look like SQL GRAMMAR, not just start with a SQL word. Two
# gates, both cheap:
#
#   1. the head must not be shell-shaped: no `-s`, no `/abs/path`, no `./rel`,
#      no `~`, no `$VAR`, no `VAR=value` prefix.
#   2. the verb's expected follower must be there: DELETE takes FROM, INSERT
#      takes INTO, UPDATE takes SET, DROP takes an object kind.
#
# Both are deliberately strict. A statement this rejects is simply not
# classified, which is where every one of them already was; a shell command it
# ACCEPTS is a misclassification, which is strictly worse.
_SHELL_SHAPED_HEAD_RE = re.compile(
    r"^\s*(?:-{1,2}[a-zA-Z]|[/~.]|\$|[A-Za-z_][\w]*=)"
)

_REQUIRED_FOLLOWER = {
    "delete": re.compile(r"^\s*(?:from|ignore\s+from)\b", re.IGNORECASE),
    "insert": re.compile(r"^\s*(?:into|ignore|or\s+\w+)\b", re.IGNORECASE),
    "replace": re.compile(r"^\s*into\b", re.IGNORECASE),
    "update": re.compile(r"^[^;]{0,4000}?\bset\b", re.IGNORECASE),
    "merge": re.compile(r"^\s*into\b", re.IGNORECASE),
    "grant": re.compile(r"^[^;]{0,4000}?\b(?:on|to)\b", re.IGNORECASE),
    "revoke": re.compile(r"^[^;]{0,4000}?\b(?:on|from)\b", re.IGNORECASE),
    "drop": re.compile(
        r"^\s*(?:if\s+exists\s+)?(?:table|database|schema|index|view|column|"
        r"keyspace|collection|tablespace|materialized\s+view|sequence|trigger|"
        r"function|procedure|role|user|type|extension|policy|constraint)\b",
        re.IGNORECASE),
    "create": re.compile(
        r"^\s*(?:or\s+replace\s+)?(?:temp(?:orary)\s+|unique\s+|global\s+|"
        r"materialized\s+)*(?:table|database|schema|index|view|keyspace|"
        r"sequence|trigger|function|procedure|role|user|type|extension|policy)\b",
        re.IGNORECASE),
    "alter": re.compile(
        r"^\s*(?:table|database|schema|index|view|sequence|role|user|type|"
        r"materialized\s+view)\b", re.IGNORECASE),
    # TRUNCATE [TABLE] ident. The identifier requirement is what separates it
    # from `truncate -s 0 <file>`, whose next token is a flag.
    "truncate": re.compile(r"^\s*(?:table\s+)?[`\"\[]?[a-zA-Z_]", re.IGNORECASE),
    # SELECT / WITH / CALL / EXECUTE are left to the shell-shape gate alone:
    # `select` and `with` are not shell binaries, and requiring FROM would reject
    # `SELECT 1`, which is a real health-check query.
}

# `DROP TABLE`, `TRUNCATE TABLE`, `ALTER TABLE ... DROP COLUMN`, ...
_OBJECT_KIND_RE = re.compile(
    r"^\s*\w+\s+(?:if\s+exists\s+)?"
    r"(table|database|schema|index|view|column|keyspace|collection|tablespace|"
    r"materialized\s+view|sequence|trigger|function|procedure|role|user)\b",
    re.IGNORECASE,
)

# The identifier after the object kind, or after FROM/INTO/UPDATE for DML.
# Bounded and deliberately forgiving: a missed name costs a rule its `object`
# match, it never costs correctness of the statement type.
_OBJECT_RE = re.compile(
    r"\b(?:from|into|update|table|database|schema|keyspace)\s+"
    r"(?:if\s+exists\s+)?"
    r"[`\"\[]?([a-zA-Z_][\w$]{0,62}(?:\.[a-zA-Z_][\w$]{0,62})?)[`\"\]]?",
    re.IGNORECASE,
)

# ALTER ... DROP <kind>. Separated from a leading DROP because dropping a COLUMN
# in a migration and dropping a TABLE are different facts, and the shipped shell
# rule (infra.database_drop) already draws the line in exactly this place: its
# pattern is `drop\s+(database|schema|table)` and does not name COLUMN.
_ALTER_DROP_RE = re.compile(
    r"\bdrop\s+(column|constraint|index|partition|default)\b", re.IGNORECASE
)

_WHERE_RE = re.compile(r"\bwhere\b", re.IGNORECASE)

# Tautology forms. All bounded, no nested quantifiers.
_TAUTOLOGIES = (
    # 1=1, 0=0, 42 = 42
    re.compile(r"\b(\d{1,9})\s*=\s*\1\b"),
    # WHERE true  /  WHERE 1  (a bare truthy predicate)
    re.compile(r"\bwhere\s+(?:true|1)\s*(?:;|$|\)|--)", re.IGNORECASE),
    # 'a' = 'a'  (backreference, so only genuinely equal literals match)
    re.compile(r"'([^'\n]{0,64})'\s*=\s*'\1'"),
    # id = id  (a column compared with itself)
    re.compile(r"\b([a-zA-Z_][\w$]{0,62})\s*=\s*\1\b"),
    # ... OR 1=1 style, already covered by the first form, plus the word variant
    re.compile(r"\bor\s+true\b", re.IGNORECASE),
)

# Comments and string literals, removed before any structural question is asked
# so that a literal containing the word WHERE, or a commented-out DROP, cannot
# change the answer. Order matters: block comments first, then line comments,
# then literals.
_BLOCK_COMMENT_RE = re.compile(r"/\*.{0,4000}?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"(?:--|#)[^\n]{0,4000}")
_DQ_LITERAL_RE = re.compile(r'"[^"\n]{0,4000}"')


class SqlShape(NamedTuple):
    """The structural facts a classification rule is allowed to key on."""

    statement: str            # lowercased leading verb
    object_kind: Optional[str]  # lowercased, when the grammar names one
    object: Optional[str]     # the identifier, when there is an obvious one
    predicate: str            # "none" | "bounded" | "tautology"
    raw: str                  # the statement text, comments stripped


def _strip_comments(text: str) -> str:
    text = _BLOCK_COMMENT_RE.sub(" ", text)
    text = _LINE_COMMENT_RE.sub(" ", text)
    return text


def _split_statements(text: str) -> list:
    """Split on semicolons that are not inside a single-quoted literal.

    A hand-rolled scan rather than a regex: the alternative is a pattern with a
    quantified alternation over quotes, which is exactly the shape the ReDoS
    invariants exist to keep out of this codebase.
    """
    out, buf, in_str = [], [], False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "'":
                # '' is an escaped quote inside a literal, not the end of it.
                if i + 1 < n and text[i + 1] == "'":
                    buf.append("''")
                    i += 2
                    continue
                in_str = False
            buf.append(ch)
        elif ch == "'":
            in_str = True
            buf.append(ch)
        elif ch == ";":
            out.append("".join(buf))
            buf = []
            if len(out) >= MAX_STATEMENTS:
                return out
        else:
            buf.append(ch)
        i += 1
    out.append("".join(buf))
    return out


def _predicate_state(stmt: str) -> str:
    """"none" | "bounded" | "tautology" for a single statement.

    The tautology patterns run on the WHERE CLAUSE ONLY, never on the whole
    statement. `UPDATE counters SET hits = hits + 1 WHERE id = 7` is ordinary
    work, and `hits = hits` in its SET list matches the column-compared-with-
    itself form exactly. The SET list is an assignment, the WHERE clause is a
    comparison, and only the second one can be a tautology. Scoping to the
    clause is what keeps the two apart.
    """
    m = _WHERE_RE.search(stmt)
    if not m:
        return "none"
    clause = stmt[m.start():]
    for pat in _TAUTOLOGIES:
        if pat.search(clause):
            return "tautology"
    return "bounded"


def _statement_head(text: str) -> Optional[tuple]:
    """(verb, remainder) when `text` opens with real SQL grammar, else None.

    Anchored at the start on purpose: that is what keeps prose which merely
    discusses a statement ("we had to DROP TABLE users") and shell commands that
    wrap one (`psql -c "..."`) out of the SQL path entirely. The follower check
    is what keeps shell binaries that share a name with a SQL verb out of it too.
    """
    if not isinstance(text, str):
        return None
    capped = text[:MAX_SQL_CHARS]
    stripped = _strip_comments(capped).lstrip().lstrip("(").lstrip()
    m = _STATEMENT_RE.match(stripped)
    if not m:
        return None
    verb = m.group(1).lower()
    rest = stripped[m.end():]

    # The shell-shape gate runs on the RAW remainder as well as the stripped
    # one, and the raw check is the one that matters. `--` opens a comment in
    # SQL and a long option everywhere else, so comment-stripping turns
    # `select --version` into a bare `select` and hides the very evidence that
    # it is a shell command. Deciding "is this shell-shaped" has to happen
    # before `--` is interpreted as SQL.
    raw_m = _STATEMENT_RE.match(capped.lstrip().lstrip("(").lstrip())
    if raw_m:
        raw_rest = capped.lstrip().lstrip("(").lstrip()[raw_m.end():]
        if _SHELL_SHAPED_HEAD_RE.match(raw_rest):
            return None
    if _SHELL_SHAPED_HEAD_RE.match(rest):
        return None
    follower = _REQUIRED_FOLLOWER.get(verb)
    if follower is not None and not follower.match(rest):
        return None
    return (verb, rest)


def looks_like_sql(text: str) -> bool:
    """Cheap gate: does this value BEGIN with a SQL statement?"""
    return _statement_head(text) is not None


def parse_sql(text: str) -> list:
    """Return a list of SqlShape, one per statement. Empty when this is not SQL.

    Never raises.
    """
    try:
        if not isinstance(text, str) or not text.strip():
            return []
        text = text[:MAX_SQL_CHARS]
        if not looks_like_sql(text):
            return []

        shapes = []
        for raw_stmt in _split_statements(_strip_comments(text))[:MAX_STATEMENTS]:
            stmt = raw_stmt.strip()
            if not stmt:
                continue
            head = _statement_head(stmt)
            if head is None:
                # A trailing fragment after a semicolon that is not itself a
                # statement, or one that fails the grammar gate. Not an error,
                # just nothing to say about it. Applying the SAME gate per
                # statement matters: without it a shell command sitting after a
                # semicolon in an otherwise-SQL value would be read as SQL.
                continue
            statement = head[0]

            # Literals are removed only for the STRUCTURAL questions below; the
            # tautology check needs them intact, so it runs on `stmt`.
            structural = _DQ_LITERAL_RE.sub(" ", stmt)

            object_kind = None
            km = _OBJECT_KIND_RE.match(structural)
            if km:
                object_kind = re.sub(r"\s+", " ", km.group(1).lower())

            # ALTER TABLE x DROP COLUMN y is a column operation, not a table drop.
            if statement == "alter":
                am = _ALTER_DROP_RE.search(structural)
                if am:
                    object_kind = am.group(1).lower()

            obj = None
            om = _OBJECT_RE.search(structural)
            if om:
                obj = om.group(1).lower()

            shapes.append(SqlShape(
                statement=statement,
                object_kind=object_kind,
                object=obj,
                predicate=_predicate_state(stmt),
                raw=stmt,
            ))
        return shapes
    except Exception:
        return []
