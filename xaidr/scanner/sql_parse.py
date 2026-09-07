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

# THE STATEMENT VALUE THAT MEANS "WE DID NOT READ ALL OF THIS".
#
# Every bound in this module is a place where the parser stops. A bound that
# DROPS what it did not reach reports the same thing as an input that contained
# nothing: a caller cannot tell "there was no DELETE" from "we stopped before the
# DELETE". Both of those bypasses were measured on 1.12.0-rc, one by padding past
# MAX_SQL_CHARS and one by preceding the payload with MAX_STATEMENTS harmless
# statements; in both the destructive statement ran.
#
# So every bound now emits this shape IN ADDITION to whatever it did manage to
# parse, and `sql.unparsed_input` in impact-classes.json gates it. The shape is
# deliberately NOT a fabricated DELETE: it says "a SQL value exceeded what this
# parser can read", which is true, and the rule that gates it says why. The
# pattern is borrowed from L1, which already does exactly this for over-length
# input via OVERSIZED_INPUT_RULE rather than truncating in silence.
UNPARSED_STATEMENT = "unparsed"


def _unparsed_shape(text, reason: str):
    """The fail-closed shape for input a bound stopped us from reading."""
    return SqlShape(
        statement=UNPARSED_STATEMENT,
        object_kind=None,
        object=None,
        predicate="unknown",
        raw=f"[{reason}] {str(text)[:200]}",
    )

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


# ═══════════════════════════════════════════════════════════════════════════
# THE LEXER, and why this is a lexer and not either a regex layer or a parser
# ═══════════════════════════════════════════════════════════════════════════
#
# An independent audit measured three bypasses and two false positives that all
# have ONE cause: string and comment boundaries were decided by regexes run over
# raw text, so a quoted literal changed the structural reading of routine valid
# SQL. Against a real SQLite oracle, each of these deleted every row while the
# scanner returned allowed at score 0.00 under a critical-tier approval policy:
#
#   DELETE FROM records RETURNING 'where id=7'   the WHERE inside a STRING made
#                                                the statement look bounded
#   WITH x AS (SELECT 1) DELETE FROM records     the leading CTE was classified
#                                                instead of the real mutation
#   SELECT '--'; DELETE FROM records WHERE 1=1   the `--` inside a STRING was
#                                                read as a comment, swallowing
#                                                the statement that followed
#
# and two the other way, blocking work that deletes 0 and 1 row respectively:
#
#   DELETE FROM records WHERE note='1=1'         `1=1` inside a STRING
#   DELETE FROM records WHERE id=7 AND 1=1       a tautology as one CONJUNCT of
#                                                an otherwise bounded predicate
#
# WHY A LEXER RATHER THAN FAILING CLOSED ON THE CURRENT RECOGNISER. Failing
# closed was the alternative considered, and on its own it does not work: to
# decide "I cannot confidently parse this" you must ALREADY know where strings
# and comments end. `SELECT '--'; DELETE ...` cannot even be split into
# statements without that, so a fail-closed rule bolted onto the regex layer
# would fail closed on the wrong inputs and still miss this one. Tokenization is
# the precondition for an honest "I do not know".
#
# WHY NOT A REAL PARSER. What the classifier consumes is a verb, an object, and
# whether the predicate restricts the rows — token-level structure, not a
# grammar. A full parser (sqlglot, sqlparse) would be a runtime dependency, and
# `pip install xaidr` pulling in nothing is the product's headline claim, not a
# detail to trade away for a scanner that already declines to be a semantic
# authority. A lexer is ~150 lines, linear-time, dialect-tolerant, and testable
# against a real database.
#
# SO: TOKENIZE, THEN FAIL CLOSED ON WHAT THE TOKENS DO NOT SETTLE. Anything the
# lexer can read but the recogniser cannot confidently classify gets
# predicate="unknown", which callers treat as UNRESTRICTED. A shallow
# recogniser that is confidently wrong is worse than one that says it does not
# know.

#: Token kinds. `str` and `comment` are opaque: their CONTENT never reaches a
#: structural question, which is the whole point.
_TOK_WORD, _TOK_STR, _TOK_COMMENT, _TOK_PUNCT = "word", "str", "comment", "punct"

_IDENT_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_IDENT_CHARS = _IDENT_START | set("0123456789$")


class SqlToken(NamedTuple):
    kind: str
    text: str          # verbatim source slice
    lower: str         # lowercased, for word comparisons; "" for str/comment


def tokenize(text: str) -> list:
    """SQL text -> tokens, with correct string and comment boundaries.

    Handles, because each appears in ordinary SQL an agent will send:
      * single-quoted literals with the '' escape,
      * double-quoted and backtick-quoted identifiers (ANSI and MySQL),
      * dollar-quoted bodies, $$...$$ and $tag$...$tag$ (PostgreSQL),
      * -- and # line comments,
      * /* */ block comments, nested (PostgreSQL nests; treating them as nested
        is the conservative reading either way).

    Linear in the input and allocation-bounded: no regex, no backtracking, so
    it cannot become the ReDoS surface the invariants in this package exist to
    keep out. An unterminated string or comment runs to end-of-input and is
    returned as one token, which is what makes the caller able to notice it.
    """
    out: list = []
    i, n = 0, min(len(text), MAX_SQL_CHARS)
    while i < n:
        ch = text[i]

        if ch in " \t\r\n":
            i += 1
            continue

        # ── comments ────────────────────────────────────────────────────
        if text.startswith("--", i) or ch == "#":
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(SqlToken(_TOK_COMMENT, text[i:j], ""))
            i = j
            continue
        if text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            out.append(SqlToken(_TOK_COMMENT, text[i:j], ""))
            i = j
            continue

        # ── strings and quoted identifiers ──────────────────────────────
        if ch == "'":
            j = i + 1
            while j < n:
                if text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            out.append(SqlToken(_TOK_STR, text[i:j], ""))
            i = j
            continue
        if ch in '"`':
            j = i + 1
            while j < n and text[j] != ch:
                j += 1
            j = min(j + 1, n)
            # A quoted IDENTIFIER is a name, not a literal: it keeps its text so
            # `DELETE FROM "records"` still resolves an object.
            out.append(SqlToken(_TOK_WORD, text[i:j], text[i + 1:j - 1].lower()))
            i = j
            continue
        if ch == "$":
            close = text.find("$", i + 1)
            if close != -1 and close - i <= 64:
                tag = text[i:close + 1]
                end = text.find(tag, close + 1)
                end = n if end == -1 else end + len(tag)
                out.append(SqlToken(_TOK_STR, text[i:end], ""))
                i = end
                continue

        # ── words and punctuation ───────────────────────────────────────
        if ch in _IDENT_START:
            j = i
            while j < n and text[j] in _IDENT_CHARS:
                j += 1
            word = text[i:j]
            out.append(SqlToken(_TOK_WORD, word, word.lower()))
            i = j
            continue
        if ch.isdigit():
            j = i
            while j < n and (text[j].isdigit() or text[j] == "."):
                j += 1
            out.append(SqlToken(_TOK_WORD, text[i:j], text[i:j]))
            i = j
            continue

        out.append(SqlToken(_TOK_PUNCT, ch, ch))
        i += 1

        if len(out) > _MAX_TOKENS:
            break
    return out


#: Bound on tokens per value. A pathological argument must not turn one tool
#: call into unbounded work; hitting it is also a fail-CLOSED signal, because a
#: truncated token stream cannot settle a predicate.
_MAX_TOKENS = 20000


def _split_token_statements(tokens: list) -> tuple:
    """Split on `;` at depth 0 -> (statements, over_cap).

    Comments are dropped; strings are kept opaque. Statement splitting on TOKENS
    is what fixes `SELECT '--'; DELETE ...`: the `--` is inside a string token,
    so it is not a comment, so the `;` after it is still a statement boundary and
    the DELETE is still inspected.

    THE SECOND RETURN VALUE IS THE POINT. This used to return a short list when
    it hit MAX_STATEMENTS, and a short list is indistinguishable from a short
    input: "we stopped looking" read as "there was nothing there". A batch of
    MAX_STATEMENTS harmless statements followed by an unbounded DELETE parsed to
    harmless statements only, and the DELETE ran. The cap is now reported, and
    parse_sql turns the report into a shape the classifier must gate.

    This is also the ONLY place MAX_STATEMENTS is enforced. It was enforced here,
    again as a slice in parse_sql, and a third time in a string splitter that the
    token rewrite had already made unreachable. One constant with three
    enforcement points is a constant nobody can reason about.
    """
    stmts, cur, depth = [], [], 0
    for tok in tokens:
        if tok.kind == _TOK_COMMENT:
            continue
        if tok.kind == _TOK_PUNCT:
            if tok.text == "(":
                depth += 1
            elif tok.text == ")":
                depth = max(0, depth - 1)
            elif tok.text == ";" and depth == 0:
                if cur:
                    stmts.append(cur)
                cur = []
                if len(stmts) >= MAX_STATEMENTS:
                    return stmts, True
                continue
        cur.append(tok)
    if cur:
        stmts.append(cur)
    return stmts, False


def _skip_cte(tokens: list) -> list:
    """Drop a leading WITH ... AS (...) [, ...] so the real verb is reachable.

    `WITH x AS (SELECT 1) DELETE FROM records` classified as the leading WITH —
    a read — while deleting every row. The CTE is a preamble; the statement is
    what follows it.
    """
    if not tokens or tokens[0].lower != "with":
        return tokens
    i = 1
    if i < len(tokens) and tokens[i].lower == "recursive":
        i += 1
    while i < len(tokens):
        # name [ (cols) ] AS ( body )
        while i < len(tokens) and tokens[i].lower != "as":
            if tokens[i].kind == _TOK_PUNCT and tokens[i].text == "(":
                depth = 1
                i += 1
                while i < len(tokens) and depth:
                    if tokens[i].text == "(":
                        depth += 1
                    elif tokens[i].text == ")":
                        depth -= 1
                    i += 1
                continue
            i += 1
        if i >= len(tokens):
            return []                      # malformed -> nothing to classify
        i += 1                             # past AS
        if i < len(tokens) and tokens[i].text == "(":
            depth = 1
            i += 1
            while i < len(tokens) and depth:
                if tokens[i].text == "(":
                    depth += 1
                elif tokens[i].text == ")":
                    depth -= 1
                i += 1
        if i < len(tokens) and tokens[i].text == ",":
            i += 1
            continue                       # another CTE
        return tokens[i:]
    return []


#: Words that BOUND a predicate: a comparison against one of these restricts the
#: rows. Anything else in a WHERE clause leaves the predicate unsettled.
_PREDICATE_TERMINATORS = frozenset({
    "returning", "order", "limit", "group", "having", "window", "offset",
    "fetch", "for", "into", "on",
})


def _predicate_state_tokens(tokens: list) -> str:
    """"none" | "bounded" | "tautology" | "unknown", from TOKENS.

    Two things the regex version could not do, both of which the audit measured:

      * a WHERE inside a string literal is not a WHERE, and `1=1` inside a
        string literal is not a tautology. String tokens are opaque here, so
        neither can be seen.
      * a tautology as ONE CONJUNCT of a predicate does not make the predicate
        unrestricted. `WHERE id=7 AND 1=1` deletes one row; calling it
        tautological was a false positive. The clause is split on top-level OR
        into disjuncts, and each disjunct on AND into conjuncts: a disjunct is
        unrestricted only when EVERY one of its conjuncts is a tautology, and
        the predicate is unrestricted only when ANY disjunct is. That is the
        auditor's criterion — never treat a substring tautology as evidence the
        whole predicate is unrestricted — expressed as boolean structure rather
        than as a longer regex.
    """
    where_at = None
    depth = 0
    for idx, tok in enumerate(tokens):
        if tok.kind == _TOK_PUNCT:
            if tok.text == "(":
                depth += 1
            elif tok.text == ")":
                depth = max(0, depth - 1)
        elif tok.kind == _TOK_WORD and depth == 0 and tok.lower == "where":
            where_at = idx
            break
    if where_at is None:
        return "none"

    clause, depth = [], 0
    for tok in tokens[where_at + 1:]:
        if tok.kind == _TOK_PUNCT:
            if tok.text == "(":
                depth += 1
            elif tok.text == ")":
                depth = max(0, depth - 1)
        elif tok.kind == _TOK_WORD and depth == 0 and tok.lower in _PREDICATE_TERMINATORS:
            break
        clause.append(tok)
    if not clause:
        return "unknown"                   # `WHERE` with nothing after it

    def split_top(toks, word):
        parts, cur, d = [], [], 0
        for t in toks:
            if t.kind == _TOK_PUNCT:
                if t.text == "(":
                    d += 1
                elif t.text == ")":
                    d = max(0, d - 1)
            elif t.kind == _TOK_WORD and d == 0 and t.lower == word:
                parts.append(cur)
                cur = []
                continue
            cur.append(t)
        parts.append(cur)
        return parts

    def is_tautology(term):
        """A three-token comparison whose two sides are identical constants."""
        real = [t for t in term if t.kind != _TOK_COMMENT]
        # bare truthy: `WHERE 1` / `WHERE true`
        if len(real) == 1 and real[0].lower in ("1", "true"):
            return True
        if len(real) == 3 and real[1].kind == _TOK_PUNCT and real[1].text == "=":
            left, right = real[0], real[2]
            if left.kind == _TOK_STR or right.kind == _TOK_STR:
                # 'a'='a' is a tautology; 'a'='b' is not. Compare the literals
                # themselves, never their contents against anything else.
                return left.kind == right.kind and left.text == right.text
            return left.lower == right.lower
        return False

    for disjunct in split_top(clause, "or"):
        conjuncts = split_top(disjunct, "and")
        if conjuncts and all(is_tautology(c) for c in conjuncts):
            return "tautology"
    return "bounded"

def _strip_comments(text: str) -> str:
    text = _BLOCK_COMMENT_RE.sub(" ", text)
    text = _LINE_COMMENT_RE.sub(" ", text)
    return text


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

    TOKEN-DRIVEN since the audit. Every statement is inspected, not just the
    first; a leading CTE is skipped so the real verb is classified; strings and
    comments are opaque, so neither their contents nor a `--` inside a literal
    can change the structural reading.

    FAILS CLOSED. A statement whose predicate the token structure cannot settle
    gets predicate="unknown", and callers treat unknown exactly as they treat an
    unrestricted mutation. The recogniser is allowed to say it does not know; it
    is not allowed to say "bounded" when it means "I could not tell".

    Never raises.
    """
    try:
        if not isinstance(text, str) or not text.strip():
            return []
        # Read the caps BEFORE truncating, so "we stopped" is recoverable.
        over_chars = len(text) > MAX_SQL_CHARS
        text = text[:MAX_SQL_CHARS]
        if not looks_like_sql(text):
            return []

        shapes = []
        tokens = tokenize(text)
        truncated = len(tokens) > _MAX_TOKENS
        statements, over_statements = _split_token_statements(tokens)
        for stmt_tokens in statements:
            body = _skip_cte(stmt_tokens)
            if not body:
                continue
            # The grammar gate still decides whether this is SQL at all, and it
            # runs on the RECONSTRUCTED statement so the shell-shape checks in
            # _statement_head keep working.
            stmt = " ".join(t.text for t in body)
            head = _statement_head(stmt)
            if head is None:
                continue
            statement = head[0]

            structural = _DQ_LITERAL_RE.sub(" ", stmt)
            object_kind = None
            km = _OBJECT_KIND_RE.match(structural)
            if km:
                object_kind = re.sub(r"\s+", " ", km.group(1).lower())
            if statement == "alter":
                am = _ALTER_DROP_RE.search(structural)
                if am:
                    object_kind = am.group(1).lower()
            obj = None
            om = _OBJECT_RE.search(structural)
            if om:
                obj = om.group(1).lower()

            predicate = "unknown" if truncated else _predicate_state_tokens(body)
            shapes.append(SqlShape(
                statement=statement,
                object_kind=object_kind,
                object=obj,
                predicate=predicate,
                raw=stmt,
            ))

        # A bound stopped us. Say so, IN ADDITION to what was parsed, so the
        # classifier gates on the part we could not read rather than on the
        # harmless part we could. Each reason is named separately because they
        # fail for different lengths of input and a maintainer tuning one cap
        # needs to know which one fired.
        if over_chars:
            shapes.append(_unparsed_shape(
                text, f"input over MAX_SQL_CHARS={MAX_SQL_CHARS}"))
        if over_statements:
            shapes.append(_unparsed_shape(
                text, f"batch over MAX_STATEMENTS={MAX_STATEMENTS}"))
        if truncated:
            shapes.append(_unparsed_shape(
                text, f"token stream over _MAX_TOKENS={_MAX_TOKENS}"))
        return shapes
    except Exception:
        # Fail CLOSED on a lexer fault: an unparseable value that begins with a
        # SQL verb is reported as an unknown-predicate statement of that verb,
        # not as "not SQL". Returning [] here is what would let a crafted value
        # vanish from the structural path entirely.
        try:
            head = _statement_head(text if isinstance(text, str) else "")
            if head is not None:
                return [SqlShape(statement=head[0], object_kind=None, object=None,
                                 predicate="unknown", raw=str(text)[:MAX_SQL_CHARS])]
        except Exception:
            pass
        return []
