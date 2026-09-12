"""THE STANDING DIFFERENTIAL GATE.

    Every parser in this package that reads a string the system will later ACT
    ON is compared here against the REAL CONSUMER of that string, never against
    a fixed expectation list.

WHY THIS FILE EXISTS AND WHY IT IS NOT MORE UNIT TESTS. A fixed expectation list
encodes what we THINK the parser does. It is written by the same person, at the
same moment, out of the same mental model as the parser — so when the model is
wrong, the test agrees with the bug. Two HIGH findings landed exactly there, and
both had passing test files sitting next to them:

    the sensor's host is not the transport's host
        `_extract_host` read the whole AUTHORITY with a regex, so
        `https://user@blocked.invalid/path` produced `user@blocked.invalid`. A
        deny-destination rule naming `blocked.invalid` matched nothing and the
        request went out. Every existing test asserted the regex's own output.

    unparseable SQL predicates read as bounded
        `_predicate_state_tokens` ended `return "bounded"`, so six one-line
        predicates — `(1=1)`, `2>1`, `NOT FALSE`, `coalesce(1,0)=1`,
        `1 BETWEEN 0 AND 2`, `1<>0` — deleted every row in a table while the
        scanner called them bounded and scored the call 0.00.

Neither is findable by asking "does the parser return what I expect". Both are
findable in one line by asking "does the parser agree with the thing that
actually runs this string".

THE THREE ORACLES, and why each one is the real consumer:

    URL host        `httpx.URL(...).raw_host` — the exact bytes the transport
                    puts in the Host header and hands to DNS. Falls back to
                    `urllib.parse.urlsplit(...).hostname` when the optional
                    `http` extra is absent; both are external to the code under
                    test, and neither is a list we wrote.
    SQL predicate   a real SQLite database. Five rows go in, the statement runs
                    inside a transaction, `cursor.rowcount` comes out, the
                    transaction rolls back. "Touched every row" is measured, not
                    asserted.
    shell command   `shlex` in POSIX mode with `punctuation_chars=True` — the
                    standard library's shell lexer, the one `subprocess` users
                    tokenize with. It performs quote removal and operator
                    splitting, which is the half of shell parsing the scanner
                    must agree about.

WHY THE SHELL ORACLE IS NOT A LIVE SHELL. Getting bash's own parse requires the
command text to become code (`f() { <cmd> ; }; declare -f f`), and a corpus entry
containing `}` breaks out of the function and EXECUTES. Running an attack corpus
through a real shell to test a security scanner is not a trade this suite makes.
`shlex` is a real parser with no execution, and the boundary it cannot cross —
expansion (`$(...)`, `$IFS`, backticks) — is one the scanner already declares for
itself via `ParsedCommand.expands`, so the comparison is gated on it rather than
fudged.

EVERY DIFFERENTIAL HERE ALSO ASSERTS ITS OWN COVERAGE. A gate that compares zero
items passes. `test_*_is_not_vacuous` pins the floor for each one.
"""
from __future__ import annotations

import itertools
import os
import shlex
import sqlite3
import warnings

import pytest

from xaidr.scanner.command_parse import parse_command
from xaidr.scanner.sql_parse import parse_sql
from xaidr.sensor import DelphiSensor, ProtectedHttpClient

try:                                              # optional `http` extra
    import httpx
except Exception:                                 # pragma: no cover
    httpx = None


# ═══════════════════════════════════════════════════════════════════════════
# 1. URL HOST  vs  the transport's own parse
# ═══════════════════════════════════════════════════════════════════════════

_SCHEMES = ["http", "https"]
_USERINFO = ["", "user@", "user:pw@", "svc%40corp@", "a@b@"]
_HOSTS = [
    "blocked.invalid", "API.Example.COM", "sub.blocked.invalid",
    "blocked.invalid.", "127.0.0.1", "169.254.169.254", "localhost",
    "[::1]", "[2001:DB8::1]", "[::ffff:169.254.169.254]",
    "exämple.com", "xn--exmple-cua.com",
]
_PORTS = ["", ":8080", ":443"]
_PATHS = ["", "/", "/path", "/p?q=1#f", "/@notahost", "/a?u=x@y.z"]


def _urls():
    for s, u, h, p, path in itertools.product(
            _SCHEMES, _USERINFO, _HOSTS, _PORTS, _PATHS):
        yield f"{s}://{u}{h}{p}{path}"


def _transport_host(url: str):
    """The host the REAL consumer resolves, as a policy key, or None.

    `raw_host` rather than `host` because the A-label is what goes on the wire.
    The trailing root dot is normalised away on BOTH sides here — the sensor
    strips it deliberately, and that divergence is pinned on its own in
    `test_trailing_root_dot_is_one_policy_key` rather than hidden in here.
    """
    if httpx is not None:
        try:
            return httpx.URL(url).raw_host.decode("ascii").lower().rstrip(".")
        except Exception:
            return None
    from urllib.parse import urlsplit
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.lower().rstrip(".")
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except Exception:
            pass
    return host


def _client():
    return ProtectedHttpClient.__new__(ProtectedHttpClient)


def test_extracted_host_equals_the_host_the_transport_resolves():
    """THE DIFFERENTIAL. No expected-value list: the oracle is httpx."""
    client = _client()
    compared, mismatches = 0, []
    for url in _urls():
        expected = _transport_host(url)
        if expected is None:
            continue                      # the transport refuses it too
        compared += 1
        got = (client._extract_host(url) or "").rstrip(".")
        if got != expected:
            mismatches.append((url, got, expected))
    assert not mismatches, (
        f"{len(mismatches)} of {compared} URLs resolve to a different host in "
        f"the sensor than in the transport — a deny-destination rule naming "
        f"the transport's host will not match the sensor's. First five: "
        + "; ".join(f"{u!r} sensor={g!r} transport={e!r}"
                    for u, g, e in mismatches[:5])
    )


def test_url_differential_is_not_vacuous():
    assert sum(1 for u in _urls() if _transport_host(u) is not None) >= 500


# ── the three cases that need a STATED answer, pinned individually ──────────

def test_userinfo_is_not_part_of_the_host():
    c = _client()
    assert c._extract_host("https://user@blocked.invalid/path") == "blocked.invalid"
    assert c._extract_host("https://user:pw@evil.com:443/") == "evil.com"
    assert c._extract_host("https://a@b@blocked.invalid/") == "blocked.invalid"


def test_trailing_root_dot_is_one_policy_key():
    """`evil.com.` and `evil.com` are the same DNS name, so one policy key.

    The sensor deliberately goes one step further than the transport here:
    httpx keeps the dot on the wire, and keeping it in a policy key would make
    the root anchor a one-character bypass.
    """
    c = _client()
    assert c._extract_host("https://evil.com./p") == "evil.com"
    assert c._extract_host("https://evil.com/p") == "evil.com"


def test_ipv6_resolves_to_the_address_without_brackets_or_port():
    c = _client()
    assert c._extract_host("https://[::1]:8080/x") == "::1"
    assert c._extract_host("https://[2001:DB8::1]/x") == "2001:db8::1"
    # A malformed literal is refused, not truncated to a fragment.
    assert c._extract_host("https://[::1") is None


def test_idna_resolves_to_the_a_label_and_keeps_the_u_label_as_a_candidate():
    c = _client()
    assert c._extract_host("https://exämple.com/p") == "xn--exmple-cua.com"
    assert c._host_candidates("https://exämple.com/p") == [
        "xn--exmple-cua.com", "exämple.com"]
    # An ASCII host has exactly one spelling and must not produce two keys.
    assert c._host_candidates("https://evil.com/p") == ["evil.com"]


# ── the consequence the differential exists to prevent ──────────────────────

@pytest.mark.skipif(httpx is None, reason="needs the http extra")
@pytest.mark.parametrize("url", [
    "http://user@blocked.invalid/path",
    "http://user:pw@blocked.invalid/path",
    "http://blocked.invalid./path",
    "http://BLOCKED.INVALID/path",
])
def test_a_deny_destination_policy_blocks_every_spelling_of_its_host(url):
    """The end of the chain: a host the parser gets wrong is a block that does
    not happen. `blocked.invalid` is denied by policy; none of these reach the
    transport."""
    from xaidr.types import DelphiBlockedError

    sent = []

    def handler(request):
        sent.append(str(request.url))
        return httpx.Response(200, json={"ok": True})

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = DelphiSensor(agent_id="diff", enforcement_mode="block")
    s.set_policy({
        "version": "1", "defaults": {"effect": "allow"},
        "rules": [{"id": "deny", "effect": "block",
                   "match": {"destination_identifier": ["blocked.invalid"]}}],
    })
    c = s.protect_http(httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(DelphiBlockedError):
        c.get(url)
    assert sent == [], f"{url} reached the transport despite a deny rule"


# ── the SAME differential, through the S10 extension destination policy ─────
#
# WHY THIS SECTION EXISTS. Nothing above it reaches the extension seam. The
# 2160-URL loop calls `_extract_host` directly on a bare
# `ProtectedHttpClient.__new__` — no sensor, no extensions, and it never enters
# `_check_destination` at all. The four operator-policy cases above DO enter
# `_check_destination`, but the S10 branch is guarded by
# `if self._sensor._extensions:` and they attach none, so across this entire
# file `DestinationView` was constructed ZERO times (measured, not assumed).
#
# That guard is the gap. `DestinationView.host` is built from `_extract_host`,
# so an authority-reading parser hands an enterprise control
# `user:pw@blocked.invalid` as "the host" — and a control keyed on its own host
# then DECLINES, silently, and the operator blocklist below it never sees a
# reason to fire either. S10 shipped against the regex version and its own test
# file uses only bare hosts, so the userinfo × extension-policy combination had
# no coverage on either side of the merge.
_S10_USERINFO_URLS = [
    "http://user@blocked.invalid/path",
    "http://user:pw@blocked.invalid/path",
    "http://svc%40corp@blocked.invalid/p?q=1",
    "http://a@b@blocked.invalid/",
    "http://user@BLOCKED.INVALID./path",
    "http://user@sub.blocked.invalid/path",
    "http://user:pw@[::1]:8080/x",
    "http://user@exämple.com/p",
]

#: The subset whose transport host is EXACTLY `blocked.invalid`, i.e. the ones a
#: control keyed on that host must stop. Derived from the oracle rather than
#: hand-listed, so a new case above cannot quietly skip the blocking half.
_S10_BLOCKED_HOST_URLS = [
    u for u in _S10_USERINFO_URLS if _transport_host(u) == "blocked.invalid"
]


def _capturing_extension(captured, block_host=None):
    """An extension that records the view it is handed, and optionally blocks.

    It RECORDS rather than asserts: a fault raised inside `destination_policy`
    is caught by `_extension_failed` and the scan proceeds, so an assertion in
    here would be swallowed and the test would pass by never checking anything.
    """
    from xaidr import SensorExtension
    from xaidr.types import ScanResult

    class _Capture(SensorExtension):
        name = "host-differential"

        def destination_policy(self, dest):
            captured.append(dest)
            if block_host is not None and dest.host == block_host:
                return ScanResult(action="blocked", score=1.0,
                                  category="ext_destination",
                                  rules=["EXT_DEST_BLOCKED"])
            return None

    return _Capture()


@pytest.mark.skipif(httpx is None, reason="needs the http extra")
@pytest.mark.parametrize("url", _S10_USERINFO_URLS)
def test_the_view_handed_to_an_extension_carries_the_transport_host(url):
    """THE DIFFERENTIAL, through S10. The oracle is still httpx."""
    from xaidr.extensions import DestinationView

    captured = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = DelphiSensor(agent_id="diff-s10", enforcement_mode="block",
                         extensions=[_capturing_extension(captured)])
    client = s.protect_http(
        httpx.Client(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"ok": True}))))
    client.get(url)

    assert captured, (
        f"destination_policy was never consulted for {url!r} — the S10 branch "
        f"did not run, so this case proves nothing about it"
    )
    view = captured[0]
    assert isinstance(view, DestinationView)
    expected = _transport_host(url)
    got = (view.host or "").rstrip(".")
    assert got == expected, (
        f"the extension was handed host={view.host!r} for {url!r} but the "
        f"transport resolves {expected!r} — an enterprise destination control "
        f"keyed on its own host declines, and the operator blocklist below it "
        f"never fires either"
    )
    assert "@" not in (view.host or ""), (
        f"host={view.host!r} still carries userinfo: the view is being built "
        f"from the AUTHORITY, which is attacker-chosen"
    )
    assert "@" not in (view.dest_id or ""), (
        f"dest_id={view.dest_id!r} carries userinfo, so the telemetry record "
        f"and the block message both name a host nothing was sent to"
    )


@pytest.mark.skipif(httpx is None, reason="needs the http extra")
@pytest.mark.parametrize("url", _S10_BLOCKED_HOST_URLS)
def test_an_extension_destination_policy_blocks_through_userinfo(url):
    """The consequence: the control fires, and nothing reaches the transport."""
    from xaidr.types import DelphiBlockedError

    sent, captured = [], []

    def handler(request):
        sent.append(str(request.url))
        return httpx.Response(200, json={"ok": True})

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = DelphiSensor(
            agent_id="diff-s10", enforcement_mode="block",
            extensions=[_capturing_extension(
                captured, block_host="blocked.invalid")])
    client = s.protect_http(httpx.Client(transport=httpx.MockTransport(handler)))

    with pytest.raises(DelphiBlockedError):
        client.get(url)
    assert captured, "the hook was never consulted"
    assert sent == [], (
        f"{url} reached the transport despite an extension destination policy "
        f"naming its host"
    )


def test_s10_differential_is_not_vacuous():
    """Each case must carry userinfo AND be a URL the transport accepts.

    Both halves have failed silently before: a case list the transport refuses
    is skipped by `_transport_host(...) is None`, and a case without userinfo
    passes against the authority-reading parser too, which is the whole point
    of the section.
    """
    assert len(_S10_USERINFO_URLS) >= 8
    for url in _S10_USERINFO_URLS:
        authority = url.split("://", 1)[1].split("/", 1)[0]
        assert "@" in authority, f"{url} exercises no userinfo"
        assert _transport_host(url) is not None, f"{url} is refused by httpx"
    assert len(_S10_BLOCKED_HOST_URLS) >= 4, (
        f"the blocking half runs on {_S10_BLOCKED_HOST_URLS} — a subset the "
        f"oracle narrowed to nothing would parametrize zero cases and pass"
    )


# ═══════════════════════════════════════════════════════════════════════════
# 2. SQL PREDICATE BOUNDEDNESS  vs  a real SQLite row count
# ═══════════════════════════════════════════════════════════════════════════

_ROWS = 5


def _rows_touched(stmt: str):
    """Rows the statement ACTUALLY touches, or None if SQLite rejects it."""
    con = sqlite3.connect(":memory:")
    try:
        con.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, note TEXT, "
                    "deleted INTEGER DEFAULT 0, hits INTEGER DEFAULT 0)")
        for i in range(1, _ROWS + 1):
            con.execute("INSERT INTO records (id, note, deleted) VALUES (?,?,?)",
                        (i, f"n{i}", 1 if i == 1 else 0))
        con.commit()
        try:
            n = con.execute(stmt).rowcount
        except sqlite3.Error:
            return None
        con.rollback()
        return n
    finally:
        con.close()


def _predicate_of(stmt: str):
    shapes = parse_sql(stmt)
    return shapes[0].predicate if shapes else None


#: Constant predicates, generated rather than enumerated: every one of these is
#: decided without reading a row, so NONE of them may be reported bounded. The
#: six named in the finding are members of this set, not the whole of it.
_CONSTANT_PREDICATES = [
    "1=1", "(1=1)", "((1=1))", "2>1", "1<>0", "1!=0", "NOT FALSE", "NOT 1=0",
    "TRUE", "1", "'a'='a'", "coalesce(1,0)=1", "length('ab')=2",
    "1 BETWEEN 0 AND 2", "1 IN (1,2)", "'a' IN ('a','b')", "1 IS NOT NULL",
    "'x' LIKE 'x'", "1+1=2", "(2>1) AND (3>2)", "1=1 OR 1=0",
    "CASE WHEN 1 THEN 1 ELSE 0 END", "abs(-1)=1", "2 IS NOT 1",
    "id=id", "records.id = records.id",
]

#: Predicates whose truth depends on the ROW. SQLite decides how many rows each
#: one touches; the assertion below only forbids calling an ALL-ROWS statement
#: bounded, so these are here to prove the fix did not simply answer "unknown"
#: to everything.
_ROW_DEPENDENT_PREDICATES = [
    "id=7", "id=1", "id IN (1,2)", "id=7 AND 1=1", "note='1=1'", "deleted=1",
    "NOT deleted", "id BETWEEN 1 AND 2", "lower(note)='n1'",
    "id < 3 AND note IS NOT NULL", "id=1 OR id=2", "note LIKE 'n1%'",
    "id = (SELECT max(id) FROM records)", "id <> 1 AND deleted = 0",
    "id IN (SELECT id FROM records WHERE id=2)",
]

_VERBS = ["DELETE FROM records WHERE {p}", "UPDATE records SET hits = 1 WHERE {p}"]


def _sql_cases():
    for tmpl in _VERBS:
        for p in _CONSTANT_PREDICATES + _ROW_DEPENDENT_PREDICATES:
            yield tmpl.format(p=p)


def test_a_statement_that_touches_every_row_is_never_reported_bounded():
    """THE DIFFERENTIAL. The expectation is SQLite's row count, not a list."""
    compared, wrong = 0, []
    for stmt in _sql_cases():
        n = _rows_touched(stmt)
        if n is None:
            continue                      # not valid in this dialect
        compared += 1
        pred = _predicate_of(stmt)
        if n >= _ROWS and pred == "bounded":
            wrong.append((stmt, n))
    assert not wrong, (
        f"{len(wrong)} of {compared} statements touched all {_ROWS} rows while "
        f"the parser called the predicate BOUNDED — every one is an unbounded "
        f"mutation that no rule will classify: "
        + "; ".join(repr(s) for s, _ in wrong[:6])
    )


def test_a_bounded_statement_is_not_reported_unknown():
    """The other direction. Failing closed is only honest if it is SELECTIVE:
    a parser that answers `unknown` to everything would pass the test above and
    classify every routine write as an unbounded mutation."""
    compared, wrong = 0, []
    for p in _ROW_DEPENDENT_PREDICATES:
        stmt = f"DELETE FROM records WHERE {p}"
        n = _rows_touched(stmt)
        if n is None or n >= _ROWS:
            continue
        compared += 1
        if _predicate_of(stmt) != "bounded":
            wrong.append((stmt, n, _predicate_of(stmt)))
    assert compared >= 12
    assert not wrong, (
        "predicates SQLite proved bounded were not reported bounded — every one "
        "is a routine write newly classified as a critical unbounded mutation: "
        + "; ".join(f"{s!r} touched {n} rows, parser said {p!r}"
                    for s, n, p in wrong)
    )


def test_sql_differential_is_not_vacuous():
    runnable = sum(1 for s in _sql_cases() if _rows_touched(s) is not None)
    assert runnable >= 60, f"only {runnable} statements reached SQLite"


#: KNOWN RESIDUAL, kept as a failing test rather than as a paragraph.
#: These reference a column — so their truth DOES depend on the row and the
#: closed lexical test says "bounded" — and are nonetheless true of every row.
#: Separating them needs EVALUATION against the data, which is a database's job.
#: `strict=True` so that closing the gap fails this test and forces the list to
#: shrink rather than rot.
@pytest.mark.xfail(strict=True, reason=(
    "column-referencing always-true predicates need evaluation, not parsing; "
    "named residual of the F2 fix"))
@pytest.mark.parametrize("pred", [
    "id IS NOT NULL OR id IS NULL",
    "id > -1",
    "note LIKE '%'",
    "id IN (SELECT id FROM records)",
])
def test_residual_column_referencing_tautologies(pred):
    stmt = f"DELETE FROM records WHERE {pred}"
    assert _rows_touched(stmt) == _ROWS
    assert _predicate_of(stmt) != "bounded"


# ═══════════════════════════════════════════════════════════════════════════
# 3. SHELL CLASSIFICATION  vs  the real POSIX lexer
# ═══════════════════════════════════════════════════════════════════════════

_OPS = {"|", "||", "&&", ";", "&", "\n", ";;", "|&"}
_REDIR = {">", ">>", "<", "<<", "<<<", ">&", "<&", "&>", "&>>", ">|"}


def _basename(word: str) -> str:
    b = os.path.basename(word.replace("\\", "/")).lower()
    return b[:-4] if b.endswith(".exe") else b


def _oracle_binaries(cmd: str):
    """Command-position words per top-level segment, per `shlex`.

    shlex does the two hard parts — quote removal (`r''m` -> `rm`) and operator
    splitting — and what is layered on top is mechanical: a segment's command
    word is its first token that is neither a `VAR=value` assignment nor a
    redirection.
    """
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    tokens = list(lex)                    # raises ValueError on unbalanced quotes

    out, segment = [], []
    for tok in tokens + [";"]:
        if tok in _OPS:
            i = 0
            while i < len(segment):
                word = segment[i]
                if word in _REDIR:
                    i += 2
                    continue
                head = word.split("=", 1)[0]
                if ("=" in word and head and not word.startswith("=")
                        and all(c.isalnum() or c == "_" for c in head)):
                    i += 1
                    continue
                break
            if i < len(segment):
                out.append(_basename(segment[i]))
            segment = []
        else:
            segment.append(tok)
    return out


def _scanner_binaries(parsed):
    """What the scanner puts at each top-level command position.

    A wrapper the scanner stripped (`sudo`, `env`) was the command word the
    shell saw, so the comparison is against the head of the wrapper chain, not
    against the binary behind it.
    """
    out = []
    for seg in parsed:
        if seg.depth:
            continue                      # inside an interpreter payload; the
            # scanner deliberately reads deeper than a top-level shell parse
        chain = (seg.wrappers or []) + ([seg.name] if seg.name else [])
        if chain:
            out.append(_basename(chain[0]))
    return out


def _shell_corpus():
    import json
    path = os.path.join(os.path.dirname(__file__), "fixtures", "shell_corpus.json")
    with open(path, encoding="utf-8") as fh:
        corpus = json.load(fh)
    return ([e["command"] for e in corpus["attacks"]]
            + [e["command"] for e in corpus["benign"]])


def _comparable_shell_cases():
    """Corpus commands where shlex is an authority, with the scanner's parse.

    Two exclusions, both taken from the SCANNER'S OWN declared limits rather
    than chosen to make the numbers work:
      * `expands` — the segment contains `$(...)`, `$VAR` or backticks. Neither
        parser resolves expansion, so neither is an oracle for the other.
      * `parse_degraded` — the scanner already says it fell back.
    A command shlex itself refuses (unbalanced quotes) is excluded for the
    matching reason: there is no oracle reading.
    """
    for cmd in _shell_corpus():
        parsed = parse_command(cmd)
        if any(s.expands or s.parse_degraded for s in parsed):
            continue
        try:
            yield cmd, _oracle_binaries(cmd), _scanner_binaries(parsed)
        except ValueError:
            continue


def test_scanner_agrees_with_the_real_lexer_about_what_ran():
    """THE DIFFERENTIAL. Every classification the shell path makes keys on the
    binary at a command position; if that disagrees with the lexer, the class
    is about a command nobody ran."""
    mismatches = [(c, o, s) for c, o, s in _comparable_shell_cases() if o != s]
    assert not mismatches, (
        f"{len(mismatches)} corpus commands parse to different command-position "
        f"binaries in the scanner than in shlex — the impact class named for "
        f"each is about a different command: "
        + "; ".join(f"{c!r} lexer={o} scanner={s}" for c, o, s in mismatches[:5])
    )


def test_shell_differential_is_not_vacuous():
    """The exclusions above are the scanner's own flags, so a bug that set
    `expands` everywhere would empty this comparison and leave it green."""
    compared = sum(1 for _ in _comparable_shell_cases())
    total = len(_shell_corpus())
    assert compared >= 300, (
        f"only {compared} of {total} corpus commands were compared; the "
        f"differential is measuring almost nothing")
