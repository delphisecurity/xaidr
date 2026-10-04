"""THE MULTI-ORACLE DIFFERENTIAL: every host a real consumer reads, the core reads.

Companion to ``tests/test_differential_parsers.py`` (the standing gate). That
file compares one parser with one transport. This one exists because the
transports DISAGREE WITH EACH OTHER, which makes "agree with the transport" a
question with no single answer (ARCHITECTURE.md F2):

                                         ada (WHATWG)   urllib3        httpx        urllib.parse
    https://corp.example\\@evil.test/x    corp.example   corp.example   evil.test    evil.test

So the rule here is a SUPERSET rule (Q2, decided 2026-10-03). For every
spelling and every oracle, the host that oracle reads must be among the hosts
the core's argument walk reads. An under-read is a host a real HTTP client
sends to and value origin never looks at; under ENFORCE that is a bypass. It
was one: before Q1 the core read only `corp.example` above, so a call httpx
sends to an UNTRUSTED `evil.test` came back AUTHORIZED (finding 1, the
1.15.0 userinfo-bypass shape in new code).

The corpus is SPELLINGS x ORACLES, generated, never a list of expected answers.
Each oracle's host is put through the core's own host normaliser
(`_host_authority`: percent-decode, UTS-46, every IP literal form, PSL), so the
question asked is only "which substring is the host", the one the parsers
disagree about. Normalisation itself is pinned by the conformance suite.

A host no resolver can look up — one carrying a backslash, a space, an `@` —
is not a place any consumer can send to, so it is not compared (`_NAME`).

THE ORACLES ARE REQUIRED. Missing one REFUSES; it never skips (Q3). A skipped
oracle is a silent pass, and an absent oracle is exactly how the first
differential here missed finding 1: it had urllib.parse and nothing else. The
`base` CI config, which installs no third-party package by design, deselects
this module explicitly with ``-m "not requires_dev_extra"``; every config that
installs the dev extra runs it.
"""
from __future__ import annotations

import collections
import itertools
import re

import pytest

pytestmark = pytest.mark.requires_dev_extra


def _oracles():
    """name -> callable(url) -> host or None, and the names that are missing."""
    out, missing = {}, []
    from urllib.parse import urlsplit

    def o_urllib(u):
        try:
            return urlsplit(u).hostname or None
        except Exception:
            return None
    out["urllib.parse"] = o_urllib
    try:
        import httpx
    except ImportError:
        missing.append("httpx")
    else:
        def o_httpx(u):
            try:
                return httpx.URL(u).host or None
            except Exception:
                return None
        out["httpx"] = o_httpx
    try:
        import urllib3.util
    except ImportError:
        missing.append("urllib3")
    else:
        def o_urllib3(u):
            try:
                return urllib3.util.parse_url(u).host or None
            except Exception:
                return None
        out["urllib3"] = o_urllib3
    try:
        import ada_url
    except ImportError:
        missing.append("ada-url")
    else:
        def o_ada(u):
            try:
                return ada_url.URL(u).hostname or None
            except Exception:
                return None
        out["ada-url (WHATWG)"] = o_ada
    return out, missing


@pytest.fixture(scope="module")
def oracles():
    found, missing = _oracles()
    if missing:
        pytest.fail(
            f"REFUSING: oracle(s) {missing} are not installed, so this differential "
            "cannot compare the core with every consumer it claims to cover. Install "
            "the dev extra (pip install '.[dev]'). This is a refusal, not a skip: a "
            "skipped oracle is how finding 1 went unseen.", pytrace=False)
    return found


# ── the corpus: spellings x oracles ─────────────────────────────────────────
_SCHEMES = ("http", "https", "HTTP", "wss", "ftp", "gopher")
_SEPARATORS = ("://", ":", ":/", ":\\", ":///", ":\\\\")
_PREFIXES = ("", "user@", "user:pw@", "x@corp.example@", "corp.example\\@",
             "corp.example\\\\@", "corp.example%5C@", "corp.example/@", "corp.example?@",
             "corp.example#@", "\\@", "[::1]\\@", "corp.example:80\\@", "corp.example\\x@",
             # urlsplit REFUSES these (a bare ']' in userinfo) where httpx, urllib3
             # and WHATWG read the host after '@' — the WPT adversarial run's
             # `http://&a:foo(b]c@d:2/` (2026-10-03).
             "&a:foo(b]c@", "corp.example]@", "a]b:pw@")
_HOSTS = ("evil.test", "EVIL.TEST", "sub.evil.test.", "169.254.169.254", "0xA9FEA9FE",
          "[::ffff:169.254.169.254]", "ev%69l.test", "éxample.test", "169．254．169．254",
          # a '[' that does not open the host (silent-failure review, M0)
          "ev[il].test", "[evil.test]")
_TAILS = ("", "/x", ":8080/x", "\\x", "?q=@corp.example", "#@corp.example", "/@corp.example")

# What a resolver can look up: LDH labels (underscore tolerated, as resolvers
# do) after the core's IDNA step, or an IP literal. Anything else is not a host
# any consumer reaches.
_NAME = re.compile(r"^[a-z0-9._-]+$")


def _spellings():
    for s, sep, p, h, t in itertools.product(_SCHEMES, _SEPARATORS, _PREFIXES, _HOSTS, _TAILS):
        yield f"{s}{sep}{p}{h}{t}"


def _reachable_key(host):
    from xaidr.value_origin._authority import _host_authority
    a = _host_authority(host, arg_fallback=True)
    if a is None:
        return None
    if a.scheme == "dns" and not _NAME.match(a.value):
        return None
    return a.key()


def _core_keys(url):
    from xaidr.value_origin import extract_destinations
    found, _ = extract_destinations({"url": url})
    return {f.destination.key() for f in found if f.destination is not None}


def _urlsplit_refuses_a_bracketed_host(url):
    from urllib.parse import urlsplit
    if "]" not in url:
        return False
    try:
        urlsplit(url)
    except ValueError:
        return True
    return False


# Over-reads: a host the core reads that NO oracle in THIS process reads.
# Allowed only in a named class whose reason is TRUE; a new shape is red (§2.3
# rule 2). The core's RFC 3986 reading is exactly CPython 3.12.2's
# urlsplit().hostname, the most permissive version measured. Later patch
# releases refuse some of what it reads, and in THIS process only those
# spellings can be over-reads. The class is pinned both ways by
# test_the_named_over_read_class_stands_for_a_measured_interpreter.
_OVER_READ_CLASSES = {
    "urlsplit-bracket-validation": (
        _urlsplit_refuses_a_bracketed_host,
        "CPython 3.12.2's urllib.parse reads these hosts, and the bracketed-host "
        "validation backported to later patch releases (measured: 3.10.21, "
        "3.12.14) refuses them. urllib.parse is a covered consumer, and xaidr's "
        "own ProtectedHttpClient._extract_host decides destination policy with it. "
        "urllib.request does NOT send there: it passes the netloc on, percent-decoded "
        "and userinfo included, as one host string."),
}


def _urlsplit_reads_like_3_12_2():
    """True on an interpreter whose urlsplit predates the bracketed-host
    backport (CPython 3.12.2 behaves this way; 3.10.21 and 3.12.14 do not)."""
    from urllib.parse import urlsplit
    try:
        return urlsplit("http://[::1]\\@evil.test/").hostname == "evil.test"
    except ValueError:
        return False


@pytest.fixture(scope="module")
def comparison(oracles):
    under, over = [], collections.defaultdict(list)
    per_oracle = collections.Counter()
    keys, n = set(), 0
    for url in _spellings():
        n += 1
        core = _core_keys(url)
        read = set()
        for name, fn in oracles.items():
            host = fn(url)
            if not host:
                continue
            k = _reachable_key(host)
            if k is None:
                continue
            per_oracle[name] += 1
            read.add(k)
            keys.add(k)
            if k not in core:
                under.append((url, name, k, sorted(core)))
        for k in sorted(core - read):
            cls = next((c for c, (pred, _) in _OVER_READ_CLASSES.items() if pred(url)), None)
            over[cls].append((url, k))
    return {"n": n, "under": under, "over": over, "per_oracle": per_oracle, "keys": keys}


def test_the_differential_is_not_vacuous(oracles, comparison):
    """A gate that compares nothing passes. Every oracle must actually have
    read hosts, and the readings must reach the hosts this exists for."""
    assert comparison["n"] >= 30_000, comparison["n"]
    assert set(comparison["per_oracle"]) == set(oracles), comparison["per_oracle"]
    assert min(comparison["per_oracle"].values()) >= 3_000, comparison["per_oracle"]
    assert {"dns:evil.test", "dns:corp.example", "ip:169.254.169.254"} <= comparison["keys"]


def test_core_reads_every_host_any_consumer_reads(comparison):
    """THE DIFFERENTIAL (Q1, Q2). No under-read: a host any covered consumer
    sends to is a host the core's argument walk names."""
    under = comparison["under"]
    by = collections.Counter(name for _, name, _, _ in under)
    assert not under, (
        f"{len(under)} readings name a host the core never reads ({dict(by)}): a call "
        "the transport sends there is invisible to value origin, and under ENFORCE an "
        "untrusted host walks through. First five: "
        + "; ".join(f"{u!r} {name} reads {k}, core reads {c}"
                    for u, name, k, c in under[:5]))


def test_core_over_reads_only_in_named_classes(comparison):
    """An over-read (a host no consumer reads) is allowed only in a named class
    with a stated reason; a new shape of over-read is red, not silently
    absorbed."""
    stray = comparison["over"].get(None, [])
    assert not stray, (
        f"{len(stray)} over-reads in no named class, e.g. {stray[:5]}. Name the class "
        "and its reason in _OVER_READ_CLASSES, or fix the core.")


def test_the_named_over_read_class_stands_for_a_measured_interpreter(comparison):
    """The class's reason is a claim about a real consumer, so it is checked
    both ways. On an interpreter whose urlsplit reads like 3.12.2, the class
    must absorb NOTHING: urllib.parse there reads every one of those hosts. On a
    post-backport interpreter it must be needed. An allowance that never fires
    there would be dead weight hiding nothing, and is red too."""
    absorbed = comparison["over"].get("urlsplit-bracket-validation", [])
    if _urlsplit_reads_like_3_12_2():
        assert not absorbed, (
            f"{len(absorbed)} over-reads were absorbed on an interpreter whose "
            "urllib.parse should READ them, so the class's reason is false here: "
            f"{absorbed[:5]}")
    else:
        assert absorbed, ("the urlsplit-bracket-validation class absorbed nothing on "
                          "a post-backport interpreter; delete it rather than keep "
                          "an allowance that hides nothing")


# ═══════════════════════════════════════════════════════════════════════════
# url_parse: the ADDRESS CLASS every consumer reaches (A2 M2, ARCHITECTURE.md §2.4)
# ═══════════════════════════════════════════════════════════════════════════
#
# `url_parse` decides detection on the tool-call path: `classify()`, the
# `danger` findings that move an action, `bound_faults`, and whether a
# scheme-less value is a URL at all (§2.1). Its load-bearing output is
# `address`, and `link_local` is the class that BLOCKS. So the question here is
# not "which host" but "which address class", asked of every consumer:
#
#   each oracle's host is handed to the platform resolver exactly as a Python
#   HTTP client hands it over — `socket.getaddrinfo(str, AI_NUMERICHOST)`,
#   which applies Python's IDNA codec and then libc's numeric parse, and makes
#   no network call — and classified by the address it reaches; a host the
#   resolver does not read as an address is a NAME (class None).
#
# Superset rule (Q2), for a single-valued field: `address` must be at least as
# severe as the most severe class any consumer reaches. Severity is a total
# order, so an equal rank means an equal class.
#
# The resolver is per-platform (F9). Its one divergence — BSD libc reading a
# leading-zero dotted quad as DECIMAL — is Q22's single named exemption,
# asserted present on darwin and empty on Linux, never skipped.

import ipaddress
import socket
import sys

_ADDRESS_ORDER = (None, "public", "private", "loopback", "link_local")


def _rank(cls):
    return _ADDRESS_ORDER.index(cls)


def _kind(ip):
    """The class of an address, in url_parse's own check order. Written out
    here, not imported, so the oracle does not reuse the code under test."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_link_local:
        return "link_local"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    return "public"


_RESOLVED = {}


def _resolve(host):
    """The address the platform resolver reads ``host`` as, or None (a name).
    ``gaierror`` is the resolver saying "not a numeric host", which is the
    answer, not a fault. UnicodeError is Python's IDNA codec refusing the label
    before libc sees it: nothing is sent, so it is a name too."""
    if host in _RESOLVED:
        return _RESOLVED[host]
    h = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        info = socket.getaddrinfo(h, None, flags=socket.AI_NUMERICHOST)
        ip = ipaddress.ip_address(info[0][4][0].split("%")[0])
    except (OSError, UnicodeError, ValueError):
        ip = None
    _RESOLVED[host] = ip
    return ip


def _bsd_decimal_leading_zero(host, ip):
    """Q22's one exemption, exactly: a 4-part dotted quad of ASCII digits with
    at least one leading-zero part, which the resolver read as DECIMAL
    (macOS: 0251.254.0251.254 -> 251.254.251.254). glibc, WHATWG, inet_aton
    and the core read the leading zero as octal."""
    parts = host.split(".")
    if ip is None or len(parts) != 4 or not all(p.isascii() and p.isdigit() for p in parts):
        return False
    # a leading-zero part whose octal reading differs from its decimal one; where
    # they agree (`10.01.10.01`) the resolver read nothing differently
    if not any(len(p) > 1 and p.startswith("0")
               and (not set(p) <= set("01234567") or int(p, 8) != int(p, 10))
               for p in parts):
        return False
    vals = [int(p, 10) for p in parts]
    return all(v <= 255 for v in vals) and ip == ipaddress.ip_address(".".join(map(str, vals)))


def _url_parse_address(url):
    from xaidr.scanner.url_parse import parse_url
    shape = parse_url(url)
    return shape.address if shape else None


# The grid: the §2.2 measurement's axes (url_diff.py, 3,888 spellings) widened
# with M0's split-disagreement prefixes, the mirror tail `\@corp.example`, the
# hosts M3's deltas name, and the standing gate's `_urls()` userinfo and IPv6
# forms.
_UP_SCHEMES = ("http://", "https://", "HTTP://", "wss://", "ftp://", "gopher://",
               "http:", "http:/", "http:\\\\", "http:///")
_UP_PREFIXES = ("", "user@", "user:pw@", "svc%40corp@", "a@b@", "x@corp.example@",
                "corp.example\\@", "corp.example%5C@", "\\@", "[::1]\\@", "&a:foo(b]c@",
                "corp.example:80\\@")
_UP_HOSTS = ("169.254.169.254", "0xA9FEA9FE", "2852039166", "0251.0376.0251.0376",
             "169.254.43518", "0251.254.0251.254", "[::ffff:169.254.169.254]",
             "[::ffff:a9fe:a9fe]", "%31%36%39.254.169.254", "１６９.２５４.１６９.２５４",
             "169．254．169．254", "169.254.169.254.", "١٦٩.٢٥٤.١٦٩.٢٥٤", "1.2.3.256",
             "1.2.65536", "0x.0x.0", "10.0.0.5", "127.1", "0x7f.1", "[::1]",
             "[2001:db8::1]", "8.8.8.8", "evil.test", "ev%69l.test", "EVIL.test", "corp.example")
_UP_TAILS = ("", "/latest", ":80/x", "?q", "#f", "\\x", "\\@corp.example", "/@corp.example")


def _url_parse_spellings():
    for s, p, h, t in itertools.product(_UP_SCHEMES, _UP_PREFIXES, _UP_HOSTS, _UP_TAILS):
        yield f"{s}{p}{h}{t}"


# The under-read classes url_parse had before M3, by class. Each class is a
# property of the spelling, never a list of spellings, so a regenerated grid
# cannot hide one; first match wins, in this order (urlsplit-refusal before
# backslash since the M2 silent-failure review: a refused spelling that also
# carries a backslash was being counted as a backslash defect). They were strict
# xfails at M2 (f95f5df); M3 moved url_parse onto the core's readings and host
# pipeline, and every bucket, `unclassified` included, must now be empty. The
# classes stay as labels, so a regression names its mechanism.
def _urlsplit_raises(u):
    from urllib.parse import urlsplit
    try:
        urlsplit(u)
    except ValueError:
        return True
    return False


def _special_without_slashes(u):
    return re.match(r"(?i)(https?|wss?|ftp):(?!//[^/])", u) is not None


_UP_UNDER_READ_CLASSES = (
    ("special-scheme-without-//",
     _special_without_slashes,
     "R4: WHATWG (ada) takes the authority after any run of / and \\; urlsplit finds none"),
    ("urlsplit-refusal",
     lambda u: _urlsplit_raises(u),
     "this interpreter's urlsplit raises, url_parse returns None, and httpx, urllib3 "
     "and WHATWG send the request anyway (M0's WPT sibling, `http://&a:foo(b]c@d:2/`)"),
    ("backslash",
     lambda u: "\\" in u,
     "F1's shape for url_parse: WHATWG and urllib3 read a backslash as a slash"),
    ("fullwidth",
     lambda u: any(0xFF00 <= ord(c) <= 0xFFEF for c in u),
     "F3: httpx IDNA-maps U+FF0E, and Python's IDNA codec maps it for the resolver"),
    ("percent-encoded-host",
     lambda u: re.search(r"//[^/?#]*%3[0-9]", u) is not None,
     "F3: urllib3 and WHATWG percent-decode the host"),
    ("empty-hex-part",
     lambda u: re.search(r"(?i)(^|[/@.])0x(\.|[/:?#\\]|$)", u) is not None,
     "WHATWG reads an empty hex part as 0 (and the macOS resolver does)"),
)


def _under_read_class(url):
    return next((name for name, pred, _ in _UP_UNDER_READ_CLASSES if pred(url)), "unclassified")


@pytest.fixture(scope="module")
def url_parse_comparison(oracles):
    under, over = collections.defaultdict(list), collections.defaultdict(list)
    per_oracle, reached = collections.Counter(), collections.Counter()
    n = 0
    for url in _url_parse_spellings():
        n += 1
        readings, hosts = {}, {}
        for name, fn in oracles.items():
            host = fn(url)
            if not host:
                continue
            ip = _resolve(host)
            readings[name] = _kind(ip) if ip is not None else None
            hosts[name] = (host, ip)
            per_oracle[name] += 1
        want = max(readings.values(), key=_rank, default=None)
        reached[want] += 1
        got = _url_parse_address(url)
        if _rank(want) > _rank(got):
            who = sorted(name for name, c in readings.items() if c == want)
            under[_under_read_class(url)].append((url, got, want, who))
        elif _rank(got) > _rank(want):
            # the mechanism-specific classes first; M0's bracket predicate is
            # true of ANY `]` that urlsplit refuses, so it goes last
            cls = next((c for c, (pred, _) in _UP_OVER_READ_CLASSES.items()
                        if pred(hosts)), None)
            if cls is None and _urlsplit_refuses_a_bracketed_host(url):
                cls = "urlsplit-bracket-validation"      # M0's class, same reason
            over[cls].append((url, got, readings))
    return {"n": n, "under": under, "over": over, "per_oracle": per_oracle,
            "reached": reached}


def test_the_url_parse_differential_is_not_vacuous(oracles, url_parse_comparison):
    c = url_parse_comparison
    assert c["n"] >= 20_000, c["n"]
    assert set(c["per_oracle"]) == set(oracles), c["per_oracle"]
    assert min(c["per_oracle"].values()) >= 5_000, c["per_oracle"]
    # the readings reach every class, and link-local (the class that blocks) a lot
    assert set(c["reached"]) == set(_ADDRESS_ORDER), c["reached"]
    assert c["reached"]["link_local"] >= 3_000, c["reached"]


@pytest.mark.parametrize("cls", [
    *(name for name, _, _ in _UP_UNDER_READ_CLASSES),
    "unclassified",
])
def test_url_parse_address_covers_every_consumer_reading(url_parse_comparison, cls):
    """THE url_parse DIFFERENTIAL (§2.3 rule 1). A consumer that reaches a more
    severe address than url_parse reports is a call detection under-classifies;
    for link_local, a credential fetch that is not blocked."""
    rows = url_parse_comparison["under"].get(cls, [])
    who = collections.Counter(o for *_, names in rows for o in names)
    assert not rows, (
        f"[{cls}] {len(rows)} spellings reach an address more severe than url_parse "
        f"reports (reached by {dict(who)}); first five: "
        + "; ".join(f"{u!r}: url_parse={g}, {', '.join(n)} reach {w}" for u, g, w, n in rows[:5]))


# Over-reads allowed in a named class whose reason is TRUE (§2.3 rule 2), each
# pinned both ways below.
_UP_OVER_READ_CLASSES = {
    "q22-bsd-decimal-leading-zero": (
        lambda hosts: any(_bsd_decimal_leading_zero(h, ip) for h, ip in hosts.values()),
        "Q22's class, seen from the other side: url_parse reads a leading-zero quad "
        "as OCTAL (0251.254.0251.254 -> 169.254.169.254, link_local), as WHATWG, "
        "glibc and inet_aton do, and the macOS resolver reads it as DECIMAL "
        "(251.254.251.254). Agents run on Linux, where glibc reaches the "
        "link-local address."),
    "one-host-pipeline-for-every-reading": (
        lambda hosts: any(_decoded_only_by_the_core(h, ip) for h, ip in hosts.values()),
        "The core canonicalises EVERY reading's host with one pipeline, WHATWG's: "
        "percent-decode, strip the root dot, and WHATWG's IPv4 number parser (an "
        "empty hex part is 0, M3a). Some hosts are split out only by "
        "readings whose consumers do neither: httpx and urllib.parse behind a `\\@` "
        "(`http://corp.example\\@%31%36%39.254.169.254`), or the opaque host of a "
        "non-special scheme (`gopher://169.254.169.254.`). Those consumers keep the "
        "literal, and the resolver does not read it as an address (glibc refuses "
        "`0x.0x.0`; the macOS resolver reads it). Over-read only: "
        "it flags spellings nothing sends to the metadata service. url_parse "
        "stripped the root dot before M3 as well (for parity with `_extract_host`); "
        "the percent half is new with M3. M0's core gate cannot see this class by "
        "construction, because it normalises each oracle's host with the core's own "
        "pipeline."),
}


def _decoded_only_by_the_core(host, ip):
    """A host an oracle split out, which the resolver does NOT read as an
    address, and which the core's host pipeline turns into one by decoding a
    percent-escape, stripping a root dot, or reading an empty hex part as 0."""
    if ip is not None or not ("%" in host or host.endswith(".")
                              or any(p.lower() == "0x" for p in host.split("."))):
        return False
    from xaidr.value_origin._authority import _host_authority
    a = _host_authority(host, arg_fallback=False)
    return a is not None and a.scheme == "ip"


def test_url_parse_over_reads_only_in_named_classes(url_parse_comparison):
    """§2.3 rule 2: url_parse may not report an address class no consumer
    reaches, outside a named class. Over-reading link_local blocks a call no
    transport sends to the metadata service. (Strict xfail at M2: Arabic-Indic
    digits and inet_aton overflow, gone with M3's move onto the core.)"""
    over = url_parse_comparison["over"].get(None, [])
    assert not over, (
        f"{len(over)} spellings where url_parse reports a class no consumer reaches; "
        f"first five: " + "; ".join(f"{u!r}: url_parse={g}, readings={r}" for u, g, r in over[:5]))


@pytest.mark.parametrize("url, consumer, form", [
    # F3 — url_parse misses these today; a transport reaches 169.254.169.254
    # (strict xfails at M2; M3 reads the host through the core's pipeline)
    ("http://169．254．169．254/latest", "httpx", "fullwidth dots"),
    ("http://%31%36%39.254.169.254/", "urllib3", "percent-encoded"),
    # caught TODAY (int() takes fullwidth digits) and the core's coerce_ip
    # ALONE drops it (F3's regression risk): it must stay caught through M3
    ("http://１６９.２５４.１６９.２５４/latest", "ada-url (WHATWG)", "fullwidth digits"),
])
def test_f3_a_link_local_spelling_a_consumer_reaches_is_link_local(oracles, url, consumer, form):
    """Named, with the consumer that actually reaches the address. The
    consumer's reach is asserted first, so this cannot pass on a spelling
    nothing sends to the metadata service."""
    host = oracles[consumer](url)
    ip = _resolve(host) if host else None
    assert ip is not None and _kind(ip) == "link_local", (
        f"precondition: {consumer} was expected to reach a link-local address for "
        f"{url!r}, it read host {host!r} -> {ip}")
    got = _url_parse_address(url)
    assert got == "link_local", (
        f"{form}: {consumer} reaches {ip} for {url!r} and url_parse reports "
        f"address={got!r}, so a credential fetch through it is not blocked")


# The IP spellings, each inside a URL host (V-19 confines the integer forms to
# one), against the resolver alone: coerce_diff.py's forms (ARCHITECTURE §2.4).
def _ip_forms():
    def spell(n):
        return [str(n), hex(n), hex(n).upper().replace("X", "x"),
                "0" + oct(n)[2:] if n else "0", "000" + str(n)]
    forms = set()
    for a, b in ((169, 254), (127, 0), (10, 1)):
        for sa in spell(a):
            for sb in spell(b):
                forms.add(f"{sa}.{sb}.{sa}.{sb}")
    forms |= {"2852039166", "0xA9FEA9FE", "0251.0376.0251.0376", "169.254.43518",
              "169.16689662", "1.2.3.256", "1.2.3.4.5", "1.2.65536",
              "１６９.２５４.１６９.２５４", "١٦٩.٢٥٤.١٦٩.٢٥٤", "169．254．169．254", "0x",
              "0x.1.1.1", "0x.0x.0", "08.1.1.1", "4294967296", "4294967295", "127.1", "0",
              "[::ffff:169.254.169.254]", "[::ffff:a9fe:a9fe]", "[::1]", "1e2.1.1.1",
              "169.254.169.254.", "0177.1", "017700000001", "0x7f.1", "0x7f000001",
              # the M2 review's: read as 169.254.169.254 by the macOS resolver
              "000169.254.000169.254", "169.000254.169.000254"}
    return sorted(forms)


def _ip_comparison():
    """(form, resolver ip, url_parse class, core keys) for every form the
    resolver reads as an address."""
    from xaidr.value_origin import extract_destinations
    rows = []
    for h in _ip_forms():
        ip = _resolve(h)
        if ip is None:
            continue
        url = f"http://{h}/"
        found, _ = extract_destinations({"url": url})
        core = {f.destination.key() for f in found if f.destination is not None}
        rows.append((h, ip, _url_parse_address(url), core))
    return rows


def _ip_key(ip):
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return "ip:" + (ip.compressed if isinstance(ip, ipaddress.IPv6Address) else str(ip))


def _bsd_integer_wrap(host, ip):
    """NOT exempted, and not ruled: a decimal integer above 2**32 - 1 that the
    resolver read modulo 2**32 (macOS: 4294967296 -> 0.0.0.0). glibc and
    WHATWG refuse it. Measured 2026-10-03; Q22 exempted exactly ONE darwin
    class, so this one is held out of the two tests below only to be pinned
    on its own, red on darwin, in test_bsd_libc_integer_wrap_is_an_unruled_platform_class."""
    if ip is None or not (host.isascii() and host.isdigit()):
        return False
    n = int(host, 10)
    return n > 0xFFFFFFFF and ip == ipaddress.ip_address(n % (1 << 32))


def _platform_class(h, ip):
    return _bsd_decimal_leading_zero(h, ip) or _bsd_integer_wrap(h, ip)


def test_the_named_url_parse_over_read_class_stands_for_a_measured_platform(url_parse_comparison):
    """Q22, both ways, for the over-read direction: present on darwin, EMPTY on
    Linux, so the allowance cannot grow silently there."""
    absorbed = url_parse_comparison["over"].get("q22-bsd-decimal-leading-zero", [])
    if sys.platform == "darwin":
        assert absorbed, ("Q22: on darwin the resolver was expected to read a "
                          "leading-zero quad as decimal; the class absorbed nothing")
    else:
        assert not absorbed, (f"Q22's class absorbed {len(absorbed)} over-reads on "
                              f"{sys.platform}, where it must be empty: {absorbed[:5]}")


def test_the_bracket_validation_over_read_class_stands_for_a_measured_interpreter(
        url_parse_comparison):
    """M0's class (_OVER_READ_CLASSES, same reason), now for url_parse too:
    url_parse reads what CPython 3.12.2's urlsplit reads, through the core's RFC
    reading. It absorbs NOTHING where urlsplit reads like 3.12.2, and must be
    needed on a post-backport interpreter (measured: 3.10.21, 3.11.16, 3.12.14)."""
    absorbed = url_parse_comparison["over"].get("urlsplit-bracket-validation", [])
    if _urlsplit_reads_like_3_12_2():
        assert not absorbed, (f"{len(absorbed)} over-reads absorbed where urllib.parse "
                              f"should read them: {absorbed[:5]}")
    else:
        assert absorbed, "the class absorbed nothing on a post-backport interpreter"


def test_the_pipeline_over_read_class_is_needed(url_parse_comparison):
    """An allowance that absorbs nothing hides nothing and is red: delete it."""
    assert url_parse_comparison["over"].get("one-host-pipeline-for-every-reading"), (
        "the one-host-pipeline over-read class absorbed nothing; delete it")


def test_ip_spellings_resolve_where_the_resolver_does_url_parse():
    """url_parse's class is at least the class of what the resolver reaches,
    for every literal form, except Q22's exemption."""
    rows = _ip_comparison()
    assert len(rows) >= 50, len(rows)
    bad = [(h, ip, got) for h, ip, got, _ in rows
           if _rank(got) < _rank(_kind(ip)) and not _platform_class(h, ip)]
    assert not bad, (f"{len(bad)} host spellings the resolver reaches at a more severe "
                     f"class than url_parse reports: {bad[:8]}")


def test_ip_spellings_resolve_where_the_resolver_does_core():
    """The core names the address the resolver reaches, for every literal
    form, except Q22's exemption."""
    rows = _ip_comparison()
    bad = [(h, str(ip), sorted(core)) for h, ip, _, core in rows
           if _ip_key(ip) not in core and not _platform_class(h, ip)]
    assert not bad, (f"{len(bad)} host spellings where the resolver reaches an address "
                     f"the core never names: {bad[:8]}")


@pytest.mark.xfail(sys.platform == "darwin", strict=True, raises=AssertionError, reason=(
    "UNRULED: the macOS resolver wraps a decimal integer modulo 2**32. Q22 exempted "
    "exactly one darwin class (decimal leading zeros); this is a second, held for "
    "the owner"))
def test_bsd_libc_integer_wrap_is_an_unruled_platform_class():
    """Pinned both ways, as Q22's class is: red (strict xfail) on darwin, where
    the resolver reads it; green on Linux, where glibc refuses it. Neither url_parse
    nor the core reads it, so on darwin `http://4294967296/` reaches 0.0.0.0
    unclassified."""
    wrapped = [(h, str(ip), got, sorted(core)) for h, ip, got, core in _ip_comparison()
               if _bsd_integer_wrap(h, ip)]
    assert not wrapped, (
        f"{len(wrapped)} decimal integers above 2**32-1 that the resolver wraps to an "
        f"address neither url_parse nor the core reads: {wrapped}")


@pytest.mark.xfail(sys.platform == "darwin", strict=True, raises=AssertionError, reason=(
    "FOR THE OWNER (found by the M2 milestone review): Q22's exemption was ruled on "
    "the premise that the decimal reading lands in reserved space (251.254.251.254). "
    "It also covers 000169.254.000169.254, which the macOS resolver reads as "
    "169.254.169.254, LINK-LOCAL, while url_parse and the core read octal "
    "121.254.121.254. Held for a re-ruling; behaviour unchanged."))
def test_q22_exemption_hides_no_link_local_reach():
    """The exemption may absorb a platform divergence, never a reach of the
    metadata service. Green on Linux (the class is empty there); a strict xfail
    on darwin until the owner re-rules Q22 on the true premise."""
    hidden = [(h, str(ip)) for h, ip, _, _ in _ip_comparison()
              if _bsd_decimal_leading_zero(h, ip) and _kind(ip) == "link_local"]
    assert not hidden, (
        f"Q22's exemption hides {len(hidden)} spellings the resolver sends to a "
        f"LINK-LOCAL address that neither url_parse nor the core reads: {hidden}")


def test_q22_bsd_libc_decimal_leading_zero_class_is_present_on_darwin_and_empty_on_linux():
    """Q22, both ways. On darwin the class EXISTS: the resolver reads at least
    one leading-zero quad as decimal (so the exemption above is spent on a real
    divergence). On Linux it is EMPTY: glibc reads those quads as octal, the
    exemption absorbs nothing, and so it cannot grow silently."""
    exempt = [(h, str(ip)) for h, ip, _, _ in _ip_comparison() if _bsd_decimal_leading_zero(h, ip)]
    if sys.platform == "darwin":
        assert exempt, ("Q22: on darwin the resolver was expected to read a leading-zero "
                        "quad as decimal (0251.254.0251.254 -> 251.254.251.254); it read "
                        "none that way, so the exemption is stale")
        assert ("0251.254.0251.254", "251.254.251.254") in exempt, exempt
    else:
        assert not exempt, (f"Q22: the BSD-decimal class absorbed {len(exempt)} forms on "
                            f"{sys.platform}, where it must be empty: {exempt[:8]}")
