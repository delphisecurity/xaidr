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
        "urllib.request does NOT send there: it passes the raw netloc on."),
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
