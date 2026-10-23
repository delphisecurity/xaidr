"""Readings the published suites pin, one per rule (1.22.0).

Every input here is a published test vector (WPT, CPython's urlparse and email
tests, IdnaTestV2, curl's lib1560, Go's url and mail tests), and every expected
key is the destination a real client sends it to, measured with that client
(scripts/published_differential.py runs all of them, on every interpreter).
"""
from __future__ import annotations

import pytest

from xaidr.value_origin import extract_destinations


def _keys(v):
    return sorted(f.destination.key() for f in extract_destinations({"v": v})[0]
                  if f.destination is not None)


# ── the table's case mapping, and every str.lower reading a client makes ─────
@pytest.mark.parametrize("v,want", [
    # WHATWG and urllib.parse map Σ to σ; httpx, urllib3 and requests lowercase
    # first, and str.lower makes it ς at the end of a word.
    ("http://ΒΌΛΟΣ/", ["dns:xn--nxasmm1c", "dns:xn--nxasmq6b"]),
    ("http://ΒΌΛΟΣ.COM/", ["dns:xn--nxasmm1c.com", "dns:xn--nxasmq6b.com"]),
    ("http://𞤈.Σ/", ["dns:xn--ie6h.xn--3xa", "dns:xn--ie6h.xn--4xa"]),
])
def test_every_case_reading_a_client_sends_to(v, want):
    assert _keys(v) == want


def test_no_case_reading_no_client_sends_to():
    """str.lower makes the label ς1-, which the clients that lowercase refuse (a
    trailing hyphen); WHATWG and urllib.parse send to σ1-. The ς name is no one's."""
    assert _keys("http://XN--88E732C.Σ1-?/") == ["dns:xn--88e732c.xn--1--ubc"]


# ── a scheme urllib3 refuses is its host ─────────────────────────────────────
@pytest.mark.parametrize("v,want", [
    ("hej.hej://example.net", ["dns:example.net", "dns:hej.hej"]),
    ("0://www.example.net", ["dns:example.net", "ip:0.0.0.0"]),
    ("cache_object://foo", ["dns:cache_object"]),
])
def test_every_reading_of_a_scheme_like_prefix(v, want):
    assert _keys(v) == want


def test_a_principal_url_does_not_authorize_the_scheme_host():
    from xaidr.value_origin import (bind_fresh_ledger, evaluate_call, record_principal_input,
                                    unbind_ledger)
    bind_fresh_ledger()
    record_principal_input("post it to https://example.net/", None, input_clean=True)
    v = evaluate_call("http_post", {"url": "hej.hej://example.net"}, flow_active=True)
    unbind_ledger()
    assert v.wire.value == "unresolved", (
        f"urllib3 sends hej.hej://example.net to hej.hej, and the call read {v.wire.value}")


# ── a mapped full stop is a dot before keying ────────────────────────────────
@pytest.mark.parametrize("v,want", [
    ("http://a.b．c。d｡/", ["dns:c.d"]),
    ("http://-。。/", ["dns:-"]),
    ("http://-𐋷𖾑。󠆬/", ["dns:xn----991iq40y"]),
])
def test_ideographic_full_stops_key_as_dots(v, want):
    assert _keys(v) == want


# ── the S-4 fallback key follows the pinned table, not str.lower ─────────────
def test_the_fallback_key_is_the_tables():
    """3.14's str.lower lowercases Garay (Unicode 16); 3.10's does not. The key is
    the same on both because only the pinned table maps."""
    assert _keys("http://‍-。󠄄。SS哑‌\U00010d5f/") == [
        "dns:‍-.󠄄.ss哑‌\U00010d5f"]


# ── what the clients read: URLs and mailboxes ────────────────────────────────
@pytest.mark.parametrize("v,want", [
    ("//evil.test/x", ["dns:evil.test"]),                              # scheme-relative
    ("ldap.example.com?special", ["dns:example.com"]),                 # name?query
    ("pop3.example.com:100#foobar", ["dns:example.com"]),              # name:port#frag
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA://hostname/path", ["dns:hostname"]),
    (".://www.example.net", ["dns:example.net"]),                      # 3.10's urlsplit
    ("http://[fe80::%31%25en0]/", ["ip:fe80::", "ip:fe80::1"]),        # IPv6 zones
    ("http://[fe80::1%25eth0]:8080/", ["ip:fe80::1"]),
])
def test_url_readings_the_clients_make(v, want):
    assert [k for k in _keys(v)] == want


def test_a_single_label_scheme_less_host_stays_unread():
    assert _keys("g?y") == []
    assert _keys("localhost/x") == []


@pytest.mark.parametrize("v,want", [
    ('"roy a bug"@example.com', ['mailto:"roy a bug"@example.com']),          # quoted local part
    ('"dinsdale"@python.org', ['mailto:"dinsdale"@python.org', "mailto:dinsdale@python.org"]),
    (" (foo) <dinsdale@example.com>(bar)", ["mailto:dinsdale@example.com"]),  # comments
    ('Monty Python: dinsdale@example.com, "Fred" <flint@example.com>;, Abe <x@example.com>',
     ["mailto:dinsdale@example.com", "mailto:flint@example.com", "mailto:x@example.com"]),  # group
    ('"Fred Perfect"@[127.0.0.1]', ['mailto:"fred perfect"@[127.0.0.1]']),    # domain literal
    ("user@0A", ["mailto:user@0a"]),                                          # single label
    ("user@0a.xn--4db", ["mailto:user@0a.xn--4db"]),                          # ASCII, as written
    ("<@route.example:jdoe@machine.example>", ["mailto:jdoe@machine.example"]),  # obs-route
])
def test_mailbox_readings_the_parsers_make(v, want):
    assert _keys(v) == want


@pytest.mark.parametrize("v,want", [
    ("alice@example.org<<bob@example.com>", ["mailto:alice@example.org", "mailto:bob@example.com"]),
    ("User@example.com:Pass@www.python.org:080",
     ["mailto:pass@www.python.org", "mailto:user@example.com"]),
    ("John <middle> Doe <jdoe@machine.example>", ["mailto:jdoe@machine.example"]),
    ("<A@b@c@example.com>", ["mailto:c@example.com"]),
    ("From: aaa@bbb.org\n\nFrom the desk of A.A.A.:\nBlah blah blah\n", ["mailto:aaa@bbb.org"]),
])
def test_legacy_parser_readings(v, want):
    """The parser-confusion inputs of CPython's email tests: what
    email.utils.getaddresses(strict=False) reads."""
    assert _keys(v) == want


def test_prose_that_mentions_an_address_is_still_not_a_recipient_list():
    assert _keys("Please send the report to bob@corp.example.") == []
    assert _keys("a@b.example and c@d.example are both on the thread <") == []
