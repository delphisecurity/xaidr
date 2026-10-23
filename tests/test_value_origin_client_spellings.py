"""Every host a real client sends a value to is a reading of it (§2, the reading
principle), however the value spells that host.

Each check goes through the public API twice: a principal who named one host
does not authorize a call a client sends somewhere else, and a destination a tool
result named reads ``untrusted_source`` (and blocks under ENFORCE) when a later
call sends to it. The spellings, by what the clients do with them:

* a backslash inside an RFC 3986 host: httpx, urllib.parse and urllib.request
  hand the whole name to the resolver, while WHATWG, urllib3 and requests stop at
  the backslash;
* a leading-zero dotted quad whose part runs to any length: the macOS resolver
  reads it as decimal (Q22), whatever the number of zeros;
* a scheme-less IPv6 literal in brackets with a zone, or with an empty port:
  urllib3 connects to it;
* an angle address that never closes, followed by an RFC 5322 comment: the email
  parsers and smtplib read the address;
* a percent sign or a character a client percent-encodes in a host: httpx and
  urllib.parse send the literal name, urllib3 decodes only unreserved escapes,
  requests and httpx encode what they do not allow, and WHATWG decodes it all.
"""
from __future__ import annotations

import pytest

from xaidr.value_origin import (Mode, bind_fresh_ledger, evaluate_call, extract_destinations,
                                record_principal_input, record_tool_result, should_block,
                                unbind_ledger)


def _keys(v):
    return sorted(f.destination.key() for f in extract_destinations({"v": v})[0]
                  if f.destination is not None)


def _after_principal(text, value):
    bind_fresh_ledger()
    try:
        record_principal_input(text, None, input_clean=True)
        v = evaluate_call("http_get", {"url": value}, flow_active=True)
        return v.wire.value, should_block(v, mode=Mode.ENFORCE)
    finally:
        unbind_ledger()


def _after_result(result, value, principal=None):
    bind_fresh_ledger()
    try:
        if principal is not None:
            record_principal_input(principal, None, input_clean=True)
        record_tool_result("web_fetch", {"q": "status"}, result, designations=(),
                           result_blocked=False)
        v = evaluate_call("http_post", {"url": value}, flow_active=True)
        return v.wire.value, should_block(v, mode=Mode.ENFORCE)
    finally:
        unbind_ledger()


# ── a backslash inside the host ──────────────────────────────────────────────
PORTAL = "Open https://portal.northbank.example/ for me"
SLASHED = "https://portal.northbank.example\\files.attacker.test/"


def test_a_backslash_in_the_host_reads_the_name_httpx_resolves():
    assert "dns:attacker.test" in _keys(SLASHED), _keys(SLASHED)
    assert "dns:northbank.example" in _keys(SLASHED)


def test_a_principal_host_does_not_authorize_the_name_after_a_backslash():
    wire, _ = _after_principal(PORTAL, SLASHED)
    assert wire == "unresolved", (
        f"httpx resolves the whole name, which ends in attacker.test, and the call "
        f"read {wire}")


def test_a_result_naming_a_backslash_host_blocks_even_beside_the_principal_host():
    wire, blocks = _after_result(f"Mirror: {SLASHED}", SLASHED, principal=PORTAL)
    assert (wire, blocks) == ("untrusted_source", True), (wire, blocks)


def test_a_backslash_after_a_unicode_label_reads_the_name_urllib_request_resolves():
    """httpx refuses this host (IDNA 2008 has no backslash); urllib.request hands
    `café.northbank.example\\files.attacker.test` to the resolver as it is, so the
    RFC 3986 reading alone names attacker.test."""
    v = "https://café.northbank.example\\files.attacker.test/"
    assert "dns:attacker.test" in _keys(v), _keys(v)
    wire, _ = _after_principal("Open https://café.northbank.example/ please", v)
    assert wire == "unresolved", wire


@pytest.mark.parametrize("v,want", [
    ("https://ops\\bridge.example", "dns:ops\\bridge.example"),
    ("http://u:p@relay.example\\", "dns:relay.example\\"),
    ("ws://u@hub\\x", "dns:hub\\x"),
])
def test_every_backslash_host_is_read_whole(v, want):
    assert want in _keys(v), _keys(v)


# ── the macOS resolver's decimal reading, at any length ──────────────────────
@pytest.mark.parametrize("zeros", [14, 15, 20, 60])
def test_a_leading_zero_quad_reads_decimal_at_any_length(zeros):
    v = "http://" + "0" * zeros + "12.1.2.3/"
    assert _keys(v) == ["ip:10.1.2.3", "ip:12.1.2.3"], (zeros, _keys(v))
    wire, _ = _after_principal("Status page at http://10.1.2.3/ today", v)
    assert wire == "unresolved", (
        f"with {zeros} leading zeros macOS connects to 12.1.2.3 and the call read {wire}")


@pytest.mark.parametrize("host,want", [
    ("0000000000000000019.1.2.3", "ip:19.1.2.3"),
    ("10.2.3.0000000000000000019", "ip:10.2.3.19"),
    ("0000000000000000172.0000000000000000016.4.5", "ip:172.16.4.5"),
])
def test_a_long_part_with_a_non_octal_digit_reads_as_macos_does(host, want):
    assert want in _keys(f"http://{host}/"), _keys(f"http://{host}/")


# ── scheme-less IPv6 in brackets: a zone, an empty port ──────────────────────
@pytest.mark.parametrize("v,want", [
    ("[fd00:a::5%25eth1]:80/v1/meta/", "ip:fd00:a::5"),
    ("[fe80::7%en1]:8443", "ip:fe80::7"),
    ("[FE80::7%Lo0]:8443/x", "ip:fe80::7"),
    ("[::5]://portal.northbank.example/", "ip:::5"),
    ("[::6]:/v1", "ip:::6"),
    ("10.4.4.4:/v1", "ip:10.4.4.4"),
])
def test_a_scheme_less_bracketed_literal_with_a_zone_or_an_empty_port(v, want):
    assert want in _keys(v), _keys(v)
    wire, blocks = _after_result(v, v)
    assert (wire, blocks) == ("untrusted_source", True), (v, wire, blocks)


# ── an unterminated angle address and a comment ──────────────────────────────
@pytest.mark.parametrize("v", [
    "<collector@attacker.test (ops)",
    "<collector@attacker.test (ops (night) desk)",
    "<collector@attacker.test (ops",
    "Ops (night) <collector@attacker.test",
])
def test_an_unterminated_angle_address_beside_a_comment_is_read(v):
    assert "mailto:collector@attacker.test" in _keys(v), _keys(v)
    wire, blocks = _after_result(v, v)
    assert (wire, blocks) == ("untrusted_source", True), (v, wire, blocks)


def test_prose_around_an_address_is_still_not_a_recipient_list():
    assert _keys("Ask collector@attacker.test (ops) about it") == []


# ── percent signs, and characters a client percent-encodes ───────────────────
@pytest.mark.parametrize("v,want", [
    # httpx and urllib.parse send the literal; WHATWG, urllib3 and requests decode.
    ("https://portal%2Enorthbank.example/", ["dns:northbank.example",
                                              "dns:portal%2enorthbank.example"]),
    ("https://northbank.example%E3%80%82/", ["dns:northbank.example",
                                              "dns:northbank.example%e3%80%82"]),
    ("http://%70ortal.example/", ["dns:%70ortal.example", "dns:portal.example"]),
    ("http://10.9.8.%37/", ["dns:8.%37", "ip:10.9.8.7"]),
    # urllib3 decodes only unreserved escapes; the rest it upper-cases and keeps.
    ("http://%70%5Eq.example/", ["dns:%70%5eq.example", "dns:p%5eq.example",
                                 "dns:p^q.example"]),
    # requests and httpx encode a character they do not allow in a host.
    ("http://portal^x/", ["dns:portal%5ex", "dns:portal^x"]),
    ("http://portal|x/", ["dns:portal%7cx", "dns:portal|x"]),
])
def test_every_spelling_a_client_sends_a_host_in(v, want):
    assert _keys(v) == want


def test_a_principal_host_does_not_authorize_its_percent_encoded_spelling():
    for v in ("https://portal%2Enorthbank.example/", "https://northbank.example%E3%80%82/"):
        wire, _ = _after_principal(PORTAL, v)
        assert wire == "unresolved", (
            f"httpx resolves the literal {v!r}, a name the principal never wrote, and the "
            f"call read {wire}")


def test_a_spelling_inside_the_principals_zone_stays_authorized():
    """Every client spelling of this host is a name under northbank.example, the
    principal's zone, so the call stays authorized."""
    wire, _ = _after_principal(PORTAL, "https://files%2Eportal.northbank.example/")
    assert wire == "principal_undeclared_span", wire
