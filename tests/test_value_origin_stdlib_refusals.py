"""A URL urllib.request refuses has no urllib.request host. Found 2026-10-24, not fixed.

``urllib.request.Request(url)`` computes ``request_host``, which runs
``urllib.parse.urlparse``; a URL that refuses there (a bracket that does not
pair, a bracketed host that is no address) raises before anything is resolved,
so ``urlopen`` sends nowhere. The core's reading of the standard library's
clients (``_authority.stdlib_hosts``) does not model that refusal, so for each
value below it reads a name no client resolves: an over-read, an extra
``unresolved`` finding (and ``untrusted_source`` where an untrusted result wrote
the same value). It was found while naming the client behind each finding the
ruling that a name a client resolves is a destination (2026-10-23) added to the
pinned rows (Q1-urlsplit-refusal and R33-unparseable-url among them).
Narrowing the reading is the owner's call; until then the defect is pinned
here, strict, so the fix turns it green on purpose.
"""
from __future__ import annotations

import urllib.request

import pytest

from xaidr.value_origin import extract_destinations

REFUSED = [
    ("https://a]b@evil.test/collect", "dns:a]b@evil.test"),    # Q1-urlsplit-refusal
    ("https://[::1/", "dns:[:"),                               # R33-unparseable-url
    ("http://[fe80::%31%25en0]/", "dns:fe80::%31%25en0"),
    ("http://&a:foo(b]c@d:2/", "dns:&a:foo(b]c@d"),
]


@pytest.mark.parametrize("v,key", REFUSED)
def test_urllib_request_refuses_each_of_them(v, key):
    """The premise, measured on this interpreter: Request() raises, so urlopen
    resolves nothing for the value."""
    with pytest.raises(ValueError):
        urllib.request.Request(v)


@pytest.mark.xfail(strict=True, reason="found 2026-10-24, not fixed: stdlib_hosts reads "
                   "the urllib.request/http.client name of a URL urllib.request refuses")
@pytest.mark.parametrize("v,key", REFUSED)
def test_a_url_urllib_request_refuses_names_no_stdlib_host(v, key):
    found, _ = extract_destinations({"url": v})
    keys = [f.destination.key() for f in found if f.destination is not None]
    assert key not in keys, (
        f"{v!r}: the core reads {key}, a name only urllib.request or http.client would "
        f"resolve, and urllib.request refuses the URL ({keys})")
