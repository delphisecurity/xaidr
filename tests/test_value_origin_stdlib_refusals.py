"""A value no client accepts is read conservatively.

``urllib.request.Request(url)`` computes ``request_host``, which runs
``urllib.parse.urlparse``; a URL that refuses there (a bracket that does not
pair, a bracketed host that is no address) raises before anything is resolved.
The core still reads the name urllib.request and http.client would resolve had
the split gone through (``_authority.stdlib_hosts``), beside every other
reading. That reading errs toward holding: the name is an extra ``unresolved``
finding, or ``untrusted_source`` where an untrusted result wrote the same value,
and it never authorizes a call (docs/value-origin-rulings.md §2).
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


@pytest.mark.parametrize("v,key", REFUSED)
def test_a_value_no_client_accepts_keeps_its_stdlib_name(v, key):
    found, _ = extract_destinations({"url": v})
    keys = [f.destination.key() for f in found if f.destination is not None]
    assert key in keys, (
        f"{v!r}: the core no longer reads {key}, the name urllib.request and "
        f"http.client would resolve; a value no client accepts is read conservatively "
        f"({keys})")
