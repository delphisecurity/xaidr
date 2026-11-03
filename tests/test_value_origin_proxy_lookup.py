"""requests on macOS: the name the system proxy check looks up is read.

Before it refuses a scheme it does not send, requests asks
``urllib.request.proxy_bypass`` whether the system proxy settings exempt
``urlparse(url).hostname``. On the older patch releases (measured: 3.10.11,
3.11.3, 3.12.0, 3.12.2) that check looks up ``_splitport(hostname)[0]``, the
hostname less a trailing ``:digits``, with ``gethostbyname``. A lookup is a
destination even when nothing connects. So for ``http://[fd00:ec2::254:80]/x``
the core reads both ``fd00:ec2::254:80`` (the hostname) and ``fd00:ec2::254`` (the
name looked up), on every interpreter.
"""
from __future__ import annotations

import contextvars
import socket
import sys
import urllib.parse
import urllib.request

import pytest

from xaidr import value_origin as vo
from xaidr.value_origin._authority import resolver_keys

# Hosts whose hostname ends in ``:digits`` inside the brackets: the looked-up name
# is shorter than the hostname. The scheme does not matter to the lookup.
VALUES = [
    "http://[fd00:ec2::254:80]/x",
    "https://[2001:db8::7:8443]/upload",
    "gopher://[1:2:3:4:5:6:7:80]/",
    "ftp://[::ffff:a9fe:a9fe:21]/pub",
]


def _looked_up(value: str) -> str:
    host = urllib.parse.urlsplit(value).hostname
    return urllib.parse._splitport(host)[0]


def _keys(value):
    found, _ = vo.extract_destinations({"url": value})
    return {f.destination.key() for f in found if f.destination is not None}


@pytest.mark.parametrize("value", VALUES)
def test_the_name_the_proxy_check_looks_up_is_read(value):
    name = _looked_up(value)
    assert name != urllib.parse.urlsplit(value).hostname, "precondition: a shorter name"
    want = {a.key() for a in resolver_keys(name)}
    assert want, f"precondition: {name!r} has a key"
    got = _keys(value)
    assert want <= got, (
        f"{value}: the proxy check looks up {name!r}, a destination the core does not "
        f"read (keys {sorted(want - got)} missing from {sorted(got)}), so a call to "
        "it after a result that named it reads as a destination nothing named")


# The looked-up names that are addresses: prose names an address and it is
# recorded. (``1:2:3:4:5:6:7`` is a name no prose reading records; the test above
# shows the call reads it.)
ADDRESS_VALUES = [v for v in VALUES if not v.startswith("gopher:")]


@pytest.mark.parametrize("value", ADDRESS_VALUES)
def test_a_call_after_a_result_naming_the_looked_up_name_traces_to_it(value):
    name = _looked_up(value)

    def run():
        vo.bind_fresh_ledger()
        vo.record_tool_result("search", {"q": "x"}, f"the box is at {name} now",
                              designations=(), result_blocked=False)
        return vo.evaluate_call("http_get", {"url": value}, flow_active=True)
    v = contextvars.Context().run(run)
    assert v.wire.value == "untrusted_source", (
        f"{value}: a result named {name!r}, the name the proxy check looks up, and the "
        f"call read {v.wire.value!r}")


def test_every_name_this_interpreters_proxy_check_looks_up_is_read():
    """Measured: the proxy check runs under an audit hook that records each name it
    hands the resolver and raises, so nothing leaves the machine. On an
    interpreter whose check looks nothing up, or off macOS, there is nothing to
    hold the core to, and the test says so in its result."""
    seen: list = []

    class Stop(Exception):
        pass

    def hook(event, args):
        if event in ("socket.gethostbyname", "socket.getaddrinfo", "socket.gethostbyname_ex"):
            if seen is not None and hook.armed:
                seen.append(args[0])
                raise Stop
    hook.armed = False
    sys.addaudithook(hook)
    looked = {}
    for value in VALUES + ["http://name.lookup-r6.test/x", "gopher://name.lookup-r6.test:70/"]:
        seen.clear()
        hook.armed = True
        try:
            urllib.request.proxy_bypass(urllib.parse.urlsplit(value).hostname)
        except (Stop, OSError):
            pass
        finally:
            hook.armed = False
        if seen:
            looked[value] = seen[0]
    missing = {v: n for v, n in looked.items()
               if not {a.key() for a in resolver_keys(n)} <= _keys(v)}
    assert not missing, f"names this interpreter's proxy check looks up and the core does not read: {missing}"
    if sys.platform != "darwin" or not looked:
        pytest.skip(f"this interpreter's proxy check looks nothing up "
                    f"({sys.version.split()[0]}, {sys.platform}); the readings above hold anyway")
