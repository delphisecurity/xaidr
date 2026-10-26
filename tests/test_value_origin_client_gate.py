"""THE CLIENT GATE: a value any modeled client sends to is never no_destination.

``no_destination`` says no client finds a destination in the value. It is
correct only when that is so. For every generated value, each modeled client is
run for real in its default configuration: urllib.request's default opener,
http.client given the netloc ``urlsplit`` finds in an http or https URL, httpx, urllib3's PoolManager and
requests. An audit hook records the host a client hands the resolver
(``socket.getaddrinfo``, ``gethostbyname``, ``gethostbyname_ex``) or connects to,
then raises, so no lookup and no packet leaves the machine. Where any client
yields a host, the core must read the value as a destination: a call naming it,
on a fresh ledger, reads ``unresolved`` or stricter, never ``no_destination``.

The values are generated, not a list of answers: schemes x wrappers x userinfo x
hosts x ports, and a port written in every script's decimal digits (Unicode
16.0, from the vendored data), each digit set on an unbracketed IPv6 host, a
name and a bracketed address. The clients are REQUIRED: a missing one refuses,
never skips.
"""
from __future__ import annotations

import itertools
import os
import sys

import pytest

from xaidr.value_origin import (WireValue, bind_fresh_ledger, evaluate_call, unbind_ledger)

pytestmark = pytest.mark.requires_dev_extra

_SEEN: list = []
_ARMED = [False]


class _Blocked(Exception):
    pass


def _hook(event, args):
    if not _ARMED[0]:
        return
    if event in ("socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex"):
        _SEEN.append(str(args[0]))
        raise _Blocked(event)
    if event == "socket.connect":
        addr = args[1]
        _SEEN.append(str(addr[0]) if isinstance(addr, tuple) else str(addr))
        raise _Blocked(event)


_HOOKED = []


def _clients():
    missing = []
    out = {}
    import http.client
    import urllib.parse
    import urllib.request

    opener = urllib.request.build_opener()          # the default handlers

    def http_client(u):
        # http.client takes a host, not a URL: HTTPConnection and HTTPSConnection
        # are what a program hands the netloc of an http or https URL to.
        parts = urllib.parse.urlsplit(u)
        if parts.netloc and parts.scheme in ("http", "https"):
            http.client.HTTPConnection(parts.netloc, timeout=1).request("GET", "/")
    out["urllib.request"] = lambda u: opener.open(u, timeout=1)
    out["http.client"] = http_client
    try:
        import httpx
        out["httpx"] = lambda u: httpx.get(u, timeout=1)
    except ImportError:
        missing.append("httpx")
    try:
        import urllib3
        pm = urllib3.PoolManager()
        out["urllib3"] = lambda u: pm.request("GET", u, retries=False, timeout=1)
    except ImportError:
        missing.append("urllib3")
    try:
        import requests
        out["requests"] = lambda u: requests.get(u, timeout=1)
    except ImportError:
        missing.append("requests")
    return out, missing


@pytest.fixture(scope="module")
def clients():
    found, missing = _clients()
    if missing:
        pytest.fail(f"REFUSING: client(s) {missing} are not installed; a client the gate "
                    "cannot run is a client it does not cover. pip install '.[dev]' requests.",
                    pytrace=False)
    if not _HOOKED:
        sys.addaudithook(_hook)
        _HOOKED.append(True)
    saved = {k: os.environ.pop(k) for k in list(os.environ)
             if k.lower().endswith("_proxy") or k.lower() == "no_proxy"}
    yield found
    os.environ.update(saved)


def _digit_zeros():
    """Every script's decimal digit zero (UnicodeData field 6 is 0), read from the
    vendored Unicode 16.0 file itself, not from the core."""
    from pathlib import Path
    ud = (Path(__file__).resolve().parent / "published_vectors" / "upstream"
          / "UnicodeData-16.0.0.txt")
    return [int(f[0], 16) for f in (line.split(";") for line in
                                    ud.read_text(encoding="utf-8").splitlines())
            if f[6] == "0"]


_SCHEMES = ("http", "https", "HTTPS", "ftp", "file", "ws", "gopher")
_WRAPS = ("{}", " {} ", "<URL:{}>")
_USERINFO = ("", "op@", "op:pw@", "op%40x@")
_HOSTS = ("gate.example", "198.51.100.7", "[2001:db8::7]", "2001:db8::7", "::ffff:c633:6407",
          "g%61te.example", "g%2561te.example", "gåte.example")
_PORTS = ("", ":80", ":8443", ":+80", ":8_0", ":")
_TAILS = ("/p", "/etc/hosts?q")


def _values():
    for s, w, u, h, p, t in itertools.product(_SCHEMES, _WRAPS, _USERINFO, _HOSTS, _PORTS,
                                              _TAILS[:1]):
        yield w.format(f"{s}://{u}{h}{p}{t}")
    for s in ("file", "ftp"):
        for u, h in itertools.product(_USERINFO, _HOSTS):
            yield f"{s}://{u}{h}/etc/hosts"
    for z in _digit_zeros():
        port = chr(z + 8) + chr(z)
        for s in ("http", "https"):
            for h in ("2001:db8::7", "::ffff:c633:6407", "gate.example", "[2001:db8::7]"):
                yield f"{s}://{h}:{port}/p"


def _sends(clients, v):
    hosts = {}
    for name, fn in clients.items():
        del _SEEN[:]
        _ARMED[0] = True
        try:
            fn(v)
        except BaseException:          # noqa: BLE001 - a refusal is a measurement too
            pass
        finally:
            _ARMED[0] = False
        if _SEEN:
            hosts[name] = sorted(set(_SEEN))
    return hosts


def _wire(v):
    bind_fresh_ledger()
    try:
        return evaluate_call("http_get", {"url": v}, flow_active=True).wire
    finally:
        unbind_ledger()


@pytest.fixture(scope="module")
def gate(clients):
    rows, sent = [], 0
    for v in dict.fromkeys(_values()):
        hosts = _sends(clients, v)
        if not hosts:
            continue
        sent += 1
        wire = _wire(v)
        if wire is WireValue.NO_DESTINATION:
            rows.append((v, hosts))
    return {"sent": sent, "missed": rows}


def test_the_gate_measures_something(gate):
    assert gate["sent"] >= 1_000, gate["sent"]


def test_a_value_a_client_sends_to_is_never_no_destination(gate):
    missed = gate["missed"]
    assert not missed, (
        f"{len(missed)} values a client resolves read no_destination, so a call there "
        "cannot be traced and never blocks; first ten: "
        + "; ".join(f"{v!r} -> {h}" for v, h in missed[:10]))


# Every scheme a client might take, measured, never assumed: which ones make it
# resolve a host, in its default configuration, on this interpreter.
_PROBE_SCHEMES = ("http", "https", "HTTP", "Https", "ftp", "FTP", "ftps", "file", "FILE",
                  "data", "ws", "wss", "gopher", "sftp", "ssh", "telnet", "news", "nntp",
                  "irc", "ldap", "jar", "smb", "svn", "git", "rtsp", "x-custom+v1")


@pytest.fixture(scope="module")
def schemes(clients):
    resolves = {}
    for s in _PROBE_SCHEMES:
        v = f"{s}://probe-op@scheme.example/etc/hosts"
        for name, hosts in _sends(clients, v).items():
            resolves.setdefault(name, {})[s] = hosts
    return resolves


def test_urllib_request_resolves_the_schemes_the_core_models(schemes):
    """urllib.request's default opener: http, https, ftp and file, in any case.
    A scheme it resolves that the core does not model is red; so is one the core
    models that it no longer resolves (the model would be stale)."""
    from xaidr.value_origin._authority import _STDLIB_SCHEMES
    measured = {s.lower() for s in schemes.get("urllib.request", {})}
    assert measured == set(_STDLIB_SCHEMES), (
        f"urllib.request resolves {sorted(measured)}, the core models {_STDLIB_SCHEMES}")


def test_every_scheme_any_client_resolves_is_read(schemes):
    unread = []
    for name, by_scheme in schemes.items():
        for s, hosts in by_scheme.items():
            v = f"{s}://probe-op@scheme.example/etc/hosts"
            if _wire(v) is WireValue.NO_DESTINATION:
                unread.append((name, s, hosts))
    assert not unread, f"schemes a client resolves that the core reads nothing in: {unread}"
