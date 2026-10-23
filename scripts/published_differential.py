"""The published-suite differential: every destination a real client reads in a
published test vector, the core reads (docs/value-origin-rulings.md §2, the
reading principle).

    python scripts/published_differential.py [--json OUT] [--limit N]

For each vector in ``tests/published_vectors/vectors.jsonl`` it collects what
each client would send to, with that client's own send path and no network:

    httpx            Client.build_request(...).url.raw_host (http/https/ws/wss only)
    urllib3          PoolManager().connection_from_url(v).host
    requests         HTTPAdapter.get_connection_with_tls_context(prepared).host
    urllib.parse     urlsplit(v).hostname, encoded as the socket layer encodes it
                     (the stdlib ``idna`` codec, IDNA 2003)
    whatwg           ada-url (the WHATWG parser Node.js uses), special schemes
    email            email.utils.getaddresses and parseaddr, strict and lenient,
                     and email.headerregistry's To header
    suite            the vector's own table: the host or address its project
                     expects (curl, Go, WPT, IdnaTestV2)

Each reading is reduced to the core's key space without the core's reader: an
address through ``ipaddress`` and the platform resolver (``inet_aton``,
``getaddrinfo(AI_NUMERICHOST)``), a name lowercased with its trailing dot removed
and keyed by the core's PSL function (keying only). A reading no resolver or mail
server can use (a name outside LDH and ``_``, an all-digit last label, a local
part outside RFC 5321) is not sendable and not compared.

An UNDER-READ is a client key the core's argument walk does not read
(``extract_destinations``, the findings that decide). Each under-read must belong
to a class the rulings document (``CLASSES`` below, each naming its ruling). One
that belongs to none is printed with its vector, client and key, and the run
exits 1. Over-reads (a key the core reads that no client and no suite reads) are
counted by class and never fail the run: each is an overrulable reading.
"""
from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import re
import socket
import sys
import warnings
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "tests" / "published_vectors" / "vectors.jsonl"

warnings.simplefilter("ignore")


def _require():
    missing = []
    for mod in ("httpx", "urllib3", "requests", "ada_url", "idna"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        raise SystemExit(f"REFUSING: the oracles {missing} are not installed; a missing "
                         "client is a silent pass, never a skip (Q3).")


# ── clients ──────────────────────────────────────────────────────────────────
_HTTP = ("http", "https", "ws", "wss")


def _scheme(v):
    m = re.match(r"\s*([A-Za-z][A-Za-z0-9+.\-]*):", v)
    return m.group(1).lower() if m else None


class Clients:
    def __init__(self):
        import ada_url
        import httpx
        import requests
        import urllib3
        from requests.adapters import HTTPAdapter
        self.httpx = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
        self.ada = ada_url
        self.urllib3 = urllib3
        self.pool = urllib3.PoolManager(num_pools=4)
        self.requests = requests
        self.adapter = HTTPAdapter()

    def hosts(self, v):
        """[(client, host)]: the host each URL client sends ``v`` to."""
        out = []
        try:
            req = self.httpx.build_request("GET", v)
            if req.url.scheme in _HTTP and req.url.raw_host:
                out.append(("httpx", req.url.raw_host.decode("ascii", "replace")))
        except Exception:
            pass
        try:
            pool = self.pool.connection_from_url(v)
            if pool.host:
                out.append(("urllib3", pool.host))
        except Exception:
            pass
        finally:
            self.pool.clear()
        try:
            p = self.requests.Request("GET", v).prepare()
            conn = self.adapter.get_connection_with_tls_context(p, verify=True)
            if conn.host:
                out.append(("requests", conn.host))
        except Exception:
            pass
        try:
            h = urlsplit(v).hostname               # a covered consumer, any scheme
            if h:
                try:
                    out.append(("urllib.parse", h.encode("idna").decode("ascii")))
                except UnicodeError:
                    pass
        except ValueError:
            pass
        try:
            u = self.ada.URL(v)
            if u.protocol[:-1] in _HTTP and u.hostname:
                out.append(("whatwg", u.hostname))
        except Exception:
            pass
        return out

    @staticmethod
    def mailboxes(v):
        """[(client, addr)]: each mailbox an email parser returns for ``v``. A
        whole message (a header line after a newline) is not a header value, so
        the parsers are not run on it."""
        import email.utils as eu
        from email import policy
        out = []
        if re.search(r"\n\s*[!-9;-~]+:", v) or re.match(r"[!-9;-~]+:.*\n\s*\n", v, re.S):
            return out
        for strict in (True, False):
            name = "strict" if strict else "lenient"
            try:
                pairs = (eu.getaddresses([v], strict=strict) if _has_strict()
                         else eu.getaddresses([v]))
                out += [(f"getaddresses.{name}", a) for _, a in pairs if a]
            except Exception:
                pass
            try:
                a = (eu.parseaddr(v, strict=strict) if _has_strict() else eu.parseaddr(v))[1]
                if a:
                    out.append((f"parseaddr.{name}", a))
            except Exception:
                pass
            if not _has_strict():
                break
        try:
            h = policy.default.header_factory("To", v)
            out += [("headerregistry", a.addr_spec) for a in h.addresses if a.addr_spec]
        except Exception:
            pass
        return out


def _has_strict():
    import email.utils as eu
    import inspect
    return "strict" in inspect.signature(eu.getaddresses).parameters


# ── keying (never the core's reader) ─────────────────────────────────────────
_LDH = re.compile(r"[a-z0-9_\-]{1,63}(?:\.[a-z0-9_\-]{1,63})*")
_ATEXT = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~\-]+"
_DOT_STRING = re.compile(_ATEXT + r"(?:\." + _ATEXT + r")*")
_QUOTED = re.compile(r'"(?:[\x20\x21\x23-\x5b\x5d-\x7e]|\\[\x20-\x7e])*"')
#: RFC 5321 address literals: an IPv4 dotted quad, or IPv6: and an IPv6 address.
_ADDRESS_LITERAL = re.compile(r"\[(?:\d{1,3}(?:\.\d{1,3}){3}|ipv6:[0-9a-f:.]+)\]")


def _ip_key(ip):
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return f"ip:{ip.compressed}"


def _numeric(h):
    for fn in (lambda: socket.inet_aton(h),
               lambda: socket.inet_pton(socket.AF_INET, socket.getaddrinfo(
                   h, None, socket.AF_INET, 0, 0, socket.AI_NUMERICHOST)[0][4][0])):
        try:
            return ipaddress.IPv4Address(fn())
        except (OSError, ValueError, IndexError):
            continue
    return None


def host_key(h):
    """The key a client's host reading reduces to, or None if no resolver can use it."""
    from xaidr.value_origin._authority import dns_key
    if not h:
        return None
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    h = re.split(r"%(?:25)?", h, 1)[0] if ":" in h else h       # an IPv6 zone is not compared
    try:
        return _ip_key(ipaddress.ip_address(h))
    except ValueError:
        pass
    h = h.lower().rstrip(".")
    if not h:
        return None
    ip = _numeric(h)
    if ip is not None:
        return _ip_key(ip)
    if not _LDH.fullmatch(h) or len(h) > 253 or h.rsplit(".", 1)[-1].isdigit():
        return None                            # DNS: a label <= 63, a name <= 253
    return "dns:" + dns_key(h)


def _encode_domain(d):
    import idna
    if d.startswith("[") and d.endswith("]"):
        lit = d.lower()
        if not _ADDRESS_LITERAL.fullmatch(lit):
            return None
        inner = lit[1:-1]
        try:
            ipaddress.ip_address(inner[5:] if inner.startswith("ipv6:") else inner)
        except ValueError:
            return None
        return lit
    try:
        return idna.encode(d, uts46=True, transitional=False).decode("ascii").lower()
    except Exception:
        return None


def mail_key(addr):
    if addr.count("@") < 1:
        return None
    local, _, domain = addr.rpartition("@")
    if not (_DOT_STRING.fullmatch(local) or _QUOTED.fullmatch(local)
            or (not local.isascii() and "@" not in local and " " not in local)):
        return None
    d = _encode_domain(domain.rstrip("."))
    if d is None or not ((_LDH.fullmatch(d) and len(d) <= 253)
                         or (d.startswith("[") and d.endswith("]"))):
        return None
    return f"mailto:{local.lower()}@{d}"


def suite_key(e):
    kind, _, val = e.partition(":")
    if kind == "host":
        if re.fullmatch(r".+:\d+", val) and not val.endswith("]"):
            val = val.rsplit(":", 1)[0]
        try:
            val = val.encode("idna").decode("ascii") if not val.isascii() else val
        except UnicodeError:
            return None
        return host_key(val)
    return mail_key(val)


# ── the core's reading ───────────────────────────────────────────────────────
def core_keys(v):
    from xaidr.value_origin import extract_destinations
    return {f.destination.key() for f in extract_destinations({"v": v})[0]
            if f.destination is not None}


# ── the documented classes ───────────────────────────────────────────────────
def _raw_hosts(v):
    """Hosts as written: after `scheme:` and any run of / and \\, after the last @,
    before the port; raw, not lowercased or encoded."""
    out = []
    m = re.match(r"\s*(?:[A-Za-z][A-Za-z0-9+.\-]*:)?[/\\]*([^/?#\\]*)", v)
    if m:
        auth = m.group(1)
        for hostinfo in {auth.rpartition("@")[2], auth.partition("@")[2] or auth}:
            if hostinfo.startswith("["):
                out.append(hostinfo.partition("]")[0] + "]")
            else:
                out.append(hostinfo.rsplit(":", 1)[0] if re.search(r":\d*$", hostinfo)
                           else hostinfo)
    return [h for h in out if h]


def _alternatives(raw):
    """Names (A-label form) from the encodings the rulings document as not the
    core's (S-4): IDNA 2003, IDNA 2008 without the UTS-46 mapping, UTS-46
    transitional, and UTS-46 of a newer Unicode where it allows or maps a code
    point of the host otherwise than Unicode 13.0."""
    import idna
    from urllib.parse import unquote
    from xaidr.value_origin._idna import _status
    raw = unquote(raw) if "%" in raw else raw
    out = set()
    try:                                       # IDNA 2008 without the UTS-46 mapping (libidn2)
        out.add(idna.encode(raw).decode("ascii"))
    except Exception:
        pass
    try:
        out.add(raw.encode("idna").decode("ascii"))
    except (UnicodeError, ValueError):
        pass
    try:
        out.add(idna.encode(raw, uts46=True, transitional=True).decode("ascii"))
    except Exception:
        pass
    try:
        newer = idna.uts46_remap(raw, std3_rules=False, transitional=False)
    except Exception:
        newer = None
    from xaidr.value_origin._idna import _map
    if any(_status(c) == "D" for c in raw) or (newer is not None and newer != _map(raw)):
        try:                                   # the newer Unicode reads (or maps) otherwise
            out.add(idna.encode(raw, uts46=True).decode("ascii"))
        except Exception:
            pass
    out.discard(None)
    return out


def _core_refuses(raw):
    from urllib.parse import unquote_to_bytes
    from xaidr.value_origin._idna import to_ascii
    h = raw.strip("[]").rstrip(".")
    if not h or ":" in h:
        return False
    try:
        h = unquote_to_bytes(h).decode("utf-8") if "%" in h else h
    except UnicodeDecodeError:
        return True
    return not h.isascii() and to_ascii(h) is None


_HAS_SCHEME = re.compile(r"\s*[A-Za-z][A-Za-z0-9+.\-]*:")


def _cls_mailbox_not_url(v, client, key, core):
    """§2 Mailboxes (3.2): a value with `@` that is not a URL is a mailbox list.
    urllib3 and requests read a scheme-less `user@host` as userinfo and a host;
    the core reads the mailbox, not its domain as a URL host."""
    s = v.strip()
    return (client in ("urllib3", "requests") and key.startswith(("dns:", "ip:"))
            and not _HAS_SCHEME.match(s) and "@" in re.split(r"[/?#]", s, 1)[0])


def _cls_schemeless(v, client, key, core):
    """§2 Scheme-less values, 'Not destinations': a bare hostname or address with
    no locator (V-19, §9 item 13), a bare number, a single-label host or a name
    whose last label is not alphabetic before a path."""
    s = v.strip()
    if key.startswith("mailto:"):
        return False
    if _HAS_SCHEME.match(s) and not re.match(r"\s*[^:/?#@\s]+:(?:\d+(?:[/?#]|$)|$)", s):
        return False
    host = re.split(r"[/?#]", s, 1)[0].rpartition("@")[2]
    host = host.rsplit(":", 1)[0] if re.search(r":\d*$", host) else host
    rest = s[len(re.split(r"[/?#]", s, 1)[0]):]
    labels = host.rstrip(".").split(".")
    return (not rest or len(labels) < 2 or not labels[-1].isalpha()
            or re.fullmatch(r"[0-9.]+|0x[0-9a-fA-F]+", host) is not None)


def _cls_uts46(v, client, key, core):
    """§2 URLs, UTS-46 (S-4): nontransitional, Unicode 13.0, CheckBidi on, joiners
    strict; a host it refuses is keyed whole and matches only itself. A client that
    encodes with IDNA 2003, transitionally, or with a newer Unicode reads another
    name."""
    for raw in _raw_hosts(v) + [m.group(1) for m in re.finditer(r"@([^\s<>,;@\"]+)", v)]:
        if _core_refuses(raw):
            return True
        alts = {a.lower().rstrip(".") for a in _alternatives(raw)}
        if key.startswith("mailto:") and key.rpartition("@")[2] in alts:
            return True
        if key in {host_key(a) for a in alts}:
            return True
    return False


def _cls_number(v, client, key, core):
    """§2 Addresses, an empty hex part (E): where the platform resolver refuses an
    empty hex part, Python's clients send the value as a DNS name, and the core
    reads WHATWG's address."""
    return key.startswith("dns:") and any(k.startswith("ip:") for k in core) and \
        bool(re.search(r"(?:^|\.)0x(?:\.|$)", key[4:], re.I))


def _cls_url_first(v, client, key, core):
    """§2 URLs (S-3): a value that opens with scheme:// or is a scheme-less
    host/path is a URL even when it carries @; an email parser's mailbox reading of
    it is not read."""
    return key.startswith("mailto:") and client != "suite" and (
        bool(re.match(r"\s*[A-Za-z0-9+.\-]*://", v)) or v.lstrip().startswith("//") or
        bool(re.match(r"\s*(?:https?|wss?|ftp):", v, re.I)) or
        bool(re.match(r"\s*[\w.\-]+\.[A-Za-z]+(?::\d+)?[/?#]", v)))


def _cls_spaced_at(v, client, key, core):
    """§2 Mailboxes: an `@` with whitespace on both sides is not an
    address; an email parser that joins the words around it reads one."""
    return key.startswith("mailto:") and bool(re.search(r"\s@\s|\s@$|^@\s", v)) and \
        not re.search(r"[^\s<>@,;]@[^\s<>@,;]", v)


def _cls_local_not_written(v, client, key, core):
    """§2 Mailboxes: a local part is read as the value writes it. One that a
    parser's error recovery writes and the value does not contain (the words
    before an `@` quoted into it, quotes inside it dropped) is not read: the value
    is prose or a malformed address."""
    if not key.startswith("mailto:"):
        return False
    local = key[7:].rpartition("@")[0]
    flat = re.sub(r"\s+", " ", v.lower())
    return local not in flat and local.strip('"') not in flat


def _cls_junk_around(v, client, key, core):
    """§2 Mailboxes: an address with other text run into it, and no separator (a
    second address after a space, a stray `)` or `>`), is prose and not a recipient
    list (`bob@corp.example is the owner`)."""
    if not key.startswith("mailto:"):
        return False
    addr = key[7:]
    low = v.lower()
    i = low.find(addr)
    if i < 0:
        return False
    before = low[:i].rstrip()
    after = low[i + len(addr):].lstrip()
    return bool((after and after[0] not in ",;>") or (before and before[-1] not in "<,;:\""))


def _cls_mailto(v, client, key, core):
    """§2 URLs: `mailto:<addr>` is a mailbox, so the host urllib.parse splits
    out of `mailto://...` is not read."""
    return v.strip().lower().startswith("mailto:") and client == "urllib.parse"


def _cls_utf8_local(v, client, key, core):
    """§2 Mailboxes (3.6): the local part is ASCII by grammar; a non-ASCII one is
    unresolved."""
    return key.startswith("mailto:") and not key[7:].rpartition("@")[0].isascii()


def _cls_file(v, client, key, core):
    """§2 URLs: file: and data: are never destinations."""
    return _scheme(v) in ("file", "data")


#: (class, ruling, predicate), tried in order.
CLASSES = (
    ("mailbox-not-a-url-host", "§2 Mailboxes: a value with @ is a mailbox list (3.2)", _cls_mailbox_not_url),
    ("schemeless-not-a-destination", "§2 Scheme-less values: Not destinations (V-19)", _cls_schemeless),
    ("file-or-data-scheme", "§2 URLs: file: and data:", _cls_file),
    ("url-before-mailbox", "§2 URLs: a URL is tried before the mailbox rule (S-3)", _cls_url_first),
    ("utf8-local-part", "§2 Mailboxes: the local part is ASCII (3.6)", _cls_utf8_local),
    ("spaced-at-sign", "§2 Mailboxes: an @ that is not an address", _cls_spaced_at),
    ("mailto-is-a-mailbox", "§2 URLs: mailto: is a mailbox", _cls_mailto),
    ("local-part-not-written", "§2 Mailboxes: a local part is read as written", _cls_local_not_written),
    ("text-run-into-an-address", "§2 Mailboxes: prose is not a recipient list", _cls_junk_around),
    ("name-read-as-number", "§2 Addresses: an empty hex part is 0", _cls_number),
    ("uts46-encoding", "§2 URLs: UTS-46 nontransitional, Unicode 13.0 (S-4)", _cls_uts46),
)


def classify(v, client, key, core):
    for name, _, fn in CLASSES:
        try:
            if fn(v, client, key, core):
                return name
        except Exception:
            continue
    return None


# ── the run ──────────────────────────────────────────────────────────────────
def run(limit=None):
    _require()
    clients = Clients()
    rows = [json.loads(line) for line in VECTORS.open(encoding="utf-8")]
    if limit:
        rows = rows[:limit]
    under = collections.Counter()
    by_client = collections.Counter()
    undocumented = []
    vectors_read = set()
    for r in rows:
        v = r["v"]
        if v in vectors_read:
            pass
        vectors_read.add(v)
        readings = [(c, host_key(h)) for c, h in clients.hosts(v)]
        readings += [(c, mail_key(a)) for c, a in clients.mailboxes(v)]
        readings += [("suite", suite_key(e)) for e in r["expect"]]
        keys = {(c, k) for c, k in readings if k}
        if not keys:
            continue
        core = core_keys(v)
        for c, k in sorted(keys):
            if k in core:
                continue
            cls = classify(v, c, k, core)
            if cls is None:
                undocumented.append({"src": r["src"], "v": v, "client": c, "key": k,
                                     "core": sorted(core)})
                cls = "UNDOCUMENTED"
            under[cls] += 1
            by_client[(cls, c)] += 1
    return {"vectors": len(rows), "distinct": len(vectors_read), "under": dict(under),
            "by_client": {f"{a}|{b}": n for (a, b), n in sorted(by_client.items())},
            "undocumented": undocumented}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--show", type=int, default=60)
    ap.add_argument("--core-out", help="write every vector's core reading, for the "
                                       "cross-interpreter comparison")
    a = ap.parse_args(argv)
    res = run(a.limit)
    if a.core_out:
        values = sorted({json.loads(line)["v"] for line in VECTORS.open(encoding="utf-8")})
        Path(a.core_out).write_text(json.dumps(
            {v: sorted(core_keys(v)) for v in values}, sort_keys=True))
    print(f"python {sys.version.split()[0]} {sys.platform}: {res['vectors']} vectors")
    for cls, n in sorted(res["under"].items(), key=lambda x: -x[1]):
        doc = next((d for c, d, _ in CLASSES if c == cls), "no ruling")
        print(f"  under-read {cls:32} {n:6}  ({doc})")
    for u in res["undocumented"][:a.show]:
        print(f"  UNDOCUMENTED {u['src']}: {u['v']!r} -> {u['client']} {u['key']}; core {u['core']}")
    if a.json:
        Path(a.json).write_text(json.dumps(res, indent=1))
    if res["undocumented"]:
        print(f"PUBLISHED DIFFERENTIAL: RED ({len(res['undocumented'])} under-reads no ruling documents)")
        return 1
    print("PUBLISHED DIFFERENTIAL: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
