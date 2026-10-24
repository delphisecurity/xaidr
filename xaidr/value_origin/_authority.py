"""Per-scheme authority — the one normaliser (rulings 3.2 and 3.6 in
docs/value-origin-rulings.md).

    mailto:<local@domain>   the full mailbox, local part .lower(), domain as
                            UTS-46 A-labels. No plus-stripping, no dot removal:
                            both collide genuinely distinct mailboxes (S18).
    dns:<registrable>       a URL host's registrable domain by the PSL algorithm,
                            both sections, default ``*`` rule. A host that is
                            itself a suffix, or one label, is kept whole.
    ip:<canonical>          every literal form (hex, octal, decimal, short
                            dotted, IPv4-mapped IPv6), mapped addresses
                            unwrapped BEFORE rendering.
    tel:+<digits>           ``+``-prefixed phones only. A national
                            number needs a region to normalise, and there is no
                            right default region (an open question).

Every pattern is bounded with no nested unbounded quantifier: this runs on
attacker-controlled values. Nothing here raises; nothing here does I/O.
"""
from __future__ import annotations

import ipaddress
import re
from typing import List, Optional, Tuple
from urllib.parse import unquote, unquote_to_bytes

from ._idna import _status, assigned, fold, idna2003, lower_by_unicode, pinned, to_ascii
from ._psl_data import ICANN_RULES, PRIVATE_RULES
from ._shared_tenant_data import SHARED_TENANT_APEXES
from ._types import MAX_LEAF_CHARS, Authority

# ── the PSL, compiled once ──────────────────────────────────────────────────
_RULES = frozenset(r for r in ICANN_RULES + PRIVATE_RULES if not r.startswith("!"))
_EXCEPTIONS = frozenset(r[1:] for r in ICANN_RULES + PRIVATE_RULES if r.startswith("!"))
# Ruling 3.4: the TLDs a bare hostname in prose may end in.
_ICANN_TLDS = frozenset(r.lstrip("!").rsplit(".", 1)[-1] for r in ICANN_RULES)
# RFC 2606 / RFC 6761 reserved names, which no PSL lists.
_RESERVED_TLDS = frozenset({"example", "test", "invalid", "localhost"})


def _public_suffix_len(labels: List[str]) -> int:
    """Number of labels in the public suffix of ``labels`` (PSL algorithm)."""
    n = len(labels)
    best = 1                                   # the default "*" rule
    for i in range(n):
        cand = labels[i:]
        name = ".".join(cand)
        if name in _EXCEPTIONS:
            return len(cand) - 1               # an exception rule prevails outright
        wild = ".".join(["*"] + cand[1:])
        if name in _RULES or (len(cand) > 1 and wild in _RULES):
            best = max(best, len(cand))
    return best


def registrable_domain(host: str) -> str:
    """The registrable domain of an A-label ``host``; the whole host when it
    is itself a public suffix or a single label."""
    labels = host.split(".")
    if len(labels) < 2:
        return host
    ps = _public_suffix_len(labels)
    if ps >= len(labels):
        return host
    return ".".join(labels[-(ps + 1):])


def dns_key(ascii_host: str) -> str:
    """The key of an A-label host: its registrable domain, or the whole host under
    a shared-tenant apex (``_shared_tenant_data``), whose hosts are not one
    party's."""
    rd = registrable_domain(ascii_host)
    return ascii_host if rd in SHARED_TENANT_APEXES else rd


def key_chain(a: Authority) -> List[Authority]:
    """The keys a lookup of ``a`` reads, most specific first: ``a`` itself, then,
    for a host under a shared-tenant apex, each parent up to the apex, so a host
    the principal named authorizes its subdomains."""
    if a.scheme != "dns":
        return [a]
    rd = registrable_domain(a.value)
    if rd not in SHARED_TENANT_APEXES or not a.value.endswith("." + rd):
        return [a]
    labels = a.value.split(".")
    keep = rd.count(".") + 1
    return [Authority(scheme="dns", value=".".join(labels[i:]))
            for i in range(len(labels) - keep + 1)]


def bare_host_tld_ok(ascii_host: str) -> bool:
    """Ruling 3.4: the last label is an ICANN TLD or an RFC 2606/6761 name."""
    last = ascii_host.rsplit(".", 1)[-1]
    return last in _ICANN_TLDS or last in _RESERVED_TLDS


# ── IP ───────────────────────────────────────────────────────────────────────
_HEX_DIGITS = frozenset("0123456789abcdef")
_OCT_DIGITS = frozenset("01234567")


def coerce_ip(host: str):
    """The IP address ``host`` denotes across every literal form, or None.

    Moved here from ``scanner/url_parse._coerce_ip``: the one normaliser
    lives inside the vendored unit. Integer forms (hex / octal / decimal / short
    dotted) are what ``inet_aton`` accepts; they apply to a host, a URL's or a
    scheme-less argument's with a locator after it — ``"4417"`` alone is not an
    address.
    """
    if not host:
        return None
    h = host.strip().strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    parts = h.split(".")
    if len(parts) > 4 or not all(parts):
        return None
    try:
        vals = []
        for p in parts:
            lp = p.lower()
            if lp.startswith("0x"):
                # An empty hex part is 0, as WHATWG's IPv4 number parser reads it
                # (the macOS resolver only before a later part). Digits are
                # checked, not left to int(), which also takes `_` separators no
                # resolver reads.
                digits = lp[2:]
                if not set(digits) <= _HEX_DIGITS:
                    return None
                vals.append(int(digits, 16) if digits else 0)
            elif p.startswith("0") and len(p) > 1:
                if not set(p) <= _OCT_DIGITS:
                    return None
                vals.append(int(p, 8))
            elif p.isdigit() and p.isascii():
                vals.append(int(p, 10))
            else:
                return None
        if len(vals) == 1:
            packed = vals[0]
        else:
            if any(v > 0xFF for v in vals[:-1]):
                return None
            packed = 0
            for v in vals[:-1]:
                packed = (packed << 8) | v
            if vals[-1] >= 1 << (8 * (4 - len(vals) + 1)):
                return None
            packed = (packed << (8 * (4 - len(vals) + 1))) | vals[-1]
        if not 0 <= packed <= 0xFFFFFFFF:
            return None
        return ipaddress.ip_address(packed)
    except (ValueError, TypeError):
        return None


def ip_key(ip) -> str:
    """Canonical text of an address: mapped v6 unwrapped first, then IPv4
    dotted or IPv6 ``.compressed`` — the same on every interpreter. An IPv6
    zone is not part of the destination's key."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.scope_id:
        ip = ipaddress.IPv6Address(ip.compressed.partition("%")[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv6Address):
        return ip.compressed
    return str(ip)


def _zoned_ip(inside: str):
    """An IPv6 literal with a zone (RFC 6874, ``%25`` then the zone), its address
    part percent-decoded first, as httpx, urllib3 and requests send it."""
    addr = inside.partition("%25")[0] if "%25" in inside else inside
    try:
        addr = unquote_to_bytes(addr).decode("ascii")
    except (UnicodeDecodeError, ValueError):
        return None
    ip = _strict_ip(addr.partition("%")[0])
    return ip if isinstance(ip, ipaddress.IPv6Address) else None


def _zone_readings(host: str) -> List[Authority]:
    """An IPv6 literal with a `%` in it is two addresses to Python's clients:
    urllib.parse hands the socket the text after `%` as a zone, and urllib3 and
    requests percent-decode it first (`fe80::%31` is fe80:: to one, fe80::1 to the
    other). Both are destinations."""
    h = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    if ":" not in h or "%" not in h:
        return []
    out = []
    for ip in (_zoned_ip(h), _strict_ip(h.partition("%")[0])):
        if isinstance(ip, ipaddress.IPv6Address):
            a = Authority(scheme="ip", value=ip_key(ip))
            if a not in out:
                out.append(a)
    return out


def _strict_ip(value: str):
    """A bare STRICT dotted-quad or IPv6 literal (optionally bracketed)."""
    v = value
    if v.startswith("[") and v.endswith("]"):
        v = v[1:-1]
    if not v.isascii():
        return None
    try:
        return ipaddress.ip_address(v)
    except ValueError:
        return None


# ── hosts ────────────────────────────────────────────────────────────────────
def _fallback(raw_host: str) -> Authority:
    """S-4's key for a host UTS-46 refuses: the host as written, case-mapped by
    the table (``fold``, never the interpreter's ``str.lower``), trailing dots
    removed. It matches only itself."""
    return Authority(scheme="dns", value=fold(raw_host).rstrip("."))


def _name_authority(ascii_host: str) -> Optional[Authority]:
    ascii_host = ascii_host.rstrip(".")        # a mapped full stop is a dot too
    if not ascii_host:
        return None
    ip = coerce_ip(ascii_host)
    if ip is not None:
        return Authority(scheme="ip", value=ip_key(ip))
    return Authority(scheme="dns", value=dns_key(ascii_host))


def _host_authority(raw_host: str, *, arg_fallback: bool) -> Optional[Authority]:
    """Authority of a URL host. ``raw_host`` is as the URL spelled it, case
    included.

    WHATWG order: percent-decode, then UTS-46 (the table maps case), then (if
    the result is an address in any spelling) IP. On a UTS-46 failure an
    ARGUMENT host still yields S-4's fallback key, which matches only itself and
    is never ``no_destination``; a prose candidate is dropped.
    """
    host = raw_host.strip()
    if any(c.isspace() for c in host):
        return None                            # no resolver reads a name with a space
    if host.startswith("[") and host.endswith("]"):
        ip = _strict_ip(host) or _zoned_ip(host[1:-1])
        return Authority(scheme="ip", value=ip_key(ip)) if ip is not None else None
    host = host.rstrip(".")
    if not host:
        return None
    if ":" in host:                            # only an IPv6 literal has a colon
        ip = _strict_ip(host) or _zoned_ip(host)
        if ip is not None:
            return Authority(scheme="ip", value=ip_key(ip))
        return _fallback(raw_host) if arg_fallback else None
    if "%" in host:
        try:
            host = unquote_to_bytes(host).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return _fallback(raw_host) if arg_fallback else None
        host = host.rstrip(".")
        if not host or any(c.isspace() for c in host):
            return None
    ascii_host = to_ascii(host)
    if not ascii_host or not ascii_host.rstrip("."):
        if ascii_host is None and arg_fallback:
            return _fallback(raw_host)
        return None
    return _name_authority(ascii_host)


def _case_readings(raw_host: str) -> List[Authority]:
    """The hosts Python's clients send ``raw_host`` to when they lowercase it with
    ``str.lower`` before encoding it: httpx lowercases the whole host, urllib3
    and requests each label, then each encodes with the ``idna`` package, which
    applies UseSTD3ASCIIRules and CheckHyphens. Where ``str.lower`` reads
    otherwise than the table (Final_Sigma, a letter the pinned Unicode disallows),
    that is another destination; where it reads the same, there is none.
    ``str.lower`` is taken as every supported interpreter computes it
    (``lower_by_unicode``), not as this one does, so the readings are the same on
    every interpreter."""
    host = raw_host.strip().rstrip(".")
    if host.isascii() or "%" in host or ":" in host or any(c.isspace() for c in host):
        return []
    out: List[Authority] = []
    labels = [lower_by_unicode(x) for x in host.split(".")]
    candidates = []
    for i, whole in enumerate(lower_by_unicode(host)):
        for lowered in (whole, ".".join(v[i] for v in labels)):
            if lowered not in candidates:
                candidates.append(lowered)
    for lowered in candidates:
        ascii_host = to_ascii(lowered, strict=True)
        if ascii_host:
            a = _name_authority(ascii_host)
            if a is not None and a not in out:
                out.append(a)
    return out


# Percent-encoding of an ASCII host, as each Python client sends it. RFC 3986's
# unreserved characters; httpx's ``encode_host`` keeps the sub-delims and
# '"`{}%|\\' too, and requests' ``requote_uri`` keeps "!#$%&'()*+,/:;=?@[]~".
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_HTTPX_KEEPS = _UNRESERVED | frozenset("!$&'()*+,;=\"`{}%|\\")
_REQUESTS_KEEPS = _UNRESERVED | frozenset("!#$%&'()*+,/:;=?@[]~")
_PCT_RE = re.compile(r"%([0-9A-Fa-f]{2})")


def _quote(host: str, keep) -> str:
    return "".join(c if c in keep else "%%%02X" % ord(c) for c in host)


def _urllib3_host(host: str) -> Optional[str]:
    """urllib3's ``_normalize_host``: an escape of an unreserved character decoded,
    every other escape kept; None where it refuses the host (a ``%`` that is no
    escape, a control or a space)."""
    if any(c <= " " or c == "\x7f" for c in host):
        return None
    out = _PCT_RE.sub(lambda m: chr(int(m.group(1), 16)) if chr(int(m.group(1), 16))
                      in _UNRESERVED else m.group(0), host)
    return None if "%" in _PCT_RE.sub("", out) else out


def _client_spellings(raw_host: Optional[str], clients) -> List[Authority]:
    """The names an ASCII host is sent as by ``clients``, beside the decoded
    reading every split already has (WHATWG's, and urllib.request's of the RFC
    3986 split): ``"literal"`` as written (urllib.parse), ``"httpx"`` as httpx
    percent-encodes it, ``"urllib3"`` with only the escapes of unreserved
    characters decoded, ``"requests"`` that, re-quoted. Every one is a reading:
    the literal form a client sends counts as well as the decoded one."""
    host = (raw_host or "").rstrip(".")       # a space is httpx's to encode, not to drop
    if (not host or not host.isascii() or ":" in host or host.startswith("[")
            or all(c in _UNRESERVED for c in host)):
        return []
    spellings = []
    if "literal" in clients:
        spellings.append(host)
    if "httpx" in clients:
        spellings.append(_quote(host.lower(), _HTTPX_KEEPS))
    u3 = _urllib3_host(host) if ("urllib3" in clients or "requests" in clients) else None
    if u3 is not None:
        if "urllib3" in clients:
            spellings.append(u3)
        if "requests" in clients:
            spellings.append(_quote(u3, _REQUESTS_KEEPS))
    out: List[Authority] = []
    for name in spellings:
        if any(c.isspace() for c in name):
            continue
        ascii_host = to_ascii(name)
        a = _name_authority(ascii_host) if ascii_host else _fallback(name)
        if a is not None and a not in out:
            out.append(a)
    return out


def _httpx_host(url: str) -> Optional[str]:
    """The host httpx's own parser takes from ``url``: the authority runs to the
    first ``/``, ``?`` or ``#`` (a backslash is no delimiter), the host follows its
    last ``@``, and a ``[`` matters only where it opens the host; anywhere else
    httpx percent-encodes it with the rest of the name."""
    m = _SCHEME_RE.match(url)
    if not m:
        return None
    rest = url[m.end():]
    end = _AUTHORITY_END_RE.search(rest)
    hostinfo = (rest[:end.start()] if end else rest).rpartition("@")[2]
    if hostinfo.startswith("["):
        return None                        # a bracketed literal: the other readings' rule
    return hostinfo.partition(":")[0] or None


# ── URLs ─────────────────────────────────────────────────────────────────────
# Any scheme token before `://`: urllib.parse on 3.10 splits a scheme that
# opens with a digit, `.`, `+` or `-`, and WHATWG and urllib.parse read the host
# after a scheme of any length.
_SCHEME_RE = re.compile(r"^([A-Za-z0-9+.\-]{1,256})://")
# A WHATWG special scheme other than file: takes its
# authority after ANY run of '/' and '\', so `http:evil.test`, `http:/evil.test`,
# `http:\\evil.test` and `http:///evil.test` all name evil.test. Such a value is
# rewritten to `scheme://` and parsed as one. A non-special scheme with no `//`
# has no host (`gopher:evil.test`), as WHATWG and urllib.parse agree.
_SPECIAL_RE = re.compile(r"^(https?|wss?|ftp):[/\\]*(?=[^\s/\\])", re.IGNORECASE)
# `host/path` with no scheme — ≥2 labels, alphabetic final label, an optional
# port, and a path. Labels are \w so a Unicode host is accepted here too (ruling
# 3.6), and may carry escapes, which urllib3 sends as they are written. A client
# that guesses `http://` (curl) sends `evil.test:8080/x` to evil.test (ruling 2).
_IMPLIED_RE = re.compile(r"^((?:[\w\-%]{1,63}\.){1,126}[^\W\d_]{1,63})(?::[0-9]{0,5})?[/?#]")
# No scheme, a host in any inet_aton spelling (integer, hex, octal, short or
# mixed dotted forms), then a port, path, query or fragment. A client that
# guesses `http://` sends it to the address that host denotes (ruling 2). Read for
# ARGUMENTS only: recorded from a result it would make a numeric path in a file
# listing an address that a later call to that path matches.
_IMPLIED_INT_RE = re.compile(r"^([0-9][0-9A-Za-z.]{0,63})(?::[0-9]{0,5}(?![^/?#])|(?=[/?#]))")
# No scheme, a STRICT address literal (a dotted quad, or IPv6 in brackets, with
# or without a zone), then a port (an empty one too: urllib3 connects to the
# default), path, query or fragment.
# Read in results too; the integer spellings above are read in arguments only.
_IMPLIED_IP_RE = re.compile(r"^(\[[0-9A-Fa-f:.]{2,45}(?:%[^\]\s/?#@]{1,64})?\]"
                            r"|[0-9]{1,3}(?:\.[0-9]{1,3}){3})"
                            r"(?::[0-9]{0,5}(?![^/?#])|(?=[/?#]))")
_NON_DESTINATION_SCHEMES = frozenset({"file", "data"})
# urllib3 takes a scheme only when it is a letter then letters, digits, + and -
# (``parse_url``); before any other `X://` it puts `//`, so X is the HOST it
# connects to (`hej.hej://example.net` goes to hej.hej, `0://x` to 0.0.0.0).
_URLLIB3_SCHEME_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+\-]*")
_SCHEME_AS_HOST_RE = re.compile(r"^([^\s:/?#\[\]@\\]{1,253})://")
_TAB_NEWLINE = str.maketrans("", "", "\t\n\r")
_C0_OR_SPACE = "".join(map(chr, range(0x21)))
# Q1: where an RFC 3986 authority ends (urlsplit's netloc delimiters).
_AUTHORITY_END_RE = re.compile(r"[/?#]")
# urlsplit's IPvFuture literal (`_check_bracketed_host`), its `v` either case:
# RFC 3986's ABNF is case-insensitive, and urllib.parse on 3.14.9 reads `[V6a.ip]`.
_IPVFUTURE_RE = re.compile(r"[vV][a-fA-F0-9]{1,32}\..{1,64}")

# Sentinels for the argument walk's three-way answer.
NOT_A_DESTINATION = None


class ParseFailure:
    """Destination-shaped and unparseable: UNRESOLVED, never no_destination.

    ``parsed`` holds the parts of a mailbox list that DID parse:
    the value is still UNRESOLVED as a whole, and each of them is its own finding.
    """

    __slots__ = ("parsed",)

    def __init__(self, parsed=()) -> None:
        self.parsed: Tuple[Authority, ...] = tuple(parsed)


PARSE_FAILURE = ParseFailure()


def _split_host(url: str):
    """(host as written or None, parse_ok) for ONE authority split of ``url``, as
    CPython 3.12.2's ``urlsplit`` reads it, written out (``_authority_host``): the
    interpreter's own ``urlsplit`` refuses different netlocs on different patch
    releases, so whether a value is a parse failure would follow the interpreter
    (V-4)."""
    m = _SCHEME_RE.match(url)
    if not m:
        return None, True
    rest = url[m.end():]
    end = _AUTHORITY_END_RE.search(rest)
    if _urlsplit_3_12_2_refuses(rest[:end.start()] if end else rest):
        return None, False
    return _authority_host(url, whatwg=False), True


def _whatwg(value: str) -> str:
    """``value`` (which starts with ``scheme://``) as WHATWG splits it:
    backslashes in the scheme-relative part are slashes, as WHATWG treats them
    for special schemes."""
    m = _SCHEME_RE.match(value)
    return value[:m.end()] + value[m.end():].replace("\\", "/")


def _urlsplit_3_12_2_refuses(netloc: str) -> bool:
    """The netloc checks of CPython 3.12.2's ``urlsplit``, the most permissive
    version measured (2026-10-03): brackets must balance, the FIRST bracketed
    segment of the netloc must be an IPv6 or IPvFuture literal, and no
    character may NFKC-normalise into a delimiter (``_checknetloc``). Later
    patch releases also check the bracket in the host itself, after the last
    ``@``, and refuse more; reading what 3.12.2 reads is the superset."""
    if ("[" in netloc) != ("]" in netloc):
        return True
    if "[" in netloc:
        first = netloc.partition("[")[2].partition("]")[0]
        if first[:1] in ("v", "V"):
            if not _IPVFUTURE_RE.fullmatch(first):
                return True
        else:
            try:
                if not isinstance(ipaddress.ip_address(first), ipaddress.IPv6Address):
                    return True
            except ValueError:
                return True
    if not netloc.isascii():
        # urlsplit asks NFKC; the pinned table's mapping answers the same for the
        # code points it maps, and does not change with the interpreter (V-4).
        bare = netloc.replace("@", "").replace(":", "").replace("#", "").replace("?", "")
        folded = fold(bare)
        if folded != bare and any(c in folded for c in "/?#@:"):
            return True
    return False


def _authority_host(url: str, *, whatwg: bool) -> Optional[str]:
    """The host of ``url``'s authority, without delegating to this interpreter's
    ``urlsplit``; None if there is none.

    The authority runs from ``//`` to the first ``/``, ``?`` or ``#``, and the
    host follows its LAST ``@``. No ``//`` is no authority (R4's
    ``http:\\\\host``). A backslash is no delimiter to RFC 3986: httpx,
    urllib.parse and urllib.request hand the whole name, backslash included, to
    the resolver, so it is read whole. Brackets differ by reading, because the
    consumers differ:

      * ``whatwg=False``, the RFC 3986 reading (urllib.parse, httpx): exactly
        what CPython 3.12.2's ``urlsplit(...).hostname`` reads, the most
        permissive version measured. The host is the part between the first
        ``[`` of the host and the next ``]``, otherwise the part before the
        first ``:``. A netloc 3.12.2 refuses is no host
        (``_urlsplit_3_12_2_refuses``); 3.12.2 validates only the netloc's
        first bracketed segment, and later patch releases refuse more.
        urllib.parse is a covered
        consumer, and xaidr's own ``ProtectedHttpClient._extract_host`` decides
        destination policy with it. ``urllib.request``, by contrast, passes the
        netloc on, percent-decoded and userinfo
        included, and reaches neither host (it DOES reach a percent-encoded host).
      * ``whatwg=True``, used only where ``urlsplit`` refused the WHATWG string:
        WHATWG's host rule. A ``[`` must open the host and enclose an IPv6
        literal. Any other bracket means no host, as WHATWG refuses it.

    Written out rather than delegated, because ``urlsplit`` is not the same
    function on every interpreter (V-4) and because what it REFUSES, a transport
    may still send: its bracketed-host validation differs between patch
    releases, and some netlocs it refuses are ones httpx, urllib3 and WHATWG
    send to.
    """
    m = _SCHEME_RE.match(url)
    if not m:
        return None
    rest = url[m.end():]
    end = _AUTHORITY_END_RE.search(rest)
    netloc = rest[:end.start()] if end else rest
    hostinfo = netloc.rpartition("@")[2]
    if whatwg:
        if hostinfo.startswith("[") and "]" in hostinfo:
            host = hostinfo[1:].partition("]")[0]
            if not isinstance(_strict_ip(host) or _zoned_ip(host), ipaddress.IPv6Address):
                return None
        elif "[" in hostinfo or "]" in hostinfo:
            return None
        else:
            host = hostinfo.partition(":")[0]
    else:
        if _urlsplit_3_12_2_refuses(netloc):
            return None
        _, bracket, inside = hostinfo.partition("[")
        host = inside.partition("]")[0] if bracket else hostinfo.partition(":")[0]
    return host or None


# ── the standard library's clients: urllib.request and http.client ──────────
# Written out from CPython's urllib.request.Request (unwrap, _splittag, _splittype,
# _splithost, unquote) and http.client.HTTPConnection (_get_hostport,
# _validate_host), the same on every supported interpreter.
_STDLIB_TYPE_RE = re.compile(r"([^/:]+):(.*)", re.DOTALL)
_STDLIB_HOST_RE = re.compile(r"//([^/#?]*)(.*)", re.DOTALL)
_STDLIB_CTRL_RE = re.compile(r"[\x00-\x20\x7f]")
_STDLIB_SCHEMES = ("http", "https")


def _unwrap(url: str) -> str:
    """urllib.parse.unwrap: ``<URL:scheme://host/path>`` -> ``scheme://host/path``."""
    url = url.strip()
    if url[:1] == "<" and url[-1:] == ">":
        url = url[1:-1].strip()
    if url[:4] == "URL:":
        url = url[4:].strip()
    return url


def _int_port(text: str) -> bool:
    """What ``int()`` accepts as a port: an optional sign, decimal digits (Unicode
    13.0's, so no interpreter decides otherwise) with single underscores between."""
    t = text.strip()
    t = t[1:] if t[:1] in "+-" else t
    parts = t.split("_")
    return bool(t) and all(p and all(c.isdecimal() and assigned(c) for c in p) for p in parts)


def _http_client_host(hostport: str) -> Optional[str]:
    """http.client's host for ``HTTPConnection(hostport)``: a port after the LAST
    ``:`` that follows any ``]`` (an unbracketed IPv6 address loses its last group
    to the port), brackets around the rest removed; None where it refuses."""
    i, j = hostport.rfind(":"), hostport.rfind("]")
    host = hostport
    if i > j:
        port = hostport[i + 1:]
        if port and not _int_port(port):
            return None                        # InvalidURL: nonnumeric port
        host = hostport[:i]
    if host[:1] == "[" and host[-1:] == "]":
        host = host[1:-1]
    if not host or _STDLIB_CTRL_RE.search(host):
        return None
    return host


def stdlib_hosts(value: str) -> List[str]:
    """The hosts the standard library's clients hand the resolver for ``value``:
    ``urllib.request.urlopen`` (the value unwrapped, the netloc percent-decoded,
    userinfo included) and ``http.client.HTTPConnection`` given the netloc as
    written."""
    out: List[str] = []
    url = _unwrap(value)
    url = url.rpartition("#")[0] if "#" in url else url
    m = _STDLIB_TYPE_RE.match(url)
    if m and m.group(1).lower() in _STDLIB_SCHEMES:
        h = _STDLIB_HOST_RE.match(m.group(2))
        if h and h.group(1):
            host = _http_client_host(unquote(h.group(1)))
            if host:
                out.append(host)
    written = value.strip(_C0_OR_SPACE).strip().translate(_TAB_NEWLINE)
    m = _SCHEME_RE.match(written)
    if m and m.group(1).lower() in _STDLIB_SCHEMES:
        rest = written[m.end():]
        end = _AUTHORITY_END_RE.search(rest)
        netloc = rest[:end.start()] if end else rest
        host = _http_client_host(netloc) if netloc else None
        if host and host not in out:
            out.append(host)
    return out


def resolver_keys(host: str) -> List[Authority]:
    """The keys a host string reaches through the platform resolver: an IP literal;
    else the name, encoded as the socket layer encodes a non-ASCII name (IDNA 2003,
    the older encoding: ``straße`` is ``strasse``; ``idna2003`` gives every interpreter's
    encoding, on every interpreter), every numeric reading of it, and, for a
    numeric name with a trailing dot or a host with a bracket left in it, the DNS
    name it is (no numeric parser takes the dot or the bracket)."""
    ip = _strict_ip(host)
    if ip is not None:
        return [Authority(scheme="ip", value=ip_key(ip))]
    out: List[Authority] = []
    for name in ([host] if host.isascii() else idna2003(host)):
        name = name.lower()
        a = _name_authority(name)
        if a is not None and a not in out:
            out.append(a)
        if "[" in name or "]" in name:
            # getaddrinfo reads no bracket: a host that keeps one (``[::%x];80``,
            # whatever ``ipaddress`` makes of its scope) is a name it looks up.
            d = Authority(scheme="dns", value=dns_key(name.rstrip(".")))
            if d not in out:
                out.append(d)
        out.extend(b for b in _macos_readings(name) if b not in out)
        t = _trailing_dot_name(name)
        if t is not None and t not in out:
            out.append(t)
    return out


def _trailing_dot_name(host: str) -> Optional[Authority]:
    """A numeric host written with a trailing dot (``127.0.0.1.``) is a DNS NAME to
    the resolver and to every Python client, though WHATWG reads the address."""
    h = host.strip()
    if not h.endswith(".") or ":" in h:
        return None
    bare = h.rstrip(".")
    if not bare or coerce_ip(bare) is None:
        return None
    return Authority(scheme="dns", value=dns_key(bare.lower()))


# ── the macOS resolver (Q22, RE-RULED 2026-10-04) ───────────────────────────
_DEC_QUAD_RE = re.compile(r"[0-9]+(?:\.[0-9]+){3}")


def _leading_zero_decimal(parts: List[str]):
    """A leading-zero dotted quad read as DECIMAL, as the macOS resolver does,
    however many zeros a part carries."""
    if not any(len(p) > 1 and p[0] == "0" for p in parts):
        return None
    vals = []
    for p in parts:
        digits = p.lstrip("0") or "0"
        if len(digits) > 3:
            return None
        vals.append(int(digits, 10))
    return ".".join(map(str, vals)) if all(v <= 255 for v in vals) else None


def _macos_resolver_ip(host: str):
    """The address the macOS resolver reads ``host`` as, where it differs from
    the inet_aton / WHATWG reading the core makes, else None. The resolver reads
    a leading-zero dotted quad as decimal, the IPv4 tail of an IPv6 literal the
    same way, and one number above 2**32 - 1 modulo 2**32, in decimal, hex or
    octal. glibc and WHATWG refuse all three."""
    if ":" in host:
        head, _, tail = host.rpartition(":")
        if head and _DEC_QUAD_RE.fullmatch(tail):
            quad = _leading_zero_decimal(tail.split("."))
            if quad is not None:
                try:
                    return ipaddress.ip_address(head + ":" + quad)
                except ValueError:
                    return None
        return None
    if _DEC_QUAD_RE.fullmatch(host):
        quad = _leading_zero_decimal(host.split("."))
        return ipaddress.ip_address(quad) if quad is not None else None
    if "." not in host and 0 < len(host) <= 64:
        lp = host.lower()
        if lp.startswith("0x"):
            n = int(lp[2:], 16) if lp[2:] and set(lp[2:]) <= _HEX_DIGITS else None
        elif len(lp) > 1 and lp[0] == "0":
            n = int(lp, 8) if set(lp) <= _OCT_DIGITS else None
        else:
            n = int(lp, 10) if lp.isascii() and lp.isdigit() else None
        if n is not None and n > 0xFFFFFFFF:
            return ipaddress.ip_address(n % (1 << 32))
    return None


def _raw_split_host(url: str) -> Optional[str]:
    """The authority's host with NO validation: after the last `@`, inside the
    brackets or before the port. Used only to find macOS readings, which a
    validating split can refuse."""
    m = _SCHEME_RE.match(url)
    if not m:
        return None
    rest = url[m.end():]
    end = _AUTHORITY_END_RE.search(rest)
    hostinfo = (rest[:end.start()] if end else rest).rpartition("@")[2]
    if hostinfo.startswith("[") and "]" in hostinfo:
        return hostinfo[1:].partition("]")[0]
    return hostinfo.partition(":")[0] or None


def _macos_readings(raw_host: Optional[str]) -> List[Authority]:
    """Every macOS-resolver reading is read, on every platform (a verdict does
    not depend on where the agent runs), public addresses included: a
    destination named by untrusted content is a finding wherever it points."""
    if not raw_host:
        return []
    h = raw_host.strip().rstrip(".")
    if "%" in h:
        try:
            h = unquote_to_bytes(h).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return []
    if ":" not in h:
        h = (to_ascii(h) or "").rstrip(".")
    try:
        ip = _macos_resolver_ip(h) if h else None
    except ValueError:
        return []
    if ip is None:
        return []
    return [Authority(scheme="ip", value=ip_key(ip))]


def url_authority(value: str, *, arg_mode: bool, written: Optional[str] = None):
    """Authority of a whole-value URL; None if hostless; PARSE_FAILURE if broken.

    Q1 (2026-10-03, amends V-23): EVERY reading of the authority split that a
    real consumer performs is a destination, and the weakest decides the wire.
    The readings are

      * WHATWG (backslash is a slash; urllib3 and ada agree), split as the RFC
        3986 reading splits (``_split_host``);
      * RFC 3986 (backslash is userinfo; urllib.parse and httpx agree) of the
        value as ``written``, before R4's special-scheme rewrite;
      * where ``urlsplit`` REFUSES the WHATWG string, that string's authority
        split anyway — a refusal by one parser is not a refusal by the
        transport.

    A backslash in the userinfo is one host to WHATWG and another to httpx and
    urllib.parse, so both are destinations. Distinct
    authorities come back as a list, WHATWG first — the mailbox-list shape — and
    readings that normalise to one authority are one answer. A value
    ``urlsplit`` refuses stays PARSE_FAILURE (decision 7), carrying what the
    other readings found: R1's shape, so an untrusted host still decides.
    """
    m = _SCHEME_RE.match(value)
    if not m:
        return NOT_A_DESTINATION
    if m.group(1).lower() in _NON_DESTINATION_SCHEMES:
        return NOT_A_DESTINATION
    whatwg = _whatwg(value)
    host, ok = _split_host(whatwg)
    if not ok:
        primary = PARSE_FAILURE
    elif not host:
        primary = NOT_A_DESTINATION              # hostless (C-6)
    else:
        primary = _host_authority(host, arg_fallback=arg_mode) or PARSE_FAILURE
    as_written = value if written is None else written
    rfc = _authority_host(as_written, whatwg=False)        # RFC 3986, as urlsplit 3.12.2 reads it
    others = [rfc,
              _authority_host(as_written, whatwg=True)]    # httpx: brackets checked in the HOST only
    if not ok:
        others.insert(0, _authority_host(whatwg, whatwg=True))          # what urlsplit refused
    extra = []
    for h in others:
        a = _host_authority(h, arg_fallback=arg_mode) if h else None
        if a is not None and a != primary and a not in extra:
            extra.append(a)
    for h in [host] + others:      # the str.lower readings; IPv6 zones; numeric names
        for a in (_case_readings(h) + _zone_readings(h)) if h else ():
            if a != primary and a not in extra:
                extra.append(a)
        t = _trailing_dot_name(h) if h else None
        if t is not None and t != primary and t not in extra:
            extra.append(t)
    # The spellings each client sends a host in, by the split it makes: urllib3 and
    # requests split as WHATWG does and send http and https only; urllib.parse and
    # httpx keep a backslash.
    web = m.group(1).lower() in ("http", "https")
    spelled = (_client_spellings(host, ("urllib3", "requests") if web else ())
               + _client_spellings(rfc, ("literal",))
               + _client_spellings(_httpx_host(as_written), ("httpx",)))
    for a in spelled:
        if a != primary and a not in extra:
            extra.append(a)
    for raw in (_raw_split_host(whatwg), _raw_split_host(value if written is None else written)):
        for a in _macos_readings(raw):               # Q22, re-ruled 2026-10-04
            if a != primary and a not in extra:
                extra.append(a)
    if not extra:
        if primary is PARSE_FAILURE and not arg_mode:
            return NOT_A_DESTINATION
        return primary
    if isinstance(primary, Authority):
        return [primary, *extra]
    if primary is PARSE_FAILURE:                 # R1's shape: UNRESOLVED, plus what parsed
        if arg_mode:
            return ParseFailure(extra)
    return extra[0] if len(extra) == 1 else extra   # hostless or refused to WHATWG


def implied_url_authority(value: str, *, arg_mode: bool):
    """A scheme-less ``host[:port]/path`` read as a URL with an implied ``http://``,
    every reading of its authority included (Q1, ruling 2)."""
    m = _IMPLIED_RE.match(pinned(value))
    if not m:
        return NOT_A_DESTINATION
    res = url_authority("http://" + value, arg_mode=arg_mode)
    if res is NOT_A_DESTINATION and arg_mode:
        return PARSE_FAILURE
    return res


def _implied_ip_authority(value: str, *, arg_mode: bool):
    """A scheme-less integer-spelled address with a locator, read as ``http://value``.
    Kept only when some reading is an address: a host no resolver reads as a
    number is a bare name, and a bare name is never a destination."""
    res = url_authority("http://" + value, arg_mode=arg_mode)
    found = (res.parsed if isinstance(res, ParseFailure)
             else res if isinstance(res, list) else [res] if isinstance(res, Authority) else [])
    if not any(a.scheme == "ip" for a in found):
        return NOT_A_DESTINATION
    return res


# ── mailboxes (rulings 3.2 / 3.6) ───────────────────────────────────────────
_LOCAL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~\-]{1,64}")
_ASCII_DOMAIN_RE = re.compile(r"[A-Za-z0-9\-_]{1,63}(?:\.[A-Za-z0-9\-_]{1,63}){0,126}")
_DISPLAY_RE = re.compile(r"^(?P<display>[^<>]{0,256})<(?P<addr>[^<>]{1,320})>$")


_QUOTED_LOCAL_RE = re.compile(r'"(?:[\x20\x21\x23-\x5b\x5d-\x7e]|\\[\x20-\x7e]){0,62}"')
_DOMAIN_LITERAL_RE = re.compile(r"\[(?:[0-9.]{7,15}|IPv6:[0-9A-Fa-f:.]{2,45})\]", re.I)


def mailbox_authority(addr: str) -> Optional[Authority]:
    """``local@domain`` → ``mailto:`` authority, or None if it fails the grammar.

    The local part is ASCII by grammar, a dot-atom or a quoted string: a
    non-ASCII local part is not a mailbox this core can compare (ruling 3.6:
    UNRESOLVED when it is an argument). The domain may be Unicode and is
    UTS-46-encoded first; an address literal (``[192.0.2.1]``) is kept as written.
    """
    local, at, domain = addr.rpartition("@")
    if not at or "@" in local.replace('\\"', "").strip('"') and not local.startswith('"'):
        return None
    if not (_LOCAL_RE.fullmatch(local) or _QUOTED_LOCAL_RE.fullmatch(local)):
        return None
    if _DOMAIN_LITERAL_RE.fullmatch(domain):
        inner = domain[1:-1]
        ip = _strict_ip(inner[5:] if inner.lower().startswith("ipv6:") else inner)
        if ip is None:
            return None
        return Authority(scheme="mailto", value=f"{local.lower()}@[{inner.lower()}]")
    ascii_domain = _mail_domain(domain)
    if ascii_domain is None:
        return None
    return Authority(scheme="mailto", value=f"{local.lower()}@{ascii_domain}")


def _mail_domain(domain: str) -> Optional[str]:
    """The domain a mail client sends to: UTS-46 where it applies; an ASCII
    name it refuses (an xn-- label that fails CheckBidi, say) as written, since a
    mail client does not validate it; one label too, as a resolver reads it."""
    d = domain.rstrip(".") if domain.endswith(".") and not domain.endswith("..") else domain
    ascii_domain = to_ascii(d)
    if ascii_domain is not None:
        ascii_domain = ascii_domain.rstrip(".")
    elif d.isascii():
        ascii_domain = d.lower()
    if ascii_domain is None or not _ASCII_DOMAIN_RE.fullmatch(ascii_domain) or len(ascii_domain) > 253:
        return None
    return ascii_domain


def _split_mailbox_list(value: str) -> Optional[List[str]]:
    """Split on ``,`` and ``;`` outside ``<…>`` and ``"…"``. None if the
    quoting does not balance."""
    parts, cur = [], []
    in_quote = in_angle = False
    for ch in value:
        if ch == '"' and not in_angle:
            in_quote = not in_quote
        elif ch == "<" and not in_quote:
            if in_angle:
                return None
            in_angle = True
        elif ch == ">" and not in_quote:
            if not in_angle:
                return None
            in_angle = False
        elif ch in ",;" and not in_quote and not in_angle:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    if in_quote or in_angle:
        return None
    parts.append("".join(cur))
    return parts


def _mailbox_part(part: str) -> Optional[Authority]:
    p = part.strip()
    m = _DISPLAY_RE.match(p)
    if m:
        return mailbox_authority(m.group("addr").strip())
    return mailbox_authority(p)


_DISPLAY_OPEN_RE = re.compile(r'^\s*(?:"[^"]{0,256}"|[^<>"@,;]{0,256}?)\s*<\s*$')


def _known(ch: str) -> bool:
    """A code point the pinned Unicode (13.0) allows in a name. A letter newer
    than that is a letter to one interpreter and not to another, so it counts as
    neither (V-4)."""
    return ch.isascii() or _status(ch)[0] != "D"


def _alnum(ch: str) -> bool:
    return ch.isalnum() and _known(ch)


def _drop_comments(s: str) -> str:
    """``s`` without its RFC 5322 comments (nested, ``\\`` escaping), a comment left
    open running to the end, as the legacy parser reads it."""
    if "(" not in s:
        return s
    out, depth, i = [], 0, 0
    while i < len(s):
        c = s[i]
        if depth and c == "\\":
            i += 2
            continue
        if c == "(":
            depth += 1
        elif c == ")" and depth:
            depth -= 1
        elif not depth:
            out.append(c)
        i += 1
    return "".join(out)


def _mailbox_in_junk(part: str) -> Optional[Authority]:
    """The one mailbox in a part that does not parse, when everything around it
    is junk (no letter or digit) or a display name opening ``<``; else None."""
    found = None
    for m in _J_EMAIL_RE.finditer(pinned(part)):
        if found is not None:
            return None                        # two addresses: not one mailbox in junk
        found = m
    if found is None:
        return None
    before, after = part[:found.start()], part[found.end():]
    if before and _alnum(before[-1]):
        return None                            # starts mid-word: `jürgen@` is not `rgen@`
    # RFC 5322 comments are CFWS: the email parsers drop them, open or closed.
    before, after = _drop_comments(before), _drop_comments(after)
    if any(_alnum(c) for c in after):
        return None                            # `user@evil.test/x`, or prose after it
    if any(_alnum(c) for c in before) and not _DISPLAY_OPEN_RE.match(before):
        return None                            # prose before it
    return mailbox_authority(part[found.start():found.end()].rstrip(".-"))


# One address-like token (text, `@`, text, no space), or a display name and an
# angle address, alone in a part: an address the grammar may still refuse
# (`jürgen@x.example`), which stays an unparseable address list (3.6).
_ADDRESS_SHAPED_RE = re.compile(r"\s*(?:[^\s<>@,;]+@[^\s<>@,;]+|[^<>@]*<[^<>]*@[^<>]*>?)\s*")


def _address_shaped(value: str) -> bool:
    v = value.strip()
    if v[:1] == "<" and v[-1:] == ">" and "@" in v:
        return True                  # one angle address, whatever the grammar makes of it
    parts = _split_mailbox_list(value) or re.split(r"[,;]", value)
    if any(_ADDRESS_SHAPED_RE.fullmatch(p) for p in parts if p.strip()):
        return True
    return _shaped_5322(value) or bool(_rfc5322_addresses(value)[0])


# ── RFC 5322 address lists ───────────────────────────────────────────────────
# A backslash outside a quoted string is no RFC 5322 special: it stays in its
# atom, so a local part or domain holding one is refused, never rejoined.
_SPECIALS = '()<>@,;:."[]'


def _tokens5322(s: str, *, tolerant: bool = False):
    """``s`` as RFC 5322 tokens: (kind, text) with kind ``atom``, ``quoted``,
    ``literal`` or one of ``<>@,;:.``. Comments and whitespace (CFWS) are dropped.
    None when a quoted string, a comment or a literal does not close, unless
    ``tolerant``: then it runs to the end of the value, as the legacy parser reads it."""
    out, i, n = [], 0, len(s)
    glue = -1                                    # where an atom glues onto the one before
    while i < n:
        c = s[i]
        if c.isspace():
            i += 1
        elif c == "(":
            if out and out[-1][0] == "atom" and i > 0 and not s[i - 1].isspace():
                start = i
            else:
                start = -1
            depth, i = 1, i + 1
            while i < n and depth:
                if s[i] == "\\":
                    i += 1
                elif s[i] == "(":
                    depth += 1
                elif s[i] == ")":
                    depth -= 1
                i += 1
            if depth and not tolerant:
                return None
            # A comment between two atoms with no space either side joins them,
            # as the email parsers read `xn--(o)-x` as `xn---x`.
            glue = i if start >= 0 else -1
        elif c == '"':
            j = i + 1
            while j < n and s[j] != '"':
                j += 2 if s[j] == "\\" else 1
            if j >= n:
                if not tolerant:
                    return None
                j = n - 1
            out.append(("quoted", s[i:j + 1]))
            i = j + 1
        elif c == "[":
            j = s.find("]", i)
            if j < 0:
                if not tolerant:
                    return None
                j = n - 1
            out.append(("literal", s[i:j + 1]))
            i = j + 1
        elif c in "<>@,;:.":
            out.append((c, c))
            i += 1
        else:
            j = i
            while j < n and not s[j].isspace() and s[j] not in _SPECIALS:
                j += 1
            if j == i:
                out.append(("junk", c))          # a stray `)` or `]`: no address runs across it
                i += 1
                continue
            if glue == i and out and out[-1][0] == "atom":
                out[-1] = ("atom", out[-1][1] + s[i:j])
            else:
                out.append(("atom", s[i:j]))
            glue = -1
            i = j
    return out


_BEFORE_LOCAL = frozenset({",", ";", "<", ":", ">", "@"})
_AFTER_DOMAIN = frozenset({",", ";", ">", "<", ":"})


def _addr_spec_at(toks, k):
    """The addr-spec around the ``@`` at ``toks[k]``: (start, end, text) or None.
    It must stand alone: the value's start or a separator before its local part,
    and its end or a separator after its domain (a trailing dot allowed), so no
    address is read out of text run into it."""
    n = len(toks)
    if k == 0 or toks[k - 1][0] not in ("atom", "quoted") or k + 1 >= n:
        return None
    j = k - 1
    while j >= 2 and toks[j - 1][0] == "." and toks[j - 2][0] in ("atom", "quoted"):
        j -= 2
    if j > 0 and toks[j - 1][0] not in _BEFORE_LOCAL:
        return None
    local = "".join(text for _, text in toks[j:k])
    if toks[k + 1][0] == "literal":
        m = k + 1
    elif toks[k + 1][0] == "atom":
        m = k + 1
        while m + 2 < n and toks[m + 1][0] == "." and toks[m + 2][0] == "atom":
            m += 2
    else:
        return None
    end = m + 1
    nxt = end + 1 if end < n and toks[end][0] == "." else end
    if nxt < n and toks[nxt][0] not in _AFTER_DOMAIN:
        return None
    domain = "".join(text for _, text in toks[k + 1:m + 1])
    return j, end, f"{local}@{domain}"


def _parse_mailbox(toks, i):
    """name-addr / addr-spec at ``toks[i]``: (next index, addr) or None."""
    n = len(toks)
    j = i
    while j < n and toks[j][0] in ("atom", "quoted", "."):
        j += 1
    if j < n and toks[j][0] == "<":                # [phrase] < [route] addr-spec >
        k = j + 1
        if k < n and toks[k][0] == "@":            # obs-route: @a,@b:
            while k < n and toks[k][0] != ":":
                k += 1
            k += 1
        at = next((x for x in range(k, n) if toks[x][0] in ("@", ">")), None)
        if at is None or toks[at][0] != "@":
            return None
        spec = _addr_spec_at(toks, at)
        if spec is None or spec[0] != k or spec[1] >= n or toks[spec[1]][0] != ">":
            return None
        return spec[1] + 1, spec[2]
    at = next((x for x in range(i, n) if toks[x][0] not in ("atom", "quoted", ".")), None)
    if at is None or toks[at][0] != "@":
        return None
    spec = _addr_spec_at(toks, at)
    if spec is None or spec[0] != i:
        return None
    return spec[1], spec[2]


def _parse_address_list(toks):
    """RFC 5322 address-list (groups, obs empty elements): the addr-specs, or None
    when the tokens are not one."""
    out, i, n = [], 0, len(toks)
    while i < n:
        if toks[i][0] in (",", ";"):
            i += 1
            continue
        j = i
        while j < n and toks[j][0] in ("atom", "quoted", "."):
            j += 1
        if j < n and toks[j][0] == ":" and j > i:      # group: phrase : [list] ;
            i = j + 1
            continue
        got = _parse_mailbox(toks, i)
        if got is None:
            return None
        i, addr = got
        out.append(addr)
        if i < n and toks[i][0] not in (",", ";"):
            return None
    return out


_HEADER_LINE_RE = re.compile(r"^[!-9;-~]{1,76}:[ \t]*(.*)$", re.M)
_ANGLE_RE = re.compile(r"<[^<>]{0,512}@[^<>]{0,512}>")


def _part_is_a_mailbox(toks) -> bool:
    got = _parse_mailbox(toks, 0) if toks else None
    return got is not None and got[0] == len(toks)


def _shaped_5322(value: str) -> bool:
    """Some `,`/`;` part of the value is exactly one mailbox, comments aside."""
    toks = _tokens5322(value, tolerant=True) or []
    part: list = []
    for tok in toks + [(",", ",")]:
        if tok[0] in (",", ";"):
            if _part_is_a_mailbox(part):
                return True
            part = []
        elif tok[0] == ":" and part and all(k in ("atom", "quoted", ".") for k, _ in part):
            part = []                            # a group's name
        else:
            part.append(tok)
    return False


def _rfc5322_addresses(value: str) -> Tuple[List[str], bool]:
    """(addr-specs, whether the value IS an address list). A value that is one
    reads every address in it. One that is not still reads every angle address
    in it, every addr-spec when a part of it is a mailbox or there is no
    whitespace in it at all, and the address list of each header line (what
    the email parsers read, the legacy one included)."""
    toks = _tokens5322(value)
    if toks is not None:
        whole = _parse_address_list(toks)
        if whole:
            return whole, True
    found: List[str] = []
    loose = _tokens5322(value, tolerant=True) or []
    if _shaped_5322(value) or not any(c.isspace() for c in value.strip()):
        for k, tok in enumerate(loose):
            if tok[0] == "@":
                spec = _addr_spec_at(loose, k)
                if spec is not None:
                    found.append(spec[2])
    for m in _ANGLE_RE.finditer(value):
        t2 = _tokens5322(m.group(0)[1:-1])
        for k, tok in enumerate(t2 or ()):
            if tok[0] == "@":
                spec = _addr_spec_at(t2, k)
                if spec is not None and spec[1] == len(t2):
                    found.append(spec[2])
    if "\n" in value:
        for m in _HEADER_LINE_RE.finditer(value):
            t3 = _tokens5322(m.group(1))
            for addr in (_parse_address_list(t3) or ()) if t3 is not None else ():
                found.append(addr)
    return found, False


def _rfc5322_authorities(value: str) -> Tuple[List[Authority], bool]:
    addrs, whole = _rfc5322_addresses(value)
    out: List[Authority] = []
    ok = 0
    for addr in addrs:
        got = False
        for form in _addr_forms(addr.rstrip(".")):
            a = mailbox_authority(form)
            if a is not None:
                got = True
                if a not in out:
                    out.append(a)
        ok += got
    return out, whole and ok == len(addrs)


_DOT_ATOM_RE = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~\-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~\-]+)*")


def _addr_forms(addr: str) -> List[str]:
    """``addr`` as written and, for a quoted local part that is a dot-atom inside
    its quotes, unquoted, as email.headerregistry writes it."""
    local, _, domain = addr.rpartition("@")
    if local.startswith('"') and local.endswith('"') and _DOT_ATOM_RE.fullmatch(local[1:-1]):
        return [addr, f"{local[1:-1]}@{domain}"]
    return [addr]


def mailbox_list(value: str):
    """Ruling 3.2: a value with '@' that is not a URL is a mailbox list. Every
    part must parse, or the WHOLE value is a ParseFailure. Empty parts (a
    trailing separator) are skipped.

    The failure carries every part that DID parse, and each is
    its own finding, so an untrusted part decides the wire. Without it,
    `evil@x.example, junk` is UNRESOLVED, and UNRESOLVED never blocks. Quoting
    that does not balance is junk too: the value fails, and its separators are
    taken literally to find the parts that parse (`evil@x.example, "`)."""
    parts = _split_mailbox_list(value)
    failed = parts is None
    if failed:
        parts = re.split(r"[,;]", value)
    out = []
    for part in parts:
        if not part.strip():
            continue
        a = _mailbox_part(part)
        if a is None:
            failed = True
            # Junk in the part does not hide the mailbox it surrounds: a real
            # client reads `evil@x.example` out of `evil@x.example <` and
            # `Bob <evil@x.example` (email.utils.getaddresses), so that address is
            # a finding (ruling 2). Only junk or a display name may surround it:
            # prose that mentions an address is not a recipient list.
            b = _mailbox_in_junk(part)
            if b is not None and b not in out:
                out.append(b)
        else:
            out.append(a)
    # What an RFC 5322 reader takes from the value (comments, groups, quoted
    # local parts, address literals, obs-route, every angle address).
    more, whole = _rfc5322_authorities(value)
    out.extend(a for a in more if a not in out)
    if whole and out:
        return out
    if failed or not out:
        return ParseFailure(out)
    return out


# ── phones ───────────────────────────────────────────────────────────────────
# `+`, then digits with single separators (space . -) and parenthesised groups
# between them. Bounded repetition; the digit count is checked afterwards.
_PHONE_BODY = r"\+(?:\([0-9]{1,4}\)|[0-9])(?:[ .\-]?(?:\([0-9]{1,4}\)|[0-9])){0,40}"
_PHONE_RE = re.compile(_PHONE_BODY)


def phone_authority(text: str) -> Optional[Authority]:
    if not text.isascii() or not _PHONE_RE.fullmatch(text):
        return None
    digits = re.sub(r"[^0-9]", "", text.replace("(0)", ""))
    if not 8 <= len(digits) <= 15:
        return None
    return Authority(scheme="tel", value="+" + digits)


# ── the public normaliser ───────────────────────────────────────────────────
def classify_value(value: str, *, arg_mode: bool, stdlib: bool = True):
    """``_classify``, plus the host urllib3 reads in `X://` when X is no scheme
    urllib3 accepts: one more reading, so the call is authorized only if it
    is authorized too. ``stdlib`` adds the hosts urllib.request and http.client
    resolve; principal text is read without them, since a name only those clients
    make of a principal's URL (``straße`` as ``strasse``, userinfo kept in the host) is
    one the principal never gave, and the call to it is not authorized (3.6)."""
    res = _classify(value, arg_mode=arg_mode)
    m = _SCHEME_AS_HOST_RE.match(value.strip(_C0_OR_SPACE).strip().translate(_TAB_NEWLINE))
    if m and not _URLLIB3_SCHEME_RE.fullmatch(m.group(1)):
        a = _host_authority(m.group(1), arg_fallback=arg_mode)
        if a is not None:
            res = _with_reading(res, a)
    if stdlib and ":" in value and (len(value) <= MAX_LEAF_CHARS
                                    or len(value.strip()) <= MAX_LEAF_CHARS):
        # urllib.request and http.client: an unwrapped <URL:...>, userinfo kept in
        # the host, an unbracketed IPv6 address split at its last colon.
        for host in stdlib_hosts(value):
            for a in resolver_keys(host):
                res = _with_reading(res, a)
    return res


def _with_reading(res, a: Authority):
    if res is None:
        return a
    if isinstance(res, Authority):
        return res if res == a else [res, a]
    if isinstance(res, list):
        return res if a in res else [*res, a]
    if isinstance(res, ParseFailure):
        return res if a in res.parsed else ParseFailure((*res.parsed, a))
    return res


def _classify(value: str, *, arg_mode: bool):
    """The whole-value classifier behind ``authority_of`` and the argument walk.

    Returns NOT_A_DESTINATION (None), a ParseFailure (whose ``parsed`` may hold
    the parts of a mailbox list that did parse), an Authority, or — for a
    mailbox list — a list of Authorities. Order (ruling 3.2, URLs
    first): a URL is tried first, so a URL carrying '@' is still a URL —
    including a special scheme with no `//`, a scheme-less `host[:port]/path`,
    a strict IP literal followed by a port, path, query or fragment, and, for
    an argument, an address in any inet_aton spelling followed by one;
    otherwise a value with '@' is a mailbox list when any part of it is an
    address; then a phone; then a bare strict IP. Bare hostnames are never
    destinations here.
    """
    c0 = value.strip(_C0_OR_SPACE)        # what WHATWG and urlsplit strip from a URL
    v = c0.strip()
    if not v or len(v) > MAX_LEAF_CHARS:
        return NOT_A_DESTINATION
    if v[:7].lower() == "mailto:":
        addr = v[7:].split("?", 1)[0]
        if not addr:
            return NOT_A_DESTINATION           # mailto: with no address
        return mailbox_list(addr) if arg_mode else _single(mailbox_list(addr))
    written = c0
    url = c0.translate(_TAB_NEWLINE)
    m = _SPECIAL_RE.match(url)
    if m:
        url = m.group(1) + "://" + url[m.end():]
    if url.startswith("//") and not url.startswith("///"):
        # A scheme-relative reference: urllib3 sends `//host/x` to host.
        return url_authority("http:" + url, arg_mode=arg_mode, written="http:" + written)
    if _SCHEME_RE.match(url):
        # WHATWG and urlsplit both remove every tab and newline from a URL; other
        # whitespace counts only where it lands. In a host it is no host (that
        # reading fails); in a path, query or fragment WHATWG percent-encodes it
        # and the host stays readable (ruling 3).
        return url_authority(url, arg_mode=arg_mode, written=written.translate(_TAB_NEWLINE))
    if not any(c.isspace() for c in v):
        if _IMPLIED_RE.match(pinned(v)):
            return implied_url_authority(v, arg_mode=arg_mode)
        m = _IMPLIED_IP_RE.match(v)
        if m:
            ip = _strict_ip(m.group(1))
            if ip is not None and "%" not in m.group(1):
                return Authority(scheme="ip", value=ip_key(ip))
            res = _implied_ip_authority(v, arg_mode=arg_mode)   # a zone: both readings
            if res is not NOT_A_DESTINATION:
                return res
        if arg_mode and _IMPLIED_INT_RE.match(v):
            res = _implied_ip_authority(v, arg_mode=arg_mode)
            if res is not NOT_A_DESTINATION:
                return res
    if "@" in v:
        res = mailbox_list(v)
        if not (isinstance(res, ParseFailure) and not res.parsed) or _address_shaped(v):
            return res if arg_mode else _single(res)
        # No part of it is an address, or shaped like one (`ping me @ 5pm`,
        # `curl -d @file ...`): an `@` alone does not make a value an address
        # list, so it is read like any other value.
    if v.startswith("+"):
        a = phone_authority(v)
        if a is not None:
            return a
    ip = _strict_ip(v)
    if ip is not None:
        return Authority(scheme="ip", value=ip_key(ip))
    return NOT_A_DESTINATION


def _single(res):
    if isinstance(res, list):
        return res[0] if len(res) == 1 else NOT_A_DESTINATION
    if isinstance(res, ParseFailure):
        return NOT_A_DESTINATION
    return res


def authority_of(value: str) -> Authority | None:
    """The per-scheme normaliser: the one destination ``value`` names, else ``None``.
    ``None`` is no SINGLE destination: the value names none, or it names more than
    one (it reads two ways, or lists two mailboxes), which ``extract_destinations``
    tells apart.

    Accepts one addr-spec mailbox (optionally ``display <addr>`` or
    ``mailto:``), a ``scheme://host…`` URL (a special scheme without the ``//``
    too, R4), a scheme-less ``host[:port]/path``, a strict IP literal alone or
    followed by a port, path, query or fragment (R4), an address in any inet_aton
    spelling followed by one, or a ``+`` phone. A bare hostname is NOT
    a destination (V-19). A URL host
    that fails UTS-46 still yields ``dns:<raw host lowercased>`` (V-23), as its one
    destination when no client resolves it otherwise. A URL whose authority split
    names two authorities (Q1) is None here, exactly as a two-mailbox list is, and
    so is one a client resolves under a second name (urllib.request keeps the
    userinfo in its host; the socket layer encodes ``straße`` as ``strasse``): one
    answer cannot name both, and either one alone is a host some real client does
    not send to. ``extract_destinations`` reports every one. Never raises.
    """
    try:
        if not isinstance(value, str):
            return None
        res = classify_value(value, arg_mode=True)
        if isinstance(res, Authority):
            return res
        if isinstance(res, list) and len(res) == 1:
            return res[0]
        return None
    except Exception:
        return None


# ── prose candidates (ruling 3.4) ────────────────────────────────────────────
_P_URL_RE = re.compile(r"(?<![A-Za-z0-9+.\-])[A-Za-z][A-Za-z0-9+.\-]{0,31}://[^\s\"'<>]{1,3968}")
_P_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~\-@])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~\-]{1,64}@[\w\-]{1,63}(?:\.[\w\-]{1,63}){1,126}")
# The same, its domain allowed a single label (``user@host``, ruling 3.2): read only
# in a part that does not parse, where junk alone surrounds the one address.
_J_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~\-@])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~\-]{1,64}@[\w\-]{1,63}(?:\.[\w\-]{1,63}){0,126}")
_P_HOST_RE = re.compile(r"(?<![\w.@/\-])((?:[\w\-]{1,63}\.){1,126}[\w\-]{1,63})(?![\w@\-])(/[^\s\"'<>]{0,2048})?")
_P_PHONE_RE = re.compile(r"(?<![\w+])" + _PHONE_BODY + r"(?!\d)")
_P_IPV4_RE = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?!\w)(?!\.\w)")
_P_IPV6_RE = re.compile(r"(?<![\w:])\[?[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}\]?(?![\w:])")
_TRAILING = ")]}.,;:!?'\""


def _blank(text: str, spans: List[Tuple[int, int]]) -> str:
    if not spans:
        return text
    chars = list(text)
    for a, b in spans:
        for i in range(a, b):
            chars[i] = " "
    return "".join(chars)


def _mid_word(text: str, i: int) -> bool:
    """True when ``text[i]`` continues a word: a letter before it in a script that
    puts spaces between words (below U+0E00: Latin, Greek, Cyrillic, Hebrew,
    Arabic, the Indic scripts). Thai and the CJK scripts do not, so an address
    right after their text still starts there."""
    if i == 0:
        return False
    ch = text[i - 1]
    return ch.isalpha() and ord(ch) < 0x0E00 and _known(ch)


def prose_candidates(text: str, counter: Optional[List[int]] = None, *,
                     stdlib: bool = True) -> List[Tuple[int, Authority]]:
    """Every destination candidate in prose, as (position, authority), in text
    order. URLs first and blanked; then mailboxes, blanked so a mailbox never
    authorizes its own domain; then bare hosts (ruling 3.4: ICANN TLD or
    reserved name only), phones and strict IPs. A candidate for which
    normalisation fails is dropped. ``counter``, if given, is incremented once per
    candidate EXAMINED, accepted or not -- what the work budget charges for (a
    rejected candidate costs the same normalisation: milestone review, 2026-10-06).
    ``stdlib=False`` (principal text) leaves out the hosts only urllib.request
    and http.client resolve (``classify_value``)."""
    out: List[Tuple[int, Authority]] = []
    taken: List[Tuple[int, int]] = []
    scan = pinned(text)                # classes decided here; values taken from ``text``
    for m in _P_URL_RE.finditer(scan):
        if counter is not None:
            counter[0] += 1
        cand = text[m.start():m.end()].rstrip(_TRAILING)
        taken.append((m.start(), m.end()))
        # Read as an argument value is: every reading of the split (Q1), and S-4's
        # fallback key for a host UTS-46 refuses, which a client still sends to.
        a = classify_value(cand, arg_mode=True, stdlib=stdlib)
        if isinstance(a, Authority):
            out.append((m.start(), a))
        elif isinstance(a, list):
            out.extend((m.start(), x) for x in a)
        elif isinstance(a, ParseFailure):
            out.extend((m.start(), x) for x in a.parsed)
    text, scan = _blank(text, taken), _blank(scan, taken)
    taken = []
    for m in _P_EMAIL_RE.finditer(scan):
        if counter is not None:
            counter[0] += 1
        cand = text[m.start():m.end()].rstrip(".-")
        taken.append((m.start(), m.end()))
        if _mid_word(text, m.start()):
            continue                           # `jürgen@x.example` is not `rgen@x.example`
        a = mailbox_authority(cand)
        if a is not None:
            out.append((m.start(), a))
    text, scan = _blank(text, taken), _blank(scan, taken)
    for m in _P_HOST_RE.finditer(scan):
        if counter is not None:
            counter[0] += 1
        host = text[m.start(1):m.end(1)]
        last = host.rsplit(".", 1)[-1]
        if last.isdigit():
            continue                           # dotted numbers are the IP scan's
        ascii_host = to_ascii(host)
        if ascii_host is None or not bare_host_tld_ok(ascii_host):
            continue
        a = _host_authority(host, arg_fallback=False)
        if a is not None:
            out.append((m.start(), a))
            out.extend((m.start(), b) for b in _case_readings(host) if b != a)
    for m in _P_PHONE_RE.finditer(scan):
        if counter is not None:
            counter[0] += 1
        a = phone_authority(m.group(0))
        if a is not None:
            out.append((m.start(), a))
    for m in _P_IPV4_RE.finditer(scan):
        if counter is not None:
            counter[0] += 1
        ip = _strict_ip(m.group(0))
        if ip is not None:
            out.append((m.start(), Authority(scheme="ip", value=ip_key(ip))))
    for m in _P_IPV6_RE.finditer(scan):
        if counter is not None:
            counter[0] += 1
        if m.group(0).count(":") < 2:
            continue
        ip = _strict_ip(m.group(0))
        if ip is not None and isinstance(ip, ipaddress.IPv6Address):
            out.append((m.start(), Authority(scheme="ip", value=ip_key(ip))))
    out.sort(key=lambda t: t[0])
    return out


# ── a result's text, read as argument values are (§5) ────────────────────────
# A character without which no whitespace-free token is a destination the
# argument reader reads, beyond what the prose patterns above find (a bare
# address, a phone): a scheme, a path, a port, an address literal, a mailbox, an
# escape, a backslash.
_VALUE_SIGNS = frozenset("@:/?#[]%\\")
_LINE_RE = re.compile(r"[^\r\n]+")


def result_candidates(text: str, counter: Optional[List[int]] = None
                      ) -> List[Tuple[int, Authority]]:
    """``prose_candidates``, plus every key the argument reader reads from each
    whitespace-separated token of ``text`` and from each line of it that holds
    whitespace: a tool result is read as an argument is, so a destination the
    result names in prose is recorded however it is spelled (``//host/x``,
    ``[v6]:port/x``, ``https:/host``, a mailbox at a Unicode domain). For results
    only: recording a destination a result named makes it untrusted, while a
    reading of principal text authorizes, and principal prose stays read by the
    prose patterns. ``counter`` is charged one per token or line read, as
    ``prose_candidates`` charges a candidate."""
    out = prose_candidates(text, counter)
    for m in _LINE_RE.finditer(text):
        line = m.group(0)
        if not any(c in _VALUE_SIGNS for c in line):
            continue
        if "@" in line:
            out.extend((m.start(), a) for a in _addr_specs_in(line, counter))
        stripped = line.strip()
        if any(c.isspace() for c in stripped):
            if counter is not None:
                counter[0] += 1
            out.extend((m.start(), a) for a in _whole(classify_value(stripped, arg_mode=True)))
        for t in re.finditer(r"\S+", line):
            tok = t.group(0)
            u = _P_URL_RE.match(tok)
            if u and u.end() == len(tok) and tok.rstrip(_TRAILING) == tok:
                continue                   # the prose URL pattern read this very token
            if any(c in _VALUE_SIGNS for c in tok):
                if counter is not None:
                    counter[0] += 1
                out.extend((m.start() + t.start(), a)
                           for a in _whole(classify_value(tok, arg_mode=True)))
    out.sort(key=lambda t: t[0])
    return out


def _addr_specs_in(line: str, counter: Optional[List[int]] = None) -> List[Authority]:
    """Every RFC 5322 addr-spec in a line of result text, whatever stands around
    it: the local part a run of atoms and quoted strings joined by dots, the domain
    a run of atoms joined by dots or an address literal, comments and whitespace
    between them dropped, as the email parsers drop them. A quoted local part
    (``"ops desk"@x.example``) or one with comments is read this way; an address
    the prose pattern already reads is read again and kept once."""
    toks = _tokens5322(line, tolerant=True) or []
    out: List[Authority] = []
    n = len(toks)
    for k, tok in enumerate(toks):
        if tok[0] != "@" or k == 0 or k + 1 >= n or toks[k - 1][0] not in ("atom", "quoted"):
            continue
        if counter is not None:
            counter[0] += 1
        j = k - 1
        while j >= 2 and toks[j - 1][0] == "." and toks[j - 2][0] in ("atom", "quoted"):
            j -= 2
        if toks[k + 1][0] == "literal":
            end = k + 2
        elif toks[k + 1][0] == "atom":
            end = k + 2
            while end + 1 < n and toks[end][0] == "." and toks[end + 1][0] == "atom":
                end += 2
        else:
            continue
        addr = "".join(t for _, t in toks[j:k]) + "@" + "".join(t for _, t in toks[k + 1:end])
        for form in _addr_forms(addr.rstrip(".")):
            a = mailbox_authority(form)
            if a is not None and a not in out:
                out.append(a)
    return out


def _whole(res) -> List[Authority]:
    if isinstance(res, Authority):
        return [res]
    if isinstance(res, list):
        return list(res)
    if isinstance(res, ParseFailure):
        return list(res.parsed)
    return []

