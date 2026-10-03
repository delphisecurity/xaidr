"""Per-scheme authority — the one normaliser (§6 C-6, V-19..V-23, rulings 3.2/3.6,
R1/R4 of 2026-10-03).

    mailto:<local@domain>   the full mailbox, local part .lower(), domain as
                            UTS-46 A-labels. No plus-stripping, no dot removal:
                            both collide genuinely distinct mailboxes (S18).
    dns:<registrable>       a URL host's registrable domain by the PSL algorithm,
                            both sections, default ``*`` rule. A host that is
                            itself a suffix, or one label, is kept whole (V-10).
    ip:<canonical>          every literal form (hex, octal, decimal, short
                            dotted, IPv4-mapped IPv6), mapped addresses
                            unwrapped BEFORE rendering (V-21).
    tel:+<digits>           ``+``-prefixed phones only (V-22). A national
                            number needs a region to normalise, and there is no
                            right default region (C-6, OPEN).

Every pattern is bounded with no nested unbounded quantifier: this runs on
attacker-controlled values. Nothing here raises; nothing here does I/O.
"""
from __future__ import annotations

import ipaddress
import re
from typing import List, Optional, Tuple
from urllib.parse import unquote_to_bytes, urlsplit

from ._idna import to_ascii
from ._psl_data import ICANN_RULES, PRIVATE_RULES
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
    is itself a public suffix or a single label (V-10)."""
    labels = host.split(".")
    if len(labels) < 2:
        return host
    ps = _public_suffix_len(labels)
    if ps >= len(labels):
        return host
    return ".".join(labels[-(ps + 1):])


def bare_host_tld_ok(ascii_host: str) -> bool:
    """Ruling 3.4: the last label is an ICANN TLD or an RFC 2606/6761 name."""
    last = ascii_host.rsplit(".", 1)[-1]
    return last in _ICANN_TLDS or last in _RESERVED_TLDS


# ── IP ───────────────────────────────────────────────────────────────────────
def coerce_ip(host: str):
    """The IP address ``host`` denotes across every literal form, or None.

    Moved here from ``scanner/url_parse._coerce_ip`` (§4.1): the one normaliser
    lives inside the vendored unit. Integer forms (hex / octal / decimal / short
    dotted) are what ``inet_aton`` accepts; they apply ONLY inside a URL host
    (V-19) — ``"4417"`` as a bare value is not an address.
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
            if p.lower().startswith("0x"):
                vals.append(int(p, 16))
            elif p.startswith("0") and len(p) > 1:
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
    dotted or IPv6 ``.compressed`` — the same on every interpreter (V-21)."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv6Address):
        return ip.compressed
    return str(ip)


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
def _host_authority(raw_host: str, *, arg_fallback: bool) -> Optional[Authority]:
    """Authority of a URL host. ``raw_host`` is as the URL spelled it.

    WHATWG order: percent-decode, then UTS-46, then (if the result is an
    address in any spelling) IP. On a UTS-46 failure an ARGUMENT host still
    yields ``dns:<raw host lowercased>`` (V-23), which matches only itself and is
    never ``no_destination``; a prose candidate is dropped.
    """
    host = raw_host.strip()
    if host.startswith("[") and host.endswith("]"):
        ip = _strict_ip(host)
        return Authority(scheme="ip", value=ip_key(ip)) if ip is not None else None
    host = host.rstrip(".")
    if not host:
        return None
    if ":" in host:                            # only an IPv6 literal has a colon
        ip = _strict_ip(host)
        if ip is not None:
            return Authority(scheme="ip", value=ip_key(ip))
        return (Authority(scheme="dns", value=raw_host.lower().rstrip("."))
                if arg_fallback else None)
    if "%" in host:
        try:
            host = unquote_to_bytes(host).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return (Authority(scheme="dns", value=raw_host.lower().rstrip("."))
                    if arg_fallback else None)
        host = host.rstrip(".")
        if not host:
            return None
    ascii_host = to_ascii(host)
    if ascii_host is None or not ascii_host:
        if arg_fallback:
            return Authority(scheme="dns", value=raw_host.lower().rstrip("."))
        return None
    ip = coerce_ip(ascii_host)
    if ip is not None:
        return Authority(scheme="ip", value=ip_key(ip))
    return Authority(scheme="dns", value=registrable_domain(ascii_host))


# ── URLs ─────────────────────────────────────────────────────────────────────
_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]{0,31})://")
# R4 (2026-10-03): a WHATWG special scheme other than file: (C-6) takes its
# authority after ANY run of '/' and '\', so `http:evil.test`, `http:/evil.test`,
# `http:\\evil.test` and `http:///evil.test` all name evil.test. Such a value is
# rewritten to `scheme://` and parsed as one. A non-special scheme with no `//`
# has no host (`gopher:evil.test`), as WHATWG and urllib.parse agree.
_SPECIAL_RE = re.compile(r"^(https?|wss?|ftp):[/\\]*(?=[^\s/\\])", re.IGNORECASE)
# V-19: `host/path` with no scheme — ≥2 labels, alphabetic final label, and a
# path. Labels are \w so a Unicode host is accepted here too (ruling 3.6).
_IMPLIED_RE = re.compile(r"^((?:[\w\-]{1,63}\.){1,126}[^\W\d_]{1,63})/")
# R4 (2026-10-03): no scheme, a STRICT address literal (a dotted quad, or IPv6 in
# brackets), then a port, path, query or fragment — `169.254.169.254/latest`.
# Strict because V-19 confines the integer spellings (hex, decimal, octal, short
# dotted) to a URL host: `2024/report` is a path, not 0.0.7.232.
_IMPLIED_IP_RE = re.compile(r"^(\[[0-9A-Fa-f:.]{2,45}\]|[0-9]{1,3}(?:\.[0-9]{1,3}){3})"
                            r"(?::[0-9]{1,5}(?![^/?#])|(?=[/?#]))")
_NON_DESTINATION_SCHEMES = frozenset({"file", "data"})

# Sentinels for the argument walk's three-way answer.
NOT_A_DESTINATION = None


class ParseFailure:
    """Destination-shaped and unparseable: UNRESOLVED, never no_destination.

    ``parsed`` holds the parts of a mailbox list that DID parse (R1, 2026-10-03):
    the value is still UNRESOLVED as a whole, and each of them is its own finding.
    """

    __slots__ = ("parsed",)

    def __init__(self, parsed=()) -> None:
        self.parsed: Tuple[Authority, ...] = tuple(parsed)


PARSE_FAILURE = ParseFailure()


def _url_host(value: str):
    """(raw host or None, parse_ok). ``value`` must start with ``scheme://``."""
    m = _SCHEME_RE.match(value)
    scheme_len = m.end()
    # V-23: backslashes in the scheme-relative part are slashes, as WHATWG does
    # for special schemes — `https://evil.test\@corp.example/` is evil.test.
    rest = value[scheme_len:].replace("\\", "/")
    try:
        parts = urlsplit(value[:scheme_len] + rest)
        host = parts.hostname
    except ValueError:
        return None, False
    return host, True


def url_authority(value: str, *, arg_mode: bool):
    """Authority of a whole-value URL; None if hostless; PARSE_FAILURE if broken."""
    m = _SCHEME_RE.match(value)
    if not m:
        return NOT_A_DESTINATION
    if m.group(1).lower() in _NON_DESTINATION_SCHEMES:
        return NOT_A_DESTINATION
    host, ok = _url_host(value)
    if not ok:
        return PARSE_FAILURE if arg_mode else NOT_A_DESTINATION
    if not host:
        return NOT_A_DESTINATION                 # hostless (C-6)
    a = _host_authority(host, arg_fallback=arg_mode)
    if a is None:
        return PARSE_FAILURE if arg_mode else NOT_A_DESTINATION
    return a


def implied_url_authority(value: str, *, arg_mode: bool):
    """V-19's one exception: ``host/path`` counts as a URL with an implied scheme."""
    m = _IMPLIED_RE.match(value)
    if not m:
        return NOT_A_DESTINATION
    a = _host_authority(m.group(1), arg_fallback=arg_mode)
    if a is None:
        return PARSE_FAILURE if arg_mode else NOT_A_DESTINATION
    return a


# ── mailboxes (V-4, rulings 3.2 / 3.6) ──────────────────────────────────────
_LOCAL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~\-]{1,64}")
_ASCII_DOMAIN_RE = re.compile(r"[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){1,126}")
_DISPLAY_RE = re.compile(r"^(?P<display>[^<>]{0,256})<(?P<addr>[^<>]{1,320})>$")


def mailbox_authority(addr: str) -> Optional[Authority]:
    """``local@domain`` → ``mailto:`` authority, or None if it fails the grammar.

    The local part is ASCII by grammar: a non-ASCII local part is not a mailbox
    this core can compare (ruling 3.6: UNRESOLVED when it is an argument). The
    domain may be Unicode and is UTS-46-encoded first.
    """
    if addr.count("@") != 1:
        return None
    local, domain = addr.split("@")
    if not _LOCAL_RE.fullmatch(local):
        return None
    ascii_domain = to_ascii(domain)
    if ascii_domain is None or not _ASCII_DOMAIN_RE.fullmatch(ascii_domain):
        return None
    return Authority(scheme="mailto", value=f"{local.lower()}@{ascii_domain}")


def _split_mailbox_list(value: str) -> Optional[List[str]]:
    """Split on ``,`` and ``;`` outside ``<…>`` and ``"…"`` (V-4). None if the
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


def mailbox_list(value: str):
    """Ruling 3.2: a value with '@' that is not a URL is a mailbox list. Every
    part must parse, or the WHOLE value is a ParseFailure. Empty parts (a
    trailing separator) are skipped.

    R1 (2026-10-03): the failure carries every part that DID parse, and each is
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
        else:
            out.append(a)
    if failed or not out:
        return ParseFailure(out)
    return out


# ── phones (V-22) ────────────────────────────────────────────────────────────
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
def classify_value(value: str, *, arg_mode: bool):
    """The whole-value classifier behind ``authority_of`` and the argument walk.

    Returns NOT_A_DESTINATION (None), a ParseFailure (whose ``parsed`` may hold
    the parts of a mailbox list that did parse, R1), an Authority, or — for a
    mailbox list — a list of Authorities. Order (ruling 3.2 as settled
    2026-09-24): a URL is tried first, so a URL carrying '@' is still a URL —
    including a special scheme with no `//` and a strict IP literal followed by
    a port or path (R4); otherwise a value with '@' is a mailbox list; then a
    phone; then a bare strict IP. Bare hostnames are never destinations here
    (V-19).
    """
    v = value.strip()
    if not v or len(v) > MAX_LEAF_CHARS:
        return NOT_A_DESTINATION
    if v[:7].lower() == "mailto:":
        addr = v[7:].split("?", 1)[0]
        if not addr:
            return NOT_A_DESTINATION           # mailto: with no address (C-6)
        return mailbox_list(addr) if arg_mode else _single(mailbox_list(addr))
    m = _SPECIAL_RE.match(v)
    if m:
        v = m.group(1) + "://" + v[m.end():]
    if _SCHEME_RE.match(v):
        if any(c.isspace() for c in v):
            return PARSE_FAILURE if arg_mode else NOT_A_DESTINATION
        return url_authority(v, arg_mode=arg_mode)
    if not any(c.isspace() for c in v):
        if _IMPLIED_RE.match(v):
            return implied_url_authority(v, arg_mode=arg_mode)
        m = _IMPLIED_IP_RE.match(v)
        if m:
            ip = _strict_ip(m.group(1))
            if ip is not None:
                return Authority(scheme="ip", value=ip_key(ip))
    if "@" in v:
        res = mailbox_list(v)
        return res if arg_mode else _single(res)
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
    """The per-scheme normaliser (§6 C-6). ``None`` = not a destination.

    Accepts one addr-spec mailbox (optionally ``display <addr>`` or
    ``mailto:``), a ``scheme://host…`` URL (a special scheme without the ``//``
    too, R4), a V-19 ``host/path``, a strict IP literal alone or followed by a
    port, path, query or fragment (R4), or a ``+`` phone. A bare hostname is NOT
    a destination (V-19). A URL host
    that fails UTS-46 still yields ``dns:<raw host lowercased>`` (V-23). Never
    raises.
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


# ── prose candidates (C-7, V-19, V-20, V-22, V-23, ruling 3.4) ───────────────
_P_URL_RE = re.compile(r"(?<![A-Za-z0-9+.\-])[A-Za-z][A-Za-z0-9+.\-]{0,31}://[^\s\"'<>]{1,3968}")
_P_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~\-@])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~\-]{1,64}@[\w\-]{1,63}(?:\.[\w\-]{1,63}){1,126}")
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


def prose_candidates(text: str) -> List[Tuple[int, Authority]]:
    """Every destination candidate in prose, as (position, authority), in text
    order. URLs first and blanked; then mailboxes, blanked so a mailbox never
    authorizes its own domain (V-20); then bare hosts (ruling 3.4: ICANN TLD or
    reserved name only), phones and strict IPs. A candidate for which
    normalisation fails is dropped."""
    out: List[Tuple[int, Authority]] = []
    taken: List[Tuple[int, int]] = []
    for m in _P_URL_RE.finditer(text):
        cand = m.group(0).rstrip(_TRAILING)
        taken.append((m.start(), m.end()))
        a = classify_value(cand, arg_mode=False)
        if isinstance(a, Authority):
            out.append((m.start(), a))
    text = _blank(text, taken)
    taken = []
    for m in _P_EMAIL_RE.finditer(text):
        cand = m.group(0).rstrip(".-")
        taken.append((m.start(), m.end()))
        a = mailbox_authority(cand)
        if a is not None:
            out.append((m.start(), a))
    text = _blank(text, taken)
    for m in _P_HOST_RE.finditer(text):
        host = m.group(1)
        last = host.rsplit(".", 1)[-1]
        if last.isdigit():
            continue                           # dotted numbers are the IP scan's
        ascii_host = to_ascii(host)
        if ascii_host is None or not bare_host_tld_ok(ascii_host):
            continue
        a = _host_authority(host, arg_fallback=False)
        if a is not None:
            out.append((m.start(), a))
    for m in _P_PHONE_RE.finditer(text):
        a = phone_authority(m.group(0))
        if a is not None:
            out.append((m.start(), a))
    for m in _P_IPV4_RE.finditer(text):
        ip = _strict_ip(m.group(0))
        if ip is not None:
            out.append((m.start(), Authority(scheme="ip", value=ip_key(ip))))
    for m in _P_IPV6_RE.finditer(text):
        if m.group(0).count(":") < 2:
            continue
        ip = _strict_ip(m.group(0))
        if ip is not None and isinstance(ip, ipaddress.IPv6Address):
            out.append((m.start(), Authority(scheme="ip", value=ip_key(ip))))
    out.sort(key=lambda t: t[0])
    return out
