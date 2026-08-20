"""Structural shape of a URL, for impact classification.

WHY THIS EXISTS, and why it is not a regex. The only URL awareness the product
had was ``SHELL_cloud_metadata_credentials``, a string list of four metadata
addresses behind a binary-name alternation:

    \\b(?:curl|wget|fetch|http|httpie|nc|ncat|python\\d?|node|ruby|perl)\\b …

That alternation was written to name the HTTPie binary ``http``. What actually
satisfied it in ``http_get(url="http://169.254.169.254/…")`` is the literal
SCHEME — ``http`` followed by ``:``, and ``:`` is a word boundary. The rule
reached tool arguments by accident, and the accident was one character wide:
``https`` has no word boundary after ``http``, so

    http://169.254.169.254/latest/meta-data/    blocked 0.90
    https://169.254.169.254/latest/meta-data/   allowed 0.00

Repairing the alternation would have kept the design that produced the bug — a
list of spellings, where every form nobody thought to write down is a bypass.
Nine of fifteen forms of the SAME address were allowed: hex, decimal, octal, no
scheme, and every non-http scheme. So URLs get their own reader, sitting
ALONGSIDE the shell and SQL ones, exactly as ``sql_parse`` does: an agent fetches
a URL by calling ``http_get(url=…)``, not by running a shell.

WHAT IT EXTRACTS, and nothing more. This is not a URL library and must never grow
into one. It answers three questions a classification rule needs:

    scheme      lowercased, "" when the value carries none
    host        the hostname, lowercased, brackets stripped
    address     "link_local" | "private" | "loopback" | "public" | None

ADDRESS IS THE LOAD-BEARING FIELD, and its three states are not
interchangeable — the measurement is what separates them:

    link_local   169.254.0.0/16     0 of 30 benign agent URLs      BLOCKS
    private      RFC1918 / 127/8    9 of 30 benign agent URLs      classify only
    public       everything else    -                              no finding

Link-local is where every cloud serves short-lived role credentials to whoever
asks, and no ordinary agent call goes there. PRIVATE IS DELIBERATELY NOT BLOCKED:
in a service mesh the private address IS the normal case, and blocking it measured
a 30% false-positive rate against ordinary traffic — ``http://10.2.14.7:8080/api/
v1/orders``, ``http://172.17.0.3:8080/ready``, ``http://localhost:8000/health``.
It names its class for a policy to bind to and does not block on its own, the same
line ``terraform destroy`` sits on.

HOSTNAME-BASED METADATA STAYS A STRING LIST, and that is not a shortcut. No parse
can tell that ``metadata.google.internal`` is a metadata endpoint — the fact lives
in DNS, and resolving a name here would put a network call inside a scanner, on
attacker-controlled input, on the request path. So the four published metadata
HOSTNAMES remain enumerated in the ruleset while the ADDRESSES are parsed. The
split is honest: what structure can decide, structure decides; what only a name
lookup could decide stays a name.

SAFETY. Every pattern here is bounded and has no nested quantifier, because this
runs on attacker-controlled argument values (see the ReDoS invariants in the test
suite). Input is capped, and the module never raises: an unparseable value is
simply not a URL.
"""
from __future__ import annotations

import ipaddress
import re
from typing import NamedTuple, Optional
from urllib.parse import urlsplit

# Hard input ceiling. A URL longer than this is not something we can say anything
# useful about, and the cap keeps the scan cost flat regardless of what a caller
# passes. Real URLs are comfortably under it.
MAX_URL_CHARS = 4_000

# A value that OPENS with `scheme://`. Anchored at the start for the same reason
# sql_parse anchors its statement head: prose that merely mentions a URL ("we saw
# traffic to http://evil.tld") is not a URL-valued argument, and a shell command
# that wraps one (`curl http://…`) starts with a binary name and belongs to the
# command reader. Bounded scheme length, single character class — linear.
_SCHEME_RE = re.compile(r"^\s*([a-zA-Z][a-zA-Z0-9+.\-]{0,31}):(//)?")

# A SCHEME-LESS value whose first segment is a bare IP literal:
# `169.254.169.254/latest/meta-data/`. Deliberately restricted to something that
# parses as an ADDRESS rather than to any dotted token — "report.v2/summary" and
# "example.txt/foo" are not URLs, and a hostname rule here would swallow them.
# An address is unambiguous, so this covers the no-scheme evasion without
# inventing a URL out of an ordinary string.
_BARE_AUTHORITY_RE = re.compile(r"^\s*([0-9a-fA-Fx:.\[\]]{3,45})(?::\d{1,5})?(?:[/?#]|$)")

# Schemes an HTTP-fetching tool has no business being handed. `file:` turns a URL
# fetcher into a local file reader (SSRF collapsing to LFI); `gopher:`/`dict:` let
# it speak an arbitrary line protocol to an internal service, which is how a
# fetcher is made to issue Redis or SMTP commands. Enumerated because the set of
# URL schemes is itself an enumeration (IANA registry), not an open vocabulary.
NON_HTTP_LOCAL_SCHEMES = frozenset({"file", "netdoc", "jar"})
NON_HTTP_SMUGGLING_SCHEMES = frozenset({"gopher", "dict", "tftp", "ldap", "ldaps"})


class UrlShape(NamedTuple):
    """The structural facts a classification rule is allowed to key on."""

    scheme: str               # lowercased; "" when the value carried none
    host: str                 # lowercased hostname, brackets stripped; "" if none
    address: Optional[str]    # "link_local"|"private"|"loopback"|"public"|None
    raw: str                  # the value, capped


def _coerce_ip(host: str):
    """The IP address ``host`` denotes, across every literal form, or None.

    ``urlsplit`` hands back the authority verbatim, so the same address arrives as
    ``169.254.169.254``, ``0xA9FEA9FE``, ``2852039166``, ``0251.0376.0251.0376``
    or ``[::ffff:169.254.169.254]``. Every one of those is the SAME destination
    and a string list can only ever know the first. Parsing them is what makes the
    rule about the address instead of about its spelling.

    Never raises: anything that is not an address is a name, and returns None.
    """
    if not host:
        return None
    h = host.strip().strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    # Integer forms. inet_aton accepts hex (0x…), octal (leading 0) and decimal,
    # both dotted and packed; Python's ipaddress does not, so they are converted
    # here rather than left as a gap a bypass lives in. Bounded: at most four
    # dot-separated parts, each parsed with int(), no regex backtracking.
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
            elif p.isdigit():
                vals.append(int(p, 10))
            else:
                return None
        if len(vals) == 1:
            packed = vals[0]
        else:
            # a.b.c.d style; the final part absorbs the remaining octets, which is
            # what inet_aton does for the short forms (10.1 == 10.0.0.1).
            if any(v > 0xFF for v in vals[:-1]):
                return None
            packed = 0
            for v in vals[:-1]:
                packed = (packed << 8) | v
            packed = (packed << (8 * (4 - len(vals) + 1))) | vals[-1]
        if not 0 <= packed <= 0xFFFFFFFF:
            return None
        return ipaddress.ip_address(packed)
    except (ValueError, TypeError):
        return None


def _address_kind(host: str) -> Optional[str]:
    """"link_local" | "private" | "loopback" | "public" for an IP literal, else
    None (the host is a NAME, which no parse can classify — see the module note
    on why that is not resolved here)."""
    ip = _coerce_ip(host)
    if ip is None:
        return None
    # An IPv4-mapped IPv6 address (::ffff:169.254.169.254) IS the IPv4 address it
    # wraps, so classify the mapped form rather than the container.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_link_local:
        return "link_local"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    return "public"


def looks_like_url(text: str) -> bool:
    """Cheap gate: is this VALUE a URL?

    The gate is the VALUE, never the key — the same decision ``extract_sql``
    already settled and documented: "a key allowlist here would be a gate the
    attacker chooses the combination to". ``url``, ``uri``, ``endpoint``,
    ``target``, ``href``, ``webhook`` and ``callback`` are all ordinary names for
    the argument that carries one, and a custom tool may use anything at all.
    """
    return parse_url(text) is not None


def parse_url(text: str) -> Optional[UrlShape]:
    """Return a UrlShape, or None when the value is not a URL. Never raises."""
    try:
        if not isinstance(text, str) or not text.strip():
            return None
        capped = text[:MAX_URL_CHARS].strip()
        # A URL argument is a single token. Embedded whitespace means this is
        # prose that CONTAINS a URL, not a URL-valued argument, and prose belongs
        # to the content path where the L1 rules already read it.
        if any(c.isspace() for c in capped):
            return None

        m = _SCHEME_RE.match(capped)
        if m:
            scheme = m.group(1).lower()
            # `file:///etc/passwd` has an empty authority and a meaningful path;
            # every other scheme needs a host to be a fetchable destination.
            parts = urlsplit(capped)
            host = (parts.hostname or "").lower()
            if not host and scheme not in NON_HTTP_LOCAL_SCHEMES:
                return None
            return UrlShape(
                scheme=scheme,
                host=host,
                address=_address_kind(host),
                raw=capped,
            )

        # Scheme-less, bare-address form: `169.254.169.254/latest/meta-data/`.
        b = _BARE_AUTHORITY_RE.match(capped)
        if not b:
            return None
        host = b.group(1).strip("[]").lower()
        kind = _address_kind(host)
        if kind is None:
            return None
        # Without a scheme there is nothing to say "this is a destination", so the
        # value has to say it some other way: either it is a WELL-FORMED address
        # literal, or it carries a path/query/fragment. Otherwise "1.2" — a
        # version string — coerces to 1.0.0.2 and reads as a URL. Neither form
        # produces a finding on a public address, but a scanner should not claim
        # a version number is a URL.
        has_locator = bool(re.search(r"[/?#]", capped)) or ":" in capped
        strict_literal = True
        try:
            ipaddress.ip_address(host)
        except ValueError:
            strict_literal = False
        if not (strict_literal or has_locator):
            return None
        return UrlShape(scheme="", host=host, address=kind, raw=capped)
    except Exception:
        return None
