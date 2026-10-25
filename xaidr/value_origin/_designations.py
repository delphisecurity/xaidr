"""Source designations: construction-time validation and read matching."""
from __future__ import annotations

import fnmatch
import ipaddress
import posixpath
import re
from typing import Iterable, Mapping, Optional, Tuple
from urllib.parse import unquote

from . import _ucd
from ._types import Authority, MatchKind, Mode, SourceDesignation


def validate_designations(designations: Iterable[SourceDesignation]
                          ) -> tuple[SourceDesignation, ...]:
    """Validate at construction, loudly. Raises ValueError naming the offending
    field. A designation WITHOUT ``key_args`` trusts its result unconditionally:
    that is an operator claim, because which arguments select content cannot be
    inferred."""
    out = []
    seen = set()
    if isinstance(designations, (str, bytes)) or designations is None:
        raise ValueError("designations: expected an iterable of SourceDesignation, "
                         f"got {type(designations).__name__}")
    for i, d in enumerate(designations):
        where = f"designations[{i}]"
        if not isinstance(d, SourceDesignation):
            raise ValueError(f"{where}: not a SourceDesignation ({type(d).__name__})")
        if not isinstance(d.tool, str) or not d.tool:
            raise ValueError(f"{where}.tool: must be a non-empty string")
        if not isinstance(d.label, str) or not d.label:
            raise ValueError(f"{where}.label: must be a non-empty string")
        if not isinstance(d.match, MatchKind):
            raise ValueError(f"{where}.match: must be a MatchKind, got {d.match!r}")
        if not isinstance(d.key_args, tuple) or not all(
                isinstance(k, str) and k for k in d.key_args):
            raise ValueError(f"{where}.key_args: must be a tuple of non-empty strings")
        if d.match is not MatchKind.ANY:
            if not isinstance(d.source_arg, str) or not d.source_arg:
                raise ValueError(f"{where}.source_arg: required when match is {d.match.value}")
            if not isinstance(d.pattern, str) or not d.pattern:
                raise ValueError(f"{where}.pattern: required when match is {d.match.value}")
        if d.match is MatchKind.URL_PREFIX:
            if _prefix_parts(d.pattern) is None:
                raise ValueError(f"{where}.pattern: URL_PREFIX pattern {d.pattern!r} "
                                 "does not parse to a scheme and a host")
        if d.match is MatchKind.PATH_GLOB:
            if not d.pattern.startswith("/") or posixpath.normpath(d.pattern) != d.pattern:
                raise ValueError(f"{where}.pattern: PATH_GLOB pattern {d.pattern!r} "
                                 "must be absolute and normalised")
        if d.source_arg is not None and d.source_arg in d.key_args:
            raise ValueError(f"{where}.key_args: {d.source_arg!r} is also the source_arg")
        ident = (d.tool, d.match, d.source_arg, d.pattern)
        if ident in seen:
            raise ValueError(f"{where}: duplicate (tool, match, source_arg, pattern) {ident!r}")
        seen.add(ident)
        out.append(d)
    return tuple(out)


def validate_mode(mode: Mode | str) -> Mode:
    """Raises ValueError naming the received value."""
    if isinstance(mode, Mode):
        return mode
    if isinstance(mode, str):
        try:
            return Mode(mode)
        except ValueError:
            pass
    raise ValueError(f"value_origin mode: expected one of "
                     f"{[m.value for m in Mode]}, got {mode!r}")


_DEFAULT_PORTS = {"http": 80, "https": 443}
# scheme "://" netloc path, written out: the interpreter's urlsplit refuses
# different netlocs on different patch releases, and would make whether a read is
# trusted follow the interpreter (V-4).
_PREFIX_URL_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]*)([^?#]*)")
_PORT_RE = re.compile(r"[0-9]{1,5}")


def _prefix_parts(url: str) -> Optional[Tuple[str, str, Optional[int], str]]:
    """(scheme, host, port, path) of a URL every reader splits alike, else None:
    no userinfo, no backslash, no tab, newline or other control, a ``[`` only
    around a whole IPv6 literal with no zone, a decimal port up to 65535. Scheme
    and host are lowercased (ASCII) or case-mapped by the pinned table."""
    from ._idna import fold
    if any(c <= " " or c in "\\\x7f" for c in url):
        return None
    m = _PREFIX_URL_RE.fullmatch(url.partition("?")[0].partition("#")[0])
    if not m:
        return None
    scheme, netloc, path = m.groups()
    if "@" in netloc:
        return None
    if netloc.startswith("["):
        inner, close, rest = netloc[1:].partition("]")
        try:
            ok = close and isinstance(ipaddress.ip_address(inner), ipaddress.IPv6Address)
        except ValueError:
            ok = False
        if not ok or "%" in inner or (rest and not rest.startswith(":")):
            return None
        host, port = inner, rest[1:] if rest else ""
    else:
        if "[" in netloc or "]" in netloc:
            return None
        host, _, port = netloc.partition(":")
    if not host or (port and not (_PORT_RE.fullmatch(port) and int(port) <= 65535)):
        return None
    return _ucd.lower(scheme), fold(host), int(port) if port else None, path


def _url_prefix_match(value: str, pattern: str) -> bool:
    """URL_PREFIX matching. No userinfo; equal lowercased schemes; equal hosts,
    case-mapped by the pinned table, exactly; equal ports after mapping 80/443 to
    absent; the pattern's path segments a SEGMENT-WISE prefix of the value's.
    Query and fragment ignored. A value path with a dot segment never matches:
    ``/public/../x`` would otherwise be trusted as ``/public`` (the safe direction
    is no match). A value the core reads as more than one destination never
    matches (§4), and neither does one the readers split otherwise
    (``_prefix_parts``)."""
    from ._authority import classify_value
    try:
        v, p = _prefix_parts(value), _prefix_parts(pattern)
        if v is None or p is None or not v[1]:
            return False
        if not isinstance(classify_value(value, arg_mode=True), Authority):
            return False
        if v[0] != p[0] or v[1] != p[1]:
            return False
        vp = v[2] if v[2] != _DEFAULT_PORTS.get(v[0]) else None
        pp = p[2] if p[2] != _DEFAULT_PORTS.get(p[0]) else None
        if vp != pp:
            return False
    except Exception:
        return False
    vseg = v[3].split("/")
    if any(unquote(s) in (".", "..") for s in vseg):
        return False
    pseg = p[3].split("/")
    while len(pseg) > 1 and pseg[-1] == "":
        pseg.pop()
    if pseg == [""]:
        return True
    return vseg[:len(pseg)] == pseg


def source_matches(d: SourceDesignation, tool_name: str,
                   arguments: Mapping[str, object] | None) -> bool:
    """Does designation ``d`` name this read's source?"""
    if tool_name != d.tool:
        return False
    if d.match is MatchKind.ANY:
        return True
    if not isinstance(arguments, Mapping) or d.source_arg not in arguments:
        return False
    value = arguments[d.source_arg]
    if not isinstance(value, str):
        return False
    if d.match is MatchKind.EXACT:
        return value.strip(_ucd.WHITESPACE) == d.pattern.strip(_ucd.WHITESPACE)
    if d.match is MatchKind.URL_PREFIX:
        return _url_prefix_match(value.strip(_ucd.WHITESPACE), d.pattern)
    if d.match is MatchKind.PATH_GLOB:
        if not value.startswith("/"):
            return False                   # a relative value never matches
        return fnmatch.fnmatchcase(posixpath.normpath(value), d.pattern)
    return False
