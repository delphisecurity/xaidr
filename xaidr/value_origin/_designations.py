"""Source designations: construction-time validation and read matching (C-3, V-8f, V-17)."""
from __future__ import annotations

import fnmatch
import posixpath
from typing import Iterable, Mapping
from urllib.parse import unquote, urlsplit

from ._types import MatchKind, Mode, SourceDesignation


def validate_designations(designations: Iterable[SourceDesignation]
                          ) -> tuple[SourceDesignation, ...]:
    """Validate at construction, loudly. Raises ValueError naming the offending
    field. A designation WITHOUT ``key_args`` trusts its result unconditionally:
    that is an operator claim, because which arguments select content cannot be
    inferred (C-3)."""
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
            try:
                p = urlsplit(d.pattern)
                ok = bool(p.scheme) and bool(p.hostname)
            except ValueError:
                ok = False
            if not ok:
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


def _url_prefix_match(value: str, pattern: str) -> bool:
    """V-17 URL_PREFIX. No userinfo; equal lowercased schemes; equal lowercased
    hosts, exactly; equal ports after mapping 80/443 to absent; the pattern's
    path segments a SEGMENT-WISE prefix of the value's. Query and fragment
    ignored. A value path with a dot segment never matches: ``/public/../x``
    would otherwise be trusted as ``/public`` (the safe direction is no match)."""
    try:
        v = urlsplit(value)
        p = urlsplit(pattern)
        if "@" in v.netloc or v.username is not None:
            return False
        if v.scheme.lower() != p.scheme.lower():
            return False
        if (v.hostname or "") != (p.hostname or "") or not v.hostname:
            return False
        scheme = v.scheme.lower()
        vp = v.port if v.port != _DEFAULT_PORTS.get(scheme) else None
        pp = p.port if p.port != _DEFAULT_PORTS.get(scheme) else None
        if vp != pp:
            return False
    except ValueError:
        return False
    vseg = v.path.split("/")
    if any(unquote(s) in (".", "..") for s in vseg):
        return False
    pseg = p.path.split("/")
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
        return value.strip() == d.pattern.strip()
    if d.match is MatchKind.URL_PREFIX:
        return _url_prefix_match(value.strip(), d.pattern)
    if d.match is MatchKind.PATH_GLOB:
        if not value.startswith("/"):
            return False                   # a relative value never matches
        return fnmatch.fnmatchcase(posixpath.normpath(value), d.pattern)
    return False
