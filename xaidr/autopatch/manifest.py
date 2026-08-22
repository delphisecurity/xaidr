"""The manifest ``xaidr.protect()`` returns — and the loudness rules around it.

The whole point of this object is that a framework which is PRESENT but NOT
PATCHED is impossible to miss. Silence about an unprotected boundary is the
failure mode this project exists to avoid, so:

  * every ``found_unpatchable`` entry raises a :class:`XaidrProtectionWarning`
    AND prints a line to stderr, unconditionally — ``quiet=True`` suppresses the
    "everything is fine" summary and nothing else;
  * ``__repr__`` renders the unpatched section before the patched one, labelled
    ``UNPROTECTED``;
  * ``not_present`` is reported too, because "you never imported it" and "we
    could not patch it" are different operational facts and collapsing them
    would be a guess dressed up as a claim.

The object doubles as the reversal handle (``manifest.unprotect()``): tests need
it, and so does anyone bisecting a patch. It also behaves enough like the literal
``{"patched": [...], "found_unpatchable": [...], "not_present": [...]}`` contract
that ``manifest["patched"]`` and ``dict(manifest)`` both work.
"""

from __future__ import annotations

import sys
import warnings
from dataclasses import dataclass
from typing import Any, Iterator, Optional


class XaidrProtectionWarning(UserWarning):
    """A framework was present in ``sys.modules`` but could not be instrumented.

    Its own category so a host can ``filterwarnings("error", category=...)`` and
    make an unprotected boundary a hard failure in CI.
    """


@dataclass(frozen=True)
class PatchRecord:
    """One boundary, and what happened to it."""

    framework: str
    """Display name of the framework, e.g. ``"langchain_core"``."""

    target: str
    """Fully-qualified patch site, e.g. ``"langchain_core.tools.BaseTool.run"``."""

    boundary: str
    """Which agent boundary this site covers: input / output / tool / egress."""

    detail: str = ""
    """Why it could not be patched, or what the patch does. Always human-readable."""

    already_patched: bool = False
    """True when a previous ``protect()`` had already installed this patch and
    this call correctly declined to wrap it a second time."""

    def to_dict(self) -> dict:
        return {
            "framework": self.framework,
            "target": self.target,
            "boundary": self.boundary,
            "detail": self.detail,
            "already_patched": self.already_patched,
        }


_SECTION_KEYS = ("patched", "found_unpatchable", "not_present")


class ProtectionManifest:
    """What ``xaidr.protect()`` did, what it could not do, and how to undo it."""

    def __init__(
        self,
        agent_id: str,
        enforcement_mode: str,
        sensor: Any = None,
    ) -> None:
        self.agent_id = agent_id
        self.enforcement_mode = enforcement_mode
        self.sensor = sensor
        self.patched: list[PatchRecord] = []
        self.found_unpatchable: list[PatchRecord] = []
        self.not_present: list[str] = []
        self.notes: list[str] = []
        self.error: Optional[str] = None
        # Reversal state: (owner, attr, original, installed, owner_had_own_attr)
        self._sites: list[tuple] = []
        self._reverted = False

    # ── the dict contract ────────────────────────────────────────────────
    #
    # Constraint 3 specifies a literal
    # {"patched": [...], "found_unpatchable": [...], "not_present": [...]}.
    # A rich object is more useful at a REPL, so this supports both readings:
    # `m.patched` for the objects, `m["patched"]` / `dict(m)` for the mapping.

    def keys(self) -> tuple[str, ...]:
        return _SECTION_KEYS

    def __getitem__(self, key: str) -> Any:
        if key not in _SECTION_KEYS:
            raise KeyError(key)
        return getattr(self, key)

    def __iter__(self) -> Iterator[str]:
        return iter(_SECTION_KEYS)

    def __len__(self) -> int:
        return len(_SECTION_KEYS)

    def to_dict(self) -> dict:
        """A JSON-serializable form — for logging the manifest at startup."""
        return {
            "agent_id": self.agent_id,
            "enforcement_mode": self.enforcement_mode,
            "patched": [r.to_dict() for r in self.patched],
            "found_unpatchable": [r.to_dict() for r in self.found_unpatchable],
            "not_present": list(self.not_present),
            "notes": list(self.notes),
            "error": self.error,
        }

    # ── status ───────────────────────────────────────────────────────────

    @property
    def fully_covered(self) -> bool:
        """True when nothing that was present went unpatched.

        Deliberately does NOT consider ``not_present`` — a framework you never
        imported is not a coverage gap.
        """
        return not self.found_unpatchable and self.error is None

    @property
    def is_active(self) -> bool:
        """True while this handle's patches are installed."""
        return bool(self._sites) and not self._reverted

    # ── reversal ─────────────────────────────────────────────────────────

    def unprotect(self, close_sensor: bool = False) -> list[str]:
        """Reverse every patch THIS call installed. Returns the sites restored.

        Only restores a site whose current value is still the wrapper we put
        there. If something else has since patched over us, unwinding would
        clobber that third party's patch, so the site is left alone and reported
        as a warning — a security tool must not silently uninstall someone
        else's instrumentation.

        ``close_sensor`` is opt-out by default: telemetry lifetime belongs to the
        host application, not to a patch handle.
        """
        restored: list[str] = []
        stranded: list[str] = []
        # Unwind in reverse install order.
        for owner, attr, original, installed, had_own in reversed(self._sites):
            label = f"{_owner_label(owner)}.{attr}"
            try:
                current = vars(owner).get(attr, None) if hasattr(owner, "__dict__") else None
                if current is not installed:
                    stranded.append(label)
                    continue
                if had_own:
                    setattr(owner, attr, original)
                else:
                    delattr(owner, attr)
                restored.append(label)
            except Exception as exc:  # never fatal
                stranded.append(f"{label} ({type(exc).__name__})")
        self._sites = []
        self._reverted = True
        if stranded:
            _shout(
                "unprotect() left %d site(s) in place — patched over by someone "
                "else since protect(): %s" % (len(stranded), ", ".join(stranded))
            )
        if close_sensor and self.sensor is not None:
            try:
                self.sensor.close_sync()
            except Exception:
                pass
        return restored

    # ── rendering ────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        L: list[str] = []
        head = (
            f"xaidr.protect() manifest — agent_id={self.agent_id!r} "
            f"mode={self.enforcement_mode!r}"
        )
        L.append(head)
        L.append("=" * len(head))

        if self.error:
            L.append(f"  !! protect() FAILED: {self.error}")
            L.append("  !! NOTHING IS INSTRUMENTED. The host application was not "
                     "interrupted.")

        # UNPROTECTED first: it is the section a reader must not scroll past.
        if self.found_unpatchable:
            L.append(f"  PRESENT BUT NOT PATCHED ({len(self.found_unpatchable)}) "
                     f"— THESE BOUNDARIES ARE UNPROTECTED")
            for r in self.found_unpatchable:
                L.append(f"    x {r.framework:<16} {r.target}  [{r.boundary}]")
                if r.detail:
                    L.append(f"        {r.detail}")

        if self.patched:
            L.append(f"  PATCHED ({len(self.patched)})")
            for r in self.patched:
                mark = "=" if r.already_patched else "+"
                L.append(f"    {mark} {r.framework:<16} {r.target}  [{r.boundary}]")
                if r.detail:
                    L.append(f"        {r.detail}")
        else:
            L.append("  PATCHED (0) — nothing was instrumented")

        if self.not_present:
            L.append(f"  NOT PRESENT ({len(self.not_present)}) — not in sys.modules, "
                     f"nothing to patch")
            L.append("    - " + ", ".join(sorted(self.not_present)))

        if self.notes:
            L.append("  NOTES")
            for n in self.notes:
                L.append(f"    ! {n}")
        return "\n".join(L)

    __str__ = __repr__

    # ── loudness ─────────────────────────────────────────────────────────

    def announce(self, quiet: bool = False) -> None:
        """Emit the manifest.

        The unpatched section is emitted whether or not ``quiet`` is set:
        ``quiet`` exists to silence a clean startup banner, never to silence an
        unprotected boundary.
        """
        for r in self.found_unpatchable:
            msg = (
                f"xaidr.protect(): {r.framework} is imported but its {r.boundary} "
                f"boundary at {r.target} was NOT instrumented — {r.detail}"
            )
            warnings.warn(msg, XaidrProtectionWarning, stacklevel=3)
            _shout(msg)
        if self.error:
            msg = f"xaidr.protect() failed and instrumented nothing: {self.error}"
            warnings.warn(msg, XaidrProtectionWarning, stacklevel=3)
            _shout(msg)
        if not quiet:
            print(repr(self), file=sys.stderr)


def _owner_label(owner: Any) -> str:
    """Dotted name of a patch site's owner — a module or a class."""
    if isinstance(owner, type):
        return f"{owner.__module__}.{owner.__qualname__}"
    return getattr(owner, "__name__", None) or repr(owner)


def _shout(message: str) -> None:
    """One stderr line, in the house ``[xaidr]`` style.

    Warnings alone are not enough: ``-W ignore`` and a default warning filter
    that shows each message once are both realistic, and this is the one
    message a deployer must never miss.
    """
    print(f"[xaidr] {message}", file=sys.stderr)
