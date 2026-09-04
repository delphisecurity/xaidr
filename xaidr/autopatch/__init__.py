"""``xaidr.protect()`` — one explicit call that instruments every agent boundary
this process can actually reach.

    import xaidr
    print(xaidr.protect(agent_id="support-agent", enforcement_mode="block"))

Read the four rules before changing anything here; they are the product, not
implementation detail.

1. **Only what is already imported.** ``protect()`` patches modules found in
   ``sys.modules`` and imports nothing. A framework you have not imported is
   reported in ``not_present``, never pulled in. This is what keeps
   ``pip install xaidr`` a zero-dependency install.
2. **Explicit call.** Nothing installs itself at import time. A security control
   that appears without a call site cannot be audited, and being auditable is
   half of what this is for.
3. **Loud manifest.** A framework that is PRESENT but UNPATCHED is a warning, a
   stderr line, and the first section of the printed manifest. Silence about an
   unprotected boundary is the one outcome this design does not permit.
4. **Idempotent.** Calling ``protect()`` twice does not double-wrap; the second
   call reports each site as ``already_patched``. That is what makes "call it
   again after importing more frameworks" a supported workflow rather than a
   bug.

WHAT protect() DOES NOT DO — and why (the boundaries-only decision):

It constructs a ``Sensor`` from the kwargs you pass and puts it at boundaries.
It does NOT separately wire telemetry, policy loading, or the circuit breaker,
because the Sensor constructor already owns all three and already has deliberate
defaults: a ``StdoutReporter`` when no ``reporter=`` is given, an auto-load of
``./xaidr-policy.yaml`` when no ``policy_file=`` is given, and a circuit breaker
that is ENTIRELY inert unless one is passed. Re-deciding any of those inside
``protect()`` would create a second way to configure one thing and a precedence
question nobody can answer from the call site. The circuit breaker in particular
stays opt-in: it changes availability, and a one-line "protect me" call must
never quietly introduce a new way for the host application to stop serving
traffic. So everything non-boundary is forwarded verbatim as ``**sensor_kwargs``
— which is a real decision about who owns configuration, not a punt.
"""

from __future__ import annotations

import sys
from typing import Any, Iterable, Optional

from .core import PatchContext, PatchUnavailable, exempt
from .frameworks import TARGETS, TARGETS_BY_NAME
from .manifest import (
    PatchRecord,
    ProtectionManifest,
    XaidrProtectionWarning,
    _shout,
)

__all__ = [
    "protect",
    "unprotect",
    "exempt",
    "ProtectionManifest",
    "PatchRecord",
    "XaidrProtectionWarning",
    "active_manifests",
]

#: Every manifest whose patches are still installed, oldest first.
_ACTIVE: list[ProtectionManifest] = []

DEFAULT_AGENT_ID = "xaidr-protected-agent"


def active_manifests() -> list[ProtectionManifest]:
    """The manifests whose patches are currently installed."""
    return [m for m in _ACTIVE if m.is_active]


def _reject_unknown_sensor_kwargs(sensor_kwargs: dict) -> None:
    """Fail on a keyword the Sensor constructor does not accept, and NAME it.

    Why this is checked here rather than left to Python's own TypeError. The
    forwarding contract (``**sensor_kwargs``, see the module docstring) is what
    lets ``protect()`` stay a one-line call, and its cost is that a misspelled
    keyword is indistinguishable from a keyword this build does not have yet.
    The failure it produces is real but nearly unreadable at a call site:

        TypeError: DelphiSensor.__init__() got an unexpected keyword argument
        'nano_enabled'

    That message does not tell an operator that ``enable_nano`` is the spelling
    they wanted, and the two differ by a transposition. A security control that
    is not running because of a transposition is the outcome this package spends
    its whole configuration surface avoiding (see the unknown-category and
    unknown-policy-key validators, which fail the same way for the same reason).

    So the check runs BEFORE the constructor, names the offending keyword, and
    offers the nearest accepted one. It does not change WHETHER protect() raises
    — that is still ``raise_on_config_error``'s decision, unchanged — only what
    the operator reads when it does.
    """
    if not sensor_kwargs:
        return
    import difflib
    import inspect

    from ..sensor import DelphiSensor

    accepted = {
        name for name, p in inspect.signature(DelphiSensor.__init__).parameters.items()
        if name != "self" and p.kind is not inspect.Parameter.VAR_KEYWORD
    }
    unknown = sorted(set(sensor_kwargs) - accepted)
    if not unknown:
        return
    hints = []
    for name in unknown:
        near = difflib.get_close_matches(name, sorted(accepted), n=1, cutoff=0.6)
        hints.append(f"{name!r}" + (f" (did you mean {near[0]!r}?)" if near else ""))
    raise TypeError(
        "xaidr.protect() was given keyword(s) the Sensor does not accept: "
        + ", ".join(hints)
        + ". Nothing was instrumented. protect() forwards every non-boundary "
        "keyword to Sensor(...) verbatim, so a misspelling here disables the "
        "sensor entirely rather than being ignored. Accepted keywords: "
        + ", ".join(sorted(accepted))
        + "."
    )


def protect(
    agent_id: str = DEFAULT_AGENT_ID,
    enforcement_mode: str = "monitor",
    *,
    sensor: Any = None,
    targets: Optional[Iterable[str]] = None,
    quiet: bool = False,
    raise_on_config_error: bool = True,
    **sensor_kwargs: Any,
) -> ProtectionManifest:
    """Instrument every agent boundary reachable in this process. Returns a manifest.

    Args:
        agent_id: identifier recorded on every event. Defaults to a placeholder
            and says so in the manifest notes — a nameless agent in a security
            log is a real cost, so it is visible rather than silent.
        enforcement_mode: ``"monitor"`` (default, observes and flags) or
            ``"block"``. Forwarded to the Sensor, which owns the semantics.
        sensor: an existing ``Sensor`` to instrument with, instead of building
            one. When given, ``agent_id`` / ``enforcement_mode`` /
            ``sensor_kwargs`` are ignored and the sensor's own values are used.
        targets: optional allowlist of framework names (see
            ``xaidr.autopatch.frameworks.TARGETS``). Everything else is skipped
            and reported as skipped, not silently dropped.
        quiet: suppress the clean startup banner. It does NOT suppress warnings
            about a present-but-unpatched framework — nothing does.
        raise_on_config_error: when True (default) an invalid ``agent_id`` /
            ``enforcement_mode`` raises, exactly as ``Sensor(...)`` does. Patch
            failures never raise regardless. See "failure policy" below.

    Failure policy, deliberately split in two:

    * A **patching** failure (a framework at a version we do not recognise, a
      moved attribute, a framework that raises during wrapping) never
      propagates. It lands in ``found_unpatchable``, warns, and the host
      application keeps running.
    * A **configuration** failure — you passed ``enforcement_mode="blcok"``, or
      a keyword the Sensor does not accept — raises by default, and the message
      names the keyword and the nearest accepted spelling. That is your typo,
      not the environment's drift, and a security control that silently is not
      running because of a typo is the worst of the available outcomes. Pass
      ``raise_on_config_error=False`` for the strict never-raise behaviour; you
      then get a manifest with ``error`` set and ``patched`` empty — which means
      NOTHING is protected, so read it.

    COST. This call is cheap (sub-millisecond) with one exception, and it is
    worth knowing before a one-line call goes into an import path:
    ``enable_nano=True`` loads a 130 MB ONNX artifact EAGERLY at construction.
    Measured on a 10-core laptop: ``protect()`` 0.2 ms without it and 1130 ms
    with it, once per process (the model is a singleton, so a second
    ``protect()`` or ``Sensor()`` pays nothing). Load it during startup, never
    on a request path.

    Frameworks imported AFTER this call are NOT patched: no import hook is
    installed, deliberately, because an import hook is exactly the invisible
    self-installing machinery rule 2 exists to forbid. Call ``protect()`` again
    afterwards — rule 4 makes that safe.

    DEEP AGENTS: CALL THIS BEFORE ``import deepagents``. Ordering is usually a
    performance detail; here it silently decides whether a boundary exists at
    all, so it is stated rather than left to the general rule above.
    ``deepagents`` has no seam of its own — ``deepagents.graph`` and
    ``deepagents.middleware.subagents`` each run ``from langchain.agents import
    create_agent`` at IMPORT time, and that is a name rebind. Import deepagents
    first and those modules keep the ORIGINAL builder, so the middleware is
    never injected and the model INPUT and OUTPUT of every deep agent and every
    subagent go unscanned: measured against deepagents 0.7.13, an injected
    prompt reaches the model and a leaked AWS key reaches the caller verbatim.
    Nothing at the call site looks different, which is why this is reported as a
    loud ``found_unpatchable`` gap rather than a note. Two ways to be safe::

        import xaidr
        xaidr.protect(agent_id="a", enforcement_mode="block")   # FIRST
        from deepagents import create_deep_agent                # then this

        # ...or wire it yourself, at a known cost:
        create_deep_agent(model=..., tools=[...],
                          middleware=[delphi_middleware(agent_id="a")])

    The explicit ``middleware=`` form covers the PARENT agent only. Subagents are
    built by a separate ``create_agent`` call inside ``SubAgentMiddleware`` that
    never sees your list, so a subagent's model output is unscanned and returns
    to the parent as a ToolMessage — which no boundary scans either. Only the
    protect-first order reaches inside a subagent.
    """
    manifest = ProtectionManifest(agent_id=agent_id, enforcement_mode=enforcement_mode)

    # ── phase 1: the sensor (configuration errors are yours) ─────────────
    try:
        if sensor is None:
            from ..sensor import DelphiSensor

            _reject_unknown_sensor_kwargs(sensor_kwargs)
            sensor = DelphiSensor(
                agent_id=agent_id,
                enforcement_mode=enforcement_mode,
                **sensor_kwargs,
            )
            if agent_id == DEFAULT_AGENT_ID:
                manifest.notes.append(
                    f"agent_id was not set; every event will be attributed to "
                    f"{DEFAULT_AGENT_ID!r}. Pass agent_id= to make your telemetry "
                    f"identifiable."
                )
        else:
            if sensor_kwargs:
                manifest.notes.append(
                    "an existing sensor= was passed, so these kwargs were IGNORED: "
                    + ", ".join(sorted(sensor_kwargs))
                )
        manifest.agent_id = sensor.agent_id
        manifest.enforcement_mode = sensor.enforcement_mode
        manifest.sensor = sensor
    except Exception as exc:
        manifest.error = f"{type(exc).__name__}: {exc}"
        manifest.error_is_fatal = bool(raise_on_config_error)
        manifest.announce(quiet=quiet)
        if raise_on_config_error:
            raise
        return manifest

    # ── phase 2: discovery + dispatch (nothing here may raise) ───────────
    try:
        _dispatch(manifest, sensor, targets)
    except Exception as exc:  # a bug in our own dispatcher must not be fatal
        manifest.error = (
            f"dispatch aborted after {len(manifest.patched)} patch(es) "
            f"({type(exc).__name__}: {exc})"
        )

    if manifest._sites or manifest._teardowns:
        # Only a call that actually installed something needs unwinding; a
        # fully-idempotent repeat call owns no sites and must not appear active.
        # Registry hooks count: they are instrumentation this call owns and must
        # remove, even though they patched no attribute.
        _ACTIVE.append(manifest)
    manifest.announce(quiet=quiet)
    return manifest


def _dispatch(
    manifest: ProtectionManifest,
    sensor: Any,
    targets: Optional[Iterable[str]],
) -> None:
    selected = None
    if targets is not None:
        selected = set(targets)
        unknown = selected - set(TARGETS_BY_NAME)
        if unknown:
            manifest.notes.append(
                "targets= named frameworks this build does not know about: "
                + ", ".join(sorted(unknown))
            )

    # Rule 1 is checked, not merely intended: if any patcher causes an import,
    # the manifest says which module appeared.
    before_modules = set(sys.modules)

    skipped: list[str] = []
    for target in TARGETS:
        if selected is not None and target.name not in selected:
            # Not attempted — and named, because a framework this call chose not
            # to look at is exactly as unprotected as one it could not patch.
            skipped.append(target.name)
            continue
        if not target.present():
            manifest.not_present.append(target.name)
            continue
        ctx = PatchContext(manifest, sensor, target.name)
        try:
            target.apply(ctx)
        except PatchUnavailable as exc:
            ctx.unpatchable(f"{target.name} (whole framework)", target.summary,
                            str(exc))
        except Exception as exc:
            ctx.unpatchable(
                f"{target.name} (whole framework)", target.summary,
                f"unexpected error while instrumenting "
                f"({type(exc).__name__}: {exc})",
            )

    if skipped:
        manifest.notes.append(
            "targets= limited this call; NOT attempted (and therefore NOT "
            "instrumented, whether or not they are imported): "
            + ", ".join(sorted(skipped))
        )

    appeared = sorted(set(sys.modules) - before_modules)
    # Our own submodules are not framework imports; everything else is a rule-1
    # violation and gets named.
    foreign = [m for m in appeared if not m.startswith("xaidr")]
    if foreign:
        manifest.notes.append(
            "RULE 1 VIOLATION: patching caused these modules to be imported, "
            "which protect() must never do — " + ", ".join(foreign)
        )
        _shout("protect() imported modules while patching: " + ", ".join(foreign))

    if manifest.not_present:
        manifest.notes.append(
            "protect() patches only what is ALREADY in sys.modules and installs "
            "no import hook. Anything listed under NOT PRESENT that you import "
            "later will be UNINSTRUMENTED until you call xaidr.protect() again "
            "(which is idempotent and will only add the new sites)."
        )
    if manifest.patched and all(r.already_patched for r in manifest.patched):
        manifest.notes.append(
            "every site was ALREADY instrumented by an earlier protect(), so "
            "this call's sensor is attached to nothing. If you meant to re-point "
            "instrumentation at a new sensor, call xaidr.unprotect() first."
        )
    if manifest.patched:
        manifest.notes.append(
            "enforcement: TOOL boundaries return a refusal string the agent can "
            "read and recover from; TRANSPORT and ENTRYPOINT boundaries raise "
            "xaidr.DelphiBlockedError, because there is no in-band way for an "
            "HTTP send or a runner entrypoint to say 'refused'."
        )


def unprotect(manifest: Optional[ProtectionManifest] = None,
              close_sensor: bool = False) -> list[str]:
    """Reverse ``protect()``. With no argument, reverses every active manifest.

    Returns the list of restored patch sites. Never raises: a site someone else
    has since patched over is left alone and reported loudly, because silently
    uninstalling a third party's instrumentation would be worse than leaving
    ours in place.
    """
    if manifest is not None:
        restored = manifest.unprotect(close_sensor=close_sensor)
        if manifest in _ACTIVE:
            _ACTIVE.remove(manifest)
        return restored
    restored: list[str] = []
    for m in list(reversed(_ACTIVE)):
        restored.extend(m.unprotect(close_sensor=close_sensor))
    _ACTIVE.clear()
    return restored
