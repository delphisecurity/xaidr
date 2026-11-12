"""Discovery and dispatch machinery for ``xaidr.protect()``.

Four rules are enforced HERE, in one place, so no individual framework patcher
can quietly break them:

1. **Patch only what is already in ``sys.modules``.** :meth:`PatchContext.install`
   resolves the owning module by exact ``sys.modules`` key and never imports.
   ``protect()`` additionally snapshots ``sys.modules`` around the whole patch
   phase and reports any module that appeared, so a violation introduced later
   is visible rather than theoretical. The one deferred form,
   :meth:`PatchContext.install_on_import` (httpx2 only), imports nothing either:
   it waits for the host's own import of that one module, then patches it.
2. **Explicit call, no import-time magic.** Nothing in this package runs on
   import; ``xaidr/__init__.py`` binds the name and stops.
3. **Loud manifest.** Every failure path routes to
   ``manifest.found_unpatchable`` — there is no ``except: pass``.
4. **Idempotent.** Every wrapper carries a ``__xaidr_patch__`` token; a site
   already carrying one is recorded as ``already_patched`` and left untouched.

Everything a wrapper does at runtime fails OPEN: a fault in extraction or
scanning lets the original call through. Only a clean halting VERDICT stops it.
"""

from __future__ import annotations

import functools
import inspect
import logging
import sys
import threading
import warnings
from typing import Any, Callable, Optional

from ..types import DelphiBlockedError, ScanResult
from .manifest import PatchRecord, ProtectionManifest, XaidrProtectionWarning, _shout

logger = logging.getLogger("xaidr.protect")

#: Marker stamped on every wrapper this module installs. Identity, not a bool,
#: so a stray truthy attribute on someone else's function cannot impersonate it.
PATCH_TOKEN = object()


class PatchUnavailable(Exception):
    """A framework is present but its shape is not one we can instrument.

    Raised by a patcher (or by :meth:`PatchContext.install`) and turned into a
    ``found_unpatchable`` manifest entry. Never escapes ``protect()``.
    """


class Halt:
    """Sentinel returned by a ``before`` hook to skip the original call.

    Carries the in-band refusal value the caller receives instead.
    """

    __slots__ = ("value",)

    def __init__(self, value: Any) -> None:
        self.value = value


_MISSING = object()

#: Registry-hook targets this process has already registered into. The
#: idempotency rule (rule 4) applies to a framework's callback registry exactly
#: as it does to a patched attribute, but a registry has no wrapper to stamp
#: with PATCH_TOKEN — so the record lives here instead. Entries are removed by
#: the teardown installed alongside them.
_INSTALLED_REGISTRY_HOOKS: set[str] = set()

#: Attribute marking an HTTP client whose traffic the egress patches must ignore.
EXEMPT_ATTR = "_xaidr_exempt"

#: The import hook of each module name ``install_on_import`` has served: one
#: object per name for the life of the process. It is inserted into
#: ``sys.meta_path`` once and never taken out (removing an entry while another
#: thread's import walks the list makes that walk skip the next finder); it is
#: ARMED by a ``protect()`` and DISARMED when it fires or by ``unprotect()``,
#: and a disarmed hook answers nothing.
_IMPORT_HOOKS: dict = {}
_HOOKS_LOCK = threading.Lock()


class _ImportHook:
    """A meta-path hook for ONE module name; inert unless armed.

    Armed, it answers ``find_spec`` for its name only, and only by asking the
    finders behind it for the real spec: it never imports and never changes
    which module is loaded. It wraps that spec's loader's ``exec_module`` on the
    loader instance; when the module of ITS name has run its own code (a loader
    shared by several modules, as zipimport's is, runs others through the same
    wrapper first), the loader is restored and the armed callback runs once,
    under a lock that ``disarm`` also takes, so an ``unprotect()`` either lands
    before it (nothing is patched) or after it (the patch is unwound). A fault
    in the callback is logged and never raised into the host's import.
    """

    def __init__(self, name: str) -> None:
        self._name = name
        self._lock = threading.RLock()
        self._on_loaded: Optional[Callable[[Any], None]] = None

    @property
    def armed(self) -> bool:
        return self._on_loaded is not None

    def arm(self, on_loaded: Callable[[Any], None]) -> bool:
        with self._lock:
            if self._on_loaded is not None:
                return False
            self._on_loaded = on_loaded
            return True

    def disarm(self, on_loaded: Optional[Callable[[Any], None]] = None) -> None:
        """Disarm, or, given ``on_loaded``, disarm only if that is what is armed."""
        with self._lock:
            if on_loaded is None or self._on_loaded is on_loaded:
                self._on_loaded = None

    def find_spec(self, fullname, path=None, target=None):  # the finder protocol
        if fullname != self._name or self._on_loaded is None:
            return None
        spec = _spec_behind(self, fullname, path, target)
        loader = getattr(spec, "loader", None)
        exec_module = getattr(loader, "exec_module", None)
        if exec_module is None:
            return None                    # the import proceeds exactly as without us
        hook = self

        def exec_module_then_patch(module):
            exec_module(module)
            if getattr(module, "__name__", None) != hook._name:
                return                     # a shared loader running another module
            try:
                del loader.exec_module     # the loader is the module's __loader__
            except Exception:
                pass
            hook._loaded(module)

        try:
            loader.exec_module = exec_module_then_patch
        except Exception:
            return None
        return spec

    def _loaded(self, module: Any) -> None:
        with self._lock:
            on_loaded, self._on_loaded = self._on_loaded, None
            if on_loaded is None:
                return
            try:
                on_loaded(module)
            except Exception as exc:  # never into the host's import
                logger.warning(
                    "xaidr.protect: the deferred patch for %s failed (%s); it is NOT "
                    "instrumented", self._name, type(exc).__name__,
                )


def _spec_behind(hook: Any, fullname: str, path=None, target=None):
    """The spec the finders other than xaidr's import hooks give ``fullname``,
    asked in ``sys.meta_path`` order, as the import system asks them. Reads a
    spec; imports nothing."""
    for finder in list(sys.meta_path):
        if finder is hook or isinstance(finder, _ImportHook):
            continue
        find = getattr(finder, "find_spec", None)
        if find is None:
            continue
        spec = find(fullname, path, target)
        if spec is not None:
            return spec
    return None


def _installed(name: str) -> bool:
    """Whether a top-level module ``name`` is importable here, read the way the
    import system reads it and without importing it (nor ``importlib.util``)."""
    try:
        return _spec_behind(None, name) is not None
    except Exception:
        return False


def is_armed_on_import(name: str) -> bool:
    """True while an import hook for ``name`` is armed in this process."""
    hook = _IMPORT_HOOKS.get(name)
    return hook is not None and hook.armed


def exempt(obj: Any) -> Any:
    """Mark an HTTP client so ``protect()``'s egress patches skip its traffic.

    Needed for one specific, real feedback loop: a telemetry reporter that ships
    events over HTTP. Once ``httpx.Client.send`` is patched, the reporter's own
    POST is scanned, that scan enqueues an event, that event is flushed as
    another POST, and the sensor talks to itself forever. ``WebhookReporter``
    marks its client with this; mark yours if you wrote your own HTTP reporter.

    Returns ``obj`` so it can be used inline: ``client = exempt(httpx.Client())``.
    """
    try:
        setattr(obj, EXEMPT_ATTR, True)
    except Exception:
        logger.warning(
            "xaidr.protect: could not mark %s as exempt from egress scanning",
            type(obj).__name__,
        )
    return obj


def is_exempt(args: tuple) -> bool:
    """True when the bound instance (``args[0]``) is marked exempt."""
    return bool(args) and bool(getattr(args[0], EXEMPT_ATTR, False))


def is_xaidr_wrapper(obj: Any) -> bool:
    """True if ``obj`` is a wrapper installed by a previous ``protect()``."""
    if obj is None:
        return False
    # Bound methods / classmethods proxy attribute reads to __func__, but be
    # explicit so a descriptor object (classmethod/staticmethod) works too.
    for candidate in (obj, getattr(obj, "__func__", None)):
        if candidate is not None and getattr(candidate, "__xaidr_patch__", None) is PATCH_TOKEN:
            return True
    return False


def make_wrapper(
    original: Callable,
    before: Optional[Callable[[tuple, dict], Optional[Halt]]] = None,
    after: Optional[Callable[[Any, tuple, dict], Any]] = None,
) -> Callable:
    """Wrap ``original``, matching its sync/async-ness.

    ``before(args, kwargs)`` returns ``None`` to proceed or a :class:`Halt` to
    short-circuit. ``after(result, args, kwargs)`` may replace the result.

    Both hooks fail OPEN: any exception other than :class:`DelphiBlockedError`
    (deliberate control flow) is logged and swallowed, and the call proceeds.
    A security wrapper that crashes the host is worse than one that misses.
    """

    def _before(args, kwargs):
        if before is None:
            return None
        try:
            return before(args, kwargs)
        except DelphiBlockedError:
            raise
        except Exception as exc:
            # Type only, never the message: a fault raised while handling a URL
            # or a tool argument can interpolate that content into its message.
            logger.warning(
                "xaidr.protect: %s pre-call hook failed open (%s) "
                "[message suppressed: may contain request content]",
                getattr(original, "__qualname__", original),
                type(exc).__name__,
            )
            return None

    def _after(result, args, kwargs):
        if after is None:
            return result
        try:
            return after(result, args, kwargs)
        except DelphiBlockedError:
            raise
        except Exception as exc:
            logger.warning(
                "xaidr.protect: %s post-call hook failed open (%s) "
                "[message suppressed: may contain response content]",
                getattr(original, "__qualname__", original),
                type(exc).__name__,
            )
            return result

    if inspect.iscoroutinefunction(original):

        async def wrapper(*args, **kwargs):  # type: ignore[misc]
            halt = _before(args, kwargs)
            if halt is not None:
                return halt.value
            result = await original(*args, **kwargs)
            return _after(result, args, kwargs)

    else:

        def wrapper(*args, **kwargs):
            halt = _before(args, kwargs)
            if halt is not None:
                return halt.value
            result = original(*args, **kwargs)
            return _after(result, args, kwargs)

    try:
        functools.wraps(original)(wrapper)
    except Exception:  # exotic callables (builtins, C functions)
        pass
    # AFTER functools.wraps: wraps copies __dict__ from the original, which
    # would otherwise let a token leak backwards onto an unpatched function.
    wrapper.__xaidr_patch__ = PATCH_TOKEN
    wrapper.__xaidr_original__ = original
    return wrapper


class PatchContext:
    """Handed to each framework patcher. The only sanctioned way to patch."""

    def __init__(self, manifest: ProtectionManifest, sensor: Any, framework: str) -> None:
        self.manifest = manifest
        self.sensor = sensor
        self.framework = framework

    # ── resolution (sys.modules only) ────────────────────────────────────

    def module(self, name: str) -> Any:
        """Return an ALREADY-IMPORTED module, or raise PatchUnavailable.

        Never imports. ``name`` must be the exact ``sys.modules`` key, so a
        lazy package ``__getattr__`` cannot be tricked into importing a
        submodule for us.
        """
        mod = sys.modules.get(name)
        if mod is None:
            raise PatchUnavailable(
                f"module {name!r} is not in sys.modules — import it before "
                f"calling xaidr.protect(), or call protect() again afterwards"
            )
        return mod

    def _owner(self, module_name: str, dotted: str) -> tuple[Any, str]:
        obj = self.module(module_name)
        parts = dotted.split(".")
        for step in parts[:-1]:
            try:
                obj = getattr(obj, step)
            except AttributeError as exc:
                raise PatchUnavailable(
                    f"{module_name}.{'.'.join(parts[:-1])} not found "
                    f"({type(exc).__name__}) — unexpected version layout"
                ) from exc
        return obj, parts[-1]

    # ── the one patch primitive ──────────────────────────────────────────

    def install(
        self,
        module_name: str,
        dotted: str,
        boundary: str,
        factory: Callable[[Callable], Callable],
        detail: str = "",
    ) -> None:
        """Replace ``module_name.dotted`` with ``factory(original)``.

        Records exactly one manifest entry either way. Preserves
        ``classmethod``/``staticmethod`` descriptors so the patched call site
        keeps its binding semantics.

        Raises :class:`PatchUnavailable` when the site is not what we expect —
        the caller (``protect``) turns that into a loud ``found_unpatchable``.
        """
        target = f"{module_name}.{dotted}"
        owner, attr = self._owner(module_name, dotted)

        resolved = getattr(owner, attr, _MISSING)
        if resolved is _MISSING:
            raise PatchUnavailable(
                f"{target} does not exist on this version — nothing to wrap"
            )

        # ── idempotency ──────────────────────────────────────────────────
        if is_xaidr_wrapper(resolved):
            self.manifest.patched.append(
                PatchRecord(
                    framework=self.framework,
                    target=target,
                    boundary=boundary,
                    detail="already patched by an earlier xaidr.protect(); "
                           "left as-is (not double-wrapped)",
                    already_patched=True,
                )
            )
            return

        own = vars(owner).get(attr, _MISSING) if hasattr(owner, "__dict__") else _MISSING
        had_own = own is not _MISSING

        if isinstance(own, (classmethod, staticmethod)):
            inner = own.__func__
            if not callable(inner):
                raise PatchUnavailable(f"{target} is not callable")
            installed = type(own)(factory(inner))
            original_for_undo = own
        else:
            func = own if had_own else resolved
            if not callable(func):
                raise PatchUnavailable(
                    f"{target} is a {type(func).__name__}, not a callable — "
                    f"this version does not expose it as a patchable call site"
                )
            installed = factory(func)
            original_for_undo = func

        setattr(owner, attr, installed)
        self.manifest._sites.append((owner, attr, original_for_undo, installed, had_own))
        self.manifest.patched.append(
            PatchRecord(
                framework=self.framework,
                target=target,
                boundary=boundary,
                detail=detail,
            )
        )

    # ── the second primitive: a framework's OWN callback registry ────────

    def install_registry_hook(
        self,
        target: str,
        boundary: str,
        register: Callable[[], Callable[[], None]],
        detail: str = "",
    ) -> bool:
        """Instrument via a framework's sanctioned hook registry, not a patch.

        ``register()`` installs the hook and returns the callable that removes
        it again; that callable is stored on the manifest so ``unprotect()``
        undoes this exactly as it undoes a monkeypatch.

        Preferred over :meth:`install` wherever a framework offers one. A patch
        is a bet that a private call path will not move; a registry is a
        contract the framework maintains. CrewAI is the worked example: its
        agent tool path does not go through ``BaseTool.run``, so a patch there
        would be silently dead while a manifest still claimed coverage.

        Idempotency cannot use the wrapper token here — there is no wrapper to
        stamp — so it keys on a process-wide record of which registries this
        package has already registered into. Records exactly one manifest entry
        either way, like :meth:`install`. Returns whether a hook was installed.
        """
        if target in _INSTALLED_REGISTRY_HOOKS:
            self.manifest.patched.append(
                PatchRecord(
                    framework=self.framework,
                    target=target,
                    boundary=boundary,
                    detail="already registered by an earlier xaidr.protect(); "
                           "left as-is (not registered twice)",
                    already_patched=True,
                )
            )
            return False
        try:
            uninstall = register()
        except Exception as exc:
            self.unpatchable(
                target, boundary,
                f"the framework's hook registry rejected our hook "
                f"({type(exc).__name__}: {exc})",
            )
            return False
        if not callable(uninstall):
            self.unpatchable(
                target, boundary,
                "hook registration returned no uninstall callable, so this "
                "could not be made reversible and was not kept",
            )
            return False

        _INSTALLED_REGISTRY_HOOKS.add(target)

        def teardown() -> None:
            try:
                uninstall()
            finally:
                _INSTALLED_REGISTRY_HOOKS.discard(target)

        self.manifest._teardowns.append((target, teardown))
        self.manifest.patched.append(
            PatchRecord(
                framework=self.framework,
                target=target,
                boundary=boundary,
                detail=detail,
            )
        )
        return True

    # ── the third primitive: a patch that waits for the host's import ───

    def install_on_import(self, module_name: str, apply: Callable[["PatchContext"], None],
                          summary: str) -> bool:
        """Arm the import hook for ``module_name``, so ``apply`` runs when the host
        first imports it, for a target whose module is installed but not imported.

        Imports nothing: whether the module is installed is read from the import
        system's own finders, and the hook waits for the host's import. When the
        module is not installed nothing is armed and nothing is noted. One armed
        hook per module name in the process (rule 4); ``unprotect()`` disarms it.
        When it fires, ``apply`` runs on this manifest and sensor as ``protect()``
        would have, its sites join ``manifest.patched`` and are unwound by
        ``unprotect()``, and a site it cannot patch is warned and shouted then,
        because the manifest was printed at ``protect()``. Returns whether this
        call armed it.
        """
        if module_name in sys.modules:
            return False
        if is_armed_on_import(module_name):
            self.note(
                f"{module_name}: its import hook was already armed by an earlier "
                "xaidr.protect(); left as-is (not armed twice)")
            return False
        if not _installed(module_name):
            return False

        manifest, sensor, framework = self.manifest, self.sensor, self.framework

        def on_loaded(module: Any) -> None:
            if manifest._reverted:
                return
            ctx = PatchContext(manifest, sensor, framework)
            seen = len(manifest.found_unpatchable)
            try:
                apply(ctx)
            except PatchUnavailable as exc:
                ctx.unpatchable(f"{framework} (whole framework)", summary, str(exc))
            except Exception as exc:
                ctx.unpatchable(
                    f"{framework} (whole framework)", summary,
                    f"unexpected error while instrumenting ({type(exc).__name__}: {exc})")
            if framework in manifest.not_present:
                manifest.not_present.remove(framework)
            for r in manifest.found_unpatchable[seen:]:
                msg = (f"xaidr.protect(): {r.framework} was imported after protect() but "
                       f"its {r.boundary} boundary at {r.target} was NOT instrumented — "
                       f"{r.detail}")
                warnings.warn(msg, XaidrProtectionWarning, stacklevel=2)
                _shout(msg)
            done = [r.target for r in manifest.patched if r.framework == framework]
            if done:
                logger.info("xaidr.protect: %s imported after protect(); patched %s",
                            framework, ", ".join(done))

        with _HOOKS_LOCK:
            hook = _IMPORT_HOOKS.get(module_name)
            if hook is None:
                hook = _IMPORT_HOOKS[module_name] = _ImportHook(module_name)
            if not any(f is hook for f in sys.meta_path):
                sys.meta_path.insert(0, hook)
            if not hook.arm(on_loaded):
                return False
        self.manifest._disarms.append(lambda: hook.disarm(on_loaded))
        self.note(
            f"{module_name}: installed but not imported yet. protect() armed an import "
            f"hook for this one module, which patches it when the host imports it; "
            f"unprotect() disarms the hook. protect() itself imports nothing.")
        return True

    def try_install(self, module_name: str, dotted: str, boundary: str,
                    factory: Callable[[Callable], Callable], detail: str = "") -> bool:
        """:meth:`install`, but a shape mismatch records instead of raising.

        For a framework with several independent seams, one missing seam must
        not cost us the others — but it must still be reported. Returns whether
        the site was patched.
        """
        try:
            self.install(module_name, dotted, boundary, factory, detail)
            return True
        except PatchUnavailable as exc:
            self.unpatchable(f"{module_name}.{dotted}", boundary, str(exc))
            return False
        except Exception as exc:  # a framework's own descriptor blowing up
            self.unpatchable(
                f"{module_name}.{dotted}", boundary,
                f"unexpected error while patching ({type(exc).__name__}: {exc})",
            )
            return False

    # ── manifest helpers ─────────────────────────────────────────────────

    def unpatchable(self, target: str, boundary: str, detail: str) -> None:
        """Record a boundary we deliberately or unavoidably did not cover."""
        self.manifest.found_unpatchable.append(
            PatchRecord(
                framework=self.framework,
                target=target,
                boundary=boundary,
                detail=detail,
            )
        )

    def note(self, message: str) -> None:
        if message not in self.manifest.notes:
            self.manifest.notes.append(message)


# ── shared enforcement helpers used by the framework patchers ────────────


def refusal_text(tool_name: str, result: ScanResult) -> str:
    """The in-band refusal a tool boundary returns.

    Word-for-word the strings ``Sensor.protect_tools`` returns, because an
    operator reading a transcript must not have to learn two vocabularies for
    the same verdict — and because a denial (final) and a pending approval
    (routable to a human) must never collapse into one message.
    """
    # FAIL-CLOSED FIRST, because it is the one refusal that is NOT a statement
    # about the content. Everything else here tells the agent its action was
    # judged; this tells it the judgement could not be made. An agent handed
    # "[BLOCKED] blocked by security policy (fail_closed)" will reasonably try
    # to rephrase the call, which cannot help and wastes a turn — so the text
    # says the sensor is degraded and that retrying will not change it.
    if getattr(result, "input_status", None) == "fail_closed":
        pending = getattr(result, "action", None) == "approval_required"
        head = "[APPROVAL REQUIRED]" if pending else "[BLOCKED]"
        tail = (
            "Route this action to a human approver."
            if pending else
            "Retrying will not help; this is an operator-configured refusal."
        )
        rule = (getattr(result, "rules", None) or ["FAIL_CLOSED"])[0]
        return (
            f"{head} Tool '{tool_name}' was NOT executed: the security sensor "
            f"could not produce a reliable verdict ({rule}) and this deployment "
            f"is configured to refuse rather than allow in that case. {tail}"
        )
    if getattr(result, "action", None) == "approval_required":
        return (
            f"[APPROVAL REQUIRED] Tool '{tool_name}' requires human approval "
            f"and was NOT executed ({result.category or 'policy'}). Route this "
            "action to a human approver."
        )
    if getattr(result, "category", None) == "blocked_tool":
        return f"[BLOCKED] Tool '{tool_name}' has been blocked by local policy."
    return (
        f"[BLOCKED] Tool '{tool_name}' blocked by security policy "
        f"({result.category or 'policy'})."
    )


def tool_verdict(sensor: Any, tool_name: str, arguments: Any) -> Optional[ScanResult]:
    """Scan one tool invocation. ``None`` means proceed; a result means HALT.

    Mirrors ``protect_tools``: the operator blocked-tools list is enforced in
    BOTH enforcement modes (an explicit block is configuration, not a detection
    verdict, so monitor mode does not soften it); detection and policy verdicts
    honour ``enforcement_mode``.
    """
    if not isinstance(arguments, dict):
        arguments = {"input": arguments} if arguments is not None else {}
    result = sensor.scan_tool_call(tool_name, arguments)
    if tool_name in getattr(sensor, "_blocked_tools", ()):
        _shout(f"TOOL BLOCKED: {tool_name}")
        return ScanResult(
            action="blocked", score=1.0, category="blocked_tool",
            rules=["TOOL_BLOCKED"], latency_ms=result.latency_ms,
            value_origin=getattr(result, "value_origin", None),   # C-13, A2 M4
            found_action="blocked",            # configuration: blocks in both modes
            scan_id=getattr(result, "scan_id", None),   # the row this call emitted
        )
    if result.must_halt:
        _shout(
            f"TOOL {'APPROVAL REQUIRED' if result.requires_approval else 'BLOCKED'}: "
            f"{tool_name} ({result.category}: {', '.join(result.rules)})"
        )
        return result
    return None


def scan_tool_boundary(sensor: Any, tool_name: str, arguments: Any) -> Optional[Halt]:
    """:func:`tool_verdict` plus the in-band refusal string a tool returns."""
    result = tool_verdict(sensor, tool_name, arguments)
    if result is None:
        return None
    return Halt(refusal_text(tool_name, result))


def scan_text_boundary(
    sensor: Any, text: Any, direction: str = "input", **kwargs: Any
) -> None:
    """Scan free text at an entrypoint boundary. Raises on a halting verdict.

    Entrypoint and transport boundaries have no in-band way to say "refused" —
    there is no ToolMessage to return — so they raise ``DelphiBlockedError``,
    which is the same signal ``protect_http`` has always raised. Tool
    boundaries return a refusal string instead; that split is deliberate and
    documented in the manifest notes.
    """
    if not isinstance(text, str) or not text.strip():
        return
    if direction == "output":
        result = sensor.scan_output(text, **kwargs)
    else:
        result = sensor.scan(text, direction=direction, **kwargs)
    if result.must_halt:
        raise DelphiBlockedError(result)


def strings_in(value: Any, limit: int = 64) -> list[str]:
    """Collect string leaves from a nested structure, bounded.

    Used where a framework hands us an untyped ``inputs`` dict. Bounded so a
    pathological payload cannot turn one entrypoint into an unbounded scan.
    """
    out: list[str] = []

    def walk(node: Any) -> None:
        if len(out) >= limit:
            return
        if isinstance(node, str):
            if node.strip():
                out.append(node)
        elif isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, (list, tuple)):
            for v in node:
                walk(v)

    walk(value)
    return out
