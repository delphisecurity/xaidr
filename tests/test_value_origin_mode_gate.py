"""The structural gate: no public route asks for value-origin enforcement and gets
RECORD instead (owner, 2026-11-09).

Not a list of entry points. The gate walks every public callable (everything in
``xaidr.__all__`` and ``xaidr.value_origin.__all__``, and the public functions and
classes of ``xaidr.integrations.*``) and every parameter named like ``mode`` or
``value_origin``, and, where a callable forwards ``**kwargs`` to a sensor,
``value_origin=`` through them. It calls each with every spelling of enforcement,
alone and beside an existing sensor wherever the callable takes ``sensor=``.

* A value-origin mode (``value_origin``, or ``mode`` in ``xaidr.value_origin``)
  must raise ``ValueOriginEnforcementUnavailable``.
* Any other mode-named parameter may raise anything; if the call returns normally,
  what it returns must not hold value origin in RECORD (a ``Mode``, a
  ``should_block`` answer, or a sensor, or an object holding one).

A framework not installed is a skip, unless ``XAIDR_GATE_REQUIRE_FRAMEWORKS=1``
(the CI job that installs LangChain and Haystack sets it), where it fails.
"""
from __future__ import annotations

import contextlib
import importlib
import inspect
import io
import os
import pkgutil
import re
import warnings

import pytest

import xaidr
import xaidr.integrations
from xaidr import value_origin as vo
from xaidr.value_origin import Mode


class _LyingStr(str):
    """A str subclass whose own __str__ says RECORD."""

    def __str__(self):
        return "record"


SPELLINGS = {"enforce": "enforce", "ENFORCE": "ENFORCE", "padded": " Enforce ",
             "str-subclass": _LyingStr("enforce"), "Mode.ENFORCE": Mode.ENFORCE}
MODE_LIKE = re.compile(r"(^|_)mode$|value_origin")
REQUIRE_FRAMEWORKS = os.environ.get("XAIDR_GATE_REQUIRE_FRAMEWORKS") == "1"


def _quiet(fn):
    with warnings.catch_warnings(), contextlib.redirect_stdout(io.StringIO()):
        warnings.simplefilter("ignore")
        return fn()


class _Null:
    def report(self, *a, **k): pass
    def close(self, *a, **k): pass


def _sensor():
    return _quiet(lambda: xaidr.Sensor(agent_id="gate", reporter=_Null()))


def _verdict():
    vo.bind_fresh_ledger()
    try:
        return vo.evaluate_call("http_post", {"url": "https://x.example/"}, flow_active=True)
    finally:
        vo.unbind_ledger()


# Values for REQUIRED parameters, by name. A new public callable whose required
# parameter is not here fails the gate until it is added: the walk cannot call it.
SAMPLES = {"agent_id": lambda: "gate", "enforcement_mode": lambda: "monitor",
           "direction": lambda: "input", "action": lambda: "allowed", "score": lambda: 0.0,
           "verdict": _verdict, "wire": lambda: "untrusted_source",
           "scan_mode": lambda: "tool_call", "mode": lambda: "record"}


def _public():
    """``[(label, callable, module)]`` for every public callable."""
    out, seen = [], set()

    def add(label, obj, module):
        if inspect.isclass(obj):
            targets = [(label, obj)] + [(f"{label}.{n}", f) for n, f in
                                        inspect.getmembers(obj, inspect.isfunction)
                                        if not n.startswith("_")]
        elif callable(obj):
            targets = [(label, obj)]
        else:
            targets = []
        for lab, t in targets:
            if lab not in seen:
                seen.add(lab)
                out.append((lab, t, module))
    for name in xaidr.__all__:
        add(f"xaidr.{name}", getattr(xaidr, name), "xaidr")
    for name in vo.__all__:
        add(f"xaidr.value_origin.{name}", getattr(vo, name), "xaidr.value_origin")
    for m in pkgutil.iter_modules(xaidr.integrations.__path__):
        if m.name.startswith("_"):
            continue
        mod = importlib.import_module(f"xaidr.integrations.{m.name}")
        for name, obj in sorted(vars(mod).items()):
            if not name.startswith("_") and getattr(obj, "__module__", None) == mod.__name__:
                add(f"xaidr.integrations.{m.name}.{name}", obj, mod.__name__)
    return out


def _routes():
    """``(label, callable, module, param, via_kwargs)``: every mode-like parameter,
    and ``value_origin`` through ``**kwargs`` where a callable forwards them."""
    out = []
    for label, fn, module in _public():
        try:
            params = inspect.signature(fn).parameters
        except (TypeError, ValueError):
            continue
        if "self" in params and not any(MODE_LIKE.search(p) for p in params):
            continue                             # a method with no mode of its own
        named = [p for p in params if MODE_LIKE.search(p)]
        for p in named:
            out.append((label, fn, module, p, False))
        # **kwargs beside a sensor= parameter is the forwarding signature: those
        # keywords build the sensor (protect, delphi_middleware, delphi_hooks).
        if (any(p.kind is p.VAR_KEYWORD for p in params.values()) and "sensor" in params
                and "value_origin" not in params):
            out.append((label, fn, module, "value_origin", True))
    return out


ROUTES = _routes()


def _is_value_origin_mode(fn, module, param, via_kwargs):
    """A value-origin MODE: ``mode`` in xaidr.value_origin, ``value_origin`` passed
    through a sensor-building ``**kwargs``, or a parameter whose default is a mode.
    (``ScanResult.value_origin`` is a result field, defaulting to None.)"""
    if via_kwargs or (module == "xaidr.value_origin" and param == "mode"):
        return True
    p = inspect.signature(fn).parameters.get(param)
    return p is not None and p.default in {m.value for m in Mode} | set(Mode)


def _holds_record(result):
    """Does a normal return leave value origin in RECORD (or answer the decision)?"""
    if isinstance(result, (Mode, bool)):
        return True
    for obj in (result, getattr(result, "sensor", None), getattr(result, "_sensor", None)):
        if getattr(obj, "_value_origin", None) is not None:
            return True
    return False


def _call(fn, param, value, with_sensor):
    params = inspect.signature(fn).parameters
    args, kwargs = [], {}
    for name, p in params.items():
        if name in ("self", param) or p.kind in (p.VAR_KEYWORD, p.VAR_POSITIONAL):
            continue
        if p.default is not inspect.Parameter.empty:
            continue
        assert name in SAMPLES, (f"{fn.__qualname__} requires {name!r}; add a sample to "
                                 "SAMPLES so the gate can call it")
        if p.kind is p.POSITIONAL_ONLY:
            args.append(SAMPLES[name]())
        else:
            kwargs[name] = SAMPLES[name]()
    kwargs[param] = value
    if with_sensor:
        kwargs["sensor"] = _sensor()
    if "raise_on_config_error" in params:
        kwargs.setdefault("quiet", True)
    return _quiet(lambda: fn(*args, **kwargs))


CASES = [pytest.param(r, s, w, id=f"{r[0]}:{r[3]}{'(**kw)' if r[4] else ''}:{s}"
                      f"{':beside-sensor' if w else ''}")
         for r in ROUTES for s in SPELLINGS
         for w in ((False, True) if "sensor" in inspect.signature(r[1]).parameters else (False,))]


@pytest.mark.parametrize("route,spelling,with_sensor", CASES)
def test_no_route_reads_enforcement_as_record(route, spelling, with_sensor):
    label, fn, module, param, via_kwargs = route
    vo_mode = _is_value_origin_mode(fn, module, param, via_kwargs)
    try:
        result = _call(fn, param, SPELLINGS[spelling], with_sensor)
    except ImportError as e:
        if REQUIRE_FRAMEWORKS:
            raise
        pytest.skip(f"{label}: its framework is not installed ({e})")
    except Exception as e:
        if type(e).__name__ == "ValueOriginEnforcementUnavailable":   # the refusal
            return
        assert not vo_mode, (
            f"{label}({param}={SPELLINGS[spelling]!r}) raised {type(e).__name__}: {e}, "
            "not ValueOriginEnforcementUnavailable")
        return
    try:
        kept = getattr(result, param, object()) is SPELLINGS[spelling]   # stored as given
        assert not vo_mode and (kept or not _holds_record(result)), (
            f"{label}({param}={SPELLINGS[spelling]!r}"
            f"{', sensor=<Sensor>' if with_sensor else ''}) returned normally "
            f"({type(result).__name__}): a request for enforcement read as RECORD")
    finally:
        if isinstance(result, xaidr.ProtectionManifest):
            _quiet(result.unprotect)


def test_the_gate_walks_the_routes_it_must():
    """Not vacuous: the routes this gate exists for are among those it walks."""
    labels = {(r[0], r[3]) for r in ROUTES}
    for must in [("xaidr.Sensor", "value_origin"), ("xaidr.value_origin.should_block", "mode"),
                 ("xaidr.value_origin.validate_mode", "mode"), ("xaidr.protect", "value_origin"),
                 ("xaidr.integrations.langchain.delphi_middleware", "value_origin"),
                 ("xaidr.integrations.haystack.delphi_hooks", "value_origin")]:
        assert must in labels, f"the gate does not walk {must}"
    assert any(c.values[2] for c in CASES), "no route was called beside an existing sensor"


def test_the_error_is_public_and_a_value_error():
    from xaidr import ValueOriginEnforcementUnavailable
    assert "ValueOriginEnforcementUnavailable" in xaidr.__all__
    assert issubclass(ValueOriginEnforcementUnavailable, ValueError)
    with pytest.raises(ValueOriginEnforcementUnavailable):
        vo.validate_mode("enforce")


@pytest.mark.parametrize("bad", ["recrod", "", "Record ", None, 0, ["record"]])
def test_a_value_that_is_not_a_mode_is_a_plain_error_never_record(bad):
    with pytest.raises(ValueError) as e:
        vo.validate_mode(bad)
    assert type(e.value) is ValueError, f"{bad!r}: {type(e.value).__name__}"
    with pytest.raises(ValueError):
        vo.should_block(_verdict(), mode=bad)


# ── instances: methods are called on real objects ────────────────────────────

def _classes():
    out = {}
    for name in xaidr.__all__:
        obj = getattr(xaidr, name)
        if inspect.isclass(obj):
            out[f"xaidr.{name}"] = obj
    for m in pkgutil.iter_modules(xaidr.integrations.__path__):
        if m.name.startswith("_"):
            continue
        mod = importlib.import_module(f"xaidr.integrations.{m.name}")
        for name, obj in sorted(vars(mod).items()):
            if (inspect.isclass(obj) and not name.startswith("_")
                    and getattr(obj, "__module__", None) == mod.__name__):
                out[f"xaidr.integrations.{m.name}.{name}"] = obj
    return out


def _build(cls):
    """An instance from SAMPLES (a Sensor gets a null reporter), or the reason not."""
    if cls is xaidr.Sensor:
        return _sensor(), None
    if issubclass(cls, BaseException):
        return None, "an exception or warning class"
    try:
        params = inspect.signature(cls).parameters
    except (TypeError, ValueError):
        return None, "no signature"
    kwargs = {}
    for name, p in params.items():
        if p.default is not inspect.Parameter.empty or p.kind in (p.VAR_KEYWORD, p.VAR_POSITIONAL):
            continue
        if name not in SAMPLES:
            return None, f"requires {name!r}"
        kwargs[name] = SAMPLES[name]()
    try:
        return _quiet(lambda: cls(**kwargs)), None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"[:120]


INSTANCES, UNBUILT = {}, {}
for _label, _cls in _classes().items():
    _obj, _why = _build(_cls)
    if _obj is None:
        UNBUILT[_label] = _why
    else:
        INSTANCES[_label] = _obj


# The public classes the gate cannot build from SAMPLES, and why. Exact: a class
# added to the public API that the gate cannot build is a red, not a silent hole.
CANNOT_INSTANTIATE = {
    "xaidr.DelphiBlockedError": "an exception or warning class",
    "xaidr.ValueOriginEnforcementUnavailable": "an exception or warning class",
    "xaidr.XaidrProtectionWarning": "an exception or warning class",
    "xaidr.HealthReport": "requires 'healthy'",
    "xaidr.ProtectedHttpClient": "requires 'client'",
    "xaidr.ToolView": "requires 'name'",
    "xaidr.integrations.web.RequestScopeASGIMiddleware": "requires 'app'",
    "xaidr.integrations.web.RequestScopeMiddleware": "requires 'app'",
}


def test_the_classes_the_gate_cannot_instantiate_are_listed():
    """The gate calls each public method on a real instance. The classes it cannot
    build from SAMPLES are named here, so a new one is a visible change, not a
    silent hole in the walk."""
    assert INSTANCES, "the gate built no instance"
    assert "xaidr.Sensor" in INSTANCES
    print("instances:", sorted(INSTANCES))
    print("cannot instantiate:", UNBUILT)
    listed = set(CANNOT_INSTANTIATE)
    if not REQUIRE_FRAMEWORKS:     # without the frameworks, fewer integrations classes exist
        listed &= set(UNBUILT) | {k for k in listed if not k.startswith("xaidr.integrations.")}
    new = {k: UNBUILT[k] for k in set(UNBUILT) - listed}
    gone = listed - set(UNBUILT)
    assert not new, (f"the gate cannot instantiate {new}, so it calls none of their methods: "
                     "give SAMPLES what they need, or list them in CANNOT_INSTANTIATE")
    assert not gone, (f"{sorted(gone)} can be instantiated now (or are gone): take them off "
                      "CANNOT_INSTANTIATE so the list stays the gate's real hole")


def _bound_policy_routes():
    """``(label, callable, param)`` for every public callable and every method of a
    real instance that takes a policy (``policy``) or a policy file
    (``policy_file``)."""
    out = []
    for label, fn, _module in _public():
        try:
            params = inspect.signature(fn).parameters
        except (TypeError, ValueError):
            continue
        if "self" in params:
            continue
        for p in ("policy", "policy_file"):
            if p in params:
                out.append((label, fn, p))
        # A policy file through **kwargs, where the keywords build a sensor.
        if (any(p.kind is p.VAR_KEYWORD for p in params.values()) and "sensor" in params
                and "policy_file" not in params):
            out.append((label, fn, "policy_file"))
    for label, obj in INSTANCES.items():
        for name, meth in inspect.getmembers(obj, inspect.ismethod):
            if name.startswith("_"):
                continue
            try:
                params = inspect.signature(meth).parameters
            except (TypeError, ValueError):
                continue
            for p in ("policy", "policy_file"):
                if p in params:
                    out.append((f"{label}().{name}", meth, p))
    return out


POLICY_ROUTES = _bound_policy_routes()
_GOOD = {"version": "1", "defaults": {"effect": "allow"},
         "rules": [{"id": "b", "effect": "block",
                    "match": {"destination_identifier": ["evil.example"]}}]}


def _policy_value(param, value, tmp_path):
    if param == "policy":
        return dict(_GOOD, value_origin=value)
    pytest.importorskip("yaml") if not REQUIRE_FRAMEWORKS else __import__("yaml")
    import yaml
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(dict(_GOOD, value_origin=str.__str__(value))), encoding="utf-8")
    return str(path)


def _policy_call(label, fn, kwargs, param, arg):
    try:
        result = _quiet(lambda: fn(**kwargs, **{param: arg}))
    except ImportError as e:
        if REQUIRE_FRAMEWORKS:
            raise
        pytest.skip(f"{label}: its framework is not installed ({e})")
    if isinstance(result, xaidr.ProtectionManifest):
        _quiet(result.unprotect)
    return result


@pytest.mark.parametrize("route", POLICY_ROUTES, ids=[r[0] + ":" + r[2] for r in POLICY_ROUTES])
@pytest.mark.parametrize("spelling", ["enforce", "ENFORCE", "padded", "str-subclass", "Mode.ENFORCE"])
def test_value_origin_in_a_policy_never_reads_as_record(route, spelling, tmp_path):
    label, fn, param = route
    value = SPELLINGS[spelling]
    if param == "policy_file" and not isinstance(value, str):
        pytest.skip("a YAML file holds the spelling as text; the text spellings cover it")
    arg = _policy_value(param, value, tmp_path)
    kwargs = {"agent_id": "gate"} if "agent_id" in inspect.signature(fn).parameters else {}
    if "raise_on_config_error" in inspect.signature(fn).parameters:
        kwargs["quiet"] = True
    try:
        result = _policy_call(label, fn, kwargs, param, arg)
    except xaidr.ValueOriginEnforcementUnavailable as e:
        assert "later release" in str(e), f"{label}: the refusal does not name its reason: {e}"
        return
    except Exception as e:
        pytest.fail(f"{label}({param}=<policy with value_origin={value!r}>) raised "
                    f"{type(e).__name__}: {e}: a request for enforcement read as a malformed "
                    "policy, not as enforcement that is unavailable")
    pytest.fail(f"{label}({param}=<policy with value_origin={value!r}>) returned normally "
                f"({type(result).__name__}): a request for enforcement in a policy was not refused")


@pytest.mark.parametrize("route", POLICY_ROUTES, ids=[r[0] + ":" + r[2] for r in POLICY_ROUTES])
def test_any_other_value_origin_in_a_policy_says_set_it_on_the_sensor(route, tmp_path):
    label, fn, param = route
    arg = _policy_value(param, "record", tmp_path)
    kwargs = {"agent_id": "gate"} if "agent_id" in inspect.signature(fn).parameters else {}
    if "raise_on_config_error" in inspect.signature(fn).parameters:
        kwargs["quiet"] = True
    try:
        result = _policy_call(label, fn, kwargs, param, arg)
    except ValueError as e:
        assert type(e) is ValueError and "set value_origin on the Sensor" in str(e), (
            f"{label}: {type(e).__name__}: {e}: the refusal does not tell the caller to set "
            "value_origin on the Sensor")
        return
    pytest.fail(f"{label}({param}=<policy with value_origin='record'>) returned normally "
                f"({type(result).__name__}): a value_origin in a policy was not refused")


def test_set_policy_keeps_the_last_good_policy_when_it_refuses():
    s = _sensor()
    assert s.set_policy(_GOOD)
    before = s._policy
    for value in ("enforce", "record"):
        try:
            took = s.set_policy(dict(_GOOD, value_origin=value))
        except ValueError:
            took = None
        assert took is None, (f"set_policy(value_origin={value!r}) returned {took!r} "
                              "instead of raising: the caller is not told why it was refused")
        assert s._policy is before, "a refused policy replaced the one in force"


def test_the_gate_walks_the_policy_routes_it_must():
    labels = {(r[0], r[2]) for r in POLICY_ROUTES}
    for must in [("xaidr.Sensor().set_policy", "policy"), ("xaidr.Sensor", "policy_file"),
                 ("xaidr.protect", "policy_file"),
                 ("xaidr.integrations.langchain.delphi_middleware", "policy_file"),
                 ("xaidr.integrations.haystack.delphi_hooks", "policy_file")]:
        assert must in labels, f"the gate does not walk {must}: {sorted(labels)}"


# ── misspelled keywords: raise, beside sensor= or not ────────────────────────

def _params(fn):
    try:
        return inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return {}


KWARG_ROUTES = [(label, fn) for label, fn, _m in _public()
                if any(p.kind is p.VAR_KEYWORD for p in _params(fn).values())
                and "sensor" in _params(fn)]


@pytest.mark.parametrize("route", KWARG_ROUTES, ids=[r[0] for r in KWARG_ROUTES])
@pytest.mark.parametrize("with_sensor", [False, True], ids=["alone", "beside-sensor"])
def test_a_misspelled_keyword_raises_with_a_hint(route, with_sensor):
    """``value_orign`` is not a keyword any Sensor takes. It raises, naming the
    nearest one, whether the function builds its sensor or was given one; never
    a note, never dropped."""
    label, fn = route
    kwargs = {"value_orign": "record"}
    if with_sensor:
        kwargs["sensor"] = _sensor()
    if "raise_on_config_error" in inspect.signature(fn).parameters:
        kwargs["quiet"] = True
    try:
        result = _quiet(lambda: fn(**kwargs))
    except ImportError as e:
        if REQUIRE_FRAMEWORKS:
            raise
        pytest.skip(f"{label}: its framework is not installed ({e})")
    except TypeError as e:
        assert "did you mean 'value_origin'" in str(e), (
            f"{label}: {e}: the misspelling failed deep in Sensor(...) with no hint, "
            "not at the caller's own check")
        return
    if isinstance(result, xaidr.ProtectionManifest):
        _quiet(result.unprotect)
    pytest.fail(f"{label}(value_orign=...{', sensor=<Sensor>' if with_sensor else ''}) "
                f"returned normally ({type(result).__name__}): the misspelling was dropped")


def test_the_gate_walks_the_keyword_routes_it_must():
    labels = {r[0] for r in KWARG_ROUTES}
    for must in ("xaidr.protect", "xaidr.integrations.langchain.delphi_middleware",
                 "xaidr.integrations.haystack.delphi_hooks"):
        assert must in labels, f"the gate does not walk {must}"
