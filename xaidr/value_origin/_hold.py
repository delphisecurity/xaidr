"""Value origin records in 1.22.0; its enforcement is available in a later release.

Every public way to ask for ENFORCE refuses with a configuration error
(``ValueOriginEnforcementUnavailable``, a ValueError, exported from ``xaidr``).
Every value-origin mode in the package passes through one validator,
``validate_mode``: ``Sensor(value_origin=...)``, every constructor that passes its
keywords on (``protect(...)``, the LangChain and Haystack integrations), and
``should_block``. Enforcement in any spelling or type is refused; a value that is
not a mode is a plain ValueError. Beside an existing ``sensor=``, ``value_origin``
is refused, never dropped (``refuse_beside_sensor``), and so is a ``value_origin``
key in a policy file or ``set_policy`` (``refuse_in_policy``). None of them falls back to
RECORD (tests/test_value_origin_mode_gate.py walks every public route).

The enforcement code itself is kept and tested. It is reachable only inside
``_enforce_for_tests()``, a test-only switch that no option, keyword, environment
variable or file sets (tests/test_value_origin_hold.py proves it).
"""
from __future__ import annotations

import contextlib
import threading

MESSAGE = ("value_origin='enforce': value-origin enforcement is available in a later "
           "release; xaidr 1.22.0 records value origin (value_origin='record', the "
           "default) and never blocks on it")


class ValueOriginEnforcementUnavailable(ValueError):
    """ENFORCE was asked for; this release records value origin only."""


_lock = threading.Lock()
_depth = 0


@contextlib.contextmanager
def _enforce_for_tests():
    """Test-only: let ENFORCE through for the duration, on every thread."""
    global _depth
    with _lock:
        _depth += 1
    try:
        yield
    finally:
        with _lock:
            _depth -= 1


def refuse_beside_sensor(kwargs) -> None:
    """``value_origin=`` passed together with an existing ``sensor=``: never dropped.
    Enforcement in any spelling raises ``ValueOriginEnforcementUnavailable``;
    anything else raises a ValueError telling the caller to set it on the Sensor."""
    if "value_origin" not in kwargs:
        return
    from ._designations import validate_mode
    validate_mode(kwargs["value_origin"])
    raise ValueError(f"value_origin={kwargs['value_origin']!r} was passed together with an "
                     "existing sensor=, which has its own; set value_origin on the Sensor")


def refuse_in_policy(raw, where: str) -> None:
    """A ``value_origin`` key in a policy (a policy file, or ``set_policy``):
    refused, never parsed past and never ignored. Enforcement in any spelling
    raises ``ValueOriginEnforcementUnavailable``; any other value raises a
    ValueError, because value origin is the Sensor's setting, not a policy's."""
    if not isinstance(raw, dict) or "value_origin" not in raw:
        return
    from ._designations import validate_mode
    validate_mode(raw["value_origin"])
    raise ValueError(f"{where}: a policy sets value_origin={raw['value_origin']!r}; value "
                     "origin is not a policy setting, so set value_origin on the Sensor")


def check_enforce() -> None:
    """Raise ``ValueOriginEnforcementUnavailable`` unless inside the test-only switch."""
    if _depth <= 0:
        raise ValueOriginEnforcementUnavailable(MESSAGE)
