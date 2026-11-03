"""Value origin records in 1.22.0; its enforcement is available in a later release.

Every public way to ask for ENFORCE refuses with a configuration error
(``ValueOriginEnforcementUnavailable``, a ValueError): ``Sensor(value_origin=...)``
and every constructor that passes its keywords on (``protect(...)``, the LangChain
and Haystack integrations) through ``validate_mode``, and ``should_block`` asked for
``Mode.ENFORCE``. None of them falls back to RECORD: a caller who asked for
ENFORCE is told it is unavailable, never given RECORD in its place.

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


def check_enforce() -> None:
    """Raise ``ValueOriginEnforcementUnavailable`` unless inside the test-only switch."""
    if _depth <= 0:
        raise ValueOriginEnforcementUnavailable(MESSAGE)
