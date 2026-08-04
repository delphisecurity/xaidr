"""xaidr — Delphi xAIDR Python SDK.

Standalone, local-first security sensor for AI agents: L1/L2/DLP + compositional
and A2A-protocol scanning with a 3-state verdict (allow / flag / block). No
account, no backend, no network required.
"""

from .sensor import DelphiSensor as Sensor, ProtectedHttpClient
from .circuit_breaker import CircuitBreaker
from .provenance import set_origin, origin_scope, clear_origin
from .provenance_chain import (
    begin_flow, inject_context, extract_context, clear_flow,
)
from .types import DelphiBlockedError, ScanResult

__version__ = "0.5.0"

__all__ = [
    "Sensor",
    "ProtectedHttpClient",
    "ScanResult",
    "DelphiBlockedError",
    "CircuitBreaker",
    "set_origin",
    "origin_scope",
    "clear_origin",
    "begin_flow",
    "inject_context",
    "extract_context",
    "clear_flow",
    "__version__",
]
