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
# Auto-instrumentation. Importing this binds names and NOTHING else — no
# framework is imported, no boundary is patched, nothing runs. Instrumentation
# happens only when someone calls xaidr.protect(), which is the whole point:
# a security control with no visible call site cannot be audited.
from .autopatch import (
    protect, unprotect, ProtectionManifest, XaidrProtectionWarning,
)

__version__ = "1.6.2"

__all__ = [
    "Sensor",
    "ProtectedHttpClient",
    "protect",
    "unprotect",
    "ProtectionManifest",
    "XaidrProtectionWarning",
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
