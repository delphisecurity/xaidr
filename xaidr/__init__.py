"""xaidr — Delphi xAIDR Python SDK.

v0.2: Local L1/L2/DLP scanning. Brain for L4 escalation + fleet intelligence.
"""

from .sensor import DelphiSensor as Sensor, ProtectedHttpClient
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
    "set_origin",
    "origin_scope",
    "clear_origin",
    "begin_flow",
    "inject_context",
    "extract_context",
    "clear_flow",
    "__version__",
]
