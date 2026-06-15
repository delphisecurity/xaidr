"""xaidr — Delphi xAIDR Python SDK.

v0.2: Local L1/L2/DLP scanning. Brain for L4 escalation + fleet intelligence.
"""

from .sensor import DelphiSensor as Sensor, ProtectedHttpClient
from .types import DelphiBlockedError, ScanResult

__version__ = "0.5.0"

__all__ = [
    "Sensor",
    "ProtectedHttpClient",
    "ScanResult",
    "DelphiBlockedError",
    "__version__",
]
