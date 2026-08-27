"""TrueForge integration for Sentinel.

This package is the only place that speaks HTTP to TrueForge. The
deterministic investigation layers (analyzer, risk, report) never import it.
"""

from trueforge.config import TrueForgeConfig
from trueforge.client import (
    TrueForgeClient,
    TrueForgeError,
    TrueForgeHTTPError,
    TrueForgeUnavailable,
    TrueForgeProtocolError,
    TrueForgeTimeout,
)

__all__ = [
    "TrueForgeConfig",
    "TrueForgeClient",
    "TrueForgeError",
    "TrueForgeHTTPError",
    "TrueForgeUnavailable",
    "TrueForgeProtocolError",
    "TrueForgeTimeout",
]
