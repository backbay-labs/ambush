"""
Membrane configuration.

Environment variables:
- CYNTRA_MEMBRANE_URL: Full URL to membrane service (default: http://localhost:7331)
- CYNTRA_MEMBRANE_TIMEOUT: Request timeout in seconds (default: 30)
"""

import os

# Default membrane service URL
MEMBRANE_URL = "http://localhost:7331"

# Request timeout in seconds
MEMBRANE_TIMEOUT = 30.0


def get_membrane_url() -> str:
    """Get the configured membrane service URL."""
    return os.environ.get("CYNTRA_MEMBRANE_URL", MEMBRANE_URL)


def get_membrane_timeout() -> float:
    """Get the configured timeout in seconds."""
    timeout_str = os.environ.get("CYNTRA_MEMBRANE_TIMEOUT")
    if timeout_str:
        try:
            return float(timeout_str)
        except ValueError:
            pass
    return MEMBRANE_TIMEOUT
