"""
Membrane integration for Cyntra kernel.

Provides:
- RunReceipt generation and canonicalization
- HTTP client for membrane service
- Configuration management
"""

from .client import MembraneClient
from .config import MEMBRANE_TIMEOUT, MEMBRANE_URL, get_membrane_url
from .receipt import RunReceipt, generate_receipt

__all__ = [
    "MEMBRANE_URL",
    "MEMBRANE_TIMEOUT",
    "get_membrane_url",
    "RunReceipt",
    "generate_receipt",
    "MembraneClient",
]
