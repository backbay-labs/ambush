"""A client library for accessing Swarm Team Six Platform API"""

from .client import AuthenticatedClient, Client
from .helpers import iter_findings_sse, make_platform_client

__all__ = (
    "AuthenticatedClient",
    "Client",
    "iter_findings_sse",
    "make_platform_client",
)
