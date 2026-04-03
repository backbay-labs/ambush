"""GoPhish API integration for phishing simulation campaigns."""
from hellcat.offensive.tools.gophish.client import GoPhishClient
from hellcat.offensive.tools.gophish.models import CapturedCredential, PhishingCampaign, PhishingResult
from hellcat.offensive.tools.gophish.parser import GoPhishParser

__all__ = [
    "CapturedCredential",
    "GoPhishClient",
    "GoPhishParser",
    "PhishingCampaign",
    "PhishingResult",
]
