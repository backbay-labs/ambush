"""
OSINT source integrations for Hellcat recon operators.

Provides structured OSINT data collection via search engine APIs and web
scraping, plus a curated catalog of hacker search engines for manual lookup.
"""

from hellcat.offensive.tools.osint.base import OsintFinding, OsintResult, OsintSource
from hellcat.offensive.tools.osint.catalog import (
    SEARCH_ENGINE_CATALOG,
    SearchEngine,
    SearchEngineCategory,
    format_osint_suggestions,
    get_engines_for_category,
    get_engines_with_api,
    get_free_engines,
)
from hellcat.offensive.tools.osint.censys import CensysClient, CensysHostResult
from hellcat.offensive.tools.osint.collector import OsintCollector
from hellcat.offensive.tools.osint.crtsh import CrtshClient
from hellcat.offensive.tools.osint.cvemap import CvemapClient, CvemapEntry
from hellcat.offensive.tools.osint.epss import EPSSClient, EPSSRecord
from hellcat.offensive.tools.osint.kev import KevClient, KevEntry
from hellcat.offensive.tools.osint.nvd import NvdClient
from hellcat.offensive.tools.osint.shodan import ShodanClient, ShodanHostResult

__all__ = [
    "CensysClient",
    "CensysHostResult",
    "CrtshClient",
    "CvemapClient",
    "CvemapEntry",
    "EPSSClient",
    "EPSSRecord",
    "KevClient",
    "KevEntry",
    "NvdClient",
    "OsintCollector",
    "SEARCH_ENGINE_CATALOG",
    "OsintFinding",
    "OsintResult",
    "OsintSource",
    "SearchEngine",
    "SearchEngineCategory",
    "ShodanClient",
    "ShodanHostResult",
    "format_osint_suggestions",
    "get_engines_for_category",
    "get_engines_with_api",
    "get_free_engines",
]
