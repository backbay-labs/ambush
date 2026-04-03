"""
External security tool integration for Hellcat StrikeCells.

Provides a ToolRegistry for managing security tools (nmap, subfinder, sqlmap,
nuclei, etc.), parsers for converting their output into TargetGraph nodes, and
OSINT integrations.
"""

from hellcat.offensive.tools.osint import (
    OsintFinding,
    OsintResult,
    OsintSource,
    SearchEngine,
    SearchEngineCategory,
    format_osint_suggestions,
    get_engines_for_category,
    get_engines_with_api,
    get_free_engines,
)
from hellcat.offensive.tools.parsers import (
    HttpxParser,
    NmapParser,
    NucleiParser,
    SqlmapParser,
    SubfinderParser,
)
from hellcat.offensive.tools.registry import SecurityTool, ToolRegistry

__all__ = [
    "HttpxParser",
    "NmapParser",
    "NucleiParser",
    "OsintFinding",
    "OsintResult",
    "OsintSource",
    "SearchEngine",
    "SearchEngineCategory",
    "SecurityTool",
    "SqlmapParser",
    "SubfinderParser",
    "ToolRegistry",
    "format_osint_suggestions",
    "get_engines_for_category",
    "get_engines_with_api",
    "get_free_engines",
]
