"""
StrikeCell - Docker-isolated execution environments for security operators.

StrikeCells provide sandboxed containers for running operator toolchains
against authorized targets, with volume-mounted workspaces for artifact
collection and log streaming.
"""

from hellcat.offensive.strikecell.browser import BrowserConfig, BrowserContext, BrowserManager
from hellcat.offensive.strikecell.cell import StrikeCell, StrikeCellResult, StrikeCellState
from hellcat.offensive.strikecell.manager import StrikeCellManager
from hellcat.offensive.strikecell.manifest import StrikeManifest

__all__ = [
    "BrowserConfig",
    "BrowserContext",
    "BrowserManager",
    "StrikeCell",
    "StrikeCellManager",
    "StrikeCellResult",
    "StrikeCellState",
    "StrikeManifest",
]
