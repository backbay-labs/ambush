"""
Metasploit Framework integration for Hellcat StrikeCells.

Provides a persistent msfconsole subprocess client, output parsers,
and dataclasses for sessions and command results.
"""

from hellcat.offensive.tools.metasploit.client import MetasploitClient
from hellcat.offensive.tools.metasploit.models import MsfCommandResult, MsfSession
from hellcat.offensive.tools.metasploit.parser import MetasploitParser

__all__ = [
    "MetasploitClient",
    "MetasploitParser",
    "MsfCommandResult",
    "MsfSession",
]
