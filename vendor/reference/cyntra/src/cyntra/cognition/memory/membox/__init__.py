"""
Membox - Topic-continuous memory layer.

Phase 1 scaffolding for a Membox-style layer (Topic Loom + Trace Weaver) that
builds on Cyntra's existing memory infrastructure.
"""

from cyntra.cognition.memory.membox.integration import MemboxKernelBridge
from cyntra.cognition.memory.membox.membox_store import MemboxStore
from cyntra.cognition.memory.membox.models import EventTrace, Membox, MemboxMessage, TraceLink
from cyntra.cognition.memory.membox.topic_loom import TopicLoom, TopicLoomConfig
from cyntra.cognition.memory.membox.trace_weaver import TraceWeaver, TraceWeaverConfig

__all__ = [
    "EventTrace",
    "Membox",
    "MemboxKernelBridge",
    "MemboxMessage",
    "MemboxStore",
    "TopicLoom",
    "TopicLoomConfig",
    "TraceLink",
    "TraceWeaver",
    "TraceWeaverConfig",
]

