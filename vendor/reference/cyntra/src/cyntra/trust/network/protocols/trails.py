"""
Trail gossip protocol handler.

Protocol: /cnp/trails/1.0.0

Messages:
- TRAIL_ANNOUNCE: Broadcast a new trail to peers
- TRAIL_QUERY: Request trails matching criteria
- TRAIL_RESPONSE: Return matching trails
- TRAIL_CITE: Report following a trail (reinforcement)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Callable, Awaitable

from cyntra.trust.network.schemas import (
    Trail,
    TrailQuery,
    TrailCitation,
    ActionType,
    StateFeatures,
    TrailContext,
    TrailOutcome,
    TaskComplexity,
)


logger = logging.getLogger(__name__)


PROTOCOL_ID = "/cnp/trails/1.0.0"


class TrailMessageType(str, Enum):
    """Trail protocol message types."""

    ANNOUNCE = "trail_announce"
    QUERY = "trail_query"
    RESPONSE = "trail_response"
    CITE = "trail_cite"


@dataclass
class TrailMessage:
    """A trail protocol message."""

    type: TrailMessageType
    payload: dict
    sender_id: str = ""
    timestamp: str = ""

    def to_bytes(self) -> bytes:
        """Serialize to bytes for network transmission."""
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        return json.dumps({
            "type": self.type.value,
            "payload": self.payload,
            "sender_id": self.sender_id,
            "timestamp": self.timestamp,
        }).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> "TrailMessage":
        """Deserialize from bytes."""
        d = json.loads(data)
        return cls(
            type=TrailMessageType(d["type"]),
            payload=d["payload"],
            sender_id=d.get("sender_id", ""),
            timestamp=d.get("timestamp", ""),
        )

    @classmethod
    def announce(cls, trail: Trail, sender_id: str) -> "TrailMessage":
        """Create an announce message."""
        return cls(
            type=TrailMessageType.ANNOUNCE,
            payload=trail_to_dict(trail),
            sender_id=sender_id,
        )

    @classmethod
    def query(cls, query: TrailQuery, sender_id: str) -> "TrailMessage":
        """Create a query message."""
        return cls(
            type=TrailMessageType.QUERY,
            payload=query_to_dict(query),
            sender_id=sender_id,
        )

    @classmethod
    def response(cls, trails: list[Trail], sender_id: str) -> "TrailMessage":
        """Create a response message."""
        return cls(
            type=TrailMessageType.RESPONSE,
            payload={"trails": [trail_to_dict(t) for t in trails]},
            sender_id=sender_id,
        )

    @classmethod
    def cite(cls, citation: TrailCitation, sender_id: str) -> "TrailMessage":
        """Create a cite message."""
        return cls(
            type=TrailMessageType.CITE,
            payload={
                "trail_id": citation.trail_id,
                "success": citation.success,
                "worker_id": citation.worker_id,
                "cited_at": citation.cited_at.isoformat(),
            },
            sender_id=sender_id,
        )


class TrailsProtocol:
    """
    Handler for the /cnp/trails/1.0.0 protocol.

    Manages trail announcements, queries, and citations.
    """

    def __init__(self):
        self._on_announce: Optional[Callable[[Trail, str], Awaitable[None]]] = None
        self._on_query: Optional[Callable[[TrailQuery, str], Awaitable[list[Trail]]]] = None
        self._on_cite: Optional[Callable[[TrailCitation, str], Awaitable[None]]] = None

    @property
    def protocol_id(self) -> str:
        return PROTOCOL_ID

    def on_announce(self, handler: Callable[[Trail, str], Awaitable[None]]) -> None:
        """Set handler for trail announcements."""
        self._on_announce = handler

    def on_query(self, handler: Callable[[TrailQuery, str], Awaitable[list[Trail]]]) -> None:
        """Set handler for trail queries."""
        self._on_query = handler

    def on_cite(self, handler: Callable[[TrailCitation, str], Awaitable[None]]) -> None:
        """Set handler for trail citations."""
        self._on_cite = handler

    async def handle_message(self, data: bytes, sender_id: str) -> Optional[bytes]:
        """
        Handle an incoming protocol message.

        Returns response bytes if applicable, None otherwise.
        """
        try:
            msg = TrailMessage.from_bytes(data)
            logger.debug(f"Received {msg.type.value} from {sender_id}")

            if msg.type == TrailMessageType.ANNOUNCE:
                return await self._handle_announce(msg, sender_id)
            elif msg.type == TrailMessageType.QUERY:
                return await self._handle_query(msg, sender_id)
            elif msg.type == TrailMessageType.RESPONSE:
                return await self._handle_response(msg, sender_id)
            elif msg.type == TrailMessageType.CITE:
                return await self._handle_cite(msg, sender_id)
            else:
                logger.warning(f"Unknown message type: {msg.type}")
                return None

        except Exception as e:
            logger.error(f"Error handling message: {e}")
            return None

    async def _handle_announce(self, msg: TrailMessage, sender_id: str) -> None:
        """Handle trail announcement."""
        if not self._on_announce:
            return None

        try:
            trail = dict_to_trail(msg.payload)
            await self._on_announce(trail, sender_id)
        except Exception as e:
            logger.error(f"Error processing trail announcement: {e}")

        return None

    async def _handle_query(self, msg: TrailMessage, sender_id: str) -> Optional[bytes]:
        """Handle trail query."""
        if not self._on_query:
            return TrailMessage.response([], "").to_bytes()

        try:
            query = dict_to_query(msg.payload)
            trails = await self._on_query(query, sender_id)
            response = TrailMessage.response(trails, "")
            return response.to_bytes()
        except Exception as e:
            logger.error(f"Error processing query: {e}")
            return TrailMessage.response([], "").to_bytes()

    async def _handle_response(self, msg: TrailMessage, sender_id: str) -> None:
        """Handle query response (client-side)."""
        # Responses are handled by the caller, not the protocol
        return None

    async def _handle_cite(self, msg: TrailMessage, sender_id: str) -> None:
        """Handle trail citation."""
        if not self._on_cite:
            return None

        try:
            citation = TrailCitation(
                trail_id=msg.payload["trail_id"],
                success=msg.payload["success"],
                worker_id=msg.payload.get("worker_id", sender_id),
                cited_at=datetime.fromisoformat(msg.payload["cited_at"]),
            )
            await self._on_cite(citation, sender_id)
        except Exception as e:
            logger.error(f"Error processing citation: {e}")

        return None

    def create_announce(self, trail: Trail, sender_id: str) -> bytes:
        """Create an announce message."""
        return TrailMessage.announce(trail, sender_id).to_bytes()

    def create_query(self, query: TrailQuery, sender_id: str) -> bytes:
        """Create a query message."""
        return TrailMessage.query(query, sender_id).to_bytes()

    def create_cite(self, citation: TrailCitation, sender_id: str) -> bytes:
        """Create a cite message."""
        return TrailMessage.cite(citation, sender_id).to_bytes()

    def parse_response(self, data: bytes) -> list[Trail]:
        """Parse a query response."""
        msg = TrailMessage.from_bytes(data)
        if msg.type != TrailMessageType.RESPONSE:
            raise ValueError(f"Expected response, got {msg.type}")
        return [dict_to_trail(t) for t in msg.payload.get("trails", [])]


# --- Serialization Helpers ---

def trail_to_dict(trail: Trail) -> dict:
    """Convert Trail to dict for serialization."""
    return {
        "id": trail.id,
        "version": trail.version,
        "state_hash": trail.state_hash,
        "state_features": {
            "languages": trail.state_features.languages,
            "frameworks": trail.state_features.frameworks,
            "file_count": trail.state_features.file_count,
            "avg_file_size": trail.state_features.avg_file_size,
            "test_ratio": trail.state_features.test_ratio,
            "cyclomatic_avg": trail.state_features.cyclomatic_avg,
            "depth_avg": trail.state_features.depth_avg,
        },
        "action_type": trail.action_type.value,
        "action_description": trail.action_description,
        "action_embedding": trail.action_embedding,
        "outcome": {
            "success": trail.outcome.success,
            "tests_passed": trail.outcome.tests_passed,
            "tests_failed": trail.outcome.tests_failed,
            "coverage": trail.outcome.coverage,
            "token_count": trail.outcome.token_count,
            "duration_ms": trail.outcome.duration_ms,
            "gates_passed": trail.outcome.gates_passed,
            "gates_failed": trail.outcome.gates_failed,
        },
        "context": {
            "language": trail.context.language,
            "framework": trail.context.framework,
            "task_complexity": trail.context.task_complexity.value,
            "tags": trail.context.tags,
        },
        "worker_id": trail.worker_id,
        "receipt_hash": trail.receipt_hash,
        "signature": trail.signature,
        "strength": trail.strength,
        "citations": trail.citations,
        "created_at": trail.created_at.isoformat(),
        "last_cited_at": trail.last_cited_at.isoformat() if trail.last_cited_at else None,
    }


def dict_to_trail(d: dict) -> Trail:
    """Convert dict to Trail."""
    sf = d.get("state_features", {})
    state_features = StateFeatures(
        languages=sf.get("languages", {}),
        frameworks=sf.get("frameworks", []),
        file_count=sf.get("file_count", 0),
        avg_file_size=sf.get("avg_file_size", 0),
        test_ratio=sf.get("test_ratio", 0.0),
        cyclomatic_avg=sf.get("cyclomatic_avg", 0.0),
        depth_avg=sf.get("depth_avg", 0.0),
    )

    oc = d.get("outcome", {})
    outcome = TrailOutcome(
        success=oc.get("success", False),
        tests_passed=oc.get("tests_passed", 0),
        tests_failed=oc.get("tests_failed", 0),
        coverage=oc.get("coverage", 0.0),
        token_count=oc.get("token_count", 0),
        duration_ms=oc.get("duration_ms", 0),
        gates_passed=oc.get("gates_passed", []),
        gates_failed=oc.get("gates_failed", []),
    )

    ctx = d.get("context", {})
    context = TrailContext(
        language=ctx.get("language", "unknown"),
        framework=ctx.get("framework"),
        task_complexity=TaskComplexity(ctx.get("task_complexity", "moderate")),
        tags=ctx.get("tags", []),
    )

    return Trail(
        id=d.get("id", ""),
        version=d.get("version", 1),
        state_hash=d.get("state_hash", ""),
        state_features=state_features,
        action_type=ActionType(d.get("action_type", "other")),
        action_description=d.get("action_description", ""),
        action_embedding=d.get("action_embedding", []),
        outcome=outcome,
        context=context,
        worker_id=d.get("worker_id", ""),
        receipt_hash=d.get("receipt_hash", ""),
        signature=d.get("signature", ""),
        strength=d.get("strength", 1.0),
        citations=d.get("citations", 0),
        created_at=datetime.fromisoformat(d["created_at"]) if d.get("created_at") else datetime.now(timezone.utc),
        last_cited_at=datetime.fromisoformat(d["last_cited_at"]) if d.get("last_cited_at") else None,
    )


def query_to_dict(query: TrailQuery) -> dict:
    """Convert TrailQuery to dict."""
    return {
        "state_hash": query.state_hash,
        "state_features": {
            "languages": query.state_features.languages,
            "frameworks": query.state_features.frameworks,
            "file_count": query.state_features.file_count,
            "avg_file_size": query.state_features.avg_file_size,
            "test_ratio": query.state_features.test_ratio,
            "cyclomatic_avg": query.state_features.cyclomatic_avg,
            "depth_avg": query.state_features.depth_avg,
        } if query.state_features else None,
        "similarity_threshold": query.similarity_threshold,
        "action_type": query.action_type.value if query.action_type else None,
        "action_embedding": query.action_embedding,
        "language": query.language,
        "framework": query.framework,
        "max_complexity": query.max_complexity.value if query.max_complexity else None,
        "min_strength": query.min_strength,
        "min_citations": query.min_citations,
        "require_success": query.require_success,
        "limit": query.limit,
        "offset": query.offset,
    }


def dict_to_query(d: dict) -> TrailQuery:
    """Convert dict to TrailQuery."""
    sf = d.get("state_features")
    state_features = None
    if sf:
        state_features = StateFeatures(
            languages=sf.get("languages", {}),
            frameworks=sf.get("frameworks", []),
            file_count=sf.get("file_count", 0),
            avg_file_size=sf.get("avg_file_size", 0),
            test_ratio=sf.get("test_ratio", 0.0),
            cyclomatic_avg=sf.get("cyclomatic_avg", 0.0),
            depth_avg=sf.get("depth_avg", 0.0),
        )

    return TrailQuery(
        state_hash=d.get("state_hash"),
        state_features=state_features,
        similarity_threshold=d.get("similarity_threshold", 0.7),
        action_type=ActionType(d["action_type"]) if d.get("action_type") else None,
        action_embedding=d.get("action_embedding"),
        language=d.get("language"),
        framework=d.get("framework"),
        max_complexity=TaskComplexity(d["max_complexity"]) if d.get("max_complexity") else None,
        min_strength=d.get("min_strength", 0.1),
        min_citations=d.get("min_citations", 0),
        require_success=d.get("require_success", True),
        limit=d.get("limit", 10),
        offset=d.get("offset", 0),
    )
