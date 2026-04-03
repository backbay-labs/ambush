from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class MemboxMessage:
    role: str
    content: str
    source: str | None = None
    created_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "source": self.source,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MemboxMessage":
        created_at_raw = data.get("created_at")
        created_at = utc_now()
        if isinstance(created_at_raw, str) and created_at_raw:
            try:
                created_at = datetime.fromisoformat(created_at_raw.replace("Z", "+00:00"))
            except Exception:
                created_at = utc_now()
        return cls(
            role=str(data.get("role", "")),
            content=str(data.get("content", "")),
            source=(str(data["source"]) if data.get("source") is not None else None),
            created_at=created_at,
        )


@dataclass(frozen=True)
class Membox:
    id: str
    topic: str
    keywords: list[str] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    messages: list[MemboxMessage] = field(default_factory=list)
    created_at: datetime = field(default_factory=utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "topic": self.topic,
            "keywords": self.keywords,
            "events": self.events,
            "messages": [m.to_dict() for m in self.messages],
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Membox":
        created_at_raw = data.get("created_at")
        created_at = utc_now()
        if isinstance(created_at_raw, str) and created_at_raw:
            try:
                created_at = datetime.fromisoformat(created_at_raw.replace("Z", "+00:00"))
            except Exception:
                created_at = utc_now()

        messages_raw = data.get("messages") or []
        messages: list[MemboxMessage] = []
        if isinstance(messages_raw, list):
            for item in messages_raw:
                if isinstance(item, dict):
                    messages.append(MemboxMessage.from_dict(item))

        return cls(
            id=str(data.get("id", "")),
            topic=str(data.get("topic", "")),
            keywords=[str(x) for x in (data.get("keywords") or []) if x is not None],
            events=[str(x) for x in (data.get("events") or []) if x is not None],
            messages=messages,
            created_at=created_at,
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass(frozen=True)
class EventTrace:
    id: str
    summary: str
    events: list[str] = field(default_factory=list)
    membox_ids: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "summary": self.summary,
            "events": self.events,
            "membox_ids": self.membox_ids,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EventTrace":
        def _parse_dt(value: Any) -> datetime:
            if isinstance(value, str) and value:
                try:
                    return datetime.fromisoformat(value.replace("Z", "+00:00"))
                except Exception:
                    return utc_now()
            return utc_now()

        return cls(
            id=str(data.get("id", "")),
            summary=str(data.get("summary", "")),
            events=[str(x) for x in (data.get("events") or []) if x is not None],
            membox_ids=[str(x) for x in (data.get("membox_ids") or []) if x is not None],
            created_at=_parse_dt(data.get("created_at")),
            updated_at=_parse_dt(data.get("updated_at")),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass(frozen=True)
class TraceLink:
    membox_id: str
    trace_id: str
    link_type: str
    confidence: float = 0.0
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "membox_id": self.membox_id,
            "trace_id": self.trace_id,
            "link_type": self.link_type,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TraceLink":
        confidence_raw = data.get("confidence", 0.0)
        try:
            confidence = float(confidence_raw)
        except Exception:
            confidence = 0.0
        return cls(
            membox_id=str(data.get("membox_id", "")),
            trace_id=str(data.get("trace_id", "")),
            link_type=str(data.get("link_type", "")),
            confidence=confidence,
            reasoning=str(data.get("reasoning", "")),
        )


def dump_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True)

