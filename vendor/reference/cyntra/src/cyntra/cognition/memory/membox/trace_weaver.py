from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from cyntra.cognition.memory.membox.models import EventTrace, Membox, TraceLink


@dataclass(frozen=True)
class TraceWeaverConfig:
    max_candidate_traces: int = 10
    similarity_threshold: float = 0.3
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 512
    temperature: float = 0.2


class TraceWeaver:
    """
    Links memboxes across discontinuities into longer event traces.

    For Phase 1 scaffolding:
    - Uses VectorOps if provided (embedding similarity)
    - Optionally verifies links via LLM if provided
    - Falls back to a keyword overlap score if neither is available
    """

    def __init__(
        self,
        *,
        vector_ops: Any | None = None,
        llm_client: Any | None = None,
        config: TraceWeaverConfig | None = None,
    ):
        self.vector_ops = vector_ops
        self.llm_client = llm_client
        self.config = config or TraceWeaverConfig()
        self._traces: list[EventTrace] = []

    def set_traces(self, traces: list[EventTrace]) -> None:
        self._traces = list(traces)

    def get_traces(self) -> list[EventTrace]:
        return list(self._traces)

    async def link_membox(self, membox: Membox) -> tuple[list[TraceLink], list[EventTrace]]:
        if not membox.events:
            return [], self._traces

        links: list[TraceLink] = []

        best_trace, best_score = await self._find_best_trace(membox)
        if best_trace is None or best_score < self.config.similarity_threshold:
            new_trace = EventTrace(
                id=str(uuid4()),
                summary=membox.topic or "trace",
                events=list(membox.events),
                membox_ids=[membox.id],
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
            self._traces.append(new_trace)
            links.append(
                TraceLink(
                    membox_id=membox.id,
                    trace_id=new_trace.id,
                    link_type="new",
                    confidence=0.5,
                    reasoning="no suitable trace found",
                )
            )
            return links, self._traces

        # Optional LLM verify
        if self.llm_client is not None:
            ok = await self._verify_link(best_trace, membox)
            if not ok:
                new_trace = EventTrace(
                    id=str(uuid4()),
                    summary=membox.topic or "trace",
                    events=list(membox.events),
                    membox_ids=[membox.id],
                    created_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC),
                )
                self._traces.append(new_trace)
                links.append(
                    TraceLink(
                        membox_id=membox.id,
                        trace_id=new_trace.id,
                        link_type="new",
                        confidence=0.4,
                        reasoning="LLM rejected link to best candidate trace",
                    )
                )
                return links, self._traces

        # Append to trace
        updated = EventTrace(
            id=best_trace.id,
            summary=best_trace.summary,
            events=[*best_trace.events, *membox.events],
            membox_ids=[*best_trace.membox_ids, membox.id],
            created_at=best_trace.created_at,
            updated_at=datetime.now(UTC),
            metadata=best_trace.metadata,
        )
        self._traces = [t if t.id != best_trace.id else updated for t in self._traces]
        links.append(
            TraceLink(
                membox_id=membox.id,
                trace_id=best_trace.id,
                link_type="append",
                confidence=min(max(best_score, 0.0), 1.0),
                reasoning="best similarity match",
            )
        )
        return links, self._traces

    async def _find_best_trace(self, membox: Membox) -> tuple[EventTrace | None, float]:
        if not self._traces:
            return None, 0.0

        candidates = self._traces[-self.config.max_candidate_traces :]
        if self.vector_ops is not None:
            return await self._best_trace_by_embedding(membox, candidates)

        return self._best_trace_by_overlap(membox, candidates)

    async def _best_trace_by_embedding(
        self, membox: Membox, candidates: list[EventTrace]
    ) -> tuple[EventTrace | None, float]:
        query = membox.topic + "\n" + "\n".join(membox.events[:3])
        q = await self.vector_ops.generate_embedding(query)

        best: EventTrace | None = None
        best_score = -math.inf
        for trace in candidates:
            text = trace.summary + "\n" + "\n".join(trace.events[-3:])
            emb = await self.vector_ops.generate_embedding(text)
            score = float(self.vector_ops.cosine_similarity(q, emb))
            if score > best_score:
                best_score = score
                best = trace
        if best is None:
            return None, 0.0
        return best, best_score

    def _best_trace_by_overlap(
        self, membox: Membox, candidates: list[EventTrace]
    ) -> tuple[EventTrace | None, float]:
        membox_tokens = set(_simple_tokens(membox.topic + " " + " ".join(membox.keywords)))
        best: EventTrace | None = None
        best_score = 0.0
        for trace in candidates:
            trace_tokens = set(_simple_tokens(trace.summary + " " + " ".join(trace.events[-3:])))
            if not membox_tokens or not trace_tokens:
                score = 0.0
            else:
                score = len(membox_tokens & trace_tokens) / len(membox_tokens | trace_tokens)
            if score > best_score:
                best_score = score
                best = trace
        return best, best_score

    async def _verify_link(self, trace: EventTrace, membox: Membox) -> bool:
        prompt = (
            "Determine if this new membox belongs to the existing event chain.\n\n"
            f"Existing chain (summary: {trace.summary}):\n"
            + "\n".join(trace.events[-5:])
            + "\n\nNew membox:\n"
            + "\n".join(membox.events[:5])
            + "\n\nDoes this continue or relate to the same core activity? Answer: Yes/No"
        )
        resp = await self.llm_client.messages.create(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        text = resp.content[0].text.lower()
        return "yes" in text


def _simple_tokens(text: str) -> list[str]:
    return [t.lower() for t in re.findall(r"[a-zA-Z0-9_]+", text) if len(t) > 2]


import re

