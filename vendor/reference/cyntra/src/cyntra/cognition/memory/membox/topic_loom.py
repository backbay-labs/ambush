from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from cyntra.cognition.memory.membox.models import Membox, MemboxMessage

_STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "but",
    "by",
    "for",
    "from",
    "has",
    "have",
    "he",
    "her",
    "his",
    "i",
    "in",
    "is",
    "it",
    "its",
    "me",
    "of",
    "on",
    "or",
    "our",
    "she",
    "that",
    "the",
    "their",
    "them",
    "there",
    "they",
    "this",
    "to",
    "was",
    "we",
    "were",
    "with",
    "you",
    "your",
}


def _tokenize(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-zA-Z0-9_]+", text.lower()) if t and t not in _STOPWORDS]


@dataclass(frozen=True)
class TopicLoomConfig:
    window_size: int = 2
    min_box_size: int = 2
    heuristic_overlap_min: int = 2
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 1024
    temperature: float = 0.2


class TopicLoom:
    """
    Sliding-window topic-break classifier.

    For Phase 1 scaffolding:
    - Uses an LLM if provided (Anthropic-style client with `messages.create`)
    - Falls back to a simple lexical-overlap heuristic when LLM is unavailable
    """

    def __init__(self, *, llm_client: Any | None = None, config: TopicLoomConfig | None = None):
        self.llm_client = llm_client
        self.config = config or TopicLoomConfig()
        self._current_box: list[MemboxMessage] = []

    async def process_message(self, message: MemboxMessage) -> Membox | None:
        if not self._current_box:
            self._current_box.append(message)
            return None

        window = self._current_box[-self.config.window_size :]
        classification = await self._classify_continuity(window, message)

        if classification == "continuous":
            self._current_box.append(message)
            return None

        sealed = await self._seal_box(self._current_box)
        self._current_box = [message]
        return sealed

    async def flush(self) -> Membox | None:
        if not self._current_box:
            return None

        if len(self._current_box) >= self.config.min_box_size:
            sealed = await self._seal_box(self._current_box)
            self._current_box = []
            return sealed
        # At end-of-stream, prefer returning a small box over dropping context.
        sealed = await self._seal_box(self._current_box)
        self._current_box = []
        return sealed

    async def _classify_continuity(
        self, window: list[MemboxMessage], new_message: MemboxMessage
    ) -> str:
        if self.llm_client is None:
            return self._heuristic_classify(window, new_message)

        prompt = self._build_continuity_prompt(window, new_message)
        response_text = await self._call_llm(prompt)
        low = response_text.lower()
        if "part" in low:
            return "partial_shift"
        if "yes" in low:
            return "continuous"
        if "no" in low:
            return "discontinuous"
        return self._heuristic_classify(window, new_message)

    def _heuristic_classify(self, window: list[MemboxMessage], new_message: MemboxMessage) -> str:
        window_tokens: set[str] = set()
        for m in window:
            window_tokens.update(_tokenize(m.content))
        new_tokens = set(_tokenize(new_message.content))
        overlap = len(window_tokens & new_tokens)
        return "continuous" if overlap >= self.config.heuristic_overlap_min else "discontinuous"

    def _build_continuity_prompt(self, window: list[MemboxMessage], new_message: MemboxMessage) -> str:
        window_text = "\n\n".join([f"{m.role}: {m.content}" for m in window])
        return (
            "Determine whether the current message continues the main topic of the previous messages.\n\n"
            f"Previous messages:\n{window_text}\n\n"
            f"Current message:\n{new_message.content}\n\n"
            "Answer only: Yes/No/Partially Shifted"
        )

    async def _seal_box(self, messages: list[MemboxMessage]) -> Membox:
        if self.llm_client is None:
            return self._heuristic_seal(messages)

        prompt = self._build_seal_prompt(messages)
        response_text = await self._call_llm(prompt)
        extracted = self._parse_seal_response(response_text)
        return Membox(
            id=str(uuid4()),
            topic=extracted.get("topic", "unknown"),
            events=extracted.get("events", []),
            keywords=extracted.get("keywords", []),
            messages=list(messages),
            created_at=datetime.now(UTC),
        )

    def _heuristic_seal(self, messages: list[MemboxMessage]) -> Membox:
        tokens: list[str] = []
        for m in messages:
            tokens.extend(_tokenize(m.content))
        counts = Counter(tokens)
        keywords = [w for w, _c in counts.most_common(8)]
        topic = " ".join(keywords[:3]) if keywords else "unknown"
        events = [m.content.strip().splitlines()[0][:200] for m in messages if m.content.strip()]
        return Membox(
            id=str(uuid4()),
            topic=topic,
            keywords=keywords,
            events=events[:10],
            messages=list(messages),
            created_at=datetime.now(UTC),
        )

    def _build_seal_prompt(self, messages: list[MemboxMessage]) -> str:
        content = "\n".join([m.content for m in messages])
        return (
            "Analyze this dialogue and extract:\n"
            "1) Core topic (one clear phrase)\n"
            "2) Explicit events mentioned (concrete actions or occurrences)\n"
            "3) Salient keywords (3-8 nouns/entities)\n\n"
            f"Content:\n{content}\n\n"
            "Output as JSON:\n"
            '{\n  "topic": "...",\n  "events": ["..."],\n  "keywords": ["..."]\n}'
        )

    def _parse_seal_response(self, response_text: str) -> dict[str, Any]:
        try:
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            if start == -1 or end <= start:
                return {}
            raw = json.loads(response_text[start:end])
            if not isinstance(raw, dict):
                return {}
        except Exception:
            return {}

        topic = raw.get("topic")
        events = raw.get("events")
        keywords = raw.get("keywords")
        return {
            "topic": str(topic) if topic else "unknown",
            "events": [str(x) for x in events] if isinstance(events, list) else [],
            "keywords": [str(x) for x in keywords] if isinstance(keywords, list) else [],
        }

    async def _call_llm(self, prompt: str) -> str:
        resp = await self.llm_client.messages.create(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text
