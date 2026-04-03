from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Literal

from cyntra.cognition.memory.membox.membox_store import MemboxStore
from cyntra.cognition.memory.membox.models import EventTrace, Membox


@dataclass(frozen=True)
class RetrievalConfig:
    max_results: int = 8
    max_candidates: int = 250
    min_score: float = 0.1
    max_events_per_item: int = 3
    max_tokens: int = 200
    primary_weight: float = 0.7
    secondary_weight: float = 0.2
    coverage_weight: float = 0.1


@dataclass(frozen=True)
class RetrievalHit:
    kind: Literal["trace", "membox"]
    id: str
    title: str
    score: float
    matched_terms: list[str]
    events: list[str]
    timestamp: str


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
    return [
        t
        for t in re.findall(r"[a-zA-Z0-9_]+", text.lower())
        if t and t not in _STOPWORDS and len(t) > 1
    ]


def _overlap_score(query_tokens: set[str], doc_tokens: set[str]) -> tuple[float, list[str]]:
    overlap = query_tokens & doc_tokens
    if not overlap:
        return 0.0, []
    score = len(overlap) / math.sqrt(len(doc_tokens) + 1)
    matched = sorted(overlap, key=lambda t: (-len(t), t))[:8]
    return float(score), matched


def _merge_matched(primary: list[str], secondary: list[str]) -> list[str]:
    seen: set[str] = set()
    merged: list[str] = []
    for token in primary + secondary:
        if token in seen:
            continue
        seen.add(token)
        merged.append(token)
    return merged


def _coverage_score(query_tokens: set[str], overlap_tokens: set[str]) -> float:
    if not query_tokens:
        return 0.0
    return len(overlap_tokens) / float(len(query_tokens))


def _estimate_tokens(text: str) -> int:
    return len(text.split())


def render_membox_context_section(membox_context: dict[str, Any]) -> list[str]:
    """
    Render the injected Membox context section (Markdown lines) as it appears in prompts.

    This is used by both prompt builders and CLI diagnostics to ensure they stay aligned.
    """
    if not isinstance(membox_context, dict):
        return []

    selected = membox_context.get("selected")
    if not isinstance(selected, list) or not selected:
        return []

    lines: list[str] = [
        "## Membox Context",
        "*Topic-continuous memory (ranked for this task):*",
        "",
    ]

    for item in selected:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        kind = str(item.get("kind") or "").strip()
        matched_terms = item.get("matched_terms") if isinstance(item.get("matched_terms"), list) else []
        events = item.get("events") if isinstance(item.get("events"), list) else []

        if not title or kind not in {"trace", "membox"}:
            continue

        parts: list[str] = [f"- {'Trace' if kind == 'trace' else 'Membox'}: {title}"]
        if matched_terms:
            terms = ", ".join(str(t) for t in matched_terms[:6] if t is not None)
            if terms:
                parts.append(f"(matches: {terms})")
        line = " ".join(parts)

        if events:
            preview = " | ".join(str(e).strip()[:160] for e in events[:3] if e is not None and str(e).strip())
            if preview:
                line += f"; events: {preview}"

        lines.append(line)

    lines.append("")
    return lines


def build_membox_query_text(*, issue: Any, manifest: dict[str, Any]) -> str:
    """
    Build a retrieval query string for Membox context injection.

    Phase 1 uses lexical relevance, so this should emphasize high-signal task identifiers:
    issue title/description, acceptance criteria, key file paths, and gate names.
    """

    def _get_attr(obj: Any, name: str) -> Any:
        if isinstance(obj, dict):
            return obj.get(name)
        return getattr(obj, name, None)

    parts: list[str] = []
    title = _get_attr(issue, "title")
    if isinstance(title, str) and title.strip():
        parts.append(title.strip())

    description = _get_attr(issue, "description")
    if isinstance(description, str) and description.strip():
        parts.append(description.strip())

    acceptance_criteria = _get_attr(issue, "acceptance_criteria")
    if isinstance(acceptance_criteria, list):
        criteria = [c.strip() for c in acceptance_criteria if isinstance(c, str) and c.strip()]
        if criteria:
            parts.append("Acceptance criteria:\n" + "\n".join(criteria))

    context_files = _get_attr(issue, "context_files")
    if isinstance(context_files, list):
        files = [f.strip() for f in context_files if isinstance(f, str) and f.strip()]
        if files:
            parts.append("Relevant files:\n" + "\n".join(files))

    tags = _get_attr(issue, "tags")
    if isinstance(tags, list) and tags:
        parts.append("Tags: " + " ".join(str(t) for t in tags if t))

    job_type = manifest.get("job_type")
    if isinstance(job_type, str) and job_type.strip():
        parts.append(f"Job type: {job_type.strip()}")

    toolchain = manifest.get("toolchain")
    if isinstance(toolchain, str) and toolchain.strip():
        parts.append(f"Toolchain: {toolchain.strip()}")

    gates = manifest.get("quality_gates")
    if isinstance(gates, dict) and gates:
        parts.append("Quality gates: " + " ".join(str(k) for k in gates.keys()))

    return "\n\n".join([p for p in parts if isinstance(p, str) and p.strip()])


class MemboxRetrieval:
    """
    Lexical relevance-based retrieval over Membox + Trace tables.

    Phase 1 uses simple token overlap scoring. A future Phase 2 can swap in embeddings
    (VectorOps) while keeping the same output schema.
    """

    def __init__(self, store: MemboxStore, *, config: RetrievalConfig | None = None):
        self.store = store
        self.config = config or RetrievalConfig()

    def build_context(self, *, query: str) -> dict[str, Any]:
        """
        Rank traces+memboxes against the query text, then select top hits under a token budget.
        """
        query_tokens = set(_tokenize(query))
        trace_candidates = self.store.list_traces(limit=self.config.max_candidates)
        membox_candidates = self.store.list_recent_memboxes(limit=self.config.max_candidates)

        hits: list[RetrievalHit] = []
        for trace in trace_candidates:
            hit = self._score_trace(trace, query_tokens)
            if hit is not None:
                hits.append(hit)

        for membox in membox_candidates:
            hit = self._score_membox(membox, query_tokens)
            if hit is not None:
                hits.append(hit)

        hits.sort(key=lambda h: h.score, reverse=True)
        hits = hits[: max(self.config.max_results * 3, self.config.max_results)]

        selected: list[dict[str, Any]] = []
        used_tokens = 0
        for hit in hits:
            if len(selected) >= self.config.max_results:
                break

            item_text = f"{hit.kind} {hit.title} {' '.join(hit.matched_terms)} {' '.join(hit.events)}"
            token_cost = _estimate_tokens(item_text)
            if token_cost <= 0:
                continue

            # Try to truncate events to fit budget.
            events = list(hit.events)
            while events and used_tokens + token_cost > self.config.max_tokens:
                events = events[:-1]
                item_text = f"{hit.kind} {hit.title} {' '.join(hit.matched_terms)} {' '.join(events)}"
                token_cost = _estimate_tokens(item_text)

            if used_tokens + token_cost > self.config.max_tokens:
                continue

            used_tokens += token_cost
            selected.append(
                {
                    "kind": hit.kind,
                    "id": hit.id,
                    "title": hit.title,
                    "score": hit.score,
                    "matched_terms": hit.matched_terms,
                    "events": events,
                    "timestamp": hit.timestamp,
                    "token_cost": token_cost,
                }
            )

        return {
            "query": query,
            "selected": selected,
            "stats": {
                "query_tokens": len(query_tokens),
                "candidates": {
                    "traces": len(trace_candidates),
                    "memboxes": len(membox_candidates),
                },
                "token_budget": {"max_tokens": self.config.max_tokens, "used_tokens": used_tokens},
            },
        }

    def _score_trace(self, trace: EventTrace, query_tokens: set[str]) -> RetrievalHit | None:
        title = trace.summary.strip() or "trace"
        # Use the most recent events as context.
        events = [e for e in trace.events[-10:] if isinstance(e, str) and e.strip()]
        title_tokens = set(_tokenize(title))
        event_tokens: set[str] = set()
        for evt in events:
            event_tokens.update(_tokenize(evt))

        primary_score, primary_matched = _overlap_score(query_tokens, title_tokens)
        secondary_score, secondary_matched = _overlap_score(query_tokens, event_tokens)
        overlap_tokens = (query_tokens & title_tokens) | (query_tokens & event_tokens)
        coverage = _coverage_score(query_tokens, overlap_tokens)
        score = (
            self.config.primary_weight * primary_score
            + self.config.secondary_weight * secondary_score
            + self.config.coverage_weight * coverage
        )
        matched = _merge_matched(primary_matched, secondary_matched)
        if score < self.config.min_score or not matched:
            return None

        preview = [e.strip()[:200] for e in events[-self.config.max_events_per_item :]]
        return RetrievalHit(
            kind="trace",
            id=trace.id,
            title=title[:200],
            score=score,
            matched_terms=matched,
            events=preview,
            timestamp=trace.updated_at.isoformat(),
        )

    def _score_membox(self, membox: Membox, query_tokens: set[str]) -> RetrievalHit | None:
        title = membox.topic.strip() or "membox"
        events = [e for e in membox.events if isinstance(e, str) and e.strip()]
        title_tokens = set(_tokenize(title))
        keyword_tokens = set(_tokenize(" ".join(membox.keywords)))
        primary_tokens = title_tokens | keyword_tokens
        event_tokens: set[str] = set()
        for evt in events[:10]:
            event_tokens.update(_tokenize(evt))

        primary_score, primary_matched = _overlap_score(query_tokens, primary_tokens)
        secondary_score, secondary_matched = _overlap_score(query_tokens, event_tokens)
        overlap_tokens = (query_tokens & primary_tokens) | (query_tokens & event_tokens)
        coverage = _coverage_score(query_tokens, overlap_tokens)
        score = (
            self.config.primary_weight * primary_score
            + self.config.secondary_weight * secondary_score
            + self.config.coverage_weight * coverage
        )
        matched = _merge_matched(primary_matched, secondary_matched)
        if score < self.config.min_score or not matched:
            return None

        preview = [e.strip()[:200] for e in events[: self.config.max_events_per_item]]
        return RetrievalHit(
            kind="membox",
            id=membox.id,
            title=title[:200],
            score=score,
            matched_terms=matched,
            events=preview,
            timestamp=membox.created_at.isoformat(),
        )
