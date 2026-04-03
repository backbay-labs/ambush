"""Memory extraction engine.

Extracts structured memories from a run transcript using an LLM, optionally
deduplicates them via embeddings, and persists them to the MemoryStore.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from .models import ExtractedMemory, MemoryType

logger = logging.getLogger(__name__)

PROMPTS_DIR = Path(__file__).parent / "prompts"


def _load_prompt(name: str) -> str:
    path = PROMPTS_DIR / name
    if path.exists():
        return path.read_text()
    return ""


@dataclass(frozen=True)
class ExtractionConfig:
    """Configuration for memory extraction."""

    # LLM params
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 4096
    temperature: float = 0.3

    # Extraction params
    max_memories_per_run: int = 10
    min_importance: float = 0.3

    # Deduplication
    dedup_threshold: float = 0.9


class MemoryExtractor:
    """LLM-backed memory extractor with optional persistence."""

    def __init__(
        self,
        llm_client: Any,
        store: Any,
        vector_ops: Any,
        config: ExtractionConfig | None = None,
    ) -> None:
        self.config = config or ExtractionConfig()
        self.llm_client = llm_client
        self.store = store
        self.vector_ops = vector_ops

        self.system_prompt = _load_prompt("extraction_system.txt")
        self.user_prompt_template = _load_prompt("extraction_user.txt")

    async def extract_from_run(
        self,
        run_id: str,
        agent_id: str,
        transcript: str,
        issue_tags: list[str] | None = None,
        file_paths: list[str] | None = None,
    ) -> list[ExtractedMemory]:
        """Extract (and persist) memories for a single run."""
        if not transcript.strip():
            return []

        issue_tags = issue_tags or []
        file_paths = file_paths or []

        prompt = self._build_extraction_prompt(
            run_id=run_id,
            agent_id=agent_id,
            transcript=transcript,
            issue_tags=issue_tags,
            file_paths=file_paths,
        )

        response_text = await self._call_llm(prompt)
        extracted = self._parse_extraction_response(response_text)

        # Fill context defaults
        extracted = [
            m.model_copy(
                update={
                    "issue_tags": m.issue_tags or issue_tags,
                    "file_paths": m.file_paths or file_paths,
                }
            )
            for m in extracted
        ]

        # Filter low-importance
        extracted = [m for m in extracted if m.importance_score >= self.config.min_importance]

        # Deduplicate
        extracted = await self.deduplicate_batch(extracted, threshold=self.config.dedup_threshold)

        if not extracted:
            return []

        # Persist
        embeddings: list[list[float]] | None = None
        if self.vector_ops:
            embeddings = [await self.vector_ops.generate_embedding(m.text) for m in extracted]

        created_ids: list[UUID] | None = None
        if self.store:
            if hasattr(self.store, "create_batch"):
                created_ids = await self.store.create_batch(
                    memories=extracted,
                    agent_id=agent_id,
                    embeddings=embeddings,
                    run_id=run_id,
                )
            elif hasattr(self.store, "create"):
                created_ids = []
                for i, memory in enumerate(extracted):
                    emb = embeddings[i] if embeddings else None
                    mid = await self.store.create(
                        memory=memory,
                        agent_id=agent_id,
                        embedding=emb,
                        run_id=run_id,
                    )
                    created_ids.append(mid)

        if created_ids and len(created_ids) == len(extracted):
            return [
                m.model_copy(update={"id": mid})
                for m, mid in zip(extracted, created_ids, strict=False)
            ]

        return extracted

    async def deduplicate_batch(
        self,
        memories: list[ExtractedMemory],
        threshold: float,
    ) -> list[ExtractedMemory]:
        """Deduplicate a list of extracted memories by semantic similarity."""
        if not self.vector_ops or len(memories) <= 1:
            return memories

        texts = [m.text for m in memories]
        embeddings = await self.vector_ops.batch_embeddings(texts)

        keep: set[int] = set(range(len(memories)))
        for i in range(len(memories)):
            if i not in keep:
                continue
            for j in range(i + 1, len(memories)):
                if j not in keep:
                    continue
                sim = self.vector_ops.cosine_similarity(embeddings[i], embeddings[j])
                if sim >= threshold:
                    # Keep higher-importance memory
                    if memories[i].importance_score >= memories[j].importance_score:
                        keep.discard(j)
                    else:
                        keep.discard(i)
                        break

        return [memories[i] for i in sorted(keep)]

    def _build_extraction_prompt(
        self,
        run_id: str,
        agent_id: str,
        transcript: str,
        issue_tags: list[str],
        file_paths: list[str],
    ) -> str:
        if self.user_prompt_template:
            try:
                return self.user_prompt_template.format(
                    run_id=run_id,
                    agent_id=agent_id,
                    status="completed",
                    patch_applied="unknown",
                    gates_passed="unknown",
                    issue_tags=", ".join(issue_tags) if issue_tags else "none",
                    file_changes="\n".join(file_paths) if file_paths else "none",
                    file_paths="\n".join(file_paths) if file_paths else "none",
                    transcript=transcript[:50_000],
                )
            except KeyError:
                # Prompt templates may evolve; fall back to a minimal prompt if
                # placeholders don't match this extractor's inputs.
                pass

        tags_str = ", ".join(issue_tags) if issue_tags else "none"
        files_str = ", ".join(file_paths) if file_paths else "none"
        return (
            "Extract discrete memories from this run transcript.\n\n"
            f"Run ID: {run_id}\n"
            f"Agent: {agent_id}\n"
            f"Issue Tags: {tags_str}\n"
            f"File Paths: {files_str}\n\n"
            "Return a JSON array of objects with keys:\n"
            "- text\n"
            "- memory_type (pattern|failure|dynamic|context|playbook|frontier)\n"
            "- importance_score (0..1)\n"
            "- confidence (0..1)\n\n"
            f"Transcript:\n{transcript[:50_000]}\n"
        )

    async def _call_llm(self, prompt: str) -> str:
        messages: list[dict[str, str]] = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": prompt})

        resp = await self.llm_client.messages.create(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            messages=messages,
        )
        return resp.content[0].text

    def _parse_extraction_response(self, response_text: str) -> list[ExtractedMemory]:
        """Parse an LLM response into ExtractedMemory objects."""
        config = getattr(self, "config", ExtractionConfig())
        try:
            start = response_text.find("[")
            end = response_text.rfind("]") + 1
            if start == -1 or end <= start:
                return []
            raw = json.loads(response_text[start:end])
            if not isinstance(raw, list):
                return []
        except Exception:
            return []

        memories: list[ExtractedMemory] = []
        for item in raw[: config.max_memories_per_run]:
            if not isinstance(item, dict):
                continue

            text = str(item.get("text", "")).strip()
            if not text:
                continue

            memory_type = self._parse_memory_type(str(item.get("memory_type", "pattern")))
            try:
                importance = float(item.get("importance_score", 0.5))
            except Exception:
                importance = 0.5
            try:
                confidence = float(item.get("confidence", 0.5))
            except Exception:
                confidence = 0.5

            memories.append(
                ExtractedMemory(
                    id=None,
                    text=text,
                    memory_type=memory_type,
                    importance_score=max(0.0, min(1.0, importance)),
                    confidence=max(0.0, min(1.0, confidence)),
                    issue_tags=item.get("issue_tags") or [],
                    file_paths=item.get("file_paths") or [],
                )
            )

        return memories

    def _parse_memory_type(self, type_str: str) -> MemoryType:
        try:
            return MemoryType(type_str.lower())
        except Exception:
            return MemoryType.PATTERN


class ExtractionBatchService:
    """Simple in-memory batch tracker for extraction jobs (used for testing)."""

    def __init__(self, extractor: Any, store: Any) -> None:
        self.extractor = extractor
        self.store = store
        self._batches: dict[str, dict[str, Any]] = {}

    async def create_batch(self, run_ids: list[str], agent_id: str) -> str:
        batch_id = f"batch_{uuid4().hex}"
        self._batches[batch_id] = {
            "agent_id": agent_id,
            "run_ids": list(run_ids),
            "transcripts": {},
            "created_at": uuid4().hex,  # opaque
        }
        return batch_id

    async def process_batch(self, batch_id: str) -> list[ExtractedMemory]:
        batch = self._batches.get(batch_id)
        if not batch:
            raise KeyError(f"Unknown batch: {batch_id}")

        agent_id = str(batch["agent_id"])
        transcripts: dict[str, str] = batch.get("transcripts") or {}

        results: list[ExtractedMemory] = []
        for run_id, transcript in transcripts.items():
            extracted = await self.extractor.extract_from_run(
                run_id=run_id,
                agent_id=agent_id,
                transcript=transcript,
            )
            results.extend(extracted)

        return results
