"""
Vector Operations - Embedding generation and similarity calculations.

Provides async embedding generation using sentence-transformers or
OpenAI embeddings with caching support.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import cast

logger = logging.getLogger(__name__)

# Default embedding model (768d, asymmetric for retrieval)
DEFAULT_MODEL = "nomic-ai/nomic-embed-text-v1.5"
EMBEDDING_DIM = 768


class VectorOps:
    """
    Async vector operations for memory embeddings.

    Supports:
    - sentence-transformers (local, fast, no API costs)
    - OpenAI embeddings (API, higher quality for some tasks)
    """

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        use_openai: bool = False,
        openai_model: str = "text-embedding-3-small",
        cache_size: int = 1000,
    ):
        """
        Initialize vector operations.

        Args:
            model_name: Sentence-transformers model name
            use_openai: Use OpenAI API instead of local model
            openai_model: OpenAI embedding model name
            cache_size: LRU cache size for embeddings
        """
        self.model_name = model_name
        self.use_openai = use_openai
        self.openai_model = openai_model
        self._model = None
        self._openai_client = None
        self._cache: dict = {}
        self._cache_size = cache_size

    def _cache_put(self, cache_key: str, embedding: list[float]) -> None:
        """Insert into cache with simple FIFO eviction."""
        if len(self._cache) >= self._cache_size:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
        self._cache[cache_key] = embedding

    async def _get_model(self):
        """Lazy load sentence-transformers model."""
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer

                # Load in thread pool to avoid blocking
                loop = asyncio.get_event_loop()
                self._model = await loop.run_in_executor(
                    None, lambda: SentenceTransformer(self.model_name, trust_remote_code=True)
                )
                logger.info(f"Loaded embedding model: {self.model_name}")
            except ImportError as err:
                raise ImportError(
                    "sentence-transformers not installed. "
                    "Install with: pip install sentence-transformers"
                ) from err
        return self._model

    async def _get_openai_client(self):
        """Lazy load OpenAI client."""
        if self._openai_client is None:
            try:
                from openai import AsyncOpenAI

                self._openai_client = AsyncOpenAI()
                logger.info("Initialized OpenAI embeddings client")
            except ImportError as err:
                raise ImportError("openai not installed. Install with: pip install openai") from err
        return self._openai_client

    def _cache_key(self, text: str) -> str:
        """Generate cache key for text."""
        return hashlib.md5(text.encode()).hexdigest()

    async def generate_embedding(self, text: str) -> list[float]:
        """
        Generate embedding for text.

        Args:
            text: Text to embed

        Returns:
            Embedding vector (768d or model-specific)
        """
        # Check cache
        cache_key = self._cache_key(text)
        if cache_key in self._cache:
            return self._cache[cache_key]

        if self.use_openai:
            embedding = await self._embed_openai(text)
        else:
            embedding = await self._embed_local(text)

        self._cache_put(cache_key, embedding)

        return embedding

    async def batch_embeddings(
        self,
        texts: list[str],
        batch_size: int = 32,
    ) -> list[list[float]]:
        """
        Generate embeddings for multiple texts.

        Args:
            texts: List of texts to embed
            batch_size: Batch size for processing

        Returns:
            List of embedding vectors
        """
        if not texts:
            return []

        results: list[list[float] | None] = [None] * len(texts)
        uncached_texts: list[str] = []
        uncached_indices: list[int] = []

        for i, text in enumerate(texts):
            cache_key = self._cache_key(text)
            cached = self._cache.get(cache_key)
            if cached is not None:
                results[i] = cached
            else:
                uncached_texts.append(text)
                uncached_indices.append(i)

        if uncached_texts:
            if self.use_openai:
                embeddings = await self._batch_embed_openai(uncached_texts, batch_size)
            else:
                embeddings = await self._batch_embed_local(uncached_texts, batch_size)

            if len(embeddings) != len(uncached_texts):
                raise ValueError("Embedding batch size mismatch")

            for idx, text, embedding in zip(
                uncached_indices, uncached_texts, embeddings, strict=False
            ):
                cache_key = self._cache_key(text)
                self._cache_put(cache_key, embedding)
                results[idx] = embedding

        if any(r is None for r in results):
            raise RuntimeError("Embedding generation failed to produce results")
        return [cast(list[float], r) for r in results]

    async def _embed_local(self, text: str) -> list[float]:
        """Generate embedding using sentence-transformers."""
        model = await self._get_model()
        loop = asyncio.get_event_loop()

        embedding = await loop.run_in_executor(
            None, lambda: model.encode(text, convert_to_numpy=True)
        )
        return embedding.tolist()

    async def _batch_embed_local(
        self,
        texts: list[str],
        batch_size: int,
    ) -> list[list[float]]:
        """Batch embed using sentence-transformers."""
        model = await self._get_model()
        loop = asyncio.get_event_loop()
        embeddings = await loop.run_in_executor(
            None,
            lambda: model.encode(texts, batch_size=batch_size, convert_to_numpy=True),
        )
        return [e.tolist() for e in embeddings]

    async def _embed_openai(self, text: str) -> list[float]:
        """Generate embedding using OpenAI API."""
        client = await self._get_openai_client()
        response = await client.embeddings.create(
            model=self.openai_model,
            input=text,
        )
        return response.data[0].embedding

    async def _batch_embed_openai(
        self,
        texts: list[str],
        batch_size: int,
    ) -> list[list[float]]:
        """Batch embed using OpenAI API."""
        client = await self._get_openai_client()
        results: list[list[float]] = []
        for batch_start in range(0, len(texts), batch_size):
            batch_texts = texts[batch_start : batch_start + batch_size]
            response = await client.embeddings.create(model=self.openai_model, input=batch_texts)
            results.extend([d.embedding for d in response.data])
        return results

    @staticmethod
    def cosine_similarity(a: list[float], b: list[float]) -> float:
        """
        Calculate cosine similarity between two vectors.

        Args:
            a: First vector
            b: Second vector

        Returns:
            Cosine similarity (0-1)
        """
        import math

        dot_product = sum(x * y for x, y in zip(a, b, strict=False))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(y * y for y in b))

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return dot_product / (norm_a * norm_b)

    @staticmethod
    def euclidean_distance(a: list[float], b: list[float]) -> float:
        """
        Calculate Euclidean distance between two vectors.

        Args:
            a: First vector
            b: Second vector

        Returns:
            Euclidean distance
        """
        import math

        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b, strict=False)))


# Singleton instance for convenience
_default_ops: VectorOps | None = None


def get_vector_ops(
    model_name: str = DEFAULT_MODEL,
    use_openai: bool = False,
) -> VectorOps:
    """
    Get default VectorOps instance.

    Args:
        model_name: Sentence-transformers model name
        use_openai: Use OpenAI API

    Returns:
        VectorOps instance
    """
    global _default_ops
    if _default_ops is None:
        _default_ops = VectorOps(
            model_name=model_name,
            use_openai=use_openai,
        )
    return _default_ops
