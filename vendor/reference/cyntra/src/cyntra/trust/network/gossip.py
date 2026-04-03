"""
Gossip coordination for trail propagation.

This module provides higher-level gossip coordination on top of
the CNP node, handling:
- Trail batching and prioritization
- Peer selection for gossip
- Anti-entropy synchronization
- Bloom filter deduplication
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Set

from cyntra.trust.network.schemas import Trail, TrailQuery
from cyntra.trust.network.store.trails import TrailStore
from cyntra.trust.network.store.peers import PeerStore, PeerStatus


logger = logging.getLogger(__name__)


@dataclass
class GossipConfig:
    """Configuration for gossip behavior."""

    # Batching
    batch_size: int = 10
    batch_interval_secs: float = 5.0

    # Peer selection
    max_peers_per_round: int = 5
    prefer_high_reputation: bool = True

    # Anti-entropy
    sync_interval_secs: int = 300  # 5 minutes
    sync_batch_size: int = 100

    # Bloom filter for deduplication
    bloom_filter_size: int = 10000
    bloom_false_positive_rate: float = 0.01

    # Limits
    max_queue_size: int = 1000
    trail_ttl_hours: int = 168  # 1 week


class BloomFilter:
    """
    Simple bloom filter for trail deduplication.

    Tracks which trails we've already seen to avoid
    re-processing or re-gossiping.
    """

    def __init__(self, size: int = 10000, num_hashes: int = 7):
        self.size = size
        self.num_hashes = num_hashes
        self.bits: Set[int] = set()

    def _hashes(self, item: str) -> list[int]:
        """Generate hash positions for an item."""
        positions = []
        for i in range(self.num_hashes):
            h = hashlib.sha256(f"{item}:{i}".encode()).digest()
            pos = int.from_bytes(h[:4], "big") % self.size
            positions.append(pos)
        return positions

    def add(self, item: str) -> None:
        """Add an item to the filter."""
        for pos in self._hashes(item):
            self.bits.add(pos)

    def contains(self, item: str) -> bool:
        """Check if item might be in the filter."""
        return all(pos in self.bits for pos in self._hashes(item))

    def clear(self) -> None:
        """Clear the filter."""
        self.bits.clear()


@dataclass
class GossipStats:
    """Statistics for gossip operations."""

    trails_queued: int = 0
    trails_sent: int = 0
    trails_received: int = 0
    trails_deduplicated: int = 0
    sync_rounds: int = 0
    peers_contacted: int = 0


class GossipManager:
    """
    Manages gossip-based trail propagation.

    Coordinates:
    - Outbound gossip of local trails
    - Inbound processing of received trails
    - Anti-entropy synchronization
    - Deduplication via bloom filters
    """

    def __init__(
        self,
        trail_store: TrailStore,
        peer_store: PeerStore,
        config: Optional[GossipConfig] = None,
    ):
        self.trail_store = trail_store
        self.peer_store = peer_store
        self.config = config or GossipConfig()

        # Outbound queue
        self._queue: list[Trail] = []
        self._queue_lock = asyncio.Lock()

        # Deduplication
        self._seen_filter = BloomFilter(
            size=self.config.bloom_filter_size,
        )

        # Stats
        self._stats = GossipStats()

        # Background tasks
        self._running = False
        self._gossip_task: Optional[asyncio.Task] = None
        self._sync_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start gossip manager."""
        if self._running:
            return

        self._running = True
        self._gossip_task = asyncio.create_task(self._gossip_loop())
        self._sync_task = asyncio.create_task(self._sync_loop())
        logger.info("Gossip manager started")

    async def stop(self) -> None:
        """Stop gossip manager."""
        self._running = False

        for task in [self._gossip_task, self._sync_task]:
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        logger.info("Gossip manager stopped")

    async def enqueue(self, trail: Trail) -> None:
        """Queue a trail for gossip."""
        async with self._queue_lock:
            if len(self._queue) >= self.config.max_queue_size:
                # Drop oldest if queue full
                self._queue.pop(0)

            self._queue.append(trail)
            self._stats.trails_queued += 1

        # Mark as seen
        self._seen_filter.add(trail.id)

    async def receive(self, trail: Trail, sender_id: str) -> bool:
        """
        Process a received trail.

        Returns True if trail was new and stored.
        """
        # Check deduplication
        if self._seen_filter.contains(trail.id):
            self._stats.trails_deduplicated += 1
            return False

        # Verify trail
        # TODO: Verify signature against sender's public key

        # Store trail
        self.trail_store.insert(trail)
        self._seen_filter.add(trail.id)
        self._stats.trails_received += 1

        # Update peer stats
        self.peer_store.increment_trails_received(sender_id)

        logger.debug(f"Received trail {trail.id[:8]} from {sender_id}")
        return True

    def stats(self) -> GossipStats:
        """Get gossip statistics."""
        return self._stats

    async def _gossip_loop(self) -> None:
        """Background loop for outbound gossip."""
        while self._running:
            try:
                await asyncio.sleep(self.config.batch_interval_secs)
                await self._do_gossip_round()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Gossip error: {e}")

    async def _do_gossip_round(self) -> None:
        """Execute one gossip round."""
        # Get batch from queue
        async with self._queue_lock:
            batch = self._queue[:self.config.batch_size]
            self._queue = self._queue[self.config.batch_size:]

        if not batch:
            return

        # Select peers
        peers = self._select_gossip_peers()
        if not peers:
            # Re-queue trails if no peers
            async with self._queue_lock:
                self._queue = batch + self._queue
            return

        # Send to selected peers
        for peer in peers:
            try:
                await self._send_trails(peer.peer_id, batch)
                self._stats.trails_sent += len(batch)
                self._stats.peers_contacted += 1
            except Exception as e:
                logger.warning(f"Failed to gossip to {peer.peer_id}: {e}")
                peer.update_reputation(success=False)

    def _select_gossip_peers(self) -> list:
        """Select peers for gossip round."""
        active_peers = self.peer_store.list_active(
            limit=self.config.max_peers_per_round * 2
        )

        if not active_peers:
            return []

        # Sort by reputation if preferred
        if self.config.prefer_high_reputation:
            active_peers.sort(key=lambda p: p.reputation_score, reverse=True)

        return active_peers[:self.config.max_peers_per_round]

    async def _send_trails(self, peer_id: str, trails: list[Trail]) -> None:
        """Send trails to a peer."""
        # TODO: Implement actual network send via libp2p
        logger.debug(f"Would send {len(trails)} trails to {peer_id}")

    async def _sync_loop(self) -> None:
        """Background loop for anti-entropy sync."""
        while self._running:
            try:
                await asyncio.sleep(self.config.sync_interval_secs)
                await self._do_sync_round()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Sync error: {e}")

    async def _do_sync_round(self) -> None:
        """Execute one anti-entropy sync round."""
        # Get random peer
        peers = self.peer_store.list_by_status(PeerStatus.CONNECTED, limit=1)
        if not peers:
            return

        peer = peers[0]

        try:
            # Request their recent trails
            # TODO: Implement via query protocol

            # Compare with our trails
            # TODO: Implement set reconciliation

            self._stats.sync_rounds += 1
            logger.debug(f"Completed sync with {peer.peer_id}")
        except Exception as e:
            logger.warning(f"Sync failed with {peer.peer_id}: {e}")

    def reset_bloom_filter(self) -> None:
        """Reset the bloom filter (e.g., periodically to prevent saturation)."""
        self._seen_filter.clear()
        logger.info("Bloom filter reset")
