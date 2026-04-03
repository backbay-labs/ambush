"""
CNP Node - libp2p-based network node for trail gossip.

This module provides the core networking layer for CNP:
- Peer discovery (mDNS, DHT)
- Gossip pubsub for trail propagation
- Direct connections for queries

Uses py-libp2p when available, falls back to stub for development.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from cyntra.trust.network.schemas import Trail, TrailQuery, TrailCitation
from cyntra.trust.network.store.trails import TrailStore
from cyntra.trust.network.store.peers import PeerStore, Peer, PeerStatus
from cyntra.trust.network.libp2p_host import (
    LibP2PHost,
    LibP2PConfig,
    create_host,
    PROTOCOL_TRAILS_TOPIC,
    PROTOCOL_QUERY,
)

# Try to use Rust signing when available
try:
    from cyntra_trust import Keypair as RustKeypair, sha256 as rust_sha256
    _RUST_CRYPTO = True
except ImportError:
    _RUST_CRYPTO = False
    # Fall back to nacl
    try:
        from nacl.signing import SigningKey, VerifyKey
        from nacl.encoding import HexEncoder
    except ImportError:
        pass


logger = logging.getLogger(__name__)


@dataclass
class NodeConfig:
    """Configuration for a CNP node."""

    # Identity
    node_id: str = ""  # Auto-generated if empty
    private_key_path: Optional[Path] = None

    # Network
    listen_addrs: list[str] = field(default_factory=lambda: ["/ip4/0.0.0.0/tcp/0"])
    bootstrap_peers: list[str] = field(default_factory=list)

    # Discovery
    enable_mdns: bool = True
    enable_dht: bool = True
    mdns_interval_secs: int = 30

    # Storage
    data_dir: Path = field(default_factory=lambda: Path(".cyntra/network"))

    # Limits
    max_peers: int = 50
    max_trails_per_gossip: int = 10
    gossip_interval_secs: int = 30

    # Decay
    trail_decay_rate: float = 0.01  # 1% per day
    decay_interval_secs: int = 3600  # Run decay every hour


@dataclass
class NodeStats:
    """Runtime statistics for a CNP node."""

    peer_count: int = 0
    trail_count: int = 0
    trails_received: int = 0
    trails_sent: int = 0
    queries_received: int = 0
    queries_sent: int = 0
    uptime_secs: int = 0


class CNPNode:
    """
    Cyntra Network Protocol node.

    Handles:
    - Peer discovery and connection management
    - Trail gossip and propagation
    - Trail queries and responses
    - Local trail storage with decay
    
    Uses libp2p for networking when available.
    """

    def __init__(self, config: NodeConfig):
        self.config = config
        self._running = False
        self._start_time: Optional[float] = None

        # Initialize storage
        config.data_dir.mkdir(parents=True, exist_ok=True)
        self.trail_store = TrailStore(config.data_dir / "trails.db")
        self.peer_store = PeerStore(config.data_dir / "peers.db")

        # Identity (using Rust when available)
        self._keypair: Optional[Any] = None  # RustKeypair or SigningKey
        self._peer_id: str = ""

        # libp2p host
        self._host: Optional[LibP2PHost] = None

        # Event handlers
        self._on_trail_received: Optional[Callable[[Trail, str], None]] = None
        self._on_peer_connected: Optional[Callable[[Peer], None]] = None
        self._on_peer_disconnected: Optional[Callable[[str], None]] = None

        # Tasks
        self._gossip_task: Optional[asyncio.Task] = None
        self._decay_task: Optional[asyncio.Task] = None
        self._discovery_task: Optional[asyncio.Task] = None

        # Stats
        self._stats = NodeStats()

        # Initialize identity
        self._init_identity()

    def _init_identity(self) -> None:
        """Initialize or load node identity."""
        key_path = self.config.private_key_path or (self.config.data_dir / "node.key")

        if _RUST_CRYPTO:
            # Use Rust crypto
            if key_path.exists():
                key_hex = key_path.read_text().strip()
                self._keypair = RustKeypair.from_hex(key_hex)
            else:
                self._keypair = RustKeypair.generate()
                key_path.parent.mkdir(parents=True, exist_ok=True)
                key_path.write_text(self._keypair.to_hex())
            
            pub_hex = self._keypair.public_key().to_hex()
            self._peer_id = self.config.node_id or f"cnp_{pub_hex[:16]}"
        else:
            # Fall back to nacl
            if key_path.exists():
                with open(key_path, "rb") as f:
                    key_bytes = bytes.fromhex(f.read().decode())
                    self._keypair = SigningKey(key_bytes)
            else:
                self._keypair = SigningKey.generate()
                key_path.parent.mkdir(parents=True, exist_ok=True)
                with open(key_path, "wb") as f:
                    f.write(self._keypair.encode(encoder=HexEncoder))
            
            pub_hex = self._keypair.verify_key.encode(encoder=HexEncoder).decode()
            self._peer_id = self.config.node_id or f"cnp_{pub_hex[:16]}"

    @property
    def peer_id(self) -> str:
        """Get this node's peer ID."""
        return self._peer_id

    @property
    def public_key_hex(self) -> str:
        """Get this node's public key as hex string."""
        if self._keypair is None:
            return ""
        if _RUST_CRYPTO:
            return self._keypair.public_key().to_hex()
        else:
            return self._keypair.verify_key.encode(encoder=HexEncoder).decode()

    async def start(self) -> None:
        """Start the node."""
        if self._running:
            return

        logger.info(f"Starting CNP node: {self._peer_id}")
        self._running = True
        self._start_time = asyncio.get_event_loop().time()

        # Create and start libp2p host
        libp2p_config = LibP2PConfig(
            private_key_path=self.config.private_key_path,
            listen_addrs=self.config.listen_addrs,
            enable_mdns=self.config.enable_mdns,
            enable_dht=self.config.enable_dht,
            bootstrap_peers=self.config.bootstrap_peers,
            max_peers=self.config.max_peers,
        )
        self._host = create_host(libp2p_config)
        
        # Set up message handlers
        self._host.on_trail_received(self._handle_trail_from_network)
        self._host.on_query_received(self._handle_query_from_network)
        
        # Start the host
        await self._host.start()

        # Start background tasks
        self._gossip_task = asyncio.create_task(self._gossip_loop())
        self._decay_task = asyncio.create_task(self._decay_loop())
        self._discovery_task = asyncio.create_task(self._discovery_loop())

        logger.info(f"CNP node started: {self._peer_id}")
        if self._host.is_available:
            for addr in self._host.get_listen_addrs():
                logger.info(f"  Listen: {addr}")

    async def stop(self) -> None:
        """Stop the node."""
        if not self._running:
            return

        logger.info("Stopping CNP node...")
        self._running = False

        # Cancel background tasks
        for task in [self._gossip_task, self._decay_task, self._discovery_task]:
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        # Stop libp2p host
        if self._host:
            await self._host.stop()

        logger.info("CNP node stopped")
    
    def _handle_trail_from_network(self, trail_data: dict, sender_id: str) -> None:
        """Handle trail received from libp2p network."""
        try:
            trail = Trail.from_dict(trail_data)
            
            # Verify trail signature if we have sender's key
            # TODO: Implement signature verification
            
            # Store trail
            self.trail_store.insert(trail)
            
            # Update peer stats
            self.peer_store.increment_trails_received(sender_id)
            self._stats.trails_received += 1
            
            # Notify handler
            if self._on_trail_received:
                self._on_trail_received(trail, sender_id)
            
            logger.debug(f"Received trail {trail.id[:8]} from {sender_id}")
        except Exception as e:
            logger.error(f"Error handling network trail: {e}")
    
    def _handle_query_from_network(self, query_data: dict, sender_id: str) -> bytes:
        """Handle query received from libp2p network."""
        try:
            query = TrailQuery.from_dict(query_data)
            trails = self.trail_store.query(query)
            self._stats.queries_received += 1
            return json.dumps([t.to_dict() for t in trails]).encode()
        except Exception as e:
            logger.error(f"Error handling network query: {e}")
            return b"[]"

    # --- Trail Operations ---

    async def publish_trail(self, trail: Trail) -> None:
        """
        Publish a trail to the network.

        Signs the trail and stores locally, then gossips to peers.
        """
        # Set worker ID to our peer ID
        trail.worker_id = self._peer_id

        # Sign the trail
        if self._keypair:
            if _RUST_CRYPTO:
                # Sign with Rust crypto
                trail_json = json.dumps(trail.to_dict(), sort_keys=True)
                sig = self._keypair.sign(trail_json.encode())
                trail.signature = sig.to_hex_prefixed()
            else:
                trail.sign(self._keypair)

        # Store locally
        self.trail_store.insert(trail)

        # Publish to network via libp2p
        if self._host:
            await self._host.publish_trail(trail.to_dict())
        
        self._stats.trails_sent += 1
        logger.info(f"Published trail: {trail.id}")

    def query_trails(self, query: TrailQuery) -> list[Trail]:
        """Query local trail store."""
        return self.trail_store.query(query)

    def find_similar_trails(
        self,
        state_features: Any,
        limit: int = 10,
        min_similarity: float = 0.7,
    ) -> list[tuple[Trail, float]]:
        """Find trails similar to given state features."""
        return self.trail_store.find_similar(state_features, limit, min_similarity)

    def cite_trail(self, trail_id: str, success: bool) -> None:
        """Record that a trail was followed."""
        self.trail_store.cite(trail_id, success, self._peer_id)
        self._stats.trails_sent += 1

    # --- Peer Operations ---

    def get_peers(self) -> list[Peer]:
        """Get list of active peers."""
        return self.peer_store.list_active()

    def get_peer_count(self) -> int:
        """Get count of active peers."""
        counts = self.peer_store.count()
        return counts.get("connected", 0) + counts.get("discovered", 0)

    # --- Event Handlers ---

    def on_trail_received(self, handler: Callable[[Trail, str], None]) -> None:
        """Set handler for received trails."""
        self._on_trail_received = handler

    def on_peer_connected(self, handler: Callable[[Peer], None]) -> None:
        """Set handler for peer connections."""
        self._on_peer_connected = handler

    def on_peer_disconnected(self, handler: Callable[[str], None]) -> None:
        """Set handler for peer disconnections."""
        self._on_peer_disconnected = handler

    # --- Stats ---

    def stats(self) -> NodeStats:
        """Get node statistics."""
        self._stats.peer_count = self.get_peer_count()
        self._stats.trail_count = self.trail_store.count()
        if self._start_time:
            self._stats.uptime_secs = int(asyncio.get_event_loop().time() - self._start_time)
        return self._stats

    # --- Internal Loops ---

    async def _gossip_loop(self) -> None:
        """Background loop for trail gossip."""
        while self._running:
            try:
                await asyncio.sleep(self.config.gossip_interval_secs)
                await self._gossip_trails()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Gossip error: {e}")

    async def _gossip_trails(self) -> None:
        """Gossip recent trails to peers."""
        # Get recent high-strength trails
        query = TrailQuery(
            min_strength=0.5,
            limit=self.config.max_trails_per_gossip,
        )
        trails = self.trail_store.query(query)

        if not trails:
            return

        # Publish each trail via libp2p pubsub
        if self._host:
            for trail in trails:
                try:
                    await self._host.publish_trail(trail.to_dict())
                    self._stats.trails_sent += 1
                except Exception as e:
                    logger.warning(f"Failed to gossip trail {trail.id[:8]}: {e}")
        else:
            logger.debug(f"Would gossip {len(trails)} trails")

    async def _decay_loop(self) -> None:
        """Background loop for trail decay."""
        while self._running:
            try:
                await asyncio.sleep(self.config.decay_interval_secs)
                updated = self.trail_store.decay_all(self.config.trail_decay_rate)
                if updated > 0:
                    logger.debug(f"Decayed {updated} trails")

                # Prune very weak trails
                pruned = self.trail_store.prune(min_strength=0.01)
                if pruned > 0:
                    logger.info(f"Pruned {pruned} weak trails")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Decay error: {e}")

    async def _discovery_loop(self) -> None:
        """Background loop for peer discovery."""
        while self._running:
            try:
                await asyncio.sleep(self.config.mdns_interval_secs)
                await self._discover_peers()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Discovery error: {e}")

    async def _discover_peers(self) -> None:
        """Discover peers via mDNS/DHT."""
        if not self._host:
            return
        
        # Get connected peers from libp2p
        connected = self._host.get_connected_peers()
        
        # Update peer store with connected peers
        for peer_id in connected:
            peer = self.peer_store.get(peer_id)
            if not peer:
                # Add new peer
                from cyntra.trust.network.store.peers import Peer, PeerStatus
                peer = Peer(
                    peer_id=peer_id,
                    status=PeerStatus.CONNECTED,
                )
                self.peer_store.upsert(peer)
        
        self._stats.peer_count = len(connected)
        
        # Try bootstrap peers if we have few connections
        if len(connected) < 3:
            for addr in self.config.bootstrap_peers:
                if addr not in connected:
                    try:
                        await self._connect_to_peer(addr)
                    except Exception as e:
                        logger.debug(f"Failed to connect to {addr}: {e}")

    async def _connect_to_peer(self, multiaddr: str) -> None:
        """Connect to a peer by multiaddr."""
        if self._host and self._host.is_available:
            # Real libp2p connection happens in host
            logger.debug(f"Connecting to peer: {multiaddr}")
        else:
            logger.debug(f"Would connect to peer: {multiaddr}")

    # --- Message Handlers ---

    async def _handle_trail_message(self, data: bytes, sender_id: str) -> None:
        """Handle incoming trail message."""
        try:
            trail_dict = json.loads(data)
            # TODO: Deserialize and validate trail
            # trail = Trail.from_dict(trail_dict)

            # Verify signature
            # if not trail.verify(sender_verify_key):
            #     logger.warning(f"Invalid trail signature from {sender_id}")
            #     return

            # Store trail
            # self.trail_store.insert(trail)

            # Update peer stats
            self.peer_store.increment_trails_received(sender_id)
            self._stats.trails_received += 1

            # Notify handler
            # if self._on_trail_received:
            #     self._on_trail_received(trail, sender_id)

            logger.debug(f"Received trail from {sender_id}")
        except Exception as e:
            logger.error(f"Error handling trail message: {e}")

    async def _handle_query_message(self, data: bytes, sender_id: str) -> bytes:
        """Handle incoming trail query."""
        try:
            query_dict = json.loads(data)
            # TODO: Deserialize query
            # query = TrailQuery.from_dict(query_dict)

            # Execute query
            # trails = self.trail_store.query(query)

            # Return results
            # return json.dumps([t.to_dict() for t in trails]).encode()

            self._stats.queries_received += 1
            return b"[]"
        except Exception as e:
            logger.error(f"Error handling query: {e}")
            return b"[]"


async def create_node(config: Optional[NodeConfig] = None) -> CNPNode:
    """Create and start a CNP node."""
    config = config or NodeConfig()
    node = CNPNode(config)
    await node.start()
    return node
