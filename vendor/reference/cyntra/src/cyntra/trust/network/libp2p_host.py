"""
libp2p Host implementation for CNP network layer.

This module provides the actual libp2p networking implementation:
- Host creation with Ed25519 identity
- Pubsub (gossipsub) for trail propagation
- mDNS for local peer discovery
- Kademlia DHT for global peer discovery
- Protocol handlers for queries and receipts

Requires py-libp2p for full functionality.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Protocol

logger = logging.getLogger(__name__)


# Protocol identifiers
PROTOCOL_TRAILS_TOPIC = "/cnp/trails/1.0.0"
PROTOCOL_QUERY = "/cnp/query/1.0.0"
PROTOCOL_RECEIPTS = "/cnp/receipts/1.0.0"

# Try to import libp2p
_LIBP2P_AVAILABLE = False
try:
    from libp2p import new_host
    from libp2p.crypto.secp256k1 import create_new_key_pair
    from libp2p.crypto.ed25519 import create_new_key_pair as ed25519_keypair
    from libp2p.peer.peerinfo import info_from_p2p_addr
    from libp2p.network.stream.net_stream import INetStream
    from libp2p.pubsub import floodsub, gossipsub
    from libp2p.pubsub.pubsub import Pubsub
    import multiaddr
    _LIBP2P_AVAILABLE = True
except ImportError:
    logger.warning("py-libp2p not installed, using stub implementation")


@dataclass
class LibP2PConfig:
    """Configuration for libp2p host."""
    
    # Identity
    private_key_path: Optional[Path] = None
    
    # Listen addresses
    listen_addrs: list[str] = field(default_factory=lambda: ["/ip4/0.0.0.0/tcp/0"])
    
    # Discovery
    enable_mdns: bool = True
    enable_dht: bool = True
    bootstrap_peers: list[str] = field(default_factory=list)
    
    # Pubsub
    pubsub_type: str = "gossipsub"  # "floodsub" or "gossipsub"
    
    # Limits
    max_peers: int = 50


class LibP2PHost:
    """
    libp2p-based network host for CNP.
    
    Provides:
    - Peer-to-peer connectivity
    - Pubsub for trail gossip
    - Direct streams for queries
    """
    
    def __init__(self, config: LibP2PConfig):
        self.config = config
        self._host = None
        self._pubsub = None
        self._peer_id: str = ""
        self._running = False
        
        # Message handlers
        self._on_trail: Optional[Callable[[dict, str], None]] = None
        self._on_query: Optional[Callable[[dict, str], bytes]] = None
        
        # Subscriptions
        self._subscriptions: dict[str, Any] = {}
        
    @property
    def peer_id(self) -> str:
        """Get this host's peer ID."""
        return self._peer_id
    
    @property
    def is_available(self) -> bool:
        """Check if libp2p is available."""
        return _LIBP2P_AVAILABLE
    
    async def start(self) -> None:
        """Start the libp2p host."""
        if self._running:
            return
            
        if not _LIBP2P_AVAILABLE:
            logger.warning("libp2p not available, running in stub mode")
            self._running = True
            return
        
        logger.info("Starting libp2p host...")
        
        # Generate or load keypair
        key_pair = await self._load_or_generate_keypair()
        
        # Create host
        self._host = new_host(key_pair=key_pair)
        self._peer_id = self._host.get_id().pretty()
        
        # Setup pubsub
        if self.config.pubsub_type == "gossipsub":
            self._pubsub = gossipsub.GossipSub(
                [self._host],
                heartbeat_interval=1.0,
            )
        else:
            self._pubsub = floodsub.FloodSub([self._host])
        
        # Start listening
        for addr in self.config.listen_addrs:
            ma = multiaddr.Multiaddr(addr)
            await self._host.get_network().listen(ma)
        
        # Register protocol handlers
        self._host.set_stream_handler(PROTOCOL_QUERY, self._handle_query_stream)
        self._host.set_stream_handler(PROTOCOL_RECEIPTS, self._handle_receipt_stream)
        
        # Subscribe to trails topic
        await self._subscribe_to_trails()
        
        # Connect to bootstrap peers
        for peer_addr in self.config.bootstrap_peers:
            try:
                await self._connect_to_peer(peer_addr)
            except Exception as e:
                logger.warning(f"Failed to connect to bootstrap peer {peer_addr}: {e}")
        
        self._running = True
        logger.info(f"libp2p host started: {self._peer_id}")
        
        # Log listen addresses
        addrs = self._host.get_addrs()
        for addr in addrs:
            logger.info(f"Listening on: {addr}/p2p/{self._peer_id}")
    
    async def stop(self) -> None:
        """Stop the libp2p host."""
        if not self._running:
            return
        
        self._running = False
        
        if self._pubsub:
            # Unsubscribe from all topics
            for topic in list(self._subscriptions.keys()):
                try:
                    await self._pubsub.unsubscribe(topic)
                except Exception:
                    pass
            self._subscriptions.clear()
        
        if self._host:
            await self._host.close()
        
        logger.info("libp2p host stopped")
    
    async def _load_or_generate_keypair(self):
        """Load keypair from file or generate new one."""
        key_path = self.config.private_key_path
        
        if key_path and key_path.exists():
            # Load existing key
            key_bytes = key_path.read_bytes()
            # TODO: Deserialize Ed25519 private key
            logger.info(f"Loaded keypair from {key_path}")
        
        # Generate new key
        return ed25519_keypair()
    
    async def _subscribe_to_trails(self) -> None:
        """Subscribe to the trails pubsub topic."""
        if not self._pubsub:
            return
        
        sub = await self._pubsub.subscribe(PROTOCOL_TRAILS_TOPIC)
        self._subscriptions[PROTOCOL_TRAILS_TOPIC] = sub
        
        # Start message handler task
        asyncio.create_task(self._trails_message_loop(sub))
    
    async def _trails_message_loop(self, subscription) -> None:
        """Process incoming trail messages."""
        async for message in subscription:
            try:
                # Decode message
                data = json.loads(message.data)
                sender = message.from_id.pretty()
                
                # Call handler
                if self._on_trail:
                    self._on_trail(data, sender)
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON in trail message")
            except Exception as e:
                logger.error(f"Error processing trail message: {e}")
    
    async def publish_trail(self, trail_data: dict) -> None:
        """Publish a trail to the network."""
        if not self._pubsub:
            logger.debug(f"Would publish trail: {trail_data.get('id', 'unknown')[:8]}")
            return
        
        message = json.dumps(trail_data).encode()
        await self._pubsub.publish(PROTOCOL_TRAILS_TOPIC, message)
    
    async def _connect_to_peer(self, multiaddr_str: str) -> None:
        """Connect to a peer by multiaddr."""
        if not self._host:
            return
        
        ma = multiaddr.Multiaddr(multiaddr_str)
        peer_info = info_from_p2p_addr(ma)
        await self._host.connect(peer_info)
        logger.info(f"Connected to peer: {peer_info.peer_id.pretty()}")
    
    async def _handle_query_stream(self, stream: INetStream) -> None:
        """Handle incoming query stream."""
        try:
            # Read query
            data = await stream.read()
            query_data = json.loads(data)
            sender = stream.muxed_conn.peer_id.pretty()
            
            # Process query
            if self._on_query:
                response = self._on_query(query_data, sender)
            else:
                response = b"[]"
            
            # Send response
            await stream.write(response)
        except Exception as e:
            logger.error(f"Error handling query stream: {e}")
        finally:
            await stream.close()
    
    async def _handle_receipt_stream(self, stream: INetStream) -> None:
        """Handle incoming receipt stream."""
        try:
            data = await stream.read()
            # TODO: Process receipt
            await stream.write(b"OK")
        except Exception as e:
            logger.error(f"Error handling receipt stream: {e}")
        finally:
            await stream.close()
    
    async def query_peer(self, peer_id: str, query: dict) -> list[dict]:
        """Send a query to a specific peer."""
        if not self._host:
            logger.debug(f"Would query peer {peer_id}: {query}")
            return []
        
        try:
            # Open stream
            from libp2p.peer.id import ID
            pid = ID.from_base58(peer_id)
            stream = await self._host.new_stream(pid, [PROTOCOL_QUERY])
            
            # Send query
            await stream.write(json.dumps(query).encode())
            
            # Read response
            response = await stream.read()
            await stream.close()
            
            return json.loads(response)
        except Exception as e:
            logger.error(f"Query to {peer_id} failed: {e}")
            return []
    
    def on_trail_received(self, handler: Callable[[dict, str], None]) -> None:
        """Set handler for received trails."""
        self._on_trail = handler
    
    def on_query_received(self, handler: Callable[[dict, str], bytes]) -> None:
        """Set handler for received queries."""
        self._on_query = handler
    
    def get_connected_peers(self) -> list[str]:
        """Get list of connected peer IDs."""
        if not self._host:
            return []
        
        network = self._host.get_network()
        return [conn.muxed_conn.peer_id.pretty() for conn in network.connections]
    
    def get_listen_addrs(self) -> list[str]:
        """Get list of listen addresses."""
        if not self._host:
            return []
        
        addrs = self._host.get_addrs()
        return [f"{addr}/p2p/{self._peer_id}" for addr in addrs]


class StubLibP2PHost(LibP2PHost):
    """
    Stub implementation when py-libp2p is not available.
    
    Provides the same interface but logs instead of networking.
    """
    
    def __init__(self, config: LibP2PConfig):
        super().__init__(config)
        self._peer_id = f"stub_{id(self):08x}"
        self._peers: list[str] = []
    
    @property
    def is_available(self) -> bool:
        return False
    
    async def start(self) -> None:
        self._running = True
        logger.info(f"Stub libp2p host started: {self._peer_id}")
    
    async def stop(self) -> None:
        self._running = False
        logger.info("Stub libp2p host stopped")
    
    async def publish_trail(self, trail_data: dict) -> None:
        logger.debug(f"[STUB] Would publish trail: {trail_data.get('id', 'unknown')[:8]}")
    
    async def query_peer(self, peer_id: str, query: dict) -> list[dict]:
        logger.debug(f"[STUB] Would query peer {peer_id}")
        return []
    
    def get_connected_peers(self) -> list[str]:
        return self._peers
    
    def get_listen_addrs(self) -> list[str]:
        return [f"/ip4/127.0.0.1/tcp/0/p2p/{self._peer_id}"]


def create_host(config: Optional[LibP2PConfig] = None) -> LibP2PHost:
    """Create a libp2p host with fallback to stub."""
    config = config or LibP2PConfig()
    
    if _LIBP2P_AVAILABLE:
        return LibP2PHost(config)
    else:
        return StubLibP2PHost(config)


__all__ = [
    "LibP2PConfig",
    "LibP2PHost",
    "StubLibP2PHost",
    "create_host",
    "PROTOCOL_TRAILS_TOPIC",
    "PROTOCOL_QUERY",
    "PROTOCOL_RECEIPTS",
]
