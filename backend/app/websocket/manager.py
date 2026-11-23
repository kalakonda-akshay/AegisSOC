"""
AegisSOC WebSocket Connection & Subscription Manager
Handles WebSocket authentication, connection lifecycle, channel dispatching,
and ring-buffer replay for seamless client reconnections.
"""

from collections import deque
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional, Set
from fastapi import WebSocket
import jwt

from app.core.config import settings
from app.core.logging import logger


class ConnectionManager:
    """Enterprise WebSocket Connection and Broadcast Hub."""

    def __init__(self, max_event_buffer: int = 100):
        self.channels: Dict[str, Set[WebSocket]] = {
            "traffic": set(),
            "events": set(),
            "health": set(),
            "ai": set(),
            "monitoring": set(),
            "general": set()
        }
        # Reconnection event buffer: deque of (event_seq_id, timestamp, event_dict)
        self.max_event_buffer = max_event_buffer
        self.event_buffer: deque = deque(maxlen=max_event_buffer)
        self._seq_counter = 0

    def authenticate(self, websocket: WebSocket) -> Optional[Dict[str, Any]]:
        """
        Validates JWT authentication credentials from query parameters or headers.
        Returns the decoded user claims if valid, or None for anonymous/unauthenticated.
        """
        token = websocket.query_params.get("token")
        if not token:
            auth_header = websocket.headers.get("authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return None

        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM]
            )
            return payload
        except Exception as e:
            logger.debug(f"WebSocket auth token rejected: {e}")
            return None

    async def connect(self, websocket: WebSocket, channel: str = "general") -> bool:
        """Accepts and registers an incoming WebSocket client on the designated channel."""
        try:
            await websocket.accept()
            if channel not in self.channels:
                self.channels[channel] = set()
            self.channels[channel].add(websocket)
            logger.debug(f"Client connected to channel '{channel}'. Active: {len(self.channels[channel])}")
            return True
        except Exception as e:
            logger.warning(f"Error accepting WebSocket connection: {e}")
            return False

    def disconnect(self, websocket: WebSocket, channel: str = "general"):
        """Removes a client from a channel upon disconnect."""
        if channel in self.channels and websocket in self.channels[channel]:
            self.channels[channel].remove(websocket)
            logger.debug(f"Client disconnected from '{channel}'. Remaining: {len(self.channels[channel])}")

    def buffer_event(self, event_data: dict) -> int:
        """Adds an event to the ring buffer and returns its monotonic sequence ID."""
        self._seq_counter += 1
        seq_id = self._seq_counter
        item = {
            "seq_id": seq_id,
            "buffered_at": datetime.now(timezone.utc).isoformat(),
            "payload": event_data
        }
        self.event_buffer.append(item)
        return seq_id

    def get_missed_events(self, since_seq_id: int) -> List[dict]:
        """Returns buffered events with sequence IDs greater than since_seq_id."""
        return [
            item["payload"] for item in self.event_buffer
            if item["seq_id"] > since_seq_id
        ]

    async def broadcast_to_channel(self, message: dict, channel: str):
        """Dispatches payload to all active clients on a channel."""
        if channel not in self.channels or not self.channels[channel]:
            return

        dead = set()
        for conn in list(self.channels[channel]):
            try:
                await conn.send_json(message)
            except Exception as e:
                dead.add(conn)

        for d in dead:
            self.disconnect(d, channel)

    def get_stats(self) -> Dict[str, Any]:
        """Returns real-time connection counters across all channels."""
        return {
            "total_active_connections": sum(len(conns) for conns in self.channels.values()),
            "channels": {ch: len(conns) for ch, conns in self.channels.items()},
            "buffered_events_count": len(self.event_buffer),
            "latest_sequence_id": self._seq_counter
        }


ws_manager = ConnectionManager()
