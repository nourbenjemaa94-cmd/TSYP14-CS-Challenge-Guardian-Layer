"""
audit/timeline.py
-----------------
Manages real-time causal timeline broadcasting for Requirement R3.
Enables judges and monitoring dashboards to observe:
Reading Received -> Guardian Verdict -> Containment Action (Isolated / Forwarded to Brain).
"""

import json
import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("guardian.timeline")


def get_utc_now() -> str:
    """Returns current UTC timestamp formatted in ISO 8601 with timezone indicator."""
    return datetime.now(UTC).isoformat()


class TimelineManager:
    """
    Manages WebSocket subscriptions and broadcasts causal audit events.
    Supports in-memory buffer for history inspection and replay.
    """

    def __init__(self, max_buffer_size: int = 500):
        self.active_connections: set[Any] = set()
        self.event_buffer: list[dict[str, Any]] = []
        self.max_buffer_size = max_buffer_size

    async def connect(self, websocket: Any):
        """Accepts and registers an incoming WebSocket connection."""
        if hasattr(websocket, "accept"):
            res = websocket.accept()
            if hasattr(res, "__await__"):
                await res
        self.active_connections.add(websocket)
        logger.info(f"[TIMELINE] Client connected. Active clients: {len(self.active_connections)}")

    def disconnect(self, websocket: Any):
        """Removes a disconnected WebSocket client."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"[TIMELINE] Client disconnected. Active clients: {len(self.active_connections)}")

    async def broadcast(self, event: dict[str, Any]):
        """
        Broadcasts an audit event payload to all connected WebSocket clients.
        Automatically removes stale/disconnected sockets.
        """
        # Ensure UTC timestamp is set
        if "timestamp" not in event:
            event["timestamp"] = get_utc_now()

        # Append to circular buffer
        self.event_buffer.append(event)
        if len(self.event_buffer) > self.max_buffer_size:
            self.event_buffer.pop(0)

        # Broadcast to active WebSockets
        dead_connections = set()
        for connection in list(self.active_connections):
            try:
                # Support both FastAPI WebSocket and synchronous/asynchronous test mocks
                if hasattr(connection, "send_json"):
                    res = connection.send_json(event)
                    if hasattr(res, "__await__"):
                        await res
                elif hasattr(connection, "send_text"):
                    res = connection.send_text(json.dumps(event))
                    if hasattr(res, "__await__"):
                        await res
            except Exception as e:
                logger.warning(f"[TIMELINE] Failed to deliver event to client: {e}")
                dead_connections.add(connection)

        for dead in dead_connections:
            self.disconnect(dead)

    def get_events_for_correlation(self, event_id: str) -> list[dict[str, Any]]:
        """Retrieves all chronological timeline events associated with a specific event_id."""
        return [evt for evt in self.event_buffer if evt.get("event_id") == event_id]

    def clear(self):
        """Clears active connections and event history buffer (useful for test resets)."""
        self.active_connections.clear()
        self.event_buffer.clear()


# Global singleton instance for Guardian runtime and tests
timeline_manager = TimelineManager()
