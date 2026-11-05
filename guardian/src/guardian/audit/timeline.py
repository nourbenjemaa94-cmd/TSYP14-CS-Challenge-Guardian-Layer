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
    """Returns current UTC timestamp formatted in ISO 8601 with a ``Z`` suffix."""
    # TODO(guardian-integration): jury logs expect Z, not +00:00.
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class TimelineManager:
    """
    Manages WebSocket subscriptions and broadcasts causal audit events.
    The replay buffer is in memory only and is not a durable audit trail.
    """

    _PUBLIC_FIELDS = frozenset({
        "timestamp", "event_id", "layer", "stage", "status", "verdict", "reason",
        "action", "anomaly_flags", "sensor_id", "metric", "value", "unit",
        "destination", "details", "forward_status", "kind", "containment_status",
        "isolation_confirmed",
    })
    _PUBLIC_RAW_FIELDS = frozenset({
        "event_id", "sensor_id", "metric", "value", "unit", "timestamp", "type", "zone_id",
    })

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
        public_event = self._public_event(event)
        if "timestamp" not in public_event:
            public_event["timestamp"] = get_utc_now()

        # Append to circular buffer
        self.event_buffer.append(public_event)
        if len(self.event_buffer) > self.max_buffer_size:
            self.event_buffer.pop(0)

        # Broadcast to active WebSockets
        dead_connections = set()
        for connection in list(self.active_connections):
            try:
                # Support both FastAPI WebSocket and synchronous/asynchronous test mocks
                if hasattr(connection, "send_json"):
                    res = connection.send_json(public_event)
                    if hasattr(res, "__await__"):
                        await res
                elif hasattr(connection, "send_text"):
                    res = connection.send_text(json.dumps(public_event))
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
        """Clears active connections and the in-memory event buffer."""
        self.active_connections.clear()
        self.event_buffer.clear()

    @classmethod
    def _public_event(cls, event: dict[str, Any]) -> dict[str, Any]:
        """Whitelist fields before an event reaches a WebSocket client."""
        public: dict[str, Any] = {
            key: value for key, value in event.items() if key in cls._PUBLIC_FIELDS
        }
        raw_input = event.get("raw_input")
        if isinstance(raw_input, dict):
            filtered = {
                key: value for key, value in raw_input.items() if key in cls._PUBLIC_RAW_FIELDS
            }
            if filtered:
                public["raw_input"] = filtered
        if isinstance(public.get("anomaly_flags"), (list, tuple)):
            public["anomaly_flags"] = [str(flag) for flag in public["anomaly_flags"]]
        return public


# Global singleton instance for Guardian runtime and tests
timeline_manager = TimelineManager()
