"""MQTT subscriber for the Twin stream.

Topic names come from configuration. A rejection is logged and audited by the
pipeline; it must not stop the subscriber. MQTT has no reply channel.

TODO(security): ASSUMPTION — REST is the primary transport. This subscriber is
used when the Twin publishes the sensor stream over MQTT. Phase 1 does not
open TLS; that gap is recorded under known limitations.
"""

import logging
from typing import Any

from guardian.config import TopicSpec
from guardian.orchestration.pipeline import Pipeline
from guardian.security.errors import SecurityRejection

_LOG = logging.getLogger("guardian.security")


class MqttIngress:
    """Feeds raw MQTT payloads into the same pipeline the REST routes use."""

    def __init__(
        self,
        pipeline: Pipeline,
        topics: list[TopicSpec] | tuple[TopicSpec, ...],
        *,
        client: Any | None = None,
        host: str,
        port: int,
        username: str = "",
        password: str = "",
        client_id: str = "guardian",
    ) -> None:
        self.pipeline = pipeline
        self.topics = tuple(topics)
        self.client = client
        self.host = host
        self.port = port
        self._username = username
        self._password = password
        self._client_id = client_id
        self._running = False

    def operation_for(self, topic: str) -> str | None:
        for route in self.topics:
            if route.direction != "inbound":
                continue
            if topic_matches(route.topic, topic):
                return route.operation
        return None

    def handle_message(self, topic: str, payload: bytes) -> None:
        """Process one payload. Exceptions are contained inside this method."""
        operation = self.operation_for(topic)
        if operation is None:
            _LOG.warning("stage=security.mqtt outcome=ignored reason=unknown_topic topic=%s", topic)
            return
        try:
            self.pipeline.process_inbound(payload, operation)
        except SecurityRejection as exc:
            _LOG.warning(
                "stage=security.mqtt outcome=rejected code=%s event_id=%s operation=%s topic=%s",
                exc.code.value,
                exc.event_id,
                operation,
                topic,
            )
        except Exception:
            _LOG.exception("stage=security.mqtt outcome=error operation=%s topic=%s", operation, topic)

    def start(self) -> None:
        if self._running:
            return
        if self.client is None:
            self.client = _build_paho_client(self._client_id)
        client = self.client
        if self._username and hasattr(client, "username_pw_set"):
            client.username_pw_set(self._username, self._password)
        client.on_message = self._on_message
        client.connect(self.host, self.port)
        for route in self.topics:
            if route.direction != "inbound":
                continue
            client.subscribe(subscription_filter(route.topic), 1)
        if hasattr(client, "loop_start"):
            client.loop_start()
        self._running = True

    def stop(self) -> None:
        client = self.client
        if client is None or not self._running:
            return
        try:
            if hasattr(client, "disconnect"):
                client.disconnect()
        finally:
            if hasattr(client, "loop_stop"):
                client.loop_stop()
            self._running = False

    def _on_message(self, _client: object, _userdata: object, message: object) -> None:
        topic = str(getattr(message, "topic", ""))
        payload = getattr(message, "payload", b"")
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        if not isinstance(payload, (bytes, bytearray)):
            _LOG.warning("stage=security.mqtt outcome=ignored reason=payload_type topic=%s", topic)
            return
        self.handle_message(topic, bytes(payload))


def topic_matches(pattern: str, topic: str) -> bool:
    """Match a configured pattern. ``{name}`` is one non-empty topic segment."""
    pattern_parts = pattern.split("/")
    topic_parts = topic.split("/")
    if len(pattern_parts) != len(topic_parts):
        return False
    for expected, actual in zip(pattern_parts, topic_parts, strict=True):
        if expected.startswith("{") and expected.endswith("}"):
            if actual == "":
                return False
            continue
        if expected != actual:
            return False
    return True


def subscription_filter(pattern: str) -> str:
    """Turn ``{device_id}`` into the MQTT single-level wildcard."""
    parts = ["+" if part.startswith("{") and part.endswith("}") else part for part in pattern.split("/")]
    return "/".join(parts)


def _build_paho_client(client_id: str) -> Any:
    import paho.mqtt.client as mqtt

    return mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=client_id,
    )
