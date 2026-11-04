# TODO(security): ASSUMPTION — signed MQTT topics are delivered by
# guardian.adapters.communication.mqtt.MqttIngress. This class remains the
# generic subscriber owned by the communications work.

import logging
import ssl
from typing import Any

import paho.mqtt.client as mqtt

from .base import HandlerResult, IncomingMessage, MessageHandler

logger = logging.getLogger(__name__)


class MqttAdapter:
    """Paho subscriber with explicit local-queue acknowledgement semantics.

    Paho acknowledges QoS 1/2 after ``on_message`` returns. Guardian cannot
    NACK from this callback, so ``QUEUED`` means only local queue acceptance,
    never successful Core processing.
    """

    ACK_POLICY = "Paho ACK after callback: QUEUED means local queue acceptance, not Core completion"

    def __init__(
    self,
    handler: MessageHandler,
    *,
    host: str,
    port: int = 8883,
    subscribe_topic: str = "twin/events",
    client_id: str = "guardian",
    qos: int = 1,
    max_payload_bytes: int = 65536,
    client: Any | None = None,
    tls_enabled: bool = True,
    ca_cert: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,):
    # 1. Validation des paramètres
        if not host:
            raise ValueError("host must not be empty")

        if not 1 <= port <= 65535:
            raise ValueError("Invalid MQTT port")

        if qos not in (0, 1, 2):
            raise ValueError("qos must be 0, 1 or 2")

        if not subscribe_topic:
            raise ValueError("subscribe_topic must not be empty")

        if max_payload_bytes <= 0:
            raise ValueError("max_payload_bytes must be positive")

        if bool(client_cert) != bool(client_key):
            raise ValueError(
                "client_cert and client_key must be provided together"
            )

        if not tls_enabled and (ca_cert or client_cert or client_key):
            raise ValueError(
                "TLS certificates provided while TLS is disabled"
            )

        # 2. Configuration générale
        self.handler = handler
        self.host = host
        self.port = port
        self.subscribe_topic = subscribe_topic
        self.qos = qos
        self.max_payload_bytes = max_payload_bytes
        self._running = False
        self._connected = False
        self._subscribed = False
        self._pending_subscribe_mid: int | None = None

        # 3. Création du client MQTT
        self.client = (
            client if client is not None
            else mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id=client_id
            )
        )

        # 4. Configuration TLS
        if tls_enabled:
            context = ssl.create_default_context(
                purpose=ssl.Purpose.SERVER_AUTH,
                cafile=ca_cert
            )

            context.minimum_version = ssl.TLSVersion.TLSv1_2

            if client_cert and client_key:
                context.load_cert_chain(
                    certfile=client_cert,
                    keyfile=client_key
                )

            self.client.tls_set_context(context)

        # 5. Association des callbacks
        self.client.on_connect = self._on_connect
        self.client.on_subscribe = self._on_subscribe
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message

    def _on_connect(
        self, client, userdata, flags, reason_code, properties
    ):
        if reason_code != 0:
            self._connected = False
            self._subscribed = False
            logger.error(
                "MQTT connection refused: %s", reason_code
            )
            return

        self._connected = True
        self._subscribed = False

        result, _message_id = client.subscribe(
            self.subscribe_topic,
            qos=self.qos
        )

        if result != mqtt.MQTT_ERR_SUCCESS:
            self._pending_subscribe_mid = None
            logger.error(
                "MQTT subscription failed: %s", result
            )
            return
        self._pending_subscribe_mid = _message_id

    def _on_subscribe(self, client, userdata, mid, reason_code_list, properties):
        """Mark readiness only after Paho has delivered a valid SUBACK."""
        del client, userdata, properties
        if mid != self._pending_subscribe_mid:
            logger.warning("Ignoring SUBACK for unknown subscription id %s", mid)
            return
        self._pending_subscribe_mid = None
        reason_codes = list(reason_code_list or [])
        if not reason_codes:
            logger.error("MQTT subscription returned no granted QoS")
            self._subscribed = False
            return

        granted_qos: list[int] = []
        for reason_code in reason_codes:
            value = int(getattr(reason_code, "value", reason_code))
            if bool(getattr(reason_code, "is_failure", value >= 0x80)):
                logger.error("MQTT subscription refused with reason code %s", reason_code)
                self._subscribed = False
                return
            granted_qos.append(value)
        if any(value not in (0, 1, 2) or value > self.qos for value in granted_qos):
            logger.error("MQTT broker granted invalid QoS values: %s", granted_qos)
            self._subscribed = False
            return
        self._subscribed = True

    def _on_disconnect(self, client, userdata, disconnect_flags=None, reason_code=0, properties=None):
        """Revoke readiness immediately when the broker connection drops."""
        self._connected = False
        self._subscribed = False
        self._pending_subscribe_mid = None
        if reason_code not in (0, None):
            logger.warning("MQTT broker disconnected: %s", reason_code)

    def _on_message(self, client, userdata, msg):
        try:
            topic_matches = mqtt.topic_matches_sub(self.subscribe_topic, msg.topic)
        except (AttributeError, TypeError, ValueError):
            topic_matches = msg.topic == self.subscribe_topic
        if not topic_matches:
            logger.warning("Ignoring MQTT message on unexpected topic %s", msg.topic)
            return
        if len(msg.payload) > self.max_payload_bytes:
            logger.warning(
                "Oversized MQTT message on %s", msg.topic
            )
            return

        message = IncomingMessage(
            payload=bytes(msg.payload),
            transport="mqtt",
            metadata={
                "topic": msg.topic,
                "qos": msg.qos,
                "retain": msg.retain
            }
        )

        try:
            result = self.handler(message)

            if not isinstance(result, HandlerResult):
                logger.error("Invalid MQTT handler response")
            elif result.accepted and result.code == "QUEUED":
                logger.debug(
                    "MQTT QoS %s message queued; Paho acknowledgement does not mean pipeline completion",
                    msg.qos,
                )
            elif not result.accepted:
                logger.warning(
                    "MQTT message rejected after callback admission: %s; Paho will not retry this delivery",
                    result.code,
                )

        except Exception:
            logger.exception("MQTT processing failed")

    def publish(
        self,
        topic: str,
        payload: bytes,
        *,
        qos: int | None = None
    ):
        selected_qos = self.qos if qos is None else qos

        if selected_qos not in (0, 1, 2):
            raise ValueError("qos must be 0, 1 or 2")
        if not topic:
            raise ValueError("topic must not be empty")
        if len(payload) > self.max_payload_bytes:
            raise ValueError("Payload too large")

        result = self.client.publish(
            topic,
            payload=payload,
            qos=selected_qos
        )

        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(
                f"MQTT publish failed: {result.rc}"
            )

    def start(self):
        if self._running:
            return

        self.client.connect(self.host, self.port)

        try:
            self.client.loop_start()
        except Exception:
            self.client.disconnect()
            raise

        self._running = True

    def stop(self):
        if not self._running:
            return

        try:
            self.client.disconnect()
        finally:
            self.client.loop_stop()
            self._connected = False
            self._subscribed = False
            self._pending_subscribe_mid = None
            self._running = False

    @property
    def connected(self) -> bool:
        """Whether the latest broker callback confirmed a live connection."""
        return self._connected

    @property
    def subscribed(self) -> bool:
        """Whether the required topic subscription was acknowledged by Paho."""
        return self._subscribed
