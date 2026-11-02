# TODO(security): ASSUMPTION — signed MQTT topics are delivered by
# guardian.adapters.communication.mqtt.MqttIngress. This class remains the
# generic subscriber owned by the communications work.

import logging
from typing import Any

import paho.mqtt.client as mqtt
import ssl

from .base import IncomingMessage, HandlerResult, MessageHandler

logger = logging.getLogger(__name__)


class MqttAdapter:

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
        self.client.on_message = self._on_message

    def _on_connect(
        self, client, userdata, flags, reason_code, properties
    ):
        if reason_code != 0:
            logger.error(
                "MQTT connection refused: %s", reason_code
            )
            return

        result, _message_id = client.subscribe(
            self.subscribe_topic,
            qos=self.qos
        )

        if result != mqtt.MQTT_ERR_SUCCESS:
            logger.error(
                "MQTT subscription failed: %s", result
            )

    def _on_message(self, client, userdata, msg):
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
            elif not result.accepted:
                logger.warning(
                    "MQTT message rejected: %s", result.code
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
            self._running = False