"""Optional real-broker MQTT/TLS smoke test.

The test is opt-in because CI and local unit-test runs do not necessarily have
Mosquitto available.  It deliberately requires a CA file and never disables
certificate verification.
"""

import os
import time

import pytest

from guardian.adapters.communication.base import HandlerResult
from guardian.adapters.communication.mqtt import MqttAdapter


class _Handler:
    def __call__(self, _message):
        return HandlerResult(True, "QUEUED")


def test_mqtt_tls_connects_to_configured_broker_when_available():
    if os.getenv("GUARDIAN_MQTT_INTEGRATION", "").lower() not in {"1", "true", "yes"}:
        pytest.skip("set GUARDIAN_MQTT_INTEGRATION=1 to run the Mosquitto integration test")

    host = os.getenv("GUARDIAN_MQTT_HOST")
    ca_cert = os.getenv("GUARDIAN_MQTT_TLS_CA")
    if not host or not ca_cert:
        pytest.skip("GUARDIAN_MQTT_HOST and GUARDIAN_MQTT_TLS_CA are required")

    adapter = MqttAdapter(
        _Handler(),
        host=host,
        port=int(os.getenv("GUARDIAN_MQTT_PORT", "8883")),
        subscribe_topic=os.getenv("GUARDIAN_MQTT_TOPIC", "twin/events"),
        ca_cert=ca_cert,
        client_cert=os.getenv("GUARDIAN_MQTT_CLIENT_CERT"),
        client_key=os.getenv("GUARDIAN_MQTT_CLIENT_KEY"),
        tls_enabled=True,
    )
    try:
        adapter.start()
        deadline = time.monotonic() + float(os.getenv("GUARDIAN_MQTT_CONNECT_TIMEOUT", "5"))
        while (not adapter.connected or not adapter.subscribed) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert adapter.connected, "MQTT broker did not confirm a TLS connection"
        assert adapter.subscribed, "MQTT broker did not confirm the TLS subscription"
    finally:
        adapter.stop()

