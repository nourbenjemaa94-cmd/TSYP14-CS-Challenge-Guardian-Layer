import asyncio
import logging
import time

import pytest

import guardian.adapters.communication.mqtt as mqtt_module
from guardian.adapters.communication.base import HandlerResult, IncomingMessage
from guardian.adapters.communication.manager import AdapterManager, AsyncPipelineHandler
from guardian.adapters.communication.mqtt import MqttAdapter
from guardian.adapters.communication.registry import AdapterRegistry


class FakeMqttClient:
    def __init__(self):
        self.on_connect = None
        self.on_subscribe = None
        self.on_message = None
        self.calls = []

    def tls_set_context(self, context):
        self.calls.append(("tls", context))

    def connect(self, host, port):
        self.calls.append(("connect", host, port))
        return 0

    def loop_start(self):
        self.calls.append(("loop_start",))

    def loop_stop(self):
        self.calls.append(("loop_stop",))

    def disconnect(self):
        self.calls.append(("disconnect",))

    def subscribe(self, topic, qos):
        self.calls.append(("subscribe", topic, qos))
        return 0, 1


class FakeTlsContext:
    def __init__(self):
        self.minimum_version = None
        self.cert_chain = None

    def load_cert_chain(self, certfile, keyfile):
        self.cert_chain = (certfile, keyfile)


class RecordingHandler:
    def __init__(self):
        self.messages = []

    def __call__(self, message):
        self.messages.append(message)
        return HandlerResult(True, "ACCEPTED")


def test_mqtt_fake_client_subscribes_on_connect_reconnects_and_stops():
    client = FakeMqttClient()
    handler = RecordingHandler()
    adapter = MqttAdapter(
        handler,
        host="mqtt.internal",
        port=8883,
        subscribe_topic="twin/readings",
        client=client,
        tls_enabled=False,
    )

    adapter.start()
    adapter._on_connect(client, None, None, 0, None)
    assert adapter.connected is True
    assert adapter.subscribed is False
    adapter._on_subscribe(client, None, 1, [1], None)
    adapter._on_connect(client, None, None, 0, None)  # reconnect callback
    assert adapter.connected is True
    assert adapter.subscribed is False
    adapter._on_subscribe(client, None, 1, [1], None)
    adapter._on_disconnect(client, None, None, 1, None)
    assert adapter.connected is False
    assert adapter.subscribed is False
    adapter._on_connect(client, None, None, 0, None)
    adapter._on_subscribe(client, None, 1, [1], None)
    message = type("MqttMessage", (), {"payload": b"{}", "topic": "twin/readings", "qos": 1, "retain": False})()
    adapter._on_message(client, None, message)
    adapter.stop()

    assert client.calls[:2] == [("connect", "mqtt.internal", 8883), ("loop_start",)]
    assert [call[0] for call in client.calls].count("subscribe") == 3
    assert handler.messages[0].transport == "mqtt"
    assert ("disconnect",) in client.calls
    assert ("loop_stop",) in client.calls
    assert adapter.connected is False
    assert adapter.subscribed is False


def test_mqtt_subscribe_waits_for_suback_and_rejects_invalid_grants():
    client = FakeMqttClient()
    adapter = MqttAdapter(RecordingHandler(), host="mqtt.internal", client=client, tls_enabled=False)

    adapter._on_connect(client, None, None, 0, None)
    assert adapter.subscribed is False
    pending = adapter._pending_subscribe_mid
    assert pending == 1

    adapter._on_subscribe(client, None, pending, [128], None)
    assert adapter.subscribed is False

    adapter._on_connect(client, None, None, 0, None)
    pending = adapter._pending_subscribe_mid
    adapter._on_subscribe(client, None, pending, [2], None)
    assert adapter.subscribed is False

    adapter._on_connect(client, None, None, 0, None)
    pending = adapter._pending_subscribe_mid
    adapter._on_subscribe(client, None, pending, [1], None)
    assert adapter.subscribed is True


def test_mqtt_tls_is_enabled_by_default(monkeypatch):
    contexts = []

    def create_context(**kwargs):
        contexts.append(kwargs)
        return FakeTlsContext()

    monkeypatch.setattr(mqtt_module.ssl, "create_default_context", create_context)
    client = FakeMqttClient()
    MqttAdapter(RecordingHandler(), host="mqtt.internal", client=client)

    assert contexts[0]["purpose"] is mqtt_module.ssl.Purpose.SERVER_AUTH
    assert contexts[0]["cafile"] is None
    assert any(call[0] == "tls" for call in client.calls)


def test_mqtt_custom_ca_and_mtls_are_passed_to_tls_context(monkeypatch):
    context = FakeTlsContext()
    monkeypatch.setattr(mqtt_module.ssl, "create_default_context", lambda **_kwargs: context)
    client = FakeMqttClient()

    MqttAdapter(
        RecordingHandler(),
        host="mqtt.internal",
        client=client,
        ca_cert="/certs/ca.pem",
        client_cert="/certs/client.pem",
        client_key="/certs/client.key",
    )

    assert context.cert_chain == ("/certs/client.pem", "/certs/client.key")


@pytest.mark.parametrize("kwargs", [{"client_cert": "/cert.pem"}, {"client_key": "/client.key"}])
def test_mqtt_rejects_incomplete_mtls_pair(kwargs):
    with pytest.raises(ValueError, match="provided together"):
        MqttAdapter(RecordingHandler(), host="mqtt.internal", tls_enabled=True, **kwargs)


@pytest.mark.parametrize("qos", [-1, 3])
def test_mqtt_rejects_invalid_qos(qos):
    with pytest.raises(ValueError, match="qos"):
        MqttAdapter(RecordingHandler(), host="mqtt.internal", qos=qos, tls_enabled=False)


def test_mqtt_uses_configured_port_and_rejects_broker_failure():
    client = FakeMqttClient()
    adapter = MqttAdapter(RecordingHandler(), host="mqtt.internal", port=9443, client=client, tls_enabled=False)
    adapter.start()
    assert ("connect", "mqtt.internal", 9443) in client.calls
    adapter.stop()

    class FailingClient(FakeMqttClient):
        def connect(self, host, port):
            raise OSError("broker unavailable")

    failing = MqttAdapter(RecordingHandler(), host="unavailable", client=FailingClient(), tls_enabled=False)
    with pytest.raises(OSError, match="broker unavailable"):
        failing.start()
    assert failing._running is False
    assert failing.connected is False


def test_mqtt_ignores_unknown_topic_and_oversized_payload():
    handler = RecordingHandler()
    adapter = MqttAdapter(handler, host="mqtt.internal", subscribe_topic="known/topic", max_payload_bytes=4,
                          client=FakeMqttClient(), tls_enabled=False)
    unknown = type("MqttMessage", (), {"payload": b"ok", "topic": "unknown/topic", "qos": 1, "retain": False})()
    oversized = type("MqttMessage", (), {"payload": b"12345", "topic": "known/topic", "qos": 1, "retain": False})()

    adapter._on_message(adapter.client, None, unknown)
    adapter._on_message(adapter.client, None, oversized)

    assert handler.messages == []


def test_mqtt_qos_rejection_policy_does_not_claim_pipeline_completion(caplog):
    class RejectingHandler:
        def __call__(self, _message):
            return HandlerResult(False, "SIGNATURE_INVALID", "rejected")

    adapter = MqttAdapter(
        RejectingHandler(),
        host="mqtt.internal",
        subscribe_topic="known/topic",
        client=FakeMqttClient(),
        tls_enabled=False,
    )
    message = type("MqttMessage", (), {"payload": b"{}", "topic": "known/topic", "qos": 1, "retain": False})()

    with caplog.at_level(logging.WARNING):
        adapter._on_message(adapter.client, None, message)

    assert "will not retry" in caplog.text
    assert "Core completion" in adapter.ACK_POLICY


def test_adapter_manager_uses_configured_mqtt_without_broker():
    client = FakeMqttClient()
    handler = RecordingHandler()
    registry = AdapterRegistry()
    registry.register("mqtt", lambda callback, **options: MqttAdapter(callback, client=client, **options))
    manager = AdapterManager(handler, registry=registry)

    manager.configure({"mqtt": {
        "host": "localhost", "port": 9443, "subscribe_topic": "telemetry",
        "tls_enabled": False,
    }})
    manager.start()
    manager.stop()

    assert ("connect", "localhost", 9443) in client.calls
    assert ("disconnect",) in client.calls


@pytest.mark.asyncio
async def test_async_pipeline_handler_does_not_block_mqtt_callback():
    processed = []

    class Pipeline:
        async def process_incoming(self, payload, logger, **kwargs):
            await asyncio.sleep(0.01)
            processed.append(payload)
            return {"status": "ACCEPTED"}

    handler = AsyncPipelineHandler(Pipeline(), None, max_queue_size=2, workers=1)
    await handler.start()
    message = IncomingMessage(b"payload", "mqtt")

    started = time.perf_counter()
    # The adapter callback itself is synchronous; invoking it on the loop
    # avoids measuring the unrelated startup cost of asyncio.to_thread.
    result = handler(message)
    elapsed = time.perf_counter() - started
    await asyncio.sleep(0.03)
    await handler.stop()

    assert result.code == "QUEUED"
    assert elapsed < 0.01
    assert processed == [b"payload"]


@pytest.mark.asyncio
async def test_async_pipeline_handler_rejects_before_ready():
    handler = AsyncPipelineHandler(None, None)

    result = handler(IncomingMessage(b"payload", "rest"))

    assert result.accepted is False
    assert result.code == "PIPELINE_NOT_CONFIGURED"
    assert result.http_status == 503
