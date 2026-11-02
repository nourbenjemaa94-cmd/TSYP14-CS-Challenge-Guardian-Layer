"""MQTT deliveries reach the pipeline, and a bad payload does not stop the loop."""

from types import SimpleNamespace

from tests.support import build_client, raw, reading, signed

from guardian.adapters.communication.mqtt import MqttIngress, subscription_filter, topic_matches


class StubClient:
    def __init__(self) -> None:
        self.on_message = None
        self.subscriptions: list[str] = []
        self.connected = None
        self.looping = False

    def connect(self, host: str, port: int) -> None:
        self.connected = (host, port)

    def subscribe(self, topic: str, qos: int = 0) -> tuple[int, int]:
        self.subscriptions.append(topic)
        return (0, 1)

    def loop_start(self) -> None:
        self.looping = True

    def inject(self, topic: str, payload: bytes) -> None:
        assert self.on_message is not None
        self.on_message(self, None, SimpleNamespace(topic=topic, payload=payload))


def test_topic_patterns() -> None:
    assert topic_matches("city/twin/readings/{device_id}", "city/twin/readings/S01")
    assert not topic_matches("city/twin/acks", "city/twin/acks/extra")
    assert subscription_filter("city/twin/readings/{device_id}") == "city/twin/readings/+"


def test_valid_message_reaches_the_pipeline_and_tamper_does_not_stop_the_loop() -> None:
    client_unused, app, clock = build_client()
    del client_unused
    stub = StubClient()
    ingress = MqttIngress(
        app.state.pipeline,
        app.state.config.topics,
        client=stub,
        host="localhost",
        port=1883,
    )
    ingress.start()
    assert stub.looping is True
    assert "city/twin/readings/+" in stub.subscriptions
    assert "city/twin/acks" in stub.subscriptions

    topic = "city/twin/readings/S01"
    first = signed(reading(timestamp=clock.stamp(), seq=1, event_id="evt-m1"))
    tampered = signed(reading(timestamp=clock.stamp(), seq=2, event_id="evt-m2"))
    tampered["payload"] = {"metric": "water_level", "value": 1, "unit": "cm"}
    second = signed(reading(timestamp=clock.stamp(), seq=3, event_id="evt-m3"))

    stub.inject(topic, raw(first))
    stub.inject(topic, raw(tampered))
    stub.inject(topic, raw(second))

    received = [item["envelope"]["event_id"] for item in app.state.core.received]
    assert received == ["evt-m1", "evt-m3"]
    assert stub.looping is True
    codes = [record["code"] for record in app.state.audit.records]
    assert "SIGNATURE_INVALID" in codes
    assert app.state.gate.settings.hmac_key_twin not in json_records(app)


def json_records(app) -> str:
    import json

    return json.dumps(app.state.audit.records)
