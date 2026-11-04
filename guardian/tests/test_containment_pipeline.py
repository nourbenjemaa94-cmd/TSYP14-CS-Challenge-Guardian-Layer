import asyncio
from dataclasses import replace
from unittest.mock import AsyncMock, MagicMock

from guardian.audit.event_store import EventStore
from guardian.core.anomaly_detector import AnomalyDetector
from guardian.core.containment import ContainmentEngine, PortResult
from guardian.core.trust_assessor import TrustAssessor
from guardian.orchestration.pipeline import GuardianPipeline


class TimelineRecorder:
    def __init__(self):
        self.events = []

    async def broadcast(self, event):
        self.events.append(event)


class IsolationPort:
    def __init__(self, mode="success"):
        self.mode = mode
        self.calls = []

    def isolate_device(self, device_id, idem_key):
        self.calls.append((device_id, idem_key))
        if self.mode == "reject":
            return PortResult(False, False, "partner rejected")
        if self.mode == "timeout":
            raise TimeoutError("partner timeout")
        return PortResult(True, True, "applied")


class DeduplicatingIsolationPort:
    def __init__(self, first_result="timeout"):
        self.first_result = first_result
        self.keys = []
        self.effects = 0

    def isolate_device(self, _device_id, idem_key):
        self.keys.append(idem_key)
        if idem_key in self.keys[:-1]:
            if self.first_result == "timeout":
                return PortResult(True, True, "already applied after timeout")
            return PortResult(False, False, "same rejected command")
        if self.first_result == "timeout":
            self.effects += 1
            raise TimeoutError("response lost after remote apply")
        return PortResult(False, False, "partner rejected")


class IncoherentEngine(ContainmentEngine):
    def contain(self, verdict):
        return replace(super().contain(verdict), state_after="ACTIVE")


def make_pipeline(engine):
    output = MagicMock()
    output.send_to_brain = AsyncMock(return_value=True)
    pipeline = GuardianPipeline(
        security=object(), contract=object(), event_store=EventStore(),
        anomaly_detector=AnomalyDetector(max_water_level_cm=1000),
        trust_assessor=TrustAssessor(), containment=engine, output_adapter=output,
    )
    pipeline.timeline = TimelineRecorder()
    return pipeline, output


def process(pipeline, event_id="containment-event"):
    return asyncio.run(pipeline._process_canonical({
        "event_id": event_id, "sensor_id": "S-01", "metric": "water_level",
        "value": 1200, "unit": "cm", "timestamp": "2026-11-04T10:00:00+00:00",
    }, MagicMock(), event_id))


def test_success_emits_applied_then_isolated_and_blocks_forwarding():
    port = IsolationPort()
    pipeline, output = make_pipeline(ContainmentEngine(port=port))

    result = process(pipeline)
    stages = [event["stage"] for event in pipeline.timeline.events]

    assert result["containment_status"] == "APPLIED"
    assert result["isolation_confirmed"] is True
    assert stages[-2:] == ["CONTAINMENT_APPLIED", "ISOLATED"]
    assert "FORWARD_REQUESTED" not in stages
    assert output.send_to_brain.await_count == 0
    assert port.calls[0][1].startswith("guardian:isolate:")


def test_rejection_and_timeout_are_failed_without_isolated():
    for mode in ("reject", "timeout"):
        port = IsolationPort(mode)
        pipeline, output = make_pipeline(ContainmentEngine(port=port))

        result = process(pipeline, f"event-{mode}")
        stages = [event["stage"] for event in pipeline.timeline.events]

        assert result["containment_status"] == "FAILED"
        assert "CONTAINMENT_FAILED" in stages
        assert "ISOLATED" not in stages
        assert output.send_to_brain.await_count == 0


def test_engine_isolation_state_requires_confirmed_port_outcome():
    for mode, expected_status in (("reject", "FAILED"), ("timeout", "FAILED"), ("success", "APPLIED")):
        engine = ContainmentEngine(port=IsolationPort(mode))

        action = engine.isolate("S-01", event_id=f"direct-{mode}")

        assert action.status == expected_status
        assert engine.is_sensor_isolated("S-01") is (mode == "success")
        assert engine.state("S-01") == ("ISOLATED" if mode == "success" else "ACTIVE")


def test_acknowledged_but_not_applied_keeps_remote_state_unconfirmed():
    class AcceptedNotAppliedPort:
        def isolate_device(self, _device_id, _idem_key):
            return PortResult(True, False, "accepted for later application")

    engine = ContainmentEngine(port=AcceptedNotAppliedPort())

    action = engine.isolate("S-01", event_id="accepted-not-applied")

    assert action.status == "ACCEPTED"
    assert action.remote_confirmed is False
    assert engine.is_sensor_isolated("S-01") is False


def test_retry_after_timeout_reuses_key_without_duplicate_remote_effect():
    port = DeduplicatingIsolationPort("timeout")
    engine = ContainmentEngine(port=port)

    first = engine.isolate("S-01", event_id="incident-E01")
    retry = engine.isolate("S-01", event_id="incident-E01")

    assert first.status == "FAILED"
    assert retry.status == "APPLIED"
    assert first.action_id != retry.action_id
    assert first.idempotency_key == retry.idempotency_key
    assert port.effects == 1
    assert engine.is_sensor_isolated("S-01") is True


def test_retry_after_refusal_reuses_key_but_new_decision_gets_new_key():
    port = DeduplicatingIsolationPort("reject")
    engine = ContainmentEngine(port=port)

    first = engine.isolate("S-01", event_id="incident-E01")
    retry = engine.isolate("S-01", event_id="incident-E01")
    new_decision = engine.isolate("S-01", event_id="incident-E02")

    assert first.status == retry.status == "FAILED"
    assert first.action_id != retry.action_id
    assert first.idempotency_key == retry.idempotency_key
    assert new_decision.idempotency_key != first.idempotency_key
    assert len(set(port.keys[:2])) == 1
    assert len(set(port.keys)) == 2
    assert engine.is_sensor_isolated("S-01") is False


def test_without_command_port_only_declares_request():
    pipeline, output = make_pipeline(ContainmentEngine())

    result = process(pipeline, "event-no-port")
    stages = [event["stage"] for event in pipeline.timeline.events]

    assert result["containment_status"] == "REQUESTED"
    assert result["isolation_confirmed"] is False
    assert stages[-1] == "CONTAINMENT_REQUESTED"
    assert "ISOLATED" not in stages
    assert output.send_to_brain.await_count == 0


def test_compatibility_pipeline_without_core_port_blocks_forwarding_only():
    output = MagicMock()
    output.send_to_brain = AsyncMock(return_value=True)
    pipeline = GuardianPipeline(
        security=object(), contract=object(), event_store=EventStore(),
        anomaly_detector=type("CompatDetector", (), {
            "detect": lambda self, _message, _history: ["ANOMALY"],
        })(),
        trust_assessor=type("CompatAssessor", (), {
            "assess": lambda self, _message, _flags: ("UNTRUSTED", "ANOMALY"),
        })(),
        containment=type("CompatContainment", (), {
            "evaluate_action": lambda self, _flags, _verdict: "ISOLATE",
        })(),
        output_adapter=output,
    )
    pipeline.timeline = TimelineRecorder()

    result = process(pipeline, "compat-no-port")
    stages = [event["stage"] for event in pipeline.timeline.events]

    assert result["containment_status"] == "LOCAL_FORWARD_BLOCKED"
    assert result["isolation_confirmed"] is False
    assert stages[-1] == "LOCAL_FORWARD_BLOCKED"
    assert "ISOLATED" not in stages
    assert output.send_to_brain.await_count == 0


def test_repeated_core_command_is_idempotent():
    port = IsolationPort()
    detector = AnomalyDetector(max_water_level_cm=1000)
    assessor = TrustAssessor()
    engine = ContainmentEngine(port=port)
    detection = detector.analyze({
        "event_id": "same-event", "sensor_id": "S-01", "metric": "water_level",
        "value": 1200, "unit": "cm", "timestamp": "2026-11-04T10:00:00+00:00",
    })
    verdict = assessor.evaluate(detection)

    first = engine.contain(verdict)
    second = engine.contain(verdict)

    assert len(port.calls) == 1
    assert first.actions[0].idempotency_key == second.actions[0].idempotency_key


def test_incoherent_confirmed_state_fails_closed():
    pipeline, output = make_pipeline(IncoherentEngine(port=IsolationPort()))

    result = process(pipeline, "event-incoherent")
    stages = [event["stage"] for event in pipeline.timeline.events]

    assert result["containment_status"] == "FAILED"
    assert "CONTAINMENT_FAILED" in stages
    assert "ISOLATED" not in stages
    assert output.send_to_brain.await_count == 0
