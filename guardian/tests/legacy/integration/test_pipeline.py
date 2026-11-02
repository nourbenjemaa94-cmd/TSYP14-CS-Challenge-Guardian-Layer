"""Pipeline order is admit, map, accept, then the core."""

from copy import deepcopy

import pytest
from tests.support import FakeTime, make_gate, raw, reading, signed

from guardian.adapters.contract.mapper import IdentityContractMapper
from guardian.audit.logger import AuditLogger
from guardian.core.stub import StubCore
from guardian.orchestration.outbound import OutboundSigner
from guardian.orchestration.pipeline import Pipeline
from guardian.security.errors import ReasonCode, SecurityRejection


def _pipeline(
    clock: FakeTime,
    mapper: object | None = None,
    core: object | None = None,
) -> tuple[Pipeline, StubCore, AuditLogger]:
    gate = make_gate(clock)
    audit = AuditLogger()
    resolved_core = core if isinstance(core, StubCore) or core is not None else StubCore()
    if core is None:
        resolved_core = StubCore()
    pipe = Pipeline(
        gate=gate,
        mapper=mapper or IdentityContractMapper(),
        core=resolved_core,
        audit=audit,
        signer=OutboundSigner(gate, clock=clock.clock),
        clock=clock.clock,
    )
    return pipe, resolved_core, audit  # type: ignore[return-value]


def test_core_receives_a_valid_reading() -> None:
    clock = FakeTime()
    pipe, core, _audit = _pipeline(clock)
    result = pipe.process_inbound(raw(signed(reading(timestamp=clock.stamp()))), "publish_reading")
    assert result.event_id == "evt-8f2c1a"
    assert core.received[0]["envelope"]["type"] == "sensor_reading"
    assert core.received[0]["envelope"]["payload"]["value"] == 180
    assert core.received[0]["warnings"] == []


def test_warnings_are_passed_to_the_core() -> None:
    clock = FakeTime()
    pipe, core, audit = _pipeline(clock)
    pipe.process_inbound(raw(signed(reading(timestamp=clock.stamp(), seq=1, event_id="evt-1"))), "publish_reading")
    pipe.process_inbound(raw(signed(reading(timestamp=clock.stamp(), seq=4, event_id="evt-4"))), "publish_reading")
    assert core.received[1]["warnings"][0].value == "SEQ_GAP"
    assert audit.records[-1]["outcome"] == "accepted_with_warning"
    assert audit.records[-1]["code"] == "SEQ_GAP"


def test_rejection_is_audited_and_reraised() -> None:
    clock = FakeTime()
    pipe, core, audit = _pipeline(clock)
    body = signed(reading(timestamp=clock.stamp()))
    body["payload"] = {"metric": "water_level", "value": 1, "unit": "cm"}
    with pytest.raises(SecurityRejection) as caught:
        pipe.process_inbound(raw(body), "publish_reading")
    assert caught.value.code is ReasonCode.SIGNATURE_INVALID
    assert audit.records[0]["code"] == "SIGNATURE_INVALID"
    assert core.received == []


def test_mapper_cannot_change_the_authenticated_layer() -> None:
    class RewriteLayer:
        def normalize(self, body: dict, operation: str) -> dict:
            copied = deepcopy(body)
            copied["source"] = {"layer": "brain", "device_id": "S01"}
            return copied

    clock = FakeTime()
    pipe, _core, audit = _pipeline(clock, mapper=RewriteLayer())
    with pytest.raises(SecurityRejection) as caught:
        pipe.process_inbound(raw(signed(reading(timestamp=clock.stamp()))), "publish_reading")
    assert caught.value.code is ReasonCode.SOURCE_MISMATCH
    assert audit.records[0]["stage"] == "security.accept"


def test_flood_hook_is_called_when_the_core_exposes_one() -> None:
    class HookCore(StubCore):
        def __init__(self) -> None:
            super().__init__()
            self.signals: list[tuple[str, str]] = []

        def on_security_signal(self, code: str, source: str) -> None:
            self.signals.append((code, source))

    clock = FakeTime()
    core = HookCore()
    gate = make_gate(clock, rate_burst=1, rate_per_source=1e-6, flood_threshold=1)
    audit = AuditLogger()
    pipe = Pipeline(
        gate=gate,
        mapper=IdentityContractMapper(),
        core=core,
        audit=audit,
        signer=OutboundSigner(gate, clock=clock.clock),
        clock=clock.clock,
    )
    pipe.process_inbound(raw(signed(reading(timestamp=clock.stamp(), seq=1, event_id="evt-1"))), "publish_reading")
    with pytest.raises(SecurityRejection):
        pipe.process_inbound(raw(signed(reading(timestamp=clock.stamp(), seq=2, event_id="evt-2"))), "publish_reading")
    assert core.signals == [("FLOOD_SUSPECTED", "twin:S01")]
    assert any(record["code"] == "FLOOD_SUSPECTED" for record in audit.records)
