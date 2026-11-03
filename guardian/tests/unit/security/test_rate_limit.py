"""Token bucket and the once-per-window flood signal."""

import pytest

from guardian.security.errors import ReasonCode, SecurityRejection
from tests.support import FakeTime, make_gate, raw, reading, signed


def _send(gate, clock: FakeTime, *, device: str = "S01", seq: int, event_id: str) -> None:
    body = signed(
        reading(
            source={"device_id": device},
            seq=seq,
            event_id=event_id,
            timestamp=clock.stamp(),
        )
    )
    gate.admit(raw(body), "publish_reading")


def test_burst_is_accepted_and_the_next_message_is_limited() -> None:
    clock = FakeTime()
    gate = make_gate(clock, rate_burst=20, rate_per_source=5)
    for index in range(20):
        _send(gate, clock, seq=index, event_id=f"evt-{index}")
    with pytest.raises(SecurityRejection) as caught:
        _send(gate, clock, seq=20, event_id="evt-20")
    assert caught.value.code is ReasonCode.RATE_LIMITED
    assert caught.value.http_status == 429
    assert caught.value.public_message == "Too many messages from this source."


def test_tokens_refill_over_time() -> None:
    clock = FakeTime()
    gate = make_gate(clock, rate_burst=20, rate_per_source=5)
    for index in range(20):
        _send(gate, clock, seq=index, event_id=f"evt-{index}")
    with pytest.raises(SecurityRejection):
        _send(gate, clock, seq=20, event_id="evt-blocked")
    clock.advance(1)
    for index in range(21, 26):
        _send(gate, clock, seq=index, event_id=f"evt-{index}")
    with pytest.raises(SecurityRejection) as caught:
        _send(gate, clock, seq=26, event_id="evt-after-refill")
    assert caught.value.code is ReasonCode.RATE_LIMITED


def test_one_source_does_not_affect_another() -> None:
    clock = FakeTime()
    gate = make_gate(clock, rate_burst=1, rate_per_source=1e-6)
    _send(gate, clock, device="S01", seq=1, event_id="evt-a")
    with pytest.raises(SecurityRejection):
        _send(gate, clock, device="S01", seq=2, event_id="evt-b")
    _send(gate, clock, device="S02", seq=1, event_id="evt-c")


def test_flood_signal_once_per_window() -> None:
    clock = FakeTime()
    gate = make_gate(clock, rate_burst=1, rate_per_source=1e-6, flood_threshold=3)
    _send(gate, clock, seq=1, event_id="evt-1")
    for index in (2, 3, 4):
        with pytest.raises(SecurityRejection):
            _send(gate, clock, seq=index, event_id=f"evt-{index}")
    assert gate.flooding_sources() == ("twin:S01",)
    assert gate.flooding_sources() == ()
    with pytest.raises(SecurityRejection):
        _send(gate, clock, seq=5, event_id="evt-5")
    assert gate.flooding_sources() == ()
    clock.advance(10)
    for index in (6, 7, 8):
        with pytest.raises(SecurityRejection):
            _send(gate, clock, seq=index, event_id=f"evt-{index}")
    assert gate.flooding_sources() == ("twin:S01",)


def test_unauthenticated_message_does_not_consume_a_bucket() -> None:
    clock = FakeTime()
    gate = make_gate(clock, rate_burst=1, rate_per_source=1e-6)
    forged = signed(reading(timestamp=clock.stamp()))
    forged["payload"] = {"metric": "water_level", "value": 1, "unit": "cm"}
    with pytest.raises(SecurityRejection):
        gate.admit(raw(forged), "publish_reading")
    _send(gate, clock, seq=1, event_id="evt-good")


def test_forbidden_operation_does_not_consume_a_bucket() -> None:
    clock = FakeTime()
    gate = make_gate(clock, rate_burst=1, rate_per_source=1e-6)
    body = raw(signed(reading(timestamp=clock.stamp())))
    with pytest.raises(SecurityRejection) as caught:
        gate.admit(body, "request_verdict")
    assert caught.value.code is ReasonCode.FORBIDDEN
    _send(gate, clock, seq=2, event_id="evt-allowed")


def test_overlong_device_id_shares_the_dash_bucket() -> None:
    clock = FakeTime()
    gate = make_gate(clock, rate_burst=1, rate_per_source=1e-6)
    missing = reading(timestamp=clock.stamp(), event_id="evt-missing", seq=1)
    missing["source"] = {"layer": "twin"}
    gate.admit(raw(signed(missing)), "publish_reading")
    huge = reading(timestamp=clock.stamp(), event_id="evt-huge", seq=1, source={"device_id": "D" * 129})
    with pytest.raises(SecurityRejection) as caught:
        gate.admit(raw(signed(huge)), "publish_reading")
    assert caught.value.code is ReasonCode.RATE_LIMITED
    _send(gate, clock, device="S01", seq=1, event_id="evt-other")


def test_least_recently_used_source_is_evicted() -> None:
    clock = FakeTime()
    gate = make_gate(clock, rate_burst=1, rate_per_source=1e-9, max_sources=2)
    _send(gate, clock, device="S01", seq=1, event_id="evt-a")
    _send(gate, clock, device="S02", seq=1, event_id="evt-b")
    _send(gate, clock, device="S03", seq=1, event_id="evt-c")
    _send(gate, clock, device="S01", seq=2, event_id="evt-d")
