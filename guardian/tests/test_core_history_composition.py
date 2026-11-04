from guardian.audit.event_store import EventStore
from guardian.core.anomaly_detector import AnomalyDetector
from guardian.core.containment import ContainmentEngine
from guardian.core.history import HistoryTracker
from guardian.core.trust_assessor import TrustAssessor


def reading(event_id, sensor_id, value, timestamp):
    return {
        "event_id": event_id,
        "sensor_id": sensor_id,
        "metric": "water_level",
        "value": value,
        "unit": "cm",
        "timestamp": timestamp,
    }


def test_core_components_share_one_history_and_keep_event_store_as_mirror():
    core_history = HistoryTracker()
    event_store = EventStore()
    detector = AnomalyDetector(history=core_history, max_water_level_cm=1000)
    assessor = TrustAssessor(history=core_history)
    containment = ContainmentEngine(history=core_history)

    assert detector.history is assessor.history is containment.history is core_history

    first = reading("evt-1", "S01", 100, "2026-11-04T10:00:00+00:00")
    anomaly = reading("evt-2", "S01", 1200, "2026-11-04T10:00:01+00:00")
    recovery = reading("evt-3", "S01", 110, "2026-11-04T10:00:02+00:00")

    results = []
    for message in (first, anomaly, recovery):
        detection = detector.analyze(message)
        verdict = assessor.evaluate(detection)
        report = containment.contain(verdict)
        event_store.add_reading(message["sensor_id"], message)
        results.append((detection, verdict, report))

    assert results[0][1].verdict == "TRUSTED"
    assert "PHYSICAL_BOUNDS_VIOLATION" in results[1][0].codes
    assert results[1][1].verdict == "UNTRUSTED"
    assert results[2][0].codes == []
    assert results[2][1].verdict == "SUSPICIOUS"
    assert results[2][1].reason_code == "DEVICE_RECOVERING"
    # Current policy requires the configured clean-readings threshold before
    # release; recovery removes the anomaly finding without silently releasing.
    # No command port is configured here: the Core decision remains ISOLATE,
    # but the remote device state cannot be reported as confirmed.
    assert results[2][2].state_after == "ACTIVE"
    assert len(core_history.entries("S01")) == 3
    assert len(event_store.get_history("S01")) == 3


def test_duplicate_event_is_not_recorded_or_counted_again():
    history = HistoryTracker()
    detector = AnomalyDetector(history=history, max_water_level_cm=1000)
    assessor = TrustAssessor(history=history)
    message = reading("same-event", "S01", 100, "2026-11-04T10:00:00+00:00")

    first = detector.analyze(message)
    assessor.evaluate(first)
    duplicate = detector.analyze(message)
    duplicate_verdict = assessor.evaluate(duplicate)

    assert first.recorded is True
    assert duplicate.recorded is False
    assert duplicate.codes == ["DUPLICATE_EVENT"]
    assert len(history.entries("S01")) == 1
    assert duplicate_verdict.recorded is False


def test_two_sensors_have_independent_core_histories():
    history = HistoryTracker()
    detector = AnomalyDetector(history=history, max_water_level_cm=1000)

    sensor_a = detector.analyze(reading("a-1", "S-A", 100, "2026-11-04T10:00:00+00:00"))
    sensor_b = detector.analyze(reading("b-1", "S-B", 110, "2026-11-04T10:00:01+00:00"))

    assert sensor_a.codes == []
    assert sensor_b.codes == []
    assert [entry.reading.sensor_id for entry in history.entries("S-A")] == ["S-A"]
    assert [entry.reading.sensor_id for entry in history.entries("S-B")] == ["S-B"]
