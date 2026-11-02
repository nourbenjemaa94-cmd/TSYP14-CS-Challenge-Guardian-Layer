"""A rejected message produces one audit record and no signature."""

import json
import logging

from tests.support import TWIN_KEY, build_client, raw, reading, signed


def test_rejection_audit_record_has_no_signature(caplog) -> None:
    client, app, clock = build_client()
    body = signed(reading(timestamp=clock.stamp()))
    signature = body["signature"]
    body["payload"] = {"metric": "water_level", "value": 1, "unit": "cm"}
    path = app.state.config.route("publish_reading").path
    with caplog.at_level(logging.INFO, logger="guardian.security"):
        response = client.post(path, content=raw(body))
    assert response.status_code == 401
    assert len(app.state.audit.records) == 1
    record = app.state.audit.records[0]
    assert list(record) == [
        "timestamp",
        "stage",
        "outcome",
        "code",
        "event_id",
        "source",
        "operation",
    ]
    assert record == {
        "timestamp": record["timestamp"],
        "stage": "security.admit",
        "outcome": "rejected",
        "code": "SIGNATURE_INVALID",
        "event_id": "evt-8f2c1a",
        "source": "twin:S01",
        "operation": "publish_reading",
    }
    blob = json.dumps(record)
    assert signature not in blob
    assert "hmac-sha256" not in blob
    assert TWIN_KEY not in blob
    assert signature not in caplog.text
    assert TWIN_KEY not in caplog.text
    assert app.state.audit.timeline == ["Guardian rejected message evt-8f2c1a: SIGNATURE_INVALID"]
