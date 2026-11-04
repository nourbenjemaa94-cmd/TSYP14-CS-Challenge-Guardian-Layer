"""HTTP output adapter tests using httpx.MockTransport."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import httpx

from guardian.adapters.communication.brain import RestBrainOutputAdapter
from guardian.orchestration.legacy_outbound import OutboundSigner
from guardian.security.authentication import verify_signature
from tests.support import GUARDIAN_KEY, make_gate

PAYLOAD = {
    "event_id": "evt-forward-1",
    "sensor_id": "S01",
    "metric": "water_level",
    "value": 180.0,
    "unit": "cm",
}


def make_adapter(handler) -> RestBrainOutputAdapter:
    transport = httpx.MockTransport(handler)
    signer = OutboundSigner(make_gate(), clock=lambda: datetime.now(UTC))
    return RestBrainOutputAdapter(
        "https://brain.example.test/ingest",
        signer=signer,
        transport=transport,
    )


def test_http_2xx_sends_one_signed_envelope() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body = json.loads(request.content)
        assert body["source"]["layer"] == "guardian"
        assert verify_signature(body, GUARDIAN_KEY)
        return httpx.Response(202)

    adapter = make_adapter(handler)
    assert asyncio.run(adapter.send_to_brain(PAYLOAD)) is True
    assert len(requests) == 1


def test_http_500_returns_false_without_double_send() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    adapter = make_adapter(handler)
    assert asyncio.run(adapter.send_to_brain(PAYLOAD)) is False
    assert calls == 1


def test_timeout_returns_false() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("brain timeout", request=request)

    assert asyncio.run(make_adapter(handler).send_to_brain(PAYLOAD)) is False


def test_dns_failure_returns_false() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("DNS failure", request=request)

    assert asyncio.run(make_adapter(handler).send_to_brain(PAYLOAD)) is False
