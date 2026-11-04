"""Signed HTTP output adapter for forwarding accepted events to City Brain."""

from collections.abc import Callable
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx

from guardian.orchestration.legacy_outbound import OutboundSigner


class BrainOutputPort(Protocol):
    """Application port used by the orchestration layer for outbound delivery."""

    async def send_to_brain(self, payload: dict[str, Any]) -> bool: ...


class RestBrainOutputAdapter:
    """Real signed HTTP output adapter with an explicit retry policy."""

    def __init__(
        self,
        endpoint_url: str,
        *,
        signer: OutboundSigner,
        timeout: float = 10.0,
        max_retries: int = 0,
        transport: httpx.AsyncBaseTransport | None = None,
        client_factory: Callable[..., httpx.AsyncClient] = httpx.AsyncClient,
    ) -> None:
        parsed = urlparse(endpoint_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("City Brain endpoint URL must be an absolute HTTP(S) URL")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        self.endpoint_url = endpoint_url
        self.signer = signer
        self.timeout = timeout
        self.max_retries = max_retries
        self.transport = transport
        self.client_factory = client_factory

    async def send_to_brain(self, payload: dict[str, Any]) -> bool:
        envelope = self.signer.sign(
            message_type="trust_verdict",
            payload=payload,
            event_id=payload.get("event_id") if isinstance(payload.get("event_id"), str) else None,
        )
        for attempt in range(self.max_retries + 1):
            try:
                async with self.client_factory(
                    timeout=self.timeout,
                    follow_redirects=False,
                    transport=self.transport,
                ) as client:
                    response = await client.post(self.endpoint_url, json=envelope)
                if 200 <= response.status_code < 300:
                    return True
                if response.status_code < 500 or attempt == self.max_retries:
                    return False
            except (httpx.TimeoutException, httpx.RequestError):
                if attempt == self.max_retries:
                    return False
        return False
