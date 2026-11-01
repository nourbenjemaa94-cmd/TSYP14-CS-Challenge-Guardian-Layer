"""REST front door for signed envelopes.

Reads the raw body and passes it to the pipeline. A security rejection becomes
the public error contract. Anything else becomes a generic 500 with the detail
kept in the server log. ``GET /health`` is the only route without a signature.
"""

import logging
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.concurrency import run_in_threadpool

from guardian.config import AppConfig
from guardian.orchestration.pipeline import Pipeline
from guardian.security.errors import SecurityRejection
from guardian.security.gate import SecuritySettings

_LOG = logging.getLogger("guardian.security")


class PublicError(BaseModel):
    """Body returned for every ``SecurityRejection``."""

    model_config = ConfigDict(extra="ignore")

    error: str
    message: str
    event_id: str | None = None
    fields: list[str] | None = None


class InternalError(BaseModel):
    """Body returned when Guardian fails unexpectedly."""

    error: str


class HealthResponse(BaseModel):
    """Liveness payload. It must not grow configuration or key material."""

    model_config = ConfigDict(extra="forbid")

    status: str
    contract_version: str
    degraded: bool


_ERROR_RESPONSES: dict[int | str, dict[str, type[BaseModel]]] = {
    401: {"model": PublicError},
    403: {"model": PublicError},
    409: {"model": PublicError},
    413: {"model": PublicError},
    422: {"model": PublicError},
    429: {"model": PublicError},
    500: {"model": InternalError},
}


def register_routes(app: FastAPI, pipeline: Pipeline, config: AppConfig, settings: SecuritySettings) -> None:
    """Register the routes declared in configuration. Paths are not hard-coded here."""
    health = config.route("health")
    if health.method != "GET":
        raise RuntimeError("The health route must be GET.")

    @app.get(health.path, response_model=HealthResponse, tags=["health"])
    def health_endpoint() -> HealthResponse:
        return HealthResponse(
            status="ok",
            contract_version=f"{settings.schema_major}.0",
            degraded=False,
        )

    for route in config.routes:
        if route.operation == "health":
            continue
        app.add_api_route(
            route.path,
            _endpoint(pipeline, route.operation, settings.max_message_bytes),
            methods=[route.method],
            name=route.operation,
            response_model=None,
            responses=_ERROR_RESPONSES,
            tags=["messages"],
        )


def _endpoint(pipeline: Pipeline, operation: str, limit: int) -> Callable[[Request], Awaitable[JSONResponse]]:
    async def endpoint(request: Request) -> JSONResponse:
        raw = await _read_limited(request, limit)
        try:
            result = await run_in_threadpool(pipeline.process_inbound, raw, operation)
        except SecurityRejection as exc:
            return JSONResponse(status_code=exc.http_status, content=exc.to_public_dict())
        except Exception:
            _LOG.exception("stage=security.rest outcome=error operation=%s", operation)
            return JSONResponse(status_code=500, content={"error": "INTERNAL_ERROR"})
        if result.response_envelope is not None:
            return JSONResponse(status_code=200, content=result.response_envelope)
        return JSONResponse(
            status_code=200,
            content={"status": "accepted", "event_id": result.event_id},
        )

    return endpoint


async def _read_limited(request: Request, limit: int) -> bytes:
    """Stop reading once the body exceeds the limit so a flood cannot be buffered."""
    received = 0
    chunks: list[bytes] = []
    async for chunk in request.stream():
        received += len(chunk)
        if received > limit:
            return b"\x00" * (limit + 1)
        chunks.append(chunk)
    return b"".join(chunks)
