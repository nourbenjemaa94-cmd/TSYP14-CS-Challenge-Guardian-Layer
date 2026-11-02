"""Guardian process entrypoint.

The ASGI app is built on first access so importing this module during tests
does not require HMAC keys. A real start calls ``create_app``, which refuses
to run when a required key is missing or shorter than 32 characters.
Replay and rate-limit state live in this process: run one worker only.
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime

from fastapi import FastAPI

from guardian.adapters.communication.rest import register_routes
from guardian.adapters.contract.mapper import IdentityContractMapper
from guardian.audit.logger import AuditLogger
from guardian.config import AppConfig, default_config_path, load_config
from guardian.core.stub import StubCore
from guardian.orchestration.outbound import OutboundSigner
from guardian.orchestration.pipeline import Pipeline
from guardian.security.gate import SecurityGate, SecuritySettings

_app: FastAPI | None = None


def create_app(
    settings: SecuritySettings | None = None,
    *,
    config: AppConfig | None = None,
    gate: SecurityGate | None = None,
    core: object | None = None,
    audit: AuditLogger | None = None,
    clock: Callable[[], datetime] | None = None,
    monotonic: Callable[[], float] | None = None,
) -> FastAPI:
    """Wire configuration, the gate, and the routes. Keys are required."""
    resolved_settings = settings if settings is not None else SecuritySettings.from_env()
    resolved_config = config if config is not None else load_config(default_config_path())
    wall = clock or _wall_clock
    resolved_gate = gate or SecurityGate(resolved_settings, clock=wall, monotonic=monotonic)
    resolved_audit = audit or AuditLogger()
    resolved_core = core if core is not None else StubCore()
    signer = OutboundSigner(resolved_gate, clock=wall)
    pipeline = Pipeline(
        gate=resolved_gate,
        mapper=IdentityContractMapper(),
        core=resolved_core,
        audit=resolved_audit,
        signer=signer,
        clock=wall,
    )
    app = FastAPI(
        title="Guardian",
        version=f"{resolved_settings.schema_major}.0",
        description=(
            "Security front door for the Guardian layer. "
            "Every POST body is a signed envelope. GET /health is the only unsigned route."
        ),
        docs_url="/docs",
        redoc_url=None,
    )
    register_routes(app, pipeline, resolved_config, resolved_settings)
    app.state.pipeline = pipeline
    app.state.gate = resolved_gate
    app.state.audit = resolved_audit
    app.state.core = resolved_core
    app.state.config = resolved_config
    app.state.signer = signer
    return app


def configure_logging() -> None:
    logger = logging.getLogger("guardian.security")
    logger.setLevel(logging.INFO)
    if not logging.getLogger().handlers and not logger.handlers:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")


def __getattr__(name: str) -> FastAPI:
    global _app
    if name == "app":
        if _app is None:
            configure_logging()
            _app = create_app()
        return _app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _wall_clock() -> datetime:

    return datetime.now(UTC)
