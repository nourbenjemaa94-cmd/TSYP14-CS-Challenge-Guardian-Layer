"""
main.py
-------
FastAPI Application Entry Point for Guardian Security Gateway (Layer 2).
Exposes:
- WebSocket /ws/timeline for live causal timeline audit (Requirement R3)
- REST POST /api/v1/telemetry for sensor ingestion
- GET /health for container liveness and /ready for orchestration readiness
"""

import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from guardian.adapters.communication.brain import RestBrainOutputAdapter
from guardian.adapters.communication.manager import AdapterManager, AsyncPipelineHandler
from guardian.adapters.contract.errors import MappingError
from guardian.adapters.contract.mapper import GenericMapper
from guardian.adapters.contract.production import production_profiles
from guardian.adapters.contract.registry import ProfileRegistry
from guardian.audit.event_store import default_event_store
from guardian.audit.logger import get_audit_logger, log_event
from guardian.audit.timeline import timeline_manager
from guardian.config import Settings
from guardian.core.anomaly_detector import AnomalyDetector
from guardian.core.containment import ContainmentEngine
from guardian.core.history import HistoryTracker
from guardian.core.trust_assessor import TrustAssessor, TrustConfig
from guardian.orchestration.legacy_outbound import OutboundSigner
from guardian.orchestration.pipeline import GuardianPipeline
from guardian.security.errors import ReasonCode, SecurityConfigurationError, SecurityRejection
from guardian.security.gate import SecurityGate


def _public_yaml_server_section() -> dict[str, Any]:
    """Read the non-secret ``server`` section of the YAML file, if any."""
    path = Path(os.getenv("GUARDIAN_CONFIG", "guardian/config.yaml"))
    try:
        raw = Settings._read_yaml(path, required=False)
    except SecurityConfigurationError:
        return {}
    server = raw.get("server")
    return server if isinstance(server, dict) else {}


def _cors_origins() -> list[str]:
    """Configured CORS origins: ``GUARDIAN_CORS_ORIGINS`` (comma list), else YAML ``server.cors_origins``."""
    explicit = os.getenv("GUARDIAN_CORS_ORIGINS")
    if explicit is not None and explicit.strip():
        return [item.strip() for item in explicit.split(",") if item.strip()]
    configured = _public_yaml_server_section().get("cors_origins")
    if isinstance(configured, list) and all(isinstance(item, str) and item.strip() for item in configured):
        return [item.strip() for item in configured]
    return ["*"]


def _cors_middleware_options() -> dict[str, Any]:
    """CORS settings; credentials are never combined with a wildcard origin."""
    origins = _cors_origins()
    return {
        "allow_origins": origins,
        "allow_credentials": "*" not in origins,
        "allow_methods": ["*"],
        "allow_headers": ["*"],
    }


# Initialize application
app = FastAPI(
    title="Guardian Security Gateway",
    description="Layer 2 Cyber-Physical Sanity and Zero-Trust Verification Gateway (Triplet 07)",
    version="1.0.0"
)

# CORS Middleware (origins from configuration, see _cors_origins)
app.add_middleware(CORSMiddleware, **_cors_middleware_options())

logger = get_audit_logger("guardian.main")

_pipeline: GuardianPipeline | None = None
_outbound_signer: OutboundSigner | None = None
_adapter_manager: AdapterManager | None = None
_pipeline_handler: AsyncPipelineHandler | None = None
_startup_error: str | None = None


def _security_rejection_response(
    rejection: SecurityRejection,
    *,
    action: str,
) -> JSONResponse:
    """Audit and return only the stable public security error contract."""
    log_event(
        logger,
        rejection.event_id or f"{action}-rejection",
        "SECURITY_REJECTED",
        "REJECTED",
        rejection.code.value,
        action=action,
    )
    return JSONResponse(
        status_code=rejection.http_status,
        content=rejection.to_public_dict(),
    )


@asynccontextmanager
async def guardian_lifespan(application: FastAPI):
    """Configure adapters and make the async pipeline ready before traffic."""
    global _adapter_manager, _pipeline_handler, _startup_error
    _startup_error = None
    pipeline = None
    loaded = None
    try:
        loaded = Settings.load()
        pipeline = _default_pipeline()
    except (SecurityConfigurationError, MappingError, ValueError) as exc:
        logger.error("Guardian pipeline is not ready: %s", exc)

    handler = AsyncPipelineHandler(pipeline, logger)
    manager = AdapterManager(handler)
    adapter_config: dict[str, dict[str, Any]] = {
        "rest": {
            "path": loaded.partners.twin.listen_path if loaded is not None else "/api/v1/telemetry",
            "max_payload_bytes": loaded.security.max_message_bytes if loaded and loaded.security else 65536,
        }
    }
    if pipeline is not None and loaded is not None and loaded.partners.twin.adapter.lower() == "mqtt":
        mqtt = loaded.partners.twin.mqtt
        adapter_config["mqtt"] = {
            "host": mqtt.host,
            "port": mqtt.port,
            "subscribe_topic": mqtt.topic,
            "tls_enabled": mqtt.tls_enabled,
            "ca_cert": mqtt.ca_cert,
            "client_cert": mqtt.client_cert,
            "client_key": mqtt.client_key,
        }
    try:
        manager.configure(adapter_config, app=application)
    except Exception as exc:
        _startup_error = f"adapter configuration failed: {type(exc).__name__}"
    if pipeline is not None:
        await handler.start()
    try:
        if _startup_error is None:
            manager.start()
    except Exception as exc:
        # Keep liveness available so an orchestrator can observe and restart the
        # process; readiness remains false until the required adapter starts.
        _startup_error = f"adapter startup failed: {type(exc).__name__}"
    _adapter_manager = manager
    _pipeline_handler = handler
    try:
        yield
    finally:
        manager.stop()
        await handler.stop()
        _adapter_manager = None
        _pipeline_handler = None
        _startup_error = None


app.router.lifespan_context = guardian_lifespan


def _timeline_mode() -> str:
    """Read only the non-secret timeline exposure setting."""
    explicit = os.getenv("GUARDIAN_TIMELINE_MODE")
    if explicit:
        return explicit.strip().lower()
    return str(_public_yaml_server_section().get("timeline_mode", "disabled")).strip().lower()


def _default_pipeline() -> GuardianPipeline:
    """Build the production pipeline. ``Settings.load()`` runs here, not at import."""
    global _pipeline, _outbound_signer
    if _pipeline is None:
        loaded = Settings.load()
        if loaded.security is None:
            raise SecurityConfigurationError("Guardian cannot start without security settings.")
        gate = SecurityGate(
            loaded.security,
            partner_identities={
                "twin": loaded.partners.twin.identity,
                "brain": "brain",
                "guardian": "guardian",
            },
        )
        # One decision history is shared by the Core components. EventStore
        # remains the application audit/read-model mirror, not a second Core
        # anomaly, trust, or containment history.
        core_history = HistoryTracker()
        signer = OutboundSigner(gate, clock=lambda: datetime.now(UTC))
        _outbound_signer = signer
        profiles = production_profiles()
        profile_registry = ProfileRegistry(Path(loaded.contract.profile_dir))
        for event_type, profile in profiles.items():
            profile_registry.ensure_builtin_active(
                profile,
                twin_identity=loaded.partners.twin.identity,
                event_type=event_type,
            )
        _pipeline = GuardianPipeline(
            security=gate,
            contract=GenericMapper(),
            event_store=default_event_store,
            anomaly_detector=AnomalyDetector(
                water_spike_threshold_cm=loaded.detection.flood_water_spike_cm,
                history=core_history,
            ),
            trust_assessor=TrustAssessor(
                config=TrustConfig.from_mapping(loaded.trust.model_dump()),
                history=core_history,
            ),
            containment=ContainmentEngine(history=core_history),
            output_adapter=RestBrainOutputAdapter(
                endpoint_url=loaded.partners.city_brain_url,
                signer=signer,
                timeout=loaded.partners.city_brain_timeout_seconds,
                max_retries=loaded.partners.city_brain_max_retries,
            ),
            mapping_profiles=profiles,
            profile_registry=profile_registry,
            forward_to_brain=loaded.partners.brain.forward,
        )
    return _pipeline


@app.get("/api/v1/verdicts/{event_id}")
async def verdict_by_event_id(event_id: str):
    """Return one persisted verdict, signed by Guardian.

    The verdict carries Guardian's HMAC signature so the reader can verify it,
    but the read itself is unauthenticated. A Brain that must authenticate on
    read uses the signed ``POST /v1/verdicts/query`` instead.
    """
    try:
        pipeline = _default_pipeline()
    except (SecurityConfigurationError, MappingError, ValueError) as exc:
        return JSONResponse(status_code=503, content={"error": "PIPELINE_NOT_CONFIGURED", "message": str(exc)})
    verdict = pipeline.store.get_verdict(event_id)
    if verdict is None:
        return JSONResponse(status_code=404, content={"error": "VERDICT_NOT_FOUND", "event_id": event_id})
    signer = _outbound_signer
    if signer is None:
        return JSONResponse(
            status_code=503,
            content={"error": "PIPELINE_NOT_CONFIGURED", "message": "Guardian cannot sign before startup."},
        )
    return JSONResponse(status_code=200, content=signer.sign(message_type="trust_verdict", payload=dict(verdict)))


@app.post("/v1/verdicts/query")
async def verdict_query(request: Request):
    """Return persisted Core verdicts to an authenticated Brain caller."""
    try:
        pipeline = _default_pipeline()
        raw = await request.body()
        admitted = pipeline.security.admit(raw, "request_verdict")
        # Keep the security envelope distinct from the business verdict.  The
        # gate validates the canonical envelope and records replay state only
        # after authentication and authorization have succeeded.
        accepted = pipeline.security.accept(admitted, admitted.body)
        envelope = accepted.envelope
        if envelope.get("type") != "verdict_request":
            raise SecurityRejection(
                ReasonCode.SCHEMA_INVALID,
                event_id=accepted.event_id,
                fields=["type"],
                source=accepted.source_key,
            )
        payload = envelope.get("payload")
        event_ids = payload.get("event_ids") if isinstance(payload, dict) else None
        if (
            not isinstance(event_ids, list)
            or not event_ids
            or any(not isinstance(event_id, str) or not event_id for event_id in event_ids)
        ):
            return JSONResponse(
                status_code=422,
                content={"error": "INVALID_VERDICT_QUERY", "message": "event_ids must be a non-empty list."},
            )

        verdicts: list[dict[str, Any]] = []
        for event_id in event_ids:
            verdict = pipeline.store.get_verdict(event_id)
            if verdict is None:
                return JSONResponse(
                    status_code=404,
                    content={"error": "VERDICT_NOT_FOUND", "event_id": event_id},
                )
            verdicts.append(verdict)

        signer = _outbound_signer
        if signer is None:
            raise SecurityConfigurationError("Guardian cannot sign a verdict response before startup.")
        response_payload: dict[str, Any]
        if len(verdicts) == 1:
            response_payload = dict(verdicts[0])
        else:
            response_payload = {"verdicts": verdicts}
        signed_response = signer.sign(
            message_type="trust_verdict",
            payload=response_payload,
            zone_id=envelope.get("zone_id"),
        )
        return JSONResponse(status_code=200, content=signed_response)
    except SecurityRejection as exc:
        return _security_rejection_response(exc, action="request_verdict")
    except SecurityConfigurationError as exc:
        return JSONResponse(status_code=503, content={"error": "PIPELINE_NOT_CONFIGURED", "message": str(exc)})


@app.get("/health")
async def health_check():
    """Process liveness probe; it does not claim that Guardian is ready."""
    return {
        "status": "ALIVE",
        "service": "guardian-gateway",
        "triplet": "Triplet 07",
    }


@app.get("/ready")
async def readiness_check():
    """Readiness probe for the complete production ingestion composition."""
    try:
        loaded = Settings.load()
        pipeline = _default_pipeline()
    except (SecurityConfigurationError, MappingError, ValueError) as exc:
        return JSONResponse(status_code=503, content={"status": "NOT_READY", "detail": str(exc)})

    checks = {
        "security": isinstance(pipeline.security, SecurityGate),
        "mapper": isinstance(pipeline.contract, GenericMapper),
        "orchestration": isinstance(pipeline, GuardianPipeline),
        "output_adapter": isinstance(pipeline.output, RestBrainOutputAdapter),
        "pipeline_handler": _pipeline_handler is not None and _pipeline_handler.ready,
        "adapter_manager": _adapter_manager is not None and _adapter_manager.running,
    }
    required_adapter = loaded.partners.twin.adapter.lower()
    checks["twin_adapter"] = _adapter_manager is not None and required_adapter in _adapter_manager.adapters
    if required_adapter == "mqtt":
        mqtt_adapter = _adapter_manager.adapters.get("mqtt") if _adapter_manager else None
        checks["mqtt_connection"] = mqtt_adapter is not None and bool(
            getattr(mqtt_adapter, "connected", False)
        )
        checks["mqtt_subscription"] = mqtt_adapter is not None and bool(
            getattr(mqtt_adapter, "subscribed", False)
        )

    if _startup_error:
        return JSONResponse(
            status_code=503,
            content={"status": "NOT_READY", "reason": "STARTUP_FAILED", "detail": _startup_error, "checks": checks},
        )
    if not all(checks.values()):
        return JSONResponse(status_code=503, content={"status": "NOT_READY", "checks": checks})
    return {"status": "READY", "service": "guardian-gateway", "checks": checks}


@app.websocket("/ws/timeline")
async def websocket_timeline_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time causal timeline streaming (Requirement R3).
    Used by jury, monitoring dashboards, and automated verification tests.
    """
    mode = _timeline_mode()
    environment = os.getenv("GUARDIAN_ENV", "development").strip().lower()
    client_host = getattr(getattr(websocket, "client", None), "host", None)
    local_hosts = {"127.0.0.1", "::1", "localhost", "testclient"}
    if environment == "production":
        await websocket.close(
            code=1008,
            reason="Unauthenticated timeline access is disabled in production.",
        )
        return
    if mode not in {"local", "demo"} or client_host not in local_hosts:
        await websocket.close(
            code=1008,
            reason="Timeline is limited to authenticated or loopback access.",
        )
        return

    await timeline_manager.connect(websocket)
    try:
        while True:
            # Keep socket alive to receive client pings or heartbeats
            data = await websocket.receive_text()
            # If client sends a ping or message, respond with ack
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        timeline_manager.disconnect(websocket)
    except Exception:
        timeline_manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn

    loaded = Settings.load()
    uvicorn.run(app, host=loaded.server.host, port=loaded.server.port)

