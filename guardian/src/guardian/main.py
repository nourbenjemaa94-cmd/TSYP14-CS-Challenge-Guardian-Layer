"""
main.py
-------
FastAPI Application Entry Point for Guardian Security Gateway (Layer 2).
Exposes:
- WebSocket /ws/timeline for live causal timeline audit (Requirement R3)
- REST POST /api/v1/telemetry for sensor ingestion
- GET /health for container liveness and orchestration readiness
"""

from typing import Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from guardian.audit.timeline import timeline_manager
from guardian.audit.logger import get_audit_logger
from guardian.audit.event_store import default_event_store
from guardian.core.anomaly_detector import AnomalyDetector
from guardian.core.trust_assessor import TrustAssessor
from guardian.core.containment import ContainmentEngine
from guardian.orchestration.pipeline import GuardianPipeline
from guardian.config import settings

# Member 4 standalone fallback interfaces (auto-loads real modules once Member 1, 2, 5, 6 commit)
try:
    from security.authentication import SecurityManager
except ImportError:
    class SecurityManager:
        def validate(self, raw_message: Dict[str, Any]) -> bool:
            return raw_message.get("token") != "invalid"

try:
    from adapters.contract.mapper import ContractMapper
except ImportError:
    class ContractMapper:
        def map_to_canonical(self, raw_message: Dict[str, Any]) -> Dict[str, Any]:
            raw_val = raw_message.get("levelOfWater", raw_message.get("value", 0))
            unit = raw_message.get("unit", "m")
            val_cm = raw_val * 100 if unit == "m" else raw_val
            return {
                "sensor_id": raw_message.get("sensor_id", "S01"),
                "metric": "water_level",
                "value": val_cm,
                "unit": "cm",
                "timestamp": raw_message.get("timestamp", "2026-10-20T10:00:00Z")
            }

try:
    from adapters.communication.rest import RestBrainOutputAdapter
except ImportError:
    class RestBrainOutputAdapter:
        def __init__(self, endpoint_url: str = ""):
            self.endpoint_url = endpoint_url
        async def send_to_brain(self, payload: Dict[str, Any]) -> bool:
            return True

# Initialize application
app = FastAPI(
    title="Guardian Security Gateway",
    description="Layer 2 Cyber-Physical Sanity and Zero-Trust Verification Gateway (Triplet 07)",
    version="1.0.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger = get_audit_logger("guardian.main")

# Instantiate default production pipeline
default_pipeline = GuardianPipeline(
    security=SecurityManager(),
    contract=ContractMapper(),
    event_store=default_event_store,
    anomaly_detector=AnomalyDetector(
        water_spike_threshold_cm=settings.detection.flood_water_spike_cm
    ),
    trust_assessor=TrustAssessor(),
    containment=ContainmentEngine(),
    output_adapter=RestBrainOutputAdapter(
        endpoint_url=settings.partners.city_brain_url
    )
)


@app.get("/health")
async def health_check():
    """Health and readiness probe."""
    return {
        "status": "HEALTHY",
        "service": "guardian-gateway",
        "triplet": "Triplet 07",
        "active_timeline_listeners": len(timeline_manager.active_connections)
    }


@app.websocket("/ws/timeline")
async def websocket_timeline_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time causal timeline streaming (Requirement R3).
    Used by jury, monitoring dashboards, and automated verification tests.
    """
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


@app.post("/api/v1/telemetry")
async def ingest_telemetry(payload: Dict[str, Any]):
    """
    Ingests raw sensor telemetry from Twin (Layer 1).
    Evaluates through GuardianPipeline:
    Auth -> Contract Mapping -> Anomaly Detection -> Trust Assessment -> Containment -> Brain Forwarding.
    """
    result = await default_pipeline.process_incoming(payload, logger)

    if result.get("status") == "REJECTED" and result.get("reason") == "SECURITY":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Security validation failed", "event_id": result.get("event_id")}
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=result
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.server.host, port=settings.server.port)

