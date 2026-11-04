"""Explicit HTTP-only City Brain stand-in for Docker integration tests.

``mocks.mock_brain`` is a verdict-request client and remains separate. This
module is the service receiving Guardian's signed outbound Brain payload.
It deliberately performs no production decisioning and contains no secrets.
"""

import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from guardian.security.authentication import verify_signature

app = FastAPI(title="Guardian Brain HTTP Mock")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "HEALTHY", "service": "brain-http-mock"}


@app.post("/api/v1/brain/ingest")
async def ingest(request: Request):
    try:
        payload = await request.json()
    except ValueError:
        return JSONResponse(status_code=422, content={"error": "INVALID_JSON"})
    if not isinstance(payload, dict) or not payload.get("signature"):
        return JSONResponse(status_code=401, content={"error": "SIGNATURE_MISSING"})
    key = os.getenv("GUARDIAN_HMAC_KEY_GUARDIAN")
    if not key:
        return JSONResponse(status_code=503, content={"error": "HMAC_NOT_CONFIGURED"})
    if not verify_signature(payload, key):
        return JSONResponse(status_code=401, content={"error": "SIGNATURE_INVALID"})
    return {"accepted": True, "service": "brain-http-mock"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("BRAIN_PORT", "8002")))
