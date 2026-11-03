# TODO(security): ASSUMPTION — Guardian's signed routes from the interface
# card are registered by guardian.adapters.communication.rest. This class
# remains the generic /events receiver owned by the communications work.

import httpx
from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from .base import HandlerResult, IncomingMessage, MessageHandler


class RestAdapter:

    def __init__(
        self,
        handler: MessageHandler,
        *,
        max_payload_bytes: int = 65536
    ):
        if max_payload_bytes <= 0:
            raise ValueError("max_payload_bytes must be positive")

        self.handler = handler
        self.max_payload_bytes = max_payload_bytes

        self.router = APIRouter()
        self.router.add_api_route(
            "/events",
            self.receive,
            methods=["POST"]
        )

    async def receive(self, request: Request):
        body = bytearray()

        async for chunk in request.stream():
            if len(body) + len(chunk) > self.max_payload_bytes:
                raise HTTPException(
                    status_code=413,
                    detail="Payload too large"
                )
            body.extend(chunk)

        if not body:
            raise HTTPException(
                status_code=400,
                detail="Empty payload"
            )

        message = IncomingMessage(
            payload=bytes(body),
            transport="rest",
            source=request.headers.get("x-source-id"),
            metadata={
                "content_type": request.headers.get(
                    "content-type", ""
                ),
                "path": request.url.path,
                "request_id": request.headers.get("x-request-id")
            }
        )

        try:
            result = await run_in_threadpool(
                self.handler, message
            )
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail="Message processing failed"
            ) from exc

        if not isinstance(result, HandlerResult):
            raise HTTPException(
                status_code=500,
                detail="Invalid handler response"
            )

        if not result.accepted:
            status = (
                503 if result.code == "PIPELINE_NOT_CONFIGURED"
                else 422
            )
            raise HTTPException(
                status_code=status,
                detail={
                    "code": result.code,
                    "detail": result.detail
                }
            )

        return {
            "accepted": True,
            "code": result.code,
            "detail": result.detail
        }

    async def send(
        self,
        url: str,
        payload: bytes,
        *,
        timeout: float = 10.0
    ) -> int:
        if len(payload) > self.max_payload_bytes:
            raise ValueError("Payload too large")

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False
        ) as client:
            response = await client.post(
                url,
                content=payload
            )
            response.raise_for_status()
            return response.status_code

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass