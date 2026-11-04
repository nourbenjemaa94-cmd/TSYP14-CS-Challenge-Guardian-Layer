# TODO(security): ASSUMPTION — Guardian's signed routes from the interface
# card are registered by guardian.adapters.communication.rest. This class
# remains the generic /events receiver owned by the communications work.

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from guardian.adapters.contract.errors import MappingError, MappingErrorCode
from guardian.security.errors import ReasonCode, SecurityRejection

from .base import HandlerResult, IncomingMessage, MessageHandler


class RestAdapter:

    def __init__(
        self,
        handler: MessageHandler,
        *,
        max_payload_bytes: int = 65536,
        path: str = "/api/v1/telemetry",
    ):
        if max_payload_bytes <= 0:
            raise ValueError("max_payload_bytes must be positive")
        if not path.startswith("/"):
            raise ValueError("path must start with /")

        self.handler = handler
        self.max_payload_bytes = max_payload_bytes
        self.path = path

        self.router = APIRouter()
        self.router.add_api_route(
            self.path,
            self.receive,
            methods=["POST"]
        )

    async def receive(self, request: Request):
        body = bytearray()

        async for chunk in request.stream():
            if len(body) + len(chunk) > self.max_payload_bytes:
                return self._security_response(SecurityRejection(ReasonCode.MESSAGE_TOO_LARGE))
            body.extend(chunk)

        if not body:
            return self._security_response(
                SecurityRejection(ReasonCode.SCHEMA_INVALID, fields=["body"])
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
            result = await run_in_threadpool(self.handler, message)
        except SecurityRejection as exc:
            return self._security_response(exc)
        except MappingError as exc:
            return JSONResponse(status_code=exc.http_status, content=exc.to_public_dict())
        except Exception:
            return JSONResponse(
                status_code=500,
                content={
                    "error": "PIPELINE_ERROR",
                    "message": "Message processing failed.",
                },
            )

        if not isinstance(result, HandlerResult):
            return JSONResponse(
                status_code=500,
                content={
                    "error": "PIPELINE_ERROR",
                    "message": "Message processing failed.",
                },
            )

        if not result.accepted:
            return self._handler_rejection_response(result)

        if isinstance(result.response, dict):
            return result.response
        return {"accepted": True, "code": result.code, "detail": result.detail}

    @staticmethod
    def _security_response(rejection: SecurityRejection) -> JSONResponse:
        """Return only the stable public security contract."""
        return JSONResponse(
            status_code=rejection.http_status,
            content=rejection.to_public_dict(),
        )

    @classmethod
    def _handler_rejection_response(cls, result: HandlerResult) -> JSONResponse:
        """Translate worker results without trusting arbitrary handler payloads."""
        try:
            code = ReasonCode(result.code)
        except ValueError:
            code = None
        if code is not None:
            return cls._security_response(SecurityRejection(code))

        try:
            mapping_code = MappingErrorCode(result.code)
        except ValueError:
            mapping_code = None
        if mapping_code is not None:
            return JSONResponse(
                status_code=MappingError(mapping_code).http_status,
                content=MappingError(mapping_code).to_public_dict(),
            )

        if result.code == "PIPELINE_NOT_CONFIGURED":
            return JSONResponse(
                status_code=503,
                content={
                    "error": "PIPELINE_NOT_CONFIGURED",
                    "message": "Guardian processing is not ready.",
                },
            )
        if result.code == "QUEUE_FULL":
            return JSONResponse(
                status_code=503,
                content={
                    "error": "QUEUE_FULL",
                    "message": "Guardian processing is temporarily unavailable.",
                },
            )
        if result.code == "PROCESSING_TIMEOUT":
            return JSONResponse(
                status_code=504,
                content={
                    "error": "PROCESSING_TIMEOUT",
                    "message": "Guardian processing timed out.",
                },
            )
        return JSONResponse(
            status_code=result.http_status if result.http_status >= 400 else 500,
            content={
                "error": "PIPELINE_ERROR",
                "message": "Message processing failed.",
            },
        )

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
