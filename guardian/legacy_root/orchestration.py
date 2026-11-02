import logging

from dataclasses import dataclass
from typing import Any, Callable

from guardian.adapters.communication.base import (
    IncomingMessage,
    HandlerResult
)

logger = logging.getLogger(__name__)


class MessageRejected(Exception):

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PipelineStages:

    precheck: Callable[[IncomingMessage], None]

    normalize: Callable[[IncomingMessage], Any]

    validate: Callable[[Any], None]

    process: Callable[[Any], HandlerResult]

    audit: Callable[
        [IncomingMessage, HandlerResult], None
    ] | None = None


class GuardianPipeline:

    def __init__(
        self,
        stages: PipelineStages | None = None
    ):
        self.stages = stages

    def process_message(
        self,
        message: IncomingMessage
    ) -> HandlerResult:

        if self.stages is None:
            return HandlerResult(
                accepted=False,
                code="PIPELINE_NOT_CONFIGURED",
                detail=(
                    "Security and processing stages "
                    "are not connected"
                )
            )

        try:
            # 1. Security boundary
            self.stages.precheck(message)

            # 2. Contract adaptation
            event = self.stages.normalize(message)

            # 3. Canonical validation
            self.stages.validate(event)

            # 4. Guardian Core
            result = self.stages.process(event)

            if not isinstance(result, HandlerResult):
                raise TypeError(
                    "Core processor must return HandlerResult"
                )

        except MessageRejected as exc:
            result = HandlerResult(
                accepted=False,
                code=exc.code,
                detail=exc.detail
            )

        except Exception:
            logger.exception("Guardian pipeline failed")

            result = HandlerResult(
                accepted=False,
                code="INTERNAL_ERROR",
                detail="Processing failed"
            )

        # 5. Audit
        if self.stages.audit is not None:
            try:
                self.stages.audit(message, result)
            except Exception:
                logger.exception("Guardian audit failed")

        return result