from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Protocol


@dataclass(frozen=True)
class IncomingMessage:
    payload: bytes
    transport: str
    source: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    received_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@dataclass(frozen=True)
class HandlerResult:
    accepted: bool
    code: str
    detail: str = ""


MessageHandler = Callable[[IncomingMessage], HandlerResult]


class CommunicationAdapter(Protocol):
    def start(self) -> None: ...
    def stop(self) -> None: ...