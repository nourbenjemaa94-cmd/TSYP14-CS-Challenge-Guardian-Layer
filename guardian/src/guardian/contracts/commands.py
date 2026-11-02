"""Containment request and outcome: requesting isolation != confirmed application."""
from typing import Literal

from pydantic import BaseModel, ConfigDict


class ContainmentCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    command_id: str
    event_id: str
    target: str
    action: Literal["ISOLATE", "QUARANTINE", "RELEASE", "ROLLBACK", "RESTORE"]
    reason: str
    idempotency_key: str


class ContainmentOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    command_id: str
    status: Literal["REQUESTED", "ACCEPTED", "APPLIED", "FAILED", "NOOP"]
    remote_confirmed: bool = False
    detail: str = ""
