"""Wire contract reflecting the richer existing core.trust_assessor.TrustVerdict."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class TrustVerdictMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    event_id: str
    sensor_id: str
    verdict: Literal["TRUSTED", "SUSPICIOUS", "UNTRUSTED"]
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    reason_code: str
    reason: str
    score: float = Field(ge=0, le=1, allow_inf_nan=False)
    assessment_id: str
    policy_version: str
    timestamp: str
    evidence: list[dict[str, str]] = Field(default_factory=list)
