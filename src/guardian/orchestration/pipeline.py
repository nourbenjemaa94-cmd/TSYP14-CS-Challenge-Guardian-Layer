"""Inbound order: admit, map, accept, then the core.

Rejections are audited and re-raised so the adapter can build the public
error. Replay and rate-limit state stay inside the gate.

TODO(security): ASSUMPTION — if the core has no ``on_security_signal`` hook,
a flood is audited as ``FLOOD_SUSPECTED`` and nothing else is called.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from guardian.adapters.contract.mapper import IdentityContractMapper
from guardian.audit.logger import AuditLogger
from guardian.orchestration.outbound import OutboundSigner
from guardian.security.errors import ReasonCode, SecurityRejection, WarningCode
from guardian.security.freshness import format_timestamp
from guardian.security.gate import SecurityGate

_SIGNED_RESPONSE_TYPES = {
    "request_verdict": "trust_verdict",
    "get_device_status": "device_status",
}


@dataclass(frozen=True)
class InboundResult:
    envelope: dict[str, Any]
    warnings: tuple[WarningCode, ...]
    core_result: dict[str, Any]
    response_envelope: dict[str, Any] | None
    event_id: str


class Pipeline:
    """One pass over a raw partner message."""

    def __init__(
        self,
        *,
        gate: SecurityGate,
        mapper: IdentityContractMapper,
        core: Any,
        audit: AuditLogger,
        signer: OutboundSigner,
        clock: Callable[[], datetime],
    ) -> None:
        self.gate = gate
        self.mapper = mapper
        self.core = core
        self.audit = audit
        self.signer = signer
        self.clock = clock

    def process_inbound(self, raw: bytes, operation: str) -> InboundResult:
        try:
            admitted = self.gate.admit(raw, operation)
        except SecurityRejection as exc:
            self._audit_rejection(exc, stage="security.admit", operation=operation)
            self._maybe_flood(exc, operation)
            raise

        try:
            canonical = self.mapper.normalize(admitted.body, operation)
            accepted = self.gate.accept(admitted, canonical)
        except SecurityRejection as exc:
            if exc.event_id is None:
                exc.event_id = admitted.event_id
            if exc.source is None:
                exc.source = admitted.source_key
            self._audit_rejection(exc, stage="security.accept", operation=operation)
            raise

        for warning in accepted.warnings:
            self.audit.record(
                timestamp=self._timestamp(),
                stage="security.accept",
                outcome="accepted_with_warning",
                code=warning.value,
                event_id=accepted.event_id,
                source=accepted.source_key,
                operation=operation,
            )

        core_result = self.core.handle(accepted.envelope, list(accepted.warnings))
        if not isinstance(core_result, dict):
            raise RuntimeError("Core result must be an object.")
        response = self._maybe_sign_response(operation, accepted.envelope, core_result)
        return InboundResult(
            envelope=accepted.envelope,
            warnings=accepted.warnings,
            core_result=core_result,
            response_envelope=response,
            event_id=accepted.event_id,
        )

    def _maybe_sign_response(
        self,
        operation: str,
        envelope: dict[str, Any],
        core_result: dict[str, Any],
    ) -> dict[str, Any] | None:
        if operation not in _SIGNED_RESPONSE_TYPES:
            return None
        payload = core_result.get("payload")
        if not isinstance(payload, dict):
            raise RuntimeError("Core payload must be an object.")
        message_type = core_result.get("type")
        if not isinstance(message_type, str):
            message_type = _SIGNED_RESPONSE_TYPES[operation]
        zone_id = core_result.get("zone_id")
        if not isinstance(zone_id, str):
            zone_id = envelope.get("zone_id") if isinstance(envelope.get("zone_id"), str) else None
        return self.signer.sign(message_type=message_type, payload=payload, zone_id=zone_id)

    def _maybe_flood(self, exc: SecurityRejection, operation: str) -> None:
        if exc.code is not ReasonCode.RATE_LIMITED:
            return
        for source in self.gate.flooding_sources():
            event_id = exc.event_id if source == exc.source else None
            self.audit.record(
                timestamp=self._timestamp(),
                stage="security.admit",
                outcome="signal",
                code="FLOOD_SUSPECTED",
                event_id=event_id,
                source=source,
                operation=operation,
            )
            hook = getattr(self.core, "on_security_signal", None)
            if callable(hook):
                hook("FLOOD_SUSPECTED", source)

    def _audit_rejection(self, exc: SecurityRejection, *, stage: str, operation: str) -> None:
        self.audit.record(
            timestamp=self._timestamp(),
            stage=stage,
            outcome="rejected",
            code=exc.code.value,
            event_id=exc.event_id,
            source=exc.source,
            operation=operation,
        )

    def _timestamp(self) -> str:
        return format_timestamp(self.clock())
