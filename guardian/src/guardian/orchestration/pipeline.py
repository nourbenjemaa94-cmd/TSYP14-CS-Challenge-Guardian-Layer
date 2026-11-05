"""
orchestration/pipeline.py
-------------------------
Orchestre le flux de traitement des données à travers la couche Guardian (Member 4: Ghaith Mnasri).

Améliorations apportées :
1. Corrélation de bout en bout (event_id garanti) : Si le message entrant n'a pas d'event_id,
   un identifiant unique traçable (EVT-...) est généré et propagé à tous les événements.
2. Chaîne causale complète (Lecture -> Verdict -> Décision -> Action) :
   - Événement 1 : READING_RECEIVED (données canoniques validées après contrat)
   - Événement 2 : GUARDIAN_VERDICT (verdict de confiance, anomalies détectées, règle de confinement)
   - Événement 3 : ISOLATED après confirmation du port, LOCAL_FORWARD_BLOCKED
     sans port, OU SENT_TO_BRAIN si action != ISOLATE
   Aucune branche aveugle : le jury voit toujours l'aboutissement effectif de la décision.
3. Horodatage unifié : Utilisation systématique de get_utc_now() (ISO 8601 UTC).
4. Respect strict des contrats : Noms de classes, méthodes et dépendances injectées conservés.
"""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from guardian.adapters.contract.errors import MappingError, MappingErrorCode
from guardian.adapters.contract.mapper import GenericMapper
from guardian.adapters.contract.registry import ProfileRegistry
from guardian.audit.logger import log_event, log_onboarding
from guardian.audit.timeline import get_utc_now, timeline_manager
from guardian.contracts.commands import ContainmentCommand, ContainmentOutcome
from guardian.core.anomaly_detector import AnomalyDetector
from guardian.core.containment import ISOLATE, ISOLATED, REQUESTED, ContainmentEngine
from guardian.core.trust_assessor import TrustAssessor
from guardian.security.errors import SecurityRejection
from guardian.security.gate import SecurityGate
from guardian.security.validation import validate_envelope


@dataclass(frozen=True)
class TransportContext:
    """Validated adapter protocol kept separate from the signed envelope.

    The live registry currently exposes only MQTT and REST. A missing context
    uses the internal REST default for backward-compatible direct calls.
    """

    transport: Literal["mqtt", "rest"]
    source: str | None = None
    metadata: dict[str, str | None] = field(default_factory=dict)
    received_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if self.transport not in {"mqtt", "rest"}:
            raise ValueError("transport must be one of: mqtt, rest")


class SecurityPort(Protocol):
    """Security dependency owned by the application composition root."""

    def admit(self, raw: bytes, operation: str) -> Any: ...

    def accept(self, admitted: Any, canonical: dict[str, Any]) -> Any: ...


class ContractPort(Protocol):
    """Contract dependency owned by the application composition root."""

    def map_message(self, message: dict[str, Any], profile: Any, source_adapter: str) -> list[Any]: ...


class OutputPort(Protocol):
    async def send_to_brain(self, payload: dict[str, Any]) -> bool: ...


class GuardianPipeline:
    """
    Orchestre le flux de traitement des données à travers la couche Guardian (R3).
    Garantit la traçabilité de chaque étape de la couche Twin vers le City Brain.
    """

    def __init__(
        self,
        security: SecurityPort,
        contract: ContractPort,
        event_store,
        anomaly_detector,
        trust_assessor,
        containment,
        output_adapter: OutputPort,
        *,
        mapping_profile: Any | None = None,
        mapping_profiles: dict[str, Any] | None = None,
        profile_registry: ProfileRegistry | None = None,
        forward_to_brain: bool = True,
        onboarding: Any | None = None,
    ):
        self.security = security
        self.contract = contract
        # Gatekeeper mode forwards non-isolated verdicts; observer mode only
        # stores them (GUARDIAN_FORWARD_TO_BRAIN=false) for the Brain to pull.
        self.forward_to_brain = forward_to_brain
        # EventStore and TimelineManager are process-local read models. They
        # are not durable evidence stores and must not be described as such.
        self.store = event_store
        self.detector = anomaly_detector
        self.assessor = trust_assessor
        self.containment = containment
        self.output = output_adapter
        self.mapping_profile = mapping_profile
        self.mapping_profiles = mapping_profiles or {}
        self.profile_registry = profile_registry
        self.onboarding = onboarding
        self.timeline = timeline_manager
        self._confirmed_isolations: set[str] = set()

    async def process_incoming(
        self,
        raw_message: dict[str, Any] | bytes,
        logger: Any,
        *,
        transport_context: TransportContext | None = None,
    ) -> dict[str, Any]:
        """
        Traite un message de capteur entrant avec diffusion temps réel de chaque étape.
        Garantit que le jury peut corréler la cause et l'effet via l'event_id.
        """
        # Garantir un identifiant de corrélation unique pour la session d'audit
        if isinstance(self.security, SecurityGate):
            return await self._process_secure(raw_message, logger, transport_context)

        # Test-only injected ports use the original in-memory contract. Production
        # composition never reaches this branch: it injects SecurityGate.
        event_id = raw_message.get("event_id") or f"EVT-{uuid.uuid4().hex[:8].upper()}"  # type: ignore[union-attr]
        sensor_id = raw_message.get("sensor_id", "unknown_sensor")  # type: ignore[union-attr]

        # -------------------------------------------------------------
        # Étape 1 : Sécurité & Validation Préliminaire (Layer 2 - Auth)
        # -------------------------------------------------------------
        if not self.security.validate(raw_message):
            log_event(logger, event_id, "SECURITY_CHECK", "UNTRUSTED", "AUTH_FAILED")
            await self.timeline.broadcast({
                "timestamp": get_utc_now(),
                "event_id": event_id,
                "layer": "GUARDIAN_LAYER",
                "stage": "SECURITY_REJECTED",
                "sensor_id": sensor_id,
                "status": "REJECTED",
                "reason": "AUTH_FAILED",
                "details": "Échec de validation de sécurité (authentification ou signature invalide)"
            })
            return {"status": "REJECTED", "reason": "SECURITY", "event_id": event_id}

        # -------------------------------------------------------------
        # Étape 2 : Adaptation de Contrat & Normalisation (Layer 2 - Contract)
        # -------------------------------------------------------------
        mapped = self.contract.map_message(raw_message, None, "test")
        canonical_msg = mapped if isinstance(mapped, dict) else mapped[0].to_sensor_event().to_core_dict()
        canonical_msg["event_id"] = event_id  # Assure la cohérence de l'identifiant

        # Diffusion de la réception : Le mapping garantit des unités et métriques canoniques
        # (ex: m -> cm, "levelOfWater" -> "water_level") interprétables par le jury.
        await self.timeline.broadcast({
            "timestamp": get_utc_now(),
            "event_id": event_id,
            "layer": "TWIN_TO_GUARDIAN",
            "stage": "READING_RECEIVED",
            "sensor_id": sensor_id,
            "metric": canonical_msg.get("metric", "unknown_metric"),
            "value": canonical_msg.get("value"),
            "unit": canonical_msg.get("unit"),
            "raw_input": {k: v for k, v in raw_message.items() if k not in ("token", "signature")}
        })

        # -------------------------------------------------------------
        # Étape 3 : Détection d'Anomalies (Layer 2 - Core Detector)
        # -------------------------------------------------------------
        history = self.store.get_history(canonical_msg["sensor_id"])
        flags = self.detector.detect(canonical_msg, history)

        # -------------------------------------------------------------
        # Étape 4 : Évaluation de la Confiance (Layer 2 - Trust Assessor)
        # -------------------------------------------------------------
        verdict, trust_reason = self.assessor.assess(canonical_msg, flags)

        # -------------------------------------------------------------
        # Étape 5 : Moteur de Confinement (Layer 2 - Containment Policy)
        # -------------------------------------------------------------
        action = self.containment.evaluate_action(flags, verdict)

        # -------------------------------------------------------------
        # Étape 6 : Persistance dans le Store & Journalisation d'audit
        # -------------------------------------------------------------
        self.store.add_reading(canonical_msg["sensor_id"], canonical_msg)

        final_reason = trust_reason if trust_reason else ("ANOMALY_DETECTED" if flags else "NORMAL")
        log_event(
            logger,
            event_id,
            "TRUST_ASSESSMENT",
            verdict,
            final_reason,
            action=action,
            anomaly_flags=flags
        )

        # Diffusion du verdict du Guardian au jury
        await self.timeline.broadcast({
            "timestamp": get_utc_now(),
            "event_id": event_id,
            "layer": "GUARDIAN_CORE",
            "stage": "GUARDIAN_VERDICT",
            "sensor_id": sensor_id,
            "verdict": verdict,                # "TRUSTED" ou "UNTRUSTED"
            "reason": final_reason,            # Ex: "ANOMALY_DETECTED", "OUT_OF_BOUNDS", "NORMAL"
            "action": action,                  # Ex: "ISOLATE", "FORWARD", "QUARANTINE"
            "anomaly_flags": flags
        })

        # -------------------------------------------------------------
        # Étape 7 : Action de Confinement ou Envoi au City Brain
        # -------------------------------------------------------------
        result_payload = {
            **canonical_msg,
            "event_id": event_id,
            "trust_verdict": verdict,
            "reason": final_reason,
            "containment_action": action
        }

        if action != "ISOLATE":
            # Transmission autorisée au City Brain
            forward_status = await self._forward(result_payload, logger, event_id, sensor_id)
            result_payload["forward_status"] = forward_status
            await self.timeline.broadcast({
                "timestamp": get_utc_now(),
                "event_id": event_id,
                "layer": "CITY_BRAIN_LAYER",
                "stage": forward_status,
                "sensor_id": sensor_id,
                "status": "DELIVERED" if forward_status == "FORWARD_CONFIRMED" else "FAILED",
                "action": action,
                "destination": "CITY_BRAIN",
                "details": "Donnée certifiée conforme transmise au système d'aide à la décision urbaine"
            })
        else:
            # Confinement actif : la donnée suspecte est bloquée à la frontière du Guardian
            await self.timeline.broadcast({
                "timestamp": get_utc_now(),
                "event_id": event_id,
                "layer": "GUARDIAN_CONTAINMENT",
                "stage": "LOCAL_FORWARD_BLOCKED",
                "sensor_id": sensor_id,
                "status": "BLOCKED",
                "action": "ISOLATE",
                "reason": final_reason,
                "details": "Aucun port de confinement ; transfert local bloqué uniquement.",
            })
            result_payload["containment_status"] = "LOCAL_FORWARD_BLOCKED"
            result_payload["isolation_confirmed"] = False

        return result_payload

    async def _forward(
        self, payload: dict[str, Any], logger: Any, event_id: str, sensor_id: str
    ) -> str:
        """Send once and return a delivery state without claiming success early."""
        await self.timeline.broadcast({
            "timestamp": get_utc_now(), "event_id": event_id,
            "layer": "CITY_BRAIN_LAYER", "stage": "FORWARD_REQUESTED",
            "sensor_id": sensor_id, "status": "REQUESTED", "destination": "CITY_BRAIN",
        })
        try:
            result = self.output.send_to_brain(payload)
            sent = await result if hasattr(result, "__await__") else result
        except Exception as exc:
            sent = False
            if logger and hasattr(logger, "warning"):
                logger.warning("[AUDIT] brain forward failed event_id=%s error=%s", event_id, type(exc).__name__)
        return "FORWARD_CONFIRMED" if sent is True else "FORWARD_FAILED"

    async def _process_secure(
        self,
        raw_message: dict[str, Any] | bytes,
        logger: Any,
        transport_context: TransportContext | None,
    ) -> dict[str, Any]:
        """Run the fail-closed order: admit, envelope, map, accept, then core."""
        if not isinstance(raw_message, bytes):
            raise TypeError("The production security entry point requires raw bytes")

        try:
            admitted = self.security.admit(raw_message, "publish_reading")
            envelope = validate_envelope(
                admitted.body,
                schema_major=self.security.settings.schema_major,
                allowed_types=self.security.settings.allowed_types,
            )
            canonical_envelope = envelope.model_dump(exclude_none=True)
            if isinstance(admitted.body.get("schema_id"), str):
                canonical_envelope["schema_id"] = admitted.body["schema_id"]
            if not isinstance(self.contract, GenericMapper):
                raise RuntimeError("Production pipeline requires GenericMapper")
            selected_record = None
            if self.profile_registry is not None:
                try:
                    selected_record = self.profile_registry.select_record(
                        twin_identity=admitted.partner_identity,
                        event_type=canonical_envelope.get("type", ""),
                        schema_id=(
                            admitted.body.get("schema_id")
                            if isinstance(admitted.body.get("schema_id"), str)
                            else None
                        ),
                        schema_version=(
                            admitted.body.get("schema_version")
                            if isinstance(admitted.body.get("schema_version"), str)
                            else None
                        ),
                        event_id=canonical_envelope.get("event_id"),
                    )
                    profile = selected_record.profile
                except MappingError as exc:
                    if exc.code is MappingErrorCode.UNKNOWN_SCHEMA and self.onboarding is not None:
                        fingerprint = self.onboarding.submit(
                            canonical_envelope,
                            twin_identity=admitted.partner_identity,
                        )
                        raise MappingError(
                            MappingErrorCode.ONBOARDING_PENDING,
                            event_id=canonical_envelope.get("event_id"),
                            fingerprint=fingerprint,
                        ) from exc
                    raise
            else:
                profile = (
                    self.mapping_profiles.get(canonical_envelope.get("type"))
                    if self.mapping_profiles
                    else self.mapping_profile
                )
            if profile is None:
                if self.onboarding is not None:
                    fingerprint = self.onboarding.submit(
                        canonical_envelope,
                        twin_identity=admitted.partner_identity,
                    )
                    raise MappingError(
                        MappingErrorCode.ONBOARDING_PENDING,
                        event_id=canonical_envelope.get("event_id"),
                        fingerprint=fingerprint,
                    )
                raise MappingError(
                    MappingErrorCode.UNKNOWN_SCHEMA,
                    event_id=canonical_envelope.get("event_id"),
                )
            source_adapter = transport_context.transport if transport_context is not None else "rest"
            profile_status = selected_record.status if selected_record is not None else "ACTIVE"
            try:
                events = self.contract.map_message(
                    canonical_envelope, profile, source_adapter, profile_status=profile_status
                )
            except MappingError:
                self._reset_probation(selected_record)
                raise
            accepted = self.security.accept(admitted, canonical_envelope)
        except SecurityRejection as exc:
            self._audit_security_rejection(logger, exc, transport_context)
            raise
        except MappingError as exc:
            self._audit_mapping_rejection(logger, exc, transport_context)
            raise

        if not events:
            raise MappingError(MappingErrorCode.UNMAPPABLE_SCHEMA, event_id=accepted.event_id)
        if any(event.kind != "measurement" for event in events):
            kind = next(event.kind for event in events if event.kind != "measurement")
            return {
                "status": "UNSUPPORTED_CORE_EVENT_KIND",
                "event_id": accepted.event_id,
                "kind": kind,
                "detail": "Event accepted by Guardian but not supported by the numeric Core.",
            }

        results = [
            await self._process_canonical(event.to_sensor_event().to_core_dict(), logger, event.event_id)
            for event in events
        ]
        self._advance_probation(selected_record, logger)
        return results[0] if len(results) == 1 else {
            "status": "ACCEPTED",
            "event_id": accepted.event_id,
            "events": results,
        }

    @staticmethod
    def _audit_security_rejection(
        logger: Any,
        rejection: SecurityRejection,
        transport_context: TransportContext | None,
    ) -> None:
        """Record rejection code and transport without logging body or secrets."""
        if not logger:
            return
        context = transport_context.transport if transport_context else "unknown"
        log_event(
            logger,
            rejection.event_id or "security-rejection",
            "SECURITY_REJECTED",
            "REJECTED",
            rejection.code.value,
            action=context,
        )

    @staticmethod
    def _audit_mapping_rejection(
        logger: Any,
        rejection: MappingError,
        transport_context: TransportContext | None,
    ) -> None:
        if not logger:
            return
        context = transport_context.transport if transport_context else "unknown"
        log_event(
            logger,
            rejection.event_id or "mapping-rejection",
            "CONTRACT_REJECTED",
            "REJECTED",
            rejection.code.value,
            action=context,
        )

    async def _process_canonical(
        self, canonical_msg: dict[str, Any], logger: Any, event_id: str
    ) -> dict[str, Any]:
        """Run the existing core/audit stages after secure contract handoff."""
        sensor_id = canonical_msg["sensor_id"]
        await self.timeline.broadcast({
            "timestamp": get_utc_now(), "event_id": event_id, "layer": "TWIN_TO_GUARDIAN",
            "stage": "READING_RECEIVED", "sensor_id": sensor_id,
            "metric": canonical_msg.get("metric"), "value": canonical_msg.get("value"),
            "unit": canonical_msg.get("unit"),
        })
        real_core = (
            isinstance(self.detector, AnomalyDetector)
            and isinstance(self.assessor, TrustAssessor)
            and isinstance(self.containment, ContainmentEngine)
        )
        if real_core:
            detection = self.detector.analyze(canonical_msg)
            trust_verdict = self.assessor.evaluate(detection)
            flags = list(detection.codes)
            verdict = trust_verdict.verdict
            trust_reason = trust_verdict.reason or trust_verdict.reason_code
            containment_report = self.containment.contain(trust_verdict)
            action = containment_report.reading_action
        else:
            history = self.store.get_history(sensor_id)
            flags = self.detector.detect(canonical_msg, history)
            verdict, trust_reason = self.assessor.assess(canonical_msg, flags)
            action = self.containment.evaluate_action(flags, verdict)
        self.store.add_reading(sensor_id, canonical_msg)
        final_reason = trust_reason if trust_reason else ("ANOMALY_DETECTED" if flags else "NORMAL")
        if real_core:
            verdict_record = trust_verdict.to_dict()
        else:
            verdict_record = {
                "event_id": event_id,
                "sensor_id": sensor_id,
                "verdict": verdict,
                "reason": final_reason,
                "reason_code": final_reason,
                "containment_action": action,
            }
        if hasattr(self.store, "record_verdict"):
            self.store.record_verdict(event_id, verdict_record)
        log_event(logger, event_id, "TRUST_ASSESSMENT", verdict, final_reason, action=action, anomaly_flags=flags)
        log_event(logger, event_id, "GUARDIAN_VERDICT", verdict, final_reason, action=action, anomaly_flags=flags)
        result_payload = {**canonical_msg, "event_id": event_id, "trust_verdict": verdict,
                          "reason": final_reason, "containment_action": action}
        if action != "ISOLATE" and not self.forward_to_brain:
            # Observer mode: the verdict is persisted above and served on request.
            result_payload["forward_status"] = "STORED"
            await self.timeline.broadcast({"timestamp": get_utc_now(), "event_id": event_id,
                "layer": "GUARDIAN_AUDIT", "stage": "VERDICT_STORED", "sensor_id": sensor_id,
                "status": "STORED", "action": action, "destination": "EVENT_STORE"})
        elif action != "ISOLATE":
            forward_status = await self._forward(result_payload, logger, event_id, sensor_id)
            result_payload["forward_status"] = forward_status
            await self.timeline.broadcast({"timestamp": get_utc_now(), "event_id": event_id,
                "layer": "CITY_BRAIN_LAYER", "stage": forward_status, "sensor_id": sensor_id,
                "status": "DELIVERED" if forward_status == "FORWARD_CONFIRMED" else "FAILED",
                "action": action, "destination": "CITY_BRAIN"})
        else:
            # A local forwarding block is immediate and independent from remote
            # containment.  ISOLATED is emitted only after the real Core report
            # carries a verified remote acknowledgement and confirmed state.
            if real_core:
                containment_status = await self._handle_containment(
                    containment_report, logger, event_id, sensor_id, final_reason
                )
                result_payload["containment_status"] = containment_status
                result_payload["isolation_confirmed"] = containment_status == "APPLIED"
            else:
                result_payload["containment_status"] = "LOCAL_FORWARD_BLOCKED"
                result_payload["isolation_confirmed"] = False
                await self.timeline.broadcast({"timestamp": get_utc_now(), "event_id": event_id,
                    "layer": "GUARDIAN_CONTAINMENT", "stage": "LOCAL_FORWARD_BLOCKED",
                    "sensor_id": sensor_id, "status": "BLOCKED", "action": "ISOLATE",
                    "reason": final_reason,
                    "details": "Aucun port de confinement ; transfert local bloqué uniquement.",})
        return result_payload

    async def _handle_containment(
        self, report: Any, logger: Any, event_id: str, sensor_id: str, reason: str
    ) -> str:
        """Audit a Core containment report without confusing request and effect."""
        actions = tuple(report.actions)
        if not actions:
            if sensor_id in self._confirmed_isolations and report.state_after == ISOLATED:
                await self.timeline.broadcast({
                    "timestamp": get_utc_now(), "event_id": event_id,
                    "layer": "GUARDIAN_CONTAINMENT", "stage": "ISOLATED",
                    "sensor_id": sensor_id, "status": "BLOCKED", "action": ISOLATE,
                    "reason": reason, "details": "Isolation distante déjà confirmée.",
                })
                return "APPLIED"
            return REQUESTED

        port_configured = getattr(self.containment, "port", None) is not None
        final_status = REQUESTED
        for action in actions:
            command = ContainmentCommand(
                command_id=action.action_id,
                event_id=action.event_id or event_id,
                target=action.target,
                action=action.action,
                reason=action.reason,
                idempotency_key=action.idempotency_key,
            )

            # ContainmentEngine reports a local APPLIED state when no command
            # port exists.  At the application boundary that is only a request.
            if not port_configured:
                outcome = ContainmentOutcome(
                    command_id=command.command_id, status=REQUESTED,
                    remote_confirmed=False, detail="NO_CONTAINMENT_PORT",
                )
                statuses = (REQUESTED,)
            else:
                status = (
                    action.status
                    if action.status in {"REQUESTED", "ACCEPTED", "APPLIED", "FAILED", "NOOP"}
                    else "FAILED"
                )
                outcome = ContainmentOutcome(
                    command_id=command.command_id, status=status,
                    remote_confirmed=action.remote_confirmed,
                    detail=action.error or "",
                )
                statuses = action.lifecycle or (status,)

            for status in statuses:
                await self.timeline.broadcast({
                    "timestamp": get_utc_now(), "event_id": event_id,
                    "layer": "GUARDIAN_CONTAINMENT", "stage": f"CONTAINMENT_{status}",
                    "sensor_id": sensor_id, "status": status, "action": action.action,
                    "command": command.model_dump(), "outcome": outcome.model_dump(),
                })
            final_status = outcome.status

            if (
                outcome.status == "APPLIED"
                and outcome.remote_confirmed
                and report.state_after == ISOLATED
                and action.action == ISOLATE
            ):
                self._confirmed_isolations.add(sensor_id)
                await self.timeline.broadcast({
                    "timestamp": get_utc_now(), "event_id": event_id,
                    "layer": "GUARDIAN_CONTAINMENT", "stage": "ISOLATED",
                    "sensor_id": sensor_id, "status": "BLOCKED", "action": ISOLATE,
                    "reason": reason, "details": "Acquittement distant et état confirmé.",
                })
                return "APPLIED"

            # A partner may acknowledge a command while the resulting state is
            # not actually isolated.  Keep the local block and fail closed.
            if outcome.status == "APPLIED" and report.state_after != ISOLATED:
                final_status = "FAILED"
                await self.timeline.broadcast({
                    "timestamp": get_utc_now(), "event_id": event_id,
                    "layer": "GUARDIAN_CONTAINMENT", "stage": "CONTAINMENT_FAILED",
                    "sensor_id": sensor_id, "status": "FAILED", "action": action.action,
                    "command": command.model_dump(), "outcome": {
                        **outcome.model_dump(), "status": "FAILED",
                        "detail": "INCONSISTENT_CONFIRMED_STATE",
                    },
                })
        return final_status

    def _probation_threshold(self) -> int:
        if self.onboarding is not None:
            return int(self.onboarding.settings.probation_messages)
        return 20

    def _reset_probation(self, record: Any) -> None:
        if record is None or self.profile_registry is None or record.status != "PROBATION":
            return
        self.profile_registry.reset_clean_map(record.fingerprint)

    def _advance_probation(self, record: Any, logger: Any) -> None:
        if record is None or self.profile_registry is None or record.status != "PROBATION":
            return
        updated = self.profile_registry.note_clean_map(record.fingerprint, self._probation_threshold())
        if updated.status == "ACTIVE":
            log_onboarding(logger, "PROFILE_ACTIVE", updated.fingerprint)

    def _probation_for_profile(self, profile: Any) -> Any:
        if self.profile_registry is None:
            return None
        return self.profile_registry.find_probation(profile)

    async def process_mapped(self, envelope: dict[str, Any], profile: Any, logger: Any = None) -> dict[str, Any]:
        """Replay a buffered envelope through map + core after onboarding succeeds."""
        if not isinstance(self.contract, GenericMapper):
            raise RuntimeError("Production pipeline requires GenericMapper")
        record = self._probation_for_profile(profile)
        status = record.status if record is not None else "ACTIVE"
        try:
            events = self.contract.map_message(envelope, profile, "onboarding", profile_status=status)
        except MappingError:
            self._reset_probation(record)
            raise
        if not events:
            raise MappingError(MappingErrorCode.UNMAPPABLE_SCHEMA, event_id=envelope.get("event_id"))
        results = [
            await self._process_canonical(event.to_sensor_event().to_core_dict(), logger, event.event_id)
            for event in events
            if event.kind == "measurement"
        ]
        self._advance_probation(record, logger)
        return results[0] if results else {"status": "SKIPPED"}

