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
   - Événement 3 : ISOLATED (si action == ISOLATE, blocage explicite) OU SENT_TO_BRAIN (si action != ISOLATE)
   Aucune branche aveugle : le jury voit toujours l'aboutissement effectif de la décision.
3. Horodatage unifié : Utilisation systématique de get_utc_now() (ISO 8601 UTC).
4. Respect strict des contrats : Noms de classes, méthodes et dépendances injectées conservés.
"""

import uuid
from typing import Any

from guardian.audit.logger import log_event
from guardian.audit.timeline import get_utc_now, timeline_manager


class GuardianPipeline:
    """
    Orchestre le flux de traitement des données à travers la couche Guardian (R3).
    Garantit la traçabilité de chaque étape de la couche Twin vers le City Brain.
    """

    def __init__(
        self,
        security,
        contract,
        event_store,
        anomaly_detector,
        trust_assessor,
        containment,
        output_adapter
    ):
        self.security = security
        self.contract = contract
        self.store = event_store
        self.detector = anomaly_detector
        self.assessor = trust_assessor
        self.containment = containment
        self.output = output_adapter
        self.timeline = timeline_manager

    async def process_incoming(self, raw_message: dict[str, Any], logger: Any) -> dict[str, Any]:
        """
        Traite un message de capteur entrant avec diffusion temps réel de chaque étape.
        Garantit que le jury peut corréler la cause et l'effet via l'event_id.
        """
        # Garantir un identifiant de corrélation unique pour la session d'audit
        event_id = raw_message.get("event_id") or f"EVT-{uuid.uuid4().hex[:8].upper()}"
        sensor_id = raw_message.get("sensor_id", "unknown_sensor")

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
        canonical_msg = self.contract.map_to_canonical(raw_message)
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
            if hasattr(self.output, "send_to_brain"):
                res = self.output.send_to_brain(result_payload)
                if hasattr(res, "__await__"):
                    await res
            await self.timeline.broadcast({
                "timestamp": get_utc_now(),
                "event_id": event_id,
                "layer": "CITY_BRAIN_LAYER",
                "stage": "SENT_TO_BRAIN",
                "sensor_id": sensor_id,
                "status": "DELIVERED",
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
                "stage": "ISOLATED",
                "sensor_id": sensor_id,
                "status": "BLOCKED",
                "action": "ISOLATE",
                "reason": final_reason,
                "details": "Attaque ou anomalie détectée : flux isolé, le City Brain reste protégé"
            })

        return result_payload

