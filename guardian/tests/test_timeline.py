"""
tests/test_timeline.py
----------------------
Script de test automatisé (pytest / Starlette TestClient) pour la validation R3 de la chronologie temps réel.

Vérifie l'exigence R3 :
1. Connexion au WebSocket /ws/timeline.
2. Ingestion du scénario d'attaque 'fake_flood' (valeur anormale sur le capteur S01).
3. Contrôle strict de l'ordre de causalité :
   - Événement 1 : READING_RECEIVED
   - Événement 2 : GUARDIAN_VERDICT (UNTRUSTED / ISOLATE)
   - Événement 3 : ISOLATED (status: BLOCKED)
4. Vérification de la transmission autorisée (SENT_TO_BRAIN) en cas de donnée saine.
5. Vérification de la corrélation via le même event_id sur l'ensemble de la chaîne cause-effet.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from fastapi.testclient import TestClient

from guardian.audit.timeline import timeline_manager
from guardian.main import app
from guardian.orchestration.pipeline import GuardianPipeline


# ---------------------------------------------------------------------------
# Mocks des composants Guardian selon l'architecture du diagramme
# ---------------------------------------------------------------------------
class MockSecurity:
    def validate(self, raw_message: dict) -> bool:
        # Rejette si token explicite 'invalid'
        return raw_message.get("token") != "invalid"


class MockContract:
    def map_to_canonical(self, raw_message: dict) -> dict:
        # Convertit m en cm comme décrit sur le schéma d'architecture
        raw_val = raw_message.get("levelOfWater", raw_message.get("value", 0))
        unit = raw_message.get("unit", "m")
        val_cm = raw_val * 100 if unit == "m" else raw_val
        return {
            "sensor_id": raw_message.get("sensor_id", "S01"),
            "metric": "water_level",
            "value": val_cm,
            "unit": "cm",
            "timestamp": "2026-10-20T10:00:00Z"
        }


class MockEventStore:
    def __init__(self):
        self.history = {}

    def get_history(self, sensor_id: str):
        return self.history.get(sensor_id, [
            {"value": 45, "unit": "cm"},
            {"value": 48, "unit": "cm"}
        ])

    def add_reading(self, sensor_id: str, reading: dict):
        self.history.setdefault(sensor_id, []).append(reading)


class MockAnomalyDetector:
    def detect(self, canonical_msg: dict, history: list) -> list:
        # Si le niveau d'eau dépasse 200 cm subitement -> ANOMALIE DE CRUE BRUTALE (Attaque)
        if canonical_msg.get("value", 0) > 200:
            return ["SUDDEN_SPIKE_DETECTED", "PHYSICAL_INCOHERENCE"]
        return []


class MockTrustAssessor:
    def assess(self, canonical_msg: dict, flags: list):
        if flags:
            return "UNTRUSTED", "ANOMALY_DETECTED"
        return "TRUSTED", "NORMAL"


class MockContainment:
    def evaluate_action(self, flags: list, verdict: str) -> str:
        if verdict == "UNTRUSTED" or flags:
            return "ISOLATE"
        return "ALLOW"


def create_test_pipeline():
    """Instancie un pipeline complet avec les mocks configurés."""
    timeline_manager.clear()
    mock_output = MagicMock()
    mock_output.send_to_brain = AsyncMock()
    mock_logger = MagicMock()

    pipeline = GuardianPipeline(
        security=MockSecurity(),
        contract=MockContract(),
        event_store=MockEventStore(),
        anomaly_detector=MockAnomalyDetector(),
        trust_assessor=MockTrustAssessor(),
        containment=MockContainment(),
        output_adapter=mock_output
    )
    return pipeline, mock_logger


# ---------------------------------------------------------------------------
# Tests Pytest
# ---------------------------------------------------------------------------

client = TestClient(app)


def test_timeline_fake_flood_attack_causality():
    """
    Test R3 : Scénario d'attaque de fausse crue (fake_flood).
    Vérifie la chaîne causale stricte :
    READING_RECEIVED -> GUARDIAN_VERDICT (UNTRUSTED, ISOLATE) -> ISOLATED (BLOCKED).
    """
    pipeline, logger = create_test_pipeline()

    # Message simulant une crue factice anormale (3.8 mètres = 380 cm vs historique à 48 cm)
    fake_flood_message = {
        "event_id": "EVT-ATTACK-FAKE-FLOOD-01",
        "sensor_id": "S01",
        "levelOfWater": 3.8,
        "unit": "m",
        "token": "valid_token"
    }

    with client.websocket_connect("/ws/timeline") as websocket:
        # Déclenchement du pipeline via asyncio.run() pour éviter les warnings de dépréciation
        result = asyncio.run(pipeline.process_incoming(fake_flood_message, logger))

        assert result["containment_action"] == "ISOLATE"
        assert result["trust_verdict"] == "UNTRUSTED"

        # 1. Événement 1 : Réception et normalisation
        evt1 = websocket.receive_json()
        assert evt1["stage"] == "READING_RECEIVED"
        assert evt1["sensor_id"] == "S01"
        assert evt1["event_id"] == "EVT-ATTACK-FAKE-FLOOD-01"
        assert evt1["value"] == 380  # Converti en cm
        assert evt1["unit"] == "cm"

        # 2. Événement 2 : Verdict du Guardian
        evt2 = websocket.receive_json()
        assert evt2["stage"] == "GUARDIAN_VERDICT"
        assert evt2["event_id"] == evt1["event_id"], "L'event_id doit être identique pour la corrélation"
        assert evt2["verdict"] == "UNTRUSTED"
        assert evt2["action"] == "ISOLATE"
        assert "SUDDEN_SPIKE_DETECTED" in evt2["anomaly_flags"]

        # 3. Événement 3 : Action de Confinement (Attaque isolée, Brain protégé)
        evt3 = websocket.receive_json()
        assert evt3["stage"] == "ISOLATED"
        assert evt3["event_id"] == evt1["event_id"]
        assert evt3["status"] == "BLOCKED"
        assert evt3["action"] == "ISOLATE"


def test_timeline_legitimate_reading_forwarded_to_brain():
    """
    Test R3 : Scénario nominal de niveau d'eau normal.
    Vérifie la chaîne :
    READING_RECEIVED -> GUARDIAN_VERDICT (TRUSTED, ALLOW) -> SENT_TO_BRAIN (DELIVERED).
    """
    pipeline, logger = create_test_pipeline()

    normal_message = {
        "event_id": "EVT-NORMAL-WATER-02",
        "sensor_id": "S01",
        "levelOfWater": 0.52,
        "unit": "m",
        "token": "valid_token"
    }

    with client.websocket_connect("/ws/timeline") as websocket:
        # Déclenchement du pipeline
        result = asyncio.run(pipeline.process_incoming(normal_message, logger))

        assert result["containment_action"] == "ALLOW"
        assert result["trust_verdict"] == "TRUSTED"

        evt1 = websocket.receive_json()
        assert evt1["stage"] == "READING_RECEIVED"
        assert evt1["event_id"] == "EVT-NORMAL-WATER-02"

        evt2 = websocket.receive_json()
        assert evt2["stage"] == "GUARDIAN_VERDICT"
        assert evt2["verdict"] == "TRUSTED"
        assert evt2["action"] == "ALLOW"

        evt3 = websocket.receive_json()
        assert evt3["stage"] == "SENT_TO_BRAIN"
        assert evt3["event_id"] == "EVT-NORMAL-WATER-02"
        assert evt3["status"] == "DELIVERED"
        assert evt3["destination"] == "CITY_BRAIN"


def test_timeline_security_rejected():
    """
    Test R3 : Échec de validation de sécurité.
    Vérifie l'émission de l'événement SECURITY_REJECTED avec le bon event_id.
    """
    pipeline, logger = create_test_pipeline()

    unauthorized_message = {
        "event_id": "EVT-AUTH-FAIL-03",
        "sensor_id": "S01",
        "levelOfWater": 0.50,
        "unit": "m",
        "token": "invalid"
    }

    with client.websocket_connect("/ws/timeline") as websocket:
        result = asyncio.run(pipeline.process_incoming(unauthorized_message, logger))

        assert result["status"] == "REJECTED"
        assert result["reason"] == "SECURITY"

        evt1 = websocket.receive_json()
        assert evt1["stage"] == "SECURITY_REJECTED"
        assert evt1["event_id"] == "EVT-AUTH-FAIL-03"
        assert evt1["status"] == "REJECTED"
