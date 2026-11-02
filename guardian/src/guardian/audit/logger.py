"""
audit/logger.py
---------------
Helper de journalisation d'événements pour le Guardian (Member 4: Ghaith Mnasri & Member 3: Rayen Saidi).
Provides structured logging compliant with Requirement R2 and R3.
"""

import sys
import logging
from typing import Dict, Any, Optional, List

try:
    from audit.timeline import get_utc_now
except ImportError:
    from .timeline import get_utc_now


def log_event(
    logger: Any,
    event_id: str,
    stage: str,
    verdict: str,
    reason: str,
    action: Optional[str] = None,
    anomaly_flags: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Enregistre un événement structuré dans le logger d'audit.
    Garantit la corrélation par event_id et l'horodatage UTC.
    """
    entry = {
        "timestamp": get_utc_now(),
        "event_id": event_id,
        "stage": stage,
        "verdict": verdict,
        "reason": reason,
        "action": action,
        "anomaly_flags": anomaly_flags or []
    }
    if logger and hasattr(logger, "info"):
        logger.info(f"[AUDIT] {entry}")
    return entry


def get_audit_logger(name: str = "guardian.audit") -> logging.Logger:
    """Configures and returns a structured logger."""
    audit_logger = logging.getLogger(name)
    if not audit_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] [%(name)s] %(message)s'
        )
        handler.setFormatter(formatter)
        audit_logger.addHandler(handler)
        audit_logger.setLevel(logging.INFO)
    return audit_logger

