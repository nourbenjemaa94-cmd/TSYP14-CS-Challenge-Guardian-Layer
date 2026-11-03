"""
Audit Subsystem (Member 3 & 4: Ghaith Mnasri & Rayen Saidi)
Responsible for:
- Event logging with correlation tracking (logger.py)
- Historical telemetry persistence (event_store.py)
- Real-time audit timeline WebSocket streaming (timeline.py)
"""

from .event_store import EventStore, default_event_store
from .logger import get_audit_logger, log_event
from .timeline import TimelineManager, get_utc_now, timeline_manager

__all__ = [
    "timeline_manager",
    "get_utc_now",
    "TimelineManager",
    "log_event",
    "get_audit_logger",
    "EventStore",
    "default_event_store",
]

