"""
Audit Subsystem (Member 3 & 4: Ghaith Mnasri & Rayen Saidi)
Responsible for:
- Event logging with correlation tracking (logger.py)
- Historical telemetry persistence (event_store.py)
- Real-time audit timeline WebSocket streaming (timeline.py)
"""

from .timeline import timeline_manager, get_utc_now, TimelineManager
from .logger import log_event, get_audit_logger
from .event_store import EventStore, default_event_store

__all__ = [
    "timeline_manager",
    "get_utc_now",
    "TimelineManager",
    "log_event",
    "get_audit_logger",
    "EventStore",
    "default_event_store",
]

