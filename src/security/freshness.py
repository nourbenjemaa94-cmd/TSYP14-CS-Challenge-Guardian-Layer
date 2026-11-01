"""Rejects stale and far-future timestamps.

Clocks across the triplet are assumed to agree within the configured skew.
The clock is injectable so tests never depend on the wall clock.
"""

from datetime import UTC, datetime

from guardian.security.errors import ReasonCode, SecurityRejection


def parse_timestamp(value: str) -> datetime:
    """Parse an envelope timestamp. The shape has already been validated."""
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    return parsed.replace(tzinfo=UTC)


def format_timestamp(moment: datetime) -> str:
    """Format UTC time as ``YYYY-MM-DDTHH:MM:SS.mmmZ``."""
    if moment.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    utc = moment.astimezone(UTC)
    millis = utc.microsecond // 1000
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{millis:03d}Z"


def check_freshness(
    timestamp: str,
    *,
    now: datetime,
    max_age_seconds: float,
    max_future_skew_seconds: float,
) -> None:
    """Reject timestamps older than the window or further ahead than the skew.

    A timestamp exactly ``max_age_seconds`` old is still fresh. A timestamp
    exactly ``max_future_skew_seconds`` ahead is still accepted.
    """
    if now.tzinfo is None:
        raise ValueError("clock must return timezone-aware datetimes")
    delta = (now.astimezone(UTC) - parse_timestamp(timestamp)).total_seconds()
    if delta > max_age_seconds:
        raise SecurityRejection(ReasonCode.STALE_TIMESTAMP, detail="Timestamp is outside the freshness window.")
    if delta < -max_future_skew_seconds:
        raise SecurityRejection(ReasonCode.FUTURE_TIMESTAMP, detail="Timestamp is too far in the future.")
