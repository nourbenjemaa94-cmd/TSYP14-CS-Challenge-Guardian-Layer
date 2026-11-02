"""Per-source token bucket and flood signal.

Limits how fast one authenticated source can send messages, which is how a
device that floods the network is contained. Only authenticated identities
reach this code, so a forged signature cannot drain someone else's bucket.

TODO(security): ASSUMPTION — the device id is ``source.device_id`` when that
value is a string of 1 to 128 characters, otherwise a top-level ``device_id``
under the same rule, otherwise ``-``. The source key is ``layer:device_id``
using the authenticated layer. Tracked sources are capped at 10,000 and the
least recently used entry is evicted.
"""

import threading
from collections import OrderedDict, deque
from collections.abc import Callable

from guardian.security.errors import ReasonCode, SecurityRejection

_TOKEN_EPSILON = 1e-9
FLOOD_WINDOW_SECONDS = 10.0
MAX_TRACKED_SOURCES = 10_000


def rate_limit_device_id(body: dict[str, object]) -> str:
    """Read a device id from the raw JSON object, or ``-`` when it is unusable."""
    candidates: list[object] = []
    source = body.get("source")
    if isinstance(source, dict):
        candidates.append(source.get("device_id"))
    candidates.append(body.get("device_id"))
    for value in candidates:
        if isinstance(value, str) and 1 <= len(value) <= 128:
            return value
    return "-"


class RateLimiter:
    """Token bucket keyed by source, plus a sliding window of rejections."""

    def __init__(
        self,
        *,
        rate_per_second: float,
        burst: int,
        flood_threshold: int,
        clock: Callable[[], float],
        max_sources: int = MAX_TRACKED_SOURCES,
        flood_window_seconds: float = FLOOD_WINDOW_SECONDS,
    ) -> None:
        self._rate = rate_per_second
        self._burst = burst
        self._threshold = flood_threshold
        self._clock = clock
        self._max_sources = max_sources
        self._flood_window = flood_window_seconds
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()
        self._rejections: dict[str, deque[float]] = {}
        self._signaled_at: dict[str, float] = {}
        self._lock = threading.Lock()

    def check(self, source: str, *, event_id: str | None = None) -> None:
        """Consume one token or raise ``RATE_LIMITED`` and count the rejection."""
        with self._lock:
            now = self._clock()
            bucket = self._touch(source, now)
            if self._consume(bucket, now):
                return
            self._record_rejection(source, now)
            raise SecurityRejection(
                ReasonCode.RATE_LIMITED,
                event_id=event_id,
                source=source,
                detail="Token bucket exhausted.",
            )

    def flooding_sources(self) -> tuple[str, ...]:
        """Sources that just crossed the flood threshold, once per 10-second window."""
        with self._lock:
            now = self._clock()
            found: list[str] = []
            quiet: list[str] = []
            for source, times in self._rejections.items():
                self._prune(times, now)
                if not times:
                    quiet.append(source)
                    continue
                if len(times) < self._threshold:
                    continue
                last = self._signaled_at.get(source)
                if last is None or now - last >= self._flood_window:
                    found.append(source)
                    self._signaled_at[source] = now
            for source in quiet:
                self._rejections.pop(source, None)
            return tuple(found)

    def _touch(self, source: str, now: float) -> "_Bucket":
        existing = self._buckets.get(source)
        if existing is not None:
            self._buckets.move_to_end(source)
            return existing
        if len(self._buckets) >= self._max_sources:
            evicted, _bucket = self._buckets.popitem(last=False)
            self._rejections.pop(evicted, None)
            self._signaled_at.pop(evicted, None)
        bucket = _Bucket(tokens=float(self._burst), updated_at=now)
        self._buckets[source] = bucket
        return bucket

    def _consume(self, bucket: "_Bucket", now: float) -> bool:
        elapsed = now - bucket.updated_at
        if elapsed < 0:
            elapsed = 0.0
        bucket.tokens = min(float(self._burst), bucket.tokens + elapsed * self._rate)
        bucket.updated_at = now
        if bucket.tokens + _TOKEN_EPSILON >= 1.0:
            bucket.tokens -= 1.0
            if bucket.tokens < 0:
                bucket.tokens = 0.0
            return True
        return False

    def _record_rejection(self, source: str, now: float) -> None:
        times = self._rejections.setdefault(source, deque())
        self._prune(times, now)
        times.append(now)

    def _prune(self, times: deque[float], now: float) -> None:
        cutoff = now - self._flood_window
        while times and times[0] <= cutoff:
            times.popleft()


class _Bucket:
    __slots__ = ("tokens", "updated_at")

    def __init__(self, tokens: float, updated_at: float) -> None:
        self.tokens = tokens
        self.updated_at = updated_at
