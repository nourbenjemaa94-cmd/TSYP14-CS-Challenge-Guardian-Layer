from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, replace
from typing import Any, Protocol

# TODO(guardian-integration): absolute import; one package root
from guardian.core.history import SUSPICIOUS, TRUSTED, UNTRUSTED, HistoryTracker, utc_now_iso
from guardian.core.trust_assessor import TrustVerdict

ACTIVE, QUARANTINED, ISOLATED = "ACTIVE", "QUARANTINED", "ISOLATED"
ALLOW, QUARANTINE, ISOLATE = "ALLOW", "QUARANTINE", "ISOLATE"
RELEASE, ROLLBACK, RESTORE = "RELEASE", "ROLLBACK", "RESTORE"
REQUESTED, ACCEPTED, APPLIED, FAILED, NOOP = "REQUESTED", "ACCEPTED", "APPLIED", "FAILED", "NOOP"

_SEVERITY_ORDER = {ALLOW: 0, QUARANTINE: 1, ISOLATE: 2}


@dataclass(frozen=True)
class PortResult:
    accepted: bool
    applied: bool = True
    detail: str = ""


class ContainmentPort(Protocol):
    def isolate_device(self, device_id: str, idem_key: str) -> PortResult: ...
    def rollback_reading(self, event_id: str, idem_key: str) -> PortResult: ...


@dataclass(frozen=True)
class ContainmentConfig:
    isolate_after_untrusted: int = 1
    quarantine_after_suspicious: int = 2
    release_quarantine_after_trusted: int = 5
    rollback_untrusted_readings: bool = True
    max_remembered: int = 500
    policy_version: str = "1.0"

    def __post_init__(self) -> None:
        if min(self.isolate_after_untrusted, self.quarantine_after_suspicious,
               self.release_quarantine_after_trusted, self.max_remembered) < 1:
            raise ValueError("containment counters must all be >= 1")

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ContainmentConfig:
        base = cls()
        values: dict[str, Any] = {}
        for key in ("isolate_after_untrusted", "quarantine_after_suspicious",
                    "release_quarantine_after_trusted", "max_remembered"):
            if key in data:
                values[key] = int(data[key])
        if "rollback_untrusted_readings" in data:
            values["rollback_untrusted_readings"] = bool(data["rollback_untrusted_readings"])
        return replace(base, **values)


@dataclass(frozen=True)
class ContainmentAction:
    action_id: str
    action: str
    target: str
    event_id: str
    status: str
    lifecycle: tuple[str, ...]
    reason: str
    changes: dict[str, Any]
    remote_confirmed: bool
    error: str
    idempotency_key: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ContainmentReport:
    event_id: str
    sensor_id: str
    assessment_id: str
    reading_action: str
    state_before: str
    state_after: str
    actions: tuple[ContainmentAction, ...]
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ContainmentEngine:
    def __init__(
        self,
        config: ContainmentConfig | None = None,
        history: HistoryTracker | None = None,
        port: ContainmentPort | None = None,
        clock: Callable[[], str] = utc_now_iso,
    ) -> None:
        self.config = config or ContainmentConfig()
        self.history = history if history is not None else HistoryTracker()
        self.port = port
        self._clock = clock
        self._states: dict[str, str] = {}
        self._counts: dict[str, tuple[str, int]] = {}
        self._remote_pending: set = set()
        self._idempotency_keys: dict[tuple[str, str, str], str] = {}
        self._reports: OrderedDict[str, ContainmentReport] = OrderedDict()
        self._sequence = 0

    def evaluate_action(self, flags: list[str], verdict: str) -> str:
        if verdict == TRUSTED:
            return ALLOW
        if verdict == SUSPICIOUS:
            return QUARANTINE
        return ISOLATE

    def contain(self, verdict: TrustVerdict) -> ContainmentReport:
        cached = self._reports.get(verdict.assessment_id)
        if cached is not None:
            return cached
        cfg, sensor = self.config, verdict.sensor_id
        before = self.state(sensor)
        actions: list[ContainmentAction] = []

        if verdict.recorded:
            count = self._count(sensor, verdict.verdict)
            if verdict.verdict == UNTRUSTED and count >= cfg.isolate_after_untrusted:
                if self.state(sensor) != ISOLATED or sensor in self._remote_pending:
                    actions.append(self.isolate(sensor, verdict.reason_code, verdict.event_id))
                if cfg.rollback_untrusted_readings:
                    entry = self.history.find_entry(verdict.event_id)
                    if entry is not None and not entry.rolled_back:
                        actions.append(self.rollback_reading(verdict.event_id, verdict.reason_code))
            elif verdict.verdict == SUSPICIOUS and count >= cfg.quarantine_after_suspicious:
                if self.state(sensor) == ACTIVE:
                    actions.append(self.quarantine(sensor, verdict.reason_code, verdict.event_id))
            elif verdict.verdict == TRUSTED and count >= cfg.release_quarantine_after_trusted:
                if self.state(sensor) == QUARANTINED:
                    actions.append(self.release(sensor, "CLEAN_READINGS", verdict.event_id))

        after = self.state(sensor)
        reading_action = self.evaluate_action([], verdict.verdict)
        device_action = {ISOLATED: ISOLATE, QUARANTINED: QUARANTINE}.get(after, ALLOW)
        if _SEVERITY_ORDER[device_action] > _SEVERITY_ORDER[reading_action]:
            reading_action = device_action

        report = ContainmentReport(verdict.event_id, sensor, verdict.assessment_id, reading_action,
                                   before, after, tuple(actions), self._clock())
        self._reports[verdict.assessment_id] = report
        while len(self._reports) > cfg.max_remembered:
            self._reports.popitem(last=False)
        return report

    def isolate(self, sensor_id: str, reason: str = "MANUAL", event_id: str = "") -> ContainmentAction:
        before = self.state(sensor_id)
        action_id, key = self._new_id(ISOLATE, sensor_id, event_id)
        outcome = self._call_port("isolate_device", sensor_id, key)
        # The local state represents confirmed remote containment.  The
        # decision to block forwarding is carried by the action/report and is
        # deliberately independent from this state transition.
        if outcome is not None and outcome[2]:
            self._states[sensor_id] = ISOLATED
            self._remote_pending.discard(sensor_id)
        elif outcome is not None:
            self._remote_pending.add(sensor_id)
        return self._build(action_id, ISOLATE, sensor_id, event_id, reason, key, outcome,
                           {"device_state": {"before": before,
                                              "after": ISOLATED if outcome is not None and outcome[2] else before}})

    def quarantine(self, sensor_id: str, reason: str = "MANUAL", event_id: str = "") -> ContainmentAction:
        before = self.state(sensor_id)
        action_id, key = self._new_id(QUARANTINE, sensor_id)
        if before != ACTIVE:
            return self._build(action_id, QUARANTINE, sensor_id, event_id, reason, key, None,
                               {"device_state": {"before": before, "after": before}}, noop=True)
        self._states[sensor_id] = QUARANTINED
        return self._build(action_id, QUARANTINE, sensor_id, event_id, reason, key, None,
                           {"device_state": {"before": before, "after": QUARANTINED}})

    def release(self, sensor_id: str, reason: str = "MANUAL", event_id: str = "") -> ContainmentAction:
        before = self.state(sensor_id)
        action_id, key = self._new_id(RELEASE, sensor_id)
        if before == ACTIVE:
            return self._build(action_id, RELEASE, sensor_id, event_id, reason, key, None,
                               {"device_state": {"before": before, "after": before}}, noop=True)
        outcome = None
        if before == ISOLATED and hasattr(self.port, "release_device"):
            outcome = self._call_port("release_device", sensor_id, key)
        self._states.pop(sensor_id, None)
        self._counts.pop(sensor_id, None)
        self._remote_pending.discard(sensor_id)
        dropped = self.history.reset(sensor_id)
        return self._build(action_id, RELEASE, sensor_id, event_id, reason, key, outcome,
                           {"device_state": {"before": before, "after": ACTIVE}, "history_entries_dropped": dropped})

    def rollback_reading(self, event_id: str, reason: str = "MANUAL") -> ContainmentAction:
        action_id, key = self._new_id(ROLLBACK, event_id)
        entry = self.history.find_entry(event_id)
        if entry is None:
            return self._build(action_id, ROLLBACK, event_id, event_id, reason, key, None, {},
                               error="UNKNOWN_EVENT: reading is not in history")
        if entry.rolled_back:
            return self._build(action_id, ROLLBACK, event_id, event_id, reason, key, None,
                               {"reading": {"value": entry.reading.value, "rolled_back": True}}, noop=True)
        self.history.mark_rolled_back(event_id, True)
        outcome = self._call_port("rollback_reading", event_id, key)
        return self._build(action_id, ROLLBACK, event_id, event_id, reason, key, outcome,
                           {"reading": {"sensor_id": entry.reading.sensor_id, "value": entry.reading.value,
                                        "rolled_back": True}})

    def restore_reading(self, event_id: str, reason: str = "MANUAL") -> ContainmentAction:
        action_id, key = self._new_id(RESTORE, event_id)
        entry = self.history.find_entry(event_id)
        if entry is None or not entry.rolled_back:
            return self._build(action_id, RESTORE, event_id, event_id, reason, key, None, {},
                               error="NOT_ROLLED_BACK: nothing to restore")
        self.history.mark_rolled_back(event_id, False)
        return self._build(action_id, RESTORE, event_id, event_id, reason, key, None,
                           {"reading": {"value": entry.reading.value, "rolled_back": False}})

    def state(self, sensor_id: str) -> str:
        return self._states.get(sensor_id, ACTIVE)

    def isolated_sensors(self) -> list[str]:
        return sorted(s for s, st in self._states.items() if st == ISOLATED)

    def mark_sensor_isolated(self, sensor_id: str) -> None:
        self.isolate(sensor_id, "MANUAL")

    def is_sensor_isolated(self, sensor_id: str) -> bool:
        return self.state(sensor_id) == ISOLATED

    def release_sensor(self, sensor_id: str) -> None:
        self.release(sensor_id, "MANUAL")

    def _count(self, sensor_id: str, verdict: str) -> int:
        last, count = self._counts.get(sensor_id, ("", 0))
        count = count + 1 if last == verdict else 1
        self._counts[sensor_id] = (verdict, count)
        return count

    def _new_id(self, kind: str, target: str, logical_id: str = "") -> tuple[str, str]:
        self._sequence += 1
        action_id = f"CA-{self._sequence:06d}"
        identity = (kind, target, logical_id) if logical_id else None
        if identity is not None and identity in self._idempotency_keys:
            key = self._idempotency_keys[identity]
        else:
            key = f"guardian:{kind.lower()}:{target}:{action_id}"
            if identity is not None:
                self._idempotency_keys[identity] = key
        return action_id, key

    def _call_port(self, method: str, target: str, key: str) -> tuple[bool, bool, bool, str] | None:
        if self.port is None:
            return None
        try:
            result = getattr(self.port, method)(target, key)
            accepted, applied = bool(result.accepted), bool(getattr(result, "applied", result.accepted))
            return accepted, applied, accepted and applied, str(getattr(result, "detail", ""))[:200]
        except Exception as exc:
            return False, False, False, f"{type(exc).__name__}: {str(exc)[:160]}"

    def _build(self, action_id: str, kind: str, target: str, event_id: str, reason: str, key: str,
               outcome: tuple[bool, bool, bool, str] | None, changes: dict[str, Any],
               noop: bool = False, error: str = "") -> ContainmentAction:
        lifecycle: tuple[str, ...]
        confirmed = False
        if error:
            status, lifecycle = FAILED, (REQUESTED, FAILED)
        elif noop:
            status, lifecycle = NOOP, (REQUESTED, NOOP)
        elif outcome is None:
            status, lifecycle = APPLIED, (REQUESTED, APPLIED)
            changes = {**changes, "remote": "not_configured"}
        else:
            accepted, applied, confirmed, detail = outcome
            if not accepted:
                status, lifecycle, error = FAILED, (REQUESTED, FAILED), detail or "REJECTED_BY_PARTNER"
                changes = {**changes, "remote": "failed"}
            elif not applied:
                status, lifecycle = ACCEPTED, (REQUESTED, ACCEPTED)
                changes = {**changes, "remote": "unconfirmed"}
            else:
                status, lifecycle = APPLIED, (REQUESTED, ACCEPTED, APPLIED)
                changes = {**changes, "remote": "confirmed"}
        return ContainmentAction(action_id, kind, target, event_id, status, lifecycle, reason,
                                 changes, confirmed, error, key, self._clock())
