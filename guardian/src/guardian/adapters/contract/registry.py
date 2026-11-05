"""Persistent, versioned mapping-profile registry.

The registry is deliberately separate from :class:`GenericMapper`: it only
selects validated ACTIVE or PROBATION profiles for an authenticated Twin
identity. PENDING proposals never enter the live path until promotion.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .errors import MappingError, MappingErrorCode
from .profile import MappingProfile, load_profile

ProfileStatus = Literal["PENDING", "PROBATION", "ACTIVE", "REVOKED", "UNMAPPABLE"]


class ProfileRecord(BaseModel):
    """A validated profile and its explicit partner/lifecycle association."""

    model_config = ConfigDict(extra="forbid")

    profile: MappingProfile | None
    status: ProfileStatus
    fingerprint: str = Field(min_length=8, max_length=64)
    twin_identity: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=64)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    proposers_agreed: list[str] = Field(default_factory=list)
    gate_results: dict[str, str] = Field(default_factory=dict)
    promoted_at: datetime | None = None
    clean_messages: int = 0

    @property
    def schema_id(self) -> str:
        return self.profile.schema_id if self.profile is not None else ""

    @property
    def version(self) -> str:
        return self.profile.version if self.profile is not None else ""


def shape_fingerprint(
    *,
    twin_identity: str,
    event_type: str,
    schema_id: str | None,
    payload_keys: list[str],
) -> str:
    """Identify an unknown payload shape before a profile exists. Never hashes values."""
    payload = {
        "twin_identity": twin_identity,
        "event_type": event_type,
        "schema_id": schema_id or "",
        "keys": sorted(payload_keys),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def profile_fingerprint(profile: MappingProfile, twin_identity: str, event_type: str) -> str:
    """Return a stable identifier for one identity/schema/profile combination."""
    payload = {
        "twin_identity": twin_identity,
        "event_type": event_type,
        "profile": profile.model_dump(mode="json"),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


class ProfileRegistry:
    """Loads profiles from disk and writes runtime records atomically."""

    def __init__(self, profile_dir: Path, *, committed_dir: Path | None = None):
        self.profile_dir = Path(profile_dir)
        self.committed_dir = Path(committed_dir) if committed_dir is not None else None
        self._records: dict[str, ProfileRecord] = {}
        self._committed: set[str] = set()
        self._lock = threading.Lock()
        if self.committed_dir is not None:
            self._load_directory(self.committed_dir, read_only=True)
        self._load_directory(self.profile_dir, read_only=False)

    def _load_directory(self, directory: Path, *, read_only: bool) -> None:
        if not directory.is_dir():
            return
        for path in sorted(directory.glob("*.json")):
            try:
                record = ProfileRecord.model_validate_json(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise MappingError(MappingErrorCode.INVALID_PROFILE, f"invalid profile record {path.name}") from exc
            if record.profile is None and record.status not in {"REVOKED", "UNMAPPABLE"}:
                raise MappingError(MappingErrorCode.INVALID_PROFILE, f"profile {path.name} has no validated profile")
            self._records[record.fingerprint] = record
            if read_only:
                self._committed.add(record.fingerprint)

    def get(self, fingerprint: str) -> ProfileRecord | None:
        return self._records.get(fingerprint)

    def records(self) -> tuple[ProfileRecord, ...]:
        return tuple(self._records[key] for key in sorted(self._records))

    def register(self, record: ProfileRecord, *, persist: bool = True) -> ProfileRecord:
        if record.profile is not None:
            record = record.model_copy(update={"profile": load_profile(record.profile.model_dump())})
        with self._lock:
            self._records[record.fingerprint] = record
            if persist and record.fingerprint not in self._committed:
                self._write(record)
        return record

    def register_profile(
        self,
        profile: MappingProfile,
        *,
        twin_identity: str,
        event_type: str,
        status: ProfileStatus = "PENDING",
        persist: bool = True,
    ) -> ProfileRecord:
        fingerprint = profile_fingerprint(profile, twin_identity, event_type)
        record = ProfileRecord(
            profile=load_profile(profile.model_dump()),
            status=status,
            fingerprint=fingerprint,
            twin_identity=twin_identity,
            event_type=event_type,
        )
        return self.register(record, persist=persist)

    def ensure_active(
        self, profile: MappingProfile, *, twin_identity: str, event_type: str, persist: bool = True
    ) -> ProfileRecord:
        """Ensure a proposal exists without promoting it.

        Runtime proposals, including AI-generated proposals, are deliberately
        left ``PENDING``.  Call :meth:`activate` only from an explicit approval
        workflow, or use :meth:`ensure_builtin_active` for profiles shipped as
        pre-approved application contracts.
        """
        fingerprint = profile_fingerprint(profile, twin_identity, event_type)
        existing = [record for record in self._records.values() if record.fingerprint == fingerprint]
        active = [record for record in existing if record.status == "ACTIVE"]
        if active:
            return active[0]
        pending = [record for record in existing if record.status == "PENDING"]
        if pending:
            return pending[0]
        return self.register_profile(
            profile,
            twin_identity=twin_identity,
            event_type=event_type,
            status="PENDING",
            persist=persist,
        )

    def ensure_builtin_active(
        self,
        profile: MappingProfile,
        *,
        twin_identity: str,
        event_type: str,
        persist: bool = True,
    ) -> ProfileRecord:
        """Install an explicitly shipped, pre-approved profile as ACTIVE.

        This is the only startup promotion path.  It is reserved for profiles
        embedded in the application contract and cannot be used by AI proposal
        code, which calls :meth:`ensure_active` and remains ``PENDING``.
        """
        fingerprint = profile_fingerprint(profile, twin_identity, event_type)
        existing = [record for record in self._records.values() if record.fingerprint == fingerprint]
        active = [record for record in existing if record.status == "ACTIVE"]
        if active:
            return active[0]
        pending = [record for record in existing if record.status == "PENDING"]
        if pending:
            return self.activate(pending[0].fingerprint)
        return self.register_profile(
            profile,
            twin_identity=twin_identity,
            event_type=event_type,
            status="ACTIVE",
            persist=persist,
        )

    def activate(self, fingerprint: str) -> ProfileRecord:
        with self._lock:
            record = self._records.get(fingerprint)
            if record is None or record.profile is None:
                raise MappingError(MappingErrorCode.PROFILE_NOT_ACTIVE, "profile is not available")
            if fingerprint in self._committed:
                return record
            for other in self._records.values():
                if (
                    other.fingerprint != fingerprint
                    and other.twin_identity == record.twin_identity
                    and other.event_type == record.event_type
                    and other.schema_id == record.schema_id
                    and other.version == record.version
                    and other.status == "ACTIVE"
                ):
                    self._records[other.fingerprint] = other.model_copy(update={"status": "PENDING"})
                    self._write(self._records[other.fingerprint])
            updated = record.model_copy(update={"status": "ACTIVE", "promoted_at": datetime.now(UTC)})
            self._records[fingerprint] = updated
            self._write(updated)
            return updated

    def update(self, fingerprint: str, **fields: Any) -> ProfileRecord:
        if fingerprint in self._committed:
            raise MappingError(MappingErrorCode.INVALID_PROFILE, "committed profiles are read-only")
        record = self._records.get(fingerprint)
        if record is None:
            raise MappingError(MappingErrorCode.UNKNOWN_SCHEMA, "profile record was not found")
        try:
            updated = record.model_copy(update=fields)
            updated = ProfileRecord.model_validate(updated.model_dump())
        except ValueError as exc:
            raise MappingError(MappingErrorCode.INVALID_PROFILE, "profile update is invalid") from exc
        return self.register(updated)

    def select(
        self,
        *,
        twin_identity: str,
        event_type: str,
        schema_id: str | None = None,
        schema_version: str | None = None,
        event_id: str | None = None,
    ) -> MappingProfile:
        return self.select_record(
            twin_identity=twin_identity,
            event_type=event_type,
            schema_id=schema_id,
            schema_version=schema_version,
            event_id=event_id,
        ).profile  # type: ignore[return-value]

    def select_record(
        self,
        *,
        twin_identity: str,
        event_type: str,
        schema_id: str | None = None,
        schema_version: str | None = None,
        event_id: str | None = None,
    ) -> ProfileRecord:
        record = self._select_one(
            twin_identity=twin_identity,
            event_type=event_type,
            schema_id=schema_id,
            schema_version=schema_version,
            event_id=event_id,
            statuses=("ACTIVE",),
        )
        if record is None:
            record = self._select_one(
                twin_identity=twin_identity,
                event_type=event_type,
                schema_id=schema_id,
                schema_version=schema_version,
                event_id=event_id,
                statuses=("PROBATION",),
            )
        if record is None:
            raise MappingError(
                MappingErrorCode.UNKNOWN_SCHEMA,
                "no active compatible profile",
                event_id=event_id,
            )
        return record

    def _select_one(
        self,
        *,
        twin_identity: str,
        event_type: str,
        schema_id: str | None,
        schema_version: str | None,
        event_id: str | None,
        statuses: tuple[str, ...],
    ) -> ProfileRecord | None:
        live_for_event = [
            record for record in self._records.values()
            if record.status in statuses
            and record.profile is not None
            and record.twin_identity == twin_identity
            and record.event_type == event_type
        ]
        candidates = [
            record for record in live_for_event
            if schema_id is not None
            and record.schema_id == schema_id
            and schema_version is not None
            and record.version == schema_version
        ]
        if len(candidates) == 1:
            return candidates[0]
        if not candidates and (schema_id is None or schema_version is None) and len(live_for_event) > 1:
            raise MappingError(MappingErrorCode.UNKNOWN_SCHEMA, "ambiguous active profiles", event_id=event_id)
        if len(candidates) > 1:
            raise MappingError(MappingErrorCode.UNKNOWN_SCHEMA, "ambiguous active profiles", event_id=event_id)
        return None

    def promote(self, fingerprint: str) -> ProfileRecord:
        """Move a PROBATION record to ACTIVE after enough clean maps."""
        record = self._records.get(fingerprint)
        if record is None or record.status != "PROBATION" or record.profile is None:
            raise MappingError(MappingErrorCode.PROFILE_NOT_ACTIVE, "profile is not available")
        return self.update(fingerprint, status="ACTIVE", promoted_at=datetime.now(UTC))

    def note_clean_map(self, fingerprint: str, threshold: int) -> ProfileRecord:
        """Count one successful map; promote when ``threshold`` consecutive maps succeed."""
        record = self._records.get(fingerprint)
        if record is None or record.status != "PROBATION":
            raise MappingError(MappingErrorCode.PROFILE_NOT_ACTIVE, "profile is not available")
        updated = self.update(fingerprint, clean_messages=record.clean_messages + 1)
        if updated.clean_messages >= threshold:
            return self.promote(fingerprint)
        return updated

    def reset_clean_map(self, fingerprint: str) -> ProfileRecord:
        """A mapping failure during probation restarts the clean-map counter."""
        record = self._records.get(fingerprint)
        if record is None or record.status != "PROBATION":
            raise MappingError(MappingErrorCode.PROFILE_NOT_ACTIVE, "profile is not available")
        return self.update(fingerprint, clean_messages=0)

    def find_probation(self, profile: MappingProfile) -> ProfileRecord | None:
        matches = [
            record for record in self._records.values()
            if record.status == "PROBATION"
            and record.profile is not None
            and record.profile.profile_id == profile.profile_id
            and record.profile.schema_id == profile.schema_id
        ]
        return matches[0] if len(matches) == 1 else None

    def _write(self, record: ProfileRecord) -> None:
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        destination = self.profile_dir / f"{record.fingerprint}.json"
        temporary = destination.with_suffix(".json.tmp")
        temporary.write_text(record.model_dump_json(indent=2), encoding="utf-8")
        os.replace(temporary, destination)
