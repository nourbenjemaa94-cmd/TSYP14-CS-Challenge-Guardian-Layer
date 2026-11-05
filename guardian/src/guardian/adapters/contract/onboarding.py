"""Automatic onboarding for an unknown but authenticated payload shape.

Never on the per-message hot path except ``submit``, which only appends to a
buffer and starts one task per fingerprint. Payload values are not logged.
"""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from guardian.adapters.contract.errors import MappingError, MappingErrorCode
from guardian.adapters.contract.gates import run_gates
from guardian.adapters.contract.profile import MappingProfile
from guardian.adapters.contract.proposers import Proposer
from guardian.adapters.contract.registry import ProfileRecord, ProfileRegistry, shape_fingerprint
from guardian.adapters.contract.schema_reader import SchemaReader
from guardian.audit.logger import log_onboarding
from guardian.config import ContractConfig

MappedHandler = Callable[[dict[str, Any], MappingProfile], Awaitable[Any]]


class OnboardingManager:
    def __init__(
        self,
        registry: ProfileRegistry,
        proposers: Sequence[Proposer],
        settings: ContractConfig,
        audit: Any,
        *,
        process_mapped: MappedHandler | None = None,
        reader: SchemaReader | None = None,
    ) -> None:
        self.registry = registry
        self.proposers = list(proposers)
        self.settings = settings
        self.audit = audit
        self.process_mapped = process_mapped
        self.reader = reader or SchemaReader()
        self._buffers: dict[str, deque[dict[str, Any]]] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}

    def fingerprint_for(self, envelope: dict[str, Any], twin_identity: str) -> str:
        payload = envelope.get("payload")
        keys = sorted(payload) if isinstance(payload, dict) else []
        schema_id = envelope.get("schema_id") if isinstance(envelope.get("schema_id"), str) else None
        event_type = str(envelope.get("type") or "unknown")
        return shape_fingerprint(
            twin_identity=twin_identity,
            event_type=event_type,
            schema_id=schema_id,
            payload_keys=keys,
        )

    def submit(self, envelope: dict[str, Any], *, twin_identity: str) -> str:
        """Buffer one envelope and start at most one task for its fingerprint."""
        fingerprint = self.fingerprint_for(envelope, twin_identity)
        existing = self.registry.get(fingerprint)
        if existing is not None and existing.status == "UNMAPPABLE":
            return fingerprint
        buffer = self._buffers.setdefault(
            fingerprint, deque(maxlen=self.settings.onboarding_buffer)
        )
        buffer.append(envelope)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return fingerprint
        if fingerprint not in self._tasks or self._tasks[fingerprint].done():
            self._tasks[fingerprint] = loop.create_task(self._run(fingerprint, twin_identity))
        return fingerprint

    async def run_now(self, fingerprint: str, twin_identity: str) -> None:
        """Test helper: run onboarding without waiting on create_task."""
        await self._run(fingerprint, twin_identity)

    def reset(self, fingerprint: str) -> None:
        """Drop an UNMAPPABLE record so the shape can be tried again."""
        record = self.registry.get(fingerprint)
        if record is None or record.status != "UNMAPPABLE":
            raise MappingError(MappingErrorCode.UNKNOWN_SCHEMA, "profile record was not found")
        with self.registry._lock:
            self.registry._records.pop(fingerprint, None)
        path = self.registry.profile_dir / f"{fingerprint}.json"
        if path.is_file():
            path.unlink()
        self._buffers.pop(fingerprint, None)
        log_onboarding(self.audit, "PROFILE_RESET", fingerprint)

    async def _run(self, fingerprint: str, twin_identity: str) -> None:
        try:
            await asyncio.wait_for(
                self._attempt(fingerprint, twin_identity),
                timeout=self.settings.onboarding_timeout_seconds,
            )
        except TimeoutError:
            self._fail(fingerprint, twin_identity, "ONBOARDING_TIMEOUT")
        except Exception:
            self._fail(fingerprint, twin_identity, "SCHEMA_UNMAPPABLE")

    async def _attempt(self, fingerprint: str, twin_identity: str) -> None:
        samples = list(self._buffers.get(fingerprint, ()))
        if not samples:
            return
        event_type = str(samples[0].get("type") or "unknown")
        schema_id = samples[0].get("schema_id") if isinstance(samples[0].get("schema_id"), str) else fingerprint
        description = self.reader.read_sample(samples[0], str(schema_id))
        proposals = [item for proposer in self.proposers if (item := proposer.propose(description))]
        profile, results = run_gates(
            proposals,
            description,
            samples,
            min_proposers=self.settings.onboarding_min_proposers,
        )
        gate_results = {item.name: item.reason for item in results}
        if profile is None:
            self._fail(fingerprint, twin_identity, "SCHEMA_UNMAPPABLE", gate_results=gate_results)
            return
        record = ProfileRecord(
            profile=profile,
            status="PROBATION",
            fingerprint=fingerprint,
            twin_identity=twin_identity,
            event_type=event_type,
            proposers_agreed=[item.proposer for item in proposals],
            gate_results=gate_results,
        )
        self.registry.register(record)
        log_onboarding(self.audit, "PROFILE_PROBATION", fingerprint, consensus=gate_results.get("consensus"))
        if self.process_mapped is not None:
            for sample in list(self._buffers.get(fingerprint, ())):
                await self.process_mapped(sample, profile)
        self._buffers.pop(fingerprint, None)

    def _fail(
        self,
        fingerprint: str,
        twin_identity: str,
        event: str,
        *,
        gate_results: dict[str, str] | None = None,
    ) -> None:
        samples = list(self._buffers.get(fingerprint, ()))
        event_type = str(samples[0].get("type") or "unknown") if samples else "unknown"
        self.registry.register(
            ProfileRecord(
                profile=None,
                status="UNMAPPABLE",
                fingerprint=fingerprint,
                twin_identity=twin_identity,
                event_type=event_type,
                gate_results=gate_results or {},
            )
        )
        log_onboarding(self.audit, event, fingerprint)
        self._buffers.pop(fingerprint, None)
