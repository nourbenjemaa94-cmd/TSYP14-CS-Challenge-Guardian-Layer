"""Entry point for the security sub-layer.

``admit`` checks size, JSON, the signature, the caller's permission, and the
rate limit. ``accept`` checks the canonical envelope, that mapping did not
change the sender, freshness, and replay. Nothing that remembers a message
runs until authentication has succeeded, and replay state is updated last.
"""

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

from guardian.security.authentication import sign_envelope, verify_signature
from guardian.security.authorization import authorize
from guardian.security.errors import ReasonCode, SecurityConfigurationError, SecurityRejection, WarningCode
from guardian.security.freshness import check_freshness
from guardian.security.rate_limit import RateLimiter, rate_limit_device_id
from guardian.security.replay_protection import ReplayProtector
from guardian.security.validation import (
    check_size,
    claimed_source,
    parse_json_object,
    safe_event_id,
    validate_envelope,
)

_KEY_VARS = (
    ("hmac_key_twin", "GUARDIAN_HMAC_KEY_TWIN"),
    ("hmac_key_brain", "GUARDIAN_HMAC_KEY_BRAIN"),
    ("hmac_key_guardian", "GUARDIAN_HMAC_KEY_GUARDIAN"),
)

_TUNABLE_ENV = {
    "max_message_bytes": "GUARDIAN_MAX_MESSAGE_BYTES",
    "schema_major": "GUARDIAN_SCHEMA_MAJOR",
    "allowed_types": "GUARDIAN_ALLOWED_TYPES",
    "max_age_seconds": "GUARDIAN_MAX_AGE_SECONDS",
    "max_future_skew_seconds": "GUARDIAN_MAX_FUTURE_SKEW_SECONDS",
    "rate_per_source": "GUARDIAN_RATE_PER_SOURCE",
    "rate_burst": "GUARDIAN_RATE_BURST",
    "flood_threshold": "GUARDIAN_FLOOD_THRESHOLD",
}

_ENV_NAMES = (
    "GUARDIAN_HMAC_KEY_TWIN",
    "GUARDIAN_HMAC_KEY_BRAIN",
    "GUARDIAN_HMAC_KEY_GUARDIAN",
    "GUARDIAN_MAX_MESSAGE_BYTES",
    "GUARDIAN_SCHEMA_MAJOR",
    "GUARDIAN_ALLOWED_TYPES",
    "GUARDIAN_MAX_AGE_SECONDS",
    "GUARDIAN_MAX_FUTURE_SKEW_SECONDS",
    "GUARDIAN_RATE_PER_SOURCE",
    "GUARDIAN_RATE_BURST",
    "GUARDIAN_FLOOD_THRESHOLD",
)


class _Tunables(BaseSettings):
    """Non-secret knobs. HMAC keys are loaded separately so errors cannot echo them."""

    model_config = SettingsConfigDict(extra="ignore", populate_by_name=True)

    max_message_bytes: int = Field(default=65_536, alias="GUARDIAN_MAX_MESSAGE_BYTES")
    schema_major: int = Field(default=1, alias="GUARDIAN_SCHEMA_MAJOR")
    allowed_types: str = Field(default="", alias="GUARDIAN_ALLOWED_TYPES")
    max_age_seconds: float = Field(default=30, alias="GUARDIAN_MAX_AGE_SECONDS")
    max_future_skew_seconds: float = Field(default=5, alias="GUARDIAN_MAX_FUTURE_SKEW_SECONDS")
    rate_per_source: float = Field(default=5, alias="GUARDIAN_RATE_PER_SOURCE")
    rate_burst: int = Field(default=20, alias="GUARDIAN_RATE_BURST")
    flood_threshold: int = Field(default=10, alias="GUARDIAN_FLOOD_THRESHOLD")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: Any,
        env_settings: Any,
        dotenv_settings: Any,
        file_secret_settings: Any,
    ) -> tuple[Any, ...]:
        # Values are passed in by from_env. Ignore the process environment so a
        # developer's shell cannot change an explicit mapping.
        del settings_cls, env_settings, dotenv_settings, file_secret_settings
        return (init_settings,)


@dataclass(frozen=True)
class SecuritySettings:
    """Runtime security configuration. The repr deliberately omits HMAC keys."""

    hmac_key_twin: str = field(repr=False)
    hmac_key_brain: str = field(repr=False)
    hmac_key_guardian: str = field(repr=False)
    max_message_bytes: int = 65_536
    schema_major: int = 1
    allowed_types: tuple[str, ...] = ()
    max_age_seconds: float = 30.0
    max_future_skew_seconds: float = 5.0
    rate_per_source: float = 5.0
    rate_burst: int = 20
    flood_threshold: int = 10

    def __post_init__(self) -> None:
        _ensure_safe(self)

    def allows(self, message_type: str) -> bool:
        if not self.allowed_types:
            return True
        return message_type in self.allowed_types

    def key_for(self, layer: str) -> str | None:
        return _keys(self).get(layer)

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        dotenv_path: Path | None = None,
    ) -> "SecuritySettings":
        """Load settings. Missing or short keys raise ``SecurityConfigurationError``."""
        env = _resolve_env(environ, dotenv_path)
        key_problems: list[str] = []
        keys: dict[str, str] = {}
        for _field_name, var_name in _KEY_VARS:
            value = env.get(var_name)
            if not isinstance(value, str) or len(value) < 32:
                key_problems.append(f"{var_name} is missing or shorter than 32 characters")
            else:
                keys[var_name] = value
        if key_problems:
            raise SecurityConfigurationError("Guardian cannot start: " + "; ".join(key_problems) + ".")

        tunable_input = {
            name: env[name]
            for name in _ENV_NAMES
            if name in env and not name.startswith("GUARDIAN_HMAC_KEY_") and str(env[name]).strip() != ""
        }
        try:
            tunables = _Tunables.model_validate(tunable_input)
        except ValidationError as exc:
            labels = sorted(
                {
                    _TUNABLE_ENV.get(str(err["loc"][0]), str(err["loc"][0]))
                    for err in exc.errors()
                    if err.get("loc")
                }
            )
            detail = ", ".join(labels) if labels else "numeric setting"
            raise SecurityConfigurationError(
                f"Guardian cannot start: invalid setting(s): {detail}."
            ) from None

        allowed = tuple(part.strip() for part in tunables.allowed_types.split(",") if part.strip())
        return cls(
            hmac_key_twin=keys["GUARDIAN_HMAC_KEY_TWIN"],
            hmac_key_brain=keys["GUARDIAN_HMAC_KEY_BRAIN"],
            hmac_key_guardian=keys["GUARDIAN_HMAC_KEY_GUARDIAN"],
            max_message_bytes=tunables.max_message_bytes,
            schema_major=tunables.schema_major,
            allowed_types=allowed,
            max_age_seconds=tunables.max_age_seconds,
            max_future_skew_seconds=tunables.max_future_skew_seconds,
            rate_per_source=tunables.rate_per_source,
            rate_burst=tunables.rate_burst,
            flood_threshold=tunables.flood_threshold,
        )


@dataclass(frozen=True)
class AdmittedMessage:
    """A message that passed authentication, authorization, and the rate limit."""

    body: dict[str, Any]
    authenticated_layer: str
    operation: str
    source_key: str
    event_id: str | None


@dataclass(frozen=True)
class AcceptedMessage:
    """A canonical envelope the core is allowed to see."""

    envelope: dict[str, Any]
    warnings: tuple[WarningCode, ...]
    authenticated_layer: str
    operation: str
    source_key: str
    event_id: str


class SecurityGate:
    """Transport-independent front door. Adapters call this; it never calls them."""

    def __init__(
        self,
        settings: SecuritySettings,
        *,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
        max_sources: int = 10_000,
    ) -> None:
        _ensure_safe(settings)
        self.settings = settings
        self.clock = clock or (lambda: datetime.now(UTC))
        mono = monotonic or _import_monotonic()
        self._limiter = RateLimiter(
            rate_per_second=settings.rate_per_source,
            burst=settings.rate_burst,
            flood_threshold=settings.flood_threshold,
            clock=mono,
            max_sources=max_sources,
        )
        self._replay = ReplayProtector(window_seconds=settings.max_age_seconds)

    def admit(self, raw: bytes, operation: str) -> AdmittedMessage:
        """Size, parse, authenticate, authorize, then rate-limit. No replay state here."""
        if not isinstance(raw, (bytes, bytearray)):
            raise SecurityRejection(ReasonCode.MALFORMED_JSON, detail="Body is not bytes.")
        body_bytes = bytes(raw)
        try:
            check_size(body_bytes, self.settings.max_message_bytes)
            body = parse_json_object(body_bytes)
        except SecurityRejection:
            raise
        event_id = safe_event_id(body)
        try:
            layer = self._authenticate(body, event_id)
        except SecurityRejection as exc:
            if exc.source is None:
                exc.source = claimed_source(body)
            raise
        source_key = f"{layer}:{rate_limit_device_id(body)}"
        try:
            authorize(layer, operation)
        except SecurityRejection as exc:
            exc.event_id = event_id
            exc.source = source_key
            raise
        self._limiter.check(source_key, event_id=event_id)
        return AdmittedMessage(
            body=body,
            authenticated_layer=layer,
            operation=operation,
            source_key=source_key,
            event_id=event_id,
        )

    def accept(self, admitted: AdmittedMessage, canonical: dict[str, Any]) -> AcceptedMessage:
        """Validate the mapped envelope, then freshness, then replay."""
        if not isinstance(canonical, dict):
            raise SecurityRejection(
                ReasonCode.SCHEMA_INVALID,
                event_id=admitted.event_id,
                fields=["body"],
                source=admitted.source_key,
            )
        try:
            envelope = validate_envelope(
                canonical,
                schema_major=self.settings.schema_major,
                allowed_types=self.settings.allowed_types,
            )
        except SecurityRejection as exc:
            if exc.event_id is None:
                exc.event_id = admitted.event_id
            if exc.source is None:
                exc.source = admitted.source_key
            raise
        if envelope.source.layer != admitted.authenticated_layer:
            raise SecurityRejection(
                ReasonCode.SOURCE_MISMATCH,
                event_id=envelope.event_id,
                source=admitted.source_key,
                detail="Mapper changed source.layer.",
            )
        source_key = f"{envelope.source.layer}:{envelope.source.device_id or '-'}"
        try:
            check_freshness(
                envelope.timestamp,
                now=self.clock(),
                max_age_seconds=self.settings.max_age_seconds,
                max_future_skew_seconds=self.settings.max_future_skew_seconds,
            )
        except SecurityRejection as exc:
            exc.event_id = envelope.event_id
            exc.source = source_key
            raise
        warnings = self._replay.observe(
            source_key=source_key,
            event_id=envelope.event_id,
            seq=envelope.seq,
            now=self.clock(),
        )
        return AcceptedMessage(
            envelope=_copy_envelope(canonical),
            warnings=tuple(warnings),
            authenticated_layer=admitted.authenticated_layer,
            operation=admitted.operation,
            source_key=source_key,
            event_id=envelope.event_id,
        )

    def check_inbound(
        self,
        raw: bytes,
        operation: str,
        canonical: dict[str, Any] | None = None,
    ) -> AcceptedMessage:
        """Admit ``raw`` and accept ``canonical``, or the parsed body when no mapping is given."""
        admitted = self.admit(raw, operation)
        mapped = admitted.body if canonical is None else canonical
        return self.accept(admitted, mapped)

    def sign_outbound(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        """Sign a Guardian-originated envelope with the Guardian key."""
        if not isinstance(envelope, Mapping):
            raise SecurityConfigurationError("Outbound envelope must be an object.")
        import copy

        body = copy.deepcopy({key: envelope[key] for key in envelope if key != "signature"})
        source = body.get("source")
        if not isinstance(source, dict) or source.get("layer") != "guardian":
            raise SecurityConfigurationError("Outbound messages must use source.layer 'guardian'.")
        try:
            validate_envelope(body, schema_major=self.settings.schema_major, allowed_types=())
        except SecurityRejection:
            raise SecurityConfigurationError(
                "Refusing to sign an outbound envelope that does not match the schema."
            ) from None
        try:
            return sign_envelope(body, self.settings.hmac_key_guardian)
        except (TypeError, ValueError):
            raise SecurityConfigurationError("Outbound envelope is not JSON-serialisable.") from None

    def flooding_sources(self) -> tuple[str, ...]:
        """Sources whose recent rate-limit rejections crossed the flood threshold."""
        return self._limiter.flooding_sources()

    def _authenticate(self, body: dict[str, Any], event_id: str | None) -> str:
        signature = body.get("signature", None)
        if "signature" not in body or signature is None or signature == "":
            raise SecurityRejection(ReasonCode.SIGNATURE_MISSING, event_id=event_id)
        if not isinstance(signature, str):
            raise SecurityRejection(ReasonCode.SIGNATURE_INVALID, event_id=event_id)
        source = body.get("source")
        layer = source.get("layer") if isinstance(source, dict) else None
        key = self.settings.key_for(layer) if isinstance(layer, str) else None
        # TODO(security): ASSUMPTION — source.layer selects the HMAC key. A layer
        # name outside twin/brain/guardian is UNKNOWN_SENDER. A bad signature for
        # a known layer is SIGNATURE_INVALID, including a signature made with
        # another layer's key.
        if key is None:
            raise SecurityRejection(ReasonCode.UNKNOWN_SENDER, event_id=event_id)
        if not verify_signature(body, key):
            raise SecurityRejection(
                ReasonCode.SIGNATURE_INVALID,
                event_id=event_id,
                detail="HMAC mismatch.",
            )
        return layer


def _keys(settings: SecuritySettings) -> dict[str, str]:
    return {
        "twin": settings.hmac_key_twin,
        "brain": settings.hmac_key_brain,
        "guardian": settings.hmac_key_guardian,
    }


def _ensure_safe(settings: SecuritySettings) -> None:
    problems: list[str] = []
    for attr, var_name in _KEY_VARS:
        value = getattr(settings, attr)
        if not isinstance(value, str) or len(value) < 32:
            problems.append(f"{var_name} is missing or shorter than 32 characters")
    if not isinstance(settings.max_message_bytes, int) or isinstance(settings.max_message_bytes, bool):
        problems.append("GUARDIAN_MAX_MESSAGE_BYTES must be a positive integer")
    elif settings.max_message_bytes <= 0:
        problems.append("GUARDIAN_MAX_MESSAGE_BYTES must be a positive integer")
    if not isinstance(settings.schema_major, int) or isinstance(settings.schema_major, bool):
        problems.append("GUARDIAN_SCHEMA_MAJOR must be an integer >= 1")
    elif settings.schema_major < 1:
        problems.append("GUARDIAN_SCHEMA_MAJOR must be an integer >= 1")
    if isinstance(settings.max_age_seconds, bool) or not isinstance(settings.max_age_seconds, (int, float)):
        problems.append("GUARDIAN_MAX_AGE_SECONDS must be a positive number")
    elif settings.max_age_seconds <= 0:
        problems.append("GUARDIAN_MAX_AGE_SECONDS must be a positive number")
    if isinstance(settings.max_future_skew_seconds, bool) or not isinstance(
        settings.max_future_skew_seconds, (int, float)
    ):
        problems.append("GUARDIAN_MAX_FUTURE_SKEW_SECONDS must be a number >= 0")
    elif settings.max_future_skew_seconds < 0:
        problems.append("GUARDIAN_MAX_FUTURE_SKEW_SECONDS must be a number >= 0")
    if isinstance(settings.rate_per_source, bool) or not isinstance(settings.rate_per_source, (int, float)):
        problems.append("GUARDIAN_RATE_PER_SOURCE must be a positive number")
    elif settings.rate_per_source <= 0:
        problems.append("GUARDIAN_RATE_PER_SOURCE must be a positive number")
    if not isinstance(settings.rate_burst, int) or isinstance(settings.rate_burst, bool):
        problems.append("GUARDIAN_RATE_BURST must be an integer >= 1")
    elif settings.rate_burst < 1:
        problems.append("GUARDIAN_RATE_BURST must be an integer >= 1")
    if not isinstance(settings.flood_threshold, int) or isinstance(settings.flood_threshold, bool):
        problems.append("GUARDIAN_FLOOD_THRESHOLD must be an integer >= 1")
    elif settings.flood_threshold < 1:
        problems.append("GUARDIAN_FLOOD_THRESHOLD must be an integer >= 1")
    if problems:
        raise SecurityConfigurationError("Guardian cannot start: " + "; ".join(problems) + ".")


def _resolve_env(environ: Mapping[str, str] | None, dotenv_path: Path | None) -> dict[str, str]:
    if environ is not None:
        return {key: str(value) for key, value in environ.items()}
    merged: dict[str, str] = {}
    path = dotenv_path if dotenv_path is not None else Path.cwd() / ".env"
    if path.is_file():
        merged.update(_parse_dotenv(path))
    for name in _ENV_NAMES:
        if name in os.environ:
            merged[name] = os.environ[name]
    return merged


def _parse_dotenv(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        raise SecurityConfigurationError("Guardian cannot start: .env could not be read.") from None
    values: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].strip()
        if "=" not in stripped:
            continue
        name, raw_value = stripped.split("=", 1)
        name = name.strip()
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if name:
            values[name] = value
    return values


def _copy_envelope(canonical: dict[str, Any]) -> dict[str, Any]:
    import copy

    return copy.deepcopy(canonical)


def _import_monotonic() -> Callable[[], float]:
    import time

    return time.monotonic
