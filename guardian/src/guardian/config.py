"""Typed Guardian configuration with YAML and environment precedence."""

from __future__ import annotations

import copy
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from guardian.security.errors import SecurityConfigurationError
from guardian.security.gate import SecuritySettings, read_dotenv


def _env_value(environ: Mapping[str, str], *names: str) -> str | None:
    for name in names:
        value = environ.get(name)
        if value is not None and value.strip():
            return value.strip()
    return None


def _override(data: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    current = data
    for part in path[:-1]:
        current = current.setdefault(part, {})
    current[path[-1]] = value


def _process_environment() -> dict[str, str]:
    """Process environment layered over ``./.env``.

    Mirrors the precedence ``SecuritySettings.from_env`` applies when it is
    called without an explicit mapping: a private ``.env`` in the working
    directory supplies defaults, and real environment variables win. Values
    are never logged.
    """
    dotenv = Path.cwd() / ".env"
    merged: dict[str, str] = read_dotenv(dotenv) if dotenv.is_file() else {}
    merged.update(os.environ)
    return merged


def _env_list(value: str) -> list[str]:
    items = [item.strip() for item in value.split(",") if item.strip()]
    if not items:
        raise ValueError("must list at least one value")
    return items


def _env_bool(value: str) -> bool:
    if value.lower() not in {"true", "false", "1", "0", "yes", "no"}:
        raise ValueError("must be a boolean")
    return value.lower() in {"true", "1", "yes"}


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    host: str = "0.0.0.0"
    port: int = Field(default=8000, ge=1, le=65535)
    debug: bool = False
    workers: int = Field(default=1, ge=1)
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])
    timeline_mode: str = Field(default="disabled", pattern="^(disabled|local|demo)$")


class MqttConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    host: str = "localhost"
    # 8883 is the IANA MQTT-over-TLS port, matching tls_enabled=True below and
    # MqttAdapter's own default; a plaintext broker is 1883 with tls_enabled=false.
    port: int = Field(default=8883, ge=1, le=65535)
    topic: str = "sensors/telemetry/raw"
    tls_enabled: bool = True
    ca_cert: str | None = None
    client_cert: str | None = None
    client_key: str | None = None

    @field_validator("host", "topic")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value.strip()

    @model_validator(mode="after")
    def validate_tls_files(self) -> MqttConfig:
        if bool(self.client_cert) != bool(self.client_key):
            raise ValueError("client_cert and client_key must be provided together")
        if not self.tls_enabled and any((self.ca_cert, self.client_cert, self.client_key)):
            raise ValueError("TLS certificate paths require tls_enabled=true")
        return self


class TwinPartnerConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    adapter: str = "rest"
    type: str = "rest"
    listen_path: str = "/api/v1/telemetry"
    identity: str = "twin:S01"
    mqtt: MqttConfig = Field(default_factory=MqttConfig)


class BrainPartnerConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    adapter: str = "rest"
    type: str = "rest"
    endpoint: str = "http://localhost:8002/api/v1/brain/ingest"
    timeout_seconds: float = Field(default=10.0, gt=0)
    retry_count: int = Field(default=0, ge=0)
    # Gatekeeper (True) pushes verdicts to the Brain; observer (False) only stores
    # them for GET /api/v1/verdicts/{event_id} and POST /v1/verdicts/query.
    forward: bool = True

    @field_validator("endpoint")
    @classmethod
    def absolute_endpoint(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("must be an absolute HTTP(S) URL")
        return value


class PartnerConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    twin: TwinPartnerConfig = Field(default_factory=TwinPartnerConfig)
    brain: BrainPartnerConfig = Field(default_factory=BrainPartnerConfig)

    @property
    def city_brain_url(self) -> str:
        return self.brain.endpoint

    @property
    def city_brain_timeout_seconds(self) -> float:
        return self.brain.timeout_seconds

    @property
    def city_brain_max_retries(self) -> int:
        return self.brain.retry_count

    @property
    def twin_mqtt_broker(self) -> str:
        return self.twin.mqtt.host

    @property
    def twin_mqtt_port(self) -> int:
        return self.twin.mqtt.port

    @property
    def twin_mqtt_topic(self) -> str:
        return self.twin.mqtt.topic


class AdapterConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    twin: str = "rest"
    brain: str = "rest"


class ContractConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    llm_provider: str = "ollama"
    llm_url: str = "http://localhost:11434"
    llm_model: str = ""
    embed_model: str = "nomic-embed-text"
    llm_timeout_seconds: int = Field(default=60, gt=0)
    llm_num_ctx: int = Field(default=2048, gt=0)
    llm_num_gpu: int = -1
    profile_dir: str = "data/profiles"
    onboarding_buffer: int = Field(default=20, ge=0)
    onboarding_timeout_seconds: int = Field(default=120, gt=0)
    # Independent proposers (heuristic, embedding, chat model) that must agree
    # before an onboarding proposal is accepted. 1 = heuristic alone.
    onboarding_min_proposers: int = Field(default=2, ge=1, le=3)
    probation_messages: int = Field(default=20, ge=0)


class DetectionConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    flood_water_spike_cm: float = Field(default=200.0, ge=0)
    sliding_window_size: int = Field(default=20, ge=2)
    trust_threshold_isolate: float = Field(default=0.4, ge=0, le=1)
    trust_threshold_suspicious: float = Field(default=0.7, ge=0, le=1)


class TrustSettings(BaseModel):
    """Trust policy handed to ``TrustConfig.from_mapping``.

    Only keys the Core consumes are accepted; an unknown key is a startup
    error rather than a silently ignored setting (QA finding CFG-02).
    """

    model_config = ConfigDict(extra="forbid")
    isolate_threshold: float = Field(default=0.4, ge=0, le=1)
    quarantine_threshold: float = Field(default=0.7, ge=0, le=1)
    recovery_clean_readings: int = Field(default=3, ge=0)
    full_confidence_readings: int = Field(default=10, ge=1)
    policy_version: str = "1.0"

    @model_validator(mode="after")
    def thresholds_are_ordered(self) -> TrustSettings:
        if self.isolate_threshold > self.quarantine_threshold:
            raise ValueError("isolate_threshold must not exceed quarantine_threshold")
        return self


class AuditSettings(BaseModel):
    """Audit section. ``sqlite_path`` is reserved: accepted, not yet consumed."""

    model_config = ConfigDict(extra="forbid")
    timeline_channel: str = "/ws/timeline"
    log_directory: str | None = None
    sqlite_path: str | None = None


class PublicSecurityConfig(BaseModel):
    """Non-secret security policy read from YAML.

    HMAC material is deliberately absent.  It is resolved only by
    ``SecuritySettings.from_env`` after this public configuration validates.
    """

    model_config = ConfigDict(extra="ignore")
    enabled: bool = True
    max_message_bytes: int = Field(default=65_536, gt=0)
    schema_major: int = Field(default=1, ge=0)
    allowed_types: str = ""
    max_age_seconds: float = Field(default=30.0, gt=0)
    freshness_window_seconds: float | None = Field(default=None, gt=0)
    max_future_skew_seconds: float = Field(default=5.0, ge=0)
    rate_per_source: float = Field(default=5.0, gt=0)
    rate_burst: int = Field(default=20, ge=1)
    flood_threshold: int = Field(default=10, ge=1)
    replay_cache_size: int = Field(default=10_000, ge=1)


class Settings(BaseModel):
    """Runtime settings: explicit environment > YAML > safe defaults."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="ignore")
    server: ServerConfig = Field(default_factory=ServerConfig)
    partners: PartnerConfig = Field(default_factory=PartnerConfig)
    adapters: AdapterConfig = Field(default_factory=AdapterConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    contract: ContractConfig = Field(default_factory=ContractConfig)
    trust: TrustSettings = Field(default_factory=TrustSettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    log_dir: str = "../logs"
    security: PublicSecurityConfig = Field(default_factory=PublicSecurityConfig)

    @classmethod
    def load(cls, path: str | Path | None = None, *, environ: Mapping[str, str] | None = None) -> Settings:
        env = _process_environment() if environ is None else environ
        selected = Path(path) if path is not None else Path(env.get("GUARDIAN_CONFIG", "guardian/config.yaml"))
        raw = cls._read_yaml(selected, required=path is not None or bool(env.get("GUARDIAN_CONFIG")))
        merged = copy.deepcopy(raw)
        cls._apply_environment(merged, env)
        try:
            settings = cls.model_validate(merged)
        except ValidationError as exc:
            detail = "; ".join(f"{'.'.join(map(str, err['loc']))}: {err['msg']}" for err in exc.errors())
            raise SecurityConfigurationError(f"Guardian cannot start: invalid configuration: {detail}") from None
        # audit.log_directory is the YAML spelling of log_dir; AUDIT_LOG_DIR and a
        # top-level log_dir keep precedence over it.
        if settings.audit.log_directory and "log_dir" not in merged:
            settings.log_dir = settings.audit.log_directory
        runtime_env = dict(env)
        cls._apply_yaml_security_overrides(runtime_env, settings.security)
        settings.security = SecuritySettings.from_env(environ=runtime_env)
        return settings

    @staticmethod
    def _apply_yaml_security_overrides(
        environ: dict[str, str], public: PublicSecurityConfig
    ) -> None:
        """Fill runtime tunables from public YAML without overriding env values."""
        values: dict[str, Any] = {
            "GUARDIAN_MAX_MESSAGE_BYTES": public.max_message_bytes,
            "GUARDIAN_SCHEMA_MAJOR": public.schema_major,
            "GUARDIAN_ALLOWED_TYPES": public.allowed_types,
            "GUARDIAN_MAX_AGE_SECONDS": (
                public.freshness_window_seconds
                if public.freshness_window_seconds is not None
                else public.max_age_seconds
            ),
            "GUARDIAN_MAX_FUTURE_SKEW_SECONDS": public.max_future_skew_seconds,
            "GUARDIAN_RATE_PER_SOURCE": public.rate_per_source,
            "GUARDIAN_RATE_BURST": public.rate_burst,
            "GUARDIAN_FLOOD_THRESHOLD": public.flood_threshold,
        }
        for name, value in values.items():
            if _env_value(environ, name) is None:
                environ[name] = str(value)

    @staticmethod
    def _read_yaml(path: Path, *, required: bool) -> dict[str, Any]:
        if not path.is_file():
            if required:
                raise SecurityConfigurationError(f"Guardian cannot start: config file not found at {path}.")
            return {}
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise SecurityConfigurationError(f"Guardian cannot read configuration {path}: {exc}") from None
        except yaml.YAMLError:
            raise SecurityConfigurationError(f"Guardian cannot start: {path} is not valid YAML.") from None
        if loaded is None:
            return {}
        if not isinstance(loaded, dict):
            raise SecurityConfigurationError(f"Guardian cannot start: {path} must contain a YAML mapping.")
        return loaded

    @staticmethod
    def _apply_environment(data: dict[str, Any], env: Mapping[str, str]) -> None:
        values: list[tuple[tuple[str, ...], tuple[str, ...], Any]] = [
            (("server", "host"), ("GUARDIAN_HOST",), str),
            (("server", "port"), ("GUARDIAN_PORT",), int),
            (("server", "debug"), ("DEBUG",), _env_bool),
            (("server", "timeline_mode"), ("GUARDIAN_TIMELINE_MODE",), str),
            (("server", "cors_origins"), ("GUARDIAN_CORS_ORIGINS",), _env_list),
            (("partners", "brain", "endpoint"), ("CITY_BRAIN_URL",), str),
            (("partners", "brain", "timeout_seconds"), ("CITY_BRAIN_TIMEOUT_SECONDS",), float),
            (("partners", "brain", "retry_count"), ("CITY_BRAIN_MAX_RETRIES",), int),
            (("partners", "brain", "forward"), ("GUARDIAN_FORWARD_TO_BRAIN",), _env_bool),
            (("partners", "twin", "mqtt", "host"), ("TWIN_MQTT_BROKER", "MQTT_HOST"), str),
            (("partners", "twin", "mqtt", "port"), ("TWIN_MQTT_PORT", "MQTT_PORT"), int),
            (("partners", "twin", "mqtt", "topic"), ("TWIN_MQTT_TOPIC", "MQTT_TOPIC"), str),
            (("partners", "twin", "mqtt", "tls_enabled"), ("MQTT_TLS_ENABLED",), _env_bool),
            (("partners", "twin", "mqtt", "ca_cert"), ("MQTT_CA_CERT",), str),
            (("partners", "twin", "mqtt", "client_cert"), ("MQTT_CLIENT_CERT",), str),
            (("partners", "twin", "mqtt", "client_key"), ("MQTT_CLIENT_KEY",), str),
            (("partners", "twin", "identity"), ("GUARDIAN_TWIN_IDENTITY",), str),
            (("detection", "flood_water_spike_cm"), ("FLOOD_WATER_SPIKE_CM",), float),
            (("detection", "sliding_window_size"), ("SLIDING_WINDOW_SIZE",), int),
            (("detection", "trust_threshold_isolate"), ("TRUST_THRESHOLD_ISOLATE",), float),
            (("detection", "trust_threshold_suspicious"), ("TRUST_THRESHOLD_SUSPICIOUS",), float),
            (("contract", "llm_provider"), ("GUARDIAN_LLM_PROVIDER",), str),
            (("contract", "llm_url"), ("GUARDIAN_LLM_URL",), str),
            (("contract", "llm_model"), ("GUARDIAN_LLM_MODEL",), str),
            (("contract", "embed_model"), ("GUARDIAN_EMBED_MODEL",), str),
            (("contract", "llm_timeout_seconds"), ("GUARDIAN_LLM_TIMEOUT_SECONDS",), int),
            (("contract", "llm_num_ctx"), ("GUARDIAN_LLM_NUM_CTX",), int),
            (("contract", "llm_num_gpu"), ("GUARDIAN_LLM_NUM_GPU",), int),
            (("contract", "profile_dir"), ("GUARDIAN_PROFILE_DIR",), str),
            (("contract", "onboarding_buffer"), ("GUARDIAN_ONBOARDING_BUFFER",), int),
            (("contract", "onboarding_timeout_seconds"), ("GUARDIAN_ONBOARDING_TIMEOUT_SECONDS",), int),
            (("contract", "onboarding_min_proposers"), ("GUARDIAN_ONBOARDING_MIN_PROPOSERS",), int),
            (("contract", "probation_messages"), ("GUARDIAN_PROBATION_MESSAGES",), int),
            (("log_dir",), ("AUDIT_LOG_DIR",), str),
        ]
        for path, names, converter in values:
            raw = _env_value(env, *names)
            if raw is not None:
                try:
                    _override(data, path, converter(raw))
                except (TypeError, ValueError):
                    raise SecurityConfigurationError(
                        f"Guardian cannot start: invalid environment setting {names[0]}."
                    ) from None

        detection = data.setdefault("detection", {})
        water = detection.get("water_level", {})
        if isinstance(water, dict) and "spike_threshold_cm" in water and "flood_water_spike_cm" not in detection:
            detection["flood_water_spike_cm"] = water["spike_threshold_cm"]
