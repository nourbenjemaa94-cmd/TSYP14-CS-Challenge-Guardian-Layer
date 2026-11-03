"""
Guardian Configuration Module
Manages runtime configuration, partner endpoints, security policies, and detection parameters.
"""

import os

from pydantic import BaseModel, ConfigDict, Field

from guardian.security.gate import SecuritySettings


class ServerConfig(BaseModel):
    host: str = Field(default_factory=lambda: os.getenv("GUARDIAN_HOST", "0.0.0.0"))
    port: int = Field(default_factory=lambda: int(os.getenv("GUARDIAN_PORT", "8000")))
    debug: bool = Field(default_factory=lambda: os.getenv("DEBUG", "False").lower() in ("true", "1"))


class PartnerConfig(BaseModel):
    city_brain_url: str = Field(
        default_factory=lambda: os.getenv("CITY_BRAIN_URL", "http://localhost:8002/api/v1/brain/ingest")
    )
    twin_mqtt_broker: str = Field(
        default_factory=lambda: os.getenv("TWIN_MQTT_BROKER", "localhost")
    )
    twin_mqtt_port: int = Field(
        default_factory=lambda: int(os.getenv("TWIN_MQTT_PORT", "1883"))
    )
    twin_mqtt_topic: str = Field(
        default_factory=lambda: os.getenv("TWIN_MQTT_TOPIC", "sensors/telemetry/raw")
    )


def _env_str(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


class ContractConfig(BaseModel):
    """LLM, profile, and onboarding settings. Names match handoff section 9."""

    llm_provider: str = Field(default_factory=lambda: _env_str("GUARDIAN_LLM_PROVIDER", "ollama"))
    llm_url: str = Field(default_factory=lambda: _env_str("GUARDIAN_LLM_URL", "http://localhost:11434"))
    llm_model: str = Field(default_factory=lambda: _env_str("GUARDIAN_LLM_MODEL", ""))
    embed_model: str = Field(default_factory=lambda: _env_str("GUARDIAN_EMBED_MODEL", "nomic-embed-text"))
    llm_timeout_seconds: int = Field(default_factory=lambda: _env_int("GUARDIAN_LLM_TIMEOUT_SECONDS", 60))
    llm_num_ctx: int = Field(default_factory=lambda: _env_int("GUARDIAN_LLM_NUM_CTX", 2048))
    llm_num_gpu: int = Field(default_factory=lambda: _env_int("GUARDIAN_LLM_NUM_GPU", -1))
    profile_dir: str = Field(default_factory=lambda: _env_str("GUARDIAN_PROFILE_DIR", "data/profiles"))
    onboarding_buffer: int = Field(default_factory=lambda: _env_int("GUARDIAN_ONBOARDING_BUFFER", 20))
    onboarding_timeout_seconds: int = Field(
        default_factory=lambda: _env_int("GUARDIAN_ONBOARDING_TIMEOUT_SECONDS", 120)
    )
    probation_messages: int = Field(default_factory=lambda: _env_int("GUARDIAN_PROBATION_MESSAGES", 20))


class DetectionConfig(BaseModel):
    flood_water_spike_cm: float = Field(
        default_factory=lambda: float(os.getenv("FLOOD_WATER_SPIKE_CM", "200.0"))
    )
    sliding_window_size: int = Field(
        default_factory=lambda: int(os.getenv("SLIDING_WINDOW_SIZE", "20"))
    )
    trust_threshold_isolate: float = Field(
        default_factory=lambda: float(os.getenv("TRUST_THRESHOLD_ISOLATE", "0.4"))
    )
    trust_threshold_suspicious: float = Field(
        default_factory=lambda: float(os.getenv("TRUST_THRESHOLD_SUSPICIOUS", "0.7"))
    )


class Settings(BaseModel):
    """Runtime settings. Importing this module does not read secrets.

    ``load`` is what ``main.create_app`` calls. It is the only path that
    requires the HMAC keys.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    server: ServerConfig = Field(default_factory=ServerConfig)
    partners: PartnerConfig = Field(default_factory=PartnerConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    contract: ContractConfig = Field(default_factory=ContractConfig)
    log_dir: str = Field(default_factory=lambda: os.getenv("AUDIT_LOG_DIR", "../logs"))
    security: SecuritySettings | None = None

    @classmethod
    def load(cls) -> "Settings":
        return cls(security=SecuritySettings.from_env())


# Non-secret defaults for the pipeline that still imports ``settings``.
# create_app() (Phase 2.4) calls Settings.load() instead.
settings = Settings()

