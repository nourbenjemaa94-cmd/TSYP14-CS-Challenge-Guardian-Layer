"""
Guardian Configuration Module
Manages runtime configuration, partner endpoints, security policies, and detection parameters.
"""

import os
from typing import List, Optional
from pydantic import BaseModel, Field


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


class SecurityConfig(BaseModel):
    api_auth_secret: str = Field(
        default_factory=lambda: os.getenv("API_AUTH_SECRET", "triplet07-supersecret-token")
    )
    token_max_age_seconds: int = Field(
        default_factory=lambda: int(os.getenv("TOKEN_MAX_AGE_SECONDS", "300"))
    )
    valid_tokens: List[str] = ["valid_token", "triplet07-supersecret-token"]


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
    server: ServerConfig = ServerConfig()
    partners: PartnerConfig = PartnerConfig()
    security: SecurityConfig = SecurityConfig()
    detection: DetectionConfig = DetectionConfig()
    log_dir: str = Field(default_factory=lambda: os.getenv("AUDIT_LOG_DIR", "../logs"))


settings = Settings()

