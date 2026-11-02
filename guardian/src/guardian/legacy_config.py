"""Load partner addresses, routes, and topics from configuration.

Nothing in the security package hard-codes a URL, port, or topic. This loader
is the only place those values enter the process, and HMAC keys are not read
from the YAML file.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from guardian.security.errors import SecurityConfigurationError

_REQUIRED_ROUTES = frozenset(
    {
        "publish_reading",
        "report_actuator_state",
        "ack_command",
        "request_verdict",
        "get_device_status",
        "report_decision",
        "health",
    }
)
_REQUIRED_INBOUND_TOPICS = frozenset(
    {"publish_reading", "report_actuator_state", "ack_command"}
)


@dataclass(frozen=True)
class RouteSpec:
    operation: str
    method: str
    path: str
    caller: str


@dataclass(frozen=True)
class TopicSpec:
    operation: str
    topic: str
    direction: str


@dataclass(frozen=True)
class AppConfig:
    """Runtime wiring. ``mqtt_password`` is excluded from the repr."""

    http_host: str
    http_port: int
    routes: tuple[RouteSpec, ...]
    topics: tuple[TopicSpec, ...]
    partner_urls: dict[str, str]
    guardian_base_url: str
    mqtt_host: str
    mqtt_port: int
    mqtt_username: str
    mqtt_password: str = ""

    def __repr__(self) -> str:
        return (
            "AppConfig("
            f"http_host={self.http_host!r}, http_port={self.http_port}, "
            f"routes={len(self.routes)}, topics={len(self.topics)})"
        )

    def route(self, operation: str) -> RouteSpec:
        for item in self.routes:
            if item.operation == operation:
                return item
        raise SecurityConfigurationError(f"Guardian cannot start: missing route for {operation}.")

    def partner_url(self, layer: str) -> str:
        try:
            return self.partner_urls[layer]
        except KeyError:
            raise SecurityConfigurationError(
                f"Guardian cannot start: missing partner URL for {layer}."
            ) from None


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_config_path() -> Path:
    override = os.environ.get("GUARDIAN_CONFIG")
    if override:
        return Path(override)
    return repo_root() / "config.example.yaml"


def load_config(path: Path, environ: Mapping[str, str] | None = None) -> AppConfig:
    """Read YAML and apply non-secret environment overrides."""
    env: Mapping[str, str] = os.environ if environ is None else environ
    if not path.is_file():
        raise SecurityConfigurationError(f"Guardian cannot start: config file not found at {path}.")
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError:
        raise SecurityConfigurationError(f"Guardian cannot start: could not read {path.name}.") from None
    except yaml.YAMLError:
        raise SecurityConfigurationError(f"Guardian cannot start: {path.name} is not valid YAML.") from None
    if not isinstance(loaded, dict):
        raise SecurityConfigurationError(f"Guardian cannot start: {path.name} must be a mapping.")

    http = _mapping(loaded.get("http"), "http")
    mqtt = _mapping(loaded.get("mqtt"), "mqtt")
    partners = _mapping(loaded.get("partners"), "partners")
    guardian = _mapping(loaded.get("guardian"), "guardian")
    routes = _routes(loaded.get("routes"))
    topics = _topics(mqtt.get("topics"))
    twin = _mapping(partners.get("twin"), "partners.twin")
    brain = _mapping(partners.get("brain"), "partners.brain")
    partner_urls = {
        "twin": _url(twin.get("base_url"), "partners.twin.base_url"),
        "brain": _url(brain.get("base_url"), "partners.brain.base_url"),
    }
    return AppConfig(
        http_host=_text(_env(env, "GUARDIAN_HTTP_HOST", http.get("host")), "http.host"),
        http_port=_port(_env(env, "GUARDIAN_HTTP_PORT", http.get("port")), "http.port"),
        routes=routes,
        topics=topics,
        partner_urls=partner_urls,
        guardian_base_url=_url(
            _env(env, "GUARDIAN_BASE_URL", guardian.get("base_url")),
            "guardian.base_url",
        ),
        mqtt_host=_text(_env(env, "MQTT_HOST", mqtt.get("host")), "mqtt.host"),
        mqtt_port=_port(_env(env, "MQTT_PORT", mqtt.get("port")), "mqtt.port"),
        mqtt_username=_optional_text(_env(env, "MQTT_USERNAME", mqtt.get("username", ""))),
        mqtt_password=_optional_text(_env(env, "MQTT_PASSWORD", mqtt.get("password", ""))),
    )


def _routes(value: object) -> tuple[RouteSpec, ...]:
    if not isinstance(value, list) or not value:
        raise SecurityConfigurationError("Guardian cannot start: routes must be a non-empty list.")
    routes: list[RouteSpec] = []
    for index, item in enumerate(value):
        data = _mapping(item, f"routes[{index}]")
        operation = _text(data.get("operation"), f"routes[{index}].operation")
        method = _text(data.get("method"), f"routes[{index}].method").upper()
        path = _text(data.get("path"), f"routes[{index}].path")
        caller = _text(data.get("caller"), f"routes[{index}].caller")
        if method not in {"GET", "POST"}:
            raise SecurityConfigurationError(
                f"Guardian cannot start: routes[{index}].method must be GET or POST."
            )
        if not path.startswith("/"):
            raise SecurityConfigurationError(
                f"Guardian cannot start: routes[{index}].path must start with /."
            )
        routes.append(RouteSpec(operation=operation, method=method, path=path, caller=caller))
    present = {route.operation for route in routes}
    missing = sorted(_REQUIRED_ROUTES - present)
    if missing:
        raise SecurityConfigurationError(
            "Guardian cannot start: config is missing routes for " + ", ".join(missing) + "."
        )
    return tuple(routes)


def _topics(value: object) -> tuple[TopicSpec, ...]:
    if not isinstance(value, list) or not value:
        raise SecurityConfigurationError("Guardian cannot start: topics must be a non-empty list.")
    topics: list[TopicSpec] = []
    for index, item in enumerate(value):
        data = _mapping(item, f"topics[{index}]")
        direction = _text(data.get("direction"), f"topics[{index}].direction")
        if direction not in {"inbound", "outbound"}:
            raise SecurityConfigurationError(
                f"Guardian cannot start: topics[{index}].direction must be inbound or outbound."
            )
        topics.append(
            TopicSpec(
                operation=_text(data.get("operation"), f"topics[{index}].operation"),
                topic=_text(data.get("topic"), f"topics[{index}].topic"),
                direction=direction,
            )
        )
    inbound = {topic.operation for topic in topics if topic.direction == "inbound"}
    missing = sorted(_REQUIRED_INBOUND_TOPICS - inbound)
    if missing:
        raise SecurityConfigurationError(
            "Guardian cannot start: config is missing inbound topics for " + ", ".join(missing) + "."
        )
    return tuple(topics)


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SecurityConfigurationError(f"Guardian cannot start: {label} must be a mapping.")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SecurityConfigurationError(f"Guardian cannot start: {label} must be a non-empty string.")
    return value.strip()


def _optional_text(value: object) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        return ""
    return value


def _url(value: object, label: str) -> str:
    text = _text(value, label)
    if "://" not in text:
        raise SecurityConfigurationError(f"Guardian cannot start: {label} must be an absolute URL.")
    return text


def _port(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int | str):
        raise SecurityConfigurationError(f"Guardian cannot start: {label} must be a port number.")
    try:
        port = int(value)
    except ValueError:
        raise SecurityConfigurationError(f"Guardian cannot start: {label} must be a port number.") from None
    if not 1 <= port <= 65535:
        raise SecurityConfigurationError(f"Guardian cannot start: {label} must be a port number.")
    return port


def _env(env: Mapping[str, str], name: str, fallback: object) -> object:
    if name in env and str(env[name]).strip() != "":
        raw = env[name]
        if name.endswith("_PORT"):
            try:
                return int(raw)
            except ValueError:
                raise SecurityConfigurationError(
                    f"Guardian cannot start: {name} must be a port number."
                ) from None
        return raw
    return fallback
