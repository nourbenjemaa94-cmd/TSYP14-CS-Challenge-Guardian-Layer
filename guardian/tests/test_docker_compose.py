import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from guardian.config import Settings
from guardian.security.errors import SecurityConfigurationError

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.yml"


_INTERPOLATION = re.compile(r"\$\{(?P<name>[A-Z0-9_]+)(?::-(?P<default>[^}]*))?\}")


def _interpolate(text: str, variables: dict[str, str] | None = None) -> str:
    """Resolve ``${VAR:-default}`` the way Compose does, without Docker."""
    values = variables or {}

    def replace(match: re.Match[str]) -> str:
        return values.get(match.group("name"), match.group("default") or "")

    return _INTERPOLATION.sub(replace, text)


def test_compose_declares_one_shot_twin_and_explicit_brain_server():
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = document["services"]

    assert services["twin-mock"]["command"][-2:] == ["--mode", "normal"]
    assert services["twin-mock"]["environment"] == ["GUARDIAN_URL=http://guardian:${GUARDIAN_PORT:-8000}"]
    assert services["twin-mock"]["env_file"] == ["./guardian/.env"]
    assert "GUARDIAN_TIMELINE_MODE=disabled" in services["guardian"]["environment"]
    assert "GUARDIAN_PROFILE_DIR=/app/data/profiles" in services["guardian"]["environment"]
    assert "guardian-profiles:/app/data/profiles" in services["guardian"]["volumes"]
    assert "guardian-profiles" in document["volumes"]
    assert "brain-http-mock" in services
    assert "mocks.mock_brain_server" in services["brain-http-mock"]["command"]
    assert services["brain-http-mock"]["env_file"] == ["./guardian/.env"]
    assert "brain-mock" not in services
    assert "city-brain" not in services["guardian"]["environment"][3]


def test_compose_port_and_partner_urls_are_interpolated_with_safe_defaults():
    text = COMPOSE.read_text(encoding="utf-8")
    assert "version:" not in yaml.safe_load(text)

    defaults = yaml.safe_load(_interpolate(text))
    guardian = defaults["services"]["guardian"]
    assert guardian["ports"] == ["8000:8000"]
    assert "GUARDIAN_PORT=8000" in guardian["environment"]
    assert "CITY_BRAIN_URL=http://brain-http-mock:8002/api/v1/brain/ingest" in guardian["environment"]
    assert "GUARDIAN_LLM_URL=http://host.docker.internal:11434" in guardian["environment"]
    assert guardian["healthcheck"]["test"][-1] == "http://localhost:8000/ready"
    assert defaults["services"]["twin-mock"]["environment"] == ["GUARDIAN_URL=http://guardian:8000"]

    overridden = yaml.safe_load(
        _interpolate(text, {"GUARDIAN_PORT": "9443", "CITY_BRAIN_URL": "https://brain.internal/ingest"})
    )
    guardian = overridden["services"]["guardian"]
    assert guardian["ports"] == ["9443:9443"]
    assert "GUARDIAN_PORT=9443" in guardian["environment"]
    assert "CITY_BRAIN_URL=https://brain.internal/ingest" in guardian["environment"]
    assert guardian["healthcheck"]["test"][-1] == "http://localhost:9443/ready"
    assert overridden["services"]["twin-mock"]["environment"] == ["GUARDIAN_URL=http://guardian:9443"]


def test_root_env_example_lists_only_compose_interpolation_variables():
    lines = [
        line.split("=", 1)[0]
        for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    assert lines == ["GUARDIAN_PORT", "CITY_BRAIN_URL", "GUARDIAN_LLM_URL"]
    assert "GUARDIAN_HMAC_KEY_" not in (ROOT / ".env.example").read_text(encoding="utf-8")


def test_dockerfile_listens_on_guardian_port():
    dockerfile = (ROOT / "guardian" / "Dockerfile").read_text(encoding="utf-8")
    assert "${GUARDIAN_PORT:-8000}" in dockerfile
    assert '"--port", "8000"' not in dockerfile


def test_compose_requires_private_env_file_and_never_embeds_hmac_keys():
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert document["services"]["guardian"]["env_file"] == ["./guardian/.env"]
    compose_text = COMPOSE.read_text(encoding="utf-8")
    assert "GUARDIAN_HMAC_KEY_TWIN=" not in compose_text
    assert "GUARDIAN_HMAC_KEY_BRAIN=" not in compose_text
    assert "GUARDIAN_HMAC_KEY_GUARDIAN=" not in compose_text


def test_valid_private_env_values_are_loaded_without_printing_or_fallback(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "GUARDIAN_HMAC_KEY_TWIN=" + "t" * 32 + "\n"
        "GUARDIAN_HMAC_KEY_BRAIN=" + "b" * 32 + "\n"
        "GUARDIAN_HMAC_KEY_GUARDIAN=" + "g" * 32 + "\n",
        encoding="utf-8",
    )
    environ = dict(line.split("=", 1) for line in env_path.read_text().splitlines())

    settings = Settings.load(environ=environ)

    assert settings.security is not None
    assert settings.security.hmac_key_twin == environ["GUARDIAN_HMAC_KEY_TWIN"]
    assert settings.security.hmac_key_brain == environ["GUARDIAN_HMAC_KEY_BRAIN"]
    assert settings.security.hmac_key_guardian == environ["GUARDIAN_HMAC_KEY_GUARDIAN"]


def test_missing_private_env_values_fail_without_default_keys():
    with pytest.raises(SecurityConfigurationError, match="GUARDIAN_HMAC_KEY_TWIN"):
        Settings.load(environ={})


def test_docker_compose_one_shot_scenario_when_available():
    if shutil.which("docker") is None:
        pytest.skip("Docker is not available")
    if not (ROOT / "guardian" / ".env").is_file():
        pytest.skip("guardian/.env with private HMAC keys is required")

    env = os.environ.copy()
    try:
        daemon = subprocess.run(
            ["docker", "info"], cwd=ROOT, env=env, capture_output=True, text=True, check=False, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("Docker daemon is not running")
    if daemon.returncode != 0:
        pytest.skip("Docker daemon is not running")

    try:
        config = subprocess.run(
            ["docker", "compose", "config"],
            cwd=ROOT, env=env, capture_output=True, text=True, check=False, timeout=60,
        )
        assert config.returncode == 0, config.stdout + config.stderr
        subprocess.run(
            ["docker", "compose", "up", "-d", "--build", "guardian", "brain-http-mock"],
            cwd=ROOT, env=env, check=True, timeout=180,
        )
        health = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", "guardian-gateway"],
            cwd=ROOT, env=env, capture_output=True, text=True, check=True, timeout=30,
        )
        assert health.stdout.strip() == "healthy"
        result = subprocess.run(
            ["docker", "compose", "run", "--rm", "--no-deps", "twin-mock"],
            cwd=ROOT, env=env, capture_output=True, text=True, check=False, timeout=60,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "actual=ACCEPTED" in result.stdout
    finally:
        subprocess.run(
            ["docker", "compose", "down", "--remove-orphans"],
            cwd=ROOT, env=env, check=False, timeout=60,
        )
