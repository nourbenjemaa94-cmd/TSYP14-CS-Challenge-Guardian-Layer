import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from guardian.config import Settings
from guardian.security.errors import SecurityConfigurationError

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.yml"


def test_compose_declares_one_shot_twin_and_explicit_brain_server():
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = document["services"]

    assert services["twin-mock"]["command"][-2:] == ["--mode", "normal"]
    assert services["twin-mock"]["environment"] == ["GUARDIAN_URL=http://guardian:8000"]
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
