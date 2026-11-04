from pathlib import Path

import pytest

from guardian.config import Settings
from guardian.security.errors import SecurityConfigurationError

HMAC_ENV = {
    "GUARDIAN_HMAC_KEY_TWIN": "t" * 32,
    "GUARDIAN_HMAC_KEY_BRAIN": "b" * 32,
    "GUARDIAN_HMAC_KEY_GUARDIAN": "g" * 32,
}


def write_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "guardian.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_yaml_server_port_certificates_and_brain_output(tmp_path):
    path = write_config(tmp_path, """
server:
  host: 127.0.0.1
  port: 9443
partners:
  twin:
    adapter: mqtt
    mqtt:
      host: mqtt.internal
      port: 8883
      topic: twin/readings
      tls_enabled: true
      ca_cert: /run/secrets/ca.pem
      client_cert: /run/secrets/client.pem
      client_key: /run/secrets/client.key
  brain:
    adapter: rest
    endpoint: https://brain.internal/ingest
    timeout_seconds: 4.5
    retry_count: 2
adapters:
  twin: mqtt
  brain: rest
""")

    settings = Settings.load(path, environ=HMAC_ENV)

    assert settings.server.port == 9443
    assert settings.partners.twin.mqtt.port == 8883
    assert settings.partners.twin.mqtt.ca_cert == "/run/secrets/ca.pem"
    assert settings.partners.twin.mqtt.client_key == "/run/secrets/client.key"
    assert settings.partners.brain.endpoint == "https://brain.internal/ingest"
    assert settings.partners.brain.timeout_seconds == 4.5
    assert settings.adapters.twin == "mqtt"


def test_environment_overrides_yaml(tmp_path):
    path = write_config(tmp_path, """
server: {port: 8001}
partners:
  twin:
    mqtt: {port: 1883}
""")

    settings = Settings.load(path, environ={**HMAC_ENV, "GUARDIAN_PORT": "9443", "MQTT_PORT": "9444"})

    assert settings.server.port == 9443
    assert settings.partners.twin.mqtt.port == 9444


def test_missing_hmac_keys_are_critical(tmp_path):
    path = write_config(tmp_path, "server: {port: 9443}\n")

    with pytest.raises(SecurityConfigurationError, match="HMAC_KEY"):
        Settings.load(path, environ={})


@pytest.mark.parametrize("content", ["server: {port: 0}\n", "server: {port: 65536}\n"])
def test_server_port_out_of_range_is_rejected(tmp_path, content):
    path = write_config(tmp_path, content)

    with pytest.raises(SecurityConfigurationError, match="server.port"):
        Settings.load(path, environ=HMAC_ENV)


def test_invalid_yaml_is_rejected(tmp_path):
    path = write_config(tmp_path, "server: [unterminated\n")

    with pytest.raises(SecurityConfigurationError, match="valid YAML"):
        Settings.load(path, environ=HMAC_ENV)


def test_example_yaml_loads_public_security_with_runtime_hmac_keys():
    path = Path(__file__).resolve().parents[1] / "config.example.yaml"

    settings = Settings.load(path, environ=HMAC_ENV)

    assert settings.security.hmac_key_twin == HMAC_ENV["GUARDIAN_HMAC_KEY_TWIN"]
    assert settings.security.hmac_key_brain == HMAC_ENV["GUARDIAN_HMAC_KEY_BRAIN"]
    assert settings.security.hmac_key_guardian == HMAC_ENV["GUARDIAN_HMAC_KEY_GUARDIAN"]
    assert settings.security.max_age_seconds == 300


def test_example_yaml_without_runtime_hmac_keys_fails_closed():
    path = Path(__file__).resolve().parents[1] / "config.example.yaml"

    with pytest.raises(SecurityConfigurationError, match="GUARDIAN_HMAC_KEY_TWIN"):
        Settings.load(path, environ={})


def test_load_reads_private_dotenv_from_working_directory(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """Native runs keep keys in ./.env; the process environment still wins."""
    for name in HMAC_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("GUARDIAN_CONFIG", raising=False)
    monkeypatch.delenv("GUARDIAN_PORT", raising=False)
    (tmp_path / ".env").write_text(
        "\n".join([f"{name}={value}" for name, value in HMAC_ENV.items()] + ["GUARDIAN_PORT=8010"]) + "\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    settings = Settings.load()
    assert settings.security.hmac_key_twin == HMAC_ENV["GUARDIAN_HMAC_KEY_TWIN"]
    assert settings.server.port == 8010

    monkeypatch.setenv("GUARDIAN_PORT", "8011")
    assert Settings.load().server.port == 8011


def test_load_without_dotenv_or_keys_fails_closed(tmp_path, monkeypatch: pytest.MonkeyPatch):
    for name in HMAC_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("GUARDIAN_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SecurityConfigurationError, match="GUARDIAN_HMAC_KEY_TWIN"):
        Settings.load()


def test_forward_to_brain_switch_defaults_true_and_reads_env():
    assert Settings.load(environ=HMAC_ENV).partners.brain.forward is True
    assert Settings.load(environ={**HMAC_ENV, "GUARDIAN_FORWARD_TO_BRAIN": "false"}).partners.brain.forward is False

    with pytest.raises(SecurityConfigurationError, match="GUARDIAN_FORWARD_TO_BRAIN"):
        Settings.load(environ={**HMAC_ENV, "GUARDIAN_FORWARD_TO_BRAIN": "maybe"})


def test_mqtt_default_port_matches_tls_default():
    settings = Settings.load(environ=HMAC_ENV)

    assert settings.partners.twin.mqtt.tls_enabled is True
    assert settings.partners.twin.mqtt.port == 8883


def test_example_yaml_mqtt_port_matches_tls_default():
    path = Path(__file__).resolve().parents[1] / "config.example.yaml"

    settings = Settings.load(path, environ=HMAC_ENV)

    assert settings.partners.twin.mqtt.tls_enabled is True
    assert settings.partners.twin.mqtt.port == 8883


def test_trust_section_reaches_the_trust_assessor(tmp_path, monkeypatch: pytest.MonkeyPatch):
    from guardian import main
    from guardian.core.trust_assessor import TrustAssessor, TrustConfig

    path = write_config(tmp_path, "trust:\n  isolate_threshold: 0.15\n  quarantine_threshold: 0.5\n")

    settings = Settings.load(path, environ=HMAC_ENV)
    assert settings.trust.isolate_threshold == 0.15
    assert settings.trust.quarantine_threshold == 0.5

    built = TrustConfig.from_mapping(settings.trust.model_dump())
    assert built.untrusted_below == 0.15
    assert built.suspicious_below == 0.5
    assert built.recovery_clean_readings == 3

    for name, value in HMAC_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("GUARDIAN_CONFIG", str(path))
    previous_pipeline, previous_signer = main._pipeline, main._outbound_signer
    main._pipeline = None
    main._outbound_signer = None
    try:
        pipeline = main._default_pipeline()
        assert isinstance(pipeline.assessor, TrustAssessor)
        assert pipeline.assessor.config.untrusted_below == 0.15
    finally:
        main._pipeline, main._outbound_signer = previous_pipeline, previous_signer


def test_unknown_trust_key_is_a_startup_error(tmp_path):
    path = write_config(tmp_path, "trust:\n  initial_score: 1.0\n")

    with pytest.raises(SecurityConfigurationError, match="trust.initial_score"):
        Settings.load(path, environ=HMAC_ENV)


def test_inverted_trust_thresholds_are_rejected(tmp_path):
    path = write_config(tmp_path, "trust:\n  isolate_threshold: 0.8\n  quarantine_threshold: 0.5\n")

    with pytest.raises(SecurityConfigurationError, match="isolate_threshold"):
        Settings.load(path, environ=HMAC_ENV)


def test_audit_log_directory_maps_to_log_dir_unless_overridden(tmp_path):
    path = write_config(tmp_path, "audit:\n  log_directory: /var/log/guardian\n  sqlite_path: reserved.db\n")

    assert Settings.load(path, environ=HMAC_ENV).log_dir == "/var/log/guardian"
    assert Settings.load(path, environ={**HMAC_ENV, "AUDIT_LOG_DIR": "/tmp/audit"}).log_dir == "/tmp/audit"

    unknown = write_config(tmp_path, "audit:\n  retention_days: 7\n")
    with pytest.raises(SecurityConfigurationError, match="audit.retention_days"):
        Settings.load(unknown, environ=HMAC_ENV)


def test_security_environment_tunables_override_public_yaml():
    path = Path(__file__).resolve().parents[1] / "config.example.yaml"

    settings = Settings.load(
        path,
        environ={**HMAC_ENV, "GUARDIAN_MAX_AGE_SECONDS": "12"},
    )

    assert settings.security.max_age_seconds == 12
