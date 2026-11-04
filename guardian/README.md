# Guardian Security Gateway (Layer 2)

Guardian is the zero-trust cyber-physical verification gateway deployed between Digital Twin simulations and the municipal City Brain.

## Core Responsibilities (Member 3 & 4: Ghaith Mnasri & Rayen Saidi)
- **Causal Audit Timeline (R3)**: WebSocket `/ws/timeline` broadcasting strictly correlated real-time events (`READING_RECEIVED` ➔ `GUARDIAN_VERDICT` ➔ `ISOLATED` / `SENT_TO_BRAIN`).
- **Anomaly Detection (`core/anomaly_detector.py`)**: Multi-heuristic detection of physical incoherence, sudden spikes, frozen sensors, and statistical outliers against historical baselines.
- **Trust Assessment (`core/trust_assessor.py`)**: Dynamic trust scoring engine calculating sensor credibility scores and returning clear verdict classifications (`TRUSTED`, `SUSPICIOUS`, `UNTRUSTED`).
- **Containment Policy Engine (`core/containment.py`)**: Active mitigation engine evaluating actions (`ALLOW`, `ISOLATE`, `QUARANTINE`, `RATE_LIMIT`) to protect City Brain from spoofed flooding attacks.
- **Audit Store & Logging (`audit/`)**: Structured immutable event storage and ISO 8601 UTC audit trails.

The current `EventStore` and WebSocket timeline are process-local memory
buffers, not durable evidence. They are cleared by process restart; connect a
durable audit backend before treating them as forensic records.
- **Pipeline Orchestration (`orchestration/pipeline.py`)**: End-to-end execution flow ensuring non-repudiation and complete traceability.

## Setup & Running
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the current tests (legacy tests are intentionally excluded)
python -m pytest -q

# 3. Check coverage and lint
python -m pytest --cov=src/guardian --cov-report=term-missing tests
python -m ruff check src tests

# 4. Start local development server
PYTHONPATH=src python -m uvicorn guardian.main:app --host 0.0.0.0 --port 8000 --reload
```

On PowerShell, set `$env:PYTHONPATH = "src"` before starting Uvicorn. The
`uvicorn src.guardian.main:app` form is invalid because `src` is the source
root, not part of the import package name.

The current non-legacy regression coverage is listed in the repository
[`TESTBOOK.md`](../TESTBOOK.md): Core history and containment, simulated MQTT
and REST communication, FastAPI HTTP requests with signed envelopes, Brain
output through `httpx.MockTransport`, readiness, configuration and the causal
timeline.

The Compose deployment sets `GUARDIAN_TIMELINE_MODE=disabled`. The
unauthenticated timeline may only be enabled in local development for loopback
clients; production rejects it even if `GUARDIAN_TIMELINE_MODE=demo` is set.
External demonstrations require a separately approved authenticated access
policy.

## Docker launch and secrets

Create the private environment file locally; it is deliberately not stored in
Git and is passed to the Guardian container through Compose `env_file`:

```bash
cp guardian/.env.example guardian/.env
python -c "import secrets; print(secrets.token_hex(32))"
```

Run the command three times and use the three generated values for
`GUARDIAN_HMAC_KEY_TWIN`, `GUARDIAN_HMAC_KEY_BRAIN`, and
`GUARDIAN_HMAC_KEY_GUARDIAN` in `guardian/.env`. Each value must contain at
least 32 characters. Never commit this file, HMAC keys, private certificates,
or certificate key files.

Optional MQTT TLS files can remain outside the image. Put them under the local
`guardian/certs/` directory, set their `/run/secrets/certs/...` paths in
`guardian/.env`, and Compose mounts that directory read-only.

There are two separate Docker steps:

```bash
# Validate interpolation and the required guardian/.env file; starts nothing.
docker compose config

# Build and start the actual services.
docker compose up --build guardian brain-http-mock

# One-shot normal Twin scenario (Guardian and Brain mock must be running).
docker compose run --rm --no-deps twin-mock

docker compose down
```

If `guardian/.env` is absent, `docker compose config` fails explicitly because
the required `env_file` is missing; there is no permissive HMAC fallback. With
a valid private `.env`, `Settings.load()` reads the three keys and Guardian's
healthcheck can become ready. `mocks.mock_brain` is a verdict-request client,
not the Brain HTTP service; `brain-http-mock` is the explicit HTTP receiver
used only for local simulation.

## Local model (optional)

Guardian runs without Ollama. Committed partner profiles still map, and unknown shapes are not onboarded automatically. A local model is only for automatic onboarding.

Three modes:

- **Committed profiles.** Ollama is off. Only profiles already in `config/profiles/` are mapped.
- **Heuristic only.** Set `GUARDIAN_ONBOARDING_MIN_PROPOSERS=1`. Onboarding may accept the heuristic proposer with no second opinion from a model.
- **Full.** Ollama is running with the chat model and `nomic-embed-text`. Onboarding asks the heuristic, the embedding model, and the chat model.

From the repository root, with `GUARDIAN_LLM_MODEL` and `GUARDIAN_EMBED_MODEL` set in `guardian/.env`:

```powershell
.\scripts\setup-ollama.ps1
```

```bash
./scripts/setup-ollama.sh
```

The script checks `ollama --version`, pulls those two models, and prints the names returned by `GET /api/tags`.

Ollama binds to `127.0.0.1`. Running Guardian natively, with `GUARDIAN_LLM_URL=http://localhost:11434`, is the recommended demo setup. Guardian inside Docker cannot reach that address. Set the user environment variable `OLLAMA_HOST=0.0.0.0:11434`, restart Ollama, accept the firewall prompt, and set `GUARDIAN_LLM_URL=http://host.docker.internal:11434` on the Guardian container.
