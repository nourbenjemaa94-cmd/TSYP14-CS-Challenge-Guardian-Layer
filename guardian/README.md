# Guardian Security Gateway (Layer 2)

Guardian is the zero-trust cyber-physical verification gateway deployed between Digital Twin simulations and the municipal City Brain.

## Core Responsibilities (Member 3 & 4: Ghaith Mnasri & Rayen Saidi)
- **Causal Audit Timeline (R3)**: WebSocket `/ws/timeline` broadcasting strictly correlated real-time events (`READING_RECEIVED` ➔ `GUARDIAN_VERDICT` ➔ `ISOLATED` / `SENT_TO_BRAIN`).
- **Anomaly Detection (`core/anomaly_detector.py`)**: Multi-heuristic detection of physical incoherence, sudden spikes, frozen sensors, and statistical outliers against historical baselines.
- **Trust Assessment (`core/trust_assessor.py`)**: Dynamic trust scoring engine calculating sensor credibility scores and returning clear verdict classifications (`TRUSTED`, `SUSPICIOUS`, `UNTRUSTED`).
- **Containment Policy Engine (`core/containment.py`)**: Active mitigation engine evaluating actions (`ALLOW`, `ISOLATE`, `QUARANTINE`, `RATE_LIMIT`) to protect City Brain from spoofed flooding attacks.
- **Audit Store & Logging (`audit/`)**: Structured immutable event storage and ISO 8601 UTC audit trails.
- **Pipeline Orchestration (`orchestration/pipeline.py`)**: End-to-end execution flow ensuring non-repudiation and complete traceability.

## Setup & Running
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run unit and integration tests
pytest -v

# 3. Start local development server
uvicorn src.guardian.main:app --host 0.0.0.0 --port 8000 --reload
```

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
