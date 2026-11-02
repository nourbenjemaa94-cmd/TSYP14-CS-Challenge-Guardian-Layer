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
