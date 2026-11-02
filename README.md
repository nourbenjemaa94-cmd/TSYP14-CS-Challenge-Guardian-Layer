# triplet-07

Collaborative repository for Triplet 07: **Digital Twin ↔ Guardian ↔ City Brain**.

## Team Members & Responsibilities
- **Member 1 (Mohamed Amine Hayouni)**: Communication & Contract Adapters (`adapters/`, `contracts/`)
- **Member 2 (Nour Ben Jemaa)**: Contract Adapters & Security (`adapters/`, `security/`)
- **Member 3 (Rayen Saidi)**: Core Engine & Audit Store (`core/`, `audit/`)
- **Member 4 (Ghaith Mnasri)**: Core Security & Verification Engine (`core/`, `audit/`, `orchestration/`)
- **Member 5 (Nour Zghonda)**: Security, Freshness & Replay Protection (`security/`)
- **Member 6 (Sarra Mtir)**: Contracts & Ingestion Adapters (`contracts/`, `adapters/`)

## Architecture Overview
```
[ Digital Twin / Sensors ] (Layer 1)
           │
           ▼ (REST / MQTT / Ingestion)
┌──────────────────────────────────────────────┐
│           GUARDIAN SECURITY GATEWAY          │ (Layer 2)
│                                              │
│  [ Security & Validation (Auth/Freshness) ]  │
│  [ Contract Adapter & Unit Normalization ]   │
│  [ Anomaly Detection & History Analysis ]    │
│  [ Trust Assessment Engine ]                 │
│  [ Containment & Quarantine Policy ]         │
│  [ Audit Event Store & Realtime Timeline ]   │
└──────────────────────────────────────────────┘
           │
           ▼ (Certified Conforming Data)
[ City Brain / Decision Support ] (Layer 3)


# Run test suite
pytest -v

# Start Guardian service
uvicorn src.guardian.main:app --host 0.0.0.0 --port 8000 --reload
```
