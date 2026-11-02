<img width="1312" height="1199" alt="architecture" src="https://github.com/user-attachments/assets/330df550-07e7-48e9-bc35-4e9ccba03132" />

# TSYP14-CS-Challenge-Guardian-Layer

## Project Structure

```text
triplet-07/
│
├── README.md
├── INTEGRATION.md
├── TESTBOOK.md
├── docker-compose.yml
│
├── twin/                       # Twin team's code
├── brain/                      # City Brain team's code
│
├── guardian/
│   ├── README.md
│   ├── INTERFACE.md
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── .env.example
│   ├── config.example.yaml
│   │
│   ├── src/
│   │   └── guardian/
│   │       ├── main.py
│   │       ├── config.py
│   │       │
│   │       ├── adapters/              # Member 1 + 2 + 6
│   │       │   ├── communication/
│   │       │   │   ├── __init__.py
│   │       │   │   ├── base.py        # Interface commune
│   │       │   │   ├── registry.py    # Registre des adaptateurs
│   │       │   │   ├── manager.py     # Gestion des adaptateurs
│   │       │   │   ├── rest.py        # Adaptateur REST
│   │       │   │   ├── mqtt.py        # Adaptateur MQTT
│   │       │   │   └── websocket.py   # Futur adaptateur (optionnel)
│   │       │   │
│   │       │   └── contract/
│   │       │       ├── mapper.py
│   │       │       ├── schema_reader.py
│   │       │       ├── ai_mapper.py
│   │       │       └── unit_converter.py
│   │       │
│   │       ├── contracts/             # Member 1 + 2 + 6
│   │       │   ├── events.py
│   │       │   ├── verdicts.py
│   │       │   └── commands.py
│   │       │
│   │       ├── security/              # Member 2 + 5
│   │       │   ├── authentication.py
│   │       │   ├── authorization.py
│   │       │   ├── validation.py
│   │       │   ├── freshness.py
│   │       │   └── replay_protection.py
│   │       │
│   │       ├── core/                  # Member 3 + 4
│   │       │   ├── history.py
│   │       │   ├── anomaly_detector.py
│   │       │   ├── trust_assessor.py
│   │       │   └── containment.py
│   │       │
│   │       ├── audit/                 # Member 4 + 3
│   │       │   ├── logger.py
│   │       │   ├── event_store.py
│   │       │   └── timeline.py
│   │       │
│   │       └── orchestration/         # Shared integration
│   │           └── pipeline.py
│   │
│   ├── mocks/
│   │   ├── mock_twin.py
│   │   └── mock_brain.py
│   │
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   └── scenarios/
│   │
│   └── docs/
│       ├── ARCHITECTURE.md
│       └── SECURITY.md
│
├── scenarios/
├── logs/
└── .github/
    ├── workflows/
    │   └── guardian-ci.yml
    └── CODEOWNERS
```

## Team Members

- **Member 1:** Mohamed Amine Hayouni
- **Member 2:** Nour ben Jemaa
- **Member 3:** Rayen Saidi
- **Member 4:** Ghaith Mnasri
- **Member 5:** Nour Zghonda
- **Member 6:** Sarra Mtir

## Project Progress

### 1. Adapters

- [x] Communication
  - [ ] Test unitaire

- [ ] Contract
  - [ ] mapper
  - [ ] schema_reader
  - [ ] ai_mapper
  - [ ] unit_converter
  - [ ] Test unitaire

### 2. Contracts

- [ ] Contracts
  - [ ] Test unitaire

### 3. Security

- [ ] Security
  - [ ] authentication
  - [ ] authorization
  - [ ] validation
  - [ ] freshness
  - [ ] replay_protection
  - [ ] Test unitaire

### 4. Core

- [ ] Core
  - [ ] history
  - [ ] anomaly_detector
  - [ ] trust_assessor
  - [ ] containment
  - [ ] Test unitaire

### 5. Audit

- [ ] Audit
  - [ ] logger
  - [ ] event_store
  - [ ] timeline

### 6. Orchestration

- [ ] Orchestration
  - [ ] pipeline
