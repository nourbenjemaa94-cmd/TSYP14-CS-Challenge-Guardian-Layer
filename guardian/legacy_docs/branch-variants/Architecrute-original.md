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
│   │       ├── adapters/        # Member 1 + 2 + 6
│   │       │   ├── communication/
│   │       │   │   ├── base.py
│   │       │   │   ├── rest.py
│   │       │   │   └── mqtt.py
│   │       │   └── contract/
│   │       │       ├── mapper.py
│   │       │       ├── schema_reader.py
│   │       │       ├── ai_mapper.py
│   │       │       └── unit_converter.py
│   │       │
│   │       ├── contracts/       # Member 1 + 2 + 6
│   │       │   ├── events.py
│   │       │   ├── verdicts.py
│   │       │   └── commands.py
│   │       │
│   │       ├── security/        # Member 2 + 5
│   │       │   ├── authentication.py
│   │       │   ├── authorization.py
│   │       │   ├── validation.py
│   │       │   ├── freshness.py
│   │       │   └── replay_protection.py
│   │       │
│   │       ├── core/            # Member 3 + 4
│   │       │   ├── history.py
│   │       │   ├── anomaly_detector.py
│   │       │   ├── trust_assessor.py
│   │       │   └── containment.py
│   │       │
│   │       ├── audit/           # Member 4 + 3
│   │       │   ├── logger.py
│   │       │   ├── event_store.py
│   │       │   └── timeline.py
│   │       │
│   │       └── orchestration/   # Shared integration
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


#member 1 : Mohamed Amine Hayouni
#member 2 : Nour ben Jemaa
#member 3 : Rayen Saidi
#member 4 : Ghaith Mnasri
#member 5 : Nour Zghonda
#member 6 : Sarra Mtir
