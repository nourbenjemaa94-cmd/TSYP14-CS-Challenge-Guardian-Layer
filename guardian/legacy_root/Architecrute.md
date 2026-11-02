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
│   │       │   ├── README.md
│   │       │   ├── history.py           # readings and verdicts per sensor, reading validation
│   │       │   ├── anomaly_detector.py  # finds problems: range, spike, frozen, correlation, repetition
│   │       │   ├── trust_assessor.py    # TRUSTED / SUSPICIOUS / UNTRUSTED with reason and confidence
│   │       │   └── containment.py       # isolate, quarantine, rollback, release
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


Core (src/guardian/core/)
-------------------------

Role: decide if a reading can be trusted, and contain the sensor if it cannot.
The core does not receive or send messages. It only works on readings that adapters/ and security/ already checked.

Flow of one reading:

  pipeline.py -> anomaly_detector.py -> trust_assessor.py -> containment.py -> audit/ and City Brain
                        |                      |                   |
                        +---------- history.py (shared) -----------+

Dependencies between the core files (one direction only):

  history.py            imports nothing from the project
  anomaly_detector.py   imports history
  trust_assessor.py     imports history, anomaly_detector
  containment.py        imports history, anomaly_detector, trust_assessor

What each file receives and returns:

  history.py            in: canonical reading           out: Reading, HistoryEntry, VerdictRecord
  anomaly_detector.py   in: canonical reading           out: DetectionResult (list of findings)
  trust_assessor.py     in: DetectionResult             out: TrustVerdict (verdict, reason_code, confidence)
  containment.py        in: TrustVerdict                out: ContainmentReport (actions and what changed)

Who uses the core:

  pipeline.py           calls detector, assessor and containment for every reading
  audit/                records DetectionResult, TrustVerdict and ContainmentReport with to_dict()
  adapters/             provides the port that containment uses to call the Twin (isolate_device, rollback_reading)
  config.py             gives the sections detection:, trust: and containment: read by from_mapping()
  contracts/            verdict and command types to align with when they are ready

Rules of the core:

  - no file in core/ talks to the network, the disk or the real clock (the clock and the Twin port are given from outside)
  - one HistoryTracker is created in main.py and shared by the three classes
  - files are imported as core.history, core.anomaly_detector, core.trust_assessor, core.containment
  - thresholds and limits come from config, nothing is fixed in the code


#member 1 : Mohamed Amine Hayouni
#member 2 : Nour ben Jemaa
#member 3 : Rayen Saidi
#member 4 : Ghaith Mnasri
#member 5 : Nour Zghonda
#member 6 : Sarra Mtir