# Cursor plan: stabilise the Guardian codebase, then build `adapters/contract`

Repo: `triplet-07` (Guardian layer). Owner: Nour Ben Jemaa (Member 2). Written 3 November 2026 against commit `056cb3b` plus the uncommitted task-2 work in `adapters/contract/`. Companion documents: the team handoff (decisions and the target design, sections 7–11) and `guardian/docs/CURSOR_BRIEF_SECURITY.md` (security tasks; its T3 pipeline order is superseded by handoff section 7).

## Assumptions (correct any that are wrong before Phase 1)

| # | Assumption | Evidence |
|---|---|---|
| A1 | Python 3.12 is the runtime. The repo's `.venv` is a uv venv on CPython 3.12; CI uses 3.12. The Dockerfile says 3.11 and is aligned to 3.12 in Phase 1 | `.venv/pyvenv.cfg`, `guardian-ci.yml`, `guardian/Dockerfile` |
| A2 | Stack: FastAPI, pydantic v2, pydantic-settings, PyYAML, httpx, pytest, ruff. No new runtime dependency except `paho-mqtt`, which `mqtt.py` already imports | `guardian/requirements.txt` |
| A3 | The pipeline order is the handoff's section 7: `gate.check_inbound(raw, operation)` on the envelope → contract mapper on the payload → core. Mapping never touches envelope fields | handoff §7 (PROPOSED), `security/gate.py` already provides `check_inbound` |
| A4 | The envelope is `security.validation.Envelope` (`schema_version, event_id, seq, timestamp, source{layer, device_id}, zone_id, type, payload, signature`). Partners vary only inside `payload` | `security/validation.py`, `mocks/mock_twin.py` |
| A5 | Guardian is a gatekeeper for Phase 1 (accepted readings and verdicts are forwarded to the Brain), because that is what `main.py` and `pipeline.py` implement. Observer mode stays PENDING | `orchestration/pipeline.py` |
| A6 | Verdict names are TRUSTED / SUSPICIOUS / UNTRUSTED as in `core/` and `contracts/verdicts.py` | code |
| A7 | REST is the primary transport; MQTT stays importable but is not wired | handoff §4 PENDING |
| A8 | Ollama runs natively on the Windows laptop at `http://localhost:11434` (version 0.40.14). Guardian talks to it over HTTP; Guardian-in-Docker reaches it through `host.docker.internal`. The compose `ollama` service is optional | screenshot: `ollama --version`, `/api/tags` |
| A9 | Ollama API shape: `POST /api/chat` with `{model, messages, stream:false, format:<JSON schema object>, options:{temperature, num_ctx, num_gpu}, keep_alive}` returning `{message:{content}}`; `POST /api/embed` with `{model, input}` returning `{embeddings:[[...]]}`. Web access is unavailable from this session, so the smoke script in step 1.7 prints raw responses to confirm this against the installed server | Ollama API as documented since structured outputs were added |
| A10 | `qwen2.5:3b` failed to load with `std::bad_alloc` (memory allocation failure in the model runner), while `nomic-embed-text` pulled and `/api/tags` works. The model choice is configuration; Phase 1.7 picks the model that loads on this laptop | screenshot |
| A11 | The `legacy_*` modules and `tests/legacy/` are the security branch's working app, broken by the 2 November reorganisation. The canonical files (`main.py`, `pipeline.py`, `config.py`, `audit/logger.py`) are kept and the gate-aware behaviour is ported into them; the legacy copies are deleted afterwards | `git log 4323589`, import errors |
| A12 | A message whose payload shape is unknown gets HTTP 202 `{"status":"ONBOARDING_PENDING","fingerprint":...}` and is buffered; nothing in the handoff fixes this response, so it is chosen here | handoff §8.2 |
| A13 | Folders owned by other members (`core/`, `audit/`, `orchestration/`) receive only the minimal edits listed here, each marked `# TODO(guardian-integration):` | handoff rule 4 |

## Rules for Cursor

1. Execute one step at a time, in order. Run the step's **Verify** before moving on. Stop at each **Checkpoint** and report.
2. Touch only the files a step names. Do not reformat, rename or "improve" code outside them.
3. No network calls in tests. Ollama is called only by the smoke script and the live checkpoints.
4. Never generate an `event_id`, never read a Twin's true values, never fetch a URI from a partner message, never call a model per message.
5. Error messages and logs may name paths and field names, never payload values or keys.
6. Commit after every step with the message given. Small commits; no squash.
7. If a Verify fails, fix the step; do not skip ahead and do not disable the test.

---

# Phase 0: Baseline

### 0.1 Branch and commit the existing contract work

- **Change:** create branch `contract-foundation` from `main`. Stage and commit the uncommitted task-2 work: `src/guardian/adapters/__init__.py`, `src/guardian/adapters/contract/` (7 modules), `tests/unit/`, and the `GuardianEvent`/`EventProvenance` additions in `src/guardian/contracts/events.py` and `contracts/__init__.py`.
- **Also:** delete `guardian/docs/CURSOR_BRIEF_CONTRACT.md` (superseded by this plan and the handoff). Do not touch `CURSOR_BRIEF_SECURITY.md`.
- **Why:** the adapter work must start from a known commit.
- **Verify:** `cd guardian && python -m pytest tests/unit/contract tests/test_timeline.py -q` → `103 passed`.
- **Commit:** `feat(contract): profile-driven mapper, unit converter, GuardianEvent (task 2)`

### 0.2 Repository hygiene

- **Change:**
  - Add `/.gitattributes` with `* text=auto eol=lf` and run `git add --renormalize .` (removes the line-ending churn on `contracts/*.py`).
  - `git rm -r --cached` every tracked `__pycache__` directory (12 files) and the empty root folders `src/`, `tests/`, `mocks/` (they hold only `__pycache__`).
  - Add `guardian/pytest.ini`:
    ```ini
    [pytest]
    pythonpath = src
    testpaths = tests
    addopts = --ignore=tests/legacy
    asyncio_default_fixture_loop_scope = function
    ```
    The `--ignore` is removed in step 2.5 once the legacy tests are ported.
- **Why:** reproducible test runs and a clean diff for teammates.
- **Verify:** `git status --short` shows no `__pycache__`; `python -m pytest -q` from `guardian/` → `103 passed`, no collection errors.
- **Commit:** `chore: gitattributes, pytest.ini, drop committed caches`

**Checkpoint 0:** branch `contract-foundation`, 103 tests green, `git status` clean.

---

# Phase 1: Prerequisite fixes

### 1.1 One import root (`guardian.*`)

- **Change:** make every module import through the `guardian` package so that one class has one identity.
  - `src/guardian/core/anomaly_detector.py`, `trust_assessor.py`, `containment.py`: `from core.X import` → `from guardian.core.X import`.
  - `src/guardian/audit/logger.py`, `src/guardian/orchestration/pipeline.py`: replace the `try: from audit... except ImportError: from .` blocks with `from guardian.audit.timeline import ...` / `from guardian.audit.logger import ...`.
  - `src/guardian/main.py`: delete the `sys.path` block (lines 20–26). Change the real imports to `guardian.audit...`, `guardian.core...`, `guardian.orchestration.pipeline`, `guardian.config`. Leave the three `try/except ImportError` stubs in place for now; Phase 2.4 removes them.
  - `tests/conftest.py`: delete the `sys.path` manipulation (keep the file, empty docstring). `tests/test_timeline.py`: delete its `sys.path` block and import `guardian.main`.
  - `guardian/Dockerfile`: `FROM python:3.12-slim`; `CMD ["uvicorn", "guardian.main:app", ...]` (PYTHONPATH already has `/app/src`).
  - Mark each edit in `core/` and `audit/` with `# TODO(guardian-integration): absolute import; one package root`.
- **Why:** the pipeline in Phase 2 must pass objects between `guardian.security`, `guardian.adapters.contract` and `core`. With two roots (`core.history` vs `guardian.core.history`) the same class is loaded twice and `isinstance` checks and singletons break.
- **Verify:**
  - `cd guardian && grep -rn "^from core\.\|^from audit\.\|^from orchestration\.\|sys.path.insert" src tests` → only the three stub fallbacks in `main.py`.
  - `PYTHONPATH=src python -c "import guardian.main, guardian.core, guardian.audit"` succeeds from a shell with no other path tricks.
  - `python -m pytest -q` → `103 passed`.
- **Commit:** `fix(imports): single guardian package root`

### 1.2 Communication package

- **Change:**
  - `git mv src/guardian/adapters/communication/REST.py rest_tmp.py && git mv rest_tmp.py rest.py` (two steps because Windows is case-insensitive); same for `MQTT.py` → `mqtt.py`.
  - Add `src/guardian/adapters/communication/__init__.py` (docstring only).
  - `requirements.txt`: add `paho-mqtt>=2.0.0`.
- **Why:** `main.py` imports `adapters.communication.rest`; the upper-case file names make that import fail silently into the stub, and `mqtt.py` cannot import at all without `paho`.
- **Verify:** `PYTHONPATH=src python -c "import guardian.adapters.communication.rest, guardian.adapters.communication.mqtt"`.
- **Commit:** `fix(adapters): importable communication package`

### 1.3 Configuration and secrets

- **Change:** `src/guardian/config.py`:
  - Remove `SecurityConfig` (`api_auth_secret`, `valid_tokens`, `token_max_age_seconds`).
  - Add `security: SecuritySettings` built with `SecuritySettings.from_env()` (from `guardian.security.gate`).
  - Add `ContractConfig` read from the environment with the handoff section 9 names and defaults: `GUARDIAN_LLM_PROVIDER=ollama`, `GUARDIAN_LLM_URL=http://localhost:11434`, `GUARDIAN_LLM_MODEL`, `GUARDIAN_EMBED_MODEL=nomic-embed-text`, `GUARDIAN_LLM_TIMEOUT_SECONDS=60`, `GUARDIAN_LLM_NUM_CTX=2048`, `GUARDIAN_LLM_NUM_GPU=-1` (−1 = Ollama default, 0 = CPU only), `GUARDIAN_PROFILE_DIR=data/profiles`, `GUARDIAN_ONBOARDING_BUFFER=20`, `GUARDIAN_ONBOARDING_TIMEOUT_SECONDS=120`, `GUARDIAN_PROBATION_MESSAGES=20`.
  - Replace the module-level `settings = Settings()` with `Settings.load()` so importing `guardian.config` never requires secrets; `main.create_app()` calls `load()`.
  - `config.example.yaml`: delete `security.valid_tokens` and `security.token_header`.
  - `.env.example`: append the `GUARDIAN_LLM_*`, `GUARDIAN_EMBED_MODEL`, `GUARDIAN_PROFILE_DIR`, `GUARDIAN_ONBOARDING_*`, `GUARDIAN_PROBATION_MESSAGES` lines with the defaults above and one comment each.
  - `/docker-compose.yml`: remove the inline `API_AUTH_SECRET`; add `env_file: ./guardian/.env` to `guardian`; set `GUARDIAN_LLM_URL=http://host.docker.internal:11434` and `extra_hosts: ["host.docker.internal:host-gateway"]`; change the mock commands to `python -m mocks.mock_twin` / `python -m mocks.mock_brain`; add an optional service under `profiles: ["ollama"]` with `image: ollama/ollama:0.40.14` (same version as the laptop; confirm the tag pulls) and volume `ollama-models:/root/.ollama`. This file is shared by the triplet: tell the team before merging.
- **Why:** the adapter needs the LLM and profile settings from configuration (R1: never hard-coded), and the hard-coded token is a Security & Trust deduction.
- **Verify:**
  - `grep -rn "supersecret\|valid_token" guardian/ docker-compose.yml` → nothing.
  - `PYTHONPATH=src python -c "from guardian.config import Settings; Settings.load()"` without keys → `SecurityConfigurationError` naming the missing variable, no traceback into pydantic. With `guardian/.env` filled → prints nothing and exits 0.
- **Commit:** `fix(config): env-driven security and contract settings; drop hard-coded tokens`

### 1.4 Mocks start again

- **Change:** `mocks/mock_twin.py`, `mocks/mock_brain.py`: replace `from guardian.config import AppConfig, load_config` with the Phase 1.3 `Settings`. Base URL from `GUARDIAN_BASE_URL` (default `http://127.0.0.1:8000`), the signing key from `GUARDIAN_HMAC_KEY_TWIN` / `_BRAIN`. Keep every attack mode and the log writer. Add mode `twin-alt` to `mock_twin.py`: sends `type: "water_reading"` with payload `{"levelOfWater": 1.8, "unitOfMeasure": "m", "gauge": "S01"}` (a different partner shape, used by Phase 4).
- **Why:** R1 (runs alone with mocks) and every integration test depend on the mocks importing.
- **Verify:** `cd guardian && PYTHONPATH=src python -m mocks.mock_twin --help` and `python -m mocks.mock_brain --help` print usage. Sending is verified at Checkpoint 2.
- **Commit:** `fix(mocks): import the live settings; add twin-alt mode`

### 1.5 Rescue the security tests

- **Change:**
  - Move `tests/legacy/support.py` → `tests/support.py`. Keep `FakeTime`, `TWIN_KEY`…, `make_settings`, `make_gate`, the signing helpers. Replace the `create_app`/`load_config` imports with a `make_client()` that raises `NotImplementedError("Phase 2.4")` for now.
  - Move `tests/legacy/unit/security/test_security_gate.py` and `test_rate_limit.py` → `tests/unit/security/` (add `__init__.py`), fix `from tests.support import ...`.
  - Leave `tests/legacy/integration`, `tests/legacy/scenarios`, `tests/legacy/unit/test_docs.py` where they are (still ignored by `pytest.ini`); Phase 2.5 ports them.
- **Why:** the 51 gate tests are the proof that security works; the adapter's round-trip tests build on `make_gate`.
- **Verify:** `python -m pytest tests/unit -q` → `154 passed` (103 + 51). If any gate test fails, the gate changed since the security branch: stop and report the test name.
- **Commit:** `test(security): restore the 51 gate tests under tests/unit/security`

### 1.6 Lint and CI

- **Change:**
  - Add `guardian/ruff.toml`: `line-length = 120`, `target-version = "py312"`, `exclude = ["**/legacy_*", "tests/legacy"]`, `[lint] select = ["E", "F", "B", "I", "UP"]`.
  - Run `ruff check --fix src tests` once (import order and `UP` fixes only; review the diff, it must contain no logic changes) and `ruff format --check` is **not** adopted.
  - `.github/workflows/guardian-ci.yml`: set `defaults.run.working-directory: guardian`; keep `ruff check src tests` and `pytest -q`; keep Python 3.12.
- **Why:** CI must be able to go green on this branch; it currently fails on collection.
- **Verify:** `ruff check src tests` → `All checks passed`; `python -m pytest -q` → `154 passed`.
- **Commit:** `chore(ci): ruff config, working directory`

### 1.7 Ollama runtime (run in the Windows terminal, not in Python)

- **Change:** diagnose `std::bad_alloc` and pick the model; no code.
  1. `type %LOCALAPPDATA%\Ollama\server.log | findstr /i "bad_alloc memory offload gpu library"` and read the 20 lines before the error.
  2. `systeminfo | findstr /C:"Total Physical Memory" /C:"Available Physical Memory"` and `ollama ps`. A 3B model needs roughly 2.5 GB plus the context cache.
  3. CPU-only, small context, via the API (this is what Guardian will send):
     ```
     curl http://localhost:11434/api/chat -d "{\"model\":\"qwen2.5:3b\",\"stream\":false,\"options\":{\"num_gpu\":0,\"num_ctx\":2048,\"temperature\":0},\"messages\":[{\"role\":\"user\",\"content\":\"Reply only with this JSON: {\\\"ok\\\": true}\"}],\"format\":{\"type\":\"object\",\"properties\":{\"ok\":{\"type\":\"boolean\"}},\"required\":[\"ok\"]}}"
     ```
     If this succeeds, the failure was the GPU path: set `GUARDIAN_LLM_NUM_GPU=0` in `.env` and keep `qwen2.5:3b`.
  4. If it still fails: `ollama pull qwen2.5:1.5b` and repeat step 3 with that model; then `qwen2.5:0.5b`. Set `GUARDIAN_LLM_MODEL` to the first model that answers.
  5. If every model fails: `ollama rm qwen2.5:3b && ollama pull qwen2.5:3b` (rules out a bad blob), then stop and report the log lines from step 1.
  6. Embeddings: `curl http://localhost:11434/api/embed -d "{\"model\":\"nomic-embed-text\",\"input\":\"water level\"}"` → one vector of 768 numbers.
- **Why:** the LLM proposer is worthless if the model cannot load on the demo laptop; the chosen model and options go into configuration, not code.
- **Verify:** step 3 (or 4) returns `{"message":{"content":"{\"ok\": true}"...}`; step 6 returns `embeddings`; `.env` has `GUARDIAN_LLM_MODEL` and, if needed, `GUARDIAN_LLM_NUM_GPU=0`. Record the model, options and response time in the Checkpoint 1 report.

**Checkpoint 1:** `ruff check` clean, `pytest -q` → 154 passed, mocks print `--help`, Ollama answers a JSON-schema chat request and an embed request with the values now in `.env`. Stubs in `main.py` are still active (by design until 2.4).

---

# Phase 2: Move into `adapters/contract`

### 2.1 Schema fingerprint and multi-sample reading (handoff task 3)

- **Files:** `src/guardian/adapters/contract/schema_reader.py`, `tests/unit/contract/test_schema_reader.py` (new).
- **Change:**
  - `SchemaDescription.fingerprint: str`: `sha256` over the sorted `(path, normalised_type)` pairs, first 16 hex characters. Normalise `integer` → `number` before hashing (the mock sends `180`, a variant sends `1.8`; same shape, same fingerprint). Add `fingerprint_payload(payload: dict) -> str` as a module function so the router can call it without building a full description.
  - `SchemaReader.read_samples(samples: list[dict], schema_id)`: merge fields across up to 20 samples; a field present in every sample is `required=True`.
  - Batch detection: only arrays whose first element is an object are candidates; `batch_candidates: list[str]`; `batch_path` set only when exactly one candidate exists.
  - Redact before storing `sample_message`: drop `signature` and any key matching `(?i)token|secret|password|key|authorization`; truncate strings over 200 characters; set `redacted: bool`.
  - Limits: depth 16, 500 fields, `truncated: bool`. Skip keys that fail `paths.split_path` and list them in `unsupported_keys`.
- **Why:** the registry (2.2) and router (2.3) key everything on the fingerprint, and the proposers (3.x) need a merged, safe description.
- **Verify:** tests: same shape with int/float → same fingerprint; a renamed field → different fingerprint; `{"tags":["a"],"sensors":[{...}]}` → `batch_path == "$.sensors"`; two object arrays → `batch_path is None` and two candidates; secrets removed and `redacted=True`; 25 samples → 20 read, `truncated=False`.
- **Commit:** `feat(contract): schema fingerprint, multi-sample reader, redaction`

### 2.2 Profile registry (handoff 8.5)

- **Files:** `src/guardian/adapters/contract/registry.py` (new), `guardian/config/profiles/twin-canonical-v1.json` (new), `tests/unit/contract/test_registry.py` (new).
- **Change:**
  - `ProfileStatus = Literal["PROBATION", "ACTIVE", "REVOKED", "UNMAPPABLE"]`.
  - `ProfileRecord(BaseModel)`: `profile: MappingProfile | None` (None for UNMAPPABLE), `status`, `fingerprint`, `created_at`, `proposers_agreed: list[str]`, `gate_results: dict[str, str]`, `promoted_at: datetime | None`, `clean_messages: int = 0`.
  - `ProfileRegistry(committed_dir: Path, data_dir: Path)`: loads `*.json` from both at startup (committed records are ACTIVE and read-only), `get(fingerprint) -> ProfileRecord | None`, `register(record)`, `update(fingerprint, **fields)`; auto records are written atomically (`.tmp` then `os.replace`) to `data_dir`. A `threading.Lock` around writes.
  - `twin-canonical-v1.json`: the record for the mock Twin's payload `{"metric": "water_level", "value": 180, "unit": "cm"}`: `metric_path: $.payload.metric`, `value_path: $.payload.value`, `unit_path: $.payload.unit`, status ACTIVE, fingerprint computed with 2.1 (write a one-off command in the test to print it; paste it in).
- **Why:** known partners never touch the LLM; auto-created profiles survive restarts.
- **Verify:** tests: load committed + data dirs; unknown fingerprint → `None`; register then reload from disk → equal; updating a committed record raises `MappingError(INVALID_PROFILE)`; `twin-canonical-v1.json` loads and its fingerprint equals `fingerprint_payload(mock payload)`.
- **Commit:** `feat(contract): profile registry with committed twin-canonical-v1`

### 2.3 Router

- **Files:** `src/guardian/adapters/contract/router.py` (new), `tests/unit/contract/test_router.py` (new), `__init__.py` (export `ContractRouter`).
- **Change:** `ContractRouter(registry, mapper=GenericMapper(), on_unknown=None)` with `map(envelope: dict, operation: str) -> list[GuardianEvent]`:
  1. `fingerprint = fingerprint_payload(envelope["payload"])`.
  2. record `None` → call `on_unknown(envelope, fingerprint)` if set (Phase 3.5 plugs onboarding in), then raise `MappingError(UNKNOWN_SCHEMA)` with the fingerprint in `detail`.
  3. status `REVOKED` or `UNMAPPABLE` → `MappingError(PROFILE_NOT_ACTIVE)`.
  4. `ACTIVE` / `PROBATION` → `mapper.map_message(envelope, record.profile, operation)`; return events. Probation bookkeeping is Phase 3.6.
- **Why:** this is the single entry point the pipeline calls; everything else in the folder sits behind it.
- **Verify:** tests for each branch; the canonical mock payload maps through the committed profile to `water_level 180.0 cm`.
- **Commit:** `feat(contract): router from fingerprint to profile to mapper`

### 2.4 Wire the live pipeline (handoff task 10)

- **Files:** `src/guardian/orchestration/pipeline.py`, `src/guardian/main.py`, `src/guardian/adapters/communication/rest.py` (route only), `tests/support.py` (`make_client`).
- **Change:**
  - `pipeline.py` (`# TODO(guardian-integration): security + contract wiring`): new signature `GuardianPipeline(gate: SecurityGate, router: ContractRouter, event_store, anomaly_detector, trust_assessor, containment, output_adapter)`. `process_incoming(raw: bytes, operation: str, logger)`:
    1. `accepted = gate.check_inbound(raw, operation)` (one call does admit and accept). On `SecurityRejection`: audit + timeline `SECURITY_REJECTED` with `reason_code`, re-raise.
    2. `events = router.map(accepted.envelope, operation)`. On `MappingError`: timeline `MAPPING_REJECTED` with `reason_code`, re-raise.
    3. For each event: `reading = event.to_sensor_event().to_core_dict()` for measurements; `detection = anomaly_detector.analyze(reading)`; `verdict = trust_assessor.evaluate(detection)`; `action = containment.evaluate_action(...)` (keep the existing containment call); `event_store.add_reading`; timeline `READING_RECEIVED`, `GUARDIAN_VERDICT` (with `verdict`, `confidence`, `reason_code`, `accepted.warnings`), then `SENT_TO_BRAIN` or `ISOLATED` as today. Non-measurement kinds: timeline `EVENT_RECORDED`, no core call.
    4. Outbound to the Brain: build a `TrustVerdictMessage` payload, wrap it in an envelope with `source {layer: guardian}`, `type: trust_verdict`, sign with `gate.sign_outbound`, send through the output adapter.
    5. Delete the `event_id` generation and the `token` handling.
  - `main.py`: add `create_app(settings: Settings | None = None) -> FastAPI` that loads settings, builds `SecurityGate(settings.security)`, `ProfileRegistry(Path("config/profiles"), settings.contract.profile_dir)`, `ContractRouter`, the core objects and the pipeline, registers routes and returns the app. Delete the three `try/except ImportError` stubs. Module-level `app` is created lazily (`__getattr__`) like the legacy module did, so importing `guardian.main` needs no keys. The telemetry route reads `await request.body()` and maps `SecurityRejection` / `MappingError` to `JSONResponse(exc.http_status, exc.to_public_dict())`.
  - Keep `/health` and `/ws/timeline` as they are.
  - `tests/support.py`: `make_client(gate=None, registry=None)` returns `TestClient(create_app(...))` with fake keys and a fake clock.
- **Why:** this is the move: the live path now runs security → contract adapter → core. Before this step the adapter is unused code.
- **Verify:**
  - `tests/integration/test_pipeline_wiring.py` (new): signed canonical reading → 200, body has `trust_verdict`; unsigned → 401 `SIGNATURE_MISSING`; replayed `event_id` → 409 `REPLAY`; unknown payload shape → 422 `UNKNOWN_SCHEMA`; `type: water_reading` without a profile → 422 `UNKNOWN_SCHEMA`; 180 cm after normal readings → `UNTRUSTED`, `ISOLATE`.
  - `grep -n "ImportError\|EVT-\|uuid" src/guardian/main.py src/guardian/orchestration/pipeline.py` → nothing.
- **Commit:** `feat(pipeline): security gate and contract router on the live path`

### 2.5 Port the remaining legacy tests and delete the legacy modules

- **Files:** `tests/legacy/**` → `tests/integration/`, `tests/scenarios/`, `tests/unit/test_docs.py`; delete `src/guardian/legacy_main.py`, `legacy_config.py`, `legacy_src_init.py`, `orchestration/legacy_pipeline.py`, `legacy_outbound.py`, `legacy_init.py`, `audit/legacy_logger.py`, `audit/legacy_init.py`, `requirements-legacy.txt`, `legacy_docs/`, `legacy_root/`, `pytest.ini`'s `--ignore`.
- **Change:** adapt the 24 integration and 5 scenario tests to `make_client()` and the live route `/api/v1/telemetry`; keep every expected reason code. Tests that targeted removed features (`test_mqtt.py` unless wired, `test_outbound.py` → re-point at `gate.sign_outbound` through the pipeline) are rewritten, not deleted; if one cannot be ported in 30 minutes, mark it `xfail(reason=...)` and list it in the checkpoint report. `test_docs.py` moves to `tests/unit/` and is expected to fail until Phase 4.3: mark `xfail` with that reason.
- **Why:** one app, one test suite; the jury reads the code.
- **Verify:** `python -m pytest -q` → everything green except the documented xfails; `grep -rn legacy src tests` → nothing; `ruff check src tests` clean.
- **Commit:** `refactor: port legacy integration and scenario tests; remove legacy modules`

**Checkpoint 2 (live, on the laptop):** `PYTHONPATH=src uvicorn guardian.main:app --port 8000` with `.env` loaded, then `python -m mocks.mock_twin --mode normal` → `ACCEPTED`; `--mode replay` → `REPLAY`; `--mode tampered` → `SIGNATURE_INVALID`; `--mode flood` → `RATE_LIMITED`; `--mode twin-alt` → `UNKNOWN_SCHEMA` (this becomes onboarding in Phase 3). Each run leaves `logs/<mode>-<UTC>.log`. `/ws/timeline` shows `READING_RECEIVED → GUARDIAN_VERDICT → SENT_TO_BRAIN` for the normal case.

---

# Phase 3: Adapter work

### 3.1 Ollama provider and smoke script (handoff 8.6, task 5)

- **Files:** `src/guardian/adapters/contract/llm/__init__.py`, `llm/ollama.py`, `src/guardian/adapters/contract/ollama_check.py`, `tests/unit/contract/test_ollama_provider.py`.
- **Change:**
  - `OllamaClient(settings: ContractConfig, transport=None)` using `httpx.Client(base_url=settings.llm_url, timeout=settings.llm_timeout_seconds, transport=transport)`.
  - `chat_json(prompt: str, schema: dict) -> str`: `POST /api/chat` with `{"model", "messages":[{"role":"user","content":prompt}], "stream": false, "format": schema, "options": {"temperature": 0, "num_ctx": settings.llm_num_ctx, **({"num_gpu": settings.llm_num_gpu} if settings.llm_num_gpu >= 0 else {})}, "keep_alive": "10m"}`; returns `message.content`; one retry on `httpx.TransportError`; raises `ProviderUnavailable` otherwise (never `MappingError`).
  - `embed(texts: list[str]) -> list[list[float]]`: `POST /api/embed` with `{"model": settings.embed_model, "input": texts}`.
  - `ollama_provider(settings) -> Callable[[str], str]`: the `AIMapper` callable, binding `MappingProfile.model_json_schema()` as `format`.
  - `ollama_check.py` (`python -m guardian.adapters.contract.ollama_check`): prints `/api/tags` models, the embed vector length, the model's raw reply for the diagram sample through `SchemaReader` + `AIMapper`, and the validated profile or the `MappingError`. Exit 0 only if the profile validates. It prints request timings.
  - The package `__init__.py` must **not** import `llm`.
- **Why:** the LLM proposer needs a provider; the smoke script is the only place a real model is called by hand.
- **Verify:** unit tests with `httpx.MockTransport` for: request body fields, `num_gpu` omitted when −1, retry once then `ProviderUnavailable`, non-JSON content passed through unchanged. Live: `python -m guardian.adapters.contract.ollama_check` exits 0 on the laptop and prints the proposal.
- **Commit:** `feat(contract): Ollama chat and embed client, ollama_check smoke script`

### 3.2 AI mapper hardening (handoff task 4)

- **Files:** `ai_mapper.py`, `tests/unit/contract/test_ai_mapper.py`.
- **Change:** build the prompt from `MappingProfile.model_json_schema()` and `CANONICAL_UNITS` (never hand-typed field lists); put the description inside `<untrusted_partner_data> … </untrusted_partner_data>` with a sentence that it is data, not instructions; at most 3 samples, strings truncated to 64 characters; strip one code fence; `{"error": ..., "ambiguous_fields": [...]}` → `NoOpinion(reason)` (new exception, never an error that stops onboarding); after `load_profile`, `validate_against(description)`: every path (via `paths.to_schema_path`) exists in `description.fields`, `batch_path` ∈ `batch_candidates`, and a dry run `GenericMapper().map_message(sample, profile)` on each stored sample succeeds; problems → `MappingError(INVALID_PROFILE, "; ".join(problems))`.
- **Verify:** tests: fenced reply parses; `{"error"}` → `NoOpinion`; invented path `$.payload.ghost` rejected naming the path; `reviewed`/unknown keys rejected; a field named `ignore previous instructions` stays inside the block and the proposal is judged only on paths.
- **Commit:** `feat(contract): hardened prompt and proposal validation`

### 3.3 Proposers (handoff 8.3)

- **Files:** `proposers.py` (new), `config/contract/synonyms.yaml` (new), `tests/unit/contract/test_proposers.py`.
- **Change:** `Proposal(profile: MappingProfile, proposer: str, notes: list[str])`; a `Proposer` protocol with `propose(description) -> Proposal | None`.
  - `HeuristicProposer(synonyms)`: normalise keys (camelCase/snake_case, strip unit suffixes `_cm`, `_m`, `Cm`), `difflib` similarity against canonical roles (`value`, `unit`, `metric`, `timestamp`, `sensor_id`, `twin_id`), type hints (ISO or 10/13-digit numbers → timestamp, short strings in the unit table → unit, numbers → value). Picks `metric_value` from the synonym table when the key implies a metric (`levelOfWater` → `water_level`). Returns `None` when it cannot place `value`.
  - `LLMProposer(ai_mapper)`: wraps `propose_profile`; `NoOpinion`, `ProviderUnavailable` and `MappingError` → `None`.
  - `EmbeddingProposer` is step 3.7.
- **Verify:** heuristic maps the diagram sample, the `twin-alt` sample and the canonical sample; returns `None` for `{"foo": "bar"}`; the LLM proposer returns `None` on provider failure (fake raising).
- **Commit:** `feat(contract): heuristic and LLM proposers`

### 3.4 Gates and reconciliation (handoff 8.4, gates 1–4)

- **Files:** `gates.py` (new), `config/contract/plausibility.yaml` (new: `water_level: {min: 0, max: 1000, unit: cm}`, placeholders for the other metrics marked `# PENDING team`), `tests/unit/contract/test_gates.py`.
- **Change:** `GateResult(name, passed, reason)`; `run_gates(proposals, description, samples, plausibility) -> tuple[MappingProfile | None, list[GateResult]]`:
  1. structural: `load_profile` + path existence (reuse 3.2's `validate_against`).
  2. consensus: `batch_path`, `sensor_id_path`, `timestamp_path`, `twin_id_path`, `event_kind` must be equal across at least two proposers (if only one proposer answered, the gate fails with `single_proposer`). Other fields come from the first passing proposal in order `[heuristic, embedding, llm]`.
  3. dry run: every sample maps.
  4. plausibility: numeric where required, unit known, value inside the metric's range, `occurred_at` within `max_age_seconds + 60` of the envelope timestamp.
- **Verify:** tests: two agreeing proposals pass; disagreement on `timestamp_path` fails gate 2; implausible value (1e9 cm) fails gate 4; a profile whose dry run raises fails gate 3; results list names the failing gate.
- **Commit:** `feat(contract): automatic gates and reconciliation`

### 3.5 Onboarding orchestration (handoff 8.2, 8.8; task 8)

- **Files:** `onboarding.py` (new), `router.py` (hook), `src/guardian/audit/logger.py` (add `log_onboarding(event, fingerprint, **fields)`, marked `# TODO(guardian-integration)`), `main.py` (construct and start), `tests/unit/contract/test_onboarding.py`.
- **Change:** `OnboardingManager(registry, reader, proposers, gates, settings, audit, clock)`:
  - `submit(envelope, fingerprint)`: append to a `deque(maxlen=settings.onboarding_buffer)` per fingerprint; if no task runs for it, `asyncio.create_task(self._run(fingerprint))`. Never blocks the caller.
  - `_run`: `SchemaReader.read_samples(buffer)` → proposers → gates → on pass: `registry.register(PROBATION)`, audit `PROFILE_PROBATION`, then `drain(fingerprint)` which replays buffered envelopes through the pipeline's post-security path (`pipeline.process_accepted(envelope)`; add that method to `pipeline.py` as a split of step 2.4's logic). On fail or `asyncio.wait_for` timeout: `registry.register(UNMAPPABLE)` with `gate_results`, audit `SCHEMA_UNMAPPABLE` / `ONBOARDING_TIMEOUT`, drop the buffer.
  - Audit events exactly as handoff 8.8, through `audit.logger`; no payloads.
  - Router: `on_unknown=onboarding.submit`; the pipeline returns HTTP 202 `{"status": "ONBOARDING_PENDING", "fingerprint": ...}` for `UNKNOWN_SCHEMA` while a run is active (assumption A12).
  - Operator reset: `POST /api/v1/profiles/{fingerprint}/reset` (operation `reset_profile`, allowed for `guardian` layer only, signed) sets UNMAPPABLE → removed.
- **Verify:** tests with fake proposers and a fake clock: unknown shape → 202 then, after the task completes, the buffered messages produce `GUARDIAN_VERDICT` timeline entries; gates failing → UNMAPPABLE and later messages get 503 `PROFILE_NOT_ACTIVE`; timeout path; only one task per fingerprint under 50 concurrent submits.
- **Commit:** `feat(contract): automatic onboarding with audit trail`

### 3.6 Probation (gate 5; task 9)

- **Files:** `router.py`, `registry.py`, `src/guardian/contracts/events.py` (`EventProvenance.profile_status: Literal["ACTIVE","PROBATION"] = "ACTIVE"`, marked `# TODO(guardian-integration)`), `mapper.py` (set it), `tests/unit/contract/test_probation.py`.
- **Change:** on each successful map through a PROBATION record, `clean_messages += 1`; at `settings.probation_messages` → `ACTIVE`, audit `PROFILE_ACTIVE`; a `MappingError` or plausibility failure during probation → `REVOKED`, audit `PROFILE_REVOKED`. The router refuses REVOKED (3 above).
- **Verify:** tests: N clean → ACTIVE and persisted; one failure → REVOKED and the next message gets `PROFILE_NOT_ACTIVE`; events carry `profile_status`.
- **Commit:** `feat(contract): probation and promotion`

### 3.7 Embedding proposer (optional; task 11)

- **Files:** `proposers.py`, `tests/unit/contract/test_proposers.py`.
- **Change:** `EmbeddingProposer(embed: Callable[[list[str]], list[list[float]]])`: cosine similarity between partner field paths (plus their sample values' types) and canonical role descriptions; threshold from config (`0.6`); returns `None` below it.
- **Verify:** test with a fake `embed` returning fixed vectors; the gate-2 test now passes with heuristic + embedding agreeing while the LLM is unavailable.
- **Commit:** `feat(contract): embedding proposer`

**Checkpoint 3:** `python -m pytest -q` green (expect ~230 tests); every test listed in handoff section 10 exists by name; `ruff check` clean; `ollama_check` passes on the laptop.

---

# Phase 4: End-to-end validation

### 4.1 Onboarding scenario (R2 for this feature)

- **Files:** `scenarios/onboarding.ps1` and `scenarios/onboarding.sh` (one command each), `mocks/mock_twin.py` (`--mode twin-alt --count 25`).
- **Change:** the script starts nothing; it assumes Guardian and Ollama are running. It sends 25 `twin-alt` readings 0.5 s apart and tails the timeline WebSocket into `logs/onboarding-<UTC>.log`.
- **Verify (live):** the log shows `SCHEMA_UNKNOWN → ONBOARDING_STARTED → PROFILE_PROPOSED (proposers_agreed: heuristic, llm) → PROFILE_PROBATION → GUARDIAN_VERDICT × 20 → PROFILE_ACTIVE`, and `data/profiles/<fingerprint>.json` exists with status ACTIVE. Record the time from first message to `PROFILE_PROBATION`; if it exceeds 60 s, lower `GUARDIAN_LLM_NUM_CTX` or switch to the smaller model and rerun.
- **Commit:** `feat(scenarios): one-command onboarding scenario with log`

### 4.2 Variant benchmark for the report

- **Files:** `src/guardian/adapters/contract/benchmark.py`, `tests/unit/contract/fixtures/variants/*.json` (the 10 variants from `test_mapper.py` plus 5 negative ones).
- **Change:** `python -m guardian.adapters.contract.benchmark` runs each proposer and the full gate chain on every variant and prints a table: variant, heuristic fields correct, LLM fields correct, gates passed, outcome. Offline by default (`--live` uses Ollama).
- **Verify:** offline run prints the table; `--live` run on the laptop completes; paste the table into report part 3.
- **Commit:** `feat(contract): proposer benchmark`

### 4.3 Documentation (task 12)

- **Files:** `guardian/INTERFACE.md`, `guardian/docs/SECURITY.md`, `guardian/docs/ARCHITECTURE.md`, `INTEGRATION.md`, `tests/unit/test_docs.py` (remove `xfail`).
- **Change:** INTERFACE.md: the envelope, one example per message type (`sensor_reading`, `trust_verdict`, `containment_command`, error body), the HTTP status per reason code (security and mapping), how to point at another partner (a profile JSON in `config/profiles/`, or let onboarding create one), how it authenticates (HMAC rules). SECURITY.md: threat → control → file → test table, AI guardrails (gates, probation, no per-message calls, untrusted-data block), the URI rule, limitations. ARCHITECTURE.md: the Phase 2 pipeline and the onboarding loop as text diagrams. INTEGRATION.md: replace the `token`/`levelOfWater` example with the envelope.
- **Verify:** `python -m pytest tests/unit/test_docs.py -q` passes (every reason code documented, examples verify with the documented keys, every control names a test).
- **Commit:** `docs: interface card, security and architecture for the contract adapter`

### 4.4 Demo readiness

- **Change:** nothing in code. Run on the demo laptop, on the team hotspot:
  1. `ollama list` shows the chosen model and `nomic-embed-text`; `ollama_check` exits 0 (no venue download needed).
  2. `docker compose up guardian brain-mock` (or native `uvicorn`), then the Checkpoint 2 mock runs and the 4.1 scenario.
  3. Pull the network cable or hotspot mid-scenario and confirm Guardian keeps serving known profiles (onboarding degrades to `UNMAPPABLE` after the timeout, nothing crashes).
- **Verify:** all three steps pass twice in a row; the logs are committed under `logs/`.

**Final checkpoint:** `ruff check src tests` clean; `python -m pytest -q` green; Checkpoint 2 mock runs pass; `ollama_check` exits 0; `scenarios/onboarding` produces the log sequence in 4.1; the four documents in 4.3 match the code and `test_docs.py` passes; `git log --oneline main..contract-foundation` shows one commit per step above.

---

# Deliberately out of scope (unchanged by this plan)

- Per-run JSON log files for every scenario (R2 beyond onboarding), the `/timeline` HTML page and Brain/Twin timeline intake (R3), the containment command to the Twin with acknowledgement, MQTT activation, CORS tightening, the observer/gatekeeper decision, `contracts/` JSON Schema export. Each is a separate task for its owner; none blocks the adapter.
- If time runs short before the 6 November freeze: cut 3.7, then make 3.5 synchronous (run onboarding inline with a 30 s cap), then cut 4.2. Steps 0–2.5 and 3.1–3.4 are the minimum for the adapter to count.
