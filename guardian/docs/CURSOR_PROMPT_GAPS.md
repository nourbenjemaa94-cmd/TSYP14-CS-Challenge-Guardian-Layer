# Cursor prompt: close the Guardian gaps, most critical first

You are the lead engineer on the Guardian layer of `triplet-07` (TSYP14 City Brain Convergence, Phase 1, submission 8 November 2026). Work in this repository on the Windows laptop you are running on. Your reference documents are, in order of authority: the challenge statement, the team handoff (sections 7–11 define the target design), `guardian/docs/CURSOR_PLAN_CONTRACT_FOUNDATION.md` (step numbers below refer to it), and this prompt. Where this prompt amends the plan, this prompt wins.

## Standing rules

1. Work through the packages below in order. Inside a package, do the steps in order. After each step run its verification; after each package stop, print the package report (what changed, test counts, anything you could not do) and wait for approval before the next package.
2. Touch only the files a step names. No refactoring, renaming or reformatting outside them. Edits in `core/`, `audit/`, `orchestration/` and `contracts/` are the minimum needed and carry `# TODO(guardian-integration): <why>`.
3. Tests never use the network. Ollama is called only by the terminal commands in P2, the smoke script, and the live checkpoints.
4. Never generate an `event_id`, never read a Twin's true values, never fetch a URI from a partner message, never call a model per message, never log payload values or secrets.
5. Nothing from Ollama goes into the repository: no installer, no model files, no `.ollama` directory. Only configuration, scripts and documentation.
6. Commit after every step with the message given. If a verification fails, fix the step; never skip it, never weaken or delete a test to pass.
7. Where a step needs a decision or an action from a person (marked **HUMAN**), do everything up to that point, print exactly what is needed, and stop.

---

## P1. Process and repository hygiene (30 minutes)

Goal: the work has a branch, the repo cannot absorb binaries or runtime state, and the plan carries the amendments below.

1. **Branch.** `main` already holds the first five plan steps (commits `6f61c77` … `0faa4ba`). Create `contract-foundation` from the current `main` and do all further work there. Tell Nour that `main` currently contains the half-wired state (live stubs) so the team knows.
2. **`.gitignore`:** add `guardian/data/`, `*.exe`, `*.msi`, `*.gguf`, `.ollama/`, `guardian/logs/*.tmp`. Verify: `git check-ignore -v guardian/data/profiles/x.json OllamaSetup.exe` prints both.
3. **Plan amendments.** Edit `guardian/docs/CURSOR_PLAN_CONTRACT_FOUNDATION.md` so later packages are consistent:
   - Step 1.3: `config.py` must not instantiate `Settings()` at import; only `Settings.load()` (called from `create_app`). Add `GUARDIAN_ONBOARDING_MIN_PROPOSERS` (default `2`) and `GUARDIAN_FORWARD_TO_BRAIN` (default `true`) to `ContractConfig`/`PartnerConfig` and to `.env.example`.
   - Step 1.7: add a deliverable `scripts/setup-ollama.ps1` and `scripts/setup-ollama.sh` (see P2.4).
   - Step 2.4: `/health` returns `"llm": "reachable" | "unreachable" | "disabled"` (a 2-second `GET /api/tags` with the configured URL, cached 30 s).
   - Step 3.4: gate 2 passes with a single proposer only when `GUARDIAN_ONBOARDING_MIN_PROPOSERS=1`; the record then stores `gate_results.consensus = "degraded"`.
   - Step 4.4: add "warm the model once (`ollama run <model> "hi"`) before the slot".
4. Verify: `cd guardian && python -m pytest -q` → `103 passed`. Commit: `chore: branch, ignore runtime and binaries, plan amendments`.

**Report P1** and wait.

---

## P2. Make the local model usable (Ollama is installed; the model does not load)

Goal: `GUARDIAN_LLM_MODEL` names a model that answers a JSON-schema request on this laptop; a teammate can reproduce the setup with one script. Run the commands in the integrated terminal (PowerShell); print every output in the report.

1. **Diagnose.** `Get-Content $env:LOCALAPPDATA\Ollama\server.log -Tail 200 | Select-String -Pattern "bad_alloc|memory|offload|gpu|library" -Context 20,0` and `systeminfo | findstr /C:"Total Physical Memory" /C:"Available Physical Memory"` and `ollama ps`. Summarise the cause in one sentence (expected: the runner could not allocate the memory the 3B model needed, possibly on the GPU path).
2. **Retry the way Guardian will call it** (CPU only, small context), with the `curl` from plan step 1.7 (`"options":{"num_gpu":0,"num_ctx":2048,"temperature":0}` and a JSON-schema `format`). If it answers `{"ok": true}`, set in `guardian/.env`: `GUARDIAN_LLM_MODEL=qwen2.5:3b`, `GUARDIAN_LLM_NUM_GPU=0`.
3. **Fallbacks.** If step 2 fails: `ollama pull qwen2.5:1.5b` and repeat; then `qwen2.5:0.5b`. Set `GUARDIAN_LLM_MODEL` to the first model that answers. If none answers, re-pull the 3B model once (`ollama rm` then `pull`) and if it still fails, **HUMAN**: stop and print the server-log lines from step 1.
4. **Embeddings:** `curl http://localhost:11434/api/embed -d "{\"model\":\"nomic-embed-text\",\"input\":\"water level\"}"` must return one vector of 768 numbers.
5. **Setup script.** Create `scripts/setup-ollama.ps1` and `scripts/setup-ollama.sh`: check `ollama --version`; read `GUARDIAN_LLM_MODEL` and `GUARDIAN_EMBED_MODEL` from `guardian/.env` (fall back to `.env.example`); `ollama pull` each; print the `/api/tags` names; exit 1 with a clear message if Ollama is not reachable. No other side effects.
6. **README.** Add a section "Local model (optional)" to `guardian/README.md`: Guardian runs without Ollama (known partners, no automatic onboarding), what the three modes are (committed profiles / heuristic-only with `GUARDIAN_ONBOARDING_MIN_PROPOSERS=1` / full), the setup script, and the Docker note: Ollama binds to `127.0.0.1`, so Guardian-in-Docker needs the user environment variable `OLLAMA_HOST=0.0.0.0:11434` (restart Ollama, accept the firewall prompt) and `GUARDIAN_LLM_URL=http://host.docker.internal:11434`; running Guardian natively avoids this and is the recommended demo setup.
7. Verify: `scripts/setup-ollama.ps1` exits 0; `.env` has a non-empty `GUARDIAN_LLM_MODEL`. Commit: `chore(llm): setup script, local-model docs` (`.env` stays uncommitted).

**Report P2** with the chosen model, options and the response time of step 2, and wait.

---

## P3. Foundation that everything else depends on (plan 1.4 → 1.6)

Goal: mocks import, the 51 security tests run, lint and CI are green.

1. Plan **1.4** (mocks import the live settings; add `--mode twin-alt`). Verify: both `--help` outputs.
2. Plan **1.5** (restore the 51 gate tests under `tests/unit/security/`, `tests/support.py` without app helpers). Verify: `pytest tests/unit -q` → `154 passed`. If a gate test fails, **HUMAN**: stop and print its name; the gate changed since the security branch.
3. Plan **1.6** (`guardian/ruff.toml`, one `ruff check --fix` for import order only, CI working directory). Verify: `ruff check src tests` clean; `pytest -q` → 154 passed.
4. Plan 1.3 correction: remove the module-level `settings = Settings()` from `config.py`; anything that used it imports `Settings` and calls `load()` inside a function. Verify: `python -c "import guardian.config"` with no `.env` loaded succeeds; `Settings.load()` without keys raises `SecurityConfigurationError` naming the variable.

Commits as in the plan. **Report P3** and wait.

---

## P4. Connect the layers (plan 2.1 → 2.5): the single most important package

Goal: the live path is security gate → contract router → core → signed verdict to the Brain; the stubs are gone; the legacy code is gone.

1. Plan **2.1** fingerprint and multi-sample reader.
2. Plan **2.2** registry; create `guardian/config/profiles/twin-canonical-v1.json`.
3. Plan **2.3** router.
4. Plan **2.4** pipeline and `create_app`, with the P1 amendments: `Settings.load()`, `/health.llm`, `GUARDIAN_FORWARD_TO_BRAIN` (when `false`, verdicts are stored and served by `GET /api/v1/verdicts/{event_id}` instead of pushed; this keeps the observer-vs-gatekeeper decision a configuration switch). Delete the three `try/except ImportError` stubs.
5. Plan **2.5** port the legacy integration and scenario tests, delete every `legacy_*` module, remove `--ignore=tests/legacy` from `pytest.ini`.
6. **Live checkpoint (run it, print the output):** start `uvicorn guardian.main:app --port 8000` with `.env` loaded; run `python -m mocks.mock_twin --mode normal|replay|tampered|flood|twin-alt`. Expected: `ACCEPTED`, `REPLAY`, `SIGNATURE_INVALID`, `RATE_LIMITED`, `UNKNOWN_SCHEMA`. Each leaves `logs/<mode>-<UTC>.log`. `curl /health` shows `"llm": "reachable"`.

Commits as in the plan. **Report P4** (test count, the five mock results, any xfail with its reason) and wait.

---

## P5. Model integration (plan 3.1 → 3.2)

1. Plan **3.1** `llm/ollama.py` (chat with JSON-schema `format`, embed, `num_gpu` omitted when `-1`, one retry, `ProviderUnavailable`), `MockTransport` tests, `ollama_check` smoke script. Live: `python -m guardian.adapters.contract.ollama_check` exits 0 and prints the proposal for the diagram sample and the timing.
2. Plan **3.2** AI mapper hardening (prompt generated from `MappingProfile.model_json_schema()`, untrusted-data block, truncation, fence stripping, `NoOpinion`, path existence, dry run).

**Report P5** with the smoke-script output, and wait.

---

## P6. Automatic onboarding (plan 3.3 → 3.6)

1. Plan **3.3** heuristic and LLM proposers, `config/contract/synonyms.yaml`.
2. Plan **3.4** gates and `config/contract/plausibility.yaml` (water_level 0–1000 cm; other metrics as placeholders marked `# PENDING core team`), with the `MIN_PROPOSERS` amendment.
3. Plan **3.5** onboarding manager, audit events through `audit/logger.py` (`log_onboarding`, marked TODO(guardian-integration)), HTTP 202 `ONBOARDING_PENDING`, operator reset endpoint.
4. Plan **3.6** probation and `EventProvenance.profile_status` (marked TODO(guardian-integration); tell Nour it needs Members 1 and 6 to agree).
5. Plan **3.7** embedding proposer only if P1–P6 are done before 6 November; otherwise skip and say so.

**Report P6** (every test name from handoff section 10 and whether it exists) and wait.

---

## P7. Proof for the jury (plan 4.1 → 4.3)

1. Plan **4.1** `scenarios/onboarding.ps1` and `.sh`; run it live; commit `logs/onboarding-<UTC>.log` showing `SCHEMA_UNKNOWN → ONBOARDING_STARTED → PROFILE_PROPOSED → PROFILE_PROBATION → GUARDIAN_VERDICT ×20 → PROFILE_ACTIVE`. Print the time to `PROFILE_PROBATION`; if over 60 s, lower `GUARDIAN_LLM_NUM_CTX` or switch to the smaller model and rerun.
2. Plan **4.2** benchmark; paste the table into the report.
3. Plan **4.3** documentation: `INTERFACE.md`, `INTEGRATION.md`, `docs/SECURITY.md`, `docs/ARCHITECTURE.md`; `tests/unit/test_docs.py` passes without `xfail`.
4. Rewrite `TESTBOOK.md` in the spec's fields (ID, name, layers, description, trigger, expected per layer, how to verify) for every scenario that now has a mock mode or a script: normal, replay, tampered, flood, stale, spoofed reading (T5), onboarding. Mark Brain-side expectations `PENDING Brain team`.

**Report P7** and wait.

---

## P8. Enabling changes outside the adapter (smallest possible; other members own these folders)

For each item, make the minimal change that lets Guardian's own scenarios run, mark it `TODO(guardian-integration)`, and list it in the report for the owner.

1. **R2 per-run log (audit, Members 4 and 3):** `audit/logger.py` gets `RunLogger(path)` writing JSON lines (`timestamp` with `Z`, `event_id`, `layer`, `stage`, `reason_code`, `action`); the pipeline opens one per scenario when `GUARDIAN_RUN_LOG` is set; signatures stripped. Do not touch `event_store.py` or `timeline.py` beyond the `Z` timestamp fix in `get_utc_now`.
2. **Containment to the Twin (core, Members 3 and 4):** add a `TwinContainmentPort` in `adapters/communication/rest.py` that POSTs a signed `ContainmentCommand` to `settings.partners.twin_command_url` and records the `ContainmentOutcome`; wire it into `ContainmentEngine(port=...)` in `create_app`. Add `--accept-commands` to `mock_twin.py` so it acknowledges. Do not change `containment.py` logic.
3. **Brain mock receives verdicts (Members 1 and 6):** `mock_brain.py` verifies the Guardian signature on `trust_verdict` and posts a `report_decision` back through the gate; the timeline shows `BRAIN_DECISION`.
4. **Repo layout (triplet):** create `.github/CODEOWNERS` (`/guardian/ @<Guardian members>`, `/twin/` and `/brain/` placeholders), root `logs/` and `scenarios/` with READMEs, `twin/README.md` and `brain/README.md` placeholders saying "owned by the partner team". Remove the empty root `src/ tests/ mocks/`. Restrict CORS to `GUARDIAN_CORS_ORIGINS` (default `http://localhost:*`).
5. Verify: full suite green, Checkpoint 2 mock runs still pass, T5 run shows `ISOLATED` with the Twin mock's acknowledgement in the log.

**Report P8** with the per-owner handoff list, and wait.

---

## P9. Pending decisions: make them configuration and write them down

Cursor cannot decide these; make each one a switch with the current code behaviour as the default, and write `guardian/docs/DECISIONS_PENDING.md` with, per item: the question, the default in code, the setting that changes it, and who must answer.

| # | Decision | Default in code | Setting |
|---|---|---|---|
| E1 | Observer or gatekeeper | gatekeeper | `GUARDIAN_FORWARD_TO_BRAIN` |
| E2 | Verdict names | TRUSTED / SUSPICIOUS / UNTRUSTED | `GUARDIAN_VERDICT_NAMES` (JSON map applied only on the wire, in the outbound adapter) |
| E3 | Partners sign HMAC | required | none; document the one-message test in INTEGRATION.md |
| E4 | MQTT | off | `GUARDIAN_MQTT_ENABLED` |
| E5 | Plausibility ranges, probation length | placeholders, 20 messages | `plausibility.yaml`, `GUARDIAN_PROBATION_MESSAGES` |
| E6 | Core use of `profile_status` | ignored | none; listed for Members 3 and 4 |
| E7 | Twin event kinds | measurement only on the live path | profiles |
| E8 | Member 5 split | — | not a setting; list the security tasks still open |

**Report P9** and stop. Print the final state: branch, commit count, test count, `ruff` result, the five mock results, the onboarding log path, the `/health` output, and the list of items handed to other owners.

---

## Priority summary (if time runs out, stop at the end of a package, never in the middle)

P1 → P2 → P3 → P4 are mandatory for the layer to score at all. P5 → P6 make the adapter automatic. P7 is the evidence the jury reads. P8 and P9 are enabling work for other owners and can be reduced to the documentation parts if the 6 November freeze is reached.
