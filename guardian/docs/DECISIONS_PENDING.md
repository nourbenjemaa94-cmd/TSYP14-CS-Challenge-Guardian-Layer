# Decisions pending

Question, default in code, setting, owner. Nothing here is a secret.

| ID | Question | Default in code | Setting | Owner |
|---|---|---|---|---|
| E1 | Observer vs gatekeeper | Forward verdicts to Brain | `GUARDIAN_FORWARD_TO_BRAIN` (default true). `false` stores and serves `GET /api/v1/verdicts/{event_id}` | Guardian |
| E2 | How many proposers must agree | 2 | `GUARDIAN_ONBOARDING_MIN_PROPOSERS` (1–3). Scenario scripts use 1 (heuristic only) | Guardian |
| E3 | Probation length | 20 clean maps | `GUARDIAN_PROBATION_MESSAGES` | Guardian |
| E4 | Plausibility ranges besides water | water_level 0–1000 cm | `config/contract/plausibility.yaml`; others pending Core | Core |
| E5 | Does Core consume `profile_status` | Ignored | `EventProvenance.profile_status` | Core / Member 3–4 |
| E6 | LLM model if onboarding > 60 s | `qwen2.5:3b`, `num_ctx=2048` | `GUARDIAN_LLM_MODEL`, `GUARDIAN_LLM_NUM_CTX` | Guardian |
| E7 | CORS allow-list | YAML `server.cors_origins` or `*` | `GUARDIAN_CORS_ORIGINS` | Guardian |
| E8 | Trust thresholds | `TrustSettings` on YAML | `trust.*` / env; unknown keys rejected | Guardian |
| B2 | Unused YAML trust keys | Rejected (`extra=forbid`) | Do not add `initial_score` / `penalty_*` | Guardian |
| B3 | Config precedence | Compose `.env` → container env → `guardian/.env` → YAML → defaults | documented in README | Guardian |
| G1 | How is a non-JSON body signed | JSON only. XML/CSV decoder not registered | `partners.twin.format=json`. REST `Content-Type: application/xml` → `415 FORMAT_MISMATCH` | Twin + Guardian. Do not add XML until Twin says whether the signature covers raw bytes or a JSON wrapper |
| H1 | Per-scenario run log | stdout audit logger | `GUARDIAN_RUN_LOG` not wired | Guardian |
| H2 | Twin containment port | Local forward block only | `partners.twin.command_url` not wired | Twin + Guardian |
| H3 | Brain `report_decision` on the live path | Mock Brain exists; live `BRAIN_DECISION` not emitted | mock_brain | Brain |
| H6 | `contract-foundation` branch | Local `main` is ahead of origin; nothing is pushed | Needs the user's go-ahead before push or delete | Nour |

## Blocked

- **A3 Compose / clean-clone:** Docker Desktop cannot start (WSL not installed; needs admin + reboot).
- **H6:** no force-push, no branch delete, no push unless asked.
