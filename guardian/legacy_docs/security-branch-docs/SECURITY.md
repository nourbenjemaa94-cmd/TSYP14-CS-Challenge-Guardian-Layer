# Guardian security measures

The security sub-layer answers one question per message: is it authentic, allowed, well-formed, fresh, and new? Authentication proves who sent it. The core decides whether the content is trustworthy.

Checks run in this order: size and JSON parse, HMAC, authorization, rate limit, contract mapping, envelope validation, source match, freshness, replay. Replay state changes last, so a forged message cannot move a sequence counter. Only an authenticated identity consumes a rate-limit bucket.

## Threats, controls, and the tests that show them

| Threat | Control | File | Test |
|---|---|---|---|
| Spoofed or tampered reading | HMAC-SHA256 over canonical JSON, verified before mapping | `src/guardian/security/authentication.py` | `test_signature_invalid_when_tampered`, `test_spoofed_reading_is_rejected` |
| Forged sender (wrong layer key) | One key per layer; `source.layer` selects it | `src/guardian/security/authentication.py` | `test_wrong_key_is_signature_invalid`, `test_forged_sender_is_rejected` |
| Unknown sender | Layer must be `twin`, `brain`, or `guardian` | `src/guardian/security/authentication.py` | `test_unknown_sender` |
| Replay | Event-id cache bounded to the freshness window | `src/guardian/security/replay_protection.py` | `test_replay_rejected`, `test_replayed_reading_is_rejected` |
| Stale reading | Reject timestamps older than `GUARDIAN_MAX_AGE_SECONDS` (default 30) | `src/guardian/security/freshness.py` | `test_stale_timestamp_rejected`, `test_stale_reading_is_rejected` |
| Far-future timestamp | Reject timestamps more than `GUARDIAN_MAX_FUTURE_SKEW_SECONDS` ahead (default 5) | `src/guardian/security/freshness.py` | `test_future_timestamp_rejected` |
| Malformed or oversized input | Size limit, UTF-8 JSON object parse, Pydantic envelope, schema major check | `src/guardian/security/validation.py` | `test_message_too_large`, `test_malformed_json`, `test_schema_invalid_lists_fields` |
| Privilege misuse | Deny-by-default operation policy. Guardian has no inbound operations. | `src/guardian/security/authorization.py` | `test_forbidden_operation` |
| Device flood | Token bucket per source, then one `FLOOD_SUSPECTED` audit event per 10-second window | `src/guardian/security/rate_limit.py` | `test_flood_signal_once_per_window`, `test_flood_is_rate_limited_and_audited` |
| Mapper changes the sender | `SOURCE_MISMATCH` after mapping, before replay state changes | `src/guardian/security/gate.py` | `test_source_mismatch_does_not_record_replay` |
| Forged verdict or containment command | Every outbound verdict and command is signed with the Guardian key | `src/guardian/orchestration/outbound.py` | `test_sign_outbound_and_modified_copy_fails` |
| Secret leakage in the audit | Fixed record fields; signatures, keys, and payloads are not logged | `src/guardian/audit/logger.py` | `test_rejection_audit_record_has_no_signature` |
| Process starts with a weak or missing key | Startup refuses keys shorter than 32 characters and does not echo the value | `src/guardian/security/gate.py` | `test_from_env_short_key_message_has_no_secret` |
| Health endpoint discloses configuration | Fixed body: `status`, `contract_version`, `degraded` | `src/guardian/adapters/communication/rest.py` | `test_health_reveals_no_secrets` |
| Runtime LLM mapping | `suggest_mapping` refuses to run; the live mapper is deterministic | `src/guardian/adapters/contract/ai_mapper.py` | `test_ai_mapper_is_not_on_the_live_path` |

Partners see a stable `ReasonCode`, a fixed sentence, and an HTTP status. The table of codes is in `INTERFACE.md`. Internal detail stays in the server log.

## Known limitations

- Symmetric HMAC: anyone who holds a layer key can sign as that layer. There is no key id and no rotation protocol in Phase 1.
- Cross-language JSON canonicalisation: Python `1.0` and JavaScript `1` are different byte strings. The first integration with each partner must exchange one signed message in each direction.
- In-memory state is lost on restart. A replay can succeed for up to one freshness window after a restart. Rate-limit and flood memory is lost as well.
- Run a single worker. Each worker would keep its own replay cache and token buckets, and a replay could slip through.
- No TLS on the local Docker network in Phase 1.
- No key rotation.
- MCP is deferred to Phase 2. An MCP adapter would be a thin caller of the same `SecurityGate`.
- The AI mapper is offline only. It is not on any path that handles a live message. A person reviews any mapping file and commits it.
- The rate-limit device id is taken from the message. A holder of a valid layer key can spread traffic across device ids up to the 10,000-source cap. A caller who does not have a valid key cannot consume any bucket.

## Assumptions to confirm with the triplet

1. Partners send the envelope in `INTERFACE.md` and sign it with the canonical JSON rules above. The layer name on `source.layer` selects the key. File: `src/guardian/security/authentication.py`.
2. REST is the primary transport. MQTT is used when the Twin publishes the stream. Route and topic names come from `config.example.yaml`. File: `src/guardian/config.py`.
3. The Twin verifies Guardian's signed isolation, quarantine, and release commands, and the Brain verifies Guardian's signed verdicts. File: `src/guardian/orchestration/outbound.py`.
4. Sequence numbers are per source, may start at any non-negative value, and then increase by 1. A gap is `SEQ_GAP`. A number that does not move forward is `SEQ_RESET`, and the stored sequence adopts the new value. File: `src/guardian/security/replay_protection.py`.
5. Clocks agree within the 5-second skew. A timestamp exactly 30 seconds old is still fresh. A timestamp exactly 5 seconds ahead is still accepted. File: `src/guardian/security/freshness.py`.
6. Payload schemas belong to contracts. Security only requires the envelope. File: `src/guardian/contracts/__init__.py`.
7. The rate-limit device id is `source.device_id` when that value is a string of 1 to 128 characters, otherwise a top-level `device_id` under the same rule, otherwise `-`. File: `src/guardian/security/rate_limit.py`.
8. This repository is the Guardian folder, so Compose loads `.env`. In the triplet checkout that same file is `guardian/.env`. File: `docker-compose.yml`.
9. The core does not yet expose `on_security_signal`. Floods are audited as `FLOOD_SUSPECTED` with outcome `signal`. File: `src/guardian/orchestration/pipeline.py` and `src/guardian/core/stub.py`.
10. Phase 1 contract mapping is the identity function. File: `src/guardian/adapters/contract/mapper.py`.
11. Log file names drop the colons from the UTC timestamp so they are legal on Windows. File: `mocks/runtime.py`.
12. The generic receivers already in `adapters/communication/` stay as they are. Guardian's signed routes are registered by `src/guardian/adapters/communication/rest.py`.
