"""Model-assisted profile proposals. Never on the live message path.

``AIMapper`` turns a ``SchemaDescription`` into a prompt, hands it to an
injected provider callable (a fake in tests, a local model in production) and
validates the answer as a ``MappingProfile`` through the same ``load_profile``
as every other profile. Prompt hardening (untrusted-data block, fence
stripping, the error shape, path existence checks) is handoff task 4.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from .errors import MappingError, MappingErrorCode
from .profile import ENVELOPE_SENSOR_ID_PATH, ENVELOPE_TIMESTAMP_PATH, MappingProfile, load_profile
from .schema_reader import SchemaDescription


class AIMapper:
    """Uses an external AI provider to propose a MappingProfile.

    The provider is a callable that receives a prompt and returns a JSON
    string containing a proposed mapping profile.
    """

    def __init__(self, ai_provider: Callable[[str], str]) -> None:
        self.ai_provider = ai_provider

    def build_prompt(self, description: SchemaDescription) -> str:
        schema_information = description.model_dump_json(indent=2)
        return f"""You are designing a data mapping profile for Guardian.

Guardian's canonical event format supports these event kinds:

1. measurement: metric, value, unit
2. status: status
3. discrete_event: event_name, detected, confidence
4. media_reference: media_type, uri

The message is an envelope; its payload is what varies by partner.
Identity and time default to the envelope: sensor_id_path defaults to
"{ENVELOPE_SENSOR_ID_PATH}" and timestamp_path to "{ENVELOPE_TIMESTAMP_PATH}".
Only override them when the payload clearly carries its own values.

The external schema is:

{schema_information}

Create a mapping profile in JSON.

Rules:
- Do not invent meanings for ambiguous fields.
- Use only paths supported by the supplied schema or sample.
- Use $ for paths relative to the complete message.
- Use @ for paths relative to the current event/sensor item.
- If the payload contains an array of events, set batch_path.
- Choose one event kind that is actually supported by the supplied data.
- For a measurement, give metric_path OR metric_value (a constant such as
  "water_level" when the metric is implied by the field name), value_path,
  and unit_path OR unit_value. metric_map may rename partner metric names.
- timestamp_format is "iso", "unix_s" or "unix_ms".
- If important meaning is ambiguous, return an error instead of guessing.
- Include profile_id, schema_id, version and event_kind.
- Include only the paths needed for the chosen event kind.
- Return JSON only. Do not include Markdown.

Example profile for a measurement:

{{
  "profile_id": "twin-a-v1",
  "schema_id": "twin-a-v1",
  "version": "1.0",
  "event_kind": "measurement",
  "metric_value": "water_level",
  "value_path": "$.payload.levelOfWater",
  "unit_path": "$.payload.unit"
}}
"""

    def propose_profile(self, description: SchemaDescription) -> MappingProfile:
        prompt = self.build_prompt(description)
        response = self.ai_provider(prompt)
        try:
            profile_data = json.loads(response)
        except json.JSONDecodeError as exc:
            raise MappingError(MappingErrorCode.INVALID_PROFILE, "AI provider did not return valid JSON") from exc
        if not isinstance(profile_data, dict):
            raise MappingError(MappingErrorCode.INVALID_PROFILE, "AI provider did not return a JSON object")
        profile = load_profile(profile_data)
        if profile.schema_id != description.schema_id:
            raise MappingError(
                MappingErrorCode.INVALID_PROFILE, "the proposed profile does not match the supplied schema"
            )
        return profile


def suggest_mapping(_description: object) -> None:
    """The live message path must not ask a model for a mapping."""
    raise RuntimeError("offline-only")
