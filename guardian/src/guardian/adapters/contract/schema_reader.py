"""Describes an external (partner) message shape so a profile can be proposed.

Offline only: it is used when an unknown schema appears, never per message.
Transcribed from the team draft; the fingerprint and multi-sample merge are
handoff task 3, and ``$ref``/``oneOf``/``anyOf`` support is a known limitation.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FieldInfo(BaseModel):
    """Description of one field in an external schema."""

    path: str
    data_type: str
    required: bool = False
    description: str | None = None


class SchemaDescription(BaseModel):
    """Simplified description of an external Twin schema."""

    schema_id: str
    fields: list[FieldInfo] = Field(default_factory=list)
    required_fields: list[str] = Field(default_factory=list)
    is_batch: bool = False
    batch_path: str | None = None
    sample_message: dict[str, Any] | None = None


class SchemaReader:
    """Reads JSON-like Twin messages and JSON Schema documents.

    It extracts field names, paths, data types and batch structure.
    """

    def read_sample(self, sample: dict[str, Any], schema_id: str = "inferred-schema") -> SchemaDescription:
        fields: list[FieldInfo] = []
        batch_path: str | None = None

        def inspect(value: Any, path: str) -> None:
            nonlocal batch_path
            if isinstance(value, dict):
                for key, child in value.items():
                    child_path = f"{path}.{key}" if path else f"$.{key}"
                    inspect(child, child_path)
            elif isinstance(value, list):
                if path and batch_path is None:
                    batch_path = path
                if value:
                    inspect(value[0], path + "[*]")
            else:
                fields.append(FieldInfo(path=path, data_type=self._get_type(value)))

        inspect(sample, "$")
        return SchemaDescription(
            schema_id=schema_id,
            fields=fields,
            is_batch=batch_path is not None,
            batch_path=batch_path,
            sample_message=sample,
        )

    def read_json_schema(self, schema: dict[str, Any], schema_id: str = "external-schema") -> SchemaDescription:
        fields: list[FieldInfo] = []
        required_fields: list[str] = []

        def inspect_schema(current_schema: dict[str, Any], path: str) -> None:
            required = current_schema.get("required", [])
            properties = current_schema.get("properties", {})
            for name, definition in properties.items():
                child_path = f"{path}.{name}" if path else f"$.{name}"
                is_required = name in required
                if is_required:
                    required_fields.append(child_path)
                data_type = definition.get("type", "unknown")
                if isinstance(data_type, list):  # e.g. ["number", "null"]
                    data_type = "|".join(str(part) for part in data_type)
                if data_type == "array":
                    items = definition.get("items", {})
                    fields.append(FieldInfo(path=child_path, data_type="array", required=is_required,
                                            description=definition.get("description")))
                    if isinstance(items, dict):
                        inspect_schema(items, child_path + "[*]")
                elif data_type == "object":
                    fields.append(FieldInfo(path=child_path, data_type="object", required=is_required,
                                            description=definition.get("description")))
                    inspect_schema(definition, child_path)
                else:
                    fields.append(FieldInfo(path=child_path, data_type=data_type, required=is_required,
                                            description=definition.get("description")))

        inspect_schema(schema, "$")
        batch_fields = [field for field in fields if field.data_type == "array"]
        batch_path = batch_fields[0].path if batch_fields else None
        return SchemaDescription(
            schema_id=schema_id,
            fields=fields,
            required_fields=required_fields,
            is_batch=batch_path is not None,
            batch_path=batch_path,
        )

    @staticmethod
    def _get_type(value: Any) -> str:
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int):
            return "integer"
        if isinstance(value, float):
            return "number"
        if isinstance(value, str):
            return "string"
        if value is None:
            return "null"
        return "unknown"
