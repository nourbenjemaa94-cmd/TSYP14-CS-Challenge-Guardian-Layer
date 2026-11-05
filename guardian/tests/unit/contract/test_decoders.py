"""JSON decoder seam. XML is not on the live path."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from guardian.adapters.communication.base import HandlerResult
from guardian.adapters.communication.rest import RestAdapter
from guardian.adapters.contract.decoders import JsonDecoder, decoder_for
from guardian.security.errors import ReasonCode
from guardian.security.validation import parse_json_object


def test_json_decoder_matches_parse_json_object():
    raw = b'{"event_id":"EVT-1","ok":true}'
    assert JsonDecoder().decode(raw) == parse_json_object(raw)
    assert decoder_for("json").format_id == "json"


def test_xml_content_type_is_rejected_as_format_mismatch():
    adapter = RestAdapter(lambda _message: HandlerResult(True, "ACCEPTED"))
    application = FastAPI()
    application.include_router(adapter.router)
    response = TestClient(application).post(
        "/api/v1/telemetry",
        content=b"<reading/>",
        headers={"content-type": "application/xml"},
    )
    assert response.status_code == 415
    assert response.json()["error"] == ReasonCode.FORMAT_MISMATCH.value
