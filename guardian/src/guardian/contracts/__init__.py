"""Payload contracts are owned by the contracts work, not by security.

TODO(security): ASSUMPTION — security checks the shared envelope only.
These names document the interface card. They do not accept or reject
live messages, and they are not consulted on the request path.
"""

INBOUND_TYPES = (
    "sensor_reading",
    "actuator_state",
    "command_ack",
    "verdict_request",
    "device_status_request",
    "decision",
)

OUTBOUND_TYPES = (
    "trust_verdict",
    "device_status",
    "isolation_command",
    "quarantine_command",
    "release_command",
)
