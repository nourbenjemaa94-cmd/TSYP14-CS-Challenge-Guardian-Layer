"""Deny-by-default operation permissions.

Stops a layer from calling an operation that belongs to another layer.
Holding a valid key is not enough: the operation must be on that layer's list.
No caller, including an automated agent using one of these identities, receives
containment permissions on the inbound path.
"""

from collections.abc import Mapping

from guardian.security.errors import ReasonCode, SecurityRejection

# Inbound operations each caller may perform. Guardian signs outbound messages
# and the signed operator reset. Unknown layers and unknown operations are denied.
DEFAULT_POLICY: dict[str, frozenset[str]] = {
    "twin": frozenset({"publish_reading", "report_actuator_state", "ack_command"}),
    "brain": frozenset({"request_verdict", "get_device_status", "report_decision"}),
    "guardian": frozenset({"reset_profile"}),
}


def authorize(
    layer: str,
    operation: str,
    policy: Mapping[str, frozenset[str]] | None = None,
) -> None:
    """Raise ``FORBIDDEN`` unless ``layer`` is allowed to perform ``operation``."""
    rules = DEFAULT_POLICY if policy is None else policy
    allowed = rules.get(layer, frozenset())
    if operation not in allowed:
        raise SecurityRejection(
            ReasonCode.FORBIDDEN,
            detail=f"denied layer={layer} operation={operation}",
        )
