"""Deterministic partner-to-canonical mapping.

Protects the gate from treating a rewritten sender as authenticated. The
pipeline asks this mapper to run only after ``admit`` and before ``accept``.

TODO(security): ASSUMPTION — Twin and Brain already send the canonical
envelope, so Phase 1 mapping is the identity function. Replace this class
with the contracts owner's mapper without changing that order. Mapping stays
deterministic: there is no model call on the live path.
"""

import copy
from typing import Any

from guardian.security.errors import ReasonCode, SecurityRejection


class IdentityContractMapper:
    """Returns a deep copy of an already-canonical envelope."""

    def normalize(self, body: dict[str, Any], operation: str) -> dict[str, Any]:
        if not isinstance(operation, str) or not operation:
            raise SecurityRejection(ReasonCode.SCHEMA_INVALID, fields=["operation"])
        if not isinstance(body, dict):
            raise SecurityRejection(ReasonCode.SCHEMA_INVALID, fields=["body"])
        return copy.deepcopy(body)
