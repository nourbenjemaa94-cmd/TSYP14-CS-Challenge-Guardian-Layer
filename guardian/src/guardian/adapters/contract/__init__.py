"""Contract adapter: maps partner payloads to Guardian events (Members 1, 2, 6).

Only runtime names are exported here. ``schema_reader`` and ``ai_mapper`` are
offline helpers and must be imported explicitly, so the live message path
never loads model-related code.
"""

from .errors import MappingError, MappingErrorCode
from .mapper import BATCH_ID_SEPARATOR, GenericMapper, parse_timestamp
from .profile import MappingProfile, load_profile
from .registry import ProfileRecord, ProfileRegistry, ProfileStatus, profile_fingerprint, shape_fingerprint
from .unit_converter import CANONICAL_UNITS, UnitConverter, normalize_unit

__all__ = [
    "BATCH_ID_SEPARATOR",
    "CANONICAL_UNITS",
    "GenericMapper",
    "MappingError",
    "MappingErrorCode",
    "MappingProfile",
    "UnitConverter",
    "load_profile",
    "normalize_unit",
    "parse_timestamp",
    "ProfileRecord",
    "ProfileRegistry",
    "ProfileStatus",
    "profile_fingerprint",
    "shape_fingerprint",
]
