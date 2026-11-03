"""Handoff section 6 items 1 and 13: Guardian-owned canonical units, aliases, refusals."""

import pytest

from guardian.adapters.contract import CANONICAL_UNITS, MappingError, MappingErrorCode, UnitConverter, normalize_unit


@pytest.mark.parametrize(
    ("value", "src", "dst", "expected"),
    [
        (1.8, "m", "cm", 180.0),
        (3.8, "m", "cm", 380.0),
        (1800, "mm", "cm", 180.0),
        (1800, "mm", "m", 1.8),
        (0.4, "m", "mm", 400.0),
        (2, "km", "cm", 200000.0),
        (32, "F", "C", 0.0),
        (300, "K", "C", 26.85),
        (100, "C", "F", 212.0),
        (0, "C", "K", 273.15),
        (1, "kPa", "Pa", 1000.0),
        (1013.25, "hPa", "kPa", 101.325),
        (55, "%", "percent", 55.0),
        (7, "cm", "cm", 7.0),
    ],
)
def test_conversions(value, src, dst, expected):
    assert UnitConverter().convert(value, src, dst) == pytest.approx(expected)


@pytest.mark.parametrize(
    ("spelling", "symbol"),
    [("m", "m"), ("M", "m"), ("meters", "m"), ("Metres", "m"), ("°C", "C"), ("celsius", "C"), ("degC", "C"),
     ("°F", "F"), ("kelvin", "K"), ("KPA", "kPa"), ("percent", "%"), (" cm ", "cm")],
)
def test_aliases(spelling, symbol):
    assert normalize_unit(spelling) == symbol


@pytest.mark.parametrize("bad", ["furlong", "", "x" * 17, 12, None, "m/s"])
def test_unknown_unit(bad):
    with pytest.raises(MappingError) as info:
        normalize_unit(bad)
    assert info.value.code is MappingErrorCode.UNSUPPORTED_UNIT


def test_cross_dimension_refused():
    with pytest.raises(MappingError) as info:
        UnitConverter().convert(1, "m", "kPa")
    assert info.value.code is MappingErrorCode.UNSUPPORTED_UNIT


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), True, "1.8", None])
def test_non_numeric_value(bad):
    with pytest.raises(MappingError) as info:
        UnitConverter().convert(bad, "m", "cm")
    assert info.value.code is MappingErrorCode.INVALID_VALUE


def test_canonical_unit_is_guardians_choice():
    assert CANONICAL_UNITS["water_level"] == "cm"
    assert UnitConverter().to_canonical("water_level", 1.8, "m") == (180.0, "cm")
    assert UnitConverter().to_canonical("water_level", 180, "CM") == (180.0, "cm")


def test_metric_without_canonical_unit_passes_through_normalised():
    assert UnitConverter().to_canonical("power_load", 5, "percent") == (5.0, "%")


def test_custom_table_is_validated_at_startup():
    with pytest.raises(MappingError):
        UnitConverter({"water_level": "fathom"})
