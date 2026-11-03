"""Unit normalisation and conversion for measurements.

Guardian owns the canonical unit per metric (``CANONICAL_UNITS``); a mapping
profile never chooses the target unit (handoff section 6, item 1). Unknown
units and cross-dimension conversions are refused, never guessed.
"""

from __future__ import annotations

import math
from typing import Any

from .errors import MappingError, MappingErrorCode

# Keep in step with core.anomaly_detector.MetricLimits (water_level is checked in cm).
# TODO(guardian-integration): confirm canonical units for the other metrics with
# Members 3 and 4; metrics without an entry keep the partner's (normalised) unit.
CANONICAL_UNITS: dict[str, str] = {
    "water_level": "cm",
}

MAX_UNIT_LENGTH = 16

# Linear dimensions: factor to the dimension's base unit.
_LINEAR: dict[str, dict[str, float]] = {
    "length": {"mm": 0.001, "cm": 0.01, "m": 1.0, "km": 1000.0},
    "pressure": {"Pa": 1.0, "hPa": 100.0, "kPa": 1000.0, "bar": 100_000.0},
    "ratio": {"%": 1.0},
}
_TEMPERATURE = ("C", "F", "K")

# Lower-cased spellings partners use. Symbols are also matched case-insensitively
# as a fallback ("M" -> "m", "KPA" -> "kPa"), per handoff item 13.
_ALIASES: dict[str, str] = {
    "meter": "m", "metre": "m", "meters": "m", "metres": "m",
    "centimeter": "cm", "centimetre": "cm", "centimeters": "cm", "centimetres": "cm",
    "millimeter": "mm", "millimetre": "mm", "millimeters": "mm", "millimetres": "mm",
    "kilometer": "km", "kilometre": "km", "kilometers": "km", "kilometres": "km",
    "celsius": "C", "degc": "C", "deg c": "C", "°c": "C",
    "fahrenheit": "F", "degf": "F", "deg f": "F", "°f": "F",
    "kelvin": "K",
    "percent": "%", "pct": "%",
    "pascal": "Pa", "hectopascal": "hPa", "kilopascal": "kPa",
}

_SYMBOLS: dict[str, str] = {
    symbol: symbol for table in _LINEAR.values() for symbol in table
} | {symbol: symbol for symbol in _TEMPERATURE}
_SYMBOLS_LOWER: dict[str, str] = {symbol.lower(): symbol for symbol in _SYMBOLS}


def normalize_unit(unit: Any) -> str:
    """Return the canonical symbol for ``unit`` or raise ``UNSUPPORTED_UNIT``."""
    if not isinstance(unit, str):
        raise MappingError(MappingErrorCode.UNSUPPORTED_UNIT, "unit must be a string")
    text = unit.strip()
    if not text or len(text) > MAX_UNIT_LENGTH:
        raise MappingError(MappingErrorCode.UNSUPPORTED_UNIT, "unit is empty or too long")
    if text in _SYMBOLS:
        return text
    key = text.lower()
    if key in _SYMBOLS_LOWER:
        return _SYMBOLS_LOWER[key]
    if key in _ALIASES:
        return _ALIASES[key]
    raise MappingError(MappingErrorCode.UNSUPPORTED_UNIT, f"unknown unit {text!r}")


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise MappingError(MappingErrorCode.INVALID_VALUE, "measurement value must be a finite number")
    return float(value)


def _to_celsius(value: float, unit: str) -> float:
    if unit == "C":
        return value
    if unit == "F":
        return (value - 32.0) * 5.0 / 9.0
    return value - 273.15


def _from_celsius(value: float, unit: str) -> float:
    if unit == "C":
        return value
    if unit == "F":
        return value * 9.0 / 5.0 + 32.0
    return value + 273.15


class UnitConverter:
    """Converts between units of the same dimension; refuses everything else."""

    def __init__(self, canonical_units: dict[str, str] | None = None) -> None:
        self.canonical_units = dict(CANONICAL_UNITS if canonical_units is None else canonical_units)
        for metric, unit in self.canonical_units.items():
            normalize_unit(unit)  # fail at startup, not on the first message
            _ = metric

    def convert(self, value: Any, from_unit: str, to_unit: str) -> float:
        number = _number(value)
        src = normalize_unit(from_unit)
        dst = normalize_unit(to_unit)
        if src == dst:
            return number
        if src in _TEMPERATURE and dst in _TEMPERATURE:
            return round(_from_celsius(_to_celsius(number, src), dst), 6)
        for table in _LINEAR.values():
            if src in table and dst in table:
                return round(number * table[src] / table[dst], 6)
        raise MappingError(MappingErrorCode.UNSUPPORTED_UNIT, f"cannot convert {src} to {dst}")

    def to_canonical(self, metric: str, value: Any, unit: str) -> tuple[float, str]:
        """Return ``(value, unit)`` in the metric's canonical unit, or normalised as sent."""
        src = normalize_unit(unit)
        target = self.canonical_units.get(metric)
        if target is None:
            return _number(value), src
        return self.convert(value, src, target), target
