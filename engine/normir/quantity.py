"""Quantities: a number with a unit, compared and scaled within one dimension.

Units are data (UNITS): each has a dimension and its size in that dimension's base unit, and temperature scales an
offset too. Lengths and areas keep the inch as their base, as before. Text is read after Unicode NFKC, so "m²"
is "m2" and "°C" stays "°C"; a decimal comma reads as a point ("1,2 m"), while a comma before exactly three digits
is a thousands separator ("1,200 mm").
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache

M = 1000 / 25.4            # inches per metre
# unit -> (dimension, size in the dimension's base unit, offset). Bases: inch, square inch, litre, second, kelvin,
# kilogram, byte, pascal.
UNITS: dict[str, tuple[str, float, float]] = {
    "in": ("length", 1.0, 0), "ft": ("length", 12.0, 0), "yd": ("length", 36.0, 0), "mi": ("length", 63360.0, 0),
    "mm": ("length", M / 1000, 0), "cm": ("length", M / 100, 0), "m": ("length", M, 0), "km": ("length", M * 1000, 0),
    "sqin": ("area", 1.0, 0), "sqft": ("area", 144.0, 0), "mm2": ("area", (M / 1000) ** 2, 0), "cm2": ("area", (M / 100) ** 2, 0),
    "m2": ("area", M * M, 0), "ha": ("area", M * M * 1e4, 0), "km2": ("area", (M * 1000) ** 2, 0),
    "ml": ("volume", 0.001, 0), "l": ("volume", 1.0, 0), "m3": ("volume", 1000.0, 0), "gal": ("volume", 3.785411784, 0),
    "ms": ("time", 0.001, 0), "s": ("time", 1.0, 0), "min": ("time", 60.0, 0), "h": ("time", 3600.0, 0),
    "day": ("time", 86400.0, 0), "week": ("time", 604800.0, 0), "month": ("time", 2629800.0, 0), "year": ("time", 31557600.0, 0),
    "K": ("temperature", 1.0, 0), "°C": ("temperature", 1.0, 273.15), "°F": ("temperature", 5 / 9, 273.15 - 32 * 5 / 9),
    "g": ("mass", 0.001, 0), "kg": ("mass", 1.0, 0), "tonne": ("mass", 1000.0, 0), "lb": ("mass", 0.45359237, 0),
    "B": ("data", 1.0, 0), "KB": ("data", 1e3, 0), "MB": ("data", 1e6, 0), "GB": ("data", 1e9, 0), "TB": ("data", 1e12, 0),
    "KiB": ("data", 1024.0, 0), "MiB": ("data", 1024.0 ** 2, 0), "GiB": ("data", 1024.0 ** 3, 0),
    "Pa": ("pressure", 1.0, 0), "kPa": ("pressure", 1e3, 0), "MPa": ("pressure", 1e6, 0), "bar": ("pressure", 1e5, 0),
    "psi": ("pressure", 6894.757293168, 0),
}
# other spellings -> the unit above (matched after lowercasing; exact names are tried first)
ALIASES = {
    "inch": "in", "inches": "in", '"': "in", "feet": "ft", "foot": "ft", "'": "ft", "yard": "yd", "yards": "yd", "mile": "mi",
    "miles": "mi", "millimetre": "mm", "millimetres": "mm", "millimeter": "mm", "millimeters": "mm", "centimetre": "cm",
    "centimetres": "cm", "centimeter": "cm", "centimeters": "cm", "metre": "m", "metres": "m", "meter": "m", "meters": "m",
    "kilometre": "km", "kilometres": "km", "kilometer": "km", "kilometers": "km",
    "sq in": "sqin", "sq ft": "sqft", "ft2": "sqft", "in2": "sqin", "sqm": "m2", "sq m": "m2", "square metres": "m2",
    "square meters": "m2", "square feet": "sqft", "hectare": "ha", "hectares": "ha",
    "litre": "l", "litres": "l", "liter": "l", "liters": "l", "millilitre": "ml", "milliliter": "ml", "gallon": "gal", "gallons": "gal",
    "msec": "ms", "millisecond": "ms", "milliseconds": "ms", "sec": "s", "secs": "s", "second": "s", "seconds": "s",
    "mins": "min", "minute": "min", "minutes": "min", "hr": "h", "hrs": "h", "hour": "h", "hours": "h", "d": "day",
    "days": "day", "weeks": "week", "wk": "week", "months": "month", "yr": "year", "yrs": "year", "years": "year",
    "°c": "°C", "c": "°C", "degc": "°C", "℃": "°C", "°f": "°F", "degf": "°F", "℉": "°F", "kelvin": "K", "k": "K",
    "gram": "g", "grams": "g", "kilogram": "kg", "kilograms": "kg", "t": "tonne", "tonnes": "tonne", "lbs": "lb",
    "bytes": "B", "byte": "B", "kb": "KB", "mb": "MB", "gb": "GB", "tb": "TB", "kib": "KiB", "mib": "MiB", "gib": "GiB",
    "pa": "Pa", "kpa": "kPa", "mpa": "MPa",
}
DIMENSIONS = tuple(dict.fromkeys(d for d, _, _ in UNITS.values()))
SAMPLE = {"length": "1 m", "area": "1 m2", "volume": "1 l", "time": "1 s", "temperature": "20 °C", "mass": "1 kg",
          "data": "1 MB", "pressure": "1 kPa"}   # one valid literal per dimension
QUANTITY_RE = re.compile(r"^\s*(-?\d+(?:[.,]\d+)?)\s*(\S.*?)\s*$")


def _unit(text: str) -> str | None:
    if text in UNITS:
        return text
    low = re.sub(r"\s+", " ", text.lower())
    return ALIASES.get(low) or next((u for u in UNITS if u.lower() == low), None)


@dataclass(frozen=True)
class Quantity:
    base: float  # value in the dimension's base unit (inch^n for lengths and areas, kelvin for temperature, ...)
    dim: str     # a DIMENSIONS name
    unit: str    # unit to display in

    @staticmethod
    @lru_cache(maxsize=8192)  # rules and evidence repeat the same few literals; a Quantity is immutable
    def parse(text: str) -> Quantity | None:
        m = QUANTITY_RE.match(unicodedata.normalize("NFKC", text)) if isinstance(text, str) else None
        if not m:
            return None
        u = _unit(m.group(2))
        if u is None:
            return None
        num = m.group(1)
        if "," in num:   # 1,200 is a thousands separator; 1,2 and 1,25 are decimal commas
            whole, frac = num.split(",")
            num = whole + frac if len(frac) == 3 else f"{whole}.{frac}"
        dim, size, offset = UNITS[u]
        return Quantity(float(num) * size + offset, dim, u)

    def _same(self, other: Quantity) -> None:
        if not isinstance(other, Quantity) or other.dim != self.dim:
            raise TypeError(f"cannot combine {self} with {other}")

    # One tolerance for every comparison: 812.8 mm is exactly 32 in, but the two conversions differ in the last
    # bits of a float, and a value at a limit must pass whichever units the drawing and the code use.
    def _close(self, other: Quantity) -> bool:
        return math.isclose(other.base, self.base, rel_tol=1e-9, abs_tol=1e-12)

    def __lt__(self, other):
        self._same(other)
        return self.base < other.base and not self._close(other)

    def __le__(self, other):
        self._same(other)
        return self.base < other.base or self._close(other)

    def __gt__(self, other):
        self._same(other)
        return self.base > other.base and not self._close(other)

    def __ge__(self, other):
        self._same(other)
        return self.base > other.base or self._close(other)

    def __eq__(self, other):
        return isinstance(other, Quantity) and other.dim == self.dim and self._close(other)

    def __hash__(self):
        return hash(self.dim)  # equal quantities must hash alike, and equality has a tolerance

    def __str__(self) -> str:
        _, size, offset = UNITS[self.unit]
        v = round((self.base - offset) / size, 4)
        return f"{v:g} {self.unit}"

    __repr__ = __str__


def _scalable(q: Quantity) -> None:
    if UNITS[q.unit][2]:
        raise TypeError(f"cannot scale {q}: a temperature on an offset scale is not a multiple of anything")


def mul(a, b):
    if isinstance(a, Quantity) and isinstance(b, Quantity):
        raise TypeError("v0 does not multiply two quantities")
    if isinstance(a, Quantity):
        _scalable(a)
        return Quantity(a.base * b, a.dim, a.unit)
    if isinstance(b, Quantity):
        _scalable(b)
        return Quantity(b.base * a, b.dim, b.unit)
    return a * b


def div(a, b):
    if isinstance(a, Quantity) and isinstance(b, Quantity):
        a._same(b)
        return a.base / b.base
    if isinstance(a, Quantity):
        _scalable(a)
        return Quantity(a.base / b, a.dim, a.unit)
    if isinstance(b, Quantity):
        raise TypeError("v0 does not divide a number by a quantity")
    return a / b
