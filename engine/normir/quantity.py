"""Quantities with a length dimension: in, ft, mm, m (length) and sqft, m2 (area)."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

# unit -> (size in base units, length exponent). Base unit is the inch.
M = 1000 / 25.4
UNITS = {"in": (1.0, 1), "ft": (12.0, 1), "sqft": (144.0, 2), "mm": (M / 1000, 1), "m": (M, 1), "m2": (M * M, 2)}
QUANTITY_RE = re.compile(r"^\s*(-?\d+(?:\.\d+)?)\s*(in|ft|sqft|mm|m2|m)\s*$")


@dataclass(frozen=True)
class Quantity:
    base: float  # value in inch^dim
    dim: int
    unit: str  # unit to display in

    @staticmethod
    def parse(text: str) -> Quantity | None:
        m = QUANTITY_RE.match(text)
        if not m:
            return None
        size, dim = UNITS[m.group(2)]
        return Quantity(float(m.group(1)) * size, dim, m.group(2))

    def _same(self, other: Quantity) -> None:
        if not isinstance(other, Quantity) or other.dim != self.dim:
            raise TypeError(f"cannot combine {self} with {other}")

    def __lt__(self, other):
        self._same(other)
        return self.base < other.base

    def __le__(self, other):
        self._same(other)
        return self.base <= other.base

    def __gt__(self, other):
        self._same(other)
        return self.base > other.base

    def __ge__(self, other):
        self._same(other)
        return self.base >= other.base

    def __eq__(self, other):
        return isinstance(other, Quantity) and other.dim == self.dim and math.isclose(other.base, self.base)

    def __hash__(self):
        return hash((round(self.base, 9), self.dim))

    def __str__(self) -> str:
        v = round(self.base / UNITS[self.unit][0], 4)
        return f"{v:g} {self.unit}"

    __repr__ = __str__


def mul(a, b):
    if isinstance(a, Quantity) and isinstance(b, Quantity):
        raise TypeError("v0 does not multiply two quantities")
    if isinstance(a, Quantity):
        return Quantity(a.base * b, a.dim, a.unit)
    if isinstance(b, Quantity):
        return Quantity(b.base * a, b.dim, b.unit)
    return a * b


def div(a, b):
    if isinstance(a, Quantity) and isinstance(b, Quantity):
        a._same(b)
        return a.base / b.base
    if isinstance(a, Quantity):
        return Quantity(a.base / b, a.dim, a.unit)
    if isinstance(b, Quantity):
        raise TypeError("v0 does not divide a number by a quantity")
    return a / b
