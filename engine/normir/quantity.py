"""Quantities with a length dimension: in, ft, mm, m (length) and sqft, m2 (area)."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from functools import lru_cache

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
    @lru_cache(maxsize=4096)  # rules and evidence repeat the same few literals; a Quantity is immutable
    def parse(text: str) -> Quantity | None:
        m = QUANTITY_RE.match(text)
        if not m:
            return None
        size, dim = UNITS[m.group(2)]
        return Quantity(float(m.group(1)) * size, dim, m.group(2))

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
