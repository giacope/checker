"""IFC adapter: an IFC model in, an evidence document in the BIM vocabulary (vocab/bim.yaml) out.

uv run python -m adapters.ifc <model.ifc> -o <out.yaml>

Works on IFC2X3 and IFC4 from any authoring tool. Standard property sets and base
quantities are read first (Pset_DoorCommon, Pset_StairCommon, Pset_StairFlightCommon,
Pset_SpaceCommon, Qto_*BaseQuantities, the IfcDoor/IfcStairFlight attributes, spatial
containment); authoring-tool property sets (Revit's PSet_Revit_*, ArchiCAD's) only
when the standard ones are absent. Lengths are converted from the file's
IfcUnitAssignment. Travel distances come from the geometry (adapters/ifc_egress.py).

Deterministic, and it never guesses: a value the model does not carry is left out.
Where the model gives only a proxy (a door's leaf width rather than its clear
opening), the fact is the interval the proxy allows, as two observations.
"""

from __future__ import annotations

import argparse
import math
import re
import sys
import time
from pathlib import Path

import ifcopenshell
import ifcopenshell.util.element as E
import ifcopenshell.util.placement as P
import ifcopenshell.util.unit as U
import numpy as np
import yaml
from normir.quantity import Quantity
from shapely.ops import unary_union

from adapters import ifc_egress as G

VERSION = "0.2.0"
# A model's or drawing's length unit is plausible from 1 mm to 1 m (mm, cm, dm, m, in, ft, yd): a unit outside it
# (EXAMETRE, a conversion factor of 0, a microinch) is not one buildings are modelled or drawn in. adapters/dxf.py too.
UNIT_M = (1e-3, 1.0)
# IfcLocalPlacement chains are a few levels deep (site, building, storey, element); a deeper one is read as broken.
MAX_PLACEMENT_DEPTH = 64
# 404.2.3-style clear width: face of the open leaf to the stop. Leaf thickness and
# stop take 44 to 64 mm off the leaf width for the hinged doors in common libraries.
CLEAR_WIDTH_DEDUCTION_MM = (44, 64)
FOOT = 0.3048

# Space roles, from the space's name (Name, LongName, or a name property), in the languages of the test models.
STAIR_RE = re.compile(r"\b(stair|stairs|stairway|staircase|stairwell)\b|treppe|stiege|escalier|escalera|scala\b|階段", re.I)
CORRIDOR_RE = re.compile(r"\b(corridor|corr\.|hallway|hall|passage|circulation)\b|\bgang\b|\bflur\b|korridor|couloir|pasillo|廊下", re.I)
# Not floor anyone walks on: voids, shafts, lift cars, roofs.
VOID_RE = re.compile(r"open to below|\bvoid\b|shaft|schacht|luftraum|^\s*(elev|elevator|lift|aufzug)\.?\s*$|^\s*roof\s*$", re.I)
GUID_RE = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
MARK_IN_NAME_RE = re.compile(r"^[A-Za-zÄÖÜäöü]{0,4}[-. ]?\d{1,4}[A-Za-z]?$")
MARK_PROPS = ("mark", "doormark", "door mark", "doornumber", "door number", "iddoor", "number")
NUMBER_PROPS = ("number", "spacenumber", "roomnumber", "room number")
NAME_PROPS = ("name", "spacename", "roomname")
EMPTY = {"", "nd", "n/a", "na", "-", "--", "tbd"}

LEAVES_BY_OPERATION = {
    "SINGLE_SWING_LEFT": 1, "SINGLE_SWING_RIGHT": 1, "DOUBLE_SWING_LEFT": 1, "DOUBLE_SWING_RIGHT": 1,
    "SLIDING_TO_LEFT": 1, "SLIDING_TO_RIGHT": 1, "FOLDING_TO_LEFT": 1, "FOLDING_TO_RIGHT": 1,
    "SWING_FIXED_LEFT": 1, "SWING_FIXED_RIGHT": 1, "ROLLINGUP": 1, "LIFTING_VERTICAL_LEFT": 1, "LIFTING_VERTICAL_RIGHT": 1,
    "DOUBLE_DOOR_SINGLE_SWING": 2, "DOUBLE_DOOR_SINGLE_SWING_OPPOSITE_LEFT": 2, "DOUBLE_DOOR_SINGLE_SWING_OPPOSITE_RIGHT": 2,
    "DOUBLE_DOOR_DOUBLE_SWING": 2, "DOUBLE_DOOR_SLIDING": 2, "DOUBLE_DOOR_FOLDING": 2, "DOUBLE_DOOR_LIFTING_VERTICAL": 2,
}
SWINGING = {k for k in LEAVES_BY_OPERATION if "SWING" in k}

TRAVEL_ASSUMPTIONS = [
    "walkable floor: the bottom faces of the storey's IfcSpace solids, plus door passages, plus stair footprints, minus IfcColumn "
    "footprints; walls bound the spaces and are not read; furniture and fixtures are ignored",
    "spaces named as voids, shafts, lifts or roofs (open to below, shaft, Schacht, elevator, Aufzug, roof) and spaces with "
    "Pset_SpaceCommon.IsExternal true (balconies, terraces) are not walkable",
    f"a door is passable over its opening's plan footprint (the IfcOpeningElement it fills, else the door body), extended "
    f"{G.EXTEND} m into the rooms on both sides; spaces closer than {2 * G.CLOSE_GAP} m are joined (room separation lines)",
    "exits on the storey at grade: doors with Pset_DoorCommon.IsExternal true (where it is not set: a door with a room on one "
    "side only); travel is measured to the door's opening",
    "exits on other storeys: stair enclosures, i.e. IfcStair footprints serving the storey, spaces named as stairs, and spaces "
    "with Pset_SpaceFireSafetyRequirements.FireExit true; travel is measured to the door into the enclosure, or to the "
    "enclosure itself where no door separates it",
    f"path: geodesic inside the walkable floor; Dijkstra on a {G.RESOLUTION} m grid with 16 move directions (coarser only "
    f"above {G.MAX_CELLS} cells a storey) to the two nearest exits, then the paths from the {G.CANDIDATES} farthest cells of "
    "each space are string-pulled against the floor polygon, their bends moved onto the floor's corners and their ends onto "
    "the exit; the longest of these is reported, measured from the space's corner where the farthest cell lies in one",
    "the space's farthest point is searched among grid cells, so a farther point between cells can be missed by up to a "
    "cell; where two exits are within 3 % of each other both are tried",
    "the grade storey is the lowest with Pset_BuildingStoreyCommon.AboveGround true, else the one nearest elevation 0; a level "
    "counts as a storey when it has a walkable space and a door",
    "travel distance is horizontal: on the grade storey it ends at an exterior door, elsewhere at the stair enclosure, so "
    "travel down the stair is not included",
]


# ----------------------------------------------------------------- reading helpers

def _obs(value, at, note=None):
    o = {"value": value, "at": at}
    if note:
        o["note"] = note
    return [o]


def _num(x: float, nd: int = 1) -> str:
    s = f"{x:.{nd}f}"
    s = s.rstrip("0").rstrip(".") if "." in s else s
    return "0" if s == "-0" else s


def _mm(m: float) -> str:
    return f"{_num(m * 1000, 1)} mm"


def _m(m: float, nd: int = 2) -> str:
    return f"{_num(m, nd)} m"


def _m2(a: float, nd: int = 2) -> str:
    return f"{_num(a, nd)} m2"


# ----------------------------------------------------------------- plausible sizes (vocab/bim.yaml `range`)

def _ranges() -> dict[tuple[str, str], tuple]:
    """(type, attr) -> (attribute type, lo, hi, as written) for the vocabulary's attributes with a range; lengths and
    areas in Quantity base units."""
    vocab = yaml.safe_load((Path(__file__).resolve().parents[1] / "vocab" / "bim.yaml").read_text())
    out = {}
    for t, td in vocab["types"].items():
        for a, spec in (td.get("attrs") or {}).items():
            if "range" in spec:
                lo, hi = spec["range"]
                if spec["type"] in ("length", "area"):
                    lo, hi = Quantity.parse(lo).base, Quantity.parse(hi).base
                out[(t, a)] = (spec["type"], lo, hi, f"{spec['range'][0]} to {spec['range'][1]}")
    return out


RANGES = _ranges()


def implausible(type_: str, attr: str, value) -> str | None:
    """Why an observed value of type_.attr is not one a building can have, or None: not a finite quantity of the
    attribute's kind, or outside its plausible range (vocab/bim.yaml). The rule both readers apply to what they emit."""
    r = RANGES.get((type_, attr))
    if r is None:
        return None
    kind, lo, hi, written = r
    if kind in ("length", "area"):
        q = Quantity.parse(value) if isinstance(value, str) else None
        if q is None or q.dim != kind:
            return f"not a readable {kind}"
        v = q.base
    elif isinstance(value, bool) or not isinstance(value, (int, float)):
        return "not a number"
    else:
        v = value
    if not math.isfinite(v):
        return "not a finite number"
    if not lo <= v <= hi:
        return f"outside the plausible range of {type_}.{attr} ({written})"
    return None


def drop_implausible(facts: dict, elements: list[dict], skipped: list[str], subject: str = "building") -> None:
    """Remove the implausible observations (implausible()) from a reader's subject facts and elements, in place, each
    listed in `skipped` with its reason. An interval's two observations share their `at`, and go together."""
    def check(type_: str, label: str, fs: dict) -> None:
        for attr in list(fs):
            obs = fs[attr] if isinstance(fs[attr], list) else []
            bad = {}
            for o in obs:
                why = implausible(type_, attr, o.get("value")) if isinstance(o, dict) else None
                if why and str(o.get("at")) not in bad:
                    bad[str(o.get("at"))] = (o.get("value"), why)
            if not bad:
                continue
            fs[attr] = [o for o in obs if not (isinstance(o, dict) and str(o.get("at")) in bad)]
            for at, (v, why) in bad.items():
                skipped.append(f"{label} {attr} {str(v)[:60]} ({at}): {why}: not read")
            if not fs[attr]:
                del fs[attr]

    check(subject, subject, facts)
    for e in elements:
        check(e.get("type"), f"{e.get('type')} {e.get('id')}", e.get("facts") or {})


# ----------------------------------------------------------------- units, relationships, placements

def _is(v, cls: str) -> bool:
    """v is an entity instance of class cls (a damaged model may hold a number, a boolean or another entity where a
    reference belongs)."""
    return isinstance(v, ifcopenshell.entity_instance) and v.is_a(cls)


def _unit_scale(f: ifcopenshell.file, unit_type: str) -> tuple[float | None, str, str | None]:
    """(scale to SI, the unit as written, None) for the project's unit of this type, or (None, ..., why) where the model
    has none (a missing or dangling IfcUnitAssignment or unit), the unit is malformed (no name, a conversion that does
    not end in an SI unit, a cycle), or its scale is not a positive finite number."""
    projects = f.by_type("IfcProject")
    ua = projects[0].UnitsInContext if projects else None
    if not _is(ua, "IfcUnitAssignment"):
        return None, "", "the model has no IfcUnitAssignment"
    units = [u for u in (ua.Units if isinstance(ua.Units, (tuple, list)) else ()) if isinstance(u, ifcopenshell.entity_instance)
             and getattr(u, "UnitType", None) == unit_type]
    if not units:
        return None, "", f"its IfcUnitAssignment has no {unit_type}"
    scales, names = set(), []
    for u in units:
        names.append(f"{getattr(u, 'Prefix', None) or ''}{getattr(u, 'Name', None) or ''}".lower() or u.is_a())
        x, seen = u, set()
        while _is(x, "IfcConversionBasedUnit") and x.id() not in seen and len(seen) < 8:
            seen.add(x.id())
            cf = x.ConversionFactor
            x = cf.UnitComponent if _is(cf, "IfcMeasureWithUnit") else None
        if not _is(x, "IfcSIUnit") or not isinstance(x.Name, str):
            return None, names[-1], f"{unit_type} #{u.id()} does not resolve to an SI unit"
        try:
            s = U.get_unit_scale(u)
        except Exception as e:  # noqa: BLE001 - a malformed conversion factor or prefix
            return None, names[-1], f"{unit_type} #{u.id()} is malformed ({type(e).__name__}: {e})"
        if isinstance(s, bool) or not isinstance(s, (int, float)) or not math.isfinite(s) or s <= 0:
            return None, names[-1], f"{unit_type} #{u.id()} scales by {s!r}, not a positive finite number"
        scales.add(float(s))
    if len(scales) > 1:
        return None, ", ".join(names), f"the model gives {len(scales)} different {unit_type}s"
    return scales.pop(), names[0], None


# The entity types the reader reads attributes of (their names, placements, sizes, shapes).
READ_TYPES = ("IfcProject", "IfcBuilding", "IfcBuildingStorey", "IfcSpace", "IfcDoor", "IfcDoorType", "IfcDoorStyle", "IfcStair",
              "IfcStairFlight", "IfcRamp", "IfcRampFlight", "IfcColumn", "IfcRoof", "IfcSlab", "IfcCovering", "IfcOpeningElement")


def _attr_kind(t) -> tuple:
    """(kind, name, many) of an attribute's declared type: kind 'entity' (name: the entity), 'text' (a string or an
    enumeration), or None (numbers, selects: read elsewhere, or not checked)."""
    many = False
    for _ in range(10):
        if t.as_aggregation_type() is not None:
            t, many = t.as_aggregation_type().type_of_element(), True
            continue
        nt = t.as_named_type()
        if nt is not None:
            d = nt.declared_type()
            if d.as_entity() is not None:
                return "entity", d.name(), many
            if d.as_enumeration_type() is not None:
                return "text", d.name(), many
            if d.as_select_type() is not None:
                return None, None, many
            t = d.declared_type()
            continue
        st = t.as_simple_type()
        return ("text" if st is not None and st.declared_type() == "string" else None), None, many
    return None, None, many


def _ill_typed(f: ifcopenshell.file) -> list[str]:
    """Repair the model where an attribute holds a value of another type than the schema declares, and describe each
    repair: a relationship relating an instance of the wrong type (an IfcRelAggregates relating an
    IfcProductDefinitionShape, on which ifcopenshell.geom's iterator crashes) is removed; on the elements the reader
    reads (READ_TYPES), such an attribute (an entity where a name belongs, a shape where a placement belongs) is
    cleared, so it is read as absent. Numbers are checked where they are read (Model.num)."""
    schema = ifcopenshell.ifcopenshell_wrapper.schema_by_name(f.schema_identifier)
    checks: dict[str, list] = {}

    def wrong(e) -> tuple | None:
        name = e.is_a()
        if name not in checks:
            checks[name] = [(i, a.name(), a.optional(), *_attr_kind(a.type_of_attribute()))
                            for i, a in enumerate(schema.declaration_by_name(name).as_entity().all_attributes())]
        for i, attr, optional, kind, want, many in checks[name]:
            if kind is None:
                continue
            v = e[i]
            for x in ((v or ()) if many and isinstance(v, (tuple, list)) else (v,)):
                if x is None:
                    continue
                if kind == "entity" and not (isinstance(x, ifcopenshell.entity_instance) and x.is_a(want)):
                    got = f"{x.is_a()} #{x.id()}" if isinstance(x, ifcopenshell.entity_instance) else repr(x)[:40]
                    return attr, optional, f"{got} as {attr}, where the schema requires an {want}"
                if kind == "text" and not isinstance(x, str):
                    got = f"{x.is_a()} #{x.id()}" if isinstance(x, ifcopenshell.entity_instance) else repr(x)[:40]
                    return attr, optional, f"{got} as {attr}, where the schema requires text"
        return None

    out = []
    bad = [(r, w) for r in f.by_type("IfcRelationship") for w in [wrong(r)] if w is not None]
    for r, (_, _, why) in bad:
        out.append(f"{r.is_a()} #{r.id()} has {why}: relationship not read")
        f.remove(r)
    for t in READ_TYPES:
        try:
            es = f.by_type(t)
        except RuntimeError:   # a type the file's schema does not have
            continue
        for e in es:
            for _ in range(len(checks.get(e.is_a(), ())) + 20):
                w = wrong(e)
                if w is None:
                    break
                attr, optional, why = w
                out.append(f"{e.is_a()} #{e.id()} has {why}: {attr} not read")
                try:   # a GlobalId stays a distinct id for locators
                    setattr(e, attr, f"#{e.id()}" if attr == "GlobalId" else None)
                except Exception:  # noqa: BLE001 - a required attribute ifcopenshell will not clear
                    break
    return list(dict.fromkeys(out))


def _real(v, prop: str):
    """A property value, or None for an empty one and for authoring placeholders (Revit writes 'Fire Rating' for an unset Fire Rating)."""
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        if s.lower() in EMPTY or s.lower().replace(" ", "") == prop.lower().replace(" ", ""):
            return None
        return s
    return v


class Model:
    """The model, with its units and placements resolved once, guarded: what cannot be read is None, and why is
    listed in `skipped` (the source's skipped list)."""

    def __init__(self, f: ifcopenshell.file):
        self.f = f
        self.skipped: list[str] = _ill_typed(f)
        self.length, self.length_name, why = _unit_scale(f, "LENGTHUNIT")
        if self.length is not None and not UNIT_M[0] * (1 - 1e-9) <= self.length <= UNIT_M[1] * (1 + 1e-9):
            why = f"length unit {self.length_name} ({self.length:g} m) is not one buildings are modelled in ({UNIT_M[0]:g} to {UNIT_M[1]:g} m)"
            self.length = None
        self.unit_problem = why   # no lengths, and no geometry (ifcopenshell.geom would read it in that unit too)
        area, _, why_area = _unit_scale(f, "AREAUNIT")
        if area is None and why_area.startswith("its IfcUnitAssignment has no"):
            area, why_area = (self.length ** 2, None) if self.length is not None else (None, why_area)  # no area unit: the length unit's square
        elif area is not None and not (UNIT_M[0] ** 2) * (1 - 1e-9) <= area <= (UNIT_M[1] ** 2) * (1 + 1e-9):
            area, why_area = None, f"area unit ({area:g} m2) is not one buildings are modelled in"
        self.area = area
        self.area_problem = why_area if area is None else None
        self.angle, _, why_angle = _unit_scale(f, "PLANEANGLEUNIT")
        if self.angle is None and why_angle.startswith(("the model has no", "its IfcUnitAssignment has no")):
            self.angle = 1.0   # IFC's default plane angle unit is the radian (ifcopenshell's calculate_unit_scale)
        self._ps: dict[int, dict] = {}
        self._pl: dict[int, tuple] = {}

    def psets(self, e) -> dict:
        if e.id() not in self._ps:
            self._ps[e.id()] = E.get_psets(e)
        return self._ps[e.id()]

    def prop(self, e, pset: str, prop: str):
        return _real(self.psets(e).get(pset, {}).get(prop), prop)

    def find(self, e, names: tuple, skip: tuple = ()) -> tuple:
        """(value, 'Pset.Prop') of the first property with one of these names (case-insensitive) in any property set."""
        want = {n.lower() for n in names}
        for ps, props in self.psets(e).items():
            if ps in skip:
                continue
            for k, v in props.items():
                if k != "id" and k.lower() in want and not isinstance(v, dict):
                    v = _real(v, k)
                    if v is not None:
                        return v, f"{ps}.{k}"
        return None, None

    def num(self, v, at: str) -> float | None:
        """A number from the model, or None: absent, or (listed in skipped) not a finite number (text where a length
        belongs, 1.E400)."""
        if v is None:
            return None
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            self.skipped.append(f"{at}: {str(v)[:60]!r} is not a number: not read")
            return None
        if not math.isfinite(v):
            self.skipped.append(f"{at}: {v} is not a finite number: not read")
            return None
        return float(v)

    def metres(self, v, at: str) -> float | None:
        """A length in the model's unit, in metres; None where num() is, or the model's length unit is not known."""
        v = self.num(v, at)
        return v * self.length if v is not None and self.length is not None else None

    def square_metres(self, v, at: str) -> float | None:
        v = self.num(v, at)
        return v * self.area if v is not None and self.area is not None else None

    def plausible(self, type_: str, attr: str, value: str, at: str) -> bool:
        """implausible(), for a value read to derive others from: False, and listed in skipped, where it is not."""
        why = implausible(type_, attr, value)
        if why:
            self.skipped.append(f"{at}: {type_}.{attr} {value[:60]}: {why}: not read")
        return why is None

    def storey_of(self, e):
        c = E.get_container(e) or E.get_aggregate(e)
        for _ in range(6):
            if c is None or c.is_a("IfcBuildingStorey"):
                return c
            c = E.get_container(c) or E.get_aggregate(c)
        return None

    def placement(self, p) -> tuple[np.ndarray | None, str | None]:
        """(4x4 matrix in the model's unit, None) of an IfcObjectPlacement, or (None, why) where it cannot be read: a
        cycle or a chain deeper than MAX_PLACEMENT_DEPTH, a placement other than IfcLocalPlacement, a missing or wrongly
        typed RelativePlacement, a point or direction of the wrong size, parallel axes, or a number that is not finite."""
        if not isinstance(p, ifcopenshell.entity_instance):
            return None, f"placement {str(p)[:40]!r} cannot be read (not an entity)"
        if p.id() in self._pl:
            return self._pl[p.id()]
        why, x, seen = None, p, set()
        while x is not None and why is None:
            if not isinstance(x, ifcopenshell.entity_instance):
                why = f"PlacementRelTo is {str(x)[:40]!r}, not an entity"
            elif x.id() in seen:
                why = f"placement cycle through #{x.id()}"
            elif len(seen) >= MAX_PLACEMENT_DEPTH:
                why = f"placement chain deeper than {MAX_PLACEMENT_DEPTH}"
            elif not (x.is_a("IfcLocalPlacement") or x.is_a("IfcLinearPlacement")):
                why = f"#{x.id()} is an {x.is_a()}, not an IfcLocalPlacement"
            else:
                seen.add(x.id())
                why = _axis_problem(x.RelativePlacement)
                x = x.PlacementRelTo
        mat = None
        if why is None:
            try:
                mat = np.asarray(P.get_local_placement(p), dtype=float)
            except Exception as e:  # noqa: BLE001 - a structure the checks above do not foresee
                why = f"{type(e).__name__}: {e}"
            if mat is not None and (mat.shape != (4, 4) or not np.isfinite(mat).all()):
                mat, why = None, "its matrix is not finite"
        self._pl[p.id()] = (mat, f"placement #{p.id()} cannot be read ({why})" if why else None)
        return self._pl[p.id()]

    def meshes(self, elements: list) -> dict:
        """ifc_egress.meshes of the elements whose placement can be read (placement()): ifcopenshell.geom crashes on a
        placement cycle, and reads the model's length unit, so nothing is triangulated where that is not known."""
        if self.length is None:
            return {}
        ok = []
        for e in elements:
            p = getattr(e, "ObjectPlacement", None)
            why = self.placement(p)[1] if p is not None else None
            if why:
                self.skipped.append(f"{e.is_a()} {getattr(e, 'GlobalId', e.id())}: {why}: its geometry not read")
            else:
                ok.append(e)
        return G.meshes(self.f, ok)

    def z(self, e) -> tuple[float | None, str | None]:
        """(height of the element's placement in metres, None), or (None, why)."""
        if self.length is None:
            return None, f"length unit not known ({self.unit_problem})"
        if e.ObjectPlacement is None:
            return 0.0, None
        mat, why = self.placement(e.ObjectPlacement)
        return (float(mat[2, 3]) * self.length, None) if mat is not None else (None, why)


def _axis_problem(a) -> str | None:
    """Why an IfcAxis2Placement cannot be read, or None."""
    if not isinstance(a, ifcopenshell.entity_instance) or a.is_a() not in ("IfcAxis2Placement3D", "IfcAxis2Placement2D", "IfcAxis2PlacementLinear"):
        what = "missing" if a is None else f"an {a.is_a()}" if isinstance(a, ifcopenshell.entity_instance) else repr(a)[:40]
        return f"RelativePlacement is {what}, not an IfcAxis2Placement3D or 2D"
    n = 2 if a.is_a("IfcAxis2Placement2D") else 3

    def vec(v, kind: str, sizes: tuple) -> tuple[np.ndarray | None, str | None]:
        attr = "Coordinates" if kind == "IfcCartesianPoint" else "DirectionRatios"
        if not _is(v, kind):
            what = f"an {v.is_a()}" if isinstance(v, ifcopenshell.entity_instance) else repr(v)[:40]
            return None, f"#{a.id()} has {what} where an {kind} belongs"
        c = getattr(v, attr)
        if not isinstance(c, (tuple, list)) or len(c) not in sizes or not all(
                isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) for x in c):
            return None, f"{kind} #{v.id()} {c!r} is not {' or '.join(map(str, sizes))} finite numbers"
        return np.asarray(list(c) + [0.0] * (3 - len(c)), dtype=float), None

    loc = a.Location
    if not isinstance(loc, ifcopenshell.entity_instance):
        return f"#{a.id()} has no Location"
    if not a.is_a("IfcAxis2PlacementLinear"):   # a linear placement's Location is a point along an alignment
        _, why = vec(loc, "IfcCartesianPoint", (n,))
        if why:
            return why
    axes = []
    for attr in (("Axis", "RefDirection") if n == 3 else ("RefDirection",)):
        v = getattr(a, attr)
        if v is not None:
            d, why = vec(v, "IfcDirection", (3,) if n == 3 else (2, 3))
            if why:
                return why
            if np.linalg.norm(d) < 1e-12:
                return f"{attr} #{v.id()} has length 0"
            axes.append(d)
    if len(axes) == 2 and np.linalg.norm(np.cross(axes[0] / np.linalg.norm(axes[0]), axes[1] / np.linalg.norm(axes[1]))) < 1e-9:
        return f"#{a.id()} has parallel Axis and RefDirection"
    return None


def _mark(m: Model, e, extra_props: tuple = MARK_PROPS) -> tuple:
    """(mark, where): the Tag, else a mark property, else a Name that looks like a mark."""
    name = e.Name or ""
    tag = (getattr(e, "Tag", None) or "").strip()
    revit_id = re.search(r":(\d+)$", name)
    if tag and not GUID_RE.match(tag) and not (revit_id and revit_id.group(1) == tag) and not re.fullmatch(r"\d{5,}", tag):
        return tag, "Tag"
    v, where = m.find(e, extra_props)
    if v is not None:
        return str(v), where
    if MARK_IN_NAME_RE.match(name.strip()):
        return name.strip(), "Name"
    return None, None


def _plain_name(e) -> str | None:
    """A name as people write it ("Stair 1"), not an authoring tool's family:type:id."""
    name = (e.Name or "").strip()
    return name if name and ":" not in name and len(name) <= 24 else None


def _ids(kind: str, marks: dict) -> dict:
    """Vocabulary ids (door:<mark>) for unique marks; elements whose mark repeats keep their GlobalId."""
    seen: dict[str, int] = {}
    for mk in marks.values():
        if mk:
            seen[mk] = seen.get(mk, 0) + 1
    return {gid: (f"{kind}:{mk}" if mk and seen[mk] == 1 else gid) for gid, mk in marks.items()}


# ----------------------------------------------------------------- the adapter

# Schemas ifcopenshell has no definition for, read with the released schema that superseded them.
SUCCESSOR = {"IFC4X1": "IFC4X3_ADD2", "IFC4X2": "IFC4X3_ADD2", "IFC4X3": "IFC4X3_ADD2", "IFC4X3_RC1": "IFC4X3_ADD2",
             "IFC4X3_RC2": "IFC4X3_ADD2", "IFC4X3_RC3": "IFC4X3_ADD2", "IFC4X3_RC4": "IFC4X3_ADD2", "IFC4X3_ADD1": "IFC4X3_ADD2"}


def _open(path: Path, notes: list[str]):
    """The model; one in a draft or superseded schema is read as its successor, with a note saying so."""
    try:
        return ifcopenshell.open(str(path))
    except Exception as e:  # noqa: BLE001 - ifcopenshell raises a SchemaError of its own module
        head = path.read_bytes()[:20_000]
        m = re.search(rb"FILE_SCHEMA\s*\(\s*\(\s*'([A-Za-z0-9_]+)'", head)
        schema = m[1].decode().upper() if m else None
        if "schema" not in str(e).lower() or schema not in SUCCESSOR:
            raise
        data = path.read_bytes()
        f = ifcopenshell.file.from_string(data.replace(m[0], m[0].replace(m[1], SUCCESSOR[schema].encode()), 1).decode("utf-8", "replace"))
        notes.append(f"{path.name}: schema {schema} is not supported; read as {SUCCESSOR[schema]}, which superseded it")
        return f


def analyse(path: str | Path, describes: str | None = None, progress=lambda msg: None) -> dict:
    """Read an IFC model into one evidence document."""
    t_all = time.time()
    timings: dict[str, float] = {}
    path = Path(path)
    t = time.time()
    progress(f"Opening {path.name}")
    notes: list[str] = []
    f = _open(path, notes)
    m = Model(f)
    timings["open"] = round(time.time() - t, 2)
    skipped = m.skipped
    if m.length is None:
        skipped.append(f"{path.name}: length unit not known ({m.unit_problem}): no lengths, geometry or travel distances read")
    elif m.area is None:
        skipped.append(f"{path.name}: area unit not known ({m.area_problem}): no areas from properties read")
    if m.angle is None:
        skipped.append(f"{path.name}: plane angle unit not known: no ramp slopes from properties read")
    if not f.by_type("IfcBuildingStorey"):
        facilities = sorted({e.is_a() for e in f.by_type("IfcSpatialStructureElement")} - {"IfcSite", "IfcBuilding"}) \
            if f.schema != "IFC2X3" else []
        notes.append(f"{path.name}: no building storeys" + (f" (it models {', '.join(facilities)})" if facilities else "")
                     + "; its storeys, spaces, doors, stairs and travel distances could not be read")

    # ---------------------------------------------------- storeys
    elev, elev_at, world_z = {}, {}, {}   # metres, or None where the model gives no readable, plausible value
    for s in f.by_type("IfcBuildingStorey"):
        loc = f"ifc:{s.GlobalId}"
        z, why = m.z(s)
        if why and m.length is not None:
            skipped.append(f"storey {s.Name} ({loc}): {why}")
        if z is not None and not m.plausible("Storey", "elevation", _m(z, 3), f"{loc} ObjectPlacement"):
            z = None
        e, e_at = m.metres(s.Elevation, f"{loc} Elevation"), "Elevation"
        if e is not None and not m.plausible("Storey", "elevation", _m(e, 3), f"{loc} Elevation"):
            e = None
        if e is None:
            e, e_at = z, "ObjectPlacement"
        elev[s.id()], elev_at[s.id()], world_z[s.id()] = e, e_at, z
    storeys = sorted(f.by_type("IfcBuildingStorey"), key=lambda s: (elev[s.id()] is None, elev[s.id()] or 0.0))
    by_name = {s.Name: s for s in storeys}
    storey_ids = _ids("storey", {s.GlobalId: s.Name for s in storeys})

    # ---------------------------------------------------- spaces
    t = time.time()
    progress("Reading spaces, doors and stairs")
    spaces = f.by_type("IfcSpace")
    space_info = {}
    for s in spaces:
        num_v, num_at = m.find(s, NUMBER_PROPS)
        nm_v, nm_at = m.find(s, NAME_PROPS)
        if s.LongName:
            name, name_at = s.LongName, "LongName"
            number, number_at = (s.Name, "Name") if s.Name else (num_v, num_at)
        elif nm_v:
            name, name_at = nm_v, nm_at
            number, number_at = (s.Name, "Name") if s.Name and s.Name != nm_v else (num_v, num_at)
        else:
            name, name_at = s.Name, "Name"
            number, number_at = num_v, num_at
        st = m.storey_of(s)
        texts = " ".join(str(x) for x in (name, s.Name, s.LongName) if x)
        category = " ".join(str(v) for ps in m.psets(s).values() for k, v in ps.items() if k in ("OmniClass Table 13 Category", "Category Description", "Category"))
        external = m.prop(s, "Pset_SpaceCommon", "IsExternal")
        fire_exit = m.prop(s, "Pset_SpaceFireSafetyRequirements", "FireExit")
        space_info[s.GlobalId] = dict(
            e=s, name=name, name_at=name_at, number=str(number) if number is not None else None, number_at=number_at, storey=st,
            void=bool(VOID_RE.search(name or "") or VOID_RE.search(s.LongName or "")), external=external is True,
            stair=bool(STAIR_RE.search(texts)), fire_exit=fire_exit is True,
            corridor=bool(CORRIDOR_RE.search(texts) or re.search(r"\bcorridor\b", category, re.I)),
        )
    space_ids = _ids("space", {g: i["number"] for g, i in space_info.items()})

    # ---------------------------------------------------- geometry
    doors = f.by_type("IfcDoor")
    stairs = f.by_type("IfcStair")
    flights = f.by_type("IfcStairFlight")
    ramps = f.by_type("IfcRamp")
    columns = f.by_type("IfcColumn")
    openings = {}
    for d in doors:
        for rel in getattr(d, "FillsVoids", None) or []:
            openings[d.id()] = rel.RelatingOpeningElement
    stair_parts = {st.id(): [p for p in E.get_decomposition(st) if not p.is_a("IfcRailing")] for st in stairs}
    tg = time.time()
    progress("Triangulating spaces, door openings, stairs, ramps and columns")
    wanted = list(spaces) + list(openings.values()) + [d for d in doors if d.id() not in openings] + list(stairs) + \
        [p for ps in stair_parts.values() for p in ps] + list(flights) + list(ramps) + \
        [p for r in ramps for p in E.get_decomposition(r)] + list(columns)
    wanted = list({e.id(): e for e in wanted}.values())
    mesh = m.meshes(wanted)
    timings["geometry"] = round(time.time() - tg, 2)

    # ---------------------------------------------------- doors
    door_info = {}
    for d in doors:
        typ = E.get_type(d)
        op = getattr(d, "OperationType", None) or (getattr(typ, "OperationType", None) if typ else None)
        family = (d.Name or "").split(":")[0]
        if op in LEAVES_BY_OPERATION:
            leaves, leaves_at = LEAVES_BY_OPERATION[op], f"OperationType {op}"
        elif re.search(r"double|dbl|pair|2[- ]?fl|zweifl", (d.Name or "") + " " + ((typ.Name or "") if typ else ""), re.I):
            leaves, leaves_at = 2, f"Name '{family}'"
        elif op is not None and op not in ("USERDEFINED", "NOTDEFINED"):
            leaves, leaves_at = None, None
        else:
            leaves, leaves_at = 1, f"no leaf count in the model; Name '{family}' names no pair"
        mark, mark_at = _mark(m, d)
        door_info[d.GlobalId] = dict(e=d, op=op, leaves=leaves, leaves_at=leaves_at, mark=mark, mark_at=mark_at, storey=m.storey_of(d), family=family)
    door_ids = _ids("door", {g: i["mark"] for g, i in door_info.items()})

    elements = []
    for g, i in door_info.items():
        d = i["e"]
        loc = f"ifc:{g}"
        facts = {}
        width = m.metres(d.OverallWidth, f"{loc} OverallWidth") or None
        width_at = "OverallWidth"
        if width is None:
            q = m.prop(d, "Qto_DoorBaseQuantities", "Width")
            if q:
                width, width_at = m.metres(q, f"{loc} Qto_DoorBaseQuantities.Width") or None, "Qto_DoorBaseQuantities.Width"
        height = m.metres(d.OverallHeight, f"{loc} OverallHeight") or None
        height_at = "OverallHeight"
        if height is None:
            q = m.prop(d, "Qto_DoorBaseQuantities", "Height")
            if q:
                height, height_at = m.metres(q, f"{loc} Qto_DoorBaseQuantities.Height") or None, "Qto_DoorBaseQuantities.Height"
        if i["mark"]:
            facts["mark"] = _obs(i["mark"], f"{loc} {i['mark_at']}")
        if i["leaves"]:
            facts["leaves"] = _obs(i["leaves"], f"{loc} {i['leaves_at']}")
        if width and i["leaves"]:
            leaf = width / i["leaves"]
            facts["leaf_width"] = _obs(_mm(round(leaf, 4)), f"{loc} {width_at} {_mm(width)} / {i['leaves']} leaf")
            if i["op"] in SWINGING or i["op"] in (None, "USERDEFINED", "NOTDEFINED"):
                lo, hi = round(leaf * 1000) - CLEAR_WIDTH_DEDUCTION_MM[1], round(leaf * 1000) - CLEAR_WIDTH_DEDUCTION_MM[0]
                at = f"{loc} {width_at} {_mm(width)} / {i['leaves']} leaf, less {CLEAR_WIDTH_DEDUCTION_MM[0]}-{CLEAR_WIDTH_DEDUCTION_MM[1]} mm for a hinged leaf and stop, {i['family']}"
                facts["clear_width"] = [{"value": f"{lo} mm", "at": at}, {"value": f"{hi} mm", "at": at}]
        if height:
            facts["height"] = _obs(_mm(height), f"{loc} {height_at}")
        if i["storey"] is not None:
            facts["storey"] = _obs(i["storey"].Name, f"{loc} contained in IfcBuildingStorey {i['storey'].GlobalId}")
        fr = m.prop(d, "Pset_DoorCommon", "FireRating")
        fr_at = "Pset_DoorCommon.FireRating"
        if fr is None:
            fr, fr_at = m.find(d, ("Fire Rating", "FireRating", "FireResistanceRating"), skip=("Pset_DoorCommon",))
        if fr is not None:
            facts["fire_rating"] = _obs(str(fr), f"{loc} {fr_at}")
        ext = m.prop(d, "Pset_DoorCommon", "IsExternal")
        if ext is not None:
            facts["is_external"] = _obs(bool(ext), f"{loc} Pset_DoorCommon.IsExternal")
        elements.append({"type": "Door", "id": door_ids[g], "at": [loc], "facts": facts})

    # ---------------------------------------------------- stairs
    flights_of = {}
    for fl in flights:
        parent = E.get_aggregate(fl)
        if parent is not None and parent.is_a("IfcStair"):
            flights_of.setdefault(parent.id(), []).append(fl)
    stair_marks = {st.GlobalId: _mark(m, st, ("mark",))[0] or _plain_name(st) for st in stairs}
    stair_ids = _ids("stair", stair_marks)
    stair_geo = {}
    for st in stairs:
        loc = f"ifc:{st.GlobalId}"
        facts = {}
        parts = [st] + stair_parts[st.id()]
        ms = [mesh[p.id()] for p in parts if p.id() in mesh]
        zr = (min(x.zmin for x in ms), max(x.zmax for x in ms)) if ms else None
        if ms:
            stair_geo[st.GlobalId] = (unary_union([G.footprint(x) for x in ms]), zr)
        fls = flights_of.get(st.id(), [])
        riser_at, tread_at = "Pset_StairCommon.RiserHeight", "Pset_StairCommon.TreadLength"
        riser = m.metres(m.prop(st, "Pset_StairCommon", "RiserHeight"), f"{loc} {riser_at}")
        tread = m.metres(m.prop(st, "Pset_StairCommon", "TreadLength"), f"{loc} {tread_at}")
        n_risers = m.num(m.prop(st, "Pset_StairCommon", "NumberOfRiser"), f"{loc} Pset_StairCommon.NumberOfRiser")
        flight_risers, flight_riser_h, flight_tread = [], [], []
        for fl in fls:
            fl_loc = f"ifc:{fl.GlobalId}"
            n_at = "Pset_StairFlightCommon.NumberOfRiser"
            n = m.num(m.prop(fl, "Pset_StairFlightCommon", "NumberOfRiser"), f"{fl_loc} {n_at}")
            if not n:   # IFC2X3 NumberOfRiser, IFC4 NumberOfRisers
                n_at = "IfcStairFlight.NumberOfRiser(s)"
                n = m.num(getattr(fl, "NumberOfRisers", None) or getattr(fl, "NumberOfRiser", None), f"{fl_loc} {n_at}")
            if n:
                flight_risers.append((int(n), f"{fl_loc} {n_at}"))
            for attr, out in (("RiserHeight", flight_riser_h), ("TreadLength", flight_tread)):
                pv = m.metres(m.prop(fl, "Pset_StairFlightCommon", attr), f"{fl_loc} Pset_StairFlightCommon.{attr}")
                if pv:
                    out.append((pv, f"{fl_loc} Pset_StairFlightCommon.{attr}"))
                    continue
                av = m.num(getattr(fl, attr, None), f"{fl_loc} IfcStairFlight.{attr}")
                if not av or m.length is None:
                    continue
                val, note = av * m.length, f"{fl_loc} IfcStairFlight.{attr}"
                # Some Revit exports write these two attributes in feet whatever the file's unit: check against the flight's height.
                if attr == "RiserHeight" and n and fl.id() in mesh:
                    hgt = mesh[fl.id()].zmax - mesh[fl.id()].zmin
                    if abs(av * FOOT * n - hgt) < abs(val * n - hgt):
                        val, note = av * FOOT, note + " (written in feet: checked against the flight's height in the geometry)"
                elif attr == "TreadLength" and flight_riser_h and "feet" in flight_riser_h[-1][1]:
                    val, note = av * FOOT, note + " (written in feet, as the riser height)"
                out.append((val, note))
        if riser is not None:
            facts["riser_height"] = _obs(_mm(riser), f"{loc} {riser_at}")
        elif flight_riser_h:
            facts["riser_height"] = [{"value": _mm(v), "at": a} for v, a in _distinct(flight_riser_h)]
        else:
            v, a = m.find(st, ("Actual Riser Height",))
            v = m.metres(v, f"{loc} {a}")
            if v:
                facts["riser_height"] = _obs(_mm(v), f"{loc} {a}")
        if tread is not None:
            facts["tread_depth"] = _obs(_mm(tread), f"{loc} {tread_at}")
        elif flight_tread:
            facts["tread_depth"] = [{"value": _mm(v), "at": a} for v, a in _distinct(flight_tread)]
        else:
            v, a = m.find(st, ("Actual Tread Depth",))
            v = m.metres(v, f"{loc} {a}")
            if v:
                facts["tread_depth"] = _obs(_mm(v), f"{loc} {a}")
        if flight_risers:
            facts["risers"] = [{"value": n, "at": a} for n, a in _distinct(flight_risers, key=lambda x: x)]
        elif n_risers:
            facts["risers"] = _obs(int(n_risers), f"{loc} Pset_StairCommon.NumberOfRiser (whole stair; the model has no flights)")
        # total rise
        rh = riser if riser is not None else (flight_riser_h[0][0] if len(_distinct(flight_riser_h)) == 1 else None)
        if n_risers and rh:
            facts["rise"] = _obs(_m(n_risers * rh, 3), f"{loc} Pset_StairCommon.NumberOfRiser {int(n_risers)} x riser height {_mm(rh)}")
        else:
            con = m.psets(st).get("PSet_Revit_Constraints", {})
            if con.get("Base Level") in by_name and con.get("Top Level") in by_name:
                top_e, base_e = elev[by_name[con["Top Level"]].id()], elev[by_name[con["Base Level"]].id()]
                offs = [m.metres(con.get(k) or 0, f"{loc} PSet_Revit_Constraints.{k}") for k in ("Top Offset", "Base Offset")]
                if top_e is not None and base_e is not None and None not in offs:
                    rise = top_e - base_e + offs[0] - offs[1]
                    facts["rise"] = _obs(_m(rise, 3), f"{loc} PSet_Revit_Constraints Base/Top Level")
            elif n_risers and zr:
                st_storey = m.storey_of(st)
                base_e = elev[st_storey.id()] if st_storey is not None else None
                above = [s for s in storeys if base_e is not None and elev[s.id()] is not None and elev[s.id()] > base_e + 0.5]
                if above:
                    rise = elev[above[0].id()] - elev[st_storey.id()]
                    if abs((zr[1] - zr[0]) - rise) < 0.5:
                        facts["rise"] = _obs(_m(rise, 3), f"{loc} storey {st_storey.Name} to {above[0].Name}; the stair's geometry spans {_m(zr[1] - zr[0], 2)}")
                        facts["riser_height"] = facts.get("riser_height") or _obs(_mm(rise / n_risers), f"{loc} rise {_m(rise, 3)} / Pset_StairCommon.NumberOfRiser {int(n_risers)}")
        # width: no standard property carries it
        widths = []
        for fl in fls:
            if fl.id() in mesh:
                fp = G.footprint(mesh[fl.id()])
                if not fp.is_empty:
                    b = G.oriented_box(fp)[4]
                    widths.append((2 * b, f"ifc:{fl.GlobalId} flight footprint, short side of its oriented bounding box"))
        rv, ra = m.find(st, ("Width",), skip=("Qto_StairFlightBaseQuantities",))
        rv = m.metres(rv, f"{loc} {ra}")
        if rv:
            facts["width"] = _obs(_mm(rv), f"{loc} {ra}")
        elif widths:
            # no property: the flights' overall width, stringers included (an upper bound of the clear width)
            facts["width"] = [{"value": _mm(round(w, 3)), "at": a + " (overall, stringers included)"} for w, a in _distinct(widths, key=lambda x: round(x, 2))]
        ext = m.prop(st, "Pset_StairCommon", "IsExternal")
        if ext is not None:
            facts["is_external"] = _obs(bool(ext), f"{loc} Pset_StairCommon.IsExternal")
        elements.append({"type": "Stair", "id": stair_ids[st.GlobalId], "at": [loc], "facts": facts})

    # ---------------------------------------------------- ramps
    ramp_ids = _ids("ramp", {r.GlobalId: _mark(m, r, ("mark",))[0] or _plain_name(r) for r in ramps})
    for r in ramps:
        loc = f"ifc:{r.GlobalId}"
        facts = {}
        parts = list(E.get_decomposition(r))
        for fl in (p for p in parts if p.is_a("IfcRampFlight")):
            for attr, key in (("Slope", "slope"), ("ClearWidth", "clear_width")):
                v = m.prop(fl, "Pset_RampFlightCommon", attr)
                at = f"ifc:{fl.GlobalId} Pset_RampFlightCommon.{attr}"
                if v and attr == "Slope":
                    v = m.num(v, at)
                    val = round(math.tan(v * m.angle), 4) if v is not None and m.angle is not None else None
                elif v:
                    v = m.metres(v, at)
                    val = _mm(v) if v is not None else None
                if v and val is not None:
                    facts.setdefault(key, []).append({"value": val, "at": at})
        # the walking surface: the top layer when the ramp is split into parts (layers)
        top = max((p for p in [r] + parts if p.id() in mesh and not p.is_a("IfcRailing")), key=lambda p: mesh[p.id()].zmax, default=None)
        got = G.ramp_slope(mesh[top.id()]) if top is not None else None
        if got and "slope" not in facts:
            facts["slope"] = _obs(round(got[0], 4), f"ifc:{top.GlobalId} geometry: mean gradient of the sloped upper faces of {top.Name or top.is_a()}")
        if got:
            facts["rise"] = _obs(_m(got[1], 3), f"ifc:{top.GlobalId} geometry: height span of the sloped upper faces of {top.Name or top.is_a()}")
        elements.append({"type": "Ramp", "id": ramp_ids[r.GlobalId], "at": [loc], "facts": facts})

    timings["properties"] = round(time.time() - t - timings["geometry"], 2)

    # ---------------------------------------------------- per-storey plans
    t = time.time()
    fp_space = {}
    for g, i in space_info.items():
        s = i["e"]
        if s.id() in mesh:
            fp = G.footprint(mesh[s.id()], bottom=True)
            if fp.is_empty:
                fp = G.footprint(mesh[s.id()])
            fp_space[g] = (fp, mesh[s.id()].zmin, mesh[s.id()].zmax)
    walkable = {g for g, i in space_info.items() if g in fp_space and not i["void"] and not i["external"] and fp_space[g][0].area > 0.05}
    occupied_storeys = [s for s in storeys if any(space_info[g]["storey"] is not None and space_info[g]["storey"].id() == s.id() for g in walkable)]
    # the storey's floor in the geometry: where its spaces stand (some exporters leave storey placements at zero)
    floor_z = {}
    for s in storeys:
        zs = [fp_space[g][1] for g in walkable if space_info[g]["storey"] is not None and space_info[g]["storey"].id() == s.id()]
        floor_z[s.id()] = float(np.median(zs)) if zs else world_z[s.id()]

    def storey_at(z: float):
        cands = [s for s in occupied_storeys if floor_z[s.id()] <= z + 0.6]
        return cands[-1] if cands else None

    door_raw: dict[int, list] = {}   # storey id -> (opening footprint, width axis, origin, gid, label, IsExternal)
    for g, i in door_info.items():
        d = i["e"]
        op_el = openings.get(d.id())
        src = op_el if op_el is not None and op_el.id() in mesh else (d if d.id() in mesh else None)
        if src is None:
            continue
        msh = mesh[src.id()]
        mat, why = m.placement(d.ObjectPlacement) if d.ObjectPlacement else (None, None)
        if why:
            skipped.append(f"door {i['mark'] or g} (ifc:{g}): {why}: its width axis and position on the plan not read")
        axis = mat[:2, 0] if mat is not None and np.linalg.norm(mat[:2, 0]) > 1e-6 else None
        origin = mat[:3, 3] * m.length if mat is not None else None
        st = storey_at(msh.zmin)
        if st is not None:
            door_raw.setdefault(st.id(), []).append((G.footprint(msh), axis, origin, g, f"door {i['mark'] or g}", m.prop(d, "Pset_DoorCommon", "IsExternal")))

    # which storeys are storeys
    counted = [s for s in occupied_storeys if door_raw.get(s.id())]
    above_flags = {s.id(): m.prop(s, "Pset_BuildingStoreyCommon", "AboveGround") for s in storeys}
    if any(above_flags[s.id()] is True for s in counted):
        grade = next(s for s in counted if above_flags[s.id()] is True)
        grade_at = f"lowest storey with Pset_BuildingStoreyCommon.AboveGround true: {grade.Name}"
    elif counted:
        grade = min(counted, key=lambda s: abs(elev[s.id()]) if elev[s.id()] is not None else math.inf)
        grade_at = f"storey nearest elevation 0: {grade.Name}"
    else:
        grade, grade_at = None, "no storey has a walkable space and a door"

    plans = []
    door_plans: dict[int, list] = {}
    for s in counted:
        rooms, zf = [], floor_z[s.id()]
        # stair-named spaces first, so an enclosure is named after its stair
        for g in sorted((g for g in space_info if g in walkable), key=lambda g: not space_info[g]["stair"]):
            i = space_info[g]
            if i["storey"] is None or i["storey"].id() != s.id():
                continue
            label = f"space {i['number'] or ''} {i['name'] or ''}".strip()
            rooms.append(G.Room(g, label, fp_space[g][0], exit=i["stair"] or i["fire_exit"]))
        st_zones = []
        for st in stairs:
            if st.GlobalId in stair_geo:
                fp, (z0, z1) = stair_geo[st.GlobalId]
                if z0 - 0.6 <= zf <= z1 + 0.6 and not fp.is_empty:
                    st_zones.append(G.Room(st.GlobalId, f"stair {stair_marks.get(st.GlobalId) or st.GlobalId}", fp, exit=True))
        cols = [G.footprint(mesh[c.id()]) for c in columns if c.id() in mesh and mesh[c.id()].zmin <= zf + 0.5 <= mesh[c.id()].zmax]
        floor = unary_union([r.poly for r in rooms] + [z.poly for z in st_zones])
        door_plans[s.id()] = [dp for raw in door_raw.get(s.id(), []) for dp in [G.door_plan(raw[0], raw[1], raw[2], floor, *raw[3:])] if dp is not None]
        plans.append(G.StoreyPlan(s.GlobalId, s == grade, rooms, door_plans[s.id()], st_zones, unary_union(cols) if cols else G.Polygon()))
    timings["plans"] = round(time.time() - t, 2)

    t = time.time()
    routes: dict[str, G.StoreyRoute] = {}
    names = {s.GlobalId: s.Name for s in storeys}
    for p in plans:
        name = names[p.name]
        progress(f"Travel distances on {name}")
        r = G.route_storey(p, progress=progress)
        if r is not None:
            routes[p.name] = r
            timings[f"travel {name}"] = round(r.seconds, 2)
            if not r.exits:
                skipped.append(f"travel distance on {name}: no exit ({r.exit_kind}) is reachable from any space")
            elif r.unreachable:
                notes.append(f"{name}: {len(r.unreachable)} spaces have no route to an exit in the model: " + ", ".join(space_ids[g] for g in r.unreachable))
            if r.open_stairs:
                notes.append(f"{name}: open stairs not counted as exits (no door separates them from the floor): " + ", ".join(r.open_stairs))
    timings["travel"] = round(time.time() - t, 2)

    # ---------------------------------------------------- spaces, corridors
    route_of = {g: (r, sr) for r in routes.values() for g, sr in r.spaces.items()}
    space_area: dict[str, float | None] = {}   # m2, read once: storeys sum them
    for g, i in space_info.items():
        s = i["e"]
        loc = f"ifc:{g}"
        facts = {}
        if i["name"]:
            facts["name"] = _obs(str(i["name"]), f"{loc} {i['name_at']}")
        if i["number"]:
            facts["number"] = _obs(i["number"], f"{loc} {i['number_at']}")
        if i["storey"] is not None:
            facts["storey"] = _obs(i["storey"].Name, f"{loc} in IfcBuildingStorey {i['storey'].GlobalId}")
        area, area_at = _space_area(m, s)
        if area is None and g in fp_space and fp_space[g][0].area > 0 and m.plausible(
                "Space", "floor_area", _m2(fp_space[g][0].area), f"{loc} geometry: plan area of the space's floor"):
            area, area_at = fp_space[g][0].area, "geometry: plan area of the space's floor"
        space_area[g] = area
        if area is not None:
            facts["floor_area"] = _obs(_m2(area), f"{loc} {area_at}")
        if g in route_of:
            r, sr = route_of[g]
            facts["travel_distance"] = _obs(_m(sr.distance), f"{loc} geodesic from ({sr.point[0]:.2f}, {sr.point[1]:.2f}) to {sr.exit}"
                                            + (f" ifc:{sr.exit_gid}" if sr.exit_gid else "") + f", {len(sr.path) - 1} legs, grid {r.resolution:.2f} m")
            facts["exits"] = _obs(sr.exits, f"{loc} doorways and openings from which an exit is reached without returning through the space")
        elements.append({"type": "Space", "id": space_ids[g], "at": [loc], "facts": facts})
        if i["corridor"] and not i["stair"]:
            cf = {}
            if i["storey"] is not None:
                cf["storey"] = _obs(i["storey"].Name, f"{loc} in IfcBuildingStorey {i['storey'].GlobalId}")
            if g in fp_space and g in walkable:
                poly = fp_space[g][0]
                st_doors = door_plans.get(i["storey"].id(), []) if i["storey"] is not None else []
                conns = [d.passage.intersection(poly) for d in st_doors if d.passage.intersection(poly).area > 0.01]
                others = [fp_space[o][0] for o in space_info if o in walkable and o != g and space_info[o]["storey"] == i["storey"]]
                conns += [poly.boundary.intersection(o.buffer(G.CLOSE_GAP * 2)) for o in others if poly.boundary.intersection(o.buffer(G.CLOSE_GAP * 2)).length > 0.6]
                w = G.bottleneck_width(poly, [c for c in conns if not c.is_empty])
                if w:
                    cf["clear_width"] = _obs(_mm(round(w, 2)), f"{loc} geometry: widest disc that passes between all {len(conns)} doorways and "
                                             "openings of the space's floor (walls bound it; furniture ignored)")
            elements.append({"type": "Corridor", "id": f"corridor:{i['number']}" if space_ids[g] != g else g, "at": [loc], "facts": cf})

    # ---------------------------------------------------- storeys and the building
    st_area = {}
    for s in storeys:
        loc = f"ifc:{s.GlobalId}"
        facts = {"elevation": _obs(_m(elev[s.id()], 3), f"{loc} {elev_at[s.id()]}")} if elev[s.id()] is not None else {}
        gross = m.prop(s, "Qto_BuildingStoreyBaseQuantities", "GrossFloorArea") or m.prop(s, "BaseQuantities", "GrossFloorArea")
        gross = m.square_metres(gross, f"{loc} Qto_BuildingStoreyBaseQuantities.GrossFloorArea") if gross else None
        if gross and m.plausible("Storey", "floor_area", _m2(gross, 1), f"{loc} Qto_BuildingStoreyBaseQuantities.GrossFloorArea"):
            st_area[s.id()] = gross
            facts["floor_area"] = _obs(_m2(gross, 1), f"{loc} Qto_BuildingStoreyBaseQuantities.GrossFloorArea")
        else:
            own = [g for g, i in space_info.items() if i["storey"] is not None and i["storey"].id() == s.id() and not i["void"] and not i["external"]]
            areas = [space_area.get(g) or 0 for g in own]
            if own and sum(areas) > 0:
                st_area[s.id()] = sum(areas)
                facts["floor_area"] = _obs(_m2(sum(areas), 1), f"{loc} sum of the floor areas of its {len(own)} spaces (net: walls not included), voids and external spaces excluded")
        r = routes.get(s.GlobalId)
        if r is not None and r.spaces:
            far_g, far = max(r.spaces.items(), key=lambda kv: kv[1].distance)
            i = space_info[far_g]
            facts["max_travel_distance"] = _obs(_m(far.distance), f"ifc:{far_g} farthest point ({far.point[0]:.2f}, {far.point[1]:.2f}) in space {i['number'] or ''} {i['name'] or ''}".rstrip()
                                                + f", to {far.exit}" + (f" ifc:{far.exit_gid}" if far.exit_gid else ""))
        if r is not None and r.exits:
            facts["exits"] = _obs(len(r.exits), f"{loc} {r.exit_kind} reached from its spaces: " + ", ".join(r.exits))
        elements.append({"type": "Storey", "id": storey_ids[s.GlobalId], "at": [loc], "facts": facts})

    facts = {}
    level = {s.id(): elev[s.id()] if elev[s.id()] is not None else floor_z[s.id()] for s in counted}   # counted: floor_z from its spaces
    above = [s for s in counted if (above_flags[s.id()] is True) or (above_flags[s.id()] is None and grade is not None and level[s.id()] >= level[grade.id()] - 0.01)]
    below = [s for s in counted if s not in above]
    if grade is not None:
        facts["storeys_above_ground"] = _obs(len(above), f"IfcBuildingStorey with a walkable space and a door, at or above grade ({grade_at}): " + ", ".join(s.Name for s in above))
        facts["storeys_below_ground"] = _obs(len(below), "IfcBuildingStorey with a walkable space and a door, below grade: " + (", ".join(s.Name for s in below) or "none"))
    areas = [(st_area[s.id()], s) for s in counted if s.id() in st_area]
    if areas:
        facts["total_floor_area"] = _obs(_m2(sum(a for a, _ in areas), 0), "sum of Storey.floor_area over " + ", ".join(s.Name for _, s in areas))
        a, s = max(areas, key=lambda x: x[0])
        facts["largest_storey_area"] = _obs(_m2(a, 0), f"ifc:{s.GlobalId} Storey.floor_area of {s.Name}")
    if grade is not None:
        t = time.time()
        bh = _building_height(f, m, storeys, counted, elev, world_z, grade)
        if bh:
            facts["building_height"] = bh
        timings["building_height"] = round(time.time() - t, 2)
    drop_implausible(facts, elements, skipped)
    skipped[:] = list(dict.fromkeys(skipped))
    timings["total"] = round(time.time() - t_all, 2)

    fn = f.header.file_name
    app = "; ".join(x for x in (getattr(fn, "preprocessor_version", ""), getattr(fn, "originating_system", "")) if x)
    source = {
        "id": "ifc", "kind": "model", "describes": describes or path.name, "schema": f.schema, "authoring": app,
        "adapter": f"adapters.ifc {VERSION}", "length_unit": m.length_name + (f" ({m.length:g} m)" if m.length is not None else " (not known)"),
        "counts": {t: sum(1 for e in elements if e["type"] == t) for t in ("Storey", "Space", "Door", "Stair", "Ramp", "Corridor")},
        "travel_distance": {
            "method": "geodesic to the nearest exit inside the walkable floor: grid Dijkstra (16 directions) and string-pulling",
            "resolution": {names[k]: _m(r.resolution) for k, r in routes.items()},
            "cells": {names[k]: r.cells for k, r in routes.items()},
            "exit_doors": {names[k]: sorted(r.doors_used.values()) for k, r in routes.items()},
            "assumptions": TRAVEL_ASSUMPTIONS,
        },
        "timings_s": timings,
    }
    if notes:
        source["notes"] = notes
    if skipped:
        source["skipped"] = skipped
    # the building's name, unless it is an authoring tool's placeholder ("Project Number")
    given = [x for e in f.by_type("IfcBuilding")[:1] + f.by_type("IfcProject")[:1] for x in (e.Name, getattr(e, "LongName", None))
             if x and x.strip().lower() not in ("project number", "project name", "building name", "default", "unnamed")]
    return {
        "subject": {"kind": "building", "id": given[0] if given else (describes or path.stem)},
        "sources": [source],
        "facts": facts,
        "elements": elements,
    }


extract = analyse  # bench/clinic/check.py and older callers


def _distinct(items: list, key=lambda v: round(v, 4)) -> list:
    out, seen = [], set()
    for v, a in items:
        k = key(v)
        if k not in seen:
            seen.add(k)
            out.append((v, a))
    return out


def _space_area(m: Model, s) -> tuple:
    for ps, prop in (("Qto_SpaceBaseQuantities", "NetFloorArea"), ("Qto_SpaceBaseQuantities", "GrossFloorArea"),
                     ("BaseQuantities", "NetFloorArea"), ("BaseQuantities", "GrossFloorArea")):
        v = m.prop(s, ps, prop)
        at = f"ifc:{s.GlobalId} {ps}.{prop}"
        v = m.square_metres(v, at) if v else None
        if v and m.plausible("Space", "floor_area", _m2(v), at):
            return v, f"{ps}.{prop}"
    v, at = m.find(s, ("Area", "NetArea", "GSA BIM Area"))
    if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0:
        a = m.square_metres(v, f"ifc:{s.GlobalId} {at}")
        if a is not None and m.plausible("Space", "floor_area", _m2(a), f"ifc:{s.GlobalId} {at}"):
            return a, at
    return None, None


def _building_height(f, m: Model, storeys, counted, elev, world_z, grade) -> list | None:
    """Grade to the highest roof: the top of the roof elements, else the levels above the top storey."""
    roofs = list(f.by_type("IfcRoof")) + [s for s in f.by_type("IfcSlab") if s.PredefinedType == "ROOF"] + \
        [c for c in f.by_type("IfcCovering") if getattr(c, "PredefinedType", None) == "ROOFING"]
    g0 = world_z[grade.id()]
    if g0 is None:   # the grade storey's placement is not readable (listed in skipped)
        return None
    if roofs:
        ms = m.meshes(roofs)
        parts = []
        for r in roofs:
            sub = [r.id()] + [p.id() for p in E.get_decomposition(r)]
            parts += [(mesh_z, r) for i in sub if i in ms for mesh_z in [ms[i].zmax]]
        if not parts:
            sub = {p.id(): r for r in roofs for p in E.get_decomposition(r)}
            ms = m.meshes([f.by_id(i) for i in sub])
            parts = [(ms[i].zmax, sub[i]) for i in ms]
        if parts:
            z, r = max(parts, key=lambda x: x[0])
            return _obs(_m(z - g0), f"ifc:{r.GlobalId} top of the highest roof element ({r.is_a()}) above the floor of {grade.Name}")
    top = counted[-1]
    levels = [s for s in storeys if elev[s.id()] is not None and elev[top.id()] is not None and elev[s.id()] > elev[top.id()] + 0.5]
    if not levels or world_z[levels[0].id()] is None:
        return None
    lv = levels[0]
    out = [{"value": _m(world_z[lv.id()] - g0), "at": f"ifc:{lv.GlobalId} elevation of level {lv.Name} above {grade.Name} (the model has no IfcRoof)"}]
    contained = [e for s in levels for e in E.get_decomposition(s) if e.is_a("IfcElement")]
    ms = m.meshes(contained)
    if ms:
        z = max(x.zmax for x in ms.values())
        if z - g0 > world_z[lv.id()] - g0 + 0.01:
            out.append({"value": _m(z - g0), "at": f"ifc:{lv.GlobalId} top of the highest element on level {lv.Name} and above"})
    return out


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("ifc")
    p.add_argument("-o", "--out", required=True)
    a = p.parse_args()
    doc = analyse(a.ifc, progress=lambda msg: print(msg, file=sys.stderr))
    Path(a.out).write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=120))
    print(f"{a.out}: {doc['sources'][0]['counts']}, timings {doc['sources'][0]['timings_s']}", file=sys.stderr)


if __name__ == "__main__":
    main()
