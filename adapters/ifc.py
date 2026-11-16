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
from shapely.ops import unary_union

from adapters import ifc_egress as G

VERSION = "0.2.0"
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
    def __init__(self, f: ifcopenshell.file):
        self.f = f
        self.length = U.calculate_unit_scale(f)
        try:
            self.area = U.calculate_unit_scale(f, "AREAUNIT")
        except Exception:  # noqa: BLE001 - files without an area unit
            self.area = self.length ** 2
        self._ps: dict[int, dict] = {}

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

    def storey_of(self, e):
        c = E.get_container(e) or E.get_aggregate(e)
        for _ in range(6):
            if c is None or c.is_a("IfcBuildingStorey"):
                return c
            c = E.get_container(c) or E.get_aggregate(c)
        return None

    def z(self, e) -> float:
        return float(P.get_local_placement(e.ObjectPlacement)[2, 3]) * self.length if e.ObjectPlacement else 0.0


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
    skipped: list[str] = []
    if not f.by_type("IfcBuildingStorey"):
        facilities = sorted({e.is_a() for e in f.by_type("IfcSpatialStructureElement")} - {"IfcSite", "IfcBuilding"}) \
            if f.schema != "IFC2X3" else []
        notes.append(f"{path.name}: no building storeys" + (f" (it models {', '.join(facilities)})" if facilities else "")
                     + "; its storeys, spaces, doors, stairs and travel distances could not be read")

    # ---------------------------------------------------- storeys
    storeys = sorted(f.by_type("IfcBuildingStorey"), key=lambda s: (s.Elevation if s.Elevation is not None else m.z(s) / m.length))
    elev = {s.id(): (s.Elevation * m.length if s.Elevation is not None else m.z(s)) for s in storeys}
    world_z = {s.id(): m.z(s) for s in storeys}
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
    mesh = G.meshes(f, wanted)
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
        width = d.OverallWidth * m.length if d.OverallWidth else None
        width_at = "OverallWidth"
        if width is None:
            q = m.prop(d, "Qto_DoorBaseQuantities", "Width")
            if q:
                width, width_at = q * m.length, "Qto_DoorBaseQuantities.Width"
        height = d.OverallHeight * m.length if d.OverallHeight else None
        height_at = "OverallHeight"
        if height is None:
            q = m.prop(d, "Qto_DoorBaseQuantities", "Height")
            if q:
                height, height_at = q * m.length, "Qto_DoorBaseQuantities.Height"
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
        riser, riser_at = m.prop(st, "Pset_StairCommon", "RiserHeight"), "Pset_StairCommon.RiserHeight"
        tread, tread_at = m.prop(st, "Pset_StairCommon", "TreadLength"), "Pset_StairCommon.TreadLength"
        n_risers = m.prop(st, "Pset_StairCommon", "NumberOfRiser")
        flight_risers, flight_riser_h, flight_tread = [], [], []
        for fl in fls:
            fl_loc = f"ifc:{fl.GlobalId}"
            n, n_at = m.prop(fl, "Pset_StairFlightCommon", "NumberOfRiser"), "Pset_StairFlightCommon.NumberOfRiser"
            if not n:   # IFC2X3 NumberOfRiser, IFC4 NumberOfRisers
                n, n_at = getattr(fl, "NumberOfRisers", None) or getattr(fl, "NumberOfRiser", None), "IfcStairFlight.NumberOfRiser(s)"
            if n:
                flight_risers.append((int(n), f"{fl_loc} {n_at}"))
            for attr, out in (("RiserHeight", flight_riser_h), ("TreadLength", flight_tread)):
                pv = m.prop(fl, "Pset_StairFlightCommon", attr)
                if pv:
                    out.append((pv * m.length, f"{fl_loc} Pset_StairFlightCommon.{attr}"))
                    continue
                av = getattr(fl, attr, None)
                if not av:
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
            facts["riser_height"] = _obs(_mm(riser * m.length), f"{loc} {riser_at}")
        elif flight_riser_h:
            facts["riser_height"] = [{"value": _mm(v), "at": a} for v, a in _distinct(flight_riser_h)]
        else:
            v, a = m.find(st, ("Actual Riser Height",))
            if v:
                facts["riser_height"] = _obs(_mm(v * m.length), f"{loc} {a}")
        if tread is not None:
            facts["tread_depth"] = _obs(_mm(tread * m.length), f"{loc} {tread_at}")
        elif flight_tread:
            facts["tread_depth"] = [{"value": _mm(v), "at": a} for v, a in _distinct(flight_tread)]
        else:
            v, a = m.find(st, ("Actual Tread Depth",))
            if v:
                facts["tread_depth"] = _obs(_mm(v * m.length), f"{loc} {a}")
        if flight_risers:
            facts["risers"] = [{"value": n, "at": a} for n, a in _distinct(flight_risers, key=lambda x: x)]
        elif n_risers:
            facts["risers"] = _obs(int(n_risers), f"{loc} Pset_StairCommon.NumberOfRiser (whole stair; the model has no flights)")
        # total rise
        rh = riser * m.length if riser is not None else (flight_riser_h[0][0] if len(_distinct(flight_riser_h)) == 1 else None)
        if n_risers and rh:
            facts["rise"] = _obs(_m(n_risers * rh, 3), f"{loc} Pset_StairCommon.NumberOfRiser {int(n_risers)} x riser height {_mm(rh)}")
        else:
            con = m.psets(st).get("PSet_Revit_Constraints", {})
            if con.get("Base Level") in by_name and con.get("Top Level") in by_name:
                rise = elev[by_name[con["Top Level"]].id()] - elev[by_name[con["Base Level"]].id()] + ((con.get("Top Offset") or 0) - (con.get("Base Offset") or 0)) * m.length
                facts["rise"] = _obs(_m(rise, 3), f"{loc} PSet_Revit_Constraints Base/Top Level")
            elif n_risers and zr:
                st_storey = m.storey_of(st)
                above = [s for s in storeys if st_storey is not None and elev[s.id()] > elev[st_storey.id()] + 0.5]
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
        if rv:
            facts["width"] = _obs(_mm(rv * m.length), f"{loc} {ra}")
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
                if v:
                    val = round(math.tan(v * U.calculate_unit_scale(f, "PLANEANGLEUNIT")), 4) if attr == "Slope" else _mm(v * m.length)
                    facts.setdefault(key, []).append({"value": val, "at": f"ifc:{fl.GlobalId} Pset_RampFlightCommon.{attr}"})
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
        mat = P.get_local_placement(d.ObjectPlacement) if d.ObjectPlacement else None
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
        grade = min(counted, key=lambda s: abs(elev[s.id()]))
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
        if area is None and g in fp_space and fp_space[g][0].area > 0:
            area, area_at = fp_space[g][0].area, "geometry: plan area of the space's floor"
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
        facts = {"elevation": _obs(_m(elev[s.id()], 3), f"{loc} " + ("Elevation" if s.Elevation is not None else "ObjectPlacement"))}
        gross = m.prop(s, "Qto_BuildingStoreyBaseQuantities", "GrossFloorArea") or m.prop(s, "BaseQuantities", "GrossFloorArea")
        if gross:
            st_area[s.id()] = gross * m.area
            facts["floor_area"] = _obs(_m2(gross * m.area, 1), f"{loc} Qto_BuildingStoreyBaseQuantities.GrossFloorArea")
        else:
            own = [g for g, i in space_info.items() if i["storey"] is not None and i["storey"].id() == s.id() and not i["void"] and not i["external"]]
            areas = [_space_area(m, space_info[g]["e"])[0] or (fp_space[g][0].area if g in fp_space else 0) for g in own]
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
    above = [s for s in counted if (above_flags[s.id()] is True) or (above_flags[s.id()] is None and grade is not None and elev[s.id()] >= elev[grade.id()] - 0.01)]
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
    timings["total"] = round(time.time() - t_all, 2)

    fn = f.header.file_name
    app = "; ".join(x for x in (getattr(fn, "preprocessor_version", ""), getattr(fn, "originating_system", "")) if x)
    unit = next((u for u in (f.by_type("IfcUnitAssignment")[0].Units if f.by_type("IfcUnitAssignment") else []) if getattr(u, "UnitType", None) == "LENGTHUNIT"), None)
    source = {
        "id": "ifc", "kind": "model", "describes": describes or path.name, "schema": f.schema, "authoring": app,
        "adapter": f"adapters.ifc {VERSION}", "length_unit": f"{getattr(unit, 'Prefix', None) or ''}{getattr(unit, 'Name', '')}".lower() + f" ({m.length:g} m)",
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
        if v:
            return v * m.area, f"{ps}.{prop}"
    v, at = m.find(s, ("Area", "NetArea", "GSA BIM Area"))
    if isinstance(v, (int, float)) and v > 0:
        return v * m.area, at
    return None, None


def _building_height(f, m: Model, storeys, counted, elev, world_z, grade) -> list | None:
    """Grade to the highest roof: the top of the roof elements, else the levels above the top storey."""
    roofs = list(f.by_type("IfcRoof")) + [s for s in f.by_type("IfcSlab") if s.PredefinedType == "ROOF"] + \
        [c for c in f.by_type("IfcCovering") if getattr(c, "PredefinedType", None) == "ROOFING"]
    g0 = world_z[grade.id()]
    if roofs:
        ms = G.meshes(f, roofs)
        parts = []
        for r in roofs:
            sub = [r.id()] + [p.id() for p in E.get_decomposition(r)]
            parts += [(mesh_z, r) for i in sub if i in ms for mesh_z in [ms[i].zmax]]
        if not parts:
            sub = {p.id(): r for r in roofs for p in E.get_decomposition(r)}
            ms = G.meshes(f, [f.by_id(i) for i in sub])
            parts = [(ms[i].zmax, sub[i]) for i in ms]
        if parts:
            z, r = max(parts, key=lambda x: x[0])
            return _obs(_m(z - g0), f"ifc:{r.GlobalId} top of the highest roof element ({r.is_a()}) above the floor of {grade.Name}")
    top = counted[-1]
    levels = [s for s in storeys if elev[s.id()] > elev[top.id()] + 0.5]
    if not levels:
        return None
    lv = levels[0]
    out = [{"value": _m(world_z[lv.id()] - g0), "at": f"ifc:{lv.GlobalId} elevation of level {lv.Name} above {grade.Name} (the model has no IfcRoof)"}]
    contained = [e for s in levels for e in E.get_decomposition(s) if e.is_a("IfcElement")]
    ms = G.meshes(f, contained)
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
