"""DXF adapter: CAD drawings in, an evidence document in the BIM vocabulary out.

    uv run python -m adapters.dxf <file.dxf>... -o <out.yaml>

What a PDF cannot give, read from the geometry of model space:
  - Space: closed polylines and hatches on room/area layers, closed boundaries holding a
    room tag, and the faces the walls enclose (doors closed at their leaf, windows
    bridged) holding exactly one room tag; floor_area computed with shapely.
  - Door: door blocks (named DOOR, DR, D-, ドア, ... or a small block holding a swing),
    and loose swings on door layers. A swing is an arc (or a polyline along one) with
    the leaf drawn from its centre; the leaf width is the arc radius, scaled. The clear
    width is the interval adapters.ifc uses (leaf less 44 to 64 mm).
  - DIMENSION: the measured value (get_measurement; DIMLFAC 1 only), used only where it
    clearly spans a stair flight (width, tread depth) or a corridor (clear width).
  - Stair: a run of at least four parallel, equal, evenly spaced tread lines on a stair
    layer or in a stair block: tread_depth is the spacing.
  - Space from a room name: an upright text of words (a room word, or with its area, size
    or room number printed under it) inside a wall-enclosed area or a room-layer boundary.
    id space:<number>, else space:<name> (space:<name>#2 for a repeat on the layout); a
    printed area is a second floor_area observation, as its printed-precision interval.
    Names sharing one enclosed area (open plan) get no computed area.
Text (TEXT, MTEXT lines, ATTRIB, DIMENSION) becomes adapters.drawings.tokens.Token,
read by adapters.drawings.annotations for notes, room tags, stair notes and schedules.
annotations works in page coordinates (y down): it gets each layout turned upside down
within its extents, and its locators are mapped back to drawing units, y up.

Lengths are reported in the drawing's units system: millimetres for metric drawings,
inches for imperial ones ($INSUNITS, or $MEASUREMENT when $INSUNITS is unset); areas in
m2 or sqft. Nothing is guessed: what cannot be read is left out and counted in the
source's `skipped` list. Paper-space geometry is at sheet scale, so only its text is read.
"""

from __future__ import annotations

import argparse
import dataclasses
import math
import re
import time
from bisect import bisect_left, bisect_right
from collections import Counter
from pathlib import Path

import shapely
import yaml
from ezdxf import bbox as ebbox
from ezdxf import path as epath
from ezdxf.math import Vec2
from shapely import affinity
from shapely.geometry import LineString, Point, Polygon
from shapely.ops import unary_union

from . import ifc_egress as G
from .drawings.tokens import BBox, Sheet, Token, locator, parse_locator
from .dxf_render import read, render  # noqa: F401  (render is part of this adapter's interface)
from .ifc import CLEAR_WIDTH_DEDUCTION_MM, UNIT_M, drop_implausible

VERSION = "0.1.0"
MAX_DEPTH = 8

# $INSUNITS code -> (name, millimetres per unit)
INSUNITS = {1: ("in", 25.4), 2: ("ft", 304.8), 3: ("mi", 1_609_344.0), 4: ("mm", 1.0), 5: ("cm", 10.0), 6: ("m", 1000.0),
            7: ("km", 1e6), 8: ("microinch", 25.4e-6), 9: ("mil", 0.0254), 10: ("yd", 914.4), 11: ("angstrom", 1e-7),
            12: ("nm", 1e-6), 13: ("um", 1e-3), 14: ("dm", 100.0), 15: ("dam", 1e4), 16: ("hm", 1e5),
            21: ("US survey ft", 1200 / 3937 * 1000)}
IMPERIAL = {"in", "ft", "mi", "microinch", "mil", "yd", "US survey ft"}

# Layer and block names (the CAD layer conventions: AIA/NCS, BS 1192, JIS, and plain words)
ROOM_LAYER = re.compile(r"(?i)(^|[^a-z])(area|areas|room|rooms|rm|space|spaces|raum|räume|zone)([^a-z]|$)|室|部屋")
NOT_ROOM_LAYER = re.compile(r"(?i)furn|fixt|eqp|equip|symb|text|anno|dim|grid|title|border|^tb|case|plmb|plumb|appl|elec|"
                            r"lite|light|clng|ceil|door|glaz|wind|wall|colu|strs|stair|site|plnt|tree|家具|寸法")
WALL_LAYER = re.compile(r"(?i)wall|^a-wall|壁|wand|mur")
GLAZ_LAYER = re.compile(r"(?i)glaz|wind|win$|^a-win|窓|fenster|fenetre|fenêtre")
DOOR_LAYER = re.compile(r"(?i)door|ドア|扉|建具|tür|tuer|porte|puerta")
STAIR_LAYER = re.compile(r"(?i)stair|strs|階段|treppe|escalier|escalera")
DOOR_BLOCK = re.compile(r"(?i)door|^dr([^a-z]|$)|^d-|ドア|扉|tür|tuer|porte|puerta")
WINDOW_BLOCK = re.compile(r"(?i)window|^win([^a-z]|$)|^w-|窓|fenster")
STAIR_BLOCK = re.compile(r"(?i)stair|^str([^a-z]|$)|階段|treppe|escalier|escalera")
ROOM_TAG_BLOCK = re.compile(r"(?i)room|^rm|space|tag|室")
CORRIDOR_NAME = re.compile(r"(?i)corridor|hallway|passage|\bcorr\b|廊下|通路|flur|couloir|pasillo")
# Attribute tags of door and room tag blocks
MARK_TAG = re.compile(r"(?i)^(door[_ -]?)?(mark|no|num|number|tag|id)$|^doorno$|建具番号|符号")
ROOM_NAME_TAG = re.compile(r"(?i)^(room|rm|space)[_ -]?name$|^name$|^室名$")
ROOM_NUMBER_TAG = re.compile(r"(?i)^(room|rm|space)[_ -]?(no|num|number)$|^(no|num|number)$|^室番号$")

LEAF_MM = (380, 1650)          # a door leaf is this wide; a swing outside it is something else
MIN_ROOM_M2 = 0.5
SWING_TOL = 0.02               # relative: hinge on the arc centre, leaf length equal to the radius
STAIR_MIN_TREADS = 4

# Budgets: what a building drawing needs, with room to spare. Beyond them a file is malformed or not a plan; what exceeds
# them is not read and is listed in `skipped`, so that reading stays bounded in time and memory.
MAX_COORD = 1e10            # drawing units: a coordinate farther from the origin (or NaN, inf) is not read
MAX_PATH_VERTICES = 50_000  # a polyline, hatch boundary or curve that flattens to more vertices is not read
MAX_ROOM_VERTICES = 10_000  # a room boundary with more vertices (after repair) is not read as a room
MAX_ENTITIES = 250_000      # entities read per layout, block contents included
POINT_ATTRS = ("start", "end", "center", "insert", "defpoint", "defpoint2", "defpoint3", "defpoint4", "text_midpoint",
               "align_point", "radius", "start_angle", "end_angle", "rotation", "xscale", "yscale")


# ---------------------------------------------------------------- units

class Units:
    def __init__(self, name: str, mm: float, how: str):
        self.name, self.mm, self.how = name, mm, how
        self.imperial = name in IMPERIAL

    @property
    def per_metre(self) -> float:
        return 1000 / self.mm

    def length(self, v: float) -> str:
        mm = v * self.mm
        return f"{_num(mm / 25.4, 2)} in" if self.imperial else f"{_num(mm, 1)} mm"

    def area(self, a: float) -> str:
        mm2 = a * self.mm ** 2
        return f"{_num(mm2 / 645.16 / 144, 1)} sqft" if self.imperial else f"{_num(mm2 / 1e6, 2)} m2"

    def from_mm(self, mm: float) -> float:
        return mm / self.mm


def _num(x: float, places: int) -> str:
    s = f"{x:.{places}f}"
    return s.rstrip("0").rstrip(".") if "." in s else s


def units_of(doc) -> tuple[Units | None, str | None]:
    """(units, None), or (None, why): not set, or a unit buildings are not drawn in (adapters.ifc UNIT_M: a plan in
    kilometres or microinches is a plan in another unit with the wrong header)."""
    code = doc.header.get("$INSUNITS", 0)
    if isinstance(code, int) and code in INSUNITS:
        name, mm = INSUNITS[code]
        if not UNIT_M[0] * 1000 <= mm <= UNIT_M[1] * 1000:
            return None, (f"$INSUNITS={code} ({name}) is not a unit buildings are drawn in ({UNIT_M[0] * 1000:g} to "
                          f"{UNIT_M[1] * 1000:g} mm): no lengths or areas read")
        return Units(name, mm, f"$INSUNITS={code} ({name})"), None
    meas = doc.header.get("$MEASUREMENT")
    if meas == 0:
        return Units("in", 25.4, "$INSUNITS unset; $MEASUREMENT=0 (imperial): read as inches"), None
    if meas == 1:
        return Units("mm", 1.0, "$INSUNITS unset; $MEASUREMENT=1 (metric): read as millimetres"), None
    return None, "drawing units are not set ($INSUNITS and $MEASUREMENT missing): no lengths or areas read"


# ---------------------------------------------------------------- coordinates

def _finite(*vals) -> bool:
    """Every value a finite number within MAX_COORD: the test DXF coordinates pass before they become geometry."""
    try:
        return all(math.isfinite(v) and abs(v) <= MAX_COORD for v in vals)
    except TypeError:
        return False


def _path_problem(path, flat: float) -> str | None:
    """Why a path is not flattened, or None: a coordinate _finite() rejects, or more vertices than MAX_PATH_VERTICES
    (estimated before flattening from the length of each curve's control polygon, an upper bound in practice)."""
    n, prev = 1.0, path.start
    if not _finite(prev.x, prev.y, prev.z):
        return "coordinates that are not finite numbers within the drawing's range"
    for c in path.commands():
        pts = [getattr(c, a) for a in ("ctrl", "ctrl1", "ctrl2") if hasattr(c, a)] + [c.end]
        if not all(_finite(p.x, p.y, p.z) for p in pts):
            return "coordinates that are not finite numbers within the drawing's range"
        n += math.sqrt(sum((b - a).magnitude for a, b in zip([prev, *pts[:-1]], pts)) / flat) + 4 if len(pts) > 1 else 1
        prev = c.end
        if n > MAX_PATH_VERTICES:
            return f"more than {MAX_PATH_VERTICES} vertices when flattened"
    return None


def _flatten(path, flat: float) -> list[Vec2] | None:
    """The path's vertices, `flat` apart at most from its curves; None where _path_problem() rejects it."""
    if _path_problem(path, flat):
        return None
    return [Vec2(v) for v in path.flattening(flat)]


def _bad_geometry(e, flat: float) -> str | None:
    """Why an entity is not read, or None: a point, size or angle that is not a finite number within MAX_COORD, or a
    boundary _path_problem() rejects. Checked once per entity, where the drawing is read."""
    t = e.dxftype()
    try:
        if t in ("LWPOLYLINE", "HATCH", "MPOLYGON") or t == "POLYLINE" and e.is_2d_polyline:
            for p in (epath.from_hatch(e) if t in ("HATCH", "MPOLYGON") else [epath.make_path(e)]):
                why = _path_problem(p, flat)
                if why:
                    return why
        vals = []
        for a in POINT_ATTRS:
            if e.dxf.is_supported(a) and e.dxf.hasattr(a):
                v = e.dxf.get(a)
                vals += list(v) if hasattr(v, "__iter__") else [v]
    except Exception:  # noqa: BLE001 - what ezdxf cannot convert, the readers below skip
        return None
    return None if _finite(*vals) else "coordinates that are not finite numbers within the drawing's range"


def _extents(entities) -> BBox | None:
    """The extents of the entities, leaving out any whose own extents _finite() rejects (one NaN or far point would
    make the frame of the whole layout useless)."""
    try:
        b = ebbox.extents(entities, fast=True)
        if not b.has_data:
            return None
        box = (b.extmin.x, b.extmin.y, b.extmax.x, b.extmax.y)
        if _finite(*box):
            return box
        boxes = [(x.extmin.x, x.extmin.y, x.extmax.x, x.extmax.y) for x in ebbox.multi_flat(entities, fast=True) if x.has_data]
    except Exception:  # noqa: BLE001 - no frame: the tokens' own extents are used
        return None
    boxes = [x for x in boxes if _finite(*x)]
    return _union_box(boxes) if boxes else None


# ---------------------------------------------------------------- walking

def _hidden_layers(doc) -> set[str]:
    out = set()
    for lay in doc.layers:
        if lay.is_off() or lay.is_frozen() or lay.dxf.get("plot", 1) == 0:
            out.add(lay.dxf.name.lower())
    return out


def _expand(insert):
    try:
        if insert.mcount > MAX_ENTITIES:   # a MINSERT array of more copies than a layout may hold
            return
        for ins in (insert.multi_insert() if insert.mcount > 1 else [insert]):
            yield from ins.virtual_entities()
    except Exception:  # noqa: BLE001 - a block ezdxf cannot transform is skipped and counted by the caller
        return


def _walk(entities, hidden: set[str], key: str = "", depth: int = 0, chain: tuple = ()):
    """Every visible entity with a stable key (top-level handle, then index paths) and its enclosing INSERTs."""
    for i, e in enumerate(entities):
        layer = e.dxf.get("layer", "0")
        # `invisible` is not an attribute of every entity type (a BLOCK written among the entities has none)
        if (e.dxf.is_supported("invisible") and e.dxf.get("invisible", 0)) or not isinstance(layer, str) or layer.lower() in hidden:
            continue
        k = e.dxf.handle if depth == 0 and e.dxf.handle else f"{key}/{i}"
        yield e, k, chain
        if e.dxftype() == "INSERT" and depth < MAX_DEPTH:
            yield from _walk(list(_expand(e)), hidden, k, depth + 1, chain + (e,))


def _ext(e) -> BBox | None:
    try:
        b = ebbox.extents([e], fast=True)
    except Exception:  # noqa: BLE001
        return None
    if not b.has_data or not _finite(b.extmin.x, b.extmin.y, b.extmax.x, b.extmax.y):
        return None
    return (b.extmin.x, b.extmin.y, b.extmax.x, b.extmax.y)


def _bbox_of(points) -> BBox:
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    return (min(xs), min(ys), max(xs), max(ys))


# ---------------------------------------------------------------- text

def _text_tokens(e, sheet: Sheet, chain: tuple, units: Units | None) -> list[Token]:
    t = e.dxftype()
    if t in ("TEXT", "ATTRIB"):
        if t == "ATTRIB" and e.is_invisible:
            return []
        s = e.plain_text().strip()
        box = _ext(e) if s else None
        if not box:
            return []
        extra = {"layer": e.dxf.layer}
        if t == "ATTRIB":
            extra |= {"tag": e.dxf.tag, "block": chain[-1].dxf.name if chain else None}
        rot = e.dxf.get("rotation", 0.0)
        if not _finite(rot):
            return []
        return [Token(s, box, sheet, angle=round(rot, 1), source="dxf", extra=extra)]
    if t == "MTEXT":
        lines = [ln.strip() for ln in e.plain_text(split=True)]
        box = _ext(e)
        if not box or not any(lines):
            return []
        rot = e.get_rotation()
        if not _finite(rot):
            return []
        rot = round(rot, 1)
        out = []
        n = len(lines)
        for i, ln in enumerate(lines):
            if not ln:
                continue
            x0, y0, x1, y1 = box
            if abs(rot) < 0.5 and n > 1:  # lines share the box top to bottom
                h = (y1 - y0) / n
                b = (x0, y1 - (i + 1) * h, x1, y1 - i * h)
            else:
                b = box
            out.append(Token(ln, b, sheet, angle=rot, source="dxf", extra={"layer": e.dxf.layer, "mtext_line": i, "mtext_lines": n}))
        return out
    if t == "DIMENSION":
        d = _dimension(e, units, paper=sheet.layout != "Model")
        if not d or not d["text"]:
            return []
        extra = {"layer": e.dxf.layer, "dimtype": d["dimtype"], "measurement": d["measurement"]}
        if d.get("value"):
            extra["value"] = d["value"]
        return [Token(d["text"], d["bbox"], sheet, angle=0.0, source="dxf", extra=extra)]
    return []


def _dimension(e, units: Units | None, paper: bool = False) -> dict | None:
    dimtype = e.dimtype
    try:
        m = e.get_measurement()
    except Exception:  # noqa: BLE001
        m = None
    meas, lfac = None, 1.0
    if isinstance(m, (int, float)) and math.isfinite(m):
        try:
            lfac = float(e.override().get("dimlfac", 1.0) or 1.0)
        except Exception:  # noqa: BLE001
            lfac = 1.0
        if lfac < 0:  # a negative DIMLFAC applies in paper space only
            lfac = -lfac if paper else 1.0
        meas = abs(m) * lfac  # the value the dimension states: the measured length times DIMLFAC
    pts = [e.dxf.get(a) for a in ("defpoint", "defpoint2", "defpoint3", "text_midpoint")]
    pts = [(p.x, p.y) for p in pts if p is not None]
    if not pts or not _finite(*(c for p in pts for c in p)):
        return None
    x0, y0, x1, y1 = _bbox_of(pts)
    # the displayed text, as the drawing shows it
    shown = None
    try:
        blk = e.get_geometry_block()
        if blk is not None:
            shown = " ".join(x.plain_text(split=False).replace("\n", " ") for x in blk if x.dxftype() == "MTEXT").strip() or None
    except Exception:  # noqa: BLE001
        shown = None
    override = e.dxf.get("text", "")
    if shown is None:
        auto = units.length(meas) if (units and meas is not None) else (f"{meas:g}" if meas is not None else "")
        shown = auto if override in ("", "<>") else override.replace("<>", auto)
    return {"text": shown.strip(), "bbox": (x0, y0, x1, y1), "dimtype": dimtype, "measurement": meas, "dimlfac": lfac,
            "value": units.length(meas) if (units and meas is not None) else None,
            "p1": e.dxf.get("defpoint2"), "p2": e.dxf.get("defpoint3"), "angle": e.dxf.get("angle", 0.0)}


# ---------------------------------------------------------------- primitives and swings

def _prims(entities, flat: float, depth: int = 0) -> list[tuple]:
    """Lines, arcs and polylines of a group of entities, nested blocks flattened, in WCS."""
    out = []
    for e in entities:
        t = e.dxftype()
        if t == "LINE":
            a, b = Vec2(e.dxf.start), Vec2(e.dxf.end)
            if _finite(a.x, a.y, b.x, b.y):
                out.append(("line", a, b))
        elif t == "ARC":
            try:
                c = Vec2(e.ocs().to_wcs(e.dxf.center))
                sweep = (e.dxf.end_angle - e.dxf.start_angle) % 360 or 360
                a, b = Vec2(e.start_point), Vec2(e.end_point)
            except Exception:  # noqa: BLE001 - an arc ezdxf cannot place
                continue
            if _finite(c.x, c.y, e.dxf.radius, a.x, a.y, b.x, b.y, sweep):
                out.append(("arc", c, e.dxf.radius, a, b, sweep))
        elif t in ("LWPOLYLINE", "POLYLINE"):
            if t == "POLYLINE" and not e.is_2d_polyline:
                continue
            try:
                pts = _flatten(epath.make_path(e), flat)
            except Exception:  # noqa: BLE001
                continue
            if pts is None:
                continue
            closed = e.closed if t == "LWPOLYLINE" else e.is_closed
            if len(pts) >= 2:
                out.append(("poly", pts, closed))
        elif t == "INSERT" and depth < MAX_DEPTH:
            out += _prims(_expand(e), flat, depth + 1)
    return out


def _swings(prims: list[tuple], units: Units, bare_arcs: bool = False) -> list[dict]:
    """Door swings: a leaf (line, or a rectangle's long edge) from the centre of an arc to one of its ends.
    With `bare_arcs` (a block named as a door), an arc alone of a door's size also counts."""
    lo, hi = units.from_mm(LEAF_MM[0]), units.from_mm(LEAF_MM[1])
    lines, curves = [], []
    for p in prims:
        if p[0] == "line":
            lines.append((p[1], p[2]))
        elif p[0] == "arc":
            curves.append({"a": p[3], "b": p[4], "c": p[1], "r": p[2], "sweep": p[5], "pts": None})
        elif p[0] == "poly":
            pts, closed = p[1], p[2]
            if closed:
                ring = pts + [pts[0]]
                lines += [(a, b) for a, b in zip(ring, ring[1:]) if (b - a).magnitude > 0]
            elif len(pts) >= 3:
                curves.append({"a": pts[0], "b": pts[-1], "c": None, "r": None, "sweep": None, "pts": pts})
    out, seen = [], set()
    for a, b in lines:
        L = (b - a).magnitude
        if not lo <= L <= hi:
            continue
        tol = SWING_TOL * L
        for h, t in ((a, b), (b, a)):
            for c in curves:
                for tip, other in ((c["a"], c["b"]), (c["b"], c["a"])):
                    if (tip - t).magnitude > tol:
                        continue
                    if c["pts"] is None:
                        if (c["c"] - h).magnitude > tol or abs(c["r"] - L) > tol:
                            continue
                    elif any(abs((q - h).magnitude - L) > tol for q in c["pts"]):
                        continue
                    sweep = math.degrees((t - h).angle_between(other - h)) if (other - h).magnitude else 0
                    if not 15 <= sweep <= 181:
                        continue
                    k = (round(h.x / tol), round(h.y / tol), round(other.x / tol), round(other.y / tol))
                    if k in seen:
                        continue
                    seen.add(k)
                    out.append({"hinge": h, "r": L, "open": t, "closed": other, "sweep": sweep})
    if bare_arcs and not out:
        for c in curves:
            if c["pts"] is None and lo <= c["r"] <= hi and 15 <= c["sweep"] <= 181:
                out.append({"hinge": c["c"], "r": c["r"], "open": c["b"], "closed": c["a"], "sweep": c["sweep"], "bare": True})
    return out


def _swing_box(sw: dict) -> BBox:
    """Hinge, both ends of the swing, and the middle of the arc."""
    h = sw["hinge"]
    pts = [h, sw["open"], sw["closed"]]
    bis = (sw["open"] - h).normalize() + (sw["closed"] - h).normalize()
    if bis.magnitude > 1e-9:
        pts.append(h + bis.normalize(sw["r"]))
    return _bbox_of([(p.x, p.y) for p in pts])


def _union_box(boxes) -> BBox:
    boxes = list(boxes)
    return (min(b[0] for b in boxes), min(b[1] for b in boxes), max(b[2] for b in boxes), max(b[3] for b in boxes))


# ---------------------------------------------------------------- polygons

def _polygons(e, flat: float) -> list[Polygon]:
    t = e.dxftype()
    try:
        if t == "LWPOLYLINE" and e.closed or t == "POLYLINE" and e.is_2d_polyline and e.is_closed:
            paths = [epath.make_path(e)]
        elif t == "HATCH" or t == "MPOLYGON":
            paths = list(epath.from_hatch(e))
        else:
            return []
        rings = [_flatten(p, flat) for p in paths]
    except Exception:  # noqa: BLE001
        return []
    if any(r is None for r in rings):
        return []
    polys = []
    for r in rings:
        if len(r) >= 3:
            p = Polygon([(v.x, v.y) for v in r])
            if not p.is_valid:
                p = p.buffer(0)
            # the room's geometry stays bounded: a boundary that repairs into more vertices is not a room's
            if not p.is_empty and p.area > 0 and shapely.get_num_coordinates(p) <= MAX_ROOM_VERTICES:
                polys.append(p)
    if t in ("HATCH", "MPOLYGON") and len(polys) > 1:  # outer boundary less the islands inside it
        polys.sort(key=lambda p: -p.area)
        outer, rest = polys[0], []
        for p in polys[1:]:
            if outer.contains(p.representative_point()):
                outer = outer.difference(p)
            else:
                rest.append(p)
        polys = [g for g in [outer, *rest] if isinstance(g, Polygon) and g.area > 0]
    return polys


# ---------------------------------------------------------------- one file

def _obs(value, at: str, note: str | None = None) -> list[dict]:
    o = {"value": value, "at": at}
    if note:
        o["note"] = note
    return [o]


def _annotate(tokens: list[Token], sheet: Sheet, state: dict, frame: BBox | None = None) -> dict:
    """Notes, room tags, stair annotations and schedules from adapters.drawings.annotations, the same reader
    PDF sheets use, as {"facts", "elements", "sheet": {number, title}, "skipped"} in evidence-document form.

    annotations reads page coordinates (y down from the top-left corner): its lines, "name over number"
    tags, reading order and title-block position depend on it. DXF is y up, so the tokens are handed over
    in the layout's frame turned upside down (x' = x - x0, y' = y1 - y, `frame` = (x0, y0, x1, y1), the
    layout's extents) and every locator in the reading is mapped back to drawing units, y up."""
    if not tokens:
        return {}
    try:
        from .drawings import annotations
    except ImportError:
        state["annotations"] = "adapters.drawings.annotations is not available: notes, room tags, stair annotations and schedules were not read"
        return {}
    fx0, fy0, fx1, fy1 = frame or _union_box(t.bbox for t in tokens)
    page = dataclasses.replace(sheet, width=fx1 - fx0, height=fy1 - fy0)

    def flip(b: BBox) -> BBox:
        return (b[0] - fx0, fy1 - b[3], b[2] - fx0, fy1 - b[1])

    def unflip(b: BBox) -> BBox:
        return (b[0] + fx0, fy1 - b[3], b[2] + fx0, fy1 - b[1])

    down = [Token(t.text, flip(t.bbox), page, t.confidence, t.angle, t.source, dict(t.extra)) for t in tokens]
    r = annotations.read(page, down)
    sheet.number = sheet.number or page.number
    sheet.title = sheet.title or page.title

    def back(at):
        loc = parse_locator(at) if isinstance(at, str) else None
        if not loc or loc["file"] != sheet.file or loc["layout"] != sheet.layout or loc["page"]:
            return at
        return locator(sheet, unflip(loc["bbox"]))

    def fix(x):
        if isinstance(x, dict):
            return {k: ([back(a) for a in v] if k == "at" and isinstance(v, list) else back(v) if k == "at" else fix(v)) for k, v in x.items()}
        if isinstance(x, list):
            return [fix(v) for v in x]
        return x

    skipped = [f"{sheet.file} {sheet.layout}: {s.get('reason')}: {s.get('text')!r} ({back(s.get('at'))})" if isinstance(s, dict) else str(s)
               for s in (getattr(r, "skipped", None) or [])]
    return {"facts": fix(r.facts), "elements": [fix(e) for e in r.elements.values()], "skipped": skipped,
            "sheet": {"number": sheet.number, "title": sheet.title}}


def _viewports(doc) -> dict[str, list[tuple[BBox, float]]]:
    """Paper layout -> [(model-space window, scale)] of its viewports (twisted views left out)."""
    out = {}
    for lay in doc.layouts:
        if lay.is_modelspace:
            continue
        for v in lay.query("VIEWPORT"):
            if v.dxf.get("id", 0) == 1 or not v.dxf.get("view_height") or abs(v.dxf.get("view_twist_angle", 0)) > 0.01:
                continue
            c, h = v.dxf.view_center_point, v.dxf.view_height
            w = h * v.dxf.width / v.dxf.height if v.dxf.height else 0
            if not _finite(c.x, c.y, h, w, v.dxf.height) or w <= 0:
                continue
            out.setdefault(lay.name, []).append(((c.x - w / 2, c.y - h / 2, c.x + w / 2, c.y + h / 2), v.dxf.height / h))
    return out


def analyse_file(path: Path, rel: str, progress=lambda m: None) -> dict:
    t0 = time.time()
    doc = read(path)
    units, units_problem = units_of(doc)
    hidden = _hidden_layers(doc)
    skipped: list[str] = []
    state: dict = {}
    count = Counter()
    bad: Counter = Counter()   # reason -> entities not read for it
    if units is None:
        skipped.append(f"{rel}: {units_problem}")
    upm = units.per_metre if units else None
    flat = units.from_mm(2) if units else 1.0  # curves flattened to 2 mm
    msp = doc.modelspace()

    # --- sheets: Model, then paper layouts with content
    sheets_meta = []
    layouts = [msp] + [lay for lay in doc.layouts if not lay.is_modelspace and len(lay) > 0]
    paper_tokens: dict[str, list[Token]] = {}
    frames: dict[str, BBox] = {}  # layout -> extents, the frame annotations reads it in
    for lay in layouts:
        box = _extents(lay)
        if box:
            frames[lay.name] = box
    for lay in layouts[1:]:
        sh = Sheet(rel, layout=lay.name, text="dxf")
        toks = []
        for n, (e, _k, chain) in enumerate(_walk(lay, hidden)):
            if n >= MAX_ENTITIES:
                bad[f"beyond the first {MAX_ENTITIES} entities of layout {lay.name!r}"] += 1
                break
            if e.dxftype() in ("TEXT", "MTEXT", "ATTRIB", "DIMENSION"):
                toks += _text_tokens(e, sh, chain, None)
            if e.dxftype() == "INSERT":
                for a in e.attribs:
                    toks += _text_tokens(a, sh, chain + (e,), None)
        if lay.name.strip() and any(t.text.strip() == lay.name.strip() for t in toks):
            sh.number = lay.name.strip()  # the sheet carries its layout name as text, as title blocks do
        # the sheet size from the layout's plot settings (always in mm in DXF), in drawing units
        pl = lay.dxf_layout.dxf
        pw, ph = pl.get("paper_width", 0) or 0, pl.get("paper_height", 0) or 0
        if units and _finite(pw, ph) and pw > 0 and ph > 0:
            if pl.get("plot_rotation", 0) in (1, 3):
                pw, ph = ph, pw
            sh.width, sh.height = units.from_mm(pw), units.from_mm(ph)
        elif lay.name in frames:
            f = frames[lay.name]
            sh.width, sh.height = f[2] - f[0], f[3] - f[1]
        paper_tokens[lay.name] = toks
        sheets_meta.append(sh)

    # --- model space: one walk for text and geometry
    progress(f"DXF {rel}: reading model space")
    model_sheet = Sheet(rel, layout="Model", text="dxf", units_per_metre=upm)
    model_tokens: list[Token] = []
    door_blocks: dict[str, dict] = {}  # block name -> local analysis
    doors: list[dict] = []
    door_ids = set()        # id() of INSERTs read as doors (their content is not loose door geometry)
    loose_door: list = []
    loose_layers: set[str] = set()
    room_polys: list[dict] = []  # {poly, layer, room_layer, key}
    walls: list = []
    glazing: list = []
    stair_lines: dict[str, list] = {}
    dims: list[dict] = []
    attr_tags: list[dict] = []
    for n, (e, k, chain) in enumerate(_walk(msp, hidden)):
        if n >= MAX_ENTITIES:
            bad[f"beyond the first {MAX_ENTITIES} entities of model space"] += 1
            break
        t = e.dxftype()
        layer = e.dxf.get("layer", "0")
        why = _bad_geometry(e, flat)
        if why is None and t == "INSERT" and not (isinstance(e.dxf.get("name"), str) and e.dxf.get("name")):
            why = "no block name"
        if why:
            bad[f"{t} with {why}"] += 1
            continue
        if t in ("TEXT", "MTEXT", "DIMENSION"):
            model_tokens += _text_tokens(e, model_sheet, chain, units)
        if t == "DIMENSION" and units:
            d = _dimension(e, units)
            if d and d["measurement"] and d["dimtype"] in (0, 1) and d["p1"] is not None and d["p2"] is not None:
                if abs(d["dimlfac"] - 1) > 1e-3:  # states a length other than the one it spans (a scaled detail)
                    count["dimlfac"] += 1
                else:
                    d["at"] = locator(model_sheet, d["bbox"])
                    dims.append(d)
        if t == "INSERT":
            per_attrib = [(a, _text_tokens(a, model_sheet, chain + (e,), units)) for a in e.attribs]
            model_tokens += [tok for _, ts in per_attrib for tok in ts]
            name = e.dxf.name
            if units:
                info = door_blocks.get(name)
                if info is None:
                    info = door_blocks[name] = _door_block_info(doc, name, units, flat)
                if info["door"]:
                    d = _door_from_insert(e, k, info, units, flat, rel, model_sheet, skipped)
                    door_ids.add(id(e))
                    if d:
                        doors.append(d)
            tag = _room_tag(e, per_attrib)
            if tag:
                attr_tags.append(tag)
        if not units:
            continue
        inside_door = any(id(c) in door_ids for c in chain)
        in_window = any(WINDOW_BLOCK.search(c.dxf.name) for c in chain)
        in_stair = next((c for c in chain if STAIR_BLOCK.search(c.dxf.name)), None)
        if t in ("LINE", "ARC", "LWPOLYLINE", "POLYLINE") and DOOR_LAYER.search(layer) and not inside_door:
            loose_door += _prims([e], flat)
            loose_layers.add(layer)
        if t in ("LWPOLYLINE", "POLYLINE", "HATCH", "MPOLYGON") and not inside_door:
            if WALL_LAYER.search(layer):
                walls += _polygons(e, flat)
            elif not NOT_ROOM_LAYER.search(layer) or ROOM_LAYER.search(layer):
                for p in _polygons(e, flat):
                    room_polys.append({"poly": p, "layer": layer, "room_layer": bool(ROOM_LAYER.search(layer)), "key": k, "type": t})
        if t in ("LINE", "LWPOLYLINE", "POLYLINE") and not inside_door:
            if WALL_LAYER.search(layer):
                walls += [LineString([(a.x, a.y), (b.x, b.y)]) for a, b in _segments(e, flat)]
            elif GLAZ_LAYER.search(layer) or in_window:
                glazing += [LineString([(a.x, a.y), (b.x, b.y)]) for a, b in _segments(e, flat)]
        if t == "LINE" and (STAIR_LAYER.search(layer) or in_stair is not None):
            group = f"block {in_stair.dxf.name} {k.rsplit('/', 1)[0]}" if in_stair is not None else f"layer {layer}"
            stair_lines.setdefault(group, []).append((Vec2(e.dxf.start), Vec2(e.dxf.end), k))
    count["tokens"] = len(model_tokens)
    for why, n in sorted(bad.items()):
        skipped.append(f"{rel}: {n} entit{'y' if n == 1 else 'ies'} {why}: not read")
    if count["dimlfac"]:
        skipped.append(f"{rel}: {count['dimlfac']} linear dimension(s) with DIMLFAC other than 1 (scaled details): not used for widths or tread depths")

    elements: list[dict] = []
    facts: dict = {}

    # --- loose door swings
    if units and loose_door:
        sws = _swings(loose_door, units)
        used = set()
        for i, a in enumerate(sws):
            if i in used:
                continue
            pair = None
            for j in range(i + 1, len(sws)):
                b = sws[j]
                if j in used:
                    continue
                tol = SWING_TOL * max(a["r"], b["r"])
                if (a["closed"] - b["closed"]).magnitude <= tol and abs((a["hinge"] - b["hinge"]).magnitude - (a["r"] + b["r"])) <= 2 * tol:
                    pair = j
                    break
            group = [a] + ([sws[pair]] if pair is not None else [])
            used |= {i} | ({pair} if pair is not None else set())
            doors.append(_door(group, None, f"dxf:{rel}:swing@{round(a['hinge'].x, 1)},{round(a['hinge'].y, 1)}",
                               units, model_sheet, f"door swing{'s' if len(group) > 1 else ''} drawn on layer(s) "
                               f"{', '.join(sorted(loose_layers))}"))
    count["doors"] = len(doors)

    # --- model tokens grouped by the paper sheet whose viewport shows them
    vps = _viewports(doc)
    by_sheet: dict[str | None, list[Token]] = {}
    for tok in model_tokens:
        cx, cy = (tok.bbox[0] + tok.bbox[2]) / 2, (tok.bbox[1] + tok.bbox[3]) / 2
        best, scale = None, 0.0
        for name, wins in vps.items():
            for (x0, y0, x1, y1), s in wins:
                if x0 <= cx <= x1 and y0 <= cy <= y1 and s > scale:
                    best, scale = name, s
        by_sheet.setdefault(best, []).append(tok)
    paper = {s.layout: s for s in sheets_meta}
    annotated: list[dict] = []
    for name, toks in by_sheet.items():
        sh = Sheet(rel, layout="Model", text="dxf", units_per_metre=upm,
                   number=paper[name].number if name in paper else None, title=paper[name].title if name in paper else None)
        for tok in toks:
            tok.sheet = sh
        annotated.append(_annotate(toks, sh, state, frames.get(msp.name)))
    for name, toks in paper_tokens.items():
        res = _annotate(toks, paper[name], state, frames.get(name))
        if res.get("sheet"):
            paper[name].number = res["sheet"].get("number") or paper[name].number
            paper[name].title = res["sheet"].get("title") or paper[name].title
        annotated.append(res)
    for res in annotated:
        for k2, obs in (res.get("facts") or {}).items():
            facts.setdefault(k2, []).extend(obs)
        elements += res.get("elements") or []
        skipped += res.get("skipped") or []

    # --- room tags: attribute blocks, and Space elements the annotations read from model space
    tags = list(attr_tags)
    for el in elements:
        if el.get("type") != "Space":
            continue
        for a in el.get("at") or []:
            loc = parse_locator(a)
            if loc and loc["file"] == rel and loc["layout"] == "Model":
                b = loc["bbox"]
                tags.append({"point": ((b[0] + b[2]) / 2, (b[1] + b[3]) / 2), "bbox": b, "element": el, "at": a,
                             "name": _first(el, "name"), "number": _first(el, "number")})
                break
    if units:
        tags += _name_tags(model_tokens, [t["bbox"] for t in tags], rel, model_sheet, state)

    spaces: list[dict] = []
    travel = None
    if units:
        spaces, faces = _spaces(room_polys, walls, glazing, doors, tags, units, rel, model_sheet, skipped, count)
        elements += [s for s in spaces if s.get("_new")]
        elements += _corridors(spaces, dims, units, rel, model_sheet)
        elements += _stairs(stair_lines, dims, units, rel, model_sheet, skipped)
        progress(f"DXF {rel}: travel distances")
        travel = _egress(spaces, faces, doors, units, rel, model_sheet, skipped)
    for s in spaces:
        s.pop("_new", None)
        s.pop("_poly", None)
        s.pop("_region", None)
    elements = _door_tags(elements, doors, rel)
    for d in doors:
        d.pop("_swings", None)
        elements.append(d)

    if state.get("annotations"):
        skipped.append(f"{rel}: {state['annotations']}")
    drop_implausible(facts, elements, skipped)
    counts = Counter(e["type"] for e in elements)
    f = frames.get(msp.name)
    model_ext = (f[2] - f[0], f[3] - f[1]) if f else None
    sheet_rows = []
    if len(msp):
        sheet_rows.append({"file": rel, "layout": "Model", "number": None, "title": None,
                           "width": round(model_ext[0], 1) if model_ext else 0, "height": round(model_ext[1], 1) if model_ext else 0,
                           "text": "dxf", "tokens": len(model_tokens)})
    for sh in sheets_meta:
        sheet_rows.append({"file": rel, "layout": sh.layout, "number": sh.number, "title": sh.title, "width": round(sh.width, 1),
                           "height": round(sh.height, 1), "text": "dxf", "tokens": len(paper_tokens[sh.layout])})
    return {
        "file": {"file": rel, "units": units.name if units else None, "units_from": units.how if units else None,
                 "dxfversion": doc.dxfversion, "layouts": [s["layout"] for s in sheet_rows],
                 "counts": {**dict(sorted(counts.items())), "tokens": len(model_tokens) + sum(len(v) for v in paper_tokens.values())},
                 **({"travel_distance": travel} if travel else {}),
                 "seconds": round(time.time() - t0, 2)},
        "facts": facts, "elements": elements, "sheets": sheet_rows, "skipped": skipped,
    }


def _first(el: dict, attr: str):
    obs = (el.get("facts") or {}).get(attr) or []
    return obs[0]["value"] if obs else None


def _segments(e, flat: float):
    t = e.dxftype()
    if t == "LINE":
        return [(Vec2(e.dxf.start), Vec2(e.dxf.end))]
    try:
        pts = _flatten(epath.make_path(e), flat)
    except Exception:  # noqa: BLE001
        return []
    return list(zip(pts, pts[1:])) if pts else []


# ---------------------------------------------------------------- doors

def _door_block_info(doc, name: str, units: Units, flat: float) -> dict:
    """Is this block a door: named as one and holding a swing, or small and holding one or two swings."""
    blk = doc.blocks.get(name)
    if blk is None:
        return {"door": False}
    named = bool(DOOR_BLOCK.search(name))
    if not named and not any(e.dxftype() in ("ARC", "LWPOLYLINE", "POLYLINE", "INSERT") for e in blk):
        return {"door": False}
    prims = _prims(blk, flat)
    sws = _swings(prims, units, bare_arcs=named)
    if named:
        return {"door": True, "named": True, "swings": len(sws)}
    if not 1 <= len(sws) <= 2 or any(s.get("bare") for s in sws):
        return {"door": False}
    pts = [p for pr in prims for p in ([pr[1], pr[2]] if pr[0] == "line" else [pr[3], pr[4]] if pr[0] == "arc" else pr[1])]
    x0, y0, x1, y1 = _bbox_of([(p.x, p.y) for p in pts])
    size = max(x1 - x0, y1 - y0)
    return {"door": size <= 2.6 * max(s["r"] for s in sws) + units.from_mm(400), "named": False, "swings": len(sws)}


def _door_from_insert(e, key: str, info: dict, units: Units, flat: float, rel: str, sheet: Sheet, skipped: list) -> dict | None:
    name = e.dxf.name
    sx, sy = abs(e.dxf.get("xscale", 1)), abs(e.dxf.get("yscale", 1))
    if not math.isclose(sx, sy, rel_tol=1e-3):
        skipped.append(f"{rel}: door block {name!r} ({key}) is scaled unevenly ({sx:g} x {sy:g}): its swing is not a circle; width not read")
        return None
    sws = _swings(_prims(_expand(e), flat), units, bare_arcs=info.get("named", False))
    mark = None
    for a in e.attribs:
        if MARK_TAG.search(a.dxf.tag.strip()) and a.dxf.text.strip():
            mark = a.dxf.text.strip()
            break
    if not sws:
        skipped.append(f"{rel}: door block {name!r} ({key}) has no swing of a door's size ({LEAF_MM[0]}-{LEAF_MM[1]} mm): width not read")
        return None
    if len(sws) > 2:
        skipped.append(f"{rel}: block {name!r} ({key}) holds {len(sws)} swings: not read as one door")
        return None
    own = f"dxf:{rel}:{key}"
    return _door(sws, mark, own, units, sheet, f"block {name!r} swing arc radius" + (f" x insert scale {sx:g}" if sx != 1 else ""))


def _door(sws: list[dict], mark: str | None, own: str, units: Units, sheet: Sheet, how: str) -> dict:
    at = locator(sheet, _union_box(_swing_box(s) for s in sws))
    leaf = max(s["r"] for s in sws)
    leaf_mm = leaf * units.mm
    lo, hi = round(leaf_mm - CLEAR_WIDTH_DEDUCTION_MM[1]), round(leaf_mm - CLEAR_WIDTH_DEDUCTION_MM[0])
    note = f"{how}; leaf width less {CLEAR_WIDTH_DEDUCTION_MM[0]}-{CLEAR_WIDTH_DEDUCTION_MM[1]} mm for leaf thickness and stop"
    facts = {
        "leaf_width": [{"value": units.length(s["r"]), "at": at, "note": how} for s in sorted(sws, key=lambda s: -s["r"])][: (1 if len({round(s["r"], 3) for s in sws}) == 1 else 2)],
        "clear_width": [{"value": f"{lo} mm", "at": at, "note": note}, {"value": f"{hi} mm", "at": at, "note": note}],
        "leaves": _obs(len(sws), at, f"{len(sws)} swing{'s' if len(sws) > 1 else ''} drawn"),
    }
    if mark:
        facts["mark"] = _obs(mark, at, "block attribute")
    return {"type": "Door", "id": f"door:{mark}" if mark else own, "at": [at], "facts": facts, "_swings": sws}


def _door_tags(elements: list[dict], doors: list[dict], rel: str) -> list[dict]:
    """A door tag the annotations read in model space (a Door element with a mark and no width) names the
    one door swing it sits next to: within the swing's size of it, with no other swing as near."""
    def centre(b):
        return ((b[0] + b[2]) / 2, (b[1] + b[3]) / 2)

    boxes = [parse_locator(d["at"][0])["bbox"] for d in doors]
    keep = []
    for el in elements:
        mark = _first(el, "mark") if el.get("type") == "Door" else None
        locs = [loc for a in el.get("at") or [] for loc in [parse_locator(a)] if loc and loc["file"] == rel and loc["layout"] == "Model"]
        if not mark or not locs or "clear_width" in el.get("facts", {}) or "leaf_width" in el.get("facts", {}) or not boxes:
            keep.append(el)
            continue
        tx, ty = centre(locs[0]["bbox"])
        near = []
        for i, b in enumerate(boxes):
            cx, cy = centre(b)
            reach = 1.5 * max(b[2] - b[0], b[3] - b[1])
            dist = math.hypot(tx - cx, ty - cy)
            if dist <= reach:
                near.append((dist, i))
        near.sort()
        if len(near) != 1 or _first(doors[near[0][1]], "mark"):
            keep.append(el)
            continue
        d = doors[near[0][1]]
        d["id"] = f"door:{mark}"
        d["at"] += [a for a in el.get("at") or [] if a not in d["at"]]
        for k, obs in (el.get("facts") or {}).items():
            d["facts"].setdefault(k, []).extend(obs)
    return keep


# ---------------------------------------------------------------- spaces

def _room_tag(e, per_attrib: list) -> dict | None:
    """A room tag block: attributes named for a room's name or number."""
    name = number = None
    toks = [t for _, ts in per_attrib for t in ts]
    for a, _ in per_attrib:
        tag = a.dxf.tag.strip()
        if ROOM_NAME_TAG.search(tag) and a.dxf.text.strip():
            name = a.dxf.text.strip()
        elif ROOM_NUMBER_TAG.search(tag) and a.dxf.text.strip():
            number = a.dxf.text.strip()
    generic = not any(re.match(r"(?i)^(room|rm|space)|室", a.dxf.tag) for a in e.attribs)
    if not (name or number) or (generic and not ROOM_TAG_BLOCK.search(e.dxf.name)):
        return None
    if not _finite(e.dxf.insert.x, e.dxf.insert.y):
        return None
    vis = [t for t in toks if t.text] or None
    b = _union_box(t.bbox for t in vis) if vis else (e.dxf.insert.x, e.dxf.insert.y, e.dxf.insert.x, e.dxf.insert.y)
    return {"point": (e.dxf.insert.x, e.dxf.insert.y), "bbox": b, "name": name, "number": number, "element": None, "at": None}


NAME_TEXT = re.compile(r"^[A-Z][A-Z&/,.' -]*(?: \d{1,2}[A-Z]?)?$")   # words, perhaps a trailing room count ("BEDROOM 3")
NOT_NAME_LAYER = re.compile(r"(?i)dim|grid|door|title|border|^tb|symb|link|furn|fixt|elec|plnt|plmb|equip|eqp|lite|clng|glaz|wind|site")


def _name_tags(tokens: list[Token], taken: list[BBox], rel: str, sheet: Sheet, state: dict) -> list[dict]:
    """Room-name texts on the plan: one upright text of words (no dimension, door mark, note, sheet or
    drawing title) that is a room word (annotations.ROOM_WORDS) or has its room's area or size printed
    directly under it. Whether it names a room is decided by the geometry: only a name inside a
    wall-enclosed area or a room boundary becomes a Space (see _spaces). A room number under the name is
    read as annotations reads tags; the printed area becomes a floor_area interval."""
    try:
        from .drawings import annotations as A
        words, not_room, titles, length, area, norm = A.ROOM_WORDS, A.NOT_ROOM, A.TITLE_WORDS, A.length, A.area, A.norm
        room_no, coded_no = A.ROOM_NUMBER, A.CODED_ROOM_NUMBER
    except (ImportError, AttributeError):
        state.setdefault("annotations", "adapters.drawings.annotations patterns are not available: room names were not read")
        return []

    def upright(t):
        return abs(t.angle % 360) < 1 or abs(t.angle % 360 - 360) < 1

    def size_line(txt):
        parts = re.split(r"\s+[xX×]\s+", norm(txt))
        return len(parts) == 2 and all(length(p) for p in parts)

    # upright tokens by the top of their box, so that under() looks only at the band just below a text
    ups = sorted((u for u in tokens if upright(u)), key=lambda u: u.bbox[3])
    tops = [u.bbox[3] for u in ups]

    def under(t, pick):
        """The text directly under t, centred on it, that `pick` accepts."""
        h = t.bbox[3] - t.bbox[1]
        cx = (t.bbox[0] + t.bbox[2]) / 2
        band = ups[bisect_left(tops, t.bbox[1] - 1.2 * h):bisect_right(tops, t.bbox[1] + 0.3 * h)]
        below = [u for u in band if u is not t and -0.3 * h <= t.bbox[1] - u.bbox[3] <= 1.2 * h
                 and abs((u.bbox[0] + u.bbox[2]) / 2 - cx) <= 0.6 * max(u.bbox[2] - u.bbox[0], t.bbox[2] - t.bbox[0])
                 and 0.5 < (u.bbox[3] - u.bbox[1]) / max(h, 1e-9) < 2.0]
        below = [u for u in below if pick(u.text)]
        return min(below, key=lambda u: t.bbox[1] - u.bbox[3]) if below else None

    def overlaps(b, c):
        return min(b[2], c[2]) > max(b[0], c[0]) and min(b[3], c[3]) > max(b[1], c[1])

    out = []
    for t in tokens:
        u = norm(t.text).upper()
        if (not upright(t) or "dimtype" in t.extra or "tag" in t.extra or NOT_NAME_LAYER.search(t.extra.get("layer", ""))
                or not 2 <= len(u) <= 40 or len(u.split()) > 5 or not NAME_TEXT.match(u) or not re.search(r"[A-Z]{2}", u)
                or not_room.match(u) or titles.search(u) or length(u) or area(u) or any(overlaps(t.bbox, b) for b in taken)):
            continue
        number = under(t, lambda x, u=u: bool(coded_no.match(norm(x).upper()) or (room_no.match(norm(x).upper()) and words.search(u))))
        stated = under(number or t, lambda x: bool(area(x)))
        sized = None if stated else under(number or t, size_line)
        if not (words.search(u) or stated or sized or number):
            continue
        name = norm(t.text)
        box = _union_box([t.bbox] + [x.bbox for x in (number, stated, sized) if x])
        tag = {"point": ((t.bbox[0] + t.bbox[2]) / 2, (t.bbox[1] + t.bbox[3]) / 2), "bbox": t.bbox, "name": name,
               "number": norm(number.text) if number else None, "element": None, "at": None, "kind": "name", "box": box,
               "why": "room word" if words.search(u) else "area printed under it" if stated else "size printed under it" if sized else "room number under it"}
        if number:
            tag["number_at"] = locator(sheet, number.bbox)
        if stated:
            lo, hi = area(stated.text)
            note = f'"{stated.text.strip()}" printed under the room name: printed-precision interval {lo} to {hi}'
            tag["stated"] = [{"value": lo, "at": locator(sheet, stated.bbox), "note": note}, {"value": hi, "at": locator(sheet, stated.bbox), "note": note}]
        out.append(tag)
    return out


def _spaces(room_polys, walls, glazing, doors, tags, units: Units, rel: str, sheet: Sheet, skipped: list, count: Counter) -> list[dict]:
    min_area = (MIN_ROOM_M2 * 1e6) / units.mm ** 2
    cands = [c for c in room_polys if c["poly"].area >= min_area]
    out = []
    faces: list[Polygon] = []

    def tag_area(t):
        b = t["bbox"]
        return max((b[2] - b[0]) * (b[3] - b[1]), 0)

    # each tag to the smallest boundary around it that is clearly bigger than the tag
    held: dict[int, list[dict]] = {}
    free = []
    for t in tags:
        pt = Point(t["point"])
        # a name text counts inside room/area-layer boundaries only: any closed shape (a table cell, a fixture) may hold a word
        inside = [i for i, c in enumerate(cands) if c["poly"].area > 20 * tag_area(t) and c["poly"].contains(pt)
                  and (c["room_layer"] or t.get("kind") != "name")]
        if inside:
            held.setdefault(min(inside, key=lambda i: cands[i]["poly"].area), []).append(t)
        else:
            free.append(t)
    for i, c in enumerate(cands):
        ts = held.get(i, [])
        if not c["room_layer"] and len(ts) != 1:
            if len(ts) > 1:
                skipped.append(f"{rel}: boundary {c['key']} on layer {c['layer']!r} holds {len(ts)} room tags: not read as a room")
            continue
        how = f"{c['type']} {c['key']} on layer {c['layer']!r}, area computed"
        if len(ts) > 1:
            skipped.append(f"{rel}: area boundary {c['key']} holds {len(ts)} room tags: area read, not attributed to a tag")
        out.append(_space(c["poly"], ts[0] if len(ts) == 1 else None, f"dxf:{rel}:{c['key']}", units, sheet, how))

    # faces enclosed by walls (doors closed at the leaf, windows bridged), for tags still free
    if free and walls:
        eps = units.from_mm(10)
        parts = [g.buffer(eps) for g in walls] + [g.buffer(eps) for g in glazing]
        for d in doors:
            for s in d.get("_swings", []):
                parts.append(LineString([(s["hinge"].x, s["hinge"].y), (s["closed"].x, s["closed"].y)]).buffer(eps))
        solid = unary_union(parts)
        faces = []
        for g in getattr(solid, "geoms", [solid]):
            for ring in getattr(g, "interiors", []):
                f = Polygon(ring).buffer(eps, join_style=2)
                if f.area >= min_area:
                    faces.append(f)
        inner = {}
        for t in free:
            pt = Point(t["point"])
            hits = [i for i, f in enumerate(faces) if f.contains(pt)]
            if hits:
                inner.setdefault(min(hits, key=lambda i: faces[i].area), []).append(t)
        for i, ts in inner.items():
            if len(ts) == 1:
                out.append(_space(faces[i], ts[0], f"dxf:{rel}:face{i}", units, sheet,
                                  "net area inside the walls, doors closed at the leaf and windows bridged, computed"))
            else:
                skipped.append(f"{rel}: {len(ts)} room tags share one enclosed area (open plan): floor areas not computed for "
                               + ", ".join(str(t.get("name") or t.get("number") or "?") for t in ts))
                for t in ts:
                    if t.get("kind") == "name":
                        el = _space(None, t, f"dxf:{rel}:tag{i}", units, sheet, "")
                        el["_region"] = faces[i]   # walkable, but shared: no one room's travel distance
                        out.append(el)
        placed = {id(t) for v in inner.values() for t in v}
        lost = [t for t in free if id(t) not in placed]
    else:
        lost = list(free)
    names = [t for t in lost if t.get("kind") == "name"]
    if len(lost) > len(names):
        skipped.append(f"{rel}: {len(lost) - len(names)} room tag(s) not inside a closed boundary or wall-enclosed area: no floor area")
    if names:
        skipped.append(f"{rel}: {len(names)} room-name text(s) not inside a wall-enclosed area or room boundary: not read as rooms ("
                       + ", ".join(sorted({str(t['name']) for t in names}))[:300] + ")")
    # names are ids only when unique on the layout: a second "WC" becomes space:WC#2, top to bottom, left to right
    seen: Counter = Counter()
    for el in sorted((e for e in out if e.get("_named")), key=lambda e: (-e["_named"][1], e["_named"][0])):
        seen[el["id"]] += 1
        if seen[el["id"]] > 1:
            el["id"] = f"{el['id']}#{seen[el['id']]}"
    for el in out:
        el.pop("_named", None)
    count["spaces"] = len(out)
    return out, faces


def _space(poly: Polygon | None, tag: dict | None, own: str, units: Units, sheet: Sheet, how: str) -> dict:
    """A Space for a region (`poly`, area computed) and the tag inside it; `poly` None: a named room in an
    open plan, whose floor area cannot be told from its neighbours'."""
    at = locator(sheet, poly.bounds) if poly is not None else None
    area = _obs(units.area(poly.area), at, how + " with shapely") if poly is not None else []
    if tag and tag.get("element") is not None:
        el = tag["element"]
        if area:
            el.setdefault("facts", {}).setdefault("floor_area", []).extend(area)
            if at not in el.setdefault("at", []):
                el["at"].append(at)
            el["_poly"] = poly
        return el
    facts = {"floor_area": area + list((tag or {}).get("stated") or [])}
    if not facts["floor_area"]:
        del facts["floor_area"]
    tat = locator(sheet, tag["bbox"]) if tag else None
    named = tag and tag.get("kind") == "name"
    if tag and tag.get("name"):
        facts["name"] = _obs(tag["name"], tat, f"room name text ({tag['why']}) inside {'the room boundary' if poly is not None else 'an open-plan area'}"
                             if named else "room tag attribute")
    if tag and tag.get("number"):
        facts["number"] = _obs(tag["number"], tag.get("number_at") or tat, "under the room name" if named else "room tag attribute")
    if tag and tag.get("number"):
        id_ = f"space:{tag['number']}"
    elif tag and tag.get("name"):
        id_ = f"space:{tag['name']}"
    else:
        id_ = own
    ats = ([at] if at else []) + ([locator(sheet, tag["box"])] if named else [tat] if tat else [])
    el = {"type": "Space", "id": id_, "at": ats, "facts": facts, "_new": True, "_poly": poly}
    if named and not tag.get("number"):
        el["_named"] = tag["point"]
    return el


EGRESS_ASSUMPTIONS = [
    "the plan is at grade: its exits are exterior doors, a door with a room on one side only",
    "walkable floor: the areas enclosed by walls (door leaves closed, windows bridged) and room boundaries; "
    "furniture and fixtures ignored",
    "rooms in an open-plan area share one walkable area and get no travel distance of their own",
]


def _egress(spaces: list[dict], faces: list[Polygon], doors: list[dict], units: Units, rel: str, sheet: Sheet,
            skipped: list) -> dict | None:
    """Space.exits and Space.travel_distance from the plan, by the same search as adapters.ifc
    (ifc_egress.route_storey, in metres): rooms are the Spaces with a boundary, plus every other enclosed area as
    walkable floor; a door's opening runs between the hinge and the closed end of its leaf (or leaves)."""
    k = units.mm / 1000

    # Rooms either side of a door meet only along its closed leaf (the line that split them): cut a strip there, so
    # the door's passage is their one connection, as walls make it in a model.
    leaves = unary_union([LineString([(s["hinge"].x * k, s["hinge"].y * k), (s["closed"].x * k, s["closed"].y * k)]).buffer(0.06, cap_style="flat")
                          for d in doors for s in d.get("_swings") or []])

    def metres(g):
        return affinity.scale(g, k, k, origin=(0, 0)).difference(leaves)

    rooms = [G.Room(s["id"], f"space {_first(s, 'name') or s['id']}", metres(s["_poly"])) for s in spaces if s.get("_poly") is not None]
    covered = unary_union([r.poly for r in rooms]) if rooms else Polygon()
    for i, f in enumerate(faces):
        fm = metres(f)
        if not covered.is_empty and fm.intersection(covered).area > 0.5 * fm.area:
            continue
        names = [str(_first(s, "name") or s["id"]) for s in spaces if s.get("_region") is f]
        rooms.append(G.Room(f"_area{i}", "open-plan area " + " / ".join(names) if names else "enclosed area with no room name", fm))
    if not rooms or not doors:
        return None
    floor = unary_union([r.poly for r in rooms])
    plan_doors = []
    for d in doors:
        sws = d.get("_swings") or []
        if not sws:
            continue
        h, c = sws[0]["hinge"], sws[0]["closed"]
        u = ((c.x - h.x), (c.y - h.y))
        n = math.hypot(*u)
        u = (u[0] / n, u[1] / n)
        v = (-u[1], u[0])
        pts = [(p.x * k, p.y * k) for s in sws for p in (s["hinge"], s["closed"])]
        pu = [x * u[0] + y * u[1] for x, y in pts]
        pv = sum(s["hinge"].x * k * v[0] + s["hinge"].y * k * v[1] for s in sws) / len(sws)
        mu = (min(pu) + max(pu)) / 2
        centre = (mu * u[0] + pv * v[0], mu * u[1] + pv * v[1])
        opening = G.rectangle(centre, u, v, (max(pu) - min(pu)) / 2, 0.6)
        mark = _first(d, "mark")
        dp = G.door_plan(opening, u, centre, floor, d["id"], f"door {mark}" if mark else f"door at {d['at'][0]}", None)
        if dp is not None:
            plan_doors.append(dp)
            inside = [e.intersection(floor).area > 0.3 * e.area for e in dp.ends]
            if any(inside):
                d["facts"]["is_external"] = _obs(not all(inside), d["at"][0], "a room on one side only of the opening on the plan"
                                                 if not all(inside) else "rooms on both sides of the opening on the plan")
    r = G.route_storey(G.StoreyPlan(f"{rel}:Model", True, rooms, plan_doors, []))
    if r is None:
        return None
    if not r.exits:
        skipped.append(f"{rel}: travel distance: no exterior door (a door with a room on one side only) found on the plan")
        return {"exits": [], "assumptions": EGRESS_ASSUMPTIONS}

    def dist(m: float) -> str:
        return f"{_num(m / 0.3048, 1)} ft" if units.imperial else f"{_num(m, 2)} m"

    by_id = {s["id"]: s for s in spaces}
    for gid, sr in r.spaces.items():
        s = by_id.get(gid)
        if s is None:
            continue
        xs, ys = [p[0] / k for p in sr.path], [p[1] / k for p in sr.path]
        at = locator(sheet, (min(xs), min(ys), max(xs), max(ys)))
        s["facts"]["travel_distance"] = _obs(dist(sr.distance), at, f"geodesic from the farthest point of the space to {sr.exit}, "
                                             f"{len(sr.path) - 1} legs, grid {r.resolution:.2f} m; plan assumed at grade")
        s["facts"]["exits"] = _obs(sr.exits, s["at"][0], "doorways from which an exit is reached without returning through the space")
    lost = [str(_first(by_id[g], "name") or g) for g in r.unreachable if g in by_id]
    if lost:
        skipped.append(f"{rel}: travel distance: no route to an exterior door from " + ", ".join(lost))
    shared = [str(_first(s, "name") or s["id"]) for s in spaces if s.get("_region") is not None]
    if shared:
        skipped.append(f"{rel}: travel distance: open-plan rooms get none of their own (their area is shared): " + ", ".join(shared))
    return {"method": "geodesic to the nearest exterior door inside the walkable floor: grid Dijkstra (16 directions) and "
                      "string-pulling (adapters.ifc_egress)", "resolution": f"{r.resolution:.2f} m", "exits": r.exits,
            "assumptions": EGRESS_ASSUMPTIONS, "seconds": round(r.seconds, 2)}


def _corridors(spaces: list[dict], dims: list[dict], units: Units, rel: str, sheet: Sheet) -> list[dict]:
    """A dimension clearly across a corridor (both ends on its walls, the line through it) gives its clear width."""
    out = []
    for s in spaces:
        name = _first(s, "name")
        poly = s.get("_poly")
        if not name or poly is None or not CORRIDOR_NAME.search(str(name)):
            continue
        across = []
        for d in dims:
            p1, p2 = Vec2(d["p1"]), Vec2(d["p2"])
            tol = max(0.02 * d["measurement"], units.from_mm(10))
            seg = LineString([(p1.x, p1.y), (p2.x, p2.y)])
            if (abs((p2 - p1).magnitude - d["measurement"]) <= tol and poly.exterior.distance(Point(p1.x, p1.y)) <= tol
                    and poly.exterior.distance(Point(p2.x, p2.y)) <= tol and poly.contains(seg.interpolate(0.5, normalized=True))):
                across.append(d)
        if not across:
            continue
        d = min(across, key=lambda d: d["measurement"])
        number = _first(s, "number")
        out.append({"type": "Corridor", "id": f"corridor:{number}" if number else f"corridor:{s['id']}", "at": [d["at"]] + s["at"],
                    "facts": {"clear_width": _obs(d["value"], d["at"], f"dimension across {name}"
                                                  + (f", the smallest of {len(across)}" if len(across) > 1 else ""))}})
    return out


# ---------------------------------------------------------------- stairs

def _stairs(groups: dict[str, list], dims: list[dict], units: Units, rel: str, sheet: Sheet, skipped: list) -> list[dict]:
    out = []
    for group, lines in groups.items():
        flights = _flights(lines)
        if not flights:
            continue
        depths = [f["spacing"] for f in flights]
        st_box = _union_box(f["bbox"] for f in flights)
        at = locator(sheet, st_box)
        facts = {}
        if max(depths) - min(depths) <= 0.02 * max(depths):
            facts["tread_depth"] = _obs(units.length(sum(depths) / len(depths)), at,
                                        f"spacing of {sum(f['count'] for f in flights)} tread lines in {len(flights)} flight(s)")
        else:
            skipped.append(f"{rel}: stair {group}: flights with different tread spacings; tread depth not read")
        for f in flights:
            for d in dims:
                p1, p2 = Vec2(d["p1"]), Vec2(d["p2"])
                u, n = f["u"], f["n"]
                tol = 0.03 * f["length"]
                pu = sorted([p1.dot(u), p2.dot(u)])
                pn = [p1.dot(n), p2.dot(n)]
                if (abs(pu[0] - f["umin"]) <= tol and abs(pu[1] - f["umax"]) <= tol and all(f["nmin"] - f["length"] <= v <= f["nmax"] + f["length"] for v in pn)
                        and abs(d["measurement"] - f["length"]) <= tol):
                    facts.setdefault("width", []).append({"value": d["value"], "at": d["at"], "note": "dimension across the flight"})
                elif abs(d["measurement"] - f["spacing"]) <= 0.02 * f["spacing"] and abs((p2 - p1).dot(n)) >= 0.98 * d["measurement"] \
                        and all(f["umin"] - tol <= v <= f["umax"] + tol for v in (p1.dot(u), p2.dot(u))) \
                        and all(f["nmin"] - tol <= v <= f["nmax"] + tol for v in pn):
                    facts.setdefault("tread_depth", []).append({"value": d["value"], "at": d["at"], "note": "dimension between tread lines"})
        if facts:
            out.append({"type": "Stair", "id": f"dxf:{rel}:stair:{group}", "at": [at], "facts": facts})
    return out


def _flights(lines: list) -> list[dict]:
    """Runs of >= 4 parallel, equal-length, evenly spaced lines overlapping along their length."""
    by_dir: dict[tuple, list] = {}
    for a, b, k in lines:
        v = b - a
        L = v.magnitude
        if L <= 0:
            continue
        ang = round(math.degrees(math.atan2(v.y, v.x)) % 180) % 180
        by_dir.setdefault((ang,), []).append((a, b, L))
    flights = []
    for (ang,), ls in by_dir.items():
        u = Vec2.from_deg_angle(ang)
        n = u.orthogonal()
        ls.sort(key=lambda x: x[2])
        # cluster by length (1%)
        clusters, cur = [], []
        for x in ls:
            if cur and abs(x[2] - cur[0][2]) > 0.01 * cur[0][2]:
                clusters.append(cur)
                cur = []
            cur.append(x)
        if cur:
            clusters.append(cur)
        for cl in clusters:
            L = cl[0][2]
            items = sorted(((a.dot(n), min(a.dot(u), b.dot(u)), max(a.dot(u), b.dot(u))) for a, b, _ in cl))
            run = [items[0]]
            for it in items[1:] + [None]:
                ok = False
                if it is not None:
                    gap = it[0] - run[-1][0]
                    overlap = min(it[2], run[-1][2]) - max(it[1], run[-1][1])
                    first_gap = run[1][0] - run[0][0] if len(run) > 1 else gap
                    ok = gap > 1e-9 and overlap >= 0.9 * L and abs(gap - first_gap) <= 0.02 * first_gap
                if ok:
                    run.append(it)
                    continue
                if len(run) >= STAIR_MIN_TREADS:
                    sp = (run[-1][0] - run[0][0]) / (len(run) - 1)
                    umin, umax = min(r[1] for r in run), max(r[2] for r in run)
                    nmin, nmax = run[0][0], run[-1][0]
                    corners = [u * uu + n * nn for uu in (umin, umax) for nn in (nmin, nmax)]
                    flights.append({"spacing": sp, "count": len(run), "length": L, "u": u, "n": n, "umin": umin, "umax": umax,
                                    "nmin": nmin, "nmax": nmax, "bbox": _bbox_of([(c.x, c.y) for c in corners])})
                if it is not None:
                    run = [run[-1], it] if run and it[0] - run[-1][0] > 1e-9 and min(it[2], run[-1][2]) - max(it[1], run[-1][1]) >= 0.9 * L else [it]
    return flights


# ---------------------------------------------------------------- the adapter

def analyse(files: list[Path], root: Path, describes: str | None = None, progress=lambda m: None) -> dict:
    """DXF drawings -> one evidence document (source id "dxf"), with a top-level `sheets` list."""
    facts: dict = {}
    elements: list[dict] = []
    sheets: list[dict] = []
    file_rows, skipped = [], []
    for p in files:
        rel = Path(p).resolve().relative_to(Path(root).resolve()).as_posix()
        progress(f"DXF {rel}")
        try:
            r = analyse_file(Path(p), rel, progress)
        except Exception as e:  # noqa: BLE001 - one unreadable file must not lose the others
            skipped.append(f"{rel}: not readable as DXF ({type(e).__name__}: {e})")
            continue
        file_rows.append(r["file"])
        for k, obs in r["facts"].items():
            facts.setdefault(k, []).extend(obs)
        elements += r["elements"]
        sheets += r["sheets"]
        skipped += r["skipped"]
    source = {"id": "dxf", "kind": "drawings", "adapter": f"adapters.dxf {VERSION}", "files": file_rows}
    if describes:
        source["describes"] = describes
    if skipped:
        source["skipped"] = skipped
    return {
        "subject": {"kind": "building", "id": describes or (Path(files[0]).stem if files else "drawings")},
        "sources": [source],
        "facts": facts,
        "elements": elements,
        "sheets": sheets,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("dxf", nargs="+")
    ap.add_argument("--root", default=None, help="directory locators are relative to (default: the first file's)")
    ap.add_argument("-o", "--out", required=True)
    a = ap.parse_args()
    files = [Path(f) for f in a.dxf]
    root = Path(a.root) if a.root else files[0].resolve().parent
    doc = analyse(files, root)
    Path(a.out).write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=140))


if __name__ == "__main__":
    main()
