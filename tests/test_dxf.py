"""adapters.dxf: DXF drawings built here with ezdxf, read back into evidence."""

from __future__ import annotations

import sys
import types

import ezdxf
import pytest
from normir.evidence import load_evidence

import adapters.drawings
from adapters import dxf
from adapters.drawings.tokens import parse_locator


def _doc(insunits: int | None = 4, measurement: int | None = None):
    doc = ezdxf.new("R2010", setup=True)
    if insunits is None:
        doc.header["$INSUNITS"] = 0
    else:
        doc.header["$INSUNITS"] = insunits
    if measurement is None:
        del doc.header["$MEASUREMENT"]
    else:
        doc.header["$MEASUREMENT"] = measurement
    return doc


def _door_block(doc, name: str, r: float, mark_attr: bool = True):
    blk = doc.blocks.new(name)
    blk.add_line((0, 0), (0, r), dxfattribs={"layer": "A-DOOR"})
    blk.add_arc((0, 0), r, 0, 90, dxfattribs={"layer": "A-DOOR"})
    if mark_attr:
        blk.add_attdef("MARK", (r / 2, -r / 4), dxfattribs={"height": r / 10})
    return blk


def _room_tag_block(doc):
    blk = doc.blocks.new("ROOMTAG")
    blk.add_attdef("ROOM_NAME", (0, 0), dxfattribs={"height": 200})
    blk.add_attdef("ROOM_NUMBER", (0, -300), dxfattribs={"height": 200})


def _save(doc, tmp_path, name="plan.dxf"):
    p = tmp_path / name
    doc.saveas(p)
    return p


def _run(p, tmp_path):
    return dxf.analyse([p], tmp_path, describes="test")


def _els(doc, type_):
    return [e for e in doc["elements"] if e["type"] == type_]


def _vals(el, attr):
    return [o["value"] for o in el["facts"].get(attr, [])]


@pytest.fixture
def no_annotations(monkeypatch):
    monkeypatch.delattr(adapters.drawings, "annotations", raising=False)
    monkeypatch.setitem(sys.modules, "adapters.drawings.annotations", None)


@pytest.fixture
def stub_annotations(monkeypatch):
    """Stands in for adapters.drawings.annotations: records the tokens, returns what the test sets."""
    seen: dict = {"tokens": [], "reply": lambda tokens, sheet: {}}
    mod = types.ModuleType("adapters.drawings.annotations")

    def read(sheet, tokens):  # the real signature; returns what annotations.Reading carries
        seen["tokens"] += tokens
        d = seen["reply"](tokens, sheet)
        return types.SimpleNamespace(facts=d.get("facts", {}), skipped=[],
                                     elements={(e["type"], e["id"]): e for e in d.get("elements", [])})

    mod.read = read
    monkeypatch.setitem(sys.modules, "adapters.drawings.annotations", mod)
    monkeypatch.setattr(adapters.drawings, "annotations", mod, raising=False)
    return seen


# ---------------------------------------------------------------- spaces


def test_room_polyline_with_tag_is_a_space(tmp_path, no_annotations):
    doc = _doc()
    _room_tag_block(doc)
    msp = doc.modelspace()
    msp.add_lwpolyline([(0, 0), (5000, 0), (5000, 4000), (0, 4000)], close=True, dxfattribs={"layer": "A-AREA"})
    msp.add_blockref("ROOMTAG", (2000, 2000)).add_auto_attribs({"ROOM_NAME": "OFFICE", "ROOM_NUMBER": "101"})
    ev = _run(_save(doc, tmp_path), tmp_path)
    (sp,) = _els(ev, "Space")
    assert sp["id"] == "space:101"
    assert _vals(sp, "floor_area") == ["20 m2"]
    assert _vals(sp, "name") == ["OFFICE"] and _vals(sp, "number") == ["101"]
    loc = parse_locator(sp["at"][0])
    assert loc["file"] == "plan.dxf" and loc["layout"] == "Model" and loc["bbox"] == (0, 0, 5000, 4000)


def test_area_layer_without_tag_keeps_own_id_and_other_layers_are_not_rooms(tmp_path, no_annotations):
    doc = _doc()
    msp = doc.modelspace()
    msp.add_lwpolyline([(0, 0), (3000, 0), (3000, 3000), (0, 3000)], close=True, dxfattribs={"layer": "A-AREA"})
    msp.add_lwpolyline([(5000, 0), (8000, 0), (8000, 3000), (5000, 3000)], close=True, dxfattribs={"layer": "A-FURN"})
    ev = _run(_save(doc, tmp_path), tmp_path)
    (sp,) = _els(ev, "Space")
    assert sp["id"].startswith("dxf:plan.dxf:") and _vals(sp, "floor_area") == ["9 m2"]
    assert "name" not in sp["facts"]


def test_imperial_room_area_in_sqft(tmp_path, no_annotations):
    doc = _doc(insunits=1)
    _room_tag_block(doc)
    msp = doc.modelspace()
    msp.add_lwpolyline([(0, 0), (120, 0), (120, 144), (0, 144)], close=True, dxfattribs={"layer": "ROOM"})
    msp.add_blockref("ROOMTAG", (50, 70), dxfattribs={"xscale": 0.05, "yscale": 0.05}).add_auto_attribs({"ROOM_NAME": "BED", "ROOM_NUMBER": "2"})
    ev = _run(_save(doc, tmp_path), tmp_path)
    (sp,) = _els(ev, "Space")
    assert sp["id"] == "space:2" and _vals(sp, "floor_area") == ["120 sqft"]


# ---------------------------------------------------------------- doors


def test_door_block_mm_with_mark(tmp_path, no_annotations):
    doc = _doc()
    _door_block(doc, "DOOR-SGL", 900)
    msp = doc.modelspace()
    msp.add_blockref("DOOR-SGL", (1000, 0)).add_auto_attribs({"MARK": "D1"})
    ev = _run(_save(doc, tmp_path), tmp_path)
    (d,) = _els(ev, "Door")
    assert d["id"] == "door:D1" and _vals(d, "mark") == ["D1"]
    assert _vals(d, "leaf_width") == ["900 mm"]
    assert _vals(d, "clear_width") == ["836 mm", "856 mm"]  # adapters.ifc CLEAR_WIDTH_DEDUCTION_MM
    assert _vals(d, "leaves") == [1]
    assert parse_locator(d["at"][0])["bbox"] == (1000, 0, 1900, 900)


def test_door_block_inches_and_insert_scale(tmp_path, no_annotations):
    doc = _doc(insunits=1)
    _door_block(doc, "door plan", 24, mark_attr=False)
    doc.modelspace().add_blockref("door plan", (0, 0), dxfattribs={"xscale": 1.5, "yscale": 1.5})
    ev = _run(_save(doc, tmp_path), tmp_path)
    (d,) = _els(ev, "Door")
    assert _vals(d, "leaf_width") == ["36 in"]
    assert _vals(d, "clear_width") == ["850 mm", "870 mm"]  # 914.4 mm less 64 / 44
    assert "mark" not in d["facts"] and d["id"].startswith("dxf:plan.dxf:")
    assert "x insert scale 1.5" in d["facts"]["leaf_width"][0]["note"]


def test_unnamed_small_block_with_swing_is_a_door_but_large_arc_is_not(tmp_path, no_annotations):
    doc = _doc()
    _door_block(doc, "X1", 800, mark_attr=False)
    big = doc.blocks.new("BENCH")
    big.add_line((0, 0), (0, 2500))
    big.add_arc((0, 0), 2500, 0, 90)
    msp = doc.modelspace()
    msp.add_blockref("X1", (0, 0))
    msp.add_blockref("BENCH", (5000, 0))
    ev = _run(_save(doc, tmp_path), tmp_path)
    (d,) = _els(ev, "Door")
    assert _vals(d, "leaf_width") == ["800 mm"]


def test_door_block_without_a_swing_or_scaled_unevenly_is_skipped(tmp_path, no_annotations):
    doc = _doc()
    blk = doc.blocks.new("DOOR jamb")
    blk.add_line((0, 0), (50, 0))
    _door_block(doc, "DOOR-SGL", 900)
    msp = doc.modelspace()
    msp.add_blockref("DOOR jamb", (0, 0))
    msp.add_blockref("DOOR-SGL", (3000, 0), dxfattribs={"xscale": 1, "yscale": 2})
    ev = _run(_save(doc, tmp_path), tmp_path)
    assert _els(ev, "Door") == []
    skipped = " ".join(ev["sources"][0]["skipped"])
    assert "'DOOR jamb'" in skipped and "no swing" in skipped
    assert "scaled unevenly" in skipped


def test_double_door_from_loose_swings(tmp_path, no_annotations):
    doc = _doc()
    msp = doc.modelspace()
    for hinge, sign in ((0, 1), (1600, -1)):
        msp.add_line((hinge, 0), (hinge, 800), dxfattribs={"layer": "A-DOOR"})
        if sign > 0:
            msp.add_arc((hinge, 0), 800, 0, 90, dxfattribs={"layer": "A-DOOR"})
        else:
            msp.add_arc((hinge, 0), 800, 90, 180, dxfattribs={"layer": "A-DOOR"})
    ev = _run(_save(doc, tmp_path), tmp_path)
    (d,) = _els(ev, "Door")
    assert _vals(d, "leaves") == [2] and _vals(d, "leaf_width") == ["800 mm"]


# ---------------------------------------------------------------- units


def test_units_from_measurement_when_insunits_unset(tmp_path, no_annotations):
    doc = _doc(insunits=None, measurement=0)
    _door_block(doc, "DOOR", 30, mark_attr=False)
    doc.modelspace().add_blockref("DOOR", (0, 0))
    ev = _run(_save(doc, tmp_path), tmp_path)
    assert ev["sources"][0]["files"][0]["units"] == "in"
    assert "$MEASUREMENT=0" in ev["sources"][0]["files"][0]["units_from"]
    assert _vals(_els(ev, "Door")[0], "leaf_width") == ["30 in"]


def test_no_units_no_lengths(tmp_path, no_annotations):
    doc = _doc(insunits=None, measurement=None)
    _door_block(doc, "DOOR", 900, mark_attr=False)
    doc.modelspace().add_blockref("DOOR", (0, 0))
    ev = _run(_save(doc, tmp_path), tmp_path)
    assert _els(ev, "Door") == []
    assert any("units are not set" in s for s in ev["sources"][0]["skipped"])


# ---------------------------------------------------------------- dimensions, stairs, corridors


def _treads(msp, n, spacing=280, length=1000, layer="A-STAIR"):
    for i in range(n):
        msp.add_line((0, i * spacing), (length, i * spacing), dxfattribs={"layer": layer})


def test_stair_tread_lines_and_dimension_across_flight(tmp_path, no_annotations):
    doc = _doc()
    msp = doc.modelspace()
    _treads(msp, 6)
    msp.add_linear_dim(base=(0, -300), p1=(0, 0), p2=(1000, 0), dimstyle="Standard").render()
    msp.add_linear_dim(base=(5000, 0), p1=(5000, 0), p2=(6200, 0), dimstyle="Standard").render()  # elsewhere: not used
    ev = _run(_save(doc, tmp_path), tmp_path)
    (st,) = _els(ev, "Stair")
    assert _vals(st, "tread_depth") == ["280 mm"]
    assert _vals(st, "width") == ["1000 mm"]
    assert parse_locator(st["facts"]["width"][0]["at"])["bbox"][2] >= 1000


def test_scaled_dimension_is_not_used_for_a_width(tmp_path, no_annotations):
    doc = _doc()
    msp = doc.modelspace()
    _treads(msp, 6)
    msp.add_linear_dim(base=(0, -300), p1=(0, 0), p2=(1000, 0), dimstyle="Standard", override={"dimlfac": 2}).render()
    ev = _run(_save(doc, tmp_path), tmp_path)
    (st,) = _els(ev, "Stair")
    assert "width" not in st["facts"]
    assert any("DIMLFAC" in s for s in ev["sources"][0]["skipped"])


def test_too_few_or_uneven_tread_lines_are_not_a_stair(tmp_path, no_annotations):
    doc = _doc()
    msp = doc.modelspace()
    _treads(msp, 3)
    for i, y in enumerate((5000, 5280, 5600, 5800, 6300)):
        msp.add_line((0, y), (1000, y), dxfattribs={"layer": "A-STAIR-B"})
    ev = _run(_save(doc, tmp_path), tmp_path)
    assert _els(ev, "Stair") == []


def test_corridor_clear_width_from_dimension_across_it(tmp_path, no_annotations):
    doc = _doc()
    _room_tag_block(doc)
    msp = doc.modelspace()
    msp.add_lwpolyline([(0, 0), (12000, 0), (12000, 1500), (0, 1500)], close=True, dxfattribs={"layer": "A-AREA"})
    msp.add_blockref("ROOMTAG", (6000, 900)).add_auto_attribs({"ROOM_NAME": "CORRIDOR", "ROOM_NUMBER": "C1"})
    msp.add_linear_dim(base=(3000, 0), p1=(3000, 0), p2=(3000, 1500), angle=90, dimstyle="Standard").render()
    msp.add_linear_dim(base=(0, -500), p1=(0, 0), p2=(4000, 0), dimstyle="Standard").render()  # along it: not a width
    ev = _run(_save(doc, tmp_path), tmp_path)
    (c,) = _els(ev, "Corridor")
    assert c["id"] == "corridor:C1" and _vals(c, "clear_width") == ["1500 mm"]


def test_room_not_named_corridor_gets_no_corridor(tmp_path, no_annotations):
    doc = _doc()
    _room_tag_block(doc)
    msp = doc.modelspace()
    msp.add_lwpolyline([(0, 0), (12000, 0), (12000, 1500), (0, 1500)], close=True, dxfattribs={"layer": "A-AREA"})
    msp.add_blockref("ROOMTAG", (6000, 900)).add_auto_attribs({"ROOM_NAME": "STORE", "ROOM_NUMBER": "5"})
    msp.add_linear_dim(base=(3000, 0), p1=(3000, 0), p2=(3000, 1500), angle=90, dimstyle="Standard").render()
    ev = _run(_save(doc, tmp_path), tmp_path)
    assert _els(ev, "Corridor") == []


# ---------------------------------------------------------------- text and annotations


def test_tokens_reach_annotations(tmp_path, stub_annotations):
    doc = _doc()
    _door_block(doc, "DOOR", 900)
    msp = doc.modelspace()
    msp.add_text("GENERAL NOTES", dxfattribs={"height": 250, "insert": (0, 5000)})
    msp.add_mtext("OCCUPANCY: B\\PCONSTRUCTION TYPE: V-B", dxfattribs={"char_height": 200, "insert": (0, 4000)})
    msp.add_blockref("DOOR", (8000, 0)).add_auto_attribs({"MARK": "D9"})
    msp.add_linear_dim(base=(0, -500), p1=(0, 0), p2=(2500, 0), dimstyle="Standard").render()
    _run(_save(doc, tmp_path), tmp_path)
    toks = {t.text: t for t in stub_annotations["tokens"]}
    assert {"GENERAL NOTES", "OCCUPANCY: B", "CONSTRUCTION TYPE: V-B", "D9", "2500"} <= set(toks)
    assert all(t.source == "dxf" and t.sheet.layout == "Model" and t.sheet.units_per_metre == 1000 for t in toks.values())
    assert toks["D9"].extra["tag"] == "MARK"
    assert toks["2500"].extra["measurement"] == pytest.approx(2500) and toks["2500"].extra["value"] == "2500 mm"
    # annotations reads page coordinates: y down from the top of the layout's extents
    assert toks["OCCUPANCY: B"].bbox[1] < toks["CONSTRUCTION TYPE: V-B"].bbox[1]  # MTEXT lines top to bottom
    assert toks["GENERAL NOTES"].bbox[1] == pytest.approx(0)  # the topmost text
    assert toks["GENERAL NOTES"].at.startswith("plan.dxf#layout=Model&bbox=")


def test_missing_annotations_is_recorded(tmp_path, no_annotations):
    doc = _doc()
    doc.modelspace().add_text("ROOM 101", dxfattribs={"height": 200})
    ev = _run(_save(doc, tmp_path), tmp_path)
    assert any("annotations is not available" in s for s in ev["sources"][0]["skipped"])


def _walled_room(msp):
    """A 4 x 3 m room inside 200 mm walls, with a 900 mm door in the south wall drawn as a loose swing."""
    for box in ((-200, -200, 1000, 0), (1900, -200, 4200, 0), (-200, 3000, 4200, 3200), (-200, 0, 0, 3000), (4000, 0, 4200, 3000)):
        x0, y0, x1, y1 = box
        msp.add_lwpolyline([(x0, y0), (x1, y0), (x1, y1), (x0, y1)], close=True, dxfattribs={"layer": "A-WALL"})
    msp.add_line((1000, 0), (1000, 900), dxfattribs={"layer": "A-DOOR"})
    msp.add_arc((1000, 0), 900, 0, 90, dxfattribs={"layer": "A-DOOR"})


def test_room_tag_from_annotations_gets_area_enclosed_by_walls_and_door_tag_names_door(tmp_path, stub_annotations):
    doc = _doc()
    msp = doc.modelspace()
    _walled_room(msp)
    msp.add_text("KITCHEN", dxfattribs={"height": 200, "insert": (1500, 1500)})
    msp.add_text("D7", dxfattribs={"height": 150, "insert": (1400, -600)})

    def reply(tokens, sheet):
        by = {t.text: t for t in tokens}
        return {"elements": [
            {"type": "Space", "id": "space:KITCHEN", "at": [by["KITCHEN"].at], "facts": {"name": [{"value": "KITCHEN", "at": by["KITCHEN"].at}]}},
            {"type": "Door", "id": "door:D7", "at": [by["D7"].at], "facts": {"mark": [{"value": "D7", "at": by["D7"].at}]}},
        ]}
    stub_annotations["reply"] = reply
    ev = _run(_save(doc, tmp_path), tmp_path)
    (sp,) = _els(ev, "Space")
    assert sp["id"] == "space:KITCHEN" and _vals(sp, "floor_area") == ["12 m2"]
    (d,) = _els(ev, "Door")
    assert d["id"] == "door:D7" and _vals(d, "leaf_width") == ["900 mm"] and _vals(d, "mark") == ["D7"]


def test_real_annotations_room_name_in_walls_is_a_space(tmp_path):
    """No stub: adapters.drawings.annotations reads the notes (in its y-down frame, locators mapped back
    to the DXF's), and a room name inside the walls becomes a Space with computed and stated areas."""
    doc = _doc()
    msp = doc.modelspace()
    _walled_room(msp)
    msp.add_text("Kitchen", dxfattribs={"height": 200, "insert": (1500, 1600), "layer": "A-TEXT"})
    msp.add_text("12.0 m2", dxfattribs={"height": 200, "insert": (1500, 1300), "layer": "A-TEXT"})
    msp.add_text("SEE 3/A1.7", dxfattribs={"height": 150, "insert": (2600, 600), "layer": "A-TEXT"})  # a note: no room
    msp.add_text("STORE", dxfattribs={"height": 200, "insert": (6000, 1000), "layer": "A-TEXT"})  # outside every wall: no room
    msp.add_text("OCCUPANCY CLASSIFICATION: B", dxfattribs={"height": 200, "insert": (0, 5000), "layer": "A-TEXT"})
    ev = _run(_save(doc, tmp_path), tmp_path)
    (sp,) = _els(ev, "Space")
    assert sp["id"] == "space:Kitchen" and _vals(sp, "name") == ["Kitchen"]
    assert _vals(sp, "floor_area") == ["12 m2", "11.95 m2", "12.05 m2"]  # computed; stated, as printed-precision interval
    assert parse_locator(sp["at"][0])["bbox"] == (0, 0, 4000, 3000)
    (occ,) = ev["facts"]["stated_occupancy_classification"]
    assert occ["value"] == "B"
    b = parse_locator(occ["at"])["bbox"]
    assert 4900 < b[1] < 5000 < b[3] < 5300  # back in the drawing's frame, y up (left flipped, y would be near 0)
    assert any("not read as rooms (STORE)" in s for s in ev["sources"][0]["skipped"])


def test_travel_distance_and_exits_through_a_lobby(tmp_path):
    """An office whose one door opens into a lobby with the exterior door. By hand: the office's far corner (0, 3)
    to the door jamb (4.0, 1.0), through the 200 mm wall to (4.2, 1.0), then to the exterior opening (5.0, 0.06):
    4.472 + 0.2 + 1.234 = 5.906 m. Each room has one exit: the closed leaf between them is not an open boundary."""
    doc = _doc()
    msp = doc.modelspace()
    for x0, y0, x1, y1 in ((-200, -200, 5000, 0), (5900, -200, 8400, 0), (-200, 3000, 8400, 3200), (-200, 0, 0, 3000),
                           (8200, 0, 8400, 3000), (4000, 0, 4200, 1000), (4000, 1900, 4200, 3000)):
        msp.add_lwpolyline([(x0, y0), (x1, y0), (x1, y1), (x0, y1)], close=True, dxfattribs={"layer": "A-WALL"})
    msp.add_line((4000, 1000), (3100, 1000), dxfattribs={"layer": "A-DOOR"})   # office door, opening into the office
    msp.add_arc((4000, 1000), 900, 90, 180, dxfattribs={"layer": "A-DOOR"})
    msp.add_line((5000, 0), (5000, 900), dxfattribs={"layer": "A-DOOR"})       # exterior door, in the lobby's south wall
    msp.add_arc((5000, 0), 900, 0, 90, dxfattribs={"layer": "A-DOOR"})
    for name, x in (("Office", 1500), ("Lobby", 6000)):
        msp.add_text(name, dxfattribs={"height": 200, "insert": (x, 2000), "layer": "A-TEXT"})
        msp.add_text("12.0 m2", dxfattribs={"height": 200, "insert": (x, 1700), "layer": "A-TEXT"})
    ev = _run(_save(doc, tmp_path), tmp_path)
    sp = {s["id"]: s for s in _els(ev, "Space")}
    office, lobby = sp["space:Office"], sp["space:Lobby"]
    assert _vals(office, "exits") == [1] and _vals(lobby, "exits") == [1]
    (td,) = _vals(office, "travel_distance")
    assert td.endswith(" m") and abs(float(td[:-2]) - 5.906) < 0.1
    (td,) = _vals(lobby, "travel_distance")
    assert abs(float(td[:-2]) - 3.733) < 0.1   # far corner (8.2, 3) to the opening's corner (5.9, 0.06)
    assert parse_locator(office["facts"]["travel_distance"][0]["at"])["bbox"][2] >= 4200   # the cited region spans the route
    assert len(ev["sources"][0]["files"][0]["travel_distance"]["exits"]) == 1
    assert sorted(_vals(d, "is_external") for d in _els(ev, "Door")) == [[False], [True]]


def test_two_tags_in_one_enclosed_area_get_no_area(tmp_path, stub_annotations):
    doc = _doc()
    msp = doc.modelspace()
    _walled_room(msp)
    msp.add_text("LIVING", dxfattribs={"height": 200, "insert": (500, 2000)})
    msp.add_text("DINING", dxfattribs={"height": 200, "insert": (2500, 1000)})

    def reply(tokens, sheet):
        return {"elements": [{"type": "Space", "id": f"space:{t.text}", "at": [t.at], "facts": {"name": [{"value": t.text, "at": t.at}]}}
                             for t in tokens if t.text in ("LIVING", "DINING")]}
    stub_annotations["reply"] = reply
    ev = _run(_save(doc, tmp_path), tmp_path)
    assert all("floor_area" not in s["facts"] for s in _els(ev, "Space"))
    assert any("share one enclosed area" in s for s in ev["sources"][0]["skipped"])


# ---------------------------------------------------------------- shape, merging, render


def test_evidence_shape_sheets_and_merge_with_other_sources(tmp_path, no_annotations):
    doc = _doc()
    _door_block(doc, "DOOR", 900)
    doc.modelspace().add_blockref("DOOR", (0, 0)).add_auto_attribs({"MARK": "D1"})
    lay = doc.layouts.new("A101")
    lay.add_text("A101", dxfattribs={"height": 5})
    ev = _run(_save(doc, tmp_path), tmp_path)
    src = ev["sources"][0]
    assert src["id"] == "dxf" and src["kind"] == "drawings" and src["adapter"].startswith("adapters.dxf ")
    assert src["files"][0]["file"] == "plan.dxf" and src["files"][0]["units"] == "mm"
    sheets = {s["layout"]: s for s in ev["sheets"]}
    assert sheets["Model"]["text"] == "dxf" and sheets["A101"]["number"] == "A101"
    ifc = {"sources": [{"id": "ifc"}], "elements": [{"type": "Door", "id": "door:D1", "at": "ifc:abc",
                                                     "facts": {"clear_width": [{"value": "850 mm"}]}}]}
    merged = load_evidence({k: v for k, v in ev.items() if k != "sheets"}, ifc)
    (d,) = [e for e in merged.elements if e.type == "Door"]
    assert d.sources == {"dxf", "ifc"} and set(d.facts["clear_width"].values()) == {"836 mm", "856 mm", "850 mm"}


def test_unreadable_file_is_skipped_not_fatal(tmp_path, no_annotations):
    bad = tmp_path / "bad.dxf"
    bad.write_text("not a dxf")
    ev = dxf.analyse([bad], tmp_path)
    assert ev["elements"] == [] and "bad.dxf: not readable" in ev["sources"][0]["skipped"][0]


def test_render_layout_and_region(tmp_path):
    doc = _doc()
    _door_block(doc, "DOOR", 900, mark_attr=False)
    doc.modelspace().add_blockref("DOOR", (0, 0))
    p = _save(doc, tmp_path)
    whole = dxf.render(p, "Model", px=400)
    crop = dxf.render(p, "Model", bbox=(0, 0, 450, 450), px=400)
    assert whole[:8] == b"\x89PNG\r\n\x1a\n" and crop[:8] == b"\x89PNG\r\n\x1a\n" and whole != crop
    with pytest.raises(KeyError):
        dxf.render(p, "NoSuchLayout")


def test_entities_written_without_subclass_markers_are_read(tmp_path, no_annotations):
    """Some exporters omit LWPOLYLINE's subclass markers, which ezdxf and its recover reader both refuse."""
    import re as _re
    doc = _doc()
    _door_block(doc, "DOOR", 900)
    doc.modelspace().add_blockref("DOOR", (0, 0))
    doc.modelspace().add_lwpolyline([(0, 0), (5000, 0), (5000, 4000), (0, 4000)], close=True, dxfattribs={"layer": "A-WALL"})
    p = _save(doc, tmp_path)
    text = p.read_text()
    head, sep, rest = text.partition("\nLWPOLYLINE\n")
    body, nxt, tail = _re.split(r"(\n  0\n)", rest, maxsplit=1)
    body = _re.sub(r"(^|\n)100\n[^\n]+", "", body)              # strip both subclass markers from the polyline
    p.write_text(head + sep + body.lstrip("\n") + nxt + tail)
    import ezdxf as _ezdxf
    with pytest.raises(_ezdxf.DXFStructureError):
        _ezdxf.readfile(str(p))
    out = _run(p, tmp_path)
    assert not out["sources"][0].get("skipped") or not any("not readable" in s for s in out["sources"][0]["skipped"])
    assert [_vals(d, "leaf_width") for d in _els(out, "Door")] == [["900 mm"]]


def test_an_unreadable_drawing_is_in_the_projects_notes(tmp_path, no_annotations):
    from app.buildings import process
    files = tmp_path / "files"
    files.mkdir()
    _save(_doc(), files, "good.dxf")
    (files / "broken.dxf").write_bytes(b"AutoCAD Binary DXF\r\n\x1a\x00" + bytes(range(256)) * 4)
    notes = process(files, "p")["notes"]
    assert [n for n in notes if n.startswith("broken.dxf: not readable as DXF")], notes
