"""The drawing reader: annotation parsers on hand-built Tokens, printed-precision intervals,
locators, and one real clinic sheet (skipped when the input folder is absent)."""

from pathlib import Path

import pytest

from adapters.drawings import annotations as A
from adapters.drawings.tokens import Sheet, Token, locator, parse_locator
from normir.evidence import load_evidence
from normir.quantity import Quantity

ROOT = Path(__file__).resolve().parents[1]
CLINIC = ROOT / ".amp/in/orb-backup/inputs/nibs-clinic/2012-03-27-ClinicRedactedDrawings"


def sheet(title=None, w=3024, h=2016):
    return Sheet(file="set/A1.pdf", page=1, width=w, height=h, title=title, number="A1" if title else None)


def line(sh, x, y, *words, size=10.0, angle=0.0, conf=1.0):
    """Tokens of one upright line of text, words laid out left to right from (x, y)."""
    out = []
    for w in words:
        wd = 0.6 * size * len(w)
        out.append(Token(w, (x, y, x + wd, y + size), sh, conf, angle, "ocr"))
        x += wd + 0.6 * size
    return out


def values(obs):
    return [o["value"] for o in obs]


# --- printed precision ---------------------------------------------------------------

@pytest.mark.parametrize("text,lo,hi", [
    ("279 mm", "278.5 mm", "279.5 mm"),
    ("1.21 m", "1.205 m", "1.215 m"),
    ("1,210 MM", "1209.5 mm", "1210.5 mm"),
    ("3'-0\"", "35.5 in", "36.5 in"),
    ("3' - 0 1/2\"", "36.25 in", "36.75 in"),
    ("7 1/4\"", "7.125 in", "7.375 in"),
    ("36\"", "35.5 in", "36.5 in"),
    ("137 FT.", "136.5 ft", "137.5 ft"),
    ("41.75 M", "41.745 m", "41.755 m"),
])
def test_length_is_the_interval_its_printed_precision_allows(text, lo, hi):
    assert A.length(text) == (lo, hi)


def test_a_bare_number_is_a_length_only_where_a_convention_says_millimetres():
    assert A.length("1210") is None
    assert A.length("1210", bare=True) == ("1209.5 mm", "1210.5 mm")
    assert A.length("7", bare=True) is None          # too short to be read as a dimension
    assert A.length("EQ.") is None
    assert A.area("250 SF") == ("249.5 sqft", "250.5 sqft")
    assert A.area("45.2 ㎡") == ("45.15 m2", "45.25 m2")


def test_a_measured_length_is_two_observations_with_one_locator_and_counts_are_single():
    sh = sheet("STAIR #1 SECTION")
    toks = line(sh, 100, 100, "STAIR", "#1") + line(sh, 100, 130, "13", "EQ.", "RISERS", "@", "176", "mm", "EA.")
    r = A.read(sh, toks)
    stair = r.elements[("Stair", "stair:STAIR #1")]["facts"]
    rh = stair["riser_height"]
    assert values(rh) == ["175.5 mm", "176.5 mm"]
    assert rh[0]["at"] == rh[1]["at"] and "printed-precision interval" in rh[0]["note"] and '"13 EQ. RISERS @ 176 mm"' in rh[0]["note"]
    assert values(stair["risers"]) == [13]
    # the interval straddles a limit the single printed value does not: 11 in = 279.4 mm
    tread = A.length("279 mm")
    assert Quantity.parse(tread[0]) < Quantity.parse("11 in") < Quantity.parse(tread[1])


# --- stairs ------------------------------------------------------------------------------

def test_stair_dimensions_imperial_and_metric():
    sh = sheet("STAIR PLANS")
    toks = (line(sh, 100, 100, "STAIR", "2") + line(sh, 100, 120, "16", "R", "@", "6", "7/8\"")
            + line(sh, 100, 140, "15", "T", "@", "11\"") + line(sh, 100, 160, "HANDRAIL", "HT.", "34\"", "-", "38\"")
            + line(sh, 100, 180, "6'-8\"", "MIN.", "HEADROOM")
            + line(sh, 900, 100, "STAIR", "#3") + line(sh, 900, 120, "TREAD", "DEPTH", "0.28", "m")
            + line(sh, 900, 140, "STAIR", "WIDTH", "1,210", "mm") + line(sh, 900, 160, "HEADROOM", "2100"))
    r = A.read(sh, toks)
    s2 = r.elements[("Stair", "stair:STAIR 2")]["facts"]
    assert values(s2["riser_height"]) == ["6.8125 in", "6.9375 in"]
    assert values(s2["risers"]) == [16]
    assert values(s2["tread_depth"]) == ["10.5 in", "11.5 in"]
    assert values(s2["handrail_height"]) == ["33.5 in", "38.5 in"]
    assert "headroom" not in s2            # a stated minimum is a limit, not a measurement
    assert any("stated limit" in s["reason"] for s in r.skipped)
    s3 = r.elements[("Stair", "stair:STAIR #3")]["facts"]
    assert values(s3["tread_depth"]) == ["0.275 m", "0.285 m"]
    assert values(s3["width"]) == ["1209.5 mm", "1210.5 mm"]
    assert values(s3["headroom"]) == ["2099.5 mm", "2100.5 mm"]


def test_stair_negative_cases():
    sh = sheet("STAIR PLANS")
    # no stair named on the sheet: nothing to attach to
    r = A.read(sh, line(sh, 100, 120, "16", "R", "@", "7\""))
    assert not r.elements and any("no stair named" in s["reason"] for s in r.skipped)
    # a riser note read with low OCR confidence is left out and listed
    r = A.read(sh, line(sh, 100, 100, "STAIR", "1") + line(sh, 100, 120, "16", "R", "@", "7\"", conf=0.6))
    assert not r.elements[("Stair", "stair:STAIR 1")]["facts"] if ("Stair", "stair:STAIR 1") in r.elements else True
    assert any("low-confidence" in s["reason"] for s in r.skipped)
    # a riser count read differently in two places on one sheet is not kept
    r = A.read(sh, line(sh, 100, 100, "STAIR", "1") + line(sh, 100, 120, "13", "R", "@", "176", "mm")
               + line(sh, 100, 300, "3", "R", "@", "176", "mm"))
    assert "risers" not in r.elements[("Stair", "stair:STAIR 1")]["facts"]


def test_japanese_stair_corridor_and_room_tags():
    sh = sheet("2階平面図")
    toks = (line(sh, 100, 100, "階段A") + line(sh, 100, 120, "蹴上", "175") + line(sh, 100, 140, "踏面", "260")
            + line(sh, 100, 160, "階段幅", "1200") + line(sh, 400, 100, "廊下幅", "1,800")
            + line(sh, 600, 100, "事務室") + line(sh, 594, 112, "45.2㎡"))
    r = A.read(sh, toks)
    st = r.elements[("Stair", "stair:階段A")]["facts"]
    assert values(st["riser_height"]) == ["174.5 mm", "175.5 mm"]
    assert values(st["tread_depth"]) == ["259.5 mm", "260.5 mm"]
    assert values(st["width"]) == ["1199.5 mm", "1200.5 mm"]
    corr = next(e for (t, _), e in r.elements.items() if t == "Corridor")
    assert values(corr["facts"]["clear_width"]) == ["1799.5 mm", "1800.5 mm"]
    room = r.elements[("Space", "space:事務室")]["facts"]
    assert values(room["floor_area"]) == ["45.15 m2", "45.25 m2"]
    # 蹴上 stated as a maximum is a limit
    r = A.read(sh, line(sh, 100, 100, "階段B") + line(sh, 100, 120, "蹴上", "200", "以下"))
    assert "riser_height" not in r.elements.get(("Stair", "stair:階段B"), {"facts": {}})["facts"]


# --- notes ---------------------------------------------------------------------------------

def notes(*texts):
    sh = sheet("GENERAL NOTES")
    toks = []
    for i, t in enumerate(texts):
        toks += line(sh, 100, 100 + 40 * i, *t.split())
    return A.read(sh, toks).facts


def test_sprinkler_notes():
    f = notes("1.) BUILDING IS FULLY SPRINKLERED.")
    assert values(f["sprinkler_system"]) == ["nfpa13", "nfpa13r"]          # no standard named: open
    assert values(notes("BUILDING SPRINKLERED THROUGHOUT PER NFPA 13R")["sprinkler_system"]) == ["nfpa13r"]
    assert values(notes("AUTOMATIC SPRINKLER SYSTEM PER NFPA-13")["sprinkler_system"]) == ["nfpa13"]
    assert values(notes("BUILDING IS NON-SPRINKLERED")["sprinkler_system"]) == ["none"]
    assert "sprinkler_system" not in notes("NFPA 13 SPRINKLER HEADS SHALL BE CONCEALED")
    assert "sprinkler_system" not in notes("PARTIALLY SPRINKLERED")
    for other in ("BUILDING SPRINKLERED THROUGHOUT TO BS EN 12845", "FULLY SPRINKLERED IN ACCORDANCE WITH AS 2118.1"):
        assert "sprinkler_system" not in notes(other)                        # another standard is not an NFPA class
    assert values(notes("FULLY SPRINKLERED PER IBC 903.3.1.1")["sprinkler_system"]) == ["nfpa13", "nfpa13r"]   # the code itself


def test_occupancy_construction_and_code_notes():
    f = notes("2.) OCCUPANCY CLASSIFICATION = BUSINESS", "CONSTRUCTION TYPE II (N)", "CODE: 2009 IBC")
    assert values(f["stated_occupancy_classification"]) == ["BUSINESS"]
    assert values(f["stated_construction_type"]) == ["II (N)"]
    assert values(f["stated_code_basis"]) == ["2009 IBC"]
    f = notes("OCCUPANCY GROUP: A-3", "TYPE V-B CONSTRUCTION", "APPLICABLE CODE: INTERNATIONAL BUILDING CODE, 2018 EDITION")
    assert values(f["stated_occupancy_classification"]) == ["A-3"]
    assert values(f["stated_construction_type"]) == ["V-B"]
    assert values(f["stated_code_basis"]) == ["INTERNATIONAL BUILDING CODE, 2018 EDITION"]
    # a code cited for one value is not the drawings' code basis
    f = notes("PROVIDE OCCUPANCY SENSOR", "SEE IBC TABLE", "SOIL PROFILE SD (1997 UNIFORM BUILDING CODE)")
    assert "stated_occupancy_classification" not in f and "stated_code_basis" not in f


# --- life safety -------------------------------------------------------------------------

def test_travel_distance_occupant_load_and_exits():
    sh = sheet("LIFE SAFETY FIRST FLOOR PLAN")
    toks = (line(sh, 2500, 300, "TRAVEL", "DISTANCE", "IN", "FEET", "or", "METERS") + line(sh, 1600, 700, "137", "FT./41.75", "M")
            + line(sh, 1000, 700, "TRAVEL", "DISTANCE", "=", "98'-6\"")
            + line(sh, 300, 300, "OFFICE") + line(sh, 300, 312, "1A03") + line(sh, 300, 330, "OCC.", "LOAD", "=", "12")
            + line(sh, 2500, 500, "EXITS", "PROVIDED:", "3"))
    r = A.read(sh, toks)
    st = r.elements[("Storey", "storey:First Floor")]["facts"]
    assert values(st["max_travel_distance"]) == ["136.5 ft", "137.5 ft", "41.745 m", "41.755 m"]   # the longest route
    assert values(r.elements[("Space", "space:First Floor")]["facts"]["travel_distance"])[:2] == ["136.5 ft", "137.5 ft"]
    assert values(st["exits"]) == [3]
    assert values(r.elements[("Space", "space:1A03")]["facts"]["stated_occupant_load"]) == [12]
    # a dual label without the legend is not read as a travel distance; one under no storey is skipped
    sh2 = sheet("LIFE SAFETY PLAN")
    r = A.read(sh2, line(sh2, 1600, 700, "137", "FT./41.75", "M") + line(sh2, 100, 100, "TRAVEL", "DISTANCE", "=", "200'"))
    assert not any(t == "Storey" for t, _ in r.elements)
    assert any("no single storey" in s["reason"] for s in r.skipped)


# --- room tags -----------------------------------------------------------------------

def test_room_tags_on_plans_only():
    sh = sheet("FIRST FLOOR PLAN")
    toks = line(sh, 300, 300, "OFFICE") + line(sh, 300, 312, "1A03") + line(sh, 300, 324, "120", "SF") \
        + line(sh, 800, 300, "LANDING") + line(sh, 806, 312, "305") \
        + line(sh, 1200, 300, "CONF.", "ROOM") + line(sh, 1221, 312, "104")
    r = A.read(sh, toks)
    room = r.elements[("Space", "space:1A03")]["facts"]
    assert values(room["name"]) == ["OFFICE"] and values(room["number"]) == ["1A03"]
    assert values(room["floor_area"]) == ["119.5 sqft", "120.5 sqft"]
    assert ("Space", "space:305") not in r.elements                       # a dimension under a word
    assert values(r.elements[("Space", "space:104")]["facts"]["name"]) == ["CONF. ROOM"]
    detail = sheet("STAIR DETAIL")
    assert not A.read(detail, line(detail, 300, 300, "OFFICE") + line(detail, 300, 312, "1A03")).elements


# --- door schedules ------------------------------------------------------------------

def schedule(header, *rows, x=100, y=100):
    sh = sheet("DOOR SCHEDULE")
    cols = [x + 120 * i for i in range(len(header))]
    toks = []
    for c, h in zip(cols, header):
        toks += line(sh, c, y, *h.split())
    for j, row in enumerate(rows):
        for c, v in zip(cols, row):
            if v:
                toks += line(sh, c, y + 15 * (j + 1), *v.split())
    return A.read(sh, toks)


def test_door_schedule_imperial_with_the_clear_width_deduction():
    r = schedule(["DOOR #", "WIDTH", "HEIGHT", "FIRE RATING"], ["101", "3'-0\"", "7'-0\"", "20 MIN"], ["102", "PR 3'-0\"", "7'-0\"", "-"])
    d = r.elements[("Door", "door:101")]["facts"]
    assert values(d["leaf_width"]) == ["35.5 in", "36.5 in"]
    assert values(d["height"]) == ["83.5 in", "84.5 in"]
    assert values(d["fire_rating"]) == ["20 MIN"]
    # 35.5 in = 901.7 mm less 64; 36.5 in = 927.1 mm less 44 (adapters/ifc.py CLEAR_WIDTH_DEDUCTION_MM)
    assert values(d["clear_width"]) == ["837.7 mm", "883.1 mm"]
    assert "leaf less" not in d["clear_width"][0]["note"] and "adapters/ifc.py" in d["clear_width"][0]["note"]
    p = r.elements[("Door", "door:102")]["facts"]
    assert values(p["leaves"]) == [2] and "fire_rating" not in p


def test_door_schedule_metric_with_a_scheduled_clear_width():
    r = schedule(["MARK", "WIDTH", "CLEAR WIDTH", "HEIGHT"], ["D01", "1000", "920", "2100"])
    d = r.elements[("Door", "door:D01")]["facts"]
    assert values(d["leaf_width"]) == ["999.5 mm", "1000.5 mm"]
    assert values(d["clear_width"]) == ["919.5 mm", "920.5 mm"]
    # no width column: not a door schedule
    assert not schedule(["DOOR #", "HDW. SET"], ["101", "12"]).elements


def test_drawing_facts_merge_with_ifc_facts_by_id():
    r = schedule(["DOOR #", "WIDTH"], ["101", "915"])
    drawn = {"sources": [{"id": "drawings"}], "elements": list(r.elements.values())}
    model = {"sources": [{"id": "ifc"}], "elements": [{"type": "Door", "id": "door:101", "facts": {"height": [{"value": "2.1 m"}]}}]}
    ev = load_evidence(model, drawn)
    assert len(ev.elements) == 1 and set(ev.elements[0].facts) >= {"height", "leaf_width", "clear_width"}


# --- locators ------------------------------------------------------------------------

def test_locator_round_trip():
    sh = Sheet(file="plans/A 1#2.pdf", page=3)
    at = locator(sh, (10.04, 20.0, 300.56, 400.25))
    assert at == "plans/A 1#2.pdf#page=3&bbox=10,20,300.6,400.2" or at == "plans/A 1#2.pdf#page=3&bbox=10,20,300.6,400.3"
    p = parse_locator(at)
    assert p["file"] == "plans/A 1#2.pdf" and p["page"] == 3 and p["layout"] is None
    assert p["bbox"] == pytest.approx((10, 20, 300.6, 400.25), abs=0.06)
    assert parse_locator(locator(Sheet(file="a.dxf", layout="Model"), (0, -5, 1, 2)))["layout"] == "Model"
    assert parse_locator("ifc:3NhaIUfh12PAdrGa$S3z3M") is None


def test_part_of_a_token_gets_its_own_box():
    sh = sheet()
    (t,) = line(sh, 0, 0, "ABCDEFGHIJ")             # 60 points wide
    l = A.Line([t])
    assert l.part(5, 10)[0] == pytest.approx((30, 0, 60, 10))
    v = Token("ABCD", (0, 0, 10, 40), sh, angle=90)  # reads bottom to top
    assert A.Line([v]).part(0, 2)[0] == pytest.approx((0, 20, 10, 40))


# --- a real sheet --------------------------------------------------------------------

@pytest.mark.skipif(not CLINIC.is_dir(), reason="clinic drawings not present")
def test_clinic_life_safety_sheet():
    from adapters.drawings import analyse, render

    f = next(CLINIC.glob("Clinic_161_*.pdf"))
    doc = analyse([f], CLINIC)
    assert doc["sheets"][0]["number"] == "A18-1" and doc["sheets"][0]["text"] == "ocr"
    assert values(doc["facts"]["sprinkler_system"]) == ["nfpa13", "nfpa13r"]
    assert values(doc["facts"]["stated_occupancy_classification"]) == ["BUSINESS"]
    storey = next(e for e in doc["elements"] if e["id"] == "storey:First Floor")
    obs = storey["facts"]["max_travel_distance"]
    assert values(obs)[:2] == ["136.5 ft", "137.5 ft"]
    png = render(f, 1, parse_locator(obs[0]["at"])["bbox"])
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
