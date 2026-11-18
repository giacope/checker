"""The building corpus: sheet text as numbered lines and model elements, deterministic retrieval, and citations that
must name a real line or element of the project."""

import json
import re

import httpx

from adapters.assess import assess
from adapters.assess.building import BuildingCorpus, _lines
from app.buildings import locate

PLAN = "set/A5-1.pdf"
LAYOUT = "set/plan.dxf"


def doc():
    return {"subject": {"kind": "building", "id": "Clinic"}, "sources": [{"id": "ifc", "kind": "model"}],
            "facts": {"stated_occupancy_classification": [{"value": "BUSINESS", "at": f"{PLAN}#page=1&bbox=10,10,90,20"}],
                      "total_floor_area": [{"value": "4325 m2"}]},
            "elements": [
                {"type": "Stair", "id": "stair:1", "at": ["ifc:2abc$_X"],
                 "facts": {"riser_height": [{"value": "176 mm", "at": "ifc:2abc$_X Pset_StairCommon.RiserHeight"}],
                           "storey": [{"value": "First Floor"}]}},
                {"type": "Door", "id": "door:1A03", "at": [f"{PLAN}#page=1&bbox=100,300,330,312"],
                 "facts": {"clear_width": [{"value": "851 mm"}, {"value": "871 mm"}]}},
            ]}


def sheets():
    """A door schedule (two columns per row, a far-off note) and a DXF layout (y up: the higher text reads first)."""
    page = [("DOOR", (100, 280, 130, 292)), ("#", (132, 280, 140, 292)), ("WIDTH", (200, 280, 240, 292)),
            ("1A03", (100, 300, 130, 312)), ("915", (200, 300, 222, 312)), ("STEEL", (300, 300, 330, 312)),
            ("HANDRAILS BOTH SIDES", (900, 300, 1100, 312)),       # far to the right: its own line
            ("illegible", (100, 500, 160, 512), 0, 0.2),           # OCR below MIN_CONFIDENCE: left out
            ("A5-1", (1500, 1000, 1540, 1012), 90)]                # turned text: a line of its own
    cad = [("GUARDING 1100 mm", (0, 0, 400, 100)), ("STAIR 2", (0, 500, 200, 600))]
    return [({"file": PLAN, "page": 1, "number": "A5-1", "title": "DOOR SCHEDULE", "text": "ocr"}, page),
            ({"file": LAYOUT, "layout": "Model", "number": None, "title": None, "text": "dxf"}, cad)]


def corpus():
    return BuildingCorpus("Clinic", [doc()], sheets())


def test_sheet_text_becomes_numbered_lines():
    c = corpus()
    assert [t for _, t in c._sheets[0]["lines"]] == ["DOOR # | WIDTH", "1A03 | 915 | STEEL", "HANDRAILS BOTH SIDES", "A5-1"]
    assert [t for _, t in c._sheets[1]["lines"]] == ["STAIR 2", "GUARDING 1100 mm"]
    head, body = c.search(["width"], 10_000)[0]
    assert head == "sheet S1 · A5-1 DOOR SCHEDULE · set/A5-1.pdf p1 (OCR) · lines 1-4 of 4"
    assert body.split("\n")[:2] == ["L1 DOOR # | WIDTH", "L2 1A03 | 915 | STEEL"]
    assert _lines([("a", (0, 0, 10, 10)), ("b", (12, 1, 20, 11))]) == [("a b", (0, 0, 20, 11))]


def test_search_ranking_is_deterministic_and_within_budget():
    c = corpus()
    found = c.search(["stair", "riser", "handrail"], 100_000)
    heads = [h for h, _ in found]
    # the stair element block matches two terms (its type and riser height), the plan and the schedule one each:
    # between those the rarer term weighs more (adapters.assess.rank)
    assert heads == ["model elements: Stair 1-1 of 1", "sheet S1 · A5-1 DOOR SCHEDULE · set/A5-1.pdf p1 (OCR) · lines 1-4 of 4",
                     "sheet S2 · set/plan.dxf layout Model (CAD text) · lines 1-2 of 2"]
    # equal on both: the project's order (sheets as uploaded, then elements)
    twins = BuildingCorpus("x", [], [({"file": f"{n}.pdf", "page": 1, "text": "layer"}, [("HANDRAIL", (0, 0, 50, 10))]) for n in "BA"])
    assert [h.split(" · ")[1] for h, _ in twins.search(["handrail"], 1000)] == ["B.pdf p1 (text layer)", "A.pdf p1 (text layer)"]
    assert found == c.search(["stair", "riser", "handrail"], 100_000) == corpus().search(["stair", "riser", "handrail"], 100_000)
    assert "ifc:2abc$_X  Stair stair:1 · storey First Floor: riser height 176 mm" in found[0][1]
    assert c.search(["riser_height"], 100_000)[0][0] == "model elements: Stair 1-1 of 1"   # a fact name as written in the vocabulary
    for budget in (100, 300):
        part = c.search(["stair", "riser", "handrail"], budget)
        assert sum(len(h) + len(t) for h, t in part) <= budget and [x for x in found if x in part] == part
    assert c.search([], 1000) == [] and c.search(["zzz"], 1000) == [] and c.search(["stair"], 0) == []


def test_verify_accepts_real_lines_and_elements_and_rejects_invented_ones():
    c = corpus()
    line2 = c.verify("S1:L2")
    assert line2 == f"{PLAN}#page=1&bbox=100,300,330,312"
    assert c.verify("s1 l2") == c.verify("`S1:L2`") == c.verify(f"{PLAN}#page=1&bbox=100.0,300.00,330,312.04") == line2
    assert c.excerpt("S1:L2") == "1A03 | 915 | STEEL"
    assert c.verify("S2:L2") == f"{LAYOUT}#layout=Model&bbox=0,0,400,100"
    assert c.verify("ifc:2abc$_X") == c.verify("ifc:2abc$_X Pset_StairCommon.RiserHeight") == c.verify("stair:1") == "ifc:2abc$_X"
    assert c.excerpt("ifc:2abc$_X") == "ifc:2abc$_X  Stair stair:1 · storey First Floor: riser height 176 mm"
    assert c.verify(f"{PLAN}#page=1&bbox=10,10,90,20") is not None    # where the occupancy note was read
    # a line the schedule has and an element read from it share a region: the excerpt is the sheet's own text
    assert c.verify("door:1A03") == line2
    for bad in ("S1:L0", "S1:L5", "S3:L1", "S0:L1", "L2", f"{PLAN}#page=1&bbox=100,300,330,313",   # no line there
                f"{PLAN}#page=2&bbox=100,300,330,312", "ghost.pdf#page=1&bbox=100,300,330,312",
                "ifc:2abc$_Y", "ifc:", "ifc:../../etc", "door:9Z99", "", "set/A5-1.pdf"):
        assert c.verify(bad) is None, bad
        assert c.excerpt(bad) == ""
    # the locator a citation becomes is one the report draws as a sheet crop
    sheet = {(PLAN, 1): {"number": "A5-1"}}
    assert locate("p1", sheet, line2)["label"] == "A5-1 · set/A5-1.pdf p1" and "/crop?at=" in locate("p1", sheet, line2)["img"]


def test_assess_keeps_only_citations_the_project_has():
    c = corpus()
    reply = {"answers": [{"attr": "req_handrails", "value": True, "basis": "evidence", "note": "noted on A5-1",
                          "at": ["S1:L3", "ifc:2abc$_X", "S1:L99", "ifc:INVENTED", "A5-1:L3"]}]}
    sent = []

    def handler(request):
        user = json.loads(request.content)["messages"][0]["content"]
        sent.append(json.loads(request.content)["system"])
        assert re.search(r"Answer these requirements: req_handrails$", user)
        return httpx.Response(200, json={"content": [{"type": "text", "text": json.dumps(reply)}]})
    ev = assess([{"attr": "req_handrails", "summary": "Stairs have handrails on both sides", "clause": "1.34 Provide handrails",
                  "search": ["handrail", "stair"]}], c, provider=("anthropic", "test-model", "k"),
                transport=httpx.MockTransport(handler), subject={"kind": "building", "id": "Clinic"})
    assert [o["at"] for o in ev["facts"]["req_handrails"]] == [f"{PLAN}#page=1&bbox=900,300,1100,312", "ifc:2abc$_X"]
    assert ev["sources"][0]["rejected_locators"] == {"locator does not exist": 3}
    assert "S<n>:L<k>" in sent[0] and ev["subject"] == {"kind": "building", "id": "Clinic"}


def test_a_number_on_a_dimension_line_says_so_and_what_it_spans(tmp_path, monkeypatch):
    from adapters.drawings import dimensions
    from tests.test_drawings import pdf_bytes

    monkeypatch.setattr(dimensions, "CACHE_DIR", tmp_path / "dims")
    def text(x, y, s, turned=False):
        return f"BT /F1 12 Tf {'0 1 -1 0' if turned else '1 0 0 1'} {x} {y} Tm ({s}) Tj ET\n"
    content = (
        "0.3 w 100 500 m 701.2 500 l S\n" + text(380, 503, "8480")    # 601.2 pt at 1:40 is 8483 mm
        + text(95, 525, "29.80") + text(690, 525, "30.50")            # the levels at its two ends
        + "800 500 m 826 500 l S\n858 500 m 886.5 500 l S\n"        # broken for its text, as US drafting draws it:
        + text(830, 497, "4'-0\"")                                     # 86.5 pt is 1220.6 mm, 4'-0" is 1219.2
        + "0.3 w 100 400 m 164.8 400 l S\n" + text(120, 403, "36\"")  # inches alone: 64.8 pt is 914.4 mm
        + "302 250 m 302 462.6 l S\n" + text(300, 300, "3000", True)  # read bottom to top: a height
        + "100 200 m 355.1 200 l S\n" + text(200, 203, "450")         # fits only 1:5, which no other number has
        + text(100, 100, "RAMP ELEVATION SCALE 1:40 CONCRETE RAMP WITH STEEL PIPE HANDRAILS BOTH SIDES"))
    (tmp_path / "r.pdf").write_bytes(pdf_bytes([(content.encode(), "0 0 1224 792")]))
    c = BuildingCorpus.from_project(tmp_path, [], [{"file": "r.pdf", "page": 1, "width": 1224, "height": 792, "text": "layer"}], "r")
    lines = [t for _, t in c._sheets[0]["lines"]]
    assert "8480 [horizontal dimension line at 1:40; near its left end: 29.80; near its right end: 30.50]" in lines
    assert any(t.startswith("4’-0\" [horizontal dimension line at 1:40") for t in lines)   # Helvetica's ' is ’
    assert any(t.startswith("3000 [vertical dimension line at 1:40") for t in lines)
    assert any(t.startswith("36\" [horizontal dimension line at 1:40") for t in lines)
    assert "450" in lines   # a lone fit at a scale no other number shares is not taken for a dimension


def test_winders_and_a_door_swing_beside_a_stair_are_measured_off_the_drawing(tmp_path, monkeypatch):
    import math

    from adapters.drawings import dimensions, geometry
    from tests.test_drawings import pdf_bytes

    monkeypatch.setattr(dimensions, "CACHE_DIR", tmp_path / "dims")
    monkeypatch.setattr(geometry, "CACHE_DIR", tmp_path / "geom")
    H = 792

    def line(ax, ay, bx, by):   # in points from the top left, as pdfplumber reads them
        return f"0.6 w {ax} {H - ay} m {bx} {H - by} l S\n"

    def text(x, y, s):
        return f"BT /F1 9 Tf 1 0 0 1 {x} {H - y} Tm ({s}) Tj ET\n"

    # The winders of a plan detail at 1:24 (1 pt = 8.467 mm): four tread lines turning 90° at 30° steps whose
    # narrow ends stand 18 pt (152 mm) apart round the newel. Between the midpoints of consecutive lines lie
    # 48.75, 49.8 and 48.8 pt: 413, 422 and 413 mm.
    fan = [(949.04, 262.96, 842.48, 262.96), (949.04, 280.96, 842.48, 342.52),
           (961.76, 293.68, 900.2, 400.24), (979.76, 293.68, 979.76, 399.52)]
    content = "".join(line(*s) for s in fan) + text(900, 250, "UP")
    content += "".join(line(*(v - 760 if i % 2 == 0 else v for i, v in enumerate(s))) for s in fan)   # no stair word
    for x in (850, 90):         # each copy's dimensions: 1000 mm is 118.1 pt at 1:24
        for y in (450, 470, 490):
            content += line(x, y, x + 118.1, y) + text(x + 45, y - 2, "1000")
    # A 914 mm door (108 pt) hinged its leaf plus 9.5 pt (80 mm) beyond the first riser, closed along the wall
    # (upwards) and drawn open 30° towards the stair: drawn, it stays 63.5 pt away; swung on to 90° from closed
    # its leaf passes 80 mm from that riser.
    hx, hy, r = 979.76 + 108 + 9.5, 330.0, 108.0
    a0, a1 = math.radians(-90), math.radians(-120)
    k = 4 / 3 * math.tan((a1 - a0) / 4) * r
    p0 = (hx + r * math.cos(a0), hy + r * math.sin(a0))
    p3 = (hx + r * math.cos(a1), hy + r * math.sin(a1))
    p1 = (p0[0] - k * math.sin(a0), p0[1] + k * math.cos(a0))
    p2 = (p3[0] + k * math.sin(a1), p3[1] - k * math.cos(a1))
    content += f"0.2 w {p0[0]} {H - p0[1]} m {p1[0]} {H - p1[1]} {p2[0]} {H - p2[1]} {p3[0]} {H - p3[1]} c S\n"
    content += line(hx, hy, *p3)
    (tmp_path / "w.pdf").write_bytes(pdf_bytes([(content.encode(), f"0 0 1224 {H}")]))
    c = BuildingCorpus.from_project(tmp_path, [], [{"file": "w.pdf", "page": 1, "width": 1224, "height": H, "text": "layer"}], "w")
    lines = [t for _, t in c._sheets[0]["lines"]]
    winders = [t for t in lines if "tapered stair treads" in t]
    assert len(winders) == 1, lines   # the copy with no stair word near it is not taken for a stair
    assert "3 tapered stair treads (winders) between 4 tread lines turning 90°" in winders[0]
    assert "at the narrow end 152 / 152 / 152 mm" in winders[0]
    assert "(straight between the midpoints of its two tread lines) 413 / 422 / 413 mm" in winders[0]
    assert winders[0].endswith("; nearest stair labels: UP]")   # which stair it is
    doors = [t for t in lines if "door swing" in t]
    assert len(doors) == 1 and "leaf 914 mm, drawn open 30°" in doors[0] and "comes within 80 mm" in doors[0], doors

    # The same measurements are Stair and Door facts in the drawings' evidence, which computed checks read. A
    # scaled length is an interval, so a limit within scaling's reach of it (80 mm) is uncertain, not met.
    from pathlib import Path

    import yaml
    from normir.evidence import load_evidence, run
    from normir.model import load

    from adapters import drawings
    from adapters.regulation import build_pack

    bim = yaml.safe_load((Path(__file__).parents[1] / "vocab" / "bim.yaml").read_text())
    ev = load_evidence(drawings.analyse([tmp_path / "w.pdf"], tmp_path))

    def check(n, typ, require):
        v = typ[0].lower()
        return {"id": f"k{n}-1", "clause": f"c{n}", "summary": "s", "kind": "computed", "enabled": True,
                "for": {"var": v, "type": typ}, "require": {k: [{"fact": f"{v}.{a}"}, x] for k, (a, x) in require.items()},
                "search": ["stair", "door", "winder"]}
    checks = [check(1, "Stair", {"le": ("tapered_going_max", "300 mm")}), check(2, "Stair", {"ge": ("tapered_narrow_end", "50 mm")}),
              check(3, "Door", {"ge": ("stair_clearance", "400 mm")}), check(4, "Door", {"ge": ("stair_clearance", "80 mm")})]
    clauses = [{"id": f"c{n}", "file": "k.md", "text": "t", "requirement": True, "at": f"k.md#L{n}-L{n}"} for n in range(1, 5)]
    rs = load(build_pack({"id": "rg", "name": "Geometry", "clauses": clauses, "checks": checks}, bim, tmp_path / "pack"))
    verdicts = {r["norm"]: r["verdict"] for r in run(rs, ev)}
    assert verdicts == {"k1-1": "fail", "k2-1": "pass", "k3-1": "fail", "k4-1": "uncertain"}, verdicts
