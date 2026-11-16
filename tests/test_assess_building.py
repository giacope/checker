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
    # between those the shorter excerpt, with more hits per character, comes first
    assert heads == ["model elements: Stair 1-1 of 1", "sheet S2 · set/plan.dxf layout Model (CAD text) · lines 1-2 of 2",
                     "sheet S1 · A5-1 DOOR SCHEDULE · set/A5-1.pdf p1 (OCR) · lines 1-4 of 4"]
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
