"""The shared evidence layer: reconciliation, value-set checks, and profiles."""

from pathlib import Path

from normir import load
from normir.evidence import conflicts, load_evidence, run, summarize

ROOT = Path(__file__).resolve().parents[1]


def doc(source, elements, facts=None):
    return {"subject": {"id": "x"}, "sources": [{"id": source}], "facts": facts or {}, "elements": elements}


def stair(id_, **facts):
    return {"type": "Stair", "id": id_, "facts": {k: [{"value": v}] for k, v in facts.items()}}


def test_disagreement_decides_only_when_it_straddles_the_limit():
    # 44 in = 1117.6 mm: 1000 vs 1210 straddles it; 1200 vs 1210 does not.
    ev = load_evidence(doc("ifc", [stair("a", width="1000 mm"), stair("b", width="1200 mm")]),
                       doc("drawings", [stair("a", width="1210 mm"), stair("b", width="1210 mm")]))
    rows = {r["element"]: r for r in run(load(ROOT / "packs/austin-2024"), ev,
                                         {"occupancy_group": "B", "sprinkler_system": "nfpa13", "emergency_voice_alarm": False,
                                          "Stair": {"occupant_load": 60}, "norms": ["1011.2"]})}
    assert rows["a"]["verdict"] == "uncertain" and list(rows["a"]["deciding"]) == ["width"]
    assert rows["b"]["verdict"] == "pass"
    # both are conflicts between sources; only one decides a verdict
    assert {c["element"] for c in conflicts(ev)} == {"a", "b"}


def test_several_values_from_one_source_are_a_range_not_a_conflict():
    ev = load_evidence(doc("ifc", [{"type": "Door", "id": "d", "facts": {"clear_width": [{"value": "801 mm"}, {"value": "821 mm"}]}}]))
    assert conflicts(ev) == []
    rows = run(load(ROOT / "packs/ada-2010"), ev, {"Door": {"on_accessible_route": True, "opening_depth": "6 in",
                                                            "projection_below_34in": "0 in", "projection_34_to_80in": "0 in"},
                                                   "norms": ["404.2.3"]})
    assert rows[0]["verdict"] == "uncertain"  # 32 in = 812.8 mm lies inside 801..821


def test_profile_classifications_reach_packs_through_the_vocabulary():
    # UK names the stair's occupancy `people_served`; the profile and evidence use the
    # vocabulary name `occupant_load`. Leaving it unmapped would make the verdict unknown.
    ev = load_evidence(doc("ifc", [stair("s", width="1210 mm", rise="4.57 m")]))
    rows = run(load(ROOT / "packs/uk-adb-v2"), ev, {
        "purpose_group": "office", "evacuation_strategy": "simultaneous", "open_spatial_planning": False,
        "Stair": {"occupant_load": 136, "floors_served": 2, "serves_area_with_occupancy_over_50": True,
                  "serves_basement": False, "widest_exit_width": "915 mm"},
        "norms": ["ADB2 3.10"]})
    assert rows[0]["verdict"] == "pass", rows[0]


def test_summary_puts_fail_before_uncertain_and_pass():
    rows = [{"norm": "n", "element": "a", "verdict": "pass", "deciding": {}, "open": []},
            {"norm": "n", "element": "b", "verdict": "uncertain", "deciding": {"w": []}, "open": []},
            {"norm": "n", "element": "c", "verdict": "fail", "at": ["x.ts:3"], "deciding": {}, "open": []}]
    s = summarize(rows)["n"]
    assert s["verdict"] == "fail" and s["failing"] == ["x.ts:3"]


def test_elements_with_marks_as_ids_do_not_merge_as_code_lines():
    # "door:101" and "door:102" read like path:line locators a line apart; they are two doors.
    doc = {"subject": {"kind": "building", "id": "b"}, "sources": [{"id": "drawings"}],
           "elements": [{"type": "Door", "id": "door:101", "facts": {"leaves": [{"value": 1}]}},
                        {"type": "Door", "id": "door:102", "facts": {"leaves": [{"value": 2}]}}]}
    ev = load_evidence(doc)
    assert sorted(e.id for e in ev.elements) == ["door:101", "door:102"]
