"""The shared evidence layer: reconciliation, value-set checks, and profiles."""

from pathlib import Path

from normir import load, validate
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


def _pack(tmp_path):
    """A small pack: 13 independent flags, a length with a limit, a table whose row is open, a table with a symbol."""
    preds = [f"x{i}" for i in range(13)] + ["b0", "b1", "b2"]
    files = {
        "package.yaml": "package: t\nversion: 0.0.1\ntitle: t\nsubject: system\n",
        "predicates.yaml": "predicates:\n" + "".join(f"  - name: system.{p}\n    label: {p}\n    type: bool\n" for p in preds)
        + "  - name: system.q0\n    label: q0\n    type: length\n",
        "terms.yaml": """terms:
  - name: min_width
    label: min width
    cite: {section: T1, url: "https://example.org/t1"}
    value:
      cases:
        - {when: {fact: system.b0}, then: 900 mm, cite: {section: T1, url: "https://example.org/t1"}}
        - {else: 36 in, cite: {section: T1, url: "https://example.org/t1"}}
  - name: max_width
    label: max width
    cite: {section: T2, url: "https://example.org/t2"}
    value:
      cases:
        - {when: {fact: system.b1}, then: not-permitted, cite: {section: T2, url: "https://example.org/t2"}}
        - {else: 30 in, cite: {section: T2, url: "https://example.org/t2"}}
""",
        "norms.yaml": "norms:\n" + "".join(
            f"  - name: {n}\n    title: {n}\n    modality: obligation\n    cite: {{section: \"{n}\", url: \"https://example.org/{n}\"}}\n"
            f"    require: {r}\n" for n, r in [
                ("not_all", "{not: {all: [" + ", ".join(f"{{fact: system.x{i}}}" for i in range(13)) + "]}}"),
                ("at_least_32in", "{ge: [{fact: system.q0}, 32 in]}"),
                ("table", "{ge: [{fact: system.q0}, {term: min_width}]}"),
                ("symbol", "{le: [{fact: system.q0}, {term: max_width}]}"),
                ("flag", "{fact: system.b2}")]),
    }
    for rel, text in files.items():
        (tmp_path / rel).write_text(text)
    rs = load(tmp_path)
    assert validate(rs)[0] == []
    return rs


def _verdicts(rs, facts, norms):
    return {r["norm"]: r for r in run(rs, load_evidence({"sources": [{"id": "a"}], "facts": facts}), {"norms": norms})}


def test_a_failing_combination_past_the_enumeration_cap_is_not_a_pass(tmp_path):
    # 13 facts seen both true and false: 8192 combinations, and only the last (all true) fails.
    rs = _pack(tmp_path)
    both = [{"value": False, "source": "a"}, {"value": True, "source": "b"}]
    row = _verdicts(rs, {f"x{i}": both for i in range(13)}, ["not_all"])["not_all"]
    assert row["verdict"] == "uncertain" and row["outcomes"] == {"True": 8191, "False": 1}
    row = _verdicts(rs, {**{f"x{i}": both for i in range(12)}, "x12": [{"value": True, "source": "a"}]}, ["not_all"])["not_all"]
    assert row["verdict"] == "uncertain" and row["outcomes"] == {"True": 4095, "False": 1}


def test_lengths_at_a_limit_compare_equal_in_any_unit(tmp_path):
    rs = _pack(tmp_path)
    assert _verdicts(rs, {"q0": "812.8 mm"}, ["at_least_32in"])["at_least_32in"]["verdict"] == "pass"  # exactly 32 in
    assert _verdicts(rs, {"q0": "812.7 mm"}, ["at_least_32in"])["at_least_32in"]["verdict"] == "fail"


def test_an_open_table_row_decides_when_every_row_agrees(tmp_path):
    rs = _pack(tmp_path)  # min_width is 900 mm or 36 in (914.4 mm) depending on b0, which no source gave
    assert _verdicts(rs, {"q0": "2 m"}, ["table"])["table"]["verdict"] == "pass"
    assert _verdicts(rs, {"q0": "700 mm"}, ["table"])["table"]["verdict"] == "fail"
    between = _verdicts(rs, {"q0": "905 mm"}, ["table"])["table"]
    assert between["verdict"] == "unknown" and between["open"] == ["system.b0"]


def test_a_rule_that_cannot_be_evaluated_is_unknown_with_its_error_and_others_still_run(tmp_path):
    rs = _pack(tmp_path)  # with b1, max_width is the symbol not-permitted, which no length is <= to
    rows = _verdicts(rs, {"q0": "1 m", "b1": True, "b2": True}, ["symbol", "flag"])
    assert rows["symbol"]["verdict"] == "unknown" and "not-permitted" in rows["symbol"]["error"]
    assert rows["flag"]["verdict"] == "pass"
    assert _verdicts(rs, {"q0": "700 mm", "b1": False}, ["symbol"])["symbol"]["verdict"] == "pass"

