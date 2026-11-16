"""The shared evidence layer: reconciliation, value-set checks, and profiles."""

from pathlib import Path

from normir import load, validate
from normir.evidence import conflicts, load_evidence, prefer_sources, run, summarize
from normir.quantity import Quantity, mul

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



def test_two_queries_a_line_apart_stay_two_and_a_reader_joins_the_nearest():
    # one document's elements are distinct however close; another document's element is the nearest one's
    q = lambda i, line, c: {"type": "Query", "id": f"q{i}", "at": f"app.py:{line}", "facts": {"construction": c}}  # noqa: E731
    static = {"sources": [{"id": "static"}], "elements": [q(1, 8, "parameterized"), q(2, 9, "concatenated")]}
    reader = {"sources": [{"id": "llm:m"}], "elements": [q(7, 9, "concatenated"), q(8, 30, "concatenated")]}
    ev = load_evidence(static, reader)
    got = {e.id: (sorted(e.sources), sorted({o["value"] for o in e.facts["construction"].observations})) for e in ev.elements}
    assert got == {"q1": (["static"], ["parameterized"]), "q2": (["llm:m", "static"], ["concatenated"]),
                   "q8": (["llm:m"], ["concatenated"])}

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


def test_quantities_read_units_spellings_and_decimal_commas_and_never_mix_dimensions():
    q = Quantity.parse
    same = [("75 cm", "750 mm"), ("1,2 m", "1200 mm"), ("1,200 mm", "1.2 m"), ("120 m²", "1200000 cm2"), ("4 ℃", "4 °C"),
            ("39.2 °F", "4 °C"), ("277.15 K", "4 °C"), ("30 days", "720 h"), ("1 GiB", "1073741824 bytes"), ("2 bar", "200 kPa")]
    for a, b in same:
        assert q(a) is not None and q(a) == q(b), (a, b)
    assert q("4 °C") < q("5 °C") and q("1 GB") < q("1 GiB") and q("1 week") > q("6 days")
    assert q("75 cm").dim == "length" and q("30 days").dim == "time"
    for a, b in [("1 m", "1 s"), ("1 m", "1 m2"), ("4 °C", "4 kg")]:
        try:
            q(a) < q(b)
        except TypeError:
            continue
        raise AssertionError(f"{a} compared with {b}")
    assert str(mul(q("1,5 m"), 2)) == "3 m"
    try:
        mul(q("4 °C"), 2)   # 8 °C is not twice as warm
    except TypeError:
        pass
    else:
        raise AssertionError("scaled a temperature with an offset")


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


def test_static_decides_measured_facts_and_a_reader_only_narrows_among_its_values():
    rank = lambda type_, attr: ["static", "llm"]  # noqa: E731
    def facts(static, llm):
        ev = load_evidence({"sources": [{"id": "static"}, {"id": "llm:m"}],
                            "facts": {"f": [{"value": v, "source": "static", "at": f"a.rb:{i}"} for i, v in enumerate(static, 1)]
                                      + [{"value": v, "source": "llm:m"} for v in llm]}})
        return sorted(map(str, prefer_sources(ev, rank, narrow=True).facts["f"].values()))
    assert facts([False, False], [True]) == ["False"]  # static is definite: the reader is overridden
    assert facts([False, True], [False]) == ["False"]  # static's sites disagree: the reader picks among them
    assert facts([8, 12], [10]) == ["12", "8"]  # a value static never saw does not narrow
    assert facts([], [True]) == ["True"]  # no static observation: the reader's stands
    # static found no length rule (minimum taken as 0); the reader read one: what was read wins, in either order
    ev = load_evidence({"sources": [{"id": "static"}, {"id": "llm:m"}], "facts": {"f": [
        {"value": 0, "source": "static", "at": "a.py:3", "basis": "absence"}, {"value": 15, "source": "llm:m", "at": "a.py:9"}]}})
    for order in (["static", "llm"], ["llm", "static"]):
        assert prefer_sources(ev, lambda t, a, o=order: o, narrow=True).facts["f"].values() == [15]
    only = load_evidence({"sources": [{"id": "static"}], "facts": {"f": [{"value": 0, "source": "static", "basis": "absence"}]}})
    assert prefer_sources(only, rank).facts["f"].values() == [0]   # with nothing read, the absence stands


def test_a_norm_that_does_not_apply_is_not_applicable_not_a_pass(tmp_path):
    rs = _pack(tmp_path)
    rs.elements[("norm", "flag")].data["applies"] = {"fact": "system.b0"}
    assert validate(rs)[0] == []
    v = lambda facts: _verdicts(rs, facts, ["flag"])["flag"]  # noqa: E731
    assert v({"b0": False, "b2": False})["verdict"] == "not_applicable"
    assert v({"b0": True, "b2": False})["verdict"] == "fail"
    assert v({"b2": True})["verdict"] == "pass"  # met wherever it applies
    open_ = v({"b2": False})
    assert open_["verdict"] == "unknown" and open_["open"] == ["system.b0"]
    # the sources disagree on whether it applies: fails where it does
    both = [{"value": True, "source": "a"}, {"value": False, "source": "b"}]
    assert v({"b0": both, "b2": False})["verdict"] == "uncertain"
    assert summarize([{"norm": "n", "element": "a", "verdict": "not_applicable", "deciding": {}, "open": []},
                      {"norm": "n", "element": "b", "verdict": "pass", "deciding": {}, "open": []}])["n"]["verdict"] == "pass"
    assert summarize([{"norm": "n", "element": "a", "verdict": "not_applicable", "deciding": {}, "open": []}])["n"]["verdict"] == "not_applicable"


def test_when_none_says_what_a_norm_requires_when_no_element_was_found(tmp_path):
    (tmp_path / "pack").mkdir()
    rs = _pack(tmp_path / "pack")
    (tmp_path / "pack" / "predicates.yaml").write_text((tmp_path / "pack" / "predicates.yaml").read_text()
                                                       + "  - name: Log.secret\n    label: logs a secret\n    type: bool\n")
    (tmp_path / "pack" / "norms.yaml").write_text("""norms:
  - name: no_secrets
    title: no_secrets
    modality: obligation
    cite: {section: "L1", url: "https://example.org/l1"}
    for: {l: Log}
    require: {not: {fact: l.secret}}
    when_none: {applies: {fact: system.b0}, require: {fact: system.b1}}
""")
    rs = load(tmp_path / "pack")
    assert validate(rs)[0] == []
    def verdict(facts, elements=()):
        ev = load_evidence({"sources": [{"id": "a"}], "facts": facts, "elements": list(elements)})
        return [(r["verdict"], r.get("none_found")) for r in run(rs, ev)]
    assert verdict({"b0": True, "b1": False}) == [("fail", "Log")]
    assert verdict({"b0": False}) == [("not_applicable", "Log")]
    assert verdict({"b0": True, "b1": False}, [{"type": "Log", "id": "x.rb:3", "facts": {"secret": False}}]) == [("pass", None)]
    rs.elements[("norm", "no_secrets")].data["when_none"] = {"applies": {"fact": "l.secret"}, "require": True}
    assert any("unknown variable 'l'" in e for e in validate(rs)[0])
