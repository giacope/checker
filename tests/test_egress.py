from pathlib import Path

import pytest
import yaml

from normir import Evaluator, Quantity, Residual, amendment_status, ask, load, validate
from normir.model import PackError

ROOT = Path(__file__).resolve().parents[1]
IBC = ROOT / "packs" / "ibc-2024"
AUSTIN = ROOT / "packs" / "austin-2024"
RIVERSIDE = {"occupancy_group": "B", "sprinkler_system": "nfpa13", "has_dwelling_units": False, "care_less_than_24h": True}


def q(text):
    return Quantity.parse(text)


@pytest.mark.parametrize("pack", [IBC, AUSTIN])
def test_packs_validate(pack):
    errors, _ = validate(load(pack))
    assert errors == []


# ------------------------------------------------------------- research mode


def test_corridor_width_stays_open_on_the_facts_it_depends_on():
    a = ask(load(AUSTIN), "required_corridor_width", RIVERSIDE)
    assert not a["determined"]
    assert a["open_facts"] == [
        "Corridor.mep_access_only",
        "Corridor.occupant_load",
        "Corridor.serves_stretcher_traffic",
        "building.accepts_incapable_recipients",
        "building.care_renders_incapable",
        "building.emergency_voice_alarm",
    ]
    assert [c["row"] for c in a["ruled_out"]] == [
        "Group I-2 in areas where required for bed movement",
        "In Group E with a corridor having an occupant load of 100 or more",
        "Within a dwelling unit",
    ]
    assert any("Chapter 25-12, Article 7" in n for n in a["notes"])


@pytest.mark.parametrize(
    "building, corridor, expected",
    [
        # capacity governs once 0.15 in x 300 = 45 in exceeds the 44 in table value
        ({"emergency_voice_alarm": True, "care_renders_incapable": False, "accepts_incapable_recipients": False},
         {"occupant_load": 300, "mep_access_only": False, "serves_stretcher_traffic": False}, "45 in"),
        ({"emergency_voice_alarm": False, "care_renders_incapable": False, "accepts_incapable_recipients": False},
         {"occupant_load": 300, "mep_access_only": False, "serves_stretcher_traffic": False}, "60 in"),
        # stretcher row comes before the under-50 row
        ({"emergency_voice_alarm": False, "care_renders_incapable": True},
         {"occupant_load": 40, "mep_access_only": False, "serves_stretcher_traffic": True}, "72 in"),
        ({"emergency_voice_alarm": False, "care_renders_incapable": True},
         {"occupant_load": 40, "mep_access_only": False, "serves_stretcher_traffic": False}, "36 in"),
        # pack interpretation: the equipment-access row beats the under-50 row
        ({"emergency_voice_alarm": False, "care_renders_incapable": False, "accepts_incapable_recipients": False},
         {"occupant_load": 10, "mep_access_only": True, "serves_stretcher_traffic": False}, "24 in"),
    ],
)
def test_corridor_width_for_a_known_corridor(building, corridor, expected):
    v = Evaluator(load(AUSTIN), {**RIVERSIDE, **building}).term("required_corridor_width", corridor)
    assert v == q(expected)


@pytest.mark.parametrize(
    "group, sprinklers, expected",
    [
        ("B", "nfpa13", "300 ft"),
        ("B", "nfpa13r", "200 ft"),  # footnote c accepts only §903.3.1.1
        ("A-2", "nfpa13r", "250 ft"),  # footnote b accepts §903.3.1.2 too
        ("I-2", "none", "not-permitted"),
        ("H-3", "nfpa13", "150 ft"),
        ("I-4", "none", "150 ft"),
    ],
)
def test_travel_distance(group, sprinklers, expected):
    v = Evaluator(load(AUSTIN), {"occupancy_group": group, "sprinkler_system": sprinklers}).term("max_exit_access_travel_distance")
    assert v == (q(expected) or expected)


def test_travel_distance_does_not_depend_on_ambulatory_care():
    a = ask(load(AUSTIN), "max_exit_access_travel_distance", RIVERSIDE)
    assert a["determined"] and a["value"] == q("300 ft")


# ---------------------------------------------------------- Austin overlay


@pytest.mark.parametrize(
    "space, ibc, austin",
    [
        ({"function": "assembly-standing", "net_floor_area": "700 sqft"}, 140, 100),  # 5 net vs 7 net
        ({"function": "business", "gross_floor_area": "1000 sqft"}, 7, 7),  # 6.67 rounds up
        ({"function": "assembly-unconcentrated", "net_floor_area": "3240 sqft"}, 216, 216),
    ],
)
def test_occupant_load_uses_the_adopted_table(space, ibc, austin):
    assert Evaluator(load(IBC)).term("occupant_load", space) == ibc
    assert Evaluator(load(AUSTIN)).term("occupant_load", space) == austin


def test_rows_missing_from_a_table_go_to_the_building_official():
    space = {"function": "business-concentrated", "gross_floor_area": "1000 sqft"}
    ibc = Evaluator(load(IBC)).term("occupant_load_factor", space)
    austin = Evaluator(load(AUSTIN)).term("occupant_load_factor", space)
    assert ibc.expr == {"see": "1004.8", "row": "Concentrated business use areas"}
    assert "unlisted" in austin.expr


@pytest.mark.parametrize(
    "section, table, expected",
    [
        ("1020.3", None, "Not amended"),
        ("903.3.1.1", None, "Deleted by City of Austin Ordinance No. 20250410-045 (Chapter 9); see City Code Chapter 25-12, Article 7"),
        (None, "1004.5", "Deleted and replaced"),
        ("103.2", None, "Deleted by"),  # "103 plus subsections"
        ("1010.1.2", None, "Deleted by"),
        ("1010.1.2.1", None, "Not amended"),  # deleted without "plus subsections"
    ],
)
def test_amendment_status(section, table, expected):
    assert amendment_status(load(AUSTIN), None, section, table).startswith(expected)


# --------------------------------------------------------------------- norms


def test_corridor_norm():
    ev = Evaluator(load(AUSTIN), {**RIVERSIDE, "emergency_voice_alarm": False, "care_renders_incapable": False, "accepts_incapable_recipients": False})
    corridor = {"occupant_load": 120, "mep_access_only": False, "serves_stretcher_traffic": False}
    assert ev.norm("1020.3", {**corridor, "clear_width": "41.5 in"}) is False
    assert ev.norm("1020.3", {**corridor, "clear_width": "44 in"}) is True
    assert isinstance(ev.norm("1020.3", corridor), Residual)


@pytest.mark.parametrize(
    "voice, occupants, expected",
    [
        (False, 40, "36 in"),  # Exception 1: fewer than 50 occupants
        (False, 50, "44 in"),
        (False, 200, "60 in"),  # capacity governs: 0.3 in x 200
        (True, 200, "44 in"),  # 0.2 in x 200 = 40 in, below the 44 in minimum
    ],
)
def test_stair_width(voice, occupants, expected):
    ev = Evaluator(load(AUSTIN), {**RIVERSIDE, "emergency_voice_alarm": voice})
    assert ev.term("required_stair_width", {"occupant_load": occupants}) == q(expected)


@pytest.mark.parametrize(
    "riser, tread, ok",
    [
        ("7 in", "11 in", True),
        ("7.25 in", "11 in", False),
        ("3.5 in", "11 in", False),
        ("176 mm", "280 mm", True),
        ("176 mm", "279 mm", False),  # pack reads 11 in strictly; 279 mm is 10.98 in
    ],
)
def test_riser_and_tread(riser, tread, ok):
    assert Evaluator(load(AUSTIN)).norm("1011.5.2", {"riser_height": riser, "tread_depth": tread}) is ok


# ---------------------------------------------------------------- validator


def test_validator_catches_authoring_mistakes(tmp_path):
    (tmp_path / "package.yaml").write_text("package: bad\nversion: 0.0.1\nsubject: building\ntext_policy: link-only\n")
    (tmp_path / "rules.yaml").write_text(
        """
predicates:
  - {name: building.occupancy_group, type: enum, values: [B, E]}
terms:
  - name: wide
    cite: {section: "1", url: https://example.com, quote: "copied text"}
    value:
      cases:
        - when: {eq: [{fact: building.occupancy_group}, Group-B]}
          then: 44 in
          cite: {row: x}
        - when: {fact: building.stories}
          then: 36 in
"""
    )
    errors, _ = validate(load(tmp_path))
    joined = "\n".join(errors)
    assert "'Group-B' is not a value" in joined
    assert "undeclared predicate 'building.stories'" in joined
    assert "needs a 'cite'" in joined
    assert "link-only" in joined
    # the subject is declared, never assumed to be a building
    (tmp_path / "package.yaml").write_text("package: bad\nversion: 0.0.1\ntext_policy: link-only\n")
    assert any("declares no subject" in e for e in validate(load(tmp_path))[0])


@pytest.mark.parametrize(
    "cite, ok",
    [
        ({"section": "4.2", "url": "https://example.com/std#4.2"}, True),
        ({"section": "4.2", "at": "policy.pdf#L10-L12"}, True),                                   # customer document, no url
        ({"section": "4.2", "at": "policy.pdf#L10-L12", "url": "/regulations/r1#c3"}, True),       # app path
        ({"section": "4.2", "url": "/regulations/r1#c3"}, False),                                 # app path without at
        ({"section": "4.2", "at": "policy.pdf#L10-L12", "url": "http://example.com"}, False),     # not https
        ({"section": "4.2", "at": "policy.pdf#L10-L12", "url": "//evil.example/x"}, False),       # not an app path
        ({"at": "policy.pdf#L10-L12"}, False),                                                     # no section
    ],
)
def test_validator_accepts_customer_document_citations(tmp_path, cite, ok):
    (tmp_path / "package.yaml").write_text("package: own\nversion: '1'\nsubject: building\ntext_policy: public\n")
    (tmp_path / "rules.yaml").write_text(yaml.safe_dump({
        "predicates": [{"name": "building.sprinklered", "type": "bool"}],
        "norms": [{"name": "n1", "modality": "obligation", "cite": cite, "require": {"fact": "building.sprinklered"}}],
    }))
    errors, _ = validate(load(tmp_path))
    assert (errors == []) is ok, errors


# ---------------------------------------------------------------- packages of the wrong shape

GOOD_RULES = """predicates:
  - {name: building.sprinklered, type: bool}
  - {name: building.group, type: enum, values: [B, E]}
terms:
  - name: wide
    cite: {section: "1", url: "https://example.com/1"}
    value: {cases: [{when: {fact: building.sprinklered}, then: 44 in, cite: {row: a}}, {else: 36 in, cite: {row: b}}]}
norms:
  - {name: n1, cite: {section: "2", url: "https://example.com/2"}, require: {ge: [{term: wide}, 36 in]}}
"""


def _pack_with(tmp_path, extra: bytes | str, meta: str = "package: p\nversion: '1'\nsubject: building\n"):
    pack = tmp_path / "p"
    pack.mkdir()
    (pack / "package.yaml").write_text(meta)
    (pack / "rules.yaml").write_text(GOOD_RULES)
    (pack / "extra.yaml").write_bytes(extra if isinstance(extra, bytes) else extra.encode())
    return pack


DEEP = "norms:\n  - name: X1\n    cite: {section: '1', url: 'https://example.com'}\n    require: " + "{all: [" * 3000 + "true" + "]}" * 3000 + "\n"
LAUGHS = ("terms:\n  - name: l0\n    cite: {section: '1', url: 'https://example.com'}\n    value: &a0 {all: [true, true, true, true, true, true, true, true, true, true]}\n"
          + "".join(f"  - name: l{i}\n    cite: {{section: '1', url: 'https://example.com'}}\n    value: &a{i} {{all: [{', '.join(['*a' + str(i - 1)] * 10)}]}}\n"
                    for i in range(1, 9)))


@pytest.mark.parametrize("extra, error", [
    ("- norms\n", "extra.yaml: maps sections (predicates, tables, terms, norms) to lists of items, got a list"),
    ("norms: {a: 1}\n", "extra.yaml: norms takes a list of items, got a mapping"),
    ("norms: 5\n", "extra.yaml: norms takes a list of items, got a number"),
    ("norms: [a]\n", "extra.yaml: norms[0] needs a 'name' (text); it is text, not a mapping"),
    ("norms: [{title: x}]\n", "extra.yaml: norms[0] needs a 'name' (text)"),
    ("predicates: [{name: [a, b]}]\n", "extra.yaml: predicates[0] needs a 'name' (text)"),
    ("predicates: [{name: building.x, type: [bool]}]\n", "p: predicate 'building.x': 'type' takes a type name"),
    ("predicates: [{name: building.x, type: enum, values: 5}]\n", "p: predicate 'building.x': 'values' takes a list of values"),
    ("norms: [{name: X1, cite: '1', require: true}]\n", "p: norm 'X1': needs cite.section and an https cite.url"),
    ("norms: [{name: X1, status: {a: 1}, cite: {section: '1', url: 'https://e.com'}, require: true}]\n", "p: norm 'X1': status must be one of"),
    ("tables: [{name: T1, key: building.group, columns: [w], rows: [{row: a, w: 1}]}]\n", "p: table 'T1': rows[0] needs a 'key'"),
    # a malformed term is reported once; the norm that uses it is not checked against it
    (("terms: [{name: t1, cite: {section: '1', url: 'https://e.com'}, value: {not: {fact: [building, sprinklered]}}}]\n"
      "norms: [{name: X1, cite: {section: '1', url: 'https://e.com'}, require: {term: t1}}]\n"), "p: term 't1': 'fact' takes a name like var.attr"),
    (("terms: [{name: t1, cite: {section: '1', url: 'https://e.com'}, value: {all: [{}]}}]\n"
      "norms: [{name: X1, cite: {section: '1', url: 'https://e.com'}, require: {term: t1}}]\n"), "p: term 't1': not an expression: {}"),
    (b"norms: [{name: caf\xe9}]\n", "extra.yaml: not UTF-8 text: byte 0xe9 at line 1"),
    ("norms: !!python/object/apply:os.system ['echo pwned']\n", "extra.yaml: not valid YAML"),
    (DEEP, "extra.yaml: nested deeper than 100 levels at line 4"),
    (LAUGHS, "extra.yaml: aliases repeat"),
])
def test_validator_reports_malformed_files_and_items(tmp_path, extra, error):
    errors, _ = validate(load(_pack_with(tmp_path, extra)))
    assert any(e.startswith(error) for e in errors), errors
    assert not any("'X1'" in e and "term 't1'" in e for e in errors)  # no second error about the malformed term


@pytest.mark.parametrize("meta, error", [
    ("", "p/package.yaml: is empty, not a mapping"),
    ("- a\n", "p/package.yaml: is a list, not a mapping"),
    ("title: x\n", "p/package.yaml: 'package' takes the package's name, got missing"),
    ("package: [p]\n", "p/package.yaml: 'package' takes the package's name, got a list"),
    ("package: p\nextends: p\n", "extends loops: p -> p"),
    ("package: p\nextends: ../../../etc\n", "p: extends '../../../etc', which is not the name of a package next to it"),
    ("package: p\nextends: nope\n", "nope: no readable package.yaml"),
])
def test_a_package_that_cannot_be_read_raises_pack_error(tmp_path, meta, error):
    with pytest.raises(PackError) as e:
        load(_pack_with(tmp_path, "", meta))
    assert str(e.value).startswith(error), e.value


def test_a_package_without_package_yaml_or_with_bytes_that_are_not_utf8_raises_pack_error(tmp_path):
    pack = _pack_with(tmp_path, "")
    (pack / "package.yaml").write_bytes(b"package: p\ntitle: caf\xe9\n")
    with pytest.raises(PackError, match="p/package.yaml: not UTF-8 text: byte 0xe9 at line 2"):
        load(pack)
    (pack / "package.yaml").unlink()
    with pytest.raises(PackError, match="p: no readable package.yaml"):
        load(pack)


def test_malformed_patches_are_errors_of_the_extending_package(tmp_path):
    _pack_with(tmp_path, "")
    top = tmp_path / "top"
    top.mkdir()
    (top / "package.yaml").write_text("package: top\nextends: p\npatches: [{kind: norm, name: n1}, 5]\n")
    errors, _ = validate(load(top))
    assert "top: package.yaml patches[0] needs 'op', 'kind' and 'name' (text)" in errors
    assert "top: package.yaml patches[1] needs 'op', 'kind' and 'name' (text)" in errors
