"""Answer tests for packs/jp-bsa-egress (建築基準法施行令 避難規定).

Expected values are read from the statute text (e-Gov, as of 2026-11-14), not
from the pack: each test picks inputs on both sides of a threshold.
"""

import re
from pathlib import Path

import yaml

from normir import Evaluator, Quantity, Residual, ask, load, validate
from normir.model import walk

ROOT = Path(__file__).resolve().parents[1]
JP = ROOT / "packs" / "jp-bsa-egress"


def q(text):
    return Quantity.parse(text)


def term(building, name, instance=None):
    return Evaluator(load(JP), building).term(name, instance)


# A stair with every 令23条 classification fact settled; tests override what they vary.
PLAIN_STAIR = {
    "special_purpose_only": False,
    "uses_mlit_structure_23_4": False,
    "outdoor": False,
    "direct_stair_120_121": True,
    "within_dwelling": False,
    "for_pupils": False,
    "for_customers": False,
    "in_basement": False,
    "habitable_area_of_floor_above": "100 m2",
}
HOSPITAL_6F = {"principal_use": "hospital", "stories": 6, "total_floor_area": "4800 m2",
               "main_structure": "fire_resistant", "adult_entertainment_use": False}
OFFICE_3F = {"principal_use": "office", "stories": 3, "total_floor_area": "1500 m2",
             "main_structure": "fire_resistant", "adult_entertainment_use": False}
SMALL_OFFICE_2F = {"principal_use": "office", "stories": 2, "total_floor_area": "500 m2",
                   "main_structure": "other", "adult_entertainment_use": False}
UPPER_ROOM = {"on_evacuation_floor": False, "windowless_116_2_1": False, "finish_quasi_noncombustible": False}


def stair_values(building, stair):
    return [term(building, n, stair) for n in ("min_stair_width", "max_stair_riser", "min_stair_tread", "max_stair_rise_without_landing")]


# ------------------------------------------------------------------ package


def test_pack_validates_without_warnings():
    errors, warnings = validate(load(JP))
    assert errors == []
    assert warnings == []


def test_every_citation_links_to_the_pinned_egov_revision():
    meta = yaml.safe_load((JP / "package.yaml").read_text())
    assert meta["text_policy"] == "public" and "extends" not in meta
    revisions = {law["law_revision_id"] for law in meta["source"]["laws"]}
    assert revisions == {"325CO0000000338_20261101_508CO0000000284", "325AC0000000201_20260527_508AC0000000023"}
    pattern = re.compile(
        r"^https://laws\.e-gov\.go\.jp/law/(325CO0000000338/20261101_508CO0000000284|325AC0000000201/20260527_508AC0000000023)"
        r"#(Mp-[A-Za-z0-9_-]+|Mpat_\d+)$"
    )
    rs = load(JP)
    for el in rs.elements.values():
        assert el.data.get("status", "draft") == "draft"
        for node in walk(el.data):
            if "url" in node:
                assert pattern.match(node["url"]), (el.name, node["url"])


# ------------------------------------------------------------ 令23条・令24条


def test_stair_in_an_elementary_school_vs_a_house():
    # 表(一): 140 cm以上, 16 cm以下, 26 cm以上; 令24条: landing every 3 m for (一)(二).
    school = {"principal_use": "school_elementary", "stories": 3, "total_floor_area": "4000 m2"}
    assert stair_values(school, {**PLAIN_STAIR, "for_pupils": True}) == [q("1400 mm"), q("160 mm"), q("260 mm"), q("3 m")]
    # 表(四) 75/22/21, relaxed by ただし書 for 住宅の階段: 蹴上げ23 cm以下, 踏面15 cm以上; landing every 4 m.
    house = {"principal_use": "detached_house", "stories": 2, "total_floor_area": "120 m2"}
    assert stair_values(house, {**PLAIN_STAIR, "within_dwelling": True, "habitable_area_of_floor_above": "50 m2"}) == [q("750 mm"), q("230 mm"), q("150 mm"), q("4 m")]


def test_stair_row_3_needs_more_than_200_m2_of_rooms_on_the_floor_above():
    assert stair_values(OFFICE_3F, {**PLAIN_STAIR, "habitable_area_of_floor_above": "250 m2"})[:3] == [q("1200 mm"), q("200 mm"), q("240 mm")]
    assert stair_values(OFFICE_3F, {**PLAIN_STAIR, "habitable_area_of_floor_above": "200 m2"})[:3] == [q("750 mm"), q("220 mm"), q("210 mm")]


def test_outdoor_direct_stair_may_be_90_cm_in_a_large_store():
    store = {"principal_use": "retail_store", "store_floor_area": "2000 m2", "stories": 3, "total_floor_area": "2000 m2"}
    customer = {**PLAIN_STAIR, "for_customers": True}
    assert term(store, "min_stair_width", customer) == q("1400 mm")  # 表(二)
    assert term(store, "min_stair_width", {**customer, "outdoor": True}) == q("900 mm")  # ただし書
    assert term(store, "max_stair_riser", {**customer, "outdoor": True}) == q("180 mm")  # riser stays 表(二)
    # 1,500 m2 is not "more than 1,500": the customer stair falls to 表(四).
    assert term({**store, "store_floor_area": "1500 m2"}, "min_stair_width", customer) == q("750 mm")


def test_stair_norm():
    school = {"principal_use": "school_elementary", "stories": 3, "total_floor_area": "4000 m2"}
    stair = {**PLAIN_STAIR, "for_pupils": True, "riser": "160 mm", "tread": "260 mm"}
    ev = Evaluator(load(JP), school)
    assert ev.norm("令23条1項", {**stair, "width": "1350 mm"}) is False
    assert ev.norm("令23条1項", {**stair, "width": "1400 mm"}) is True
    assert isinstance(ev.norm("令23条1項", {**stair, "riser": None}), Residual)


# ----------------------------------------------------------- 令117条・令119条


def test_corridor_double_loaded_vs_single_loaded():
    corridor = {"exclusive_to_three_rooms_or_fewer": False, "in_basement": False, "floor_habitable_area": "250 m2"}
    assert term(OFFICE_3F, "min_corridor_width_119", {**corridor, "rooms_on_both_sides": True}) == q("1.6 m")
    assert term(OFFICE_3F, "min_corridor_width_119", {**corridor, "rooms_on_both_sides": False}) == q("1.2 m")
    # 200 m2 of rooms on the floor is not "more than 200": no row of the table applies.
    assert term(OFFICE_3F, "min_corridor_width_119", {**corridor, "floor_habitable_area": "200 m2", "rooms_on_both_sides": True}) == "not-required"


def test_corridor_for_pupils_in_a_school():
    school = {"principal_use": "school_secondary", "stories": 3, "total_floor_area": "6000 m2"}
    assert term(school, "min_corridor_width_119", {"for_pupils": True, "rooms_on_both_sides": True}) == q("2.3 m")
    assert term(school, "min_corridor_width_119", {"for_pupils": True, "rooms_on_both_sides": False}) == q("1.8 m")


def test_section_scope_small_office_vs_hospital():
    # 令117条1項: a 2-storey 500 m2 office with no windowless room is outside 第5章第2節.
    assert term(SMALL_OFFICE_2F, "section_5_2_applies") is False
    assert term(SMALL_OFFICE_2F, "max_walking_distance_to_direct_stair", {"on_floor_with_windowless_room": False}) == "not-applicable"
    # ... unless its floor has a 令116条の2第1項1号 windowless room: then 表(一), 30 m.
    windowless = {**UPPER_ROOM, "on_floor_with_windowless_room": True, "windowless_116_2_1": True, "meets_mlit_windowless_criteria": False, "storey": 2}
    assert term(SMALL_OFFICE_2F, "max_walking_distance_to_direct_stair", windowless) == q("30 m")
    # A hospital is a 法別表第一(い)欄(二)項 building whatever its size.
    assert term({**SMALL_OFFICE_2F, "principal_use": "hospital"}, "section_5_2_applies") is True


# ------------------------------------------------------------------ 令120条


def test_walking_distance_hospital_ward_by_structure_and_finish():
    ward = {**UPPER_ROOM, "main_use_room": True, "storey": 3}
    assert term(HOSPITAL_6F, "max_walking_distance_to_direct_stair", ward) == q("50 m")  # 表(二) 準耐火等
    assert term(HOSPITAL_6F, "max_walking_distance_to_direct_stair", {**ward, "finish_quasi_noncombustible": True}) == q("60 m")  # 2項 +10
    assert term({**HOSPITAL_6F, "main_structure": "other"}, "max_walking_distance_to_direct_stair", ward) == q("30 m")  # 表(二) その他


def test_walking_distance_fifteenth_floor():
    tower = {**OFFICE_3F, "stories": 20, "total_floor_area": "30000 m2"}
    office = {**UPPER_ROOM, "main_use_room": False}
    finished = {**office, "finish_quasi_noncombustible": True}
    assert term(tower, "max_walking_distance_to_direct_stair", {**finished, "storey": 14}) == q("60 m")  # 50 + 10
    assert term(tower, "max_walking_distance_to_direct_stair", {**finished, "storey": 15}) == q("50 m")  # 2項ただし書, 3項 excepts 2項本文
    assert term(tower, "max_walking_distance_to_direct_stair", {**office, "storey": 15}) == q("40 m")  # 3項: 50 - 10
    assert term({**tower, "main_structure": "other"}, "max_walking_distance_to_direct_stair", {**office, "storey": 15}) == q("30 m")  # 40 - 10


def test_walking_distance_main_room_of_a_class_4_building():
    store = {"principal_use": "retail_store", "store_floor_area": "2400 m2", "stories": 3, "total_floor_area": "2400 m2", "main_structure": "fire_resistant"}
    room = {**UPPER_ROOM, "finish_quasi_noncombustible": True, "storey": 2}
    assert term(store, "max_walking_distance_to_direct_stair", {**room, "main_use_room": True}) == q("40 m")  # 表(一) 30 + 10
    assert term(store, "max_walking_distance_to_direct_stair", {**room, "main_use_room": False}) == q("60 m")  # 表(三) 50 + 10


def test_unknown_structure_leaves_a_residual():
    building = {k: v for k, v in HOSPITAL_6F.items() if k != "main_structure"}
    a = ask(load(JP), "max_walking_distance_to_direct_stair", building, {**UPPER_ROOM, "main_use_room": True, "storey": 3})
    assert not a["determined"]
    assert a["open_facts"] == ["building.main_structure"]
    assert a["answer"].startswith("50 m if 主要構造部の構造 is one of fire_resistant, quasi_fire_resistant, noncombustible; otherwise 30 m")
    assert "令120条4項（主要構造部を準耐火構造とした共同住宅のメゾネット住戸で歩行距離40メートル以下のもの）" in a["not_formalized"]


# ------------------------------------------------------------------ 令121条


def test_two_stairs_hospital_ward_area_doubles_with_fire_resistive_structure():
    floor = {"storey": 3, "is_evacuation_floor": False, "directly_above_evacuation_floor": False, "habitable_area": "150 m2"}
    assert term(HOSPITAL_6F, "two_direct_stairs_required", {**floor, "ward_area": "120 m2"}) is True  # 4号, 2項: > 100 m2
    # 100 m2 is not "more than 100", and 6号ロ: 150 m2 ≤ 200 m2.
    assert term(HOSPITAL_6F, "two_direct_stairs_required", {**floor, "ward_area": "100 m2"}) is False
    assert term({**HOSPITAL_6F, "main_structure": "other"}, "two_direct_stairs_required", {**floor, "ward_area": "80 m2"}) is True  # 4号: > 50 m2


def test_two_stairs_sixth_floor_and_above():
    tower = {**OFFICE_3F, "stories": 8, "total_floor_area": "2000 m2"}
    floor = {"storey": 7, "is_evacuation_floor": False, "habitable_area": "90 m2"}
    assert term(tower, "two_direct_stairs_required", {**floor, "has_balcony_and_123_stair": True}) is False  # 6号イ かっこ書
    assert term(tower, "two_direct_stairs_required", {**floor, "has_balcony_and_123_stair": False}) is True


def test_two_stairs_floor_directly_above_the_evacuation_floor():
    floor = {"storey": 2, "is_evacuation_floor": False, "directly_above_evacuation_floor": True, "habitable_area": "350 m2"}
    assert term(OFFICE_3F, "two_direct_stairs_required", floor) is False  # 6号ロ: 200 → 400 m2 under 2項
    assert term({**OFFICE_3F, "main_structure": "other"}, "two_direct_stairs_required", floor) is True  # > 200 m2
    assert term(SMALL_OFFICE_2F, "two_direct_stairs_required", {**floor, "has_windowless_room": False}) == "not-applicable"  # 令117条


# --------------------------------------------------------- 令121条3項・令125条


def test_overlap_and_exterior_exit_distances():
    office_room = {**UPPER_ROOM, "main_use_room": False, "storey": 3}
    # 121条3項: half of the 令120条 value (50 m).
    assert term(OFFICE_3F, "max_overlapping_route_length_121_3",
                {**office_room, "floor_requires_two_direct_stairs": True, "escape_to_balcony_without_overlap": False}) == q("25 m")
    # 125条1項 on the evacuation floor: twice the 令120条 value.
    ground = {**office_room, "storey": 1, "on_evacuation_floor": True, "has_effective_evacuation_opening": False}
    assert term(OFFICE_3F, "max_walking_distance_room_to_exterior_exit", ground) == q("100 m")
    ward = {**ground, "main_use_room": True}
    assert term({**HOSPITAL_6F, "main_structure": "other"}, "max_walking_distance_room_to_exterior_exit", ward) == q("60 m")
    assert term(OFFICE_3F, "max_walking_distance_room_to_exterior_exit", office_room) == "not-applicable"  # upper floor: 令120条


def test_store_exterior_exit_width():
    # 125条3項: 60 cm per 100 m2 of the largest floor, for stores of more than 1,500 m2.
    store = {"principal_use": "retail_store", "store_floor_area": "2400 m2", "stories": 3, "total_floor_area": "2400 m2", "largest_floor_area": "800 m2"}
    assert term(store, "min_total_exterior_exit_width_125_3") == q("4.8 m")
    assert term({**store, "store_floor_area": "1200 m2"}, "min_total_exterior_exit_width_125_3") == "not-applicable"
