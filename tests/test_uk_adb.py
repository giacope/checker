"""Answer tests for packs/uk-adb-v2 (Approved Document B Volume 2, means of escape).

Expected values are read from the document text (gov.uk PDF, 2019 edition
incorporating 2020, 2022, 2025 and 2026 amendments, retrieved 2026-11-14), not
from the pack: each test picks inputs on both sides of a threshold.
"""

import re
from pathlib import Path

import pytest
import yaml

from normir import Evaluator, Quantity, Residual, ask, load, validate
from normir.model import walk

ROOT = Path(__file__).resolve().parents[1]
ADB = ROOT / "packs" / "uk-adb-v2"
PDF = "https://assets.publishing.service.gov.uk/media/6aa3bb7492e72b8ac437f145/AD_B2_2026.pdf"


def q(text):
    return Quantity.parse(text)


def term(building, name, instance=None):
    return Evaluator(load(ADB), building).term(name, instance)


def norm(building, name, instance=None):
    return Evaluator(load(ADB), building).norm(name, instance)


OFFICE = {"purpose_group": "office"}
OPEN_FLOOR = {"is_plant_room": False, "is_place_of_special_fire_hazard": False}


# ------------------------------------------------------------------ package


def test_pack_validates_without_warnings():
    errors, warnings = validate(load(ADB))
    assert errors == []
    assert warnings == []


def test_package_metadata_and_every_url_is_https_with_a_page_fragment():
    meta = yaml.safe_load((ADB / "package.yaml").read_text())
    assert meta["package"] == "uk-adb-v2"
    assert meta["text_policy"] == "public" and "extends" not in meta
    assert meta["licence"]["url"].startswith("https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3")
    assert meta["requirement"]["url"] == "https://www.legislation.gov.uk/uksi/2010/2214/schedule/1"
    assert meta["source"]["url"] == PDF
    page = re.compile(r"^" + re.escape(PDF) + r"#page=(\d+)$")
    rs = load(ADB)
    urls = 0
    for el in rs.elements.values():
        assert el.data.get("status", "draft") == "draft", el.name
        for node in walk(el.data):
            if "url" in node:
                m = page.match(node["url"])
                assert m, (el.name, node["url"])
                assert 1 <= int(m.group(1)) <= meta["source"]["pages"]
                urls += 1
    assert urls > 30


# ------------------------------------------------------------ Table 2.1


def test_office_travel_distance_one_direction_vs_more_than_one():
    assert term(OFFICE, "max_travel_distance", {**OPEN_FLOOR, "alternative_escape_routes": False}) == q("18 m")
    assert term(OFFICE, "max_travel_distance", {**OPEN_FLOOR, "alternative_escape_routes": True}) == q("45 m")
    # Note 1: direct distance is two-thirds of the travel distance (45 m -> 30 m).
    assert term(OFFICE, "max_direct_distance", {**OPEN_FLOOR, "alternative_escape_routes": True}) == q("30 m")


@pytest.mark.parametrize(
    "building, space, one, more",
    [
        ({"purpose_group": "residential-institutional"}, {}, "9 m", "18 m"),
        ({"purpose_group": "residential-other"}, {"residential_other_area": "bedroom-corridor"}, "9 m", "35 m"),
        ({"purpose_group": "assembly-and-recreation", "primarily_for_disabled_people": False}, {"seating_in_rows": True}, "15 m", "32 m"),
        ({"purpose_group": "industrial"}, {"higher_hazard": True}, "12 m", "25 m"),
        ({"purpose_group": "storage-and-other-non-residential"}, {"higher_hazard": False}, "25 m", "45 m"),
        (OFFICE, {"is_plant_room": True, "plant_escape_route_in_open_air": True}, "60 m", "100 m"),
    ],
)
def test_table_2_1_rows(building, space, one, more):
    space = {**OPEN_FLOOR, **space}
    assert term(building, "max_travel_distance_one_direction", space) == q(one)
    assert term(building, "max_travel_distance_more_than_one_direction", space) == q(more)


def test_place_of_special_fire_hazard_within_room_limit():
    boiler = {"is_place_of_special_fire_hazard": True, "is_plant_room": False}
    assert term(OFFICE, "max_travel_distance_within_room", {**boiler, "alternative_escape_routes": False}) == q("9 m")
    assert term(OFFICE, "max_travel_distance_within_room", {**boiler, "alternative_escape_routes": True}) == q("18 m")
    # Note 5: outside the room the purpose group limit applies.
    assert term(OFFICE, "max_travel_distance", {**boiler, "alternative_escape_routes": True}) == q("45 m")


def test_norm_2_7_limits_the_one_direction_part_of_a_two_direction_route():
    space = {**OPEN_FLOOR, "alternative_escape_routes": True, "travel_distance": "40 m"}
    assert norm(OFFICE, "ADB2 2.7", {**space, "one_direction_travel_distance": "15 m"}) is True
    assert norm(OFFICE, "ADB2 2.7", {**space, "one_direction_travel_distance": "20 m"}) is False  # > 18 m
    assert norm(OFFICE, "ADB2 2.7", {**space, "travel_distance": "46 m", "one_direction_travel_distance": "15 m"}) is False


def test_unknown_purpose_group_leaves_a_residual():
    a = ask(load(ADB), "max_travel_distance", {}, {**OPEN_FLOOR, "alternative_escape_routes": True})
    assert not a["determined"]
    assert "building.purpose_group" in a["open_facts"]


# --------------------------------------------------- Table D1, Table 2.2


def test_occupant_number_from_floor_space_factors():
    assert term(OFFICE, "occupant_number", {"accommodation": "office", "floor_area": "600 m2"}) == 100  # 600 / 6
    assert term(OFFICE, "occupant_number", {"accommodation": "office", "floor_area": "601 m2"}) == 101  # rounded up
    assert term({}, "occupant_number", {"accommodation": "committee-room-dining-room-restaurant-meeting-room", "floor_area": "75 m2"}) == 75
    assert term({}, "occupant_number", {"accommodation": "car-park", "parking_spaces": 40}) == 80  # two per space


@pytest.mark.parametrize("people, routes", [(60, 1), (61, 2), (600, 2), (601, 3)])
def test_minimum_number_of_escape_routes_from_a_storey(people, routes):
    assert term(OFFICE, "min_escape_routes_from_storey", {"occupant_number": people}) == routes


def test_office_room_needs_a_second_exit_above_60_people():
    assert term(OFFICE, "min_escape_routes_from_room", {"accommodation": "office", "floor_area": "360 m2"}) == 1  # 60
    assert term(OFFICE, "min_escape_routes_from_room", {"accommodation": "office", "floor_area": "361 m2"}) == 2  # 61


def test_single_escape_route_storey_and_inner_room_limits():
    assert term(OFFICE, "single_escape_route_acceptable_for_storey", {"occupant_number": 60, "one_direction_travel_limits_met": True}) is True
    assert term(OFFICE, "single_escape_route_acceptable_for_storey", {"occupant_number": 61, "one_direction_travel_limits_met": True}) is False
    assert term({"purpose_group": "residential-institutional"}, "max_inner_room_occupant_number") == 30
    assert term(OFFICE, "max_inner_room_occupant_number") == 60


# --------------------------------------------------------------- Table 2.3


@pytest.mark.parametrize(
    "people, width",
    [(60, "750 mm"), (61, "850 mm"), (110, "850 mm"), (111, "1050 mm"), (220, "1050 mm"), (221, "1105 mm"), (300, "1500 mm")],
)
def test_exit_width(people, width):
    assert term(OFFICE, "min_exit_width", {"people": people}) == q(width)


def test_gangway_between_racking_may_be_530_except_in_public_shop_areas():
    racking = {"people": 40, "gangway_between_fixed_storage_racking": True, "in_public_area": True}
    assert term({"purpose_group": "storage-and-other-non-residential"}, "min_escape_route_width", racking) == q("530 mm")
    assert term({"purpose_group": "shop-and-commercial"}, "min_escape_route_width", racking) == q("750 mm")
    assert term({"purpose_group": "shop-and-commercial"}, "min_escape_route_width", {**racking, "in_public_area": False}) == q("530 mm")


def test_exit_capacity_and_exit_width_norm():
    assert term(OFFICE, "exit_capacity", {"width": "850 mm"}) == 110  # 2.22 example: 3 x 110 = 330
    assert term(OFFICE, "exit_capacity", {"width": "1000 mm"}) == 110  # no interpolation below 1050
    assert term(OFFICE, "exit_capacity", {"width": "1200 mm"}) == pytest.approx(240)
    assert norm(OFFICE, "ADB2 2.18 (exits)", {"people": 240, "width": "1200 mm"}) is True
    assert norm(OFFICE, "ADB2 2.18 (exits)", {"people": 241, "width": "1200 mm"}) is False


# ------------------------------------------------------- Tables 3.1-3.3


STAIR = {"staff_only": False, "serves_assembly_area_of_100m2_or_more": False, "serves_area_with_occupancy_over_50": True, "serves_basement": False}


def test_table_3_1_simple_rows():
    ri = {"purpose_group": "residential-institutional"}
    assert term(ri, "min_stair_width", {**STAIR, "people_served": 150}) == q("1000 mm")  # 1a
    assert term(ri, "min_stair_width", {**STAIR, "people_served": 40, "staff_only": True}) == q("800 mm")  # row 2
    hall = {"purpose_group": "assembly-and-recreation"}
    assert term(hall, "min_stair_width", {**STAIR, "serves_assembly_area_of_100m2_or_more": True, "people_served": 220}) == q("1100 mm")  # 1b
    assert term(OFFICE, "min_stair_width", {**STAIR, "people_served": 50}) == q("800 mm")  # row 2


def test_table_3_2_simultaneous_evacuation():
    simultaneous = {**OFFICE, "evacuation_strategy": "simultaneous", "open_spatial_planning": False}
    stair = {**STAIR, "floors_served": 3}
    assert term(simultaneous, "min_stair_width", {**stair, "people_served": 300}) == q("1100 mm")  # 3 floors, 1100mm: 300
    assert term(simultaneous, "min_stair_width", {**stair, "people_served": 301}) == q("1200 mm")  # 1200mm: 330
    assert term(simultaneous, "min_stair_width", {**stair, "floors_served": 10, "people_served": 1035}) == q("1800 mm")
    # Beyond 1800mm (3.18 formula) or 10 floors (note 1) the width is an open fact.
    v = term(simultaneous, "min_stair_width", {**stair, "floors_served": 12, "people_served": 400})
    assert isinstance(v, Residual) and v.expr == {"fact": "Stair.calculated_min_width"}


def test_table_3_3_phased_evacuation_and_3_16():
    phased = {**OFFICE, "evacuation_strategy": "phased", "open_spatial_planning": False}
    stair = {**STAIR, "people_served": 240}
    assert term(phased, "min_stair_width", {**stair, "phased_people_per_storey": 100}) == q("1000 mm")
    assert term(phased, "min_stair_width", {**stair, "phased_people_per_storey": 101}) == q("1100 mm")
    # 3.16a: a stair serving a basement is sized for simultaneous evacuation regardless.
    assert term(phased, "simultaneous_evacuation_design", {**stair, "serves_basement": True}) is True
    assert term({**phased, "purpose_group": "assembly-and-recreation"}, "simultaneous_evacuation_design", stair) is True  # 3.16c


def test_norm_3_10_stair_as_wide_as_the_exits_onto_it():
    # Worked example on PDF page 48: 120 people per stair -> 1100mm by Table 3.3, but the
    # storey exit for 240 people is 1200mm, so the stair must be 1200mm.
    phased = {**OFFICE, "evacuation_strategy": "phased", "open_spatial_planning": False}
    stair = {**STAIR, "people_served": 240, "phased_people_per_storey": 120, "widest_exit_width": "1200 mm", "rise": "30 m", "has_central_handrail": False}
    assert norm(phased, "ADB2 3.10", {**stair, "width": "1100 mm"}) is False
    assert norm(phased, "ADB2 3.10", {**stair, "width": "1200 mm"}) is True
    # 3.10d: over 30m rise, no more than 1400mm without a central handrail.
    tall = {**stair, "rise": "31 m", "width": "1500 mm", "widest_exit_width": "1500 mm"}
    assert norm(phased, "ADB2 3.10", tall) is False
    assert norm(phased, "ADB2 3.10", {**tall, "has_central_handrail": True}) is True


def test_protected_lobbies_at_18_m():
    stair = {"is_firefighting_stair": False, "not_discounted_under_3_15b": False, "is_only_stair": False, "smoke_control_3_15a": False}
    simultaneous = {**OFFICE, "evacuation_strategy": "simultaneous"}
    assert term(simultaneous, "protected_lobbies_required", {**stair, "top_storey_height": "18 m"}) is True
    assert term(simultaneous, "protected_lobbies_required", {**stair, "top_storey_height": "17.9 m"}) is False


# ---------------------------------------------------- Sections 4 and 5


def test_small_premises_travel_distance():
    shop = {"purpose_group": "shop-and-commercial", "single_occupancy": True, "storeys": 2, "basement_storeys": 1,
            "largest_storey_area": "280 m2", "highly_flammable_materials": False}
    assert term(shop, "max_travel_distance_small_premises", {"exits": 1, "level": "ground"}) == q("27 m")
    assert term(shop, "max_travel_distance_small_premises", {"exits": 1, "level": "first"}) == q("18 m")
    assert term(shop, "max_travel_distance_small_premises", {"exits": 2, "level": "first"}) == q("45 m")
    assert term({**shop, "largest_storey_area": "281 m2"}, "max_travel_distance_small_premises", {"exits": 1, "level": "ground"}) == "not-applicable"


def test_doors_over_60_people():
    shop = {"purpose_group": "shop-and-commercial"}
    assert term(shop, "panic_fastenings_or_no_fastenings_required", {"room_occupant_number": 60}) is False
    assert term(shop, "panic_fastenings_or_no_fastenings_required", {"room_occupant_number": 61}) is True
    assert term(OFFICE, "panic_fastenings_or_no_fastenings_required", {"room_occupant_number": 100}) is False  # 5.9: groups 4 and 5 only
    assert term(OFFICE, "door_must_open_in_direction_of_escape", {"people": 60, "very_high_fire_risk": False}) is False
    assert term(OFFICE, "door_must_open_in_direction_of_escape", {"people": 61, "very_high_fire_risk": False}) is True
    assert norm(OFFICE, "ADB2 5.16", {"clear_headroom": "1.99 m"}) is False
    assert norm(OFFICE, "ADB2 5.16", {"clear_headroom": "2 m"}) is True
