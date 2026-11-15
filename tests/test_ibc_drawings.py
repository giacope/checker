"""IBC 2024 norms a drawing set or model can decide (packs/ibc-2024/ch10-components.yaml).

Expected values come from the 2024 IBC text on ICC Digital Codes: each limit is
tested on both sides, and each exception on its own.
"""

from pathlib import Path

import pytest

from normir import Evaluator, Residual, amendment_status, load, validate
from normir.evidence import load_evidence, run

ROOT = Path(__file__).resolve().parents[1]
IBC = load(ROOT / "packs" / "ibc-2024")
AUSTIN = load(ROOT / "packs" / "austin-2024")
NEW_NORMS = ["1010.1.1 width", "1010.1.1 height", "1011.3", "1011.8", "1014.2", "1012.2", "1012.4", "1012.5.1",
             "1020.5", "1006.2.1", "1006.2.1.1", "1006.3.3"]
NEW_TERMS = ["max_one_exit_space_occupant_load", "max_one_exit_common_path", "single_exit_r2_dwelling_units",
             "single_exit_other_occupancies", "single_exit_permitted", "max_dead_end_length"]


def check(norm, instance, rs=IBC, **building):
    return Evaluator(rs, {"occupancy_group": "B", "sprinkler_system": "none", **building}).norm(norm, instance)


@pytest.mark.parametrize("rs", [IBC, AUSTIN])
def test_new_elements_validate_draft_with_guidance(rs):
    errors, warnings = validate(rs)
    assert errors == []
    assert not [w for w in warnings if any(f"'{n}'" in w for n in NEW_NORMS + NEW_TERMS)]
    for name in NEW_NORMS:
        el = rs.get("norm", name)
        assert el.package == "ibc-2024" and el.data["status"] == "draft" and el.data["guidance"].strip()
        assert el.data["cite"]["url"].startswith("https://codes.iccsafe.org/s/IBC2024P1/chapter-10-means-of-egress/")


# ------------------------------------------------------------------- doors

NOT_EXCEPTED = {"means_of_egress_door": True, "storage_closet_under_10_sqft": False, "type_b_unit_user_passage": False,
                "serves_sauna_toilet_or_dressing": False}


@pytest.mark.parametrize(
    "group, door, ok",
    [
        ("B", {"clear_width": "32 in"}, True),
        ("B", {"clear_width": "31.9 in"}, False),
        # I-2 doors used for bed movement: 41½ in
        ("I-2", {"clear_width": "41.5 in", "bed_movement": True}, True),
        ("I-2", {"clear_width": "41.4 in", "bed_movement": True}, False),
        ("I-2", {"clear_width": "36 in", "bed_movement": False}, True),
        # Exception 1: R-2/R-3 units not Accessible/A/B, door not in the required means of egress
        ("R-2", {"clear_width": "24 in", "in_dwelling_or_sleeping_unit": True, "in_accessible_unit": False,
                 "part_of_required_means_of_egress": False, "is_external": True}, True),
        ("R-2", {"clear_width": "24 in", "in_dwelling_or_sleeping_unit": True, "in_accessible_unit": True,
                 "part_of_required_means_of_egress": False, "is_external": True}, False),
        ("B", {"clear_width": "24 in", "in_dwelling_or_sleeping_unit": True, "in_accessible_unit": False,
               "part_of_required_means_of_egress": False, "is_external": False}, False),
        # Exception 2: I-3 resident sleeping units, 28 in
        ("I-3", {"clear_width": "28 in", "to_resident_sleeping_unit": True, "in_accessible_unit": False}, True),
        ("I-3", {"clear_width": "27.9 in", "to_resident_sleeping_unit": True, "in_accessible_unit": False}, False),
        # Exception 3: storage closets under 10 sq ft are not limited
        ("B", {"clear_width": "18 in", "storage_closet_under_10_sqft": True}, True),
        # Exception 6: I-1, R-2, R-3, R-4 units not Accessible/A/B: interior egress doors not limited
        ("I-1", {"clear_width": "26 in", "in_dwelling_or_sleeping_unit": True, "in_accessible_unit": False,
                 "is_external": False, "part_of_required_means_of_egress": True}, True),
        ("I-1", {"clear_width": "26 in", "in_dwelling_or_sleeping_unit": True, "in_accessible_unit": False,
                 "is_external": True, "part_of_required_means_of_egress": True}, False),
        # Exception 7: Type B units, user passage, 31.75 in
        ("B", {"clear_width": "31.75 in", "type_b_unit_user_passage": True}, True),
        ("B", {"clear_width": "31.7 in", "type_b_unit_user_passage": True}, False),
        # Exception 8: sauna, toilet, dressing, fitting or changing, 20 in
        ("B", {"clear_width": "20 in", "serves_sauna_toilet_or_dressing": True}, True),
        ("B", {"clear_width": "19.9 in", "serves_sauna_toilet_or_dressing": True}, False),
        # §1010.1: only doors in the means of egress
        ("B", {"clear_width": "24 in", "means_of_egress_door": False}, True),
    ],
)
def test_door_clear_width(group, door, ok):
    assert check("1010.1.1 width", {**NOT_EXCEPTED, **door}, occupancy_group=group) is ok


def test_wide_door_passes_without_questions_and_narrow_door_asks_about_exceptions():
    assert check("1010.1.1 width", {"clear_width": "36 in"}) is True
    open_ = check("1010.1.1 width", {"clear_width": "30 in"})
    assert isinstance(open_, Residual)
    text = str(open_.expr)
    assert "Door.storage_closet_under_10_sqft" in text and "Door.means_of_egress_door" in text
    assert "Door.to_resident_sleeping_unit" not in text  # I-3 exception ruled out by the occupancy


@pytest.mark.parametrize(
    "door, ok",
    [
        ({"height": "80 in"}, True),
        ({"height": "79.9 in", "in_dwelling_or_sleeping_unit": False}, False),
        # Exception 4: within a unit, 78 in
        ({"height": "78 in", "in_dwelling_or_sleeping_unit": True, "is_external": False}, True),
        ({"height": "77.9 in", "in_dwelling_or_sleeping_unit": True, "is_external": False}, False),
        # Exception 5: unit exterior doors other than the required exit door, units not Accessible/A/B, 76 in
        ({"height": "76 in", "in_dwelling_or_sleeping_unit": True, "is_external": True, "in_accessible_unit": False,
          "unit_required_exit_door": False}, True),
        ({"height": "75.9 in", "in_dwelling_or_sleeping_unit": True, "is_external": True, "in_accessible_unit": False,
          "unit_required_exit_door": False}, False),
        ({"height": "76 in", "in_dwelling_or_sleeping_unit": True, "is_external": True, "in_accessible_unit": False,
          "unit_required_exit_door": True}, False),
        ({"height": "76 in", "in_dwelling_or_sleeping_unit": True, "is_external": True, "in_accessible_unit": True,
          "unit_required_exit_door": False}, False),
    ],
)
def test_door_height(door, ok):
    assert check("1010.1.1 height", {"means_of_egress_door": True, **door}, occupancy_group="R-2") is ok


# ------------------------------------------------------------------ stairs


@pytest.mark.parametrize(
    "stair, ok",
    [
        ({"headroom": "80 in"}, True),
        ({"headroom": "2032 mm"}, True),
        ({"headroom": "79.9 in", "spiral": False}, False),
        ({"headroom": "78 in", "spiral": True}, True),  # Exception 1
        ({"headroom": "77.9 in", "spiral": True}, False),
    ],
)
def test_stair_headroom(stair, ok):
    assert check("1011.3", stair) is ok


@pytest.mark.parametrize(
    "stair, ok",
    [
        ({"rise": "12 ft"}, True),
        ({"rise": "3657 mm"}, True),
        ({"rise": "3658 mm", "risers": 24, "riser_height": "6 in"}, True),  # printed 3658 mm is 12.001 ft; the flight decides
        # taller stairs pass when the tallest flight (risers x riser height) is within 12 ft
        ({"rise": "13 ft", "risers": 20, "riser_height": "7 in"}, True),  # 140 in
        ({"rise": "13 ft", "risers": 21, "riser_height": "7 in", "spiral": False}, False),  # 147 in
        ({"rise": "13 ft", "risers": 21, "riser_height": "7 in", "spiral": True, "serves_technical_production_area": True}, True),
        ({"rise": "13 ft", "risers": 21, "riser_height": "7 in", "spiral": True, "serves_technical_production_area": False}, False),
    ],
)
def test_stair_vertical_rise(stair, ok):
    assert check("1011.8", stair) is ok


@pytest.mark.parametrize("height, ok", [("34 in", True), ("38 in", True), ("33.9 in", False), ("38.1 in", False), ("900 mm", True)])
def test_handrail_height(height, ok):
    assert check("1014.2", {"handrail_height": height}) is ok


# ------------------------------------------------------------------- ramps


@pytest.mark.parametrize(
    "ramp, ok",
    [
        ({"slope": 1 / 12}, True),
        ({"slope": 0.084, "means_of_egress": True, "assembly_aisle_or_curb_ramp": False}, False),
        ({"slope": 0.125, "means_of_egress": False, "assembly_aisle_or_curb_ramp": False}, True),  # other ramps: 1:8
        ({"slope": 0.126, "means_of_egress": False, "assembly_aisle_or_curb_ramp": False}, False),
        ({"slope": 0.2, "means_of_egress": True, "assembly_aisle_or_curb_ramp": True}, True),  # §1012.1 Exceptions 1, 2
    ],
)
def test_ramp_slope(ramp, ok):
    assert check("1012.2", ramp) is ok


@pytest.mark.parametrize(
    "ramp, ok",
    [
        ({"rise": "30 in"}, True),
        ({"rise": "30.1 in", "means_of_egress": True, "assembly_aisle_or_curb_ramp": False, "parking_vehicle_ramp_exempt": False}, False),
        ({"rise": "40 in", "means_of_egress": True, "assembly_aisle_or_curb_ramp": False, "parking_vehicle_ramp_exempt": True}, True),
    ],
)
def test_ramp_rise(ramp, ok):
    assert check("1012.4", ramp) is ok


RAMP_ROWS_OFF = {"within_dwelling_unit": False, "mep_access_only": False, "serves_stretcher_traffic": False,
                 "bed_movement_required": False, "means_of_egress": True, "assembly_aisle_or_curb_ramp": False,
                 "parking_vehicle_ramp_exempt": False}
NO_CARE = {"emergency_voice_alarm": False, "care_less_than_24h": False}


@pytest.mark.parametrize(
    "group, ramp, ok",
    [
        ("B", {"occupant_load": 40, "clear_width": "36 in"}, True),
        ("B", {"occupant_load": 40, "clear_width": "35.9 in"}, False),  # 36 in clear minimum
        ("B", {"occupant_load": 60, "clear_width": "44 in"}, True),  # Table 1020.3: 44 in
        ("B", {"occupant_load": 60, "clear_width": "43.9 in"}, False),
        ("B", {"occupant_load": 60, "clear_width": "36 in", "within_dwelling_unit": True}, True),
        ("B", {"occupant_load": 300, "clear_width": "60 in"}, True),  # capacity 0.2 in x 300
        ("B", {"occupant_load": 300, "clear_width": "59.9 in"}, False),
        ("E", {"occupant_load": 100, "clear_width": "72 in"}, True),
        ("E", {"occupant_load": 100, "clear_width": "71.9 in"}, False),
        ("I-2", {"occupant_load": 60, "clear_width": "95.9 in", "bed_movement_required": True}, False),
        ("I-2", {"occupant_load": 60, "clear_width": "96 in", "bed_movement_required": True}, True),
        ("B", {"occupant_load": 60, "clear_width": "30 in", "means_of_egress": False}, True),
    ],
)
def test_ramp_width(group, ramp, ok):
    assert check("1012.5.1", {**RAMP_ROWS_OFF, **ramp}, occupancy_group=group, **NO_CARE) is ok


# --------------------------------------------------------------- dead ends

CORRIDOR = {"clear_width": "5 ft", "more_than_one_exit_required": True, "serves_patient_rooms": True}


@pytest.mark.parametrize(
    "building, length, ok",
    [
        ({"occupancy_group": "B", "sprinkler_system": "none"}, "20 ft", True),
        ({"occupancy_group": "B", "sprinkler_system": "none"}, "20.1 ft", False),
        # Exception 2: listed groups, sprinklered per §903.3.1.1 only
        ({"occupancy_group": "B", "sprinkler_system": "nfpa13"}, "50 ft", True),
        ({"occupancy_group": "B", "sprinkler_system": "nfpa13"}, "50.1 ft", False),
        ({"occupancy_group": "R-2", "sprinkler_system": "nfpa13r"}, "21 ft", False),
        ({"occupancy_group": "A-2", "sprinkler_system": "nfpa13"}, "21 ft", False),  # A is not listed
        # Exception 1: I-3 Condition 2, 3 or 4
        ({"occupancy_group": "I-3", "i3_condition": "condition-3"}, "50 ft", True),
        ({"occupancy_group": "I-3", "i3_condition": "condition-1"}, "21 ft", False),
        # Exception 4: I-2 Condition 2, not serving patient rooms
        ({"occupancy_group": "I-2", "i2_condition": "condition-2"}, "21 ft", False),
    ],
)
def test_dead_end_corridor(building, length, ok):
    assert Evaluator(IBC, {"sprinkler_system": "none", **building}).norm("1020.5", {**CORRIDOR, "dead_end_length": length}) is ok


@pytest.mark.parametrize("length, ok", [("30 ft", True), ("30.1 ft", False)])
def test_dead_end_i2_condition_2_not_serving_patient_rooms(length, ok):
    ev = Evaluator(IBC, {"occupancy_group": "I-2", "sprinkler_system": "nfpa13", "i2_condition": "condition-2"})
    assert ev.norm("1020.5", {**CORRIDOR, "serves_patient_rooms": False, "dead_end_length": length}) is ok


@pytest.mark.parametrize("length, ok", [("24.9 ft", True), ("25 ft", False)])
def test_dead_end_shorter_than_two_and_a_half_widths(length, ok):  # Exception 3, 2.5 x 10 ft
    assert check("1020.5", {**CORRIDOR, "clear_width": "10 ft", "dead_end_length": length}) is ok


def test_dead_end_limit_applies_only_where_two_exits_are_required():
    assert check("1020.5", {**CORRIDOR, "dead_end_length": "60 ft", "more_than_one_exit_required": False}) is True


# ---------------------------------------------- number of exits from a space

SPACE = {"exits": 1, "unoccupied_mechanical": False}


@pytest.mark.parametrize(
    "building, space, ok",
    [
        ({}, {"exits": 2, "design_occupant_load": 400, "common_path_of_travel": "300 ft"}, True),
        ({}, {"exits": 0, "design_occupant_load": 5, "common_path_of_travel": "10 ft"}, False),
        # B without sprinklers: 49 occupants; 100 ft for OL <= 30, 75 ft above
        ({}, {"design_occupant_load": 30, "common_path_of_travel": "100 ft"}, True),
        ({}, {"design_occupant_load": 30, "common_path_of_travel": "100.1 ft"}, False),
        ({}, {"design_occupant_load": 31, "common_path_of_travel": "75 ft"}, True),
        ({}, {"design_occupant_load": 31, "common_path_of_travel": "75.1 ft"}, False),
        ({}, {"design_occupant_load": 50, "common_path_of_travel": "10 ft"}, False),
        ({"sprinkler_system": "nfpa13r"}, {"design_occupant_load": 49, "common_path_of_travel": "100 ft"}, True),
        ({"sprinkler_system": "nfpa13r"}, {"design_occupant_load": 49, "common_path_of_travel": "100.1 ft"}, False),
        # R-2: 20 occupants; NP without sprinklers, 125 ft with
        ({"occupancy_group": "R-2"}, {"design_occupant_load": 5, "common_path_of_travel": "10 ft"}, False),
        ({"occupancy_group": "R-2", "sprinkler_system": "nfpa13r"}, {"design_occupant_load": 20, "common_path_of_travel": "125 ft"}, True),
        ({"occupancy_group": "R-2", "sprinkler_system": "nfpa13r"}, {"design_occupant_load": 21, "common_path_of_travel": "10 ft"}, False),
        # footnote e: R-3 common path applies only in a mixed occupancy building
        ({"occupancy_group": "R-3", "mixed_occupancy": False}, {"design_occupant_load": 20, "common_path_of_travel": "200 ft"}, True),
        ({"occupancy_group": "R-3", "mixed_occupancy": True}, {"design_occupant_load": 20, "common_path_of_travel": "200 ft"}, False),
        # H-1, H-2, H-3: 3 occupants, 25 ft with sprinklers (footnote b)
        ({"occupancy_group": "H-2", "sprinkler_system": "nfpa13"}, {"design_occupant_load": 3, "common_path_of_travel": "25 ft"}, True),
        ({"occupancy_group": "H-2", "sprinkler_system": "nfpa13"}, {"design_occupant_load": 4, "common_path_of_travel": "25 ft"}, False),
        # S: 29 occupants; footnote f, S-2 open parking garage: 100 ft
        ({"occupancy_group": "S-2", "open_parking_garage": True}, {"design_occupant_load": 29, "common_path_of_travel": "100 ft"}, True),
        ({"occupancy_group": "S-2", "open_parking_garage": False}, {"design_occupant_load": 29, "common_path_of_travel": "100 ft"}, True),
        ({"occupancy_group": "S-1"}, {"design_occupant_load": 29, "common_path_of_travel": "100 ft"}, True),
        ({"occupancy_group": "S-1"}, {"design_occupant_load": 29, "common_path_of_travel": "100.1 ft"}, False),
        ({"occupancy_group": "S-1"}, {"design_occupant_load": 30, "common_path_of_travel": "10 ft"}, False),
        # U: 75 ft with sprinklers, 100 ft without for OL <= 30, as printed
        ({"occupancy_group": "U", "sprinkler_system": "nfpa13"}, {"design_occupant_load": 10, "common_path_of_travel": "80 ft"}, False),
        ({"occupancy_group": "U"}, {"design_occupant_load": 10, "common_path_of_travel": "80 ft"}, True),
        # Exception 3: unoccupied mechanical rooms are not held to the common path
        ({}, {"design_occupant_load": 2, "common_path_of_travel": "150 ft", "unoccupied_mechanical": True}, True),
    ],
)
def test_space_with_one_exit(building, space, ok):
    assert check("1006.2.1", {**SPACE, **space}, **building) is ok


def test_space_occupant_load_read_from_the_drawings():
    assert IBC.get("predicate", "Space.design_occupant_load").data["vocab"] == "Space.stated_occupant_load"


@pytest.mark.parametrize(
    "load_, exits, ok",
    [(500, 2, True), (501, 2, False), (501, 3, True), (1000, 3, True), (1001, 3, False), (1001, 4, True)],
)
def test_space_three_or_four_exits(load_, exits, ok):
    assert check("1006.2.1.1", {"design_occupant_load": load_, "exits": exits}) is ok


# ---------------------------------------------- number of exits from a storey

NO_OTHER_ITEMS = {"rooms_exit_directly_to_exterior": False, "dwelling_units_meet_1006_3_4_item_5": False}


@pytest.mark.parametrize(
    "load_, exits, ok",
    [(500, 2, True), (501, 2, False), (501, 3, True), (1000, 3, True), (1001, 3, False), (1001, 4, True)],
)
def test_storey_exits_table_1006_3_3(load_, exits, ok):
    storey = {"occupant_load": load_, "exits": exits, "position": "third", **NO_OTHER_ITEMS}
    assert check("1006.3.3", storey, mechanical_parking_garage=False) is ok


def test_storey_with_four_exits_needs_no_occupant_load():
    assert check("1006.3.3", {"exits": 4}) is True


@pytest.mark.parametrize(
    "building, storey, ok",
    [
        # Table 1006.3.4(2), first story, B: 49 occupants, 75 ft (100 ft with §903.3.1.1, footnote b)
        ({}, {"position": "first", "occupant_load": 49, "max_travel_distance": "75 ft"}, True),
        ({}, {"position": "first", "occupant_load": 50, "max_travel_distance": "75 ft"}, False),
        ({}, {"position": "first-below", "occupant_load": 49, "max_travel_distance": "75.1 ft"}, False),
        ({"sprinkler_system": "nfpa13"}, {"position": "first", "occupant_load": 49, "max_travel_distance": "100 ft"}, True),
        ({"sprinkler_system": "nfpa13r"}, {"position": "first", "occupant_load": 49, "max_travel_distance": "100 ft"}, False),
        # second story, B: 29 occupants, 75 ft
        ({}, {"position": "second", "occupant_load": 29, "max_travel_distance": "75 ft"}, True),
        ({}, {"position": "second", "occupant_load": 30, "max_travel_distance": "75 ft"}, False),
        # pack interpretation: footnote b is marked only on the first-story row
        ({"sprinkler_system": "nfpa13"}, {"position": "second", "occupant_load": 29, "max_travel_distance": "100 ft"}, False),
        ({}, {"position": "third", "occupant_load": 5, "max_travel_distance": "10 ft"}, False),
        ({"occupancy_group": "A-2"}, {"position": "second", "occupant_load": 5, "max_travel_distance": "10 ft"}, False),
        # H-2, H-3: 3 occupants, 25 ft
        ({"occupancy_group": "H-3"}, {"position": "first", "occupant_load": 3, "max_travel_distance": "25 ft"}, True),
        ({"occupancy_group": "H-3"}, {"position": "first", "occupant_load": 3, "max_travel_distance": "25.1 ft"}, False),
        # S-2 open parking garage, footnote d: 100 ft
        ({"occupancy_group": "S-2", "open_parking_garage": True}, {"position": "second", "occupant_load": 29, "max_travel_distance": "100 ft"}, True),
        # R-2 of sleeping units (footnote c): 10 occupants, 75 ft, with footnote a
        ({"occupancy_group": "R-2", "r2_sleeping_units": True, "sprinkler_system": "nfpa13r", "emergency_escape_openings": True},
         {"position": "first", "occupant_load": 10, "max_travel_distance": "75 ft"}, True),
        ({"occupancy_group": "R-2", "r2_sleeping_units": True, "sprinkler_system": "none", "emergency_escape_openings": True},
         {"position": "first", "occupant_load": 10, "max_travel_distance": "75 ft"}, False),
        # item 4: R-3 and R-4
        ({"occupancy_group": "R-4"}, {"position": "third", "occupant_load": 40, "max_travel_distance": "200 ft"}, True),
    ],
)
def test_single_exit_storey(building, storey, ok):
    assert check("1006.3.3", {"exits": 1, **NO_OTHER_ITEMS, **storey}, mechanical_parking_garage=False, **building) is ok


@pytest.mark.parametrize(
    "item",
    [{"rooms_exit_directly_to_exterior": True}, {"dwelling_units_meet_1006_3_4_item_5": True}, {"mechanical_parking_garage": True}],
)
def test_single_exit_storey_other_items(item):
    storey = {"exits": 1, "position": "third", "occupant_load": 80, "max_travel_distance": "200 ft", **NO_OTHER_ITEMS}
    building = {"mechanical_parking_garage": False}
    target = building if "mechanical_parking_garage" in item else storey
    target.update(item)
    assert check("1006.3.3", storey, **building) is True


R2 = {"occupancy_group": "R-2", "r2_sleeping_units": False, "sprinkler_system": "nfpa13r", "emergency_escape_openings": True,
      "mechanical_parking_garage": False}


@pytest.mark.parametrize(
    "building, storey, ibc, austin",
    [
        ({"storeys_above_ground": 3}, {"position": "third", "dwelling_units": 4, "max_travel_distance": "125 ft"}, True, True),
        ({"storeys_above_ground": 3}, {"position": "third", "dwelling_units": 5, "max_travel_distance": "125 ft"}, False, False),
        ({"storeys_above_ground": 3}, {"position": "third", "dwelling_units": 4, "max_travel_distance": "125.1 ft"}, False, False),
        ({"storeys_above_ground": 3, "emergency_escape_openings": False},
         {"position": "first", "dwelling_units": 2, "max_travel_distance": "50 ft"}, False, False),
        # Austin: up to the fifth story; footnote d sends 5-story buildings to §1006.3.4.2
        ({"storeys_above_ground": 4, "occupiable_roof_above_third_story": False},
         {"position": "fourth", "dwelling_units": 4, "max_travel_distance": "125 ft"}, False, True),
        ({"storeys_above_ground": 5, "meets_1006_3_4_2": False},
         {"position": "fifth", "dwelling_units": 4, "max_travel_distance": "125 ft"}, False, False),
        ({"storeys_above_ground": 5, "meets_1006_3_4_2": True},
         {"position": "fifth", "dwelling_units": 4, "max_travel_distance": "125 ft"}, False, True),
        ({"storeys_above_ground": 4, "occupiable_roof_above_third_story": True, "meets_1006_3_4_2": False},
         {"position": "second", "dwelling_units": 4, "max_travel_distance": "125 ft"}, True, False),
        ({"storeys_above_ground": 6}, {"position": "sixth-or-higher", "dwelling_units": 1, "max_travel_distance": "20 ft"}, False, False),
    ],
)
def test_single_exit_r2_dwelling_units_ibc_and_austin(building, storey, ibc, austin):
    storey = {"exits": 1, **NO_OTHER_ITEMS, **storey}
    assert check("1006.3.3", storey, IBC, **{**R2, **building}) is ibc
    assert check("1006.3.3", storey, AUSTIN, **{**R2, **building}) is austin


# ---------------------------------------------------------- Austin overlay


@pytest.mark.parametrize("section", ["1010.1.1", "1011.3", "1011.8", "1014.2", "1012.2", "1012.4", "1012.5.1", "1020.5", "1006.2.1", "1006.3.3"])
def test_austin_leaves_the_new_sections_unamended(section):
    assert amendment_status(AUSTIN, None, section).startswith("Not amended")


def test_austin_replaces_table_1006_3_4_1():
    el = AUSTIN.get("term", "single_exit_r2_dwelling_units")
    assert el.package == "austin-2024"
    assert amendment_status(AUSTIN, el, "1006.3.4", "1006.3.4(1)").startswith("Replaced by City of Austin Ordinance No. 20250410-045")
    assert IBC.get("term", "single_exit_r2_dwelling_units").package == "ibc-2024"


# ---------------------------------------------------------- evidence level


def obs(**facts):
    return {k: [{"value": v, "at": "A-601#page=1"}] for k, v in facts.items()}


def test_drawing_evidence_through_evidence_run():
    # Every element carries a sheet locator, as the drawing adapters write them. Without one the
    # engine falls back to the id, and ids such as door:101 and door:102 then read as code
    # locators (path:line) a line apart and are merged into one element.
    doc = {
        "subject": {"kind": "building", "id": "test"},
        "sources": [{"id": "drawings", "kind": "drawings"}],
        "facts": {},
        "elements": [
            {"type": "Door", "id": "door:101", "at": "A-601.pdf#page=1&bbox=1,0,2,1", "facts": obs(clear_width="813 mm", height="2032 mm", is_external=False)},
            {"type": "Door", "id": "door:102", "at": "A-601.pdf#page=1&bbox=2,0,3,1", "facts": obs(clear_width="812 mm", height="2031 mm", is_external=False)},
            {"type": "Stair", "id": "stair:1", "at": "A-601.pdf#page=1&bbox=3,0,4,1", "facts": obs(headroom="2032 mm", handrail_height="864 mm", rise="3657 mm")},
            {"type": "Stair", "id": "stair:2", "at": "A-601.pdf#page=1&bbox=4,0,5,1", "facts": obs(headroom="2031 mm", handrail_height="966 mm", rise="3700 mm",
                                                              risers=24, riser_height="155 mm")},
            {"type": "Ramp", "id": "ramp:1", "at": "A-601.pdf#page=1&bbox=5,0,6,1", "facts": obs(slope=0.083, rise="762 mm")},
            {"type": "Ramp", "id": "ramp:2", "at": "A-601.pdf#page=1&bbox=6,0,7,1", "facts": obs(slope=0.1, rise="763 mm")},
            {"type": "Corridor", "id": "corridor:1", "at": "A-601.pdf#page=1&bbox=7,0,8,1", "facts": obs(dead_end_length="15240 mm", clear_width="1830 mm")},
            {"type": "Corridor", "id": "corridor:2", "at": "A-601.pdf#page=1&bbox=8,0,9,1", "facts": obs(dead_end_length="15250 mm", clear_width="1830 mm")},
            {"type": "Space", "id": "space:110", "at": "A-601.pdf#page=1&bbox=9,0,10,1", "facts": obs(exits=1, stated_occupant_load=49, common_path_of_travel="30480 mm")},
            {"type": "Space", "id": "space:111", "at": "A-601.pdf#page=1&bbox=10,0,11,1", "facts": obs(exits=1, stated_occupant_load=50, common_path_of_travel="1000 mm")},
            {"type": "Storey", "id": "storey:1", "at": "A-601.pdf#page=1&bbox=11,0,12,1", "facts": obs(exits=2)},
        ],
    }
    profile = {
        "occupancy_group": "B", "sprinkler_system": "nfpa13",
        "Door": {**NOT_EXCEPTED, "in_dwelling_or_sleeping_unit": False},
        "Stair": {"spiral": False, "serves_technical_production_area": False},
        "Ramp": {"means_of_egress": True, "assembly_aisle_or_curb_ramp": False, "parking_vehicle_ramp_exempt": False},
        "Corridor": {"more_than_one_exit_required": True},
        "Space": {"unoccupied_mechanical": False},
        "Storey": {"occupant_load": 120},
        "norms": ["1010.1.1 width", "1010.1.1 height", "1011.3", "1011.8", "1014.2", "1012.2", "1012.4", "1020.5", "1006.2.1", "1006.3.3"],
    }
    for rs in (IBC, AUSTIN):
        verdicts = {(r["norm"], r["element"]): r["verdict"] for r in run(rs, load_evidence(doc), profile)}
        assert verdicts == {
            ("1010.1.1 width", "door:101"): "pass", ("1010.1.1 width", "door:102"): "fail",  # 32 in = 812.8 mm
            ("1010.1.1 height", "door:101"): "pass", ("1010.1.1 height", "door:102"): "fail",  # 80 in = 2032 mm
            ("1011.3", "stair:1"): "pass", ("1011.3", "stair:2"): "fail",
            ("1014.2", "stair:1"): "pass", ("1014.2", "stair:2"): "fail",  # 34 in = 863.6 mm, 38 in = 965.2 mm
            ("1011.8", "stair:1"): "pass", ("1011.8", "stair:2"): "fail",  # 12 ft = 3657.6 mm; 24 x 155 mm = 3720 mm
            ("1012.2", "ramp:1"): "pass", ("1012.2", "ramp:2"): "fail",
            ("1012.4", "ramp:1"): "pass", ("1012.4", "ramp:2"): "fail",  # 30 in = 762 mm
            ("1020.5", "corridor:1"): "pass", ("1020.5", "corridor:2"): "fail",  # 50 ft = 15240 mm (B, §903.3.1.1)
            ("1006.2.1", "space:110"): "pass", ("1006.2.1", "space:111"): "fail",  # 49 occupants, 100 ft = 30480 mm
            ("1006.3.3", "storey:1"): "pass",
        }
