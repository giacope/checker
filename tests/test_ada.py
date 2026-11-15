"""2010 ADA Standards pack. Expected values are read from the provision text."""

from pathlib import Path

import pytest

from normir import Evaluator, Quantity, Residual, ask, load, validate
from normir.evaluate import facts_in

ADA = Path(__file__).resolve().parents[1] / "packs" / "ada-2010"
BUILDING = {"detention_correctional_facility": False}


def check(norm, element, building=BUILDING):
    return Evaluator(load(ADA), building).norm(norm, element)


def test_pack_validates_and_cites_access_board_anchors():
    rs = load(ADA)
    errors, warnings = validate(rs)
    assert errors == [] and warnings == []
    for (kind, _), el in rs.elements.items():
        if kind != "predicate":
            assert el.data["cite"]["url"].startswith("https://www.access-board.gov/ada/#ada-")
            assert el.data.get("status") == "draft"


# ---------------------------------------------------------------------- doors

DOOR = {"on_accessible_route": True, "opening_depth": "6 in", "projection_below_34in": "0 in", "projection_34_to_80in": "0 in"}


@pytest.mark.parametrize(
    "door, expected",
    [
        ({"clear_width": "31.5 in"}, False),
        ({"clear_width": "32 in"}, True),
        ({"clear_width": "34 in", "opening_depth": "30 in"}, False),  # over 24 in deep needs 36 in
        ({"clear_width": "36 in", "opening_depth": "30 in"}, True),
        ({"clear_width": "34 in", "projection_34_to_80in": "4.5 in"}, False),
        ({"clear_width": "34 in", "projection_below_34in": "0.5 in"}, False),
        ({"clear_width": "30 in", "on_accessible_route": False}, True),  # 404.1: out of scope
    ],
)
def test_door_clear_width(door, expected):
    assert check("404.2.3", {**DOOR, **door}) is expected


def test_door_width_unknown_is_a_residual_naming_the_fact():
    v = check("404.2.3", DOOR)
    assert isinstance(v, Residual)
    assert facts_in(v.expr) == ["Door.clear_width"]
    a = ask(load(ADA), "required_door_clear_width", instance={"opening_depth": "30 in"})
    assert a["value"] == Quantity.parse("36 in")


@pytest.mark.parametrize(
    "threshold, expected",
    [
        ({"has_threshold": True, "threshold_height": "0.5 in"}, True),
        ({"has_threshold": True, "threshold_height": "0.625 in", "threshold_existing_or_altered": False}, False),
        ({"has_threshold": True, "threshold_height": "0.75 in", "threshold_existing_or_altered": True, "threshold_beveled_1_2": True}, True),
        ({"has_threshold": True, "threshold_height": "0.875 in", "threshold_existing_or_altered": True, "threshold_beveled_1_2": True}, False),
        ({"has_threshold": False}, True),
    ],
)
def test_thresholds(threshold, expected):
    assert check("404.2.5", {"on_accessible_route": True, **threshold}) is expected


# ---------------------------------------------------------- walking surfaces


@pytest.mark.parametrize(
    "route, expected",
    [
        ({"clear_width": "36 in"}, True),
        ({"clear_width": "35.5 in", "longest_reduced_width_length": "60 in", "reduced_width_segment_count": 1}, False),
        ({"clear_width": "32 in", "longest_reduced_width_length": "24 in", "reduced_width_segment_count": 1}, True),
        ({"clear_width": "31.5 in", "longest_reduced_width_length": "12 in", "reduced_width_segment_count": 1}, False),
        ({"clear_width": "32 in", "longest_reduced_width_length": "24.5 in", "reduced_width_segment_count": 1}, False),
        ({"clear_width": "32 in", "longest_reduced_width_length": "24 in", "reduced_width_segment_count": 2,
          "shortest_separation_between_reduced_segments": "48 in"}, True),
        ({"clear_width": "32 in", "longest_reduced_width_length": "24 in", "reduced_width_segment_count": 2,
          "shortest_separation_between_reduced_segments": "40 in"}, False),
    ],
)
def test_walking_surface_clear_width(route, expected):
    assert check("403.5.1", {"on_accessible_route": True, **route}) is expected


# ---------------------------------------------------------------------- ramps

RAMP = {"on_accessible_route": True, "assembly_aisle_ramp_adjacent_to_seating": False, "in_existing_facility": False, "space_limited": False}
EXISTING = {**RAMP, "in_existing_facility": True, "space_limited": True}


@pytest.mark.parametrize(
    "ramp, expected",
    [
        ({**RAMP, "rise": "30 in", "horizontal_run": "30 ft"}, True),  # exactly 1:12
        ({**RAMP, "rise": "30 in", "horizontal_run": "330 in"}, False),  # 1:11
        ({**EXISTING, "rise": "6 in", "horizontal_run": "66 in"}, True),  # 1:11, rise within 6 in
        ({**EXISTING, "rise": "6.5 in", "horizontal_run": "71.5 in"}, False),  # 1:11, rise over 6 in
        ({**EXISTING, "rise": "3 in", "horizontal_run": "27 in"}, True),  # 1:9, rise within 3 in
        ({**EXISTING, "rise": "4 in", "horizontal_run": "36 in"}, False),  # 1:9, rise over 3 in
        ({**EXISTING, "rise": "2 in", "horizontal_run": "14 in"}, False),  # 1:7 is prohibited
        ({**RAMP, "assembly_aisle_ramp_adjacent_to_seating": True, "serves_required_accessible_elements": False,
          "rise": "30 in", "horizontal_run": "330 in"}, True),  # 405.1 Exception
    ],
)
def test_ramp_running_slope(ramp, expected):
    assert check("405.2", ramp) is expected


@pytest.mark.parametrize(
    "norm, ramp, expected",
    [
        ("405.3", {"cross_slope": 0.02}, True),
        ("405.3", {"cross_slope": 0.025}, False),  # steeper than 1:48 (0.0208)
        ("405.5", {"clear_width": "36 in", "has_handrails": False}, True),
        ("405.5", {"clear_width": "40 in", "has_handrails": True, "clear_width_between_handrails": "35 in"}, False),
        ("405.6", {"rise": "30 in"}, True),
        ("405.6", {"rise": "30.5 in"}, False),
    ],
)
def test_ramp_cross_slope_width_and_rise(norm, ramp, expected):
    assert check(norm, {**RAMP, **ramp}) is expected


# --------------------------------------------------------------------- stairs

STAIR = {"part_of_means_of_egress": True, "altered": False, "assembly_aisle_stair": False, "connects_play_components": False,
         "min_riser_height": "7 in", "max_riser_height": "7 in", "min_tread_depth": "11 in", "max_tread_depth": "11 in"}


@pytest.mark.parametrize(
    "stair, expected",
    [
        ({}, True),
        ({"min_riser_height": "7.25 in", "max_riser_height": "7.25 in"}, False),
        ({"min_riser_height": "3.75 in", "max_riser_height": "3.75 in"}, False),
        ({"min_tread_depth": "10.75 in", "max_tread_depth": "10.75 in"}, False),
        ({"min_riser_height": "6.5 in"}, False),  # risers not uniform
        ({"min_riser_height": "7.25 in", "max_riser_height": "7.25 in", "part_of_means_of_egress": False}, True),  # 210.1
        ({"min_riser_height": "7.25 in", "max_riser_height": "7.25 in", "altered": True,
          "levels_connected_by_accessible_route": True}, True),  # 210.1 Exception 2
    ],
)
def test_stair_treads_and_risers(stair, expected):
    assert check("504.2", {**STAIR, **stair}) is expected


def test_open_risers_and_detention_exception():
    assert check("504.3", {**STAIR, "has_open_risers": True}) is False
    assert check("504.3", {**STAIR, "has_open_risers": False}) is True
    jail = {"detention_correctional_facility": True}
    assert check("504.3", {**STAIR, "has_open_risers": True, "in_public_use_area": False}, jail) is True
    assert check("504.3", {**STAIR, "has_open_risers": True, "in_public_use_area": True}, jail) is False


@pytest.mark.parametrize(
    "low, high, expected",
    [("34 in", "38 in", True), ("33.5 in", "36 in", False), ("35 in", "38.5 in", False)],
)
def test_handrail_height(low, high, expected):
    rail = {"within_505_1": True, "min_height": low, "max_height": high, "height_consistent": True}
    assert check("505.4", rail) is expected


# -------------------------------------------------------------- water closets

WC = {"required_accessible": True, "for_childrens_use": False, "wall_to_rear_and_side": True, "in_ambulatory_compartment": False,
      "private_office_single_user": False, "in_residential_dwelling_unit": False, "seat_sprung_to_lift": False}


@pytest.mark.parametrize(
    "wc, expected",
    [
        ({"centerline_to_side_wall": "18 in"}, True),
        ({"centerline_to_side_wall": "18.5 in"}, False),
        ({"centerline_to_side_wall": "15.5 in"}, False),
        ({"centerline_to_side_wall": "18.5 in", "in_ambulatory_compartment": True}, True),
        ({"centerline_to_side_wall": "16.5 in", "in_ambulatory_compartment": True}, False),
    ],
)
def test_water_closet_location(wc, expected):
    assert check("604.2", {**WC, **wc}) is expected


@pytest.mark.parametrize(
    "wc, expected",
    [
        ({"seat_height": "17 in"}, True),
        ({"seat_height": "16.5 in"}, False),
        ({"seat_height": "19.5 in"}, False),
        ({"seat_height": "17 in", "seat_sprung_to_lift": True}, False),
        ({"seat_height": "16 in", "in_residential_dwelling_unit": True}, True),  # Exception 2
        ({"seat_height": "16 in", "private_office_single_user": True}, True),  # Exception 1
    ],
)
def test_water_closet_seat_height(wc, expected):
    assert check("604.4", {**WC, **wc}) is expected


# -------------------------------------------------------------- turning space

T = {"shape": "t-shaped", "square_side": "60 in", "arm_width": "36 in", "base_width": "36 in", "arm_clear_length": "12 in", "base_clear_length": "24 in"}


@pytest.mark.parametrize(
    "space, expected",
    [
        ({"shape": "circular", "diameter": "60 in"}, True),
        ({"shape": "circular", "diameter": "59.5 in"}, False),
        (T, True),
        ({**T, "base_width": "35 in"}, False),
        ({**T, "arm_clear_length": "11.5 in"}, False),
    ],
)
def test_turning_space(space, expected):
    assert check("304.3", space) is expected
