"""The IFC adapter on small models built here with ifcopenshell.api: units, standard property sets, ids, travel distance."""

import math

import numpy as np
import pytest
from ifcopenshell import api
from normir.quantity import Quantity

from adapters.ifc import analyse, extract

FOOT = 0.3048


def metres(v: str) -> float:
    q = Quantity.parse(v)
    return q.base * 0.0254 ** q.dim


class Model:
    """A one-building IFC4 file. Geometry arguments are in metres (the api converts); attributes in file units."""

    def __init__(self, unit: str = "mm"):
        f = self.f = api.run("project.create_file", version="IFC4")
        self.project = api.run("root.create_entity", f, ifc_class="IfcProject", name="Test")
        if unit == "ft":
            units = [api.run("unit.add_conversion_based_unit", f, name="foot"), api.run("unit.add_conversion_based_unit", f, name="square foot")]
        else:
            units = [api.run("unit.add_si_unit", f, unit_type="LENGTHUNIT", prefix={"mm": "MILLI", "m": None}[unit]),
                     api.run("unit.add_si_unit", f, unit_type="AREAUNIT")]
        api.run("unit.assign_unit", f, units=units)
        ctx = api.run("context.add_context", f, context_type="Model")
        self.body = api.run("context.add_context", f, context_type="Model", context_identifier="Body", target_view="MODEL_VIEW", parent=ctx)
        self.site = self.make("IfcSite", "Site")
        self.building = self.make("IfcBuilding", "Building")
        api.run("aggregate.assign_object", f, relating_object=self.project, products=[self.site])
        api.run("aggregate.assign_object", f, relating_object=self.site, products=[self.building])

    def make(self, cls, name=None, **attrs):
        e = api.run("root.create_entity", self.f, ifc_class=cls, name=name)
        for k, v in attrs.items():
            setattr(e, k, v)
        return e

    def place(self, e, x=0.0, y=0.0, z=0.0, x_axis=(1, 0, 0)):
        m = np.eye(4)
        xa = np.asarray(x_axis, float)
        m[:3, 0], m[:3, 1], m[:3, 3] = xa, np.cross([0, 0, 1], xa), (x, y, z)
        api.run("geometry.edit_object_placement", self.f, product=e, matrix=m)

    def box(self, e, x, y, z, dx, dy, dz):
        """An axis-aligned box from (x, y, z) of size dx by dy by dz, in metres."""
        self.place(e, x, y, z)
        rep = api.run("geometry.add_wall_representation", self.f, context=self.body, length=dx, height=dz, thickness=dy)
        api.run("geometry.assign_representation", self.f, product=e, representation=rep)

    def storey(self, name, elevation):
        st = self.make("IfcBuildingStorey", name, Elevation=elevation)
        api.run("aggregate.assign_object", self.f, relating_object=self.building, products=[st])
        return st

    def space(self, storey, number, name, x, y, dx, dy, z=0.0, **qto):
        s = self.make("IfcSpace", number, LongName=name)
        api.run("aggregate.assign_object", self.f, relating_object=storey, products=[s])
        self.box(s, x, y, z, dx, dy, 2.5)
        if qto:
            q = api.run("pset.add_qto", self.f, product=s, name="Qto_SpaceBaseQuantities")
            api.run("pset.edit_qto", self.f, qto=q, properties=qto)
        return s

    def door(self, storey, wall, tag, opening_box, width, height, axis, origin, op="SINGLE_SWING_LEFT", **pset):
        """A door filling an opening (opening_box = x, y, dx, dy in metres) in `wall`; width and height in file units."""
        d = self.make("IfcDoor", None, Tag=tag, OverallWidth=width, OverallHeight=height, OperationType=op)
        api.run("spatial.assign_container", self.f, relating_structure=storey, products=[d])
        self.place(d, origin[0], origin[1], 0.0, x_axis=axis)
        o = self.make("IfcOpeningElement", "opening")
        x, y, dx, dy = opening_box
        self.box(o, x, y, 0.0, dx, dy, 2.1)
        api.run("feature.add_feature", self.f, feature=o, element=wall)
        api.run("feature.add_filling", self.f, opening=o, element=d)
        if pset:
            p = api.run("pset.add_pset", self.f, product=d, name="Pset_DoorCommon")
            api.run("pset.edit_pset", self.f, pset=p, properties=pset)
        return d

    def wall(self, storey):
        w = self.make("IfcWall", "wall")
        api.run("spatial.assign_container", self.f, relating_structure=storey, products=[w])
        return w

    def save(self, tmp_path, name="model.ifc"):
        p = tmp_path / name
        self.f.write(str(p))
        return p


def element(doc, type_, id_):
    return next(e for e in doc["elements"] if e["type"] == type_ and e["id"] == id_)


def values(e, attr):
    return [o["value"] for o in e["facts"][attr]]


def test_millimetre_model_reads_standard_property_sets(tmp_path):
    m = Model("mm")
    ground = m.storey("Ground", 0.0)
    m.storey("Upper", 2800.0)
    m.space(ground, "101", "OFFICE", 0, 0, 5, 4, NetFloorArea=20.0)
    wall = m.wall(ground)
    m.door(ground, wall, "D101", (5.0, 1.0, 0.2, 1.0), 915.0, 2100.0, (0, 1, 0), (5.1, 1.0),
           IsExternal=True, FireRating="EI 30")
    stair = m.make("IfcStair", "Stair 1")
    api.run("spatial.assign_container", m.f, relating_structure=ground, products=[stair])
    p = api.run("pset.add_pset", m.f, product=stair, name="Pset_StairCommon")
    api.run("pset.edit_pset", m.f, pset=p, properties={"RiserHeight": 175.0, "TreadLength": 280.0, "NumberOfRiser": 16, "IsExternal": False})
    flights = [m.make("IfcStairFlight", f"flight {i}", NumberOfRisers=8, NumberOfTreads=7, RiserHeight=175.0, TreadLength=280.0) for i in (1, 2)]
    api.run("aggregate.assign_object", m.f, relating_object=stair, products=flights)

    doc = analyse(m.save(tmp_path), describes="test project")
    assert doc["sources"][0]["describes"] == "test project"
    assert doc["sources"][0]["length_unit"].startswith("millimetre")

    door = element(doc, "Door", "door:D101")              # the Tag is the mark
    assert door["at"] == [f"ifc:{m.f.by_type('IfcDoor')[0].GlobalId}"]
    assert values(door, "mark") == ["D101"]
    assert values(door, "leaf_width") == ["915 mm"]
    assert values(door, "clear_width") == ["851 mm", "871 mm"]   # 915 less 64..44 mm
    assert values(door, "height") == ["2100 mm"]
    assert values(door, "leaves") == [1]
    assert values(door, "storey") == ["Ground"]
    assert values(door, "fire_rating") == ["EI 30"]
    assert values(door, "is_external") == [True]

    space = element(doc, "Space", "space:101")
    assert values(space, "number") == ["101"] and values(space, "name") == ["OFFICE"]
    assert values(space, "storey") == ["Ground"]
    assert values(space, "floor_area") == ["20 m2"]
    assert "Qto_SpaceBaseQuantities.NetFloorArea" in space["facts"]["floor_area"][0]["at"]

    st = element(doc, "Stair", "stair:Stair 1")
    assert values(st, "riser_height") == ["175 mm"]
    assert values(st, "tread_depth") == ["280 mm"]
    assert values(st, "risers") == [8]                      # per flight; both flights have 8
    assert values(st, "rise") == ["2.8 m"]                  # 16 x 175 mm
    assert values(st, "is_external") == [False]

    assert values(element(doc, "Storey", "storey:Upper"), "elevation") == ["2.8 m"]
    # only Ground has a walkable space and a door
    assert doc["facts"]["storeys_above_ground"][0]["value"] == 1
    assert doc["facts"]["storeys_below_ground"][0]["value"] == 0
    assert extract is analyse


def test_foot_model_is_converted_to_metric(tmp_path):
    m = Model("ft")
    ground = m.storey("Level 1", 0.0)
    m.storey("Level 2", 10.0)
    m.space(ground, "101", "OFFICE", 0, 0, 6, 4, NetFloorArea=200.0)          # 200 ft2
    wall = m.wall(ground)
    m.door(ground, wall, "101A", (6.0, 1.0, 0.15, 1.0), 3.0, 7.0, (0, 1, 0), (6.05, 1.0),
           op="DOUBLE_DOOR_SINGLE_SWING", IsExternal=True)
    stair = m.make("IfcStair", "S1")
    api.run("spatial.assign_container", m.f, relating_structure=ground, products=[stair])
    flight = m.make("IfcStairFlight", "flight", NumberOfRisers=17, NumberOfTreads=16, RiserHeight=7 / 12, TreadLength=11 / 12)
    api.run("aggregate.assign_object", m.f, relating_object=stair, products=[flight])

    doc = analyse(m.save(tmp_path))
    door = element(doc, "Door", "door:101A")
    assert values(door, "leaves") == [2]                      # OperationType DOUBLE_DOOR_SINGLE_SWING
    assert values(door, "leaf_width") == ["457.2 mm"]         # 3 ft / 2
    assert values(door, "height") == ["2133.6 mm"]            # 7 ft
    assert values(element(doc, "Storey", "storey:Level 2"), "elevation") == ["3.048 m"]
    assert values(element(doc, "Space", "space:101"), "floor_area") == ["18.58 m2"]   # 200 ft2
    st = element(doc, "Stair", "stair:S1")
    assert values(st, "riser_height") == ["177.8 mm"]          # 7 in
    assert values(st, "tread_depth") == ["279.4 mm"]           # 11 in
    assert values(st, "risers") == [17]


def test_stair_flight_attributes_written_in_feet_are_detected(tmp_path):
    """Revit 2011 writes IfcStairFlight.RiserHeight and TreadLength in feet in a metre file; the flight's height tells."""
    m = Model("m")
    ground = m.storey("Ground", 0.0)
    stair = m.make("IfcStair", "S1")
    api.run("spatial.assign_container", m.f, relating_structure=ground, products=[stair])
    flight = m.make("IfcStairFlight", "flight", NumberOfRisers=12, NumberOfTreads=11, RiserHeight=0.175 / FOOT, TreadLength=0.28 / FOOT)
    api.run("aggregate.assign_object", m.f, relating_object=stair, products=[flight])
    m.box(flight, 0, 0, 0, 3.08, 1.0, 12 * 0.175)
    st = element(analyse(m.save(tmp_path)), "Stair", "stair:S1")
    assert values(st, "riser_height") == ["175 mm"]
    assert values(st, "tread_depth") == ["280 mm"]
    assert "feet" in st["facts"]["riser_height"][0]["at"]


def test_travel_distance_through_a_door_to_the_exit(tmp_path):
    """Two rooms on the ground floor, separated by a 0.2 m wall with a 1 m door; an exterior door in room B.

        y=4 +-----------+  +-----------+
            |  A        |  |  B        |=  exterior door y 2.8..3.8 at x 10.2..10.4
            |           |  |           |
        1.5 |           ====           |   internal door y 0.5..1.5 at x 5.0..5.2
        0.5 |           |  |           |
          0 +-----------+  +-----------+
            0          5  5.2        10.2

    From A's corner (0, 4) the taut string bends round the door's upper jamb, (5, 1.5) and (5.2, 1.5), and runs to
    the near edge of the exterior door's opening at (10.2, 2.8):
        sqrt(5^2 + 2.5^2) + 0.2 + sqrt(5^2 + 1.3^2) = 5.590 + 0.2 + 5.166 = 10.956 m.
    The corner (0, 0) sees (10.2, 2.8) straight through the door: sqrt(10.2^2 + 2.8^2) = 10.577 m, so (0, 4) is
    the farthest point. In B the farthest corner is (5.2, 0): sqrt(5^2 + 2.8^2) = 5.731 m.
    """
    m = Model("m")
    ground = m.storey("Ground", 0.0)
    a = m.space(ground, "A1", "OFFICE", 0, 0, 5, 4)
    b = m.space(ground, "B1", "LOBBY", 5.2, 0, 5, 4)
    wall = m.wall(ground)
    m.door(ground, wall, "D1", (5.0, 0.5, 0.2, 1.0), 1.0, 2.1, (0, 1, 0), (5.1, 0.5), IsExternal=False)
    m.door(ground, wall, "D2", (10.2, 2.8, 0.2, 1.0), 1.0, 2.1, (0, 1, 0), (10.3, 2.8), IsExternal=True)

    doc = analyse(m.save(tmp_path))
    ta = element(doc, "Space", "space:A1")
    tb = element(doc, "Space", "space:B1")
    assert metres(values(ta, "travel_distance")[0]) == pytest.approx(5.5902 + 0.2 + 5.1662, abs=0.05)
    assert metres(values(tb, "travel_distance")[0]) == pytest.approx(math.hypot(5, 2.8), abs=0.05)
    at = ta["facts"]["travel_distance"][0]["at"]
    assert at.startswith(f"ifc:{a.GlobalId} ") and "door D2" in at
    # the farthest point is A's corner (0, 4)
    x, y = (float(v) for v in at.split("from (")[1].split(")")[0].split(","))
    assert math.hypot(x - 0, y - 4) < 0.15

    storey = element(doc, "Storey", "storey:Ground")
    assert values(storey, "max_travel_distance") == values(ta, "travel_distance")
    assert f"ifc:{a.GlobalId}" in storey["facts"]["max_travel_distance"][0]["at"]
    assert values(storey, "exits") == [1]
    assert values(ta, "exits") == [1] and values(tb, "exits") == [1]
    assert b.GlobalId  # B is reached through its own exterior door
