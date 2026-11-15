"""Plan geometry and travel distance for the IFC adapter (adapters/ifc.py).

The IFC adapter reads properties; this module reads shapes. Every element is
triangulated by ifcopenshell.geom in world coordinates (metres), then flattened
to a plan footprint with shapely. Per storey:

  walkable floor = footprints of the storey's spaces (their bottom faces)
                 + door passages (the door's opening, extended EXTEND m into the
                   rooms on both sides, so a door joins the two rooms it connects)
                 + stair footprints (flights and landings, seen from above)
                 - columns standing on the floor.

Walls are not read: an IfcSpace is bounded by the wall faces, so two rooms
separated by a wall are separated by a gap in the walkable floor, and only a
door passage bridges it.

Travel distance is the geodesic (shortest path inside the walkable floor) from a
point to the nearest exit. It is computed on a square grid of RESOLUTION m with
16 move directions (Dijkstra from all exits at once, keeping each cell's two
nearest exits where they are within the grid metric's 2.7 % of each other).
For the farthest candidate cells of each space the grid path is then
string-pulled against the walkable polygon (every straight leg is checked to lie
inside it), its bends are moved onto the floor corners they turn round, and its
end onto the exit's polygon. The reported length is that of the pulled path: the
exact geodesic where the bends lie within 4 cells of a corner, which is the case
for paths through doors and round wall ends.
"""

from __future__ import annotations

import heapq
import math
import os
import time
from dataclasses import dataclass, field

import ifcopenshell
import ifcopenshell.geom
import numpy as np
import shapely
import shapely.ops
from shapely.geometry import LineString, Point, Polygon
from shapely.ops import unary_union

RESOLUTION = 0.1          # m, grid cell size for the path search
MAX_CELLS = 450_000       # per storey; the cell size grows when a floor needs more
EXTEND = 0.3              # m a door passage reaches past each face of its opening
CLOSE_GAP = 0.02          # m: spaces closer than twice this are treated as touching (room separation lines)
CANDIDATES = 4            # farthest cells per space whose path is string-pulled


# ----------------------------------------------------------------- meshes

@dataclass
class Mesh:
    verts: np.ndarray   # (n, 3) metres, world coordinates
    faces: np.ndarray   # (m, 3) vertex indices

    @property
    def zmin(self) -> float:
        return float(self.verts[:, 2].min())

    @property
    def zmax(self) -> float:
        return float(self.verts[:, 2].max())


def meshes(f: ifcopenshell.file, elements: list, subtract_openings: bool = False) -> dict[int, Mesh]:
    """Triangulate elements in world coordinates (metres). Keyed by entity id; elements without a body are absent."""
    out: dict[int, Mesh] = {}
    if not elements:
        return out
    s = ifcopenshell.geom.settings()
    s.set("use-world-coords", True)
    s.set("disable-opening-subtractions", not subtract_openings)
    it = ifcopenshell.geom.iterator(s, f, max(1, min(8, os.cpu_count() or 1)), include=elements)
    if not it.initialize():
        return out
    while True:
        sh = it.get()
        g = sh.geometry
        v = np.asarray(g.verts, dtype=float).reshape(-1, 3)
        fc = np.asarray(g.faces, dtype=np.int64).reshape(-1, 3)
        if len(fc):
            out[sh.id] = Mesh(v, fc)
        if not it.next():
            break
    return out


def footprint(m: Mesh, bottom: bool = False):
    """Plan footprint: the union of the triangles seen from above, or of the downward faces at the bottom only."""
    tri = m.verts[m.faces]
    if bottom:
        n = np.cross(tri[:, 1] - tri[:, 0], tri[:, 2] - tri[:, 0])
        norm = np.linalg.norm(n, axis=1) + 1e-12
        low = tri[:, :, 2].max(axis=1) <= m.zmin + 0.05
        tri = tri[(n[:, 2] / norm < -0.5) & low]
    t2 = tri[:, :, :2]
    area = 0.5 * np.abs((t2[:, 1, 0] - t2[:, 0, 0]) * (t2[:, 2, 1] - t2[:, 0, 1]) - (t2[:, 2, 0] - t2[:, 0, 0]) * (t2[:, 1, 1] - t2[:, 0, 1]))
    t2 = t2[area > 1e-8]
    if not len(t2):
        return Polygon()
    rings = np.concatenate([t2, t2[:, :1]], axis=1)
    return shapely.make_valid(shapely.union_all(shapely.polygons(rings)))


def rectangle(c, u, v, a: float, b: float) -> Polygon:
    """Rectangle centred at c with half-length a along unit u and half-width b along unit v."""
    c, u, v = np.asarray(c), np.asarray(u), np.asarray(v)
    return Polygon([c + a * u + b * v, c - a * u + b * v, c - a * u - b * v, c + a * u - b * v])


def oriented_box(poly, axis=None):
    """(centre, u, v, half-length along u, half-width along v) of a footprint; u is `axis` if given, else the long side."""
    if axis is None:
        r = poly.minimum_rotated_rectangle
        xy = np.asarray(r.exterior.coords)[:4]
        e1, e2 = xy[1] - xy[0], xy[2] - xy[1]
        axis = e1 if np.linalg.norm(e1) >= np.linalg.norm(e2) else e2
    u = np.asarray(axis[:2], dtype=float)
    u /= np.linalg.norm(u)
    v = np.array([-u[1], u[0]])
    xy = np.asarray(poly.exterior.coords) if poly.geom_type == "Polygon" else np.vstack([np.asarray(p.exterior.coords) for p in poly.geoms])
    pu, pv = xy @ u, xy @ v
    cu, cv = (pu.max() + pu.min()) / 2, (pv.max() + pv.min()) / 2
    return cu * u + cv * v, u, v, (pu.max() - pu.min()) / 2, (pv.max() - pv.min()) / 2


# ----------------------------------------------------------------- plan model

@dataclass
class Room:
    gid: str
    label: str            # how the report names it, e.g. "space 1AC1 CENTRAL WAITING"
    poly: object
    exit: bool = False    # part of an exit (stair enclosure, protected escape space)


@dataclass
class Door:
    gid: str
    label: str
    threshold: object     # the opening in the wall, in plan
    passage: object       # threshold extended into both rooms
    ends: tuple           # the two extensions, one per side
    external: bool | None # Pset_DoorCommon.IsExternal


@dataclass
class StoreyPlan:
    name: str             # the storey's key (adapters.ifc uses its GlobalId)
    at_grade: bool
    rooms: list[Room]
    doors: list[Door]
    stairs: list[Room]    # stair footprints, always exits off grade
    obstacles: object = field(default_factory=Polygon)


@dataclass
class SpaceRoute:
    gid: str
    distance: float               # m
    point: tuple                  # farthest point (x, y)
    exit: str                     # label of the exit reached
    exit_gid: str
    exits: int                    # exit or exit-access doorways from the space
    path: list = field(default_factory=list)


@dataclass
class StoreyRoute:
    name: str
    resolution: float
    cells: int
    spaces: dict[str, SpaceRoute]
    unreachable: list[str]        # spaces from which no exit can be reached
    exits: list[str]              # labels of the exits reached from some space
    exit_kind: str                # "exterior doors" or "stair enclosures"
    doors_used: dict[str, str]    # exit door gid -> label, for doors that are exit targets
    open_stairs: list[str]        # stairs open to the floor, not counted as exits
    seconds: float = 0.0


def door_plan(opening_fp, axis, origin, rooms, gid: str, label: str, external) -> Door | None:
    """A door passage from the footprint of its opening (or of the door itself), the door's width axis and position.

    The threshold is the gap between the rooms at the door: the opening's plan box, cut to 0.6 m either side of the
    door's placement (some tools extrude openings far through the wall), less the rooms; the piece nearest the door.
    """
    if opening_fp.is_empty or opening_fp.area < 1e-4:
        return None
    c, u, v, a, b = oriented_box(opening_fp, axis)
    if origin is not None:
        v0 = float(np.dot(np.asarray(origin[:2]) - c, v))
        lo, hi = max(-b, v0 - 0.6), min(b, v0 + 0.6)
        if hi > lo:
            c, b = c + v * (lo + hi) / 2, (hi - lo) / 2
    box = rectangle(c, u, v, a, max(b, 0.05))
    gap = box.difference(rooms) if rooms is not None and not rooms.is_empty else box
    parts = [p for p in getattr(gap, "geoms", [gap]) if p.geom_type == "Polygon" and p.area > 1e-4]
    if parts and origin is not None:
        here = Point(origin[:2])
        part = min(parts, key=lambda p: p.distance(here))
        pv = np.asarray(part.exterior.coords) @ v
        cv = (pv.max() + pv.min()) / 2
        c, b = c + v * (cv - float(np.dot(c, v))), (pv.max() - pv.min()) / 2
    b = max(b, 0.05)
    th = rectangle(c, u, v, a, b)
    passage = rectangle(c, u, v, a, b + EXTEND)
    ends = (rectangle(c + v * (b + EXTEND / 2), u, v, a, EXTEND / 2), rectangle(c - v * (b + EXTEND / 2), u, v, a, EXTEND / 2))
    return Door(gid, label, th, passage, ends, external)


# ----------------------------------------------------------------- grid search

# 16 moves: 4 orthogonal, 4 diagonal, 8 knight moves; for each, the cells the segment crosses.
_MOVES = []
for dx, dy in [(1, 0), (-1, 0), (0, 1), (0, -1), (1, 1), (1, -1), (-1, 1), (-1, -1),
               (2, 1), (2, -1), (-2, 1), (-2, -1), (1, 2), (1, -2), (-1, 2), (-1, -2)]:
    via = []
    if abs(dx) == 1 and abs(dy) == 1:
        via = [(dx, 0), (0, dy)]
    elif abs(dx) == 2:
        via = [(dx // 2, 0), (dx // 2, dy)]
    elif abs(dy) == 2:
        via = [(0, dy // 2), (dx, dy // 2)]
    _MOVES.append((dx, dy, math.hypot(dx, dy), via))


def _shift(a: np.ndarray, dx: int, dy: int) -> np.ndarray:
    """out[y, x] = a[y + dy, x + dx], False outside."""
    out = np.zeros_like(a)
    ny, nx = a.shape
    ys, yd = (slice(dy, ny), slice(0, ny - dy)) if dy >= 0 else (slice(0, ny + dy), slice(-dy, ny))
    xs, xd = (slice(dx, nx), slice(0, nx - dx)) if dx >= 0 else (slice(0, nx + dx), slice(-dx, nx))
    out[yd, xd] = a[ys, xs]
    return out


def _dijkstra(walk: np.ndarray, sources: dict[int, int], h: float):
    """Multi-source Dijkstra over walkable cells. sources: flat cell index -> exit index.
    Returns the distance to the nearest exit, the links _chain follows, and the nearest exit of every cell."""
    ny, nx = walk.shape
    n = ny * nx
    flat = walk.ravel()
    # one 16-bit mask of valid moves per cell; `moves[mask]` lists the (offset, length) of the moves it allows
    mask = np.zeros(n, dtype=np.int64)
    off, wt = [], []
    for k, (dx, dy, w, via) in enumerate(_MOVES):
        ok = walk & _shift(walk, dx, dy)
        for vx, vy in via:
            ok &= _shift(walk, vx, vy)
        mask |= ok.ravel().astype(np.int64) << k
        off.append(dy * nx + dx)
        wt.append(w * h)
    mask = mask.tolist()
    moves = {m: tuple((off[k], wt[k]) for k in range(16) if m >> k & 1) for m in set(mask)}

    # The two nearest exits of every cell (distinct exits), so that where two exits are within the grid's 2.7 %
    # of each other the string-pulled paths to both can be compared. A second exit is kept only when it is that close.
    INF = float("inf")
    tie, slack = 1.03, 3 * h
    d1, l1, p1 = [INF] * n, [-1] * n, [-1] * n
    d2, l2, p2 = [INF] * n, [-1] * n, [-1] * n
    heap = []
    for c, lab in sources.items():
        if flat[c]:
            d1[c], l1[c] = 0.0, lab
            heap.append((0.0, c, lab))
    heapq.heapify(heap)
    pop, push = heapq.heappop, heapq.heappush
    while heap:
        d, u, lab = pop(heap)
        if not ((l1[u] == lab and d <= d1[u]) or (l2[u] == lab and d <= d2[u])):
            continue
        for o, w in moves[mask[u]]:
            v = u + o
            nd = d + w
            if l1[v] == lab:
                if nd < d1[v]:
                    d1[v], p1[v] = nd, u
                    push(heap, (nd, v, lab))
            elif nd < d1[v]:
                d2[v], l2[v], p2[v] = d1[v], l1[v], p1[v]
                d1[v], l1[v], p1[v] = nd, lab, u
                push(heap, (nd, v, lab))
            elif l2[v] == lab:
                if nd < d2[v]:
                    d2[v], p2[v] = nd, u
                    push(heap, (nd, v, lab))
            elif nd < d2[v] and nd <= tie * d1[v] + slack:
                d2[v], l2[v], p2[v] = nd, lab, u
                push(heap, (nd, v, lab))
    return np.asarray(d1).reshape(ny, nx), (l1, p1, l2, p2), np.asarray(l1).reshape(ny, nx)


def _chain(c: int, lab: int, links) -> tuple[list, int]:
    """The grid path from cell c to the exit `lab` (cells), and the source cell it ends at."""
    l1, p1, _, p2 = links
    out, end = [], c
    while c != -1:
        out.append(c)
        end = c
        c = p1[c] if l1[c] == lab else p2[c]
    return out, end


def _pull(points: list, free) -> list:
    """String-pull a polyline: keep the farthest vertex each straight leg can reach inside `free` (prepared)."""
    out = [points[0]]
    i, n = 0, len(points)
    while i < n - 1:
        lo, step = i + 1, 1
        # gallop, then bisect, for the farthest visible vertex
        while lo + step < n and free.covers(LineString([points[i], points[lo + step]])):
            lo += step
            step *= 2
        hi = min(n - 1, lo + step)
        while hi > lo:
            mid = (lo + hi + 1) // 2
            if free.covers(LineString([points[i], points[mid]])):
                lo = mid
            else:
                hi = mid - 1
        i = lo
        out.append(points[i])
    return out


def _snap(pts: list, free, corners: np.ndarray, reach: float) -> list:
    """Replace each bend of a pulled path by the shortest way round the floor's corners near it: a taut path bends only
    at corners, the grid path half a cell to a cell off them. Exact where the corners lie within `reach` of the bend."""
    out = [pts[0]]
    for i in range(1, len(pts) - 1):
        a, p, b = out[-1], pts[i], pts[i + 1]
        d = np.hypot(corners[:, 0] - p[0], corners[:, 1] - p[1])
        near = [(float(corners[j, 0]), float(corners[j, 1])) for j in np.argsort(d)[:12] if d[j] <= reach]
        nodes = [a, b] + list(dict.fromkeys(near))
        # Dijkstra from a to b over the corners, legs that stay on the floor
        best = {0: (0.0, [a])}
        todo = [(0.0, 0)]
        done = set()
        while todo:
            dist, u = heapq.heappop(todo)
            if u in done:
                continue
            done.add(u)
            if u == 1:
                break
            for v in range(1, len(nodes)):
                if v in done:
                    continue
                nd = dist + math.dist(nodes[u], nodes[v])
                if (v not in best or nd < best[v][0]) and free.covers(LineString([nodes[u], nodes[v]])):
                    best[v] = (nd, best[u][1] + [nodes[v]])
                    heapq.heappush(todo, (nd, v))
        if 1 in best and best[1][0] < math.dist(a, p) + math.dist(p, b) - 1e-9:
            out += best[1][1][1:-1]
        else:
            out.append(p)
    out.append(pts[-1])
    return out


def _finish(pts: list, target, free) -> list:
    """End the path on the exit itself, at the nearest point the last legs can see: the source cells reach half a cell
    beyond the exit's polygon, so the grid path stops short of it or overshoots."""
    if target is None or len(pts) < 2:
        return pts
    best = None
    for k in range(max(0, len(pts) - 4), len(pts) - 1):
        q = pts[k]
        t = shapely.ops.nearest_points(target, Point(q))[0]
        t = (float(t.x), float(t.y))
        if q == t or free.covers(LineString([q, t])):
            cand = pts[: k + 1] + [t]
            if best is None or _length(cand) < _length(best):
                best = cand
    return best or pts


def _length(pts) -> float:
    return float(sum(math.dist(a, b) for a, b in zip(pts, pts[1:])))


def route_storey(plan: StoreyPlan, resolution: float = RESOLUTION, progress=lambda m: None) -> StoreyRoute | None:
    """Travel distance from every point of every non-exit room of the storey to its nearest exit."""
    t0 = time.time()
    rooms = [r for r in plan.rooms if not r.poly.is_empty]
    exit_regions = [r.poly for r in rooms if r.exit] + [s.poly for s in plan.stairs]
    plain = [r for r in rooms if not r.exit]
    if not plain:
        return None
    room_union = unary_union([r.poly for r in rooms] + [s.poly for s in plan.stairs])

    def side_in(poly, region) -> bool:
        return (not region.is_empty) and poly.intersection(region).area > 0.3 * poly.area

    # Which doors are exits.
    targets: list[tuple[int, object, str, str]] = []   # (exit index, target polygon, label, gid)
    exit_labels: list[str] = []
    exit_gids: list[str] = []
    doors_used: dict[str, str] = {}
    plain_union = unary_union([r.poly for r in plain])
    exit_union = Polygon()      # the exit enclosures (off grade)
    open_labels: list[str] = []  # open stairs that are not exits
    if plan.at_grade:
        exit_kind = "exterior doors"
        for d in plan.doors:
            inside = [side_in(e, room_union) for e in d.ends]
            external = d.external if d.external is not None else (sum(inside) == 1)
            if external and any(inside):
                targets.append((len(exit_labels), d.threshold, d.label, d.gid))
                exit_labels.append(d.label)
                exit_gids.append(d.gid)
                doors_used[d.gid] = d.label
    else:
        exit_kind = "stair enclosures"
        merged = unary_union([c.buffer(0.05) for c in exit_regions]) if exit_regions else Polygon()
        groups = list(merged.geoms) if merged.geom_type == "MultiPolygon" else ([merged] if not merged.is_empty else [])
        comps = [unary_union([c for c in exit_regions if c.intersects(g)]) for g in groups]
        # An enclosure is entered through doors only. A stair whose floor meets a room along 0.5 m or more without a
        # door is open (an exit access stair): travel continues down it, so it is an exit only where the storey has
        # no enclosure.
        passages_all = unary_union([d.passage for d in plan.doors]) if plan.doors else Polygon()
        enclosed = [c for c in comps if c.buffer(0.03).intersection(plain_union).difference(passages_all).area < 0.5 * 0.03]
        open_stairs = [c for c in comps if not any(c is e for e in enclosed)]
        if not enclosed and open_stairs:
            exit_kind = "open stairs (the storey has no stair enclosure)"
        comps = enclosed or open_stairs
        open_names = []
        names = []
        for group, out in ((comps, names), (open_stairs if enclosed else [], open_names)):
            for c in group:
                hit = [r for r in rooms if r.exit and r.poly.intersects(c)] + [s for s in plan.stairs if s.poly.intersects(c)]
                out.append(hit[0] if hit else None)
        open_labels = [w.label for w in open_names if w is not None]
        exit_union = unary_union(comps) if comps else Polygon()
        for k, c in enumerate(comps):
            who = names[k]
            exit_labels.append(who.label if who else f"exit region {k + 1}")
            exit_gids.append(who.gid if who else "")
            targets.append((k, c, exit_labels[-1], exit_gids[-1]))
        reach = [c.buffer(0.1) for c in comps]   # a landing may stop short of the wall face
        for d in plan.doors:
            for k, c in enumerate(reach):
                a, b = d.ends
                if (side_in(a, c) and side_in(b, plain_union)) or (side_in(b, c) and side_in(a, plain_union)):
                    targets.append((k, d.threshold, exit_labels[k], d.gid))
                    doors_used[d.gid] = f"{d.label} into {exit_labels[k]}"
    if not exit_labels:
        return StoreyRoute(plan.name, resolution, 0, {}, [r.gid for r in plain], [], exit_kind, {}, open_labels, time.time() - t0)

    passages = unary_union([d.passage for d in plan.doors]) if plan.doors else Polygon()
    free = unary_union([room_union.buffer(CLOSE_GAP, join_style="mitre").buffer(-CLOSE_GAP, join_style="mitre"), passages])
    if not plan.obstacles.is_empty:
        free = free.difference(plan.obstacles.difference(passages))
    free = shapely.make_valid(free)

    # grid
    area = free.area
    h = max(resolution, math.sqrt(area / MAX_CELLS)) if area > 0 else resolution
    x0, y0, x1, y1 = free.bounds
    nx, ny = int(math.ceil((x1 - x0) / h)) + 1, int(math.ceil((y1 - y0) / h)) + 1
    xs = x0 + (np.arange(nx) + 0.5) * h
    ys = y0 + (np.arange(ny) + 0.5) * h
    X, Y = np.meshgrid(xs, ys)
    eroded = free.buffer(-h / 2, join_style="mitre")
    walk = shapely.contains_xy(eroded, X, Y)

    def cells_of(poly) -> np.ndarray:
        """Flat indices of the walkable cells whose centre lies in `poly`."""
        bx0, by0, bx1, by1 = poly.bounds
        i0, i1 = max(0, int((bx0 - x0) / h) - 1), min(nx, int((bx1 - x0) / h) + 2)
        j0, j1 = max(0, int((by0 - y0) / h) - 1), min(ny, int((by1 - y0) / h) + 2)
        if i1 <= i0 or j1 <= j0:
            return np.zeros(0, dtype=np.int64)
        jj, ii = np.mgrid[j0:j1, i0:i1]
        sub = shapely.contains_xy(poly, X[j0:j1, i0:i1], Y[j0:j1, i0:i1]) & walk[j0:j1, i0:i1]
        return (jj[sub] * nx + ii[sub]).astype(np.int64)

    sources: dict[int, int] = {}
    reached_by: dict[int, tuple[str, str]] = {}   # source cell -> (what the path ends at, its GlobalId)
    target_of: dict[int, object] = {}             # source cell -> the exit's polygon
    door_gids = {d.gid for d in plan.doors}
    # doors first: where a door and its enclosure share cells, the path ends at the door
    for k, poly, lab, gid in sorted(targets, key=lambda t: t[3] not in door_gids):
        what = doors_used.get(gid, lab)
        for c in cells_of(poly.buffer(h * 0.5)):
            if int(c) not in sources:
                sources[int(c)] = k
                reached_by[int(c)] = (what, gid)
                target_of[int(c)] = poly
    progress(f"path search on {int(walk.sum())} cells of {h:.2f} m")
    dist, links, label = _dijkstra(walk, sources, h)

    prepared = free.buffer(1e-4, join_style="mitre")
    shapely.prepare(prepared)
    corners = shapely.get_coordinates(shapely.get_rings(free))
    results: dict[str, SpaceRoute] = {}
    unreachable: list[str] = []
    reached: set[int] = set()
    Xf, Yf, Df, Lf = X.ravel(), Y.ravel(), dist.ravel(), label.ravel()
    for r in plain:
        cells = cells_of(r.poly)
        if not len(cells):
            continue
        d = Df[cells]
        ok = np.isfinite(d)
        if ok.sum() < 0.95 * len(cells):
            unreachable.append(r.gid)
            continue
        cells, d = cells[ok], d[ok]
        picks = []
        for c in cells[np.argsort(d)[::-1][:4000]]:
            p = (Xf[c], Yf[c])
            if all(math.dist(p, q[1]) > 1.0 for q in picks):
                picks.append((int(c), p))
            if len(picks) >= CANDIDATES:
                break
        best = None
        verts = np.asarray(r.poly.exterior.coords) if r.poly.geom_type == "Polygon" else np.vstack([np.asarray(g.exterior.coords) for g in r.poly.geoms])
        for c, p in picks:
            # start from the room's corner when the cell sits in one
            near = verts[np.argmin(np.hypot(verts[:, 0] - p[0], verts[:, 1] - p[1]))]
            corner = math.dist(near, p) < 2.5 * h and prepared.covers(LineString([tuple(near), p]))
            mine = None   # the shorter of the paths to the two nearest exits
            for lab in {links[0][c], links[2][c]} - {-1}:
                cells, end = _chain(c, lab, links)
                chain = [(float(Xf[u]), float(Yf[u])) for u in cells]
                if corner:
                    chain.insert(0, (float(near[0]), float(near[1])))
                pulled = _finish(_snap(_pull(chain, prepared), prepared, corners, 4 * h), target_of.get(end), prepared)
                length = _length(pulled)
                if mine is None or length < mine[0]:
                    mine = (length, pulled, lab, reached_by.get(end, (exit_labels[lab], exit_gids[lab])))
            if best is None or mine[0] > best[0]:
                best = mine
        if best is None:
            continue
        reached.add(best[2])
        results[r.gid] = SpaceRoute(r.gid, best[0], tuple(round(v, 2) for v in best[1][0]), best[3][0], best[3][1], 0, best[1])
        # an exit serves the storey when it is the nearest exit for some point of a space
        reached |= set(int(x) for x in np.unique(Lf[cells]) if x >= 0)

    _count_exits(plan, plain, results, targets, exit_union)
    return StoreyRoute(plan.name, h, int(walk.sum()), results, unreachable, [exit_labels[k] for k in sorted(reached)], exit_kind, doors_used, open_labels, time.time() - t0)


def _count_exits(plan: StoreyPlan, plain: list[Room], results: dict, targets, exit_union) -> None:
    """Space.exits: doorways and open boundaries out of a space from which an exit is reached without coming back through it."""
    idx = {r.gid: i for i, r in enumerate(plain)}
    EXIT = len(plain)
    edges: list[tuple[set, str]] = []   # (nodes the connection joins, connection id)
    exit_doors = {gid for _, _, _, gid in targets}
    grown = [r.poly.buffer(0.05) for r in plain]
    tree = shapely.STRtree([r.poly for r in plain])
    for d in plan.doors:
        nodes = set()
        for e in d.ends:
            for i in tree.query(e):
                if e.intersection(plain[int(i)].poly).area > 0.3 * e.area:
                    nodes.add(int(i))
            if not exit_union.is_empty and e.intersection(exit_union).area > 0.3 * e.area:
                nodes.add(EXIT)
        if d.gid in exit_doors:
            nodes.add(EXIT)
        if len(nodes) >= 2:
            edges.append((nodes, d.gid))
    for i, g in enumerate(grown):
        for j in tree.query(g):
            j = int(j)
            if j > i and g.intersection(plain[j].poly).area > 0.6 * 0.05:   # a shared edge of at least 0.6 m
                edges.append(({i, j}, f"open:{i}:{j}"))
        if not exit_union.is_empty and g.intersection(exit_union).area > 0.6 * 0.05:
            edges.append(({i, EXIT}, f"open:{i}:exit"))
    adj: dict[int, list[tuple[int, int]]] = {}
    for k, (nodes, _) in enumerate(edges):
        for a in nodes:
            for b in nodes:
                if a != b:
                    adj.setdefault(a, []).append((b, k))

    def reaches_exit(start: int, banned: int) -> bool:
        seen, stack = {start}, [start]
        while stack:
            u = stack.pop()
            if u == EXIT:
                return True
            for v, _ in adj.get(u, []):
                if v != banned and v not in seen:
                    seen.add(v)
                    stack.append(v)
        return False

    for gid, route in results.items():
        i = idx[gid]
        count = 0
        for nodes, _ in edges:
            if i in nodes and any(reaches_exit(o, i) for o in nodes if o != i):
                count += 1
        route.exits = count


# ----------------------------------------------------------------- other measurements

def bottleneck_width(poly, connections: list, lo: float = 0.2, hi: float = 8.0) -> float | None:
    """Largest diameter of a disc that can move inside `poly` between all `connections` (regions on its edge)."""
    if len(connections) < 2:
        return None

    def ok(w: float) -> bool:
        core = poly.buffer(-w / 2)
        if core.is_empty:
            return False
        parts = list(core.geoms) if core.geom_type == "MultiPolygon" else [core]
        for part in parts:
            if all(part.distance(c) <= w / 2 + 0.05 for c in connections):
                return True
        return False

    if not ok(lo):
        return None
    while hi - lo > 0.005:
        mid = (lo + hi) / 2
        lo, hi = (mid, hi) if ok(mid) else (lo, mid)
    return lo


def ramp_slope(m: Mesh):
    """(slope as rise over run, rise in m) of the sloped walking surface: the upward faces that are neither flat nor steep."""
    tri = m.verts[m.faces]
    n = np.cross(tri[:, 1] - tri[:, 0], tri[:, 2] - tri[:, 0])
    area = np.linalg.norm(n, axis=1) / 2
    nz = n[:, 2] / (2 * area + 1e-12)
    keep = (nz > 0.7) & (nz < 0.99995) & (area > 1e-4)
    if area[keep].sum() < 0.5:
        return None
    nk = n[keep] / np.linalg.norm(n[keep], axis=1)[:, None]
    w = area[keep]
    mean = (nk * w[:, None]).sum(axis=0) / w.sum()
    slope = math.hypot(mean[0], mean[1]) / mean[2]
    zs = tri[keep][:, :, 2]
    return float(slope), float(zs.max() - zs.min())
