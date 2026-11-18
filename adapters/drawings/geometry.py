"""Measurements taken from a vector drawing's own lines where it draws a stair or a door but does not dimension what
a requirement measures: the depth of each tapered tread (winder) at its narrow end, centre and wide end; the going
and width of a straight flight; and how close a door's swing comes to a stair's tread lines.

Lengths in points become millimetres at the scale of the dimensions nearby (adapters.drawings.dimensions), so
nothing is measured on a sheet, or a part of one, without dimensions to give its scale. Only lines near a word that
names a stair (UP, DN, STAIR, TREAD, ... or adapters.drawings.annotations' terms in other languages) are read as a
stair's, so a schedule's ruled rows or a wall's hatching are not taken for treads.

    tapered treads  three or more tread lines whose near ends meet or lie close together and whose angles step
                    10-75 degrees from one line to the next (a fan, as winders are drawn); each pair bounds a tread
    flight          three or more parallel tread lines of one length, evenly spaced 180-480 mm apart
    door swing      an arc with a straight leaf from its centre to one of its ends; its leaf swung to 90 degrees
                    from the closed position (the arc's other end), or as far as the arc is drawn if that is further

Each measurement is one line of text with the region it covers; adapters.assess.building adds them to the sheet.
"""

from __future__ import annotations

import json
import math
import os
import re
from itertools import pairwise
from pathlib import Path

from . import dimensions, ocr
from .annotations import TERMS
from .tokens import Token

CACHE_VERSION = 1
CACHE_DIR = ocr.CACHE_DIR.parent / "geom"
PT_MM = dimensions.PT_MM
STAIR_WORD = re.compile(rf"(?<![A-Z])(?:UP|DN|DOWN|STAIRS?|STAIRCASE|WINDERS?|TREADS?|RISERS?|{TERMS['stair']})(?![A-Z])", re.IGNORECASE)
REACH = 4000           # mm around a stair word in which its lines are looked for
SCALE_NEAR = 250       # pt: the nearest dimension must be this close for its scale to be taken
TREAD_LINE = (600, 4000)      # mm: a tread line's length (the stair's width or more)
SAME_LINE = 60         # mm: parallel lines closer than this (a nosing and its riser) are one tread line
FAN_STEP = (10, 75)    # degrees between consecutive tapered tread lines
NARROW = 400           # mm: the most a tapered tread's narrow end may measure
CENTRE = 700           # mm: and its centre: deeper is a landing or another drawing's lines, not a tread
SIMILAR = 0.6          # a fan's shortest tread line is at least this fraction of its longest
GOING = (180, 480)     # mm: a straight flight's spacing
EVEN = 0.08            # and how far each spacing may stray from the median
DOOR_LEAF = (500, 1400)       # mm
DOOR_NEAR = 1000       # mm: a door swing this close to a stair's lines is reported
LABELS = 2             # stair labels named for each measurement, nearest first
ARC_FIT = 0.03         # an arc's points may stray from its circle by this fraction of the radius


# ------------------------------------------------------------------- reading the paths

def paths(path: Path, page: int, digest: str | None = None) -> dict:
    """{"lines": [(x0, y0, x1, y1)], "arcs": [(cx, cy, r, start_deg, sweep_deg)]}: every straight piece of the
    page's paths in points from the top left, and every circular arc, cached by the file's hash."""
    digest = digest or ocr.file_hash(path)
    dest = CACHE_DIR / f"{digest}-p{page}.json"
    try:
        data = json.loads(dest.read_text())
        if data.get("version") == CACHE_VERSION:
            return {"lines": [tuple(x) for x in data["lines"]], "arcs": [tuple(x) for x in data["arcs"]]}
    except (OSError, ValueError):
        pass
    from .reader import _pdf

    pg = _pdf(Path(path)).plumber_page(page)
    lines, arcs = set(), []
    if pg is not None:
        for obj in list(pg.lines) + list(pg.curves) + list(pg.rects):
            if obj.get("object_type") == "rect":
                x0, y0, x1, y1 = obj["x0"], obj["top"], obj["x1"], obj["bottom"]
                for a, b in pairwise([(x0, y0), (x1, y0), (x1, y1), (x0, y1), (x0, y0)]):
                    _add_line(lines, a, b)
                continue
            _read_path(obj.get("path") or [], lines, arcs)
    out = {"lines": sorted(lines), "arcs": _merge_arcs(arcs)}
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps({"version": CACHE_VERSION, **out}))
    tmp.replace(dest)
    return out


def _add_line(lines: set, a, b) -> None:
    if math.dist(a, b) >= 2:
        lines.add(tuple(round(v, 2) for v in (*a, *b)))


def _read_path(cmds: list, lines: set, arcs: list) -> None:
    start = cur = None
    poly: list = []     # a run of straight pieces, which may flatten an arc

    def flush():
        if len(poly) >= 5 and (a := _fit_arc(poly)):
            arcs.append(a)
        poly.clear()

    for c in cmds:
        op, pts = c[0], [tuple(p) for p in c[1:]]
        if op == "m":
            flush()
            start = cur = pts[0]
            poly.append(cur)
        elif op == "l" and cur is not None:
            _add_line(lines, cur, pts[0])
            cur = pts[0]
            poly.append(cur)
        elif op == "c" and cur is not None and len(pts) == 3:
            flush()
            bez = [_bezier(cur, *pts, t / 8) for t in range(9)]
            if (a := _fit_arc(bez)):
                arcs.append(a)
            cur = pts[2]
            poly.append(cur)
        elif op == "h" and cur is not None and start is not None:
            _add_line(lines, cur, start)
            cur = start
    flush()


def _bezier(p0, p1, p2, p3, t):
    u = 1 - t
    return tuple(u ** 3 * a + 3 * u * u * t * b + 3 * u * t * t * c + t ** 3 * d for a, b, c, d in zip(p0, p1, p2, p3))


def _fit_arc(pts: list) -> tuple | None:
    """(cx, cy, r, start, sweep) of the circle through pts (least squares), if they lie on one and turn 15-200°."""
    n = len(pts)
    mx, my = sum(p[0] for p in pts) / n, sum(p[1] for p in pts) / n
    u = [(p[0] - mx, p[1] - my) for p in pts]
    suu = sum(a * a for a, _ in u); svv = sum(b * b for _, b in u); suv = sum(a * b for a, b in u)
    suuu = sum(a ** 3 for a, _ in u); svvv = sum(b ** 3 for _, b in u)
    suvv = sum(a * b * b for a, b in u); svuu = sum(b * a * a for a, b in u)
    det = suu * svv - suv * suv
    if abs(det) < 1e-9:
        return None     # collinear
    rhs1, rhs2 = (suuu + suvv) / 2, (svvv + svuu) / 2
    uc, vc = (rhs1 * svv - rhs2 * suv) / det, (suu * rhs2 - suv * rhs1) / det
    cx, cy = uc + mx, vc + my
    r = math.dist((cx, cy), pts[0])
    if r < 4 or max(abs(math.dist((cx, cy), p) - r) for p in pts) > ARC_FIT * r:
        return None
    angs = [math.degrees(math.atan2(p[1] - cy, p[0] - cx)) for p in pts]
    sweep = sum((b - a + 180) % 360 - 180 for a, b in pairwise(angs))
    if not 15 <= abs(sweep) <= 200:
        return None
    return (round(cx, 2), round(cy, 2), round(r, 2), round(angs[0], 2), round(sweep, 2))


def _merge_arcs(arcs: list) -> list:
    """Join arcs drawn in pieces (one quarter as two eighths): same circle, one starting where the other ends."""
    arcs = sorted(arcs)
    out: list = []
    for a in arcs:
        for i, b in enumerate(out):
            if math.dist(a[:2], b[:2]) <= 0.02 * a[2] and abs(a[2] - b[2]) <= 0.02 * a[2]:
                if abs((b[3] + b[4] - a[3] + 180) % 360 - 180) < 2 and math.copysign(1, a[4]) == math.copysign(1, b[4]):
                    out[i] = (*b[:4], round(b[4] + a[4], 2))
                    break
                if abs((a[3] + a[4] - b[3] + 180) % 360 - 180) < 2 and math.copysign(1, a[4]) == math.copysign(1, b[4]):
                    out[i] = (*a[:4], round(a[4] + b[4], 2))
                    break
        else:
            out.append(a)
    return out


# ------------------------------------------------------------------- geometry helpers

def _angle(s) -> float:
    return math.degrees(math.atan2(s[3] - s[1], s[2] - s[0])) % 180


def _diff(a: float, b: float) -> float:
    d = abs(a - b) % 180
    return min(d, 180 - d)


def _mid(s):
    return ((s[0] + s[2]) / 2, (s[1] + s[3]) / 2)


def _seg_point(s, p) -> float:
    ax, ay, bx, by = s
    dx, dy = bx - ax, by - ay
    L2 = dx * dx + dy * dy
    t = 0 if L2 == 0 else max(0, min(1, ((p[0] - ax) * dx + (p[1] - ay) * dy) / L2))
    return math.dist(p, (ax + t * dx, ay + t * dy))


def _cross(s, t) -> bool:
    """s and t cross away from their ends (touching at an end is not crossing)."""
    def side(a, b, p):
        return (b[0] - a[0]) * (p[1] - a[1]) - (b[1] - a[1]) * (p[0] - a[0])
    a, b, c, d = s[:2], s[2:], t[:2], t[2:]
    d1, d2, d3, d4 = side(c, d, a), side(c, d, b), side(a, b, c), side(a, b, d)
    eps = 1e-6 * (math.dist(a, b) * math.dist(c, d) + 1)
    return d1 * d2 < -eps and d3 * d4 < -eps


def _overlap(s, t) -> float:
    """How much of s the parallel line t runs alongside, as a fraction of s's length."""
    a = math.radians(_angle(s))
    ux, uy = math.cos(a), math.sin(a)
    s0, s1 = sorted((0.0, (s[2] - s[0]) * ux + (s[3] - s[1]) * uy))
    t0, t1 = sorted(((t[0] - s[0]) * ux + (t[1] - s[1]) * uy, (t[2] - s[0]) * ux + (t[3] - s[1]) * uy))
    return max(0.0, min(s1, t1) - max(s0, t0)) / max(s1 - s0, 1e-9)


def _box(segs) -> tuple:
    xs = [v for s in segs for v in (s[0], s[2])]
    ys = [v for s in segs for v in (s[1], s[3])]
    return (min(xs), min(ys), max(xs), max(ys))


def _union(a, b) -> tuple:
    return (min(a[0], b[0]), min(a[1], b[1]), max(a[2], b[2]), max(a[3], b[3]))


# ------------------------------------------------------------------- stairs

def _one_line(segs: list, mm) -> list:
    """Parallel lines closer than SAME_LINE that overlap (a nosing and the riser behind it): the longer one."""
    segs = sorted(segs, key=lambda s: -math.dist(s[:2], s[2:]))
    keep: list = []
    for s in segs:
        a, m = _angle(s), _mid(s)
        if not any(_diff(a, _angle(k)) < 3 and _seg_point(k, m) * mm < SAME_LINE for k in keep):
            keep.append(s)
    return keep


def _fan_pairs(segs: list, mm) -> dict:
    """{(i, j): (narrow, wide, centre) in pt} for each two lines that bound a tapered tread."""
    out = {}
    for i, a in enumerate(segs):
        for j in range(i + 1, len(segs)):
            b = segs[j]
            if not FAN_STEP[0] <= _diff(_angle(a), _angle(b)) <= FAN_STEP[1] or _cross(a, b):
                continue
            ends = [(math.dist(p, q), p, q, pa, qb) for p, pa in ((a[:2], a[2:]), (a[2:], a[:2]))
                    for q, qb in ((b[:2], b[2:]), (b[2:], b[:2]))]
            narrow, _, _, fa, fb = min(ends)
            wide = math.dist(fa, fb)
            centre = math.dist(_mid(a), _mid(b))
            if narrow * mm <= NARROW and narrow < centre < wide and centre * mm <= CENTRE and wide * mm >= narrow * mm + 250:
                out[(i, j)] = (narrow, wide, centre)
    return out


def _step(a, b) -> float:
    """Degrees from line a's direction to line b's, turning the shorter way (signed)."""
    return (_angle(b) - _angle(a) + 90) % 180 - 90


def _fans(segs: list, mm) -> list[tuple[list, list]]:
    """[(tread lines in order, [(narrow, wide, centre)] per tread)] for each run of three or more tapered treads, or
    of two that carry on from a straight flight: two splayed lines alone are as often a cupboard, a wall or a
    section's handrail."""
    pairs = _fan_pairs(segs, mm)
    # a line's neighbour on each side of the fan is its partner at the smallest turn that way, if that partner
    # picks it back
    pick = {}
    for (i, j), v in pairs.items():
        for x, y in ((i, j), (j, i)):
            side = _step(segs[x], segs[y]) > 0
            best = pick.get((x, side))
            if best is None or (abs(_step(segs[x], segs[y])), v[0]) < (abs(_step(segs[x], segs[best])), pairs[(min(x, best), max(x, best))][0]):
                pick[(x, side)] = y
    adj = {}
    for (x, side), y in pick.items():
        if pick.get((y, not side)) == x:
            adj.setdefault(x, set()).add(y)
    out, seen = [], set()
    for start in sorted(adj):
        if start in seen or len(adj[start]) != 1:
            continue
        chain = [start]
        while (nxt := [k for k in adj[chain[-1]] if k not in chain]):
            chain.append(nxt[0])
        seen.update(chain)
        steps = [_step(segs[a], segs[b]) for a, b in pairwise(chain)]
        lens = [math.dist(segs[k][:2], segs[k][2:]) for k in chain]
        if not (all(x > 0 for x in steps) or all(x < 0 for x in steps)) or min(lens) < SIMILAR * max(lens):
            continue
        if len(chain) >= 4 or len(chain) == 3 and any(_continues(segs[chain[e]], segs[chain[e + (1 if e == 0 else -1)]], segs, mm) for e in (0, -1)):
            out.append(([segs[k] for k in chain], [pairs[(min(a, b), max(a, b))] for a, b in pairwise(chain)]))
    return out


def _continues(s, inner, segs: list, mm) -> bool:
    """A straight flight carries on from the fan's end line s: two more lines of about its length alongside it, one
    and two goings away on the side away from the fan (`inner` is the fan's next line)."""
    L, a = math.dist(s[:2], s[2:]), math.radians(_angle(s))
    ux, uy = math.cos(a), math.sin(a)

    def across(p):
        return -(p[0] - s[0]) * uy + (p[1] - s[1]) * ux

    side = -math.copysign(1, across(_mid(inner)))
    offs = sorted(across(_mid(t)) * side * mm for t in segs if t is not s and _diff(_angle(s), _angle(t)) < 1.5
                  and abs(math.dist(t[:2], t[2:]) - L) <= 0.2 * L and _overlap(s, t) >= 0.7 and across(_mid(t)) * side > 0)
    return any(GOING[0] <= g <= GOING[1] and any(abs(h - 2 * g) <= EVEN * g for h in offs) for g in offs)


def _flights(segs: list, mm) -> list[tuple[list, list]]:
    """[(tread lines in order, spacings in pt)] for each run of three or more evenly spaced parallel lines."""
    out = []
    used = set()
    for i, s in enumerate(segs):
        if i in used:
            continue
        a, L = _angle(s), math.dist(s[:2], s[2:])
        ux, uy = math.cos(math.radians(a)), math.sin(math.radians(a))
        group = []
        for j, t in enumerate(segs):
            if _diff(a, _angle(t)) > 1.5 or abs(math.dist(t[:2], t[2:]) - L) > 0.1 * L:
                continue
            if _overlap(s, t) < 0.7:
                continue
            group.append((-(t[0] - s[0]) * uy + (t[1] - s[1]) * ux, j))
        group.sort()
        runs, run = [], group[:1]
        for off, j in group[1:]:
            gap = (off - run[-1][0]) * mm
            if gap < 1:
                continue
            fits = GOING[0] <= gap <= GOING[1]
            if fits and (len(run) < 2 or abs(gap - (run[1][0] - run[0][0]) * mm) <= EVEN * gap):
                run.append((off, j))
            else:
                runs.append(run)
                run = [run[-1], (off, j)] if fits else [(off, j)]
        runs.append(run)
        for run in runs:
            if len(run) >= 3 and not used & {j for _, j in run}:
                used.update(j for _, j in run)
                out.append(([segs[j] for _, j in run], [b[0] - a[0] for a, b in pairwise(run)]))
    return out


# ------------------------------------------------------------------- doors

def _door_swings(arcs: list, lines: list, mm) -> list[tuple]:
    """[(hinge, leaf radius pt, closed angle deg, swing deg signed, drawn sweep deg)] for each arc with a leaf."""
    out = []
    for cx, cy, r, start, sweep in arcs:
        if not DOOR_LEAF[0] <= r * mm <= DOOR_LEAF[1] or not 25 <= abs(sweep) <= 185:
            continue
        ends = [(cx + r * math.cos(math.radians(a)), cy + r * math.sin(math.radians(a))) for a in (start, start + sweep)]
        tol = max(0.08 * r, 2)
        leaf_end = None
        for s in lines:
            for h, e in ((s[:2], s[2:]), (s[2:], s[:2])):
                if math.dist(h, (cx, cy)) <= tol and abs(math.dist(h, e) - r) <= tol:
                    k = min(range(2), key=lambda k: math.dist(e, ends[k]))
                    if math.dist(e, ends[k]) <= tol:
                        leaf_end = k
        if leaf_end is None:
            continue
        closed = start if leaf_end == 1 else start + sweep     # the arc's other end lies along the wall
        turn = sweep if leaf_end == 1 else -sweep
        swing = math.copysign(max(90.0, abs(turn)), turn)
        out.append(((cx, cy), r, closed, swing, abs(sweep)))
    return out


def _sector_dist(hinge, r, closed, swing, p) -> float:
    """Distance from p to the area a leaf of radius r sweeps turning `swing` degrees from `closed`."""
    d = math.dist(hinge, p)
    a = math.degrees(math.atan2(p[1] - hinge[1], p[0] - hinge[0]))
    rel = ((a - closed) * math.copysign(1, swing)) % 360
    if rel <= abs(swing):
        return max(0.0, d - r)
    edges = [(hinge[0] + r * math.cos(math.radians(x)), hinge[1] + r * math.sin(math.radians(x))) for x in (closed, closed + swing)]
    return min(_seg_point((*hinge, *e), p) for e in edges)


def _seg_sector(s, door) -> float:
    hinge, r, closed, swing, _ = door
    n = max(2, int(math.dist(s[:2], s[2:]) / 0.5))
    return min(_sector_dist(hinge, r, closed, swing, (s[0] + (s[2] - s[0]) * t / n, s[1] + (s[3] - s[1]) * t / n)) for t in range(n + 1))


# ------------------------------------------------------------------- measuring a sheet

def _local_scale(found: dict, tokens: list[Token], p) -> int | None:
    near = sorted((math.dist(p, _mid(tokens[i].bbox)), d["scale"]) for i, d in found.items())
    if not near or near[0][0] > SCALE_NEAR:
        return None
    top = [k for _, k in near[:5]]
    return max(set(top), key=lambda k: (top.count(k), -top.index(k)))


def _labels(box, tokens: list[Token], within: float) -> str:
    """"; nearest stair labels: ..." for the two words naming a stair nearest the box, which say which stair it is."""
    near = sorted((max(box[0] - c[0], 0, c[0] - box[2]) + max(box[1] - c[1], 0, c[1] - box[3]), u.text.strip())
                  for u in tokens if STAIR_WORD.search(u.text) and (c := _mid(u.bbox)))
    names = list(dict.fromkeys(t for d, t in near if d <= within))[:LABELS]
    return f"; nearest stair labels: {' / '.join(names)}" if names else ""


def _mm(v) -> str:
    return f"{v:.0f}"


def measure(path: Path, tokens: list[Token], page: int, digest: str | None = None) -> list[tuple[str, tuple]]:
    """[(text, bbox)]: one line for each stair's tapered treads or straight flight and each door swing near a stair
    measured on the page, in the page's coordinates. Empty for a scan or a sheet without dimensions."""
    segs = dimensions.segments(path, page, digest)
    if not segs:
        return []
    found = dimensions.match(tokens, segs)
    if not found:
        return []
    g = paths(path, page, digest)
    dim_spans = [d["span"] for d in found.values()]

    def is_dim(s):   # a dimension's own line is not a tread line
        return any(_seg_point(d, s[:2]) < 0.5 and _seg_point(d, s[2:]) < 0.5 for d in dim_spans)

    out, done, stairs = [], set(), []
    for t in tokens:
        if not STAIR_WORD.search(t.text):
            continue
        c = _mid(t.bbox)
        k = _local_scale(found, tokens, c)
        if not k:
            continue
        mm = PT_MM * k
        reach = REACH / mm
        near = [s for s in g["lines"] if math.dist(c, _mid(s)) <= reach
                and TREAD_LINE[0] <= math.dist(s[:2], s[2:]) * mm <= TREAD_LINE[1] and not is_dim(s)]
        near = _one_line(near, mm)
        for lines, treads in _fans(near, mm):
            key = frozenset(lines)
            if key in done:
                continue
            done.add(key)
            turn = sum(_step(a, b) for a, b in pairwise(lines))
            lens = [math.dist(s[:2], s[2:]) * mm for s in lines]
            names = _labels(_box(lines), tokens, 2000 / mm)
            out.append(((f"[measured from the drawing's lines at 1:{k}, the scale of the dimensions nearby: "
                         f"{len(treads)} tapered stair treads (winders) between {len(lines)} tread lines turning "
                        f"{abs(turn):.0f}° in all, listed in order around the turn; tread depth at the narrow end "
                        f"{' / '.join(_mm(n * mm) for n, _, _ in treads)} mm, at the centre of the tread's width "
                        f"(straight between the midpoints of its two tread lines) {' / '.join(_mm(c_ * mm) for _, _, c_ in treads)} mm, "
                        f"at the wide end (straight between the outer ends) {' / '.join(_mm(w * mm) for _, w, _ in treads)} mm; "
                        f"tread lines {_mm(min(lens))}-{_mm(max(lens))} mm long{names}]"), _box(lines)))
            stairs.append((lines, "tapered treads" + names, k))
        taken = {x for lines, _, _ in stairs for x in lines}
        for lines, gaps in _flights([s for s in near if s not in taken], mm):
            key = frozenset(lines)
            if key in done:
                continue
            done.add(key)
            g_ = sorted(gaps)[len(gaps) // 2]
            box = _box(lines)
            inside = [u for u in tokens if box[0] - g_ <= _mid(u.bbox)[0] <= box[2] + g_ and box[1] - g_ <= _mid(u.bbox)[1] <= box[3] + g_]
            # a flight carries its own UP / DN or riser note; a roof's seams or a section's balusters do not.
            # And a schedule's ruled rows have more words between them than lines
            if not any(STAIR_WORD.search(u.text) for u in inside) or len(inside) > 3 * len(lines):
                continue
            gm = sorted(x * mm for x in gaps)
            L = sum(math.dist(s[:2], s[2:]) for s in lines) / len(lines) * mm
            names = _labels(box, tokens, 2000 / mm)
            out.append(((f"[measured from the drawing's lines at 1:{k}, the scale of the dimensions nearby: straight "
                        f"stair flight drawn as {len(lines)} parallel tread lines {_mm(gm[len(gm) // 2])} mm apart "
                        f"({_mm(gm[0])}-{_mm(gm[-1])}), each {_mm(L)} mm long{names}]"), box))
            stairs.append((lines, "straight flight" + names, k))
    nearest = {}     # door hinge -> (clearance in mm, door, stair lines, what, scale): its nearest stair
    for lines, what, k in stairs:
        mm = PT_MM * k
        for door in _door_swings(g["arcs"], g["lines"], mm):
            hinge, r = door[0], door[1]
            if not any(_seg_point(s, hinge) * mm <= DOOR_NEAR + r * mm for s in lines):
                continue
            d = min(_seg_sector(s, door) for s in lines)
            if d * mm <= DOOR_NEAR and (hinge not in nearest or d * mm < nearest[hinge][0]):
                nearest[hinge] = (d * mm, door, lines, what, k)
    for d_mm, door, lines, what, k in nearest.values():
        hinge, r, _, swing, drawn = door
        mm = PT_MM * k
        box = _union((hinge[0] - r, hinge[1] - r, hinge[0] + r, hinge[1] + r), _box(lines))   # the door and its stair
        reach = "crosses one of its tread lines" if d_mm < 1 else f"comes within {_mm(d_mm)} mm of its nearest tread line"
        out.append(((f"[measured from the drawing's lines at 1:{k}, the scale of the dimensions nearby: door swing, "
                    f"leaf {_mm(r * mm)} mm, drawn open {drawn:.0f}°; swung through {abs(swing):.0f}° from closed, the "
                    f"leaf's path {reach} of the stair ({what}) measured beside it]"), box))
    return out
