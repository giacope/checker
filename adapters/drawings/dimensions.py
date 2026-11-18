"""Dimensions on a vector drawing: a number standing on a drawn line whose length, at the sheet's scale, is that
number. Matching the two says the number is a dimension (not a note, a level or a count), which way it runs, and
what it spans: the text at the line's two ends (spot levels, gridlines, other labels) names what it measures, so
\"8480\" on a ramp elevation becomes the going between levels 29.80 and 30.50.

A sheet's scales are not read from its title block: every number is tried against the lines beside it, the ratios
that land on a standard drawing scale are counted, and only scales several numbers agree on are kept, so a number
that happens to fit a stray line at some scale is not taken for a dimension.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from itertools import pairwise
from pathlib import Path

from . import ocr
from .tokens import Token

CACHE_VERSION = 1
CACHE_DIR = ocr.CACHE_DIR.parent / "dims"
PT_MM = 25.4 / 72
SCALES = (1, 2, 4, 5, 8, 10, 12, 16, 20, 24, 25, 32, 40, 48, 50, 64, 75, 96, 100, 120, 125, 150, 192, 200,
          240, 250, 384, 480, 500, 1000, 1250, 2500)   # metric and imperial (1/4" = 1'-0" is 1:48)
TOLERANCE = 0.012      # the line's length at the scale may differ from the number by this fraction
MIN_SUPPORT = 3        # numbers that must agree on a scale before it is taken as one of the sheet's
NEAR = 1.3             # a dimension line lies within this many text heights of its number
ENDS = 3.0             # and the labels of what it spans within this many text heights of its ends
LABELS = 2             # nearest labels named at each end: the nearest is not always the one that names the end
MIN_SEGMENT = 3.0      # pt
AXIS = 0.02            # slope below which a segment is horizontal or vertical
MM = re.compile(r"^\d{2,6}$")
FT_IN = re.compile(r"^(\d{1,4})['’′]\s*-?\s*(\d{1,2})?(?:\s*(\d)/(\d{1,2}))?[\"”″]?$")   # 12'-6", 12’-6”, 12′ 6 1/2″
IN = re.compile(r"^()(\d{1,3})(?:\s*(\d)/(\d{1,2}))?[\"”″]$")                            # 36", 10 1/2″: inches alone


def value_mm(text: str) -> float | None:
    """A dimension's value in millimetres: a whole number of millimetres, or feet and inches (12'-6\", 36")."""
    t = text.strip().rstrip(".")
    if MM.match(t):
        return float(t)
    m = FT_IN.match(t) or IN.match(t)
    if m:
        inches = int(m[1] or 0) * 12 + int(m[2] or 0) + (int(m[3]) / int(m[4]) if m[3] and int(m[4]) else 0)
        return inches * 25.4 if inches else None
    return None


def segments(path: Path, page: int, digest: str | None = None) -> list[tuple[float, float, float, float]]:
    """The page's horizontal and vertical straight segments, (x0, y0, x1, y1) in points from the top left with
    x0 <= x1 and y0 <= y1, cached by the file's hash: pdfplumber takes seconds to parse a plan's paths."""
    digest = digest or ocr.file_hash(path)
    dest = CACHE_DIR / f"{digest}-p{page}.json"
    try:
        data = json.loads(dest.read_text())
        if data.get("version") == CACHE_VERSION:
            return [tuple(s) for s in data["segments"]]
    except (OSError, ValueError):
        pass
    from .reader import _pdf

    pg = _pdf(Path(path)).plumber_page(page)
    out = []
    if pg is not None:
        for obj in list(pg.lines) + list(pg.curves) + list(pg.rects):
            pts = obj.get("pts") or []
            if obj.get("object_type") == "rect":
                x0, y0, x1, y1 = obj["x0"], obj["top"], obj["x1"], obj["bottom"]
                pts = [(x0, y0), (x1, y0), (x1, y1), (x0, y1), (x0, y0)]
            for (ax, ay), (bx, by) in pairwise(pts):
                dx, dy = abs(bx - ax), abs(by - ay)
                if max(dx, dy) >= MIN_SEGMENT and min(dx, dy) <= AXIS * max(dx, dy):
                    out.append(tuple(round(v, 2) for v in (min(ax, bx), min(ay, by), max(ax, bx), max(ay, by))))
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps({"version": CACHE_VERSION, "segments": sorted(set(out))}))
    tmp.replace(dest)
    return sorted(set(out))


def _spans(t: Token, segs: list, turned: bool, h: float) -> list[tuple[float, tuple]]:
    """(distance from t, span) for each line t's number may stand on: one segment running past its middle (the line
    drawn under or over the text), or two in line that stop either side of it (the line broken for the text)."""
    x0, y0, x1, y1 = t.bbox
    # along: the axis the dimension runs on; across: the other
    lo, hi, mid = (y0, y1, (y0 + y1) / 2) if turned else (x0, x1, (x0 + x1) / 2)
    c = (x0 + x1) / 2 if turned else (y0 + y1) / 2
    half = ((x1 - x0) if turned else (y1 - y0)) / 2
    on = []
    for s in segs:
        a0, a1, b0, b1 = (s[1], s[3], s[0], s[2]) if turned else (s[0], s[2], s[1], s[3])
        if b1 - b0 > AXIS * (a1 - a0):
            continue     # runs the other way
        dist = abs(b0 - c) - half
        if dist <= NEAR * h:
            on.append((a0, a1, b0, max(dist, 0.0), s))
    out = [(d, s) for a0, a1, _, d, s in on if a0 <= mid <= a1]
    left = [x for x in on if lo - h <= x[1] <= mid]
    right = [x for x in on if mid <= x[0] <= hi + h]
    for la0, _, lb, ld, ls in left:
        for _, ra1, rb, rd, rs in right:
            if abs(lb - rb) <= 0.3:
                span = (ls[0], ls[1], rs[2], rs[3])   # from the left (or top) piece's start to the other's end
                out.append((max(ld, rd), span))
    return out


def _candidates(t: Token, segs: list) -> list[tuple[float, float, tuple, int]]:
    """(relative error, distance, span, scale) for each standard scale a line t's number stands on fits."""
    v = value_mm(t.text)
    if v is None:
        return []
    x0, y0, x1, y1 = t.bbox
    turned = abs(((t.angle or 0) + 45) % 180 - 45) > 45     # read bottom to top or top to bottom: a vertical dimension
    h = (x1 - x0) if turned else (y1 - y0)
    out = []
    for dist, s in _spans(t, segs, turned, h):
        length = (s[3] - s[1]) if turned else (s[2] - s[0])
        if length < MIN_SEGMENT:
            continue
        ratio = v / (length * PT_MM)
        for k in SCALES:
            err = abs(ratio - k) / k
            if err <= TOLERANCE:
                out.append((err, dist, s, k))
    return sorted(out, key=lambda c: (c[0] > TOLERANCE / 3, c[1], c[0]))


def match(tokens: list[Token], segs: list) -> dict[int, dict]:
    """{token index: {scale, vertical, span (segment), ends: [[labels near its first end], [near its second]]}}
    (left and right, or top and bottom), nearest first for every token that is a
    dimension at one of the sheet's scales."""
    cands = {i: _candidates(t, segs) for i, t in enumerate(tokens)}
    support = Counter(k for c in cands.values() for k in {c_[3] for c_ in c})
    scales = {k for k, n in support.items() if n >= MIN_SUPPORT}
    found = {}
    for i, c in cands.items():
        c = [x for x in c if x[3] in scales]
        if c:   # of the lines it fits, one at the scale most of the sheet's numbers agree on
            _, _, s, k = max(c, key=lambda x: support[x[3]])
            found[i] = {"scale": k, "vertical": s[2] - s[0] < s[3] - s[1], "span": s}
    for i, d in found.items():
        s, t = d["span"], tokens[i]
        h = min(t.bbox[2] - t.bbox[0], t.bbox[3] - t.bbox[1])
        ends = []
        for ex, ey in ((s[0], s[1]), (s[2], s[3])):
            near = []
            for j, u in enumerate(tokens):
                if j == i or j in found or not u.text.strip():
                    continue
                bx0, by0, bx1, by1 = u.bbox
                dx, dy = max(bx0 - ex, 0, ex - bx1), max(by0 - ey, 0, ey - by1)
                dd = (dx * dx + dy * dy) ** 0.5
                if dd <= ENDS * h:
                    near.append((dd, u.text.strip()))
            ends.append([x for _, x in sorted(near)[:LABELS]])
        d["ends"] = ends
    return found


def describe(d: dict) -> str:
    """What a sheet line shows after a dimension's number."""
    sides = ("top", "bottom") if d["vertical"] else ("left", "right")
    where = "".join(f"; near its {side} end: {' / '.join(labels)}" for side, labels in zip(sides, d["ends"]) if labels)
    return f"[{'vertical' if d['vertical'] else 'horizontal'} dimension line at 1:{d['scale']}{where}]"


def annotate(path: Path, tokens: list[Token], page: int, digest: str | None = None) -> list[Token]:
    """tokens with each dimension's number followed by what describe() says of it; unchanged when the page has no
    vector lines (a scan) or no dimensions are found."""
    segs = segments(path, page, digest)
    if not segs:
        return tokens
    found = match(tokens, segs)
    return [Token(f"{t.text} {describe(found[i])}", t.bbox, t.sheet, t.confidence, t.angle, t.source, t.extra)
            if i in found else t for i, t in enumerate(tokens)]
