"""OCR of drawing sheets with no usable text layer (vector sheets whose text is drawn as
outlines, and scans), with RapidOCR's PP-OCRv4 detection and recognition models.

A sheet is rendered at OCR_DPI and cut into overlapping tiles, so the detector sees
drafting text at its printed scale. Each detected box is recognised upright and, if
that reads poorly, turned 180 degrees; a tall box is recognised turned both ways a
quarter turn. Boxes read twice where tiles overlap are merged. The detector breaks
vertical text into pieces, so every column of vertical pieces is cut out, turned to
read left to right, stacked on one canvas, and read again as whole lines (the rotated
pass). Results are cached by file content under ~/.cache/normir/ocr/.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import numpy as np

OCR_DPI = 144
TILE = 1800        # px per tile side; ~2.6 s of detection each on 4 cores
OVERLAP = 300      # px; longer lines cut by a tile edge are joined where the readings overlap
RETRY_BELOW = 0.9  # recognition score under which a box is also tried turned 180 degrees
PAD_X, PAD_Y = 0.25, 0.1  # crop padding, as a fraction of the box height: the detector clips thin end glyphs ("137" -> "37")
CANVAS = 1800      # px; side of the canvas the rotated pass stacks vertical columns on
CACHE_VERSION = 8
CACHE_DIR = Path(os.environ.get("NORMIR_CACHE", Path.home() / ".cache" / "normir")) / "ocr"

_engine = None


def engine():
    global _engine
    if _engine is None:
        from rapidocr_onnxruntime import RapidOCR

        # onnxruntime's default thread pool is ~1.5x slower here than one thread per core.
        _engine = RapidOCR(intra_op_num_threads=os.cpu_count() or 1, inter_op_num_threads=1)
    return _engine


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cache_path(digest: str, page: int, dpi: int) -> Path:
    return CACHE_DIR / f"{digest}-p{page}-{dpi}.json"


def cached(path: Path, page: int, dpi: int, image, digest: str | None = None) -> dict:
    """OCR of one page, from the cache when present. `image` is a callable returning the
    page as an RGB array at `dpi`. Returns {boxes: [{text, bbox (px), score, angle}], seconds, cached}."""
    digest = digest or file_hash(path)
    dest = cache_path(digest, page, dpi)
    if dest.exists():
        try:
            data = json.loads(dest.read_text())
            if data.get("version") == CACHE_VERSION:
                data["cached"] = True
                return data
        except (OSError, ValueError):
            pass
    t0 = time.perf_counter()
    img = image()
    boxes = read_image(img)
    data = {"version": CACHE_VERSION, "file": Path(path).name, "page": page, "dpi": dpi,
            "size": [int(img.shape[1]), int(img.shape[0])], "seconds": round(time.perf_counter() - t0, 2),
            "timing": {k: round(v, 2) for k, v in TIMING.items()}, "boxes": boxes}
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False))
    tmp.replace(dest)
    data["cached"] = False
    return data


# --- recognition ---------------------------------------------------------------------

def _crop(img: np.ndarray, quad: np.ndarray) -> np.ndarray:
    """The quad's region, straightened, padded along its own axes."""
    import cv2

    q = quad.astype(np.float32)
    ux, uy = q[1] - q[0], q[3] - q[0]
    w, h = float(np.linalg.norm(ux)), float(np.linalg.norm(uy))
    if w < 1 or h < 1:
        return np.full((4, 4, 3), 255, np.uint8)
    short = min(w, h)
    # pad along the reading direction (the long side) by PAD_X, across it by PAD_Y
    px, py = (PAD_X, PAD_Y) if w >= h else (PAD_Y, PAD_X)
    dx, dy = ux / w * short * px, uy / h * short * py
    q = np.array([q[0] - dx - dy, q[1] + dx - dy, q[2] + dx + dy, q[3] - dx + dy], dtype=np.float32)
    W, H = int(round(w + 2 * short * px)), int(round(h + 2 * short * py))
    dst = np.array([[0, 0], [W, 0], [W, H], [0, H]], dtype=np.float32)
    m = cv2.getPerspectiveTransform(q, dst)
    return cv2.warpPerspective(img, m, (W, H), borderMode=cv2.BORDER_CONSTANT, borderValue=(255, 255, 255), flags=cv2.INTER_CUBIC)


TIMING: dict[str, float] = {}


def _timed(stage: str, t0: float) -> None:
    TIMING[stage] = TIMING.get(stage, 0.0) + time.perf_counter() - t0


def _recognise(crops: list[np.ndarray]) -> list[tuple[str, float]]:
    if not crops:
        return []
    t0 = time.perf_counter()
    res, _ = engine().text_rec(crops)
    _timed("recognise", t0)
    return [(str(t), float(s)) for t, s in res]


def _read_boxes(img: np.ndarray, quads) -> list[dict]:
    """Recognise each detected box in the orientation that reads best.
    angle: 0 upright, 90 reading bottom to top, 180 upside down, 270 reading top to bottom."""
    crops, which, tall = [], [], []
    for i, q in enumerate(quads):
        c = _crop(img, q)
        h, w = c.shape[:2]
        if h >= 1.5 * w:
            tall.append(len(crops))
            crops.append(np.ascontiguousarray(np.rot90(c, -1)))
            which.append((i, 90))
        else:
            crops.append(c)
            which.append((i, 0))
    if tall:
        # The direction classifier (far cheaper than recognition) says whether a tall box
        # reads bottom to top or top to bottom.
        t0 = time.perf_counter()
        _, cls, _ = engine().text_cls([crops[k] for k in tall])
        _timed("classify", t0)
        for k, (label, score) in zip(tall, cls):
            if label == "180" and score >= 0.9:
                crops[k] = np.ascontiguousarray(np.rot90(crops[k], 2))
                which[k] = (which[k][0], 270)
    best: dict[int, tuple[str, float, int]] = {}
    for (i, angle), (text, score) in zip(which, _recognise(crops)):
        if i not in best or score > best[i][1]:
            best[i] = (text, score, angle)
    retry = [i for i, (t, s, a) in best.items() if a == 0 and s < RETRY_BELOW]
    if retry:
        # Only boxes the direction classifier also calls upside down are read again turned:
        # on its own the classifier is wrong too often on drafting text to trust.
        t0 = time.perf_counter()
        _, cls, _ = engine().text_cls([_crop(img, quads[i]) for i in retry])
        _timed("classify", t0)
        retry = [i for i, (label, score) in zip(retry, cls) if label == "180" and score >= 0.9]
    if retry:
        flipped = [np.ascontiguousarray(np.rot90(_crop(img, quads[i]), 2)) for i in retry]
        for i, (text, score) in zip(retry, _recognise(flipped)):
            if score > best[i][1]:
                best[i] = (text, score, 180)
    out = []
    for i, q in enumerate(quads):
        text, score, angle = best[i]
        text = text.strip()
        if text:
            out.append({"text": text, "score": round(score, 3), "angle": angle,
                        "bbox": [float(q[:, 0].min()), float(q[:, 1].min()), float(q[:, 0].max()), float(q[:, 1].max())]})
    return out


def _detect(img: np.ndarray):
    t0 = time.perf_counter()
    boxes, _ = engine().text_det(img)
    _timed("detect", t0)
    return [] if boxes is None else list(boxes)


def _tiles(size: int) -> list[int]:
    if size <= TILE:
        return [0]
    step = TILE - OVERLAP
    return sorted(set(list(range(0, size - TILE, step)) + [size - TILE]))


def _area(b) -> float:
    return max(0.0, b[2] - b[0]) * max(0.0, b[3] - b[1])


def _inter(a, b) -> float:
    return _area((max(a[0], b[0]), max(a[1], b[1]), min(a[2], b[2]), min(a[3], b[3])))


def _join(a: str, b: str) -> str | None:
    """Join two readings of a line cut by a tile edge, where a's end repeats b's start."""
    for k in range(min(len(a), len(b)), 2, -1):
        if a.endswith(b[:k]):
            return a + b[k:]
    return None


def _dedupe(boxes: list[dict]) -> list[dict]:
    """Merge boxes read twice where tiles overlap. A box clear of its tile's edges wins over
    one an edge cut; two cut pieces of one long line are joined where their text overlaps."""
    order = sorted(boxes, key=lambda b: (b["edge"], -_area(b["bbox"]), -b["score"]))
    kept: list[dict] = []
    for b in order:
        dup = next((k for k in kept if _inter(b["bbox"], k["bbox"]) > 0.5 * min(_area(b["bbox"]), _area(k["bbox"]))), None)
        if dup is None:
            kept.append(b)
            continue
        if b["edge"] and dup["edge"] and b["angle"] == dup["angle"]:
            first, second = sorted((dup, b), key=lambda x: x["bbox"][0] + x["bbox"][1])
            if b["angle"] in (90, 180):
                first, second = second, first
            joined = _join(first["text"], second["text"])
            if joined and len(joined) > len(dup["text"]):
                x, y = dup["bbox"], b["bbox"]
                dup["bbox"] = [min(x[0], y[0]), min(x[1], y[1]), max(x[2], y[2]), max(x[3], y[3])]
                dup["text"], dup["score"] = joined, min(dup["score"], b["score"])
    return kept


def _vertical_columns(boxes: list[dict]) -> list[list[float]]:
    """Regions holding columns of vertical text pieces."""
    groups: list[list[float]] = []
    for v in sorted((b["bbox"] for b in boxes if b["angle"] in (90, 270)), key=lambda b: (b[0], b[1])):
        w = v[2] - v[0]
        for g in groups:
            xo = min(g[2], v[2]) - max(g[0], v[0])
            gap = max(g[1], v[1]) - min(g[3], v[3])
            if xo > 0.5 * min(w, g[2] - g[0]) and gap < 1.5 * w:
                g[:] = [min(g[0], v[0]), min(g[1], v[1]), max(g[2], v[2]), max(g[3], v[3])]
                break
        else:
            groups.append(list(v))
    return groups


def _rotated_pass(img: np.ndarray, boxes: list[dict]) -> list[dict]:
    """Read every column of vertical text again, turned to read left to right, so the
    detector sees whole lines; the whole lines replace the pieces they cover."""
    H, W = img.shape[:2]
    strips = []  # (turned strip, angle, x0, y0, group)
    for g in _vertical_columns(boxes):
        pieces = [b for b in boxes if b["angle"] in (90, 270) and _inter(b["bbox"], g) > 0.5 * _area(b["bbox"])]
        angle = 90 if sum(b["angle"] == 90 for b in pieces) >= sum(b["angle"] == 270 for b in pieces) else 270
        # generous context: a strip cut close to the text loses the detector its line ends
        padx, pady = 1.5 * (g[2] - g[0]) + 6, 2.0 * (g[2] - g[0]) + 12
        x0, y0, x1, y1 = int(max(0, g[0] - padx)), int(max(0, g[1] - pady)), int(min(W, g[2] + padx)), int(min(H, g[3] + pady))
        region = img[y0:y1, x0:x1]
        if region.size == 0 or region.shape[0] > CANVAS - 20:
            continue
        strips.append((np.ascontiguousarray(np.rot90(region, -1 if angle == 90 else 1)), angle, x0, y0, g, pieces))
    # Shelf-pack the turned strips onto canvases, one detector run per canvas, with wide
    # blank gaps: 20 px apart, the detector joined text across neighbouring strips.
    GAP_X, GAP_Y = 160, 60
    canvases, place, cx, cy, shelf, used = [], [], 0, 0, 0, {}
    for s in strips:
        h, w = s[0].shape[:2]
        if w > CANVAS - 40:
            place.append((-1, 0, 0, w, h))
            continue
        if canvases and cx + w + 20 > CANVAS:
            cx, cy, shelf = 20, cy + shelf + GAP_Y, 0
        if not canvases or cy + h + 20 > CANVAS:
            canvases.append(np.full((CANVAS, CANVAS, 3), 255, np.uint8))
            cx, cy, shelf = 20, 20, 0
        canvases[-1][cy:cy + h, cx:cx + w] = s[0]
        place.append((len(canvases) - 1, cx, cy, w, h))
        cx, shelf = cx + w + GAP_X, max(shelf, h)
        used[len(canvases) - 1] = cy + shelf + 20
    canvases = [c[:max(used[i], 736)] for i, c in enumerate(canvases)]  # the detector upscales below 736 px
    found_by_strip: dict[int, list[dict]] = {}
    for ci, canvas in enumerate(canvases):
        for r in _read_boxes(canvas, _detect(canvas)):
            a, b_, c, d = r["bbox"]
            if (d - b_) > (c - a):  # text that is upright on the sheet, seen sideways here
                continue
            mx, my = (a + c) / 2, (b_ + d) / 2
            si = next((i for i, (k, px, py, w, h) in enumerate(place) if k == ci and px <= mx <= px + w and py <= my <= py + h), None)
            if si is None:
                continue
            _, px, py, w, h = place[si]
            a, c, b_, d = a - px, c - px, b_ - py, d - py
            if a < 3 or c > w - 3 or b_ < 1 or d > h - 1:  # cut by the strip's edge: another strip holds it whole
                continue
            strip, angle, x0, y0, g, pieces = strips[si]
            th, tw = strip.shape[:2]   # turned strip: tw = region height, th = region width
            if angle == 90:  # turned clockwise: strip (u, v) <- region (v, tw - u)
                bb = [x0 + b_, y0 + (tw - c), x0 + d, y0 + (tw - a)]
            else:            # turned anticlockwise: strip (u, v) <- region (th - v, u)
                bb = [x0 + (th - d), y0 + a, x0 + (th - b_), y0 + c]
            found_by_strip.setdefault(si, []).append({**r, "bbox": bb, "angle": (angle + r["angle"]) % 360, "edge": False})
    accepted = []
    for si, found in found_by_strip.items():
        pieces = strips[si][5]
        # keep the whole lines only if they read at least as much, about as confidently
        if sum(len(f["text"]) for f in found) < 0.8 * sum(len(p["text"]) for p in pieces):
            continue
        if np.mean([f["score"] for f in found]) < np.mean([p["score"] for p in pieces]) - 0.05:
            continue
        accepted += found
    accepted = _dedupe(accepted)  # neighbouring strips overlap and read some lines twice
    drop = {id(p) for p in boxes if p["angle"] in (90, 270) and any(_inter(p["bbox"], f["bbox"]) > 0.5 * _area(p["bbox"]) for f in accepted)}
    return [b for b in boxes if id(b) not in drop] + accepted


def read_image(img: np.ndarray) -> list[dict]:
    """OCR an RGB page image: tiles, orientation, de-duplication, rotated pass. Boxes in px."""
    H, W = img.shape[:2]
    TIMING.clear()
    boxes: list[dict] = []
    for ty in _tiles(H):
        for tx in _tiles(W):
            tile = np.ascontiguousarray(img[ty:ty + TILE, tx:tx + TILE])
            if tile.min() > 160:  # no ink
                continue
            th, tw = tile.shape[:2]
            for b in _read_boxes(tile, _detect(tile)):
                x0, y0, x1, y1 = b["bbox"]
                b["edge"] = bool((x0 < 3 and tx > 0) or (y0 < 3 and ty > 0) or (x1 > tw - 3 and tx + tw < W) or (y1 > th - 3 and ty + th < H))
                b["bbox"] = [x0 + tx, y0 + ty, x1 + tx, y1 + ty]
                boxes.append(b)
    t0 = time.perf_counter()
    boxes = _rotated_pass(img, _dedupe(boxes))
    _timed("rotated pass", t0)
    return [{"text": b["text"], "score": b["score"], "angle": b["angle"], "bbox": [round(v, 1) for v in b["bbox"]]}
            for b in sorted(boxes, key=lambda b: (round(b["bbox"][1]), b["bbox"][0]))]
