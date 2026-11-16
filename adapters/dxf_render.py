"""Render a DXF layout, or a region of it, to PNG: ezdxf.addons.drawing onto Pillow.

ezdxf's Frontend resolves layers, colours, linetypes, blocks, hatches and text into
2D primitives; its Recorder backend keeps them, and this module replays them onto a
Pillow image. Pillow is already a dependency (no matplotlib needed). The recording
of a layout is cached, so successive crops of one file only redraw what they show.
"""

from __future__ import annotations

import io
from functools import lru_cache
from pathlib import Path

import ezdxf
from ezdxf.addons.drawing import Frontend, RenderContext
from ezdxf.addons.drawing.config import BackgroundPolicy, ColorPolicy, Configuration, LineweightPolicy
from ezdxf.addons.drawing.recorder import FilledPathsRecord, PathRecord, PointsRecord, Recorder, SolidLinesRecord
from ezdxf.math import BoundingBox2d
from PIL import Image, ImageChops, ImageDraw

BBox = tuple[float, float, float, float]


# Entities some exporters write without their subclass markers (group code 100), which ezdxf requires for them.
SUBCLASS = {"LWPOLYLINE": "AcDbPolyline"}
COMMON_CODES = {6, 8, 48, 60, 62, 67, 92, 160, 284, 310, 347, 370, 390, 410, 420, 430, 440}


def read(path: Path):
    """The ezdxf document. A damaged file goes to ezdxf's recover reader; a file neither reads (binary DXF, or
    entities written without their subclass markers) is re-read tag by tag, with the missing markers added."""
    try:
        return ezdxf.readfile(str(path))
    except ezdxf.DXFStructureError:
        from ezdxf import recover
        try:
            doc, _ = recover.readfile(str(path))
            return doc
        except ezdxf.DXFStructureError:
            return _repaired(Path(path).read_bytes())


def _repaired(data: bytes):
    import io

    from ezdxf.lldxf.tagger import ascii_tags_loader, binary_tags_loader
    from ezdxf.lldxf.types import DXFTag
    if data.startswith(b"AutoCAD Binary DXF"):
        tags = list(binary_tags_loader(data))
    else:
        tags = list(ascii_tags_loader(io.StringIO(data.decode("utf-8", "replace"))))
    out, i = [], 0
    while i < len(tags):
        t = tags[i]
        j = i + 1
        while j < len(tags) and tags[j].code != 0:
            j += 1
        body = tags[i + 1:j]
        if t.code == 0 and t.value in SUBCLASS and not any(x.code == 100 for x in body):
            head = [x for x in body if x.code in (5, 102, 330)]
            common = [x for x in body if x.code in COMMON_CODES]
            rest = [x for x in body if x.code not in COMMON_CODES and x.code not in (5, 102, 330)]
            body = head + [DXFTag(100, "AcDbEntity")] + common + [DXFTag(100, SUBCLASS[t.value])] + rest
        out += [t] + body
        i = j
    return ezdxf.read(io.StringIO("".join(t.dxfstr() for t in out)))


def layout_of(doc, name: str):
    lay = doc.layouts.get(name) if name != "Model" else doc.modelspace()
    if lay is None:
        raise KeyError(f"no layout {name!r}")
    return lay


@lru_cache(maxsize=4)
def _recording(path: str, mtime: float, layout: str):
    doc = read(Path(path))
    cfg = Configuration(background_policy=BackgroundPolicy.WHITE, color_policy=ColorPolicy.MONOCHROME_LIGHT_BG,
                        lineweight_policy=LineweightPolicy.ABSOLUTE)
    rec = Recorder()
    Frontend(RenderContext(doc), rec, config=cfg).draw_layout(layout_of(doc, layout), finalize=True)
    player = rec.player()
    items = []
    for record, props in player.recordings():
        box = record.bbox()
        if box.has_data:
            items.append((record, props, box))
    return items, player.bbox()


def _flat(path, tol: float) -> list[list[tuple[float, float]]]:
    out = []
    for sub in (path.sub_paths() if path.has_sub_paths else [path]):
        pts = [(v.x, v.y) for v in sub.flattening(tol)]
        if len(pts) >= 2:
            out.append(pts)
    return out


def render(path: Path, layout: str, bbox: BBox | None = None, px: int = 1600, pad: float = 1.0) -> bytes:
    """PNG of `layout` (the whole of it, or the region around `bbox`, in drawing units, y up)
    with `bbox` outlined in red. `pad` is the margin on each side of `bbox` as a fraction of its larger
    side, so the default shows the region and its surroundings at three times its size."""
    p = Path(path)
    items, extents = _recording(str(p.resolve()), p.stat().st_mtime, layout)
    if not extents.has_data:
        raise ValueError(f"layout {layout!r} is empty")
    ex0, ey0 = extents.extmin.x, extents.extmin.y
    ex1, ey1 = extents.extmax.x, extents.extmax.y
    if bbox is None:
        vx0, vy0, vx1, vy1 = ex0, ey0, ex1, ey1
    else:
        x0, y0, x1, y1 = bbox
        side = max(x1 - x0, y1 - y0, 1e-6 * max(ex1 - ex0, ey1 - ey0, 1.0))
        cx, cy, half = (x0 + x1) / 2, (y0 + y1) / 2, side * (0.5 + pad)
        hw, hh = half, max(half * 0.66, (y1 - y0) / 2 + side * pad)
        vx0, vy0, vx1, vy1 = cx - hw, cy - hh, cx + hw, cy + hh
    w, h = max(vx1 - vx0, 1e-9), max(vy1 - vy0, 1e-9)
    scale = px / max(w, h)
    W, H = max(1, round(w * scale)), max(1, round(h * scale))
    img = Image.new("RGB", (W, H), "white")
    draw = ImageDraw.Draw(img)
    view = BoundingBox2d([(vx0, vy0), (vx1, vy1)])
    tol = 0.5 / scale  # curve flattening to half a pixel

    def to_px(pts):
        return [((x - vx0) * scale, (vy1 - y) * scale) for x, y in pts]

    for record, props, box in items:
        if not view.has_intersection(box) and not view.inside(box.center):
            continue
        color = props.color[:7]
        width = 1 if props.lineweight < 0.4 else 2
        if isinstance(record, PointsRecord):
            pts = to_px([(v.x, v.y) for v in record.points.vertices()])
            if len(pts) > 2:
                draw.polygon(pts, fill=color)
            elif len(pts) == 2:
                draw.line(pts, fill=color, width=width)
            elif pts:
                draw.point(pts, fill=color)
        elif isinstance(record, SolidLinesRecord):
            v = record.lines.vertices()
            for a, b in zip(v[0::2], v[1::2]):
                draw.line(to_px([(a.x, a.y), (b.x, b.y)]), fill=color, width=width)
        elif isinstance(record, PathRecord):
            for pts in _flat(record.path, tol):
                draw.line(to_px(pts), fill=color, width=width)
        elif isinstance(record, FilledPathsRecord):
            polys = [to_px(pts) for path in record.paths for pts in _flat(path, tol) if len(pts) >= 3]
            if len(polys) == 1:
                draw.polygon(polys[0], fill=color)
            elif polys:
                # even-odd filling (holes in glyphs and hatches) on a mask the size of the record
                xs = [x for poly in polys for x, _ in poly]
                ys = [y for poly in polys for _, y in poly]
                mx0, my0 = max(int(min(xs)) - 1, 0), max(int(min(ys)) - 1, 0)
                mx1, my1 = min(int(max(xs)) + 2, W), min(int(max(ys)) + 2, H)
                if mx1 <= mx0 or my1 <= my0:
                    continue
                mask = Image.new("1", (mx1 - mx0, my1 - my0), 0)
                for poly in polys:
                    one = Image.new("1", mask.size, 0)
                    ImageDraw.Draw(one).polygon([(x - mx0, y - my0) for x, y in poly], fill=1)
                    mask = ImageChops.logical_xor(mask, one)
                img.paste(color, (mx0, my0, mx1, my1), mask)
    if bbox is not None:
        x0, y0, x1, y1 = bbox
        (a, b), (c, d) = to_px([(x0, y1), (x1, y0)])
        draw.rectangle([a - 3, b - 3, c + 3, d + 3], outline=(220, 0, 0), width=3)
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return buf.getvalue()
