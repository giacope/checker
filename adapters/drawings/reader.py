"""Sheets and their text tokens, from PDF pages and images.

A PDF page with a text layer is read with pdfplumber: words with positions, rotated
text included, and CJK text set vertically (one upright glyph under another) joined
into vertical words. A page without usable text, and every image, is rendered and
read by OCR (adapters.drawings.ocr). Coordinates are PDF points from the top-left of
the page as displayed (after the page's /Rotate); an image's pixels are converted to
points at the image's stated resolution, or 72 dpi when it states none.
"""

from __future__ import annotations

import math
import re
import time
from pathlib import Path

import numpy as np

from . import ocr
from .tokens import Sheet, Token

PDF = {".pdf"}
IMAGES = {".png", ".jpg", ".jpeg", ".tif", ".tiff"}
MIN_LAYER_CHARS = 50   # fewer text-layer characters than this: the drawing's text is outlines or raster
CJK = re.compile(r"[\u3000-\u30ff\u3400-\u9fff\uf900-\ufaff\uff00-\uffef]")


def _rel(path: Path, root: Path | None) -> str:
    if root is not None:
        try:
            return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
        except ValueError:
            pass
    return Path(path).name


def _image_dpi(img) -> float:
    dpi = img.info.get("dpi")
    try:
        d = float(dpi[0]) if dpi else 0.0
    except (TypeError, ValueError, IndexError):
        d = 0.0
    return d if d >= 10 else 72.0


def sheets_of(path: Path, root: Path | None = None) -> list[Sheet]:
    """One Sheet per PDF page or image frame, sized in points as displayed."""
    path = Path(path)
    name = _rel(path, root)
    ext = path.suffix.lower()
    if ext in PDF:
        import pypdfium2 as pdfium

        pdf = pdfium.PdfDocument(str(path))
        try:
            return [Sheet(file=name, page=i + 1, width=round(pdf[i].get_width(), 2), height=round(pdf[i].get_height(), 2)) for i in range(len(pdf))]
        finally:
            pdf.close()
    if ext in IMAGES:
        from PIL import Image

        out = []
        with Image.open(path) as img:
            for i in range(getattr(img, "n_frames", 1)):
                img.seek(i)
                k = 72.0 / _image_dpi(img)
                out.append(Sheet(file=name, page=i + 1, width=round(img.width * k, 2), height=round(img.height * k, 2)))
        return out
    raise ValueError(f"not a PDF or image sheet: {path}")


# --- text layer ----------------------------------------------------------------------

def _angle(char: dict) -> int:
    """Reading direction of a text-layer glyph, degrees counter-clockwise on the page as
    displayed, snapped to a quarter turn: 0 left to right, 90 bottom to top, 270 top to bottom."""
    a, b = char["matrix"][0], char["matrix"][1]
    return int(round(math.degrees(math.atan2(b, a)) / 90.0)) % 4 * 90


# pdfplumber word-extraction directions for each reading direction
_DIRS = {0: {}, 90: {"char_dir_rotated": "btt", "line_dir_rotated": "ltr"},
         180: {"char_dir_rotated": "rtl", "line_dir_rotated": "btt"}, 270: {"char_dir_rotated": "ttb", "line_dir_rotated": "rtl"}}


def _vertical_cjk(words: list[dict]) -> list[dict]:
    """Join CJK glyphs set one under another (縦書き) into top-to-bottom words; pdfplumber
    reads each of them as a word of its own."""
    singles = [w for w in words if len(w["text"]) <= 2 and CJK.search(w["text"])]
    rest = [w for w in words if not (len(w["text"]) <= 2 and CJK.search(w["text"]))]
    singles.sort(key=lambda w: (round((w["x0"] + w["x1"]) / 2), w["top"]))
    out, used = [], set()
    for i, w in enumerate(singles):
        if i in used:
            continue
        col = [w]
        used.add(i)
        size = w["bottom"] - w["top"]
        for j in range(i + 1, len(singles)):
            v = singles[j]
            if j in used:
                continue
            last = col[-1]
            if abs((v["x0"] + v["x1"]) / 2 - (last["x0"] + last["x1"]) / 2) <= 0.25 * size and 0 <= v["top"] - last["bottom"] <= 0.35 * size:
                col.append(v)
                used.add(j)
        if len(col) == 1:
            out.append(w)
        else:
            out.append({"text": "".join(c["text"] for c in col), "x0": min(c["x0"] for c in col), "x1": max(c["x1"] for c in col),
                        "top": col[0]["top"], "bottom": col[-1]["bottom"], "angle": 270, "vertical_cjk": True})
    return rest + out


def layer_words(page) -> list[dict]:
    """Words of a pdfplumber page, each with its reading direction."""
    groups: dict[int, list] = {}
    for c in page.chars:
        groups.setdefault(_angle(c), []).append(c)
    words = []
    for angle, chars in groups.items():
        ids = {id(c) for c in chars}
        sub = page.filter(lambda o, ids=ids: o.get("object_type") != "char" or id(o) in ids)
        for w in sub.extract_words(keep_blank_chars=False, x_tolerance=1.5, y_tolerance=2, **_DIRS[angle]):
            w["angle"] = angle
            words.append(w)
    upright = [w for w in words if w["angle"] == 0]
    return [w for w in words if w["angle"] != 0] + _vertical_cjk(upright)


# --- tokens --------------------------------------------------------------------------

def _layer_chars(path: Path, page: int) -> int:
    """Printable characters in the page's text layer. pdfium counts them in milliseconds;
    pdfplumber would parse every vector path of an outlined sheet first (~10 s for a plan)."""
    import pypdfium2 as pdfium

    pdf = pdfium.PdfDocument(str(path))
    try:
        tp = pdf[page - 1].get_textpage()
        return len("".join(tp.get_text_range().split()))
    finally:
        pdf.close()


RENDER_TILE = 768  # px


def _render_region(pg, scale: float, region=None, grayscale: bool = False) -> np.ndarray:
    """Render region (x0, y0, x1, y1 in points, top-left origin; whole page if None) as an
    RGB array, in tiles: on some clinic sheets pdfium takes a minute for a whole page at
    144 dpi and two seconds for the same page in 48 tiles (the cost grows faster than the
    pixel count)."""
    W, H = pg.get_width(), pg.get_height()
    x0, y0, x1, y1 = region or (0.0, 0.0, W, H)
    pw, ph = max(1, round((x1 - x0) * scale)), max(1, round((y1 - y0) * scale))
    out = np.full((ph, pw, 3), 255, np.uint8)
    for ty in range(0, ph, RENDER_TILE):
        for tx in range(0, pw, RENDER_TILE):
            bx, by = min(RENDER_TILE, pw - tx), min(RENDER_TILE, ph - ty)
            # tile in points; pdfium's crop is cut from each side of the page as displayed
            l, t = x0 + tx / scale, y0 + ty / scale
            r, b = l + bx / scale, t + by / scale
            img = pg.render(scale=scale, grayscale=grayscale, crop=(l, H - b, W - r, t)).to_pil().convert("RGB")
            a = np.asarray(img)[:by, :bx]
            out[ty:ty + a.shape[0], tx:tx + a.shape[1]] = a
    return out


def _render_pdf(path: Path, page: int, dpi: float) -> np.ndarray:
    import pypdfium2 as pdfium

    pdf = pdfium.PdfDocument(str(path))
    try:
        return _render_region(pdf[page - 1], dpi / 72.0, grayscale=True)
    finally:
        pdf.close()


def _open_image(path: Path, page: int):
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = None
    img = Image.open(path)
    img.seek(page - 1)
    return img


def tokens_of(path: Path, sheet: Sheet, digest: str | None = None, stats: dict | None = None) -> list[Token]:
    """The sheet's text as Tokens; sets sheet.text to "layer", "ocr" or "none".
    `stats` receives {seconds, ocr_seconds, cached, low_confidence}."""
    path = Path(path)
    t0 = time.perf_counter()
    stats = stats if stats is not None else {}
    tokens: list[Token] = []
    if path.suffix.lower() in PDF:
        if _layer_chars(path, sheet.page) >= MIN_LAYER_CHARS:
            import pdfplumber

            with pdfplumber.open(str(path)) as pdf:
                page = pdf.pages[sheet.page - 1]
                sheet.text = "layer"
                for w in layer_words(page):
                    tokens.append(Token(w["text"], (w["x0"], w["top"], w["x1"], w["bottom"]), sheet, 1.0, float(w["angle"]), "layer",
                                        {"vertical_cjk": True} if w.get("vertical_cjk") else {}))
        if sheet.text != "layer":
            data = ocr.cached(path, sheet.page, ocr.OCR_DPI, lambda: _render_pdf(path, sheet.page, ocr.OCR_DPI), digest)
            scale = 72.0 / ocr.OCR_DPI
            tokens = _ocr_tokens(data, sheet, scale)
            stats.update(ocr_seconds=data["seconds"], cached=data.get("cached", False), timing=data.get("timing"))
    else:
        with _open_image(path, sheet.page) as img:
            src_dpi = _image_dpi(img)
        dpi = min(src_dpi, ocr.OCR_DPI) if src_dpi > 72 else src_dpi

        def image():
            with _open_image(path, sheet.page) as im:
                im = im.convert("RGB")
                if dpi < src_dpi:
                    im = im.resize((round(im.width * dpi / src_dpi), round(im.height * dpi / src_dpi)))
                return np.asarray(im)

        data = ocr.cached(path, sheet.page, int(round(dpi)), image, digest)
        tokens = _ocr_tokens(data, sheet, 72.0 / dpi)
        stats.update(ocr_seconds=data["seconds"], cached=data.get("cached", False), timing=data.get("timing"))
    if not tokens:
        sheet.text = "none"
    stats["seconds"] = round(time.perf_counter() - t0, 2)
    return tokens


def _read_region(b: dict) -> list[float]:
    """The region the recogniser read: the detector's box padded along the reading direction
    as ocr._crop pads it (the detector clips thin end glyphs, the "1" of "137")."""
    x0, y0, x1, y1 = b["bbox"]
    if b["angle"] in (90, 270):
        d = ocr.PAD_X * (x1 - x0)
        return [x0, y0 - d, x1, y1 + d]
    d = ocr.PAD_X * (y1 - y0)
    return [x0 - d, y0, x1 + d, y1]


def _ocr_tokens(data: dict, sheet: Sheet, scale: float) -> list[Token]:
    sheet.text = "ocr" if data["boxes"] else "none"
    return [Token(b["text"], tuple(v * scale for v in _read_region(b)), sheet, float(b["score"]), float(b["angle"]), "ocr")
            for b in data["boxes"]]


# --- render --------------------------------------------------------------------------

def render(path: Path, page: int, bbox=None, dpi: int = 144, pad: float = 36) -> bytes:
    """PNG of the page, or of bbox (points, top-left origin) plus `pad` points, with the
    bbox outlined in red."""
    import io

    from PIL import Image, ImageDraw

    path = Path(path)
    k = dpi / 72.0
    if path.suffix.lower() in PDF:
        import pypdfium2 as pdfium

        pdf = pdfium.PdfDocument(str(path))
        try:
            pg = pdf[page - 1]
            W, H = pg.get_width(), pg.get_height()
            if bbox is None:
                region, origin = None, (0.0, 0.0)
            else:
                x0, y0 = max(0.0, bbox[0] - pad), max(0.0, bbox[1] - pad)
                x1, y1 = min(W, bbox[2] + pad), min(H, bbox[3] + pad)
                region, origin = (x0, y0, x1, y1), (x0, y0)
            img = Image.fromarray(_render_region(pg, k, region))
        finally:
            pdf.close()
    else:
        with _open_image(path, page) as im:
            src = _image_dpi(im)
            s = dpi / src
            im = im.convert("RGB")
            W, H = im.width * 72.0 / src, im.height * 72.0 / src
            if bbox is None:
                origin = (0.0, 0.0)
                img = im.resize((max(1, round(im.width * s)), max(1, round(im.height * s))))
            else:
                x0, y0 = max(0.0, bbox[0] - pad), max(0.0, bbox[1] - pad)
                x1, y1 = min(W, bbox[2] + pad), min(H, bbox[3] + pad)
                p = src / 72.0
                region = im.crop((round(x0 * p), round(y0 * p), round(x1 * p), round(y1 * p)))
                img = region.resize((max(1, round(region.width * s)), max(1, round(region.height * s))))
                origin = (x0, y0)
    if bbox is not None:
        d = ImageDraw.Draw(img)
        r = [(bbox[0] - origin[0]) * k, (bbox[1] - origin[1]) * k, (bbox[2] - origin[0]) * k, (bbox[3] - origin[1]) * k]
        d.rectangle([r[0] - 2, r[1] - 2, r[2] + 2, r[3] + 2], outline=(220, 0, 0), width=max(2, round(k)))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
