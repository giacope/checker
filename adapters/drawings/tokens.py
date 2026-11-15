"""Shared types for drawing readers: a sheet, the text tokens on it, and locators.

Every reader (PDF text layer, OCR of outlined or scanned sheets, DXF) turns a sheet
into Tokens; adapters.drawings.annotations reads facts from Tokens, whatever produced
them. Locators follow vocab/bim.yaml:

    <file>#page=<n>&bbox=<x0>,<y0>,<x1>,<y1>       PDF or image page, points from top-left
    <file>#layout=<name>&bbox=<x0>,<y0>,<x1>,<y1>  DXF layout, drawing units, y up
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

BBox = tuple[float, float, float, float]


@dataclass
class Sheet:
    file: str                 # path relative to the upload, as it appears in locators
    page: int | None = None   # PDF/image page, from 1
    layout: str | None = None  # DXF layout name
    width: float = 0.0        # page size in points (PDF) or drawing extents (DXF)
    height: float = 0.0
    number: str | None = None  # sheet number from the title block, e.g. "A18-1"
    title: str | None = None
    text: str = "none"        # where the tokens came from: "layer", "ocr", "dxf", or "none"
    units_per_metre: float | None = None  # DXF: drawing units in one metre; PDF: points per metre at the sheet's scale, when known

    def label(self) -> str:
        where = f"p{self.page}" if self.page else (self.layout or "")
        return f"{self.number} ({self.file} {where})" if self.number else f"{self.file} {where}".strip()


@dataclass
class Token:
    text: str
    bbox: BBox
    sheet: Sheet
    confidence: float = 1.0
    angle: float = 0.0        # text direction in degrees, 0 = left to right
    source: str = "layer"     # "layer", "ocr", or "dxf"
    extra: dict = field(default_factory=dict)  # e.g. a DXF DIMENSION's measured value

    @property
    def at(self) -> str:
        return locator(self.sheet, self.bbox)


def locator(sheet: Sheet, bbox: BBox) -> str:
    x0, y0, x1, y1 = (round(v, 1) for v in bbox)
    where = f"page={sheet.page}" if sheet.page else f"layout={sheet.layout}"
    return f"{sheet.file}#{where}&bbox={x0:g},{y0:g},{x1:g},{y1:g}"


LOCATOR = re.compile(r"^(?P<file>.+)#(?:page=(?P<page>\d+)|layout=(?P<layout>[^&]+))&bbox=(?P<bbox>[-\d.,]+)$")


def parse_locator(at: str) -> dict | None:
    """'plans.pdf#page=3&bbox=1,2,3,4' -> {file, page, layout, bbox}; None for other locators."""
    m = LOCATOR.match(str(at))
    if not m:
        return None
    bbox = tuple(float(v) for v in m["bbox"].split(","))
    if len(bbox) != 4:
        return None
    return {"file": m["file"], "page": int(m["page"]) if m["page"] else None, "layout": m["layout"], "bbox": bbox}
