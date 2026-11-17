"""Drawing readers: PDF and image sheets (text layer or OCR) and DXF, into evidence in vocab/bim.yaml terms.

    uv run python -m adapters.drawings <sheet.pdf|png|jpg|tif ...> [--root DIR] -o out.yaml

analyse() reads every sheet's text (adapters.drawings.reader: pdfplumber for a text
layer, RapidOCR otherwise, cached), reads facts from it (adapters.drawings.annotations),
and returns one evidence document. render() draws the region an observation cites.
"""


import time
from collections import Counter
from pathlib import Path

from . import annotations, ocr
from .reader import IMAGES, PDF, render, sheets_of, tokens_of
from .tokens import Sheet, Token, locator, parse_locator

VERSION = "0.1.0"
SKIPPED_LISTED = 200  # skipped readings listed one by one in the source entry; the rest are counted
ELEMENT_TYPES = ("Stair", "Door", "Space", "Corridor", "Storey")   # what the readers can find
MIN_TEXT_TOKENS = 20  # a set with less text (a bare logo or sheet number) says too little to have missed anything

__all__ = ["VERSION", "analyse", "render", "sheets_of", "tokens_of", "Sheet", "Token", "locator", "parse_locator"]


def analyse(files: list[Path], root: Path, describes: str | None = None, progress=lambda msg: None) -> dict:
    """One evidence document for every PDF/PNG/JPG/TIFF sheet in `files`; locators use
    paths relative to `root`."""
    files = [Path(f) for f in files if Path(f).suffix.lower() in PDF | IMAGES]
    reading = annotations.Reading()
    sheets, timings = [], []
    no_text = []
    for path in files:
        try:
            digest = ocr.file_hash(path)
            sheets_here = sheets_of(path, root)
        except Exception as e:  # an unreadable file is reported, not fatal
            reading.skipped.append({"at": Path(path).name, "text": "", "reason": f"file not readable: {type(e).__name__}: {e}"})
            continue
        for sheet in sheets_here:
            stats: dict = {}
            progress(f"reading {sheet.file} p{sheet.page}")
            try:
                tokens = tokens_of(path, sheet, digest, stats)
            except Exception as e:  # noqa: BLE001 - one sheet that cannot be read must not lose the set
                reading.skipped.append({"at": locator(sheet, (0, 0, sheet.width, sheet.height)), "text": "",
                                        "reason": f"sheet not readable: {type(e).__name__}: {str(e)[:200]}"})
                continue
            t0 = time.perf_counter()
            r = annotations.read(sheet, tokens)
            reading.merge(r)
            if sheet.text == "none":
                no_text.append(sheet)
            timings.append(stats.get("ocr_seconds", stats.get("seconds", 0.0)))
            sheets.append({"file": sheet.file, "page": sheet.page, "number": sheet.number, "title": sheet.title,
                           "width": sheet.width, "height": sheet.height, "text": sheet.text, "tokens": len(tokens),
                           "seconds": stats.get("seconds"), "ocr_seconds": stats.get("ocr_seconds"),
                           "ocr_cached": stats.get("cached"), "read_seconds": round(time.perf_counter() - t0, 2)})
            progress(f"{sheet.label()}: {len(tokens)} tokens ({sheet.text}), {len(r.elements)} elements")
    reading.check_tags_against_schedules()
    for s in no_text:
        reading.skipped.append({"at": locator(s, (0, 0, s.width, s.height)), "text": "", "reason": "page has no text layer and OCR found no text"})
    reasons = Counter(_reason_kind(s["reason"]) for s in reading.skipped)
    source = {
        "id": "drawings", "kind": "drawings", "adapter": f"adapters.drawings {VERSION}",
        "describes": describes or (", ".join(sorted({s["file"] for s in sheets})) if len(sheets) < 4 else f"{len(files)} drawing files"),
        "files": sorted({s["file"] for s in sheets}),
        "text": dict(Counter(s["text"] for s in sheets)),
        "ocr": {"engine": "RapidOCR (PP-OCRv4 det/rec, onnxruntime)", "dpi": ocr.OCR_DPI, "min_confidence": annotations.MIN_CONFIDENCE},
        "skipped_summary": dict(reasons),
        "skipped": reading.skipped[:SKIPPED_LISTED],
    }
    if len(reading.skipped) > SKIPPED_LISTED:
        source["skipped_more"] = len(reading.skipped) - SKIPPED_LISTED
    if sum(s["tokens"] for s in sheets) >= MIN_TEXT_TOKENS and not reading.facts and not any(e["facts"] for e in reading.elements.values()):
        # Text, but no reader recognised a convention in it (another language or notation): finding no stair
        # here does not mean the building has none, so requirements about these types stay open.
        source["may_miss"] = list(ELEMENT_TYPES)
        source["skipped"].append({"at": ", ".join(source["files"][:3]), "text": "",
                                  "reason": "text read, but no drafting convention the readers know was recognised in it"})
    elements = []
    for e in reading.elements.values():
        if e["facts"]:
            elements.append(e)
    return {
        "subject": {"kind": "building", "id": describes or (Path(root).name if root else "drawings")},
        "sources": [source],
        "sheets": sheets,
        "facts": reading.facts,
        "elements": elements,
    }


def _reason_kind(reason: str) -> str:
    """'door 1A03 width: low-confidence OCR (0.62)' -> 'low-confidence OCR'; the subject
    before the colon is dropped unless it is the reason itself."""
    import re

    head, _, tail = reason.partition(": ")
    kind = tail if tail and "OCR" not in head else reason
    return re.sub(r"\s*\([^)]*\)", "", kind).strip() or reason


def main() -> None:
    import argparse
    import sys

    import yaml

    p = argparse.ArgumentParser(description="Read drawing sheets into an evidence document.")
    p.add_argument("files", nargs="+")
    p.add_argument("--root", default=None, help="directory the locators' paths are relative to (default: common parent)")
    p.add_argument("--describes", default=None)
    p.add_argument("-o", "--out", required=True)
    a = p.parse_args()
    files = [Path(f) for f in a.files]
    root = Path(a.root) if a.root else Path(*Path(files[0]).resolve().parts[:-1]) if len(files) == 1 else Path(_common(files))
    doc = analyse(files, root, a.describes, progress=lambda m: print(m, file=sys.stderr, flush=True))
    Path(a.out).write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=140))


def _common(files: list[Path]) -> str:
    import os

    return os.path.commonpath([str(Path(f).resolve().parent) for f in files])


if __name__ == "__main__":
    main()
