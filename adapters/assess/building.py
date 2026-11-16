"""A building project as an adapters.assess Corpus: the text of its drawing sheets and the elements its readers built.

    sheets    every sheet's words (PDF text layer, OCR, or CAD text, as adapters.drawings and adapters.dxf read them)
              joined into lines: words on one baseline, separated by `|` where the gap between them is wider
              than three letter heights (a schedule's columns), broken where it is wider than twelve. A sheet
              is shown in fixed 50-line windows, headed `sheet S<n> ...`, each line numbered `L<k>`. A model cites
              `S<n>:L<k>`; verify turns that into the line's region, `<file>#page=<n>&bbox=...` or
              `<file>#layout=<name>&bbox=...`, the form app.buildings.locate and crop draw.
    elements  the evidence documents' elements (IFC model elements, and the doors, spaces and stairs the drawing
              readers built from schedules and plans), merged by id as the engine merges them, one line each:
              its locator (`ifc:<GlobalId>`, or the sheet region it was read from), type, id, storey and facts.
              Shown in fixed blocks of 40 per type; the building's own facts in one block.

Every header always comes with the same text, so excerpts retrieved for different requirements merge. verify accepts
only lines and elements that exist in this project: a line number past the end of a sheet, a region no line has, or
a GlobalId no element has is None.
"""

from __future__ import annotations

import re
from pathlib import Path
from statistics import median

from normir.evidence import load_evidence

from adapters.drawings.tokens import Sheet, locator, parse_locator

WINDOW = 50            # sheet lines per excerpt
ELEMENT_BLOCK = 40     # element lines per excerpt
GAP = 3.0              # a gap wider than this many letter heights is shown as " | " (a table's next column)
SPLIT = 12.0           # and one wider than this starts a new line
MIN_CONFIDENCE = 0.5   # OCR words below this recognition score are left out
MAX_LINE = 400
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
SHORT = re.compile(r"^S(?P<s>\d+)\s*[:\s]\s*L(?P<l>\d+)$", re.IGNORECASE)
TEXT_KIND = {"layer": "text layer", "ocr": "OCR", "dxf": "CAD text", "none": "no text"}


class BuildingCorpus:
    """The drawings and model of one building project. `docs` are the evidence documents app.buildings.process
    stores; `sheets` is [(sheet, words)] with sheet a row of its `sheets` list (file, page or layout, number,
    title, text) and words Token objects (adapters.drawings.tokens) or (text, bbox[, angle[, confidence]]) tuples
    in that sheet's coordinates. BuildingCorpus.from_project reads the words from the uploaded files."""

    prompt_notes = (
        "The artifact is a building project: drawing sheets and the elements read from its model and drawings. "
        "Sheet excerpts are headed `sheet S<n>` with the sheet number, title and file; every line starts with `L<k>`. "
        "The lines are words read from the sheet (text layer, OCR, or CAD text) joined by position, so a table row "
        "or note may be split across lines, words may come from different drawings on the sheet, and OCR may misread "
        "characters: read numbers with care and say so in the note when a reading is doubtful. Cite a sheet line as "
        "`S<n>:L<k>`, with the numbers as shown. Model element lines start with their locator (`ifc:<GlobalId>`, or "
        "a sheet region `<file>#page=...&bbox=...`); cite that locator exactly as shown. Element facts are as the "
        "readers measured them (lengths in the units shown; two values for one fact are the range the sources "
        "allow). Judge the building as drawn and modelled. The excerpts are only part of the drawing set: when the "
        "requirement concerns a feature the excerpts do not show or dimension, answer null rather than false; use "
        "basis \"absence\" only when the requirement is that the drawings themselves state something and the "
        "searched sheets would show it. A requirement that applies only to a kind of building or element is "
        "not_applicable when the excerpts show the building is not that kind or has no such element (cite what "
        "shows it, such as the stated use); when they do not show which kind it is, null.")

    def __init__(self, name: str, docs: list[dict], sheets: list[tuple[dict, list]] = ()):
        self.name = name
        self.revision = None
        self._sheets: list[dict] = []           # {meta, label, lines: [(locator, text)]}
        self._line: dict[str, str] = {}         # sheet-line locator -> its text
        self._cite: dict[str, str] = {}         # element or building-fact locator -> the line shown for it
        self._by_id: dict[str, str] = {}        # element id -> its locator
        self._blocks: list[tuple[str, str, str]] = []   # (header, text, lowercased header and text)
        for meta, words in sheets:
            self._add_sheet(meta, words)
        self._add_evidence(docs)

    # ---------------------------------------------------------------- reading

    @classmethod
    def from_project(cls, files_dir: Path, docs: list[dict], sheets: list[dict], name: str, progress=lambda m: None) -> BuildingCorpus:
        """Read every sheet's words again from the uploaded files (OCR comes from adapters.drawings' cache)."""
        files_dir = Path(files_dir)
        dxf_docs: dict[str, object] = {}
        out = []
        for s in sheets:
            path = files_dir / s["file"]
            try:
                if files_dir.resolve() not in path.resolve().parents:
                    raise ValueError("outside the project")
                if s.get("layout"):
                    words = _dxf_words(path, s["file"], s["layout"], dxf_docs)
                else:
                    from adapters.drawings import ocr
                    from adapters.drawings.reader import tokens_of
                    sh = Sheet(s["file"], page=s.get("page") or 1, width=s.get("width") or 0.0, height=s.get("height") or 0.0)
                    words = tokens_of(path, sh, ocr.file_hash(path))
            except Exception as e:  # noqa: BLE001 - a sheet that can't be read again is left out of the corpus
                progress(f"assess: {s['file']} not read for assessment ({type(e).__name__})")
                words = []
            out.append((s, words))
        return cls(name, docs, out)

    def _add_sheet(self, meta: dict, words: list) -> None:
        n = len(self._sheets) + 1
        sheet = Sheet(meta["file"], page=None if meta.get("layout") else (meta.get("page") or 1), layout=meta.get("layout"))
        lines = []
        for text, bbox in _lines(words, y_up=bool(meta.get("layout"))):
            loc = locator(sheet, bbox)
            if loc in self._line:     # two lines with one region (rounding): keep the first
                continue
            self._line[loc] = text
            lines.append((loc, text))
        where = f"p{sheet.page}" if sheet.page else f"layout {sheet.layout}"
        title = " ".join(x for x in (meta.get("number"), meta.get("title")) if x)
        label = f"sheet S{n}" + (f" · {title}" if title else "") + f" · {meta['file']} {where} ({TEXT_KIND.get(meta.get('text'), meta.get('text') or 'text')})"
        self._sheets.append({"meta": meta, "label": label, "lines": lines})
        for a in range(0, len(lines), WINDOW):
            b = min(len(lines), a + WINDOW)
            header = f"{label} · lines {a + 1}-{b} of {len(lines)}"
            body = "\n".join(f"L{k + 1} {lines[k][1]}" for k in range(a, b))
            self._blocks.append((header, body, (header + "\n" + body).lower()))

    def _add_evidence(self, docs: list[dict]) -> None:
        if not docs:
            return
        ev = load_evidence(*docs)
        by_type: dict[str, list] = {}
        for e in ev.elements:
            by_type.setdefault(e.type, []).append(e)
        for typ in sorted(by_type):
            rows = []
            for e in sorted(by_type[typ], key=lambda e: (_storey(e) or "", e.id)):
                ats = [a for a in (_canonical(x) for x in e.at) if a]
                if not ats:
                    continue
                primary = next((a for a in ats if a.startswith("ifc:")), ats[0])
                line = f"{primary}  {_describe(e)}"[:MAX_LINE]
                for a in ats:
                    self._cite.setdefault(a, line)
                self._by_id.setdefault(e.id, primary)
                rows.append(line)
            for a in range(0, len(rows), ELEMENT_BLOCK):
                b = min(len(rows), a + ELEMENT_BLOCK)
                header = f"model elements: {typ} {a + 1}-{b} of {len(rows)}"
                body = "\n".join(rows[a:b])
                self._blocks.append((header, body, (header + "\n" + body).lower()))
        rows = []
        for k, f in sorted(ev.facts.items()):
            if any(str(o.get("source", "")).startswith("llm:") for o in f.observations):
                continue   # an earlier assessment's answers are not evidence for this one
            at = next((a for a in (_canonical(o.get("at")) for o in f.observations) if a), None)
            line = f"{at or '-'}  building {k.replace('_', ' ')}: {' / '.join(str(v) for v in f.values()[:4])}"[:MAX_LINE]
            if at:
                self._cite.setdefault(at, line)
            rows.append(line)
        if rows:
            header = "model: facts about the building as a whole"
            body = "\n".join(rows)
            self._blocks.append((header, body, (header + "\n" + body).lower()))

    # ---------------------------------------------------------------- Corpus

    def search(self, terms: list[str], budget: int) -> list[tuple[str, str]]:
        """Excerpts holding the terms: more distinct terms first, then more hits per thousand characters, then the
        order of the project (sheets as uploaded, then elements by type)."""
        terms = list(dict.fromkeys(t.strip().lower().replace("_", " ") for t in terms if isinstance(t, str) and len(t.strip()) >= 2))
        if not terms or budget <= 0:
            return []
        ranked = []
        for i, (_, body, low) in enumerate(self._blocks):
            counts = [low.count(t) for t in terms]
            distinct = sum(1 for c in counts if c)
            if distinct:
                ranked.append((-distinct, -round(sum(counts) / (1 + len(body) / 1000), 6), i))
        ranked.sort()
        out, used = [], 0
        for *_, i in ranked:
            header, body, _ = self._blocks[i]
            size = len(header) + len(body)
            if used + size <= budget:
                out.append((header, body))
                used += size
        return out

    def everything(self) -> list[tuple[str, str]]:
        return [(h, t) for h, t, _ in self._blocks]

    def verify(self, locator: str) -> str | None:
        s = str(locator or "").strip().strip("`'\"").strip()
        m = SHORT.match(s)
        if m:
            n, k = int(m["s"]), int(m["l"])
            if 1 <= n <= len(self._sheets) and 1 <= k <= len(self._sheets[n - 1]["lines"]):
                return self._sheets[n - 1]["lines"][k - 1][0]
            return None
        if s in self._by_id:
            return self._by_id[s]
        loc = _canonical(s)
        if loc and (loc in self._line or loc in self._cite):
            return loc
        return None

    def excerpt(self, locator: str) -> str:
        loc = self.verify(locator)
        if loc is None:
            return ""
        return self._line.get(loc) or self._cite.get(loc, "")

    def element(self, locator: str) -> str | None:
        """The line shown for an element or building-fact locator, for the report."""
        loc = self.verify(locator)
        return self._cite.get(loc) if loc else None


# ---------------------------------------------------------------- helpers

def _canonical(at) -> str | None:
    """A sheet region rounded as adapters.drawings.tokens.locator writes it, or `ifc:<GlobalId>` without the
    property path an observation adds after it; None for anything else."""
    s = str(at or "").strip()
    if s.startswith("ifc:"):
        gid = s[4:].split()[0] if s[4:].split() else ""
        return f"ifc:{gid}" if re.fullmatch(r"[0-9A-Za-z_$]{1,64}", gid) else None
    p = parse_locator(s)
    if not p:
        return None
    return locator(Sheet(p["file"], page=p["page"], layout=p["layout"]), p["bbox"])


def _storey(e) -> str | None:
    f = e.facts.get("storey")
    return " / ".join(str(v) for v in f.values()) if f is not None and f.values() else None


def _describe(e) -> str:
    facts = [f"{k.replace('_', ' ')} {' / '.join(str(v) for v in f.values()[:4])}" for k, f in e.facts.items()
             if k != "storey" and f.values()]
    storey = _storey(e)
    return f"{e.type} {e.id}" + (f" · storey {storey}" if storey else "") + (": " + "; ".join(facts) if facts else "")


def _word(w) -> tuple[str, tuple, float, float]:
    if isinstance(w, (tuple, list)):
        text, bbox = w[0], w[1]
        return str(text), tuple(bbox), float(w[2]) if len(w) > 2 else 0.0, float(w[3]) if len(w) > 3 else 1.0
    return str(w.text), tuple(w.bbox), float(getattr(w, "angle", 0.0) or 0.0), float(getattr(w, "confidence", 1.0))


def _lines(words: list, y_up: bool = False) -> list[tuple[str, tuple]]:
    """[(text, bbox)] in reading order: horizontal words on one baseline joined, split at wide gaps; turned words
    one per line. `y_up` for DXF layouts, whose y grows upwards."""
    top = (lambda b: -b[3]) if y_up else (lambda b: b[1])
    bottom = (lambda b: -b[1]) if y_up else (lambda b: b[3])
    flat, turned = [], []
    for w in words:
        text, b, angle, conf = _word(w)
        text = CONTROL.sub(" ", text).strip()
        if not text or conf < MIN_CONFIDENCE or len(b) != 4:
            continue
        (flat if min(abs(angle) % 360, 360 - abs(angle) % 360) < 1 else turned).append((text, b))
    flat.sort(key=lambda t: ((top(t[1]) + bottom(t[1])) / 2, t[1][0], t[0]))
    bands: list[dict] = []
    for t in flat:
        b = t[1]
        cy, h = (top(b) + bottom(b)) / 2, max(bottom(b) - top(b), 1e-6)
        if bands and abs(cy - bands[-1]["cy"]) <= 0.5 * min(h, bands[-1]["h"]):
            bands[-1]["words"].append(t)
        else:
            bands.append({"cy": cy, "h": h, "words": [t]})
    out = []
    for band in bands:
        ws = sorted(band["words"], key=lambda t: (t[1][0], t[0]))
        h = median(max(bottom(t[1]) - top(t[1]), 1e-6) for t in ws)
        run = [ws[0]]
        for t in ws[1:]:
            gap = t[1][0] - max(x[1][2] for x in run if x[1] is not None)
            if gap > SPLIT * h:
                out.append(_join(run))
                run = []
            elif gap > GAP * h:
                run.append(("|", None))
            run.append(t)
        out.append(_join(run))
    out += [(t[0][:MAX_LINE], t[1]) for t in turned]
    out.sort(key=lambda t: (round(top(t[1]), 1), t[1][0], t[0]))
    return out


def _join(run: list) -> tuple[str, tuple]:
    boxes = [t[1] for t in run if t[1] is not None]
    bbox = (min(b[0] for b in boxes), min(b[1] for b in boxes), max(b[2] for b in boxes), max(b[3] for b in boxes))
    return " ".join(t[0] for t in run)[:MAX_LINE], bbox


def _dxf_words(path: Path, rel: str, layout: str, cache: dict) -> list:
    """The text of one DXF layout as Tokens, read the way adapters.dxf.analyse_file reads it."""
    from adapters import dxf as D

    if rel not in cache:
        doc = D.read(path)
        cache[rel] = (doc, D.units_of(doc), D._hidden_layers(doc))
    doc, units, hidden = cache[rel]
    model = layout == "Model"
    lay = doc.modelspace() if model else doc.layouts.get(layout)
    sheet = Sheet(rel, layout=layout, text="dxf")
    kinds = ("TEXT", "MTEXT", "DIMENSION") if model else ("TEXT", "MTEXT", "ATTRIB", "DIMENSION")
    words = []
    for e, _k, chain in D._walk(lay, hidden):
        if e.dxftype() in kinds:
            words += D._text_tokens(e, sheet, chain, units if model else None)
        if e.dxftype() == "INSERT":
            for a in e.attribs:
                words += D._text_tokens(a, sheet, chain + (e,), units if model else None)
    return words
