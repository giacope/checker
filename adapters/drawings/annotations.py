"""Facts read from the text on drawing sheets, whatever produced the Tokens (a PDF text
layer, OCR, or a DXF file).

Tokens are grouped by position into lines (same reading direction, same baseline, small
gaps) and lines into phrases (a note wrapped over several lines). Each reader below is
written for a drafting convention and reads only what the drawing states; anything it
cannot read with confidence is left out and listed in `skipped`. Every observation's
`at` is the locator of the token(s) it was read from (bbox = their union, or the part
of a long token the match covers), and its `note` quotes the text as read.

Measured lengths and areas are reported as the interval their printed precision allows,
as two observations ("279 mm" -> 278.5 mm and 279.5 mm). Counts and stated text are
single values.

Conventions relied on (US and metric drafting, Japanese 設計図書):
- A dimension written without a unit is millimetres: imperial dimensions always carry
  ' or " marks. Bare numbers are read only where a convention calls for a dimension
  (a schedule's WIDTH column, "@ 176" after a riser count, 蹴上 175) and only as
  integers of three or more digits (a bare 7 could be anything).
- A value qualified MIN/MAX/MINIMUM/MAXIMUM is a stated limit, not a measurement: skipped.
"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from decimal import Decimal
from fractions import Fraction

from .tokens import BBox, Sheet, Token, locator

# A door's clear width from its leaf width: the deduction adapters/ifc.py uses.
try:
    from adapters.ifc import CLEAR_WIDTH_DEDUCTION_MM
except Exception:  # ifcopenshell missing: same values as adapters/ifc.py
    CLEAR_WIDTH_DEDUCTION_MM = (44, 64)

MIN_CONFIDENCE = 0.85  # OCR recognition score below which a token's text is not relied on
# OCR text shorter than this (points) is not read for facts: on the clinic's life-safety plans,
# room tags 5-7 pt high (10-15 px at 144 dpi) misread with high scores ("TOILET" -> "YOILET").
MIN_OCR_TEXT_PT = 8.0

# --- text normalisation ----------------------------------------------------------------

_TRANS = str.maketrans({"″": '"', "“": '"', "”": '"', "〃": '"', "′": "'", "‘": "'", "’": "'", "`": "'", "´": "'",
                        "–": "-", "—": "-", "−": "-", "‐": "-", "‑": "-", "×": "x"})


def norm(s: str) -> str:
    """Width-folded, quote-folded text (NFKC: ＝ -> =, ㎡ -> m2, ² -> 2)."""
    s = unicodedata.normalize("NFKC", s).translate(_TRANS)
    s = s.replace("''", '"')
    return re.sub(r"\s+", " ", s).strip()


# --- lines and phrases -------------------------------------------------------------------

def _frame(t: Token) -> tuple[float, float, float, float]:
    """(along0, along1, across0, across1) in the token's reading frame."""
    x0, y0, x1, y1 = t.bbox
    a = _snap(t.angle)
    if a == 90:
        return -y1, -y0, x0, x1
    if a == 270:
        return y0, y1, -x1, -x0
    if a == 180:
        return -x1, -x0, -y1, -y0
    return x0, x1, y0, y1


def _snap(angle: float) -> int:
    return int(round((angle or 0) / 90.0)) % 4 * 90


def union(boxes) -> BBox:
    boxes = list(boxes)
    return (min(b[0] for b in boxes), min(b[1] for b in boxes), max(b[2] for b in boxes), max(b[3] for b in boxes))


@dataclass
class Line:
    """Tokens read as one run of text. `spans` maps character ranges of `text` to tokens."""

    tokens: list[Token]
    text: str = ""
    spans: list[tuple[int, int, Token]] = field(default_factory=list)

    def __post_init__(self):
        if not self.text:
            parts, pos = [], 0
            for t in self.tokens:
                s = norm(t.text)
                if parts:
                    pos += 1
                self.spans.append((pos, pos + len(s), t))
                parts.append(s)
                pos += len(s)
            self.text = " ".join(parts)

    @property
    def sheet(self) -> Sheet:
        return self.tokens[0].sheet

    @property
    def angle(self) -> int:
        return _snap(self.tokens[0].angle)

    @property
    def bbox(self) -> BBox:
        return union(t.bbox for t in self.tokens)

    @property
    def height(self) -> float:
        f = [_frame(t) for t in self.tokens]
        return max(x[3] - x[2] for x in f)

    def part(self, start: int = 0, end: int | None = None) -> tuple[BBox, float, list[Token]]:
        """bbox, lowest confidence and tokens of text[start:end]. Where the range covers
        part of a token, that part is cut from the token's box by character position."""
        end = len(self.text) if end is None else end
        boxes, conf, toks = [], 1.0, []
        for s, e, t in self.spans:
            if e <= start or s >= end:
                continue
            toks.append(t)
            conf = min(conf, t.confidence)
            n = max(e - s, 1)
            f0, f1 = (max(start, s) - s) / n, (min(end, e) - s) / n
            x0, y0, x1, y1 = t.bbox
            a = _snap(t.angle)
            if a == 0:
                boxes.append((x0 + (x1 - x0) * f0, y0, x0 + (x1 - x0) * f1, y1))
            elif a == 180:
                boxes.append((x1 - (x1 - x0) * f1, y0, x1 - (x1 - x0) * f0, y1))
            elif a == 90:
                boxes.append((x0, y1 - (y1 - y0) * f1, x1, y1 - (y1 - y0) * f0))
            else:
                boxes.append((x0, y0 + (y1 - y0) * f0, x1, y0 + (y1 - y0) * f1))
        if not boxes:
            return self.bbox, min(t.confidence for t in self.tokens), list(self.tokens)
        return union(boxes), conf, toks

    def at(self, start: int = 0, end: int | None = None) -> str:
        return locator(self.sheet, self.part(start, end)[0])


def lines(tokens: list[Token], gap: float = 1.5) -> list[Line]:
    """Group tokens into lines: same reading direction, overlapping baseline band, and an
    along-the-line gap under `gap` text heights."""
    out: list[Line] = []
    by_angle: dict[int, list[Token]] = {}
    for t in tokens:
        if t.text.strip():
            by_angle.setdefault(_snap(t.angle), []).append(t)
    for toks in by_angle.values():
        fr = {id(t): _frame(t) for t in toks}
        toks.sort(key=lambda t: (fr[id(t)][2] + fr[id(t)][3]) / 2)
        rows: list[list[Token]] = []
        for t in toks:
            f = fr[id(t)]
            c, h = (f[2] + f[3]) / 2, f[3] - f[2]
            if rows:
                r = rows[-1][0]
                rf = fr[id(r)]
                rc, rh = (rf[2] + rf[3]) / 2, rf[3] - rf[2]
                if abs(c - rc) <= 0.4 * max(min(h, rh), 1) and 0.5 < h / max(rh, 0.1) < 2.0:
                    rows[-1].append(t)
                    continue
            rows.append([t])
        for row in rows:
            row.sort(key=lambda t: fr[id(t)][0])
            cur = [row[0]]
            for t in row[1:]:
                p = cur[-1]
                h = max(fr[id(p)][3] - fr[id(p)][2], fr[id(t)][3] - fr[id(t)][2])
                g = fr[id(t)][0] - max(fr[id(q)][1] for q in cur)
                if -0.5 * h <= g <= gap * h:
                    cur.append(t)
                else:
                    out.append(Line(cur))
                    cur = [t]
            out.append(Line(cur))
    return out


NOTE_START = re.compile(r"^\(?\d{1,2}\s*[.)]|^[A-Z]\.\s|^[•\-*]\s")


def phrases(ls: list[Line]) -> list[Line]:
    """Join upright lines that continue one another (a note wrapped over several lines):
    the next line starts under some word of the line above, close below it, at a similar
    size, and does not start a new numbered note."""
    up = sorted((l for l in ls if l.angle == 0), key=lambda l: (l.bbox[1], l.bbox[0]))
    out, taken = [], set()
    for i, l in enumerate(up):
        if i in taken:
            continue
        group = [l]
        taken.add(i)
        cur = l
        for j in range(i + 1, len(up)):
            n = up[j]
            if j in taken:
                continue
            h = cur.height
            if n.bbox[1] - cur.bbox[3] > 0.9 * h:
                if n.bbox[1] > cur.bbox[3] + 3 * h:
                    break
                continue
            if n.bbox[1] < cur.bbox[3] - 0.3 * h or not (0.7 < n.height / max(h, 0.1) < 1.4):
                continue
            starts = [t.bbox[0] for t in cur.tokens] + [cur.part(m.start())[0][0] for m in re.finditer(r"(?<=\s)\S", cur.text)]
            if not any(abs(n.bbox[0] - s) <= 1.0 * h for s in starts) or NOTE_START.match(n.text):
                continue
            group.append(n)
            taken.add(j)
            cur = n
        if len(group) == 1:
            out.append(l)
        else:
            out.append(Line([t for g in group for t in g.tokens]))
    return out + [l for l in ls if l.angle != 0]


# --- quantities ------------------------------------------------------------------------

LEN = (r"(?:\d+\s*'\s*-?\s*\d+(?:\.\d+)?(?:(?:\s+|\s*-\s*)\d+/\d+)?\s*\"?"
       r"|\d+\s*'(?!\s*-?\s*\d)"
       r"|\d+(?:\.\d+)?(?:\s+\d+/\d+)?\s*(?:\"|IN\b\.?|INCH(?:ES)?\b)"
       r"|\d+/\d+\s*\""
       r"|\d+(?:\.\d+)?\s*(?:FT\b\.?|FEET\b)"
       r"|(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?\s*(?:MM|CM|M)\b(?!\s*[2²]))")
BARE = r"(?:\d{1,3}(?:,\d{3})+|\d{3,5})(?![\d.,'\"])"
AREA = r"(?:(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?\s*(?:SQ\.?\s*FT\.?|S\.?F\.?\b|SF\b|M2|M²|㎡))"
LIMIT = re.compile(r"\b(?:MIN|MAX)(?:IMUM)?\b\.?|最小|最大|以上|以下", re.I)


def _dec(x) -> str:
    d = Decimal(x.numerator) / Decimal(x.denominator) if isinstance(x, Fraction) else Decimal(x)
    s = format(d.normalize(), "f")
    return s


def _half_digits(num: str) -> Decimal:
    dec = num.split(".")[1] if "." in num else ""
    return Decimal(5) * Decimal(10) ** -(len(dec) + 1)


def length(text: str, bare: bool = False) -> tuple[str, str] | None:
    """A printed length as the interval its printed precision allows: (lo, hi) as
    strings with units. '279 mm' -> ('278.5 mm', '279.5 mm'); '1.21 m' -> ('1.205 m',
    '1.215 m'); 3'-0" -> ('35.5 in', '36.5 in'); '7 1/4"' -> ('7.125 in', '7.375 in');
    '137 FT' -> ('136.5 ft', '137.5 ft'). `bare`: a unitless integer is millimetres."""
    s = norm(text).strip().upper()
    m = re.fullmatch(r"(\d+)\s*'\s*-?\s*(\d+(?:\.\d+)?)(?:(?:\s+|\s*-\s*)(\d+)/(\d+))?\s*\"?", s)
    if m:
        inch = Fraction(int(m[1]) * 12) + Fraction(Decimal(m[2]))
        if m[3]:
            if int(m[4]) == 0:
                return None
            inch += Fraction(int(m[3]), int(m[4]))
            half = Fraction(1, 2 * int(m[4]))
        else:
            half = Fraction(_half_digits(m[2]))
        return f"{_dec(inch - half)} in", f"{_dec(inch + half)} in"
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(?:'|FT\.?|FEET)", s)
    if m:
        v, h = Decimal(m[1]), _half_digits(m[1])
        return f"{_dec(v - h)} ft", f"{_dec(v + h)} ft"
    m = re.fullmatch(r"(?:(\d+(?:\.\d+)?)(?:\s+(\d+)/(\d+))?|(\d+)/(\d+))\s*(?:\"|IN\.?|INCH(?:ES)?)", s)
    if m:
        if m[4]:
            num, den, whole = int(m[4]), int(m[5]), Fraction(0)
        else:
            whole, num, den = Fraction(Decimal(m[1])), int(m[2]) if m[2] else 0, int(m[3]) if m[3] else 0
        if den:
            v, h = whole + Fraction(num, den), Fraction(1, 2 * den)
        else:
            v, h = whole, Fraction(_half_digits(m[1]))
        return f"{_dec(v - h)} in", f"{_dec(v + h)} in"
    m = re.fullmatch(r"(\d{1,3}(?:,\d{3})+|\d+)(\.\d+)?\s*(MM|CM|M)", s)
    if m:
        num = m[1].replace(",", "") + (m[2] or "")
        v, h = Decimal(num), _half_digits(num)
        unit = m[3].lower()
        if unit == "cm":
            v, h, unit = v * 10, h * 10, "mm"
        return f"{_dec(v - h)} {unit}", f"{_dec(v + h)} {unit}"
    if bare:
        m = re.fullmatch(r"(\d{1,3}(?:,\d{3})+|\d{3,5})", s)
        if m:
            v = Decimal(m[1].replace(",", ""))
            return f"{_dec(v - Decimal('0.5'))} mm", f"{_dec(v + Decimal('0.5'))} mm"
    return None


def area(text: str) -> tuple[str, str] | None:
    """A printed area as its printed-precision interval: '250 SF' -> 249.5..250.5 sqft."""
    s = norm(text).strip().upper()
    m = re.fullmatch(r"(\d{1,3}(?:,\d{3})+|\d+)(\.\d+)?\s*(SQ\.?\s*FT\.?|S\.?F\.?|M2)", s)
    if not m:
        return None
    num = m[1].replace(",", "") + (m[2] or "")
    v, h = Decimal(num), _half_digits(num)
    unit = "m2" if m[3] == "M2" else "sqft"
    return f"{_dec(v - h)} {unit}", f"{_dec(v + h)} {unit}"


# --- findings ----------------------------------------------------------------------------

@dataclass
class Reading:
    """What one sheet (or several) says: subject facts, elements, and what was skipped."""

    facts: dict[str, list[dict]] = field(default_factory=dict)
    elements: dict[tuple[str, str], dict] = field(default_factory=dict)
    skipped: list[dict] = field(default_factory=list)
    scheduled: set = field(default_factory=set)   # space ids read from room schedule rows
    tagged: set = field(default_factory=set)      # space ids read from room tags on plans

    def element(self, type_: str, id_: str, at: str | None = None) -> dict:
        e = self.elements.setdefault((type_, id_), {"type": type_, "id": id_, "at": [], "facts": {}})
        if at and at not in e["at"]:
            e["at"].append(at)
        return e

    def add(self, target: dict | None, name: str, obs: list[dict]) -> None:
        facts = self.facts if target is None else target["facts"]
        have = facts.setdefault(name, [])
        for o in obs:
            if o not in have:
                have.append(o)

    def skip(self, at: str, text: str, reason: str) -> None:
        self.skipped.append({"at": at, "text": text[:120], "reason": reason})

    def merge(self, other: "Reading") -> None:
        for k, v in other.facts.items():
            self.add(None, k, v)
        for (t, i), e in other.elements.items():
            mine = self.element(t, i)
            mine["at"] += [a for a in e["at"] if a not in mine["at"]]
            for k, v in e["facts"].items():
                self.add(mine, k, v)
        self.skipped += other.skipped
        self.scheduled |= other.scheduled
        self.tagged |= other.tagged

    def check_tags_against_schedules(self, min_rows: int = 10) -> None:
        """Where the set has a room schedule, a room number read only from a plan tag and in
        no schedule is more likely an OCR misread (1A11 read as 1AN1) than a room: drop it."""
        if len(self.scheduled) < min_rows:
            return
        for sid in sorted(self.tagged - self.scheduled):
            e = self.elements.pop(("Space", sid), None)
            if e is not None:
                at = e["at"][0] if e["at"] else ""
                self.skip(at, sid.split(":", 1)[1], "room tag number in no room schedule of the set: possible OCR misread, not used")


def _q(text: str) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= 90 else text[:87] + "..."


def _interval(lo_hi, at: str, quote: str, what: str = "") -> list[dict]:
    lo, hi = lo_hi
    note = f'"{_q(quote)}"{" " + what if what else ""}: printed-precision interval {lo} to {hi}'
    return [{"value": lo, "at": at, "note": note}, {"value": hi, "at": at, "note": note}]


def _one(value, at: str, quote: str) -> list[dict]:
    return [{"value": value, "at": at, "note": f'"{_q(quote)}"'}]


def _confident(r: Reading, line: Line, start: int, end: int, what: str) -> tuple[str, bool]:
    bbox, conf, _ = line.part(start, end)
    at = locator(line.sheet, bbox)
    if conf < MIN_CONFIDENCE:
        r.skip(at, line.text[start:end], f"{what}: low-confidence OCR ({conf:.2f})")
        return at, False
    return at, True


# --- title block -------------------------------------------------------------------------

SHEET_NUMBER = re.compile(r"^[A-Z]{1,3}\s?-?\s?\d{1,3}(?:[.\-]\d{1,3}[A-Z]?)?$")
TITLE_WORDS = re.compile(r"PLAN|SECTION|ELEVATION|DETAIL|SCHEDULE|NOTES|LEGEND|INDEX|COVER|SHEET|DIAGRAM|ABBREVIATION|"
                         r"SPECIFICATION|LAYOUT|MAP|図|表|リスト|凡例|仕様|概要", re.I)
TB_LABELS = re.compile(r"^(?:SIZE|SCALE|CODE IDENT|DRAWING NO|DRAWN|DRAWNG|CHECKED|SPEC|CONST|CONTR|DATE|PROJECT|APPROVED|"
                       r"REVISION|DESCRIPTION|PREPARED|SYM|SHEET\s*\d+\s*OF|IF SHEET IS|NOT FOR CONSTRUCTION|AS SHOWN|"
                       r"XXX|NOTE!|THIS PLAN|INFORMATION ONLY|GRAPHIC SCALE)|^\d[\d ,.]*$|縮尺|図面番号|設計者|国土交通省|年版|表示欄", re.I)


def title_block(sheet: Sheet, ls: list[Line]) -> tuple[str | None, str | None, list[str]]:
    """(sheet number, title, [locators]) from the title block: the number is the largest
    sheet-number-shaped text in the bottom-right quarter; the title is the drawing-title
    text (PLAN, SECTION, SCHEDULE, 図 ...) near it, with the lines that continue it."""
    W, H = sheet.width or 1, sheet.height or 1
    cands = []
    for l in ls:
        if l.angle != 0:
            continue
        for s, e, t in l.spans:
            txt = l.text[s:e]
            if SHEET_NUMBER.match(txt) and t.bbox[0] > 0.6 * W and t.bbox[1] > 0.6 * H and t.confidence >= MIN_CONFIDENCE:
                cands.append((t.bbox[3] - t.bbox[1], t.bbox[2] + t.bbox[3], txt.replace(" ", ""), t))
    if not cands:
        return None, None, []
    _, _, number, nt = max(cands, key=lambda c: (round(c[0], 1), c[1]))
    region = (nt.bbox[0] - 0.3 * W, nt.bbox[1] - 0.08 * H, W, H)
    inside = [l for l in ls if l.angle == 0 and l.bbox[0] >= region[0] and l.bbox[1] >= region[1]
              and not TB_LABELS.search(l.text) and not any(t is nt for t in l.tokens) and min(t.confidence for t in l.tokens) >= MIN_CONFIDENCE]
    seeds = [l for l in inside if TITLE_WORDS.search(l.text)]
    if not seeds:
        return number, None, [locator(sheet, nt.bbox)]
    # the title block proper holds the title at or below the sheet number; a drawing's own
    # title (STAIR DETAIL) may sit above it
    below = [l for l in seeds if l.bbox[1] >= nt.bbox[1] - (nt.bbox[3] - nt.bbox[1])]
    seed = max(below or seeds, key=lambda l: (l.height, -abs(l.bbox[1] - nt.bbox[1])))
    group = [seed]
    for direction in (-1, 1):
        cur = seed
        while True:
            h = cur.height
            nxt = [l for l in inside if l not in group and 0.7 < l.height / max(h, 0.1) < 1.4
                   and min(l.bbox[2], cur.bbox[2]) - max(l.bbox[0], cur.bbox[0]) > 0
                   and (0 <= l.bbox[1] - cur.bbox[3] <= 0.8 * h if direction > 0 else 0 <= cur.bbox[1] - l.bbox[3] <= 0.8 * h)]
            if not nxt:
                break
            cur = nxt[0]
            group.append(cur)
    group.sort(key=lambda l: l.bbox[1])
    title = " ".join(l.text for l in group)
    return number, title, [locator(sheet, nt.bbox), locator(sheet, union(l.bbox for l in group))]


# --- general and code-analysis notes ------------------------------------------------------

SPRINKLER_STD = re.compile(r"NFPA\s*-?\s*13\s*([RD])?(?![\d])", re.I)
SPRINKLER_NONE = re.compile(r"\b(?:NON|UN)\s*-?\s*SPRINKLERED\b|\bNOT\s+(?:BE\s+)?SPRINKLERED\b|\bNO\s+(?:AUTOMATIC\s+)?SPRINKLER", re.I)
SPRINKLER_PARTIAL = re.compile(r"\bPARTIAL(?:LY)?\s+SPRINKLERED\b", re.I)
SPRINKLER_FULL = re.compile(r"\b(?:FULLY|COMPLETELY)\s+SPRINKLERED\b|\bSPRINKLERED\s+THROUGHOUT\b|"
                            r"\bSPRINKLER\s+SYSTEM\s+THROUGHOUT\b|\bTHROUGHOUT\s+WITH\s+(?:AN\s+)?(?:AUTOMATIC\s+)?SPRINKLER|"
                            r"\bEQUIPPED\s+(?:THROUGHOUT\s+)?WITH\s+(?:AN\s+)?AUTOMATIC\s+SPRINKLER", re.I)
OCCUPANCY = re.compile(r"\b(?:OCCUPANCY|USE)\s+(?:CLASSIFICATION|GROUP|TYPE|CLASS)(?:\s+GROUP)?\s*(?:[:=\-]|IS)?\s*"
                       r"|\bOCCUPANCY\s*[:=]\s*", re.I)
OCC_VALUE = re.compile(r"(?:GROUP\s+)?([A-Z](?:\s*-\s*\d(?:\.\d)?)?(?=$|[\s,;.)(])(?:\s*(?:/|,|AND|&)\s*[A-Z](?:\s*-\s*\d(?:\.\d)?)?(?=$|[\s,;.)(]))*"
                       r"|[A-Z][A-Z]+(?:[ /&-][A-Z]+){0,3})", re.I)
CONSTRUCTION = re.compile(r"\b(?:CONSTRUCTION\s+TYPE|TYPE\s+OF\s+CONSTRUCTION)\s*[:=\-]?\s*(?:TYPE\s+)?(?P<v>(?:IV|V|I{1,3})(?:\s*-?\s*(?:[AB]|HT)\b|\s*\(\s*[A-Z0-9-]{1,4}\s*\))?)"
                          r"|\bTYPE\s+(?P<w>(?:IV|V|I{1,3})(?:\s*-?\s*(?:[AB]|HT)\b|\s*\(\s*[A-Z0-9-]{1,4}\s*\))?)\s+CONSTRUCTION\b", re.I)
CODE = re.compile(r"(?:(?P<y1>(?:19|20)\d\d)\s+(?:EDITION\s+(?:OF\s+)?(?:THE\s+)?)?)?"
                  r"(?P<c>INTERNATIONAL\s+BUILDING\s+CODE|UNIFORM\s+BUILDING\s+CODE|CALIFORNIA\s+BUILDING\s+CODE|"
                  r"(?<![A-Z])(?:IBC|UBC|CBC)(?![A-Z])|U\.B\.C\.|I\.B\.C\.)"
                  r"(?:\s*\((?:IBC|UBC|U\.B\.C\.|I\.B\.C\.)\))?(?:\s*,?\s*(?:(?P<y2>(?:19|20)\d\d)(?:\s+EDITION)?))?", re.I)


CODE_BASIS = re.compile(r"(?:\bPER|IN\s+ACCORDANCE\s+WITH|COMPLY\s+WITH|CONFORM(?:S|ING)?\s+(?:TO|WITH)|DESIGNED\s+(?:TO|UNDER|PER)|"
                        r"\bCODES?(?:\s+(?:BASIS|USED|ANALYSIS|SUMMARY))?\s*[:=\-]|APPLICABLE\s+(?:BUILDING\s+)?CODES?\s*[:=\-]?|"
                        r"GOVERNING\s+(?:BUILDING\s+)?CODES?\s*[:=\-]?|BUILDING\s+CODE\s*[:=\-])\s*(?:THE\s+)?$", re.I)


def read_notes(r: Reading, ph: list[Line]) -> None:
    for l in ph:
        t = l.text
        if re.search(r"SPRINKLER", t, re.I):
            if (m := SPRINKLER_PARTIAL.search(t)):
                at, _ = _confident(r, l, m.start(), m.end(), "sprinkler note")
                r.skip(at, t, "sprinkler note says partially sprinklered: no throughout system to record")
            elif (m := SPRINKLER_NONE.search(t)):
                at, ok = _confident(r, l, m.start(), m.end(), "sprinkler note")
                if ok:
                    r.add(None, "sprinkler_system", _one("none", at, t[m.start():m.end()]))
            elif (std := list(SPRINKLER_STD.finditer(t))) and SPRINKLER_FULL.search(t) or (std and re.search(r"AUTOMATIC\s+SPRINKLER|SPRINKLER\s+SYSTEM", t, re.I)):
                for m in std:
                    at, ok = _confident(r, l, m.start(), m.end(), "sprinkler note")
                    if ok:
                        r.add(None, "sprinkler_system", _one("nfpa13" + (m[1] or "").lower(), at, t))
            elif (m := SPRINKLER_FULL.search(t)):
                at, ok = _confident(r, l, m.start(), m.end(), "sprinkler note")
                if ok:
                    note = f'"{_q(t)}": no installation standard named, so NFPA 13 or 13R'
                    r.add(None, "sprinkler_system", [{"value": "nfpa13", "at": at, "note": note}, {"value": "nfpa13r", "at": at, "note": note}])
        for m in OCCUPANCY.finditer(t):
            v = OCC_VALUE.match(t, m.end())
            if not v or re.match(r"(?:SENSOR|LOAD|SEPARATION|PERMIT)", v[0], re.I):
                continue
            value = v[1].strip(" .,;").upper()
            at, ok = _confident(r, l, m.start(), v.end(), "occupancy classification")
            if ok and value:
                r.add(None, "stated_occupancy_classification", _one(value, at, t[m.start():v.end()]))
        for m in CONSTRUCTION.finditer(t):
            value = re.sub(r"\s+", " ", (m["v"] or m["w"])).upper()
            at, ok = _confident(r, l, m.start(), m.end(), "construction type")
            if ok:
                r.add(None, "stated_construction_type", _one(value, at, t[m.start():m.end()]))
        for m in CODE.finditer(t):
            # the code the drawings follow, not one cited for a value (\"(1997 UNIFORM BUILDING CODE)\")
            if not CODE_BASIS.search(t[max(0, m.start() - 40):m.start()]):
                continue
            value = re.sub(r"\s+", " ", m[0]).strip().upper()
            at, ok = _confident(r, l, m.start(), m.end(), "code basis")
            if ok:
                r.add(None, "stated_code_basis", _one(value, at, t[m.start():m.end()]))


# --- stairs ------------------------------------------------------------------------------

L_OR_BARE = rf"(?:{LEN}|{BARE})"
RISERS = re.compile(rf"(?P<n>\d{{1,2}})\s*(?:EQ\.?|EQUAL)?\s*(?:RISERS?|R)\s*(?:@|AT)\s*(?P<len>{L_OR_BARE})", re.I)
TREADS = re.compile(rf"(?P<n>\d{{1,2}})\s*(?:EQ\.?|EQUAL)?\s*(?:TREADS?|T)\s*(?:@|AT)\s*(?P<len>{L_OR_BARE})", re.I)
RISER_HEIGHT = re.compile(rf"\bRISER\s+(?:HEIGHT|HT\.?)\s*[:=]?\s*(?P<len>{L_OR_BARE})|蹴上げ?\s*(?:寸法)?\s*[:=＝]?\s*(?P<jlen>{L_OR_BARE})", re.I)
TREAD_DEPTH = re.compile(rf"\bTREAD\s+(?:DEPTH|WIDTH|RUN)\s*[:=]?\s*(?P<len>{L_OR_BARE})|踏面\s*(?:寸法)?\s*[:=＝]?\s*(?P<jlen>{L_OR_BARE})", re.I)
STAIR_WIDTH = re.compile(rf"\b(?:STAIR|FLIGHT)\s+(?:CLEAR\s+)?WIDTH\s*[:=]?\s*(?P<len>{L_OR_BARE})|(?P<len2>{LEN})\s+(?:CLEAR\s+)?(?:STAIR|FLIGHT)\s+WIDTH\b"
                         rf"|階段(?:有効)?幅(?:員)?\s*[:=＝]?\s*(?P<jlen>{L_OR_BARE})", re.I)
HEADROOM = re.compile(rf"\bHEAD\s*ROOM\s*[:=]?\s*(?P<len>{LEN}|{BARE})|(?P<len2>{LEN}|{BARE})\s*(?:(?:MIN|MAX)(?:IMUM)?\.?\s+|CLEAR\s+|CLR\.?\s+)?HEAD\s*ROOM\b", re.I)
HANDRAIL = re.compile(rf"\bHANDRAIL\s+(?:HEIGHT|HT\.?)\s*[:=]?\s*(?P<len>{L_OR_BARE})(?:\s*(?:-|TO)\s*(?P<hi>{L_OR_BARE}))?"
                      rf"|(?P<len2>{LEN})(?:\s*(?:-|TO)\s*(?P<hi2>{LEN}))?\s*(?:A\.?F\.?F\.?\s*|ABOVE\s+(?:STAIR\s+)?NOSINGS?\s*)?(?:TO\s+)?(?:TOP\s+OF\s+)?HANDRAIL\b"
                      rf"|\bHANDRAIL\s*(?:@|AT)\s*(?P<len3>{LEN})(?:\s*(?:-|TO)\s*(?P<hi3>{LEN}))?\s*(?:A\.?F\.?F|ABOVE)"
                      rf"|手摺(?:り)?高さ?\s*[:=＝H]?\s*(?P<jlen>{L_OR_BARE})", re.I)
STAIR_NAME = re.compile(r"\b(?P<ext>EXTERIOR\s+|EXT\.\s+)?STAIR(?:WAY)?\s*(?:NO\.?\s*|#\s*)(?P<n>[A-Z]?\d{1,2}[A-Z]?|[A-Z])\b"
                        r"|\b(?P<ext2>EXTERIOR\s+|EXT\.\s+)?STAIR(?:WAY)?\s+(?P<m>\d{1,2}|[A-Z])\b(?!\s*(?:DETAIL|SECTION|ELEVATION|-))"
                        r"|(?P<j>(?:屋外)?階段(?:室)?\s*[A-ZＡ-Ｚ0-9０-９]{1,2})", re.I)


def _len_of(m: re.Match, *groups: str):
    for g in groups:
        if m.groupdict().get(g):
            return g, m[g]
    return None, None


def _stairs(ls: list[Line]) -> list[tuple[str, bool, tuple[float, float], str]]:
    out = []
    for l in ls:
        for m in STAIR_NAME.finditer(l.text):
            if min(t.confidence for t in l.part(m.start(), m.end())[2]) < MIN_CONFIDENCE:
                continue
            if m["j"]:
                name, ext = re.sub(r"\s+", "", m["j"]), "屋外" in m["j"]
            else:
                name = f"STAIR {'#' if '#' in m[0] else ''}{(m['n'] or m['m']).upper()}"
                ext = bool(m["ext"] or m["ext2"])
            b = l.part(m.start(), m.end())[0]
            out.append((name, ext, ((b[0] + b[2]) / 2, (b[1] + b[3]) / 2), locator(l.sheet, b)))
    return out


def read_stairs(r: Reading, ls: list[Line]) -> None:
    names = _stairs(ls)

    def stair_for(bbox):
        if not names:
            return None
        c = ((bbox[0] + bbox[2]) / 2, (bbox[1] + bbox[3]) / 2)
        name, ext, _, at = min(names, key=lambda n: (n[2][0] - c[0]) ** 2 + (n[2][1] - c[1]) ** 2)
        e = r.element("Stair", f"stair:{name}", at)
        if ext:
            r.add(e, "is_external", _one(True, at, name))
        return e

    def emit(l, m, start, end, group, attr, quote, what, count=None, hi_group=None):
        text = m[group]
        if LIMIT.search(l.text[max(0, start - 12):end + 12]):
            r.skip(l.at(start, end), quote, f"{what}: stated limit (MIN/MAX), not a measurement")
            return
        at, ok = _confident(r, l, start, end, what)
        if not ok:
            return
        bare = not re.search(r"[A-Za-z'\"]", norm(text))
        iv = length(text, bare=bare)
        if hi_group and m[hi_group]:
            hv = length(m[hi_group], bare=bare)
            iv = (iv[0], hv[1]) if iv and hv else None
        if not iv:
            r.skip(at, quote, f"{what}: length not readable")
            return
        e = stair_for(l.part(start, end)[0])
        if e is None:
            r.skip(at, quote, f"{what}: no stair named on the sheet to attach it to")
            return
        if count is not None:
            r.add(e, "risers", _one(int(count), at, quote))
        r.add(e, attr, _interval(iv, at, quote, what))

    for l in ls:
        t = l.text
        for m in RISERS.finditer(t):
            emit(l, m, m.start(), m.end(), "len", "riser_height", m[0], "riser height", count=m["n"])
        for m in TREADS.finditer(t):
            emit(l, m, m.start(), m.end(), "len", "tread_depth", m[0], f"tread depth ({m['n']} treads)")
        for m in RISER_HEIGHT.finditer(t):
            g, _ = _len_of(m, "len", "jlen")
            emit(l, m, m.start(), m.end(), g, "riser_height", m[0], "riser height")
        for m in TREAD_DEPTH.finditer(t):
            g, _ = _len_of(m, "len", "jlen")
            emit(l, m, m.start(), m.end(), g, "tread_depth", m[0], "tread depth")
        for m in STAIR_WIDTH.finditer(t):
            g, _ = _len_of(m, "len", "len2", "jlen")
            emit(l, m, m.start(), m.end(), g, "width", m[0], "flight width")
        for m in HEADROOM.finditer(t):
            g, _ = _len_of(m, "len", "len2")
            emit(l, m, m.start(), m.end(), g, "headroom", m[0], "headroom")
        for m in HANDRAIL.finditer(t):
            g, _ = _len_of(m, "len", "len2", "len3", "jlen")
            emit(l, m, m.start(), m.end(), g, "handrail_height", m[0], "handrail height", hi_group={"len": "hi", "len2": "hi2", "len3": "hi3"}.get(g))

    # A sheet repeats a stair's riser note in plan and section; where OCR reads the count
    # differently in different places ("13" as "3"), keep a count only if most readings agree.
    for e in {id(x): x for x in r.elements.values() if x["type"] == "Stair"}.values():
        obs = e["facts"].get("risers", [])
        counts = Counter(o["value"] for o in obs)
        if len(counts) < 2:
            continue
        top, n = counts.most_common(1)[0]
        keep = top if n > len(obs) / 2 else None
        for o in obs:
            if o["value"] != keep:
                r.skip(o["at"], o["note"], f"riser count {o['value']}: disagrees with the other readings of this stair on the sheet")
        e["facts"]["risers"] = [o for o in obs if o["value"] == keep]
        if not e["facts"]["risers"]:
            del e["facts"]["risers"]


# --- life safety -------------------------------------------------------------------------

ORDINAL = {"FIRST": 1, "1ST": 1, "GROUND": 1, "SECOND": 2, "2ND": 2, "THIRD": 3, "3RD": 3, "FOURTH": 4, "4TH": 4, "FIFTH": 5, "5TH": 5}
ORD_NAME = {1: "First", 2: "Second", 3: "Third", 4: "Fourth", 5: "Fifth"}


def storey_of(title: str | None) -> str | None:
    """The storey a plan's title names: 'LIFE SAFETY COMPOSITE FIRST FLOOR PLAN' -> 'First Floor'."""
    if not title:
        return None
    t = norm(title).upper()
    found = set()
    for m in re.finditer(r"\b(FIRST|1ST|SECOND|2ND|THIRD|3RD|FOURTH|4TH|FIFTH|5TH|GROUND|BASEMENT)\s*FLOOR(?=\b|PLAN)", t):
        found.add("Basement" if m[1] == "BASEMENT" else ("Ground Floor" if m[1] == "GROUND" else f"{ORD_NAME[ORDINAL[m[1]]]} Floor"))
    for m in re.finditer(r"\bLEVEL\s+(\d{1,2})\b", t):
        found.add(f"Level {m[1]}")
    for m in re.finditer(r"(?<![\d])(\d{1,2})階", t):
        found.add(f"{m[1]}階")
    return found.pop() if len(found) == 1 else None


TRAVEL = re.compile(rf"\bTRAVEL\s+DIST(?:ANCE|\.)?\s*(?:=|:|IS)?\s*(?P<len>{LEN})|(?P<len2>{LEN})\s+TRAVEL\s+DIST(?:ANCE|\.)?\b|\bT\.\s?D\.\s*[:=]?\s*(?P<len3>{LEN})", re.I)
# a travel-distance arrow's label in both units, "137 FT./41.75 M"; when one half is unreadable
# ("153 FT. / .65") the other is kept and the unreadable half skipped
DUAL = re.compile(r"(?<![\d.])(?P<a>\d+(?:\.\d+)?\s*(?:FT\b\.?|'))\s*/\s*(?P<b>[\d.]+\s*(?:M\b\.?)?)"
                  r"|(?<![\d.])(?P<c>\d+(?:\.\d+)?\s*M\b\.?)\s*/\s*(?P<d>[\d.]+\s*(?:FT\b\.?|')?)", re.I)
OCC_LOAD = re.compile(r"\bOCC(?:UPANT|\.)?\s*LOAD\s*(?:=|:|IS)?\s*(?P<n>\d{1,5})\b(?!\s*(?:SF|SQ|/))|定員\s*[:=＝]?\s*(?P<j>\d{1,5})\s*人?", re.I)
EXITS = re.compile(r"\b(?:NUMBER\s+OF\s+EXITS|EXITS)\s+PROVIDED\s*[:=]?\s*(?P<n>\d{1,2})\b|\b(?P<m>\d{1,2})\s+EXITS\s+PROVIDED\b", re.I)


def read_life_safety(r: Reading, sheet: Sheet, ls: list[Line], ph: list[Line], tags: list[tuple]) -> None:
    storey = storey_of(sheet.title)
    legend = next((l for l in ph if re.search(r"TRAVEL\s+DISTANCE", l.text, re.I)), None)
    distances = []
    for l in ph:
        for m in TRAVEL.finditer(l.text):
            g, txt = _len_of(m, "len", "len2", "len3")
            distances.append((l, m.start(), m.end(), [m[g]], m[0], None))
    if legend is not None:
        legend_note = f'legend on the sheet: "{_q(legend.text)}"'
        for l in ls:
            for m in DUAL.finditer(l.text):
                s, e = m.start(), m.end()
                if True:
                    parts = [m["a"] or m["c"]]
                    other = (m["b"] or m["d"]).strip()
                    if length(other):
                        parts.append(other)
                    else:
                        r.skip(l.at(s, e), l.text[s:e], f"travel distance: second unit \"{other}\" not readable, first kept")
                    distances.append((l, s, e, parts, l.text[s:e], legend_note))
    found = []
    for l, s, e, parts, quote, why in distances:
        if LIMIT.search(l.text[max(0, s - 12):e + 12]) and why is None:
            r.skip(l.at(s, e), quote, "travel distance: stated limit (MIN/MAX), not a measurement")
            continue
        at, ok = _confident(r, l, s, e, "travel distance")
        if not ok:
            continue
        ivs = [length(p) for p in parts]
        if not all(ivs):
            r.skip(at, quote, "travel distance: length not readable")
            continue
        found.append((ivs, at, quote, why))
    if found:
        if storey is None:
            for _, at, quote, _ in found:
                r.skip(at, quote, "travel distance: the sheet title names no single storey to attach it to")
        else:
            from normir.quantity import Quantity
            # The longest annotated route is the storey's longest travel distance, and the
            # travel distance of the floor area as a whole (a Space, as vocab/bim.yaml allows).
            ivs, at, quote, why = max(found, key=lambda f: Quantity.parse(f[0][0][1]).base)
            extra = f"longest of {len(found)} travel-distance annotations" if len(found) > 1 else "travel-distance annotation"
            st = r.element("Storey", f"storey:{storey}", at)
            floor = r.element("Space", f"space:{storey}", at)
            for iv in ivs:
                r.add(st, "max_travel_distance", _interval(iv, at, quote, extra + (f"; {why}" if why else "")))
                r.add(floor, "travel_distance", _interval(iv, at, quote, f"floor area of the {storey}, " + extra + (f"; {why}" if why else "")))
            r.add(floor, "storey", _one(storey, at, sheet.title or storey))
    for l in ph:
        for m in EXITS.finditer(l.text):
            n = int(m["n"] or m["m"])
            at, ok = _confident(r, l, m.start(), m.end(), "exits provided")
            if ok and storey:
                r.add(r.element("Storey", f"storey:{storey}", at), "exits", _one(n, at, m[0]))
            elif ok:
                r.skip(at, m[0], "exits provided: the sheet title names no single storey to attach it to")
        for m in OCC_LOAD.finditer(l.text):
            n = int(m["n"] or m["j"])
            at, ok = _confident(r, l, m.start(), m.end(), "occupant load")
            if not ok:
                continue
            b = l.part(m.start(), m.end())[0]
            near = [t for t in tags if _dist(t[2], b) < 6 * l.height]
            if near:
                tag = min(near, key=lambda t: _dist(t[2], b))
                r.add(r.element("Space", f"space:{tag[0]}", at), "stated_occupant_load", _one(n, at, m[0]))
            else:
                r.skip(at, m[0], "occupant load: no room tag next to it to attach it to")


def _height(t: Token) -> float:
    f = _frame(t)
    return f[3] - f[2]


def _dist(a: BBox, b: BBox) -> float:
    dx = max(0.0, max(a[0], b[0]) - min(a[2], b[2]))
    dy = max(0.0, max(a[1], b[1]) - min(a[3], b[3]))
    return (dx * dx + dy * dy) ** 0.5


# --- room tags ---------------------------------------------------------------------------

ROOM_NUMBER = re.compile(r"^(?:\d[A-Z]{1,2}\d{1,3}[A-Z]?|[A-Z]?\d{3,4}[A-Z]?)$")
ROOM_NAME = re.compile(r"^(?=.*[A-Z]{2})[A-Z][A-Z0-9.&/,' -]*$")
NOT_ROOM = re.compile(r"^(?:UP|DN|DOWN|EQ|TYP|SIM|REV|NOTE|SEE|SCALE|SHEET|DETAIL|SECTION|ELEVATION|PLAN|LEGEND|EXIT|FIRE|N|S|E|W)\.?$", re.I)
# A tag number with letters in it (1A03, 2AC2) is a room number; a bare 3-4 digit number is
# just as often a dimension (metric) or a note's number, so it counts only under a room word.
CODED_ROOM_NUMBER = re.compile(r"^\d[A-Z]{1,3}\d{1,3}[A-Z]?$")
ROOM_WORDS = re.compile(r"\b(?:OFFICE|ROOM|RM|TOILET|TLT|WC|CORRIDOR|CORR|HALL|LOBBY|STAIR|STOR(?:AGE|E)?|STO|CLOSET|CL|JAN(?:ITOR)?|"
                        r"MECH(?:ANICAL)?|ELEC(?:TRICAL)?|CONFERENCE|CONF|WAITING|RECEPT(?:ION)?|EXAM|LAB|LOUNGE|KITCHEN|BREAK|"
                        r"VESTIBULE|VEST|ENTRY|DRESS|LOCKER|SHOWER|WORK|COPY|FILE|RECORDS|CLASSROOM|BEDROOM|BATH|LIVING|DINING|"
                        r"GARAGE|LAUNDRY|UTILITY|UTL|ELEVATOR|ELEV|SHAFT|LOADING|PHARMACY|PHARM)\b\.?")
PLAN_TITLE = re.compile(r"PLAN|平面図", re.I)
JP_ROOM = re.compile(r"^[぀-ヿ㐀-鿿A-Za-z0-9・()（）\-]*[㐀-鿿ァ-ヿ][぀-ヿ㐀-鿿A-Za-z0-9・()（）\-]*$")


def _centred(l: Line, cx: float, h: float) -> bool:
    return abs((l.bbox[0] + l.bbox[2]) / 2 - cx) <= max(1.0 * h, 0.15 * (l.bbox[2] - l.bbox[0]))


def room_tags(ls: list[Line]) -> list[tuple[str, str | None, BBox, list[Line], tuple | None]]:
    """Room tags on plans: a room name with the room number directly under it (and the
    area under that, when printed). Returns (number, name, bbox, lines, area_line)."""
    up = [l for l in ls if l.angle == 0]
    nums = [l for l in up if ROOM_NUMBER.match(l.text) and min(t.confidence for t in l.tokens) >= MIN_CONFIDENCE]
    coded = lambda n: bool(CODED_ROOM_NUMBER.match(n.text))
    out = []
    for n in nums:
        h = n.height
        cx = (n.bbox[0] + n.bbox[2]) / 2
        # a tag's lines are centred on one another; a left-aligned note above a number is not a tag
        above = [l for l in up if l is not n and 0 <= n.bbox[1] - l.bbox[3] <= 0.9 * h and _centred(l, cx, h)
                 and 0.6 < l.height / max(h, 0.1) < 1.7]
        name_lines = []
        if above:
            first = min(above, key=lambda l: n.bbox[1] - l.bbox[3])
            if ROOM_NAME.match(first.text) and not NOT_ROOM.match(first.text) and not ROOM_NUMBER.match(first.text):
                name_lines = [first]
                more = [l for l in up if l is not first and 0 <= first.bbox[1] - l.bbox[3] <= 0.9 * h and _centred(l, cx, h)
                        and ROOM_NAME.match(l.text) and not NOT_ROOM.match(l.text) and 0.6 < l.height / max(h, 0.1) < 1.7]
                if more:
                    name_lines.insert(0, min(more, key=lambda l: first.bbox[1] - l.bbox[3]))
        if not name_lines or min(t.confidence for l in name_lines for t in l.tokens) < MIN_CONFIDENCE:
            continue
        if not coded(n) and not ROOM_WORDS.search(" ".join(l.text for l in name_lines)):
            continue
        below = [l for l in up if 0 <= l.bbox[1] - n.bbox[3] <= 0.9 * h and abs((l.bbox[0] + l.bbox[2]) / 2 - cx) <= 1.0 * max(l.bbox[2] - l.bbox[0], n.bbox[2] - n.bbox[0])]
        ar = next(((l, area(l.text)) for l in below if area(l.text)), None)
        name = " ".join(l.text for l in name_lines)
        out.append((n.text, name, union([n.bbox] + [l.bbox for l in name_lines]), name_lines + [n], ar))
    return out


JP_AREA = re.compile(r"^(?P<a>(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?\s*(?:M2|m2|㎡))$")


def read_rooms(r: Reading, ls: list[Line], tags) -> None:
    for number, name, bbox, tag_lines, ar in tags:
        sheet = tag_lines[0].sheet
        at = locator(sheet, bbox)
        e = r.element("Space", f"space:{number}", at)
        r.tagged.add(f"space:{number}")
        r.add(e, "number", _one(number, locator(sheet, tag_lines[-1].bbox), number))
        r.add(e, "name", _one(name, locator(sheet, union(l.bbox for l in tag_lines[:-1])), name))
        if ar:
            l, iv = ar
            if min(t.confidence for t in l.tokens) >= MIN_CONFIDENCE:
                r.add(e, "floor_area", _interval(iv, l.at(), l.text, "room area"))
    # Japanese room tags: 室名 with its area (面積) directly under it; such tags carry no number.
    up = [l for l in ls if l.angle == 0]
    for a in up:
        m = JP_AREA.match(norm(a.text))
        if not m or min(t.confidence for t in a.tokens) < MIN_CONFIDENCE:
            continue
        h = a.height
        cx = (a.bbox[0] + a.bbox[2]) / 2
        above = [l for l in up if l is not a and 0 <= a.bbox[1] - l.bbox[3] <= 1.0 * h
                 and abs((l.bbox[0] + l.bbox[2]) / 2 - cx) <= 0.6 * max(l.bbox[2] - l.bbox[0], a.bbox[2] - a.bbox[0])]
        if not above:
            continue
        nl = min(above, key=lambda l: a.bbox[1] - l.bbox[3])
        name = nl.text.replace(" ", "")
        if not JP_ROOM.match(name):
            continue
        iv = area(m["a"])
        e = r.element("Space", f"space:{name}", locator(a.sheet, union([nl.bbox, a.bbox])))
        r.add(e, "name", _one(name, nl.at(), nl.text))
        r.add(e, "floor_area", _interval(iv, a.at(), a.text, "room area"))


CORRIDOR = re.compile(rf"廊下(?:有効)?幅(?:員)?\s*[:=＝]?\s*(?P<len>{L_OR_BARE})|\bCORRIDOR\s+(?:CLEAR\s+)?WIDTH\s*[:=]?\s*(?P<len2>{LEN})", re.I)


def read_corridors(r: Reading, sheet: Sheet, ls: list[Line]) -> None:
    storey = storey_of(sheet.title)
    for l in ls:
        for m in CORRIDOR.finditer(l.text):
            g, txt = _len_of(m, "len", "len2")
            if LIMIT.search(l.text[max(0, m.start() - 12):m.end() + 12]):
                r.skip(l.at(m.start(), m.end()), m[0], "corridor width: stated limit (MIN/MAX), not a measurement")
                continue
            at, ok = _confident(r, l, m.start(), m.end(), "corridor width")
            iv = length(txt, bare=not re.search(r"[A-Za-z'\"]", norm(txt)))
            if not ok or not iv:
                continue
            cid = f"corridor:{(storey + ' ') if storey else ''}{sheet.number or sheet.file} {locator(sheet, l.part(m.start(), m.end())[0]).split('bbox=')[1]}"
            r.add(r.element("Corridor", cid, at), "clear_width", _interval(iv, at, m[0], "corridor width"))


# --- schedules ---------------------------------------------------------------------------

def _columns(head: list[Token], ls: list[Line]) -> list[tuple[str, float, float, list[Token]]]:
    """Columns of a schedule from the header row holding `head`: the row's words grouped
    into cells (a gap under a text height joins words), each with the header text stacked
    above it. Returns (title, x0, x1, tokens) left to right, x-ranges split at midpoints
    between neighbouring cells."""
    h = max(t.bbox[3] - t.bbox[1] for t in head)
    cy = sum((t.bbox[1] + t.bbox[3]) / 2 for t in head) / len(head)
    # header text sits in a band above the row (tokens compared by identity: Token's
    # dataclass equality compares every field, sheet included, and is slow on big schedules)
    upright = [t for l in ls if l.angle == 0 and cy - 12 * h < (l.bbox[1] + l.bbox[3]) / 2 < cy + h for t in l.tokens]
    row = sorted((t for t in upright if abs((t.bbox[1] + t.bbox[3]) / 2 - cy) < 0.5 * h), key=lambda t: t.bbox[0])
    groups: list[list[Token]] = []
    for t in row:
        if groups and t.bbox[0] - groups[-1][-1].bbox[2] < 0.8 * h:
            groups[-1].append(t)
        else:
            groups.append([t])
    cells = []
    for g in groups:
        x0, x1 = g[0].bbox[0], max(t.bbox[2] for t in g)
        stack, top = list(g), min(t.bbox[1] for t in g)
        seen = {id(t) for t in stack}
        while True:
            up = [u for u in upright if id(u) not in seen and 0 <= top - u.bbox[3] <= 0.9 * h
                  and u.bbox[2] > x0 - 0.3 * h and u.bbox[0] < x1 + 0.3 * h]
            if not up:
                break
            near = max(u.bbox[3] for u in up)
            band = sorted((u for u in up if near - u.bbox[3] < 0.5 * h), key=lambda u: u.bbox[0])
            stack = band + stack
            seen |= {id(u) for u in band}
            top = min(u.bbox[1] for u in band)
        cells.append((norm(" ".join(t.text for t in stack)).upper(), (x0 + x1) / 2, stack))
    out = []
    for i, (title, cx, stack) in enumerate(cells):
        a = (cells[i - 1][1] + cx) / 2 if i else -1e9
        b = (cx + cells[i + 1][1]) / 2 if i + 1 < len(cells) else 1e9
        out.append((title, a, b, stack))
    return out


DOOR_HEAD = re.compile(r"(?<![A-Z])(?:DOOR\s*(?:#|NO\.?|NUMBER|MARK)|MARK|NO\.?)(?![A-Z])")
DOOR_MARK = re.compile(r"^(?=.*\d)[A-Z0-9][A-Z0-9.\-]{0,7}$")
PAIR = re.compile(r"^(?:PR\.?|PAIR|\(2\)|2\s*[-@x]|2/)\s*", re.I)
NONE_CELL = re.compile(r"^(?:-|—|N/?A|NONE|\.)$", re.I)


def read_door_schedule(r: Reading, ls: list[Line]) -> None:
    for hl in ls:
        if hl.angle != 0:
            continue
        for m in DOOR_HEAD.finditer(hl.text.upper()):
            head = hl.part(m.start(), m.end())[2]
            tok = head[0]
            cols = _columns(head, ls)
            titles = [c[0].replace(" ", "") for c in cols]
            if not any("WIDTH" in t or t.startswith("SIZE") or t == "W" for t in titles):
                continue
            if not any(t.endswith(("DOOR#", "DOORNO.", "DOORNO", "DOORNUMBER", "DOORMARK", "MARK")) for t in titles):
                continue
            _door_rows(r, ls, tok, cols)


MARK_TITLES = ("DOOR#", "DOORNO.", "DOORNO", "DOORNUMBER", "DOORMARK", "MARK", "DOORMARK#")


def _door_rows(r: Reading, ls: list[Line], head: Token, cols) -> None:
    mark_col = next(c for c in cols if any(t is head for t in c[3]))
    if mark_col[0].replace(" ", "") not in MARK_TITLES:  # e.g. the NO. under JAMB in the same header row
        return
    h = head.bbox[3] - head.bbox[1]

    def col(*keys):
        return next((c for c in cols if any(k in c[0].replace(" ", "") for k in keys)), None)

    clear_c = col("CLEARWIDTH", "CLR")
    width_c = next((c for c in cols if "WIDTH" in c[0].replace(" ", "") and c is not clear_c), None) or col("SIZE")
    height_c = col("HEIGHT")
    fire_c = col("FIRERATING", "RATING", "LABEL", "FIRE")
    body = sorted((t for l in ls if l.angle == 0 for t in l.tokens if t.bbox[1] > head.bbox[3] - 0.2 * h), key=lambda t: t.bbox[1])

    def in_col(c, t):
        cx = (t.bbox[0] + t.bbox[2]) / 2
        return c is not None and c[1] <= cx < c[2]

    marks = [t for t in body if in_col(mark_col, t) and DOOR_MARK.match(norm(t.text).upper())]
    # a schedule ends where its mark column stops: no gap of more than three rows
    rows, last = [], head.bbox[3]
    for t in marks:
        if t.bbox[1] - last > 4 * h + 3 * (t.bbox[3] - t.bbox[1]):
            break
        rows.append(t)
        last = t.bbox[3]
    for m in rows:
        mark = norm(m.text).upper()
        cy, mh = (m.bbox[1] + m.bbox[3]) / 2, m.bbox[3] - m.bbox[1]
        row = [t for t in body if abs((t.bbox[1] + t.bbox[3]) / 2 - cy) <= 0.45 * mh]
        sheet = m.sheet
        if m.confidence < MIN_CONFIDENCE:
            r.skip(locator(sheet, m.bbox), m.text, f"door mark: low-confidence OCR ({m.confidence:.2f})")
            continue
        if m.source == "ocr" and re.search(r"\dO|O\d", mark):
            r.skip(locator(sheet, m.bbox), m.text, "door mark: OCR letter O next to a digit, could be 0")
            continue
        row_at = locator(sheet, union(t.bbox for t in row))
        e = r.element("Door", f"door:{mark}", row_at)
        r.add(e, "mark", _one(mark, locator(sheet, m.bbox), m.text))

        def cell(c):
            ts = sorted((t for t in row if in_col(c, t)), key=lambda t: t.bbox[0])
            if not ts:
                return None
            # A column whose header OCR missed (stacked vertical letters, as THICKNESS) falls
            # inside a neighbour's range; keep the entries under the header text itself.
            x0, x1 = min(u.bbox[0] for u in c[3]) - h, max(u.bbox[2] for u in c[3]) + h
            under = [t for t in ts if t.bbox[2] > x0 and t.bbox[0] < x1]
            return Line(under or ts)

        w = cell(width_c)
        if w is not None:
            txt = w.text
            conf = min(t.confidence for t in w.tokens)
            if conf < MIN_CONFIDENCE:
                r.skip(w.at(), txt, f"door {mark} width: low-confidence OCR ({conf:.2f})")
            else:
                leaves = 2 if PAIR.match(txt) else 1
                size = PAIR.sub("", txt).strip()
                if width_c[0].replace(" ", "").startswith("SIZE") and re.search(r"\s[xX]\s", size):
                    size, hgt = re.split(r"\s+[xX]\s+", size, maxsplit=1)
                else:
                    hgt = None
                iv = length(size, bare=True)
                if iv:
                    q = f"{txt}" + (" (pair: width is per leaf)" if leaves == 2 else "")
                    r.add(e, "leaf_width", _interval(iv, w.at(), q, "leaf width"))
                    r.add(e, "leaves", _one(leaves, w.at(), txt))
                    clear = cell(clear_c) if clear_c else None
                    civ = length(clear.text, bare=True) if clear is not None and min(t.confidence for t in clear.tokens) >= MIN_CONFIDENCE else None
                    if civ:
                        r.add(e, "clear_width", _interval(civ, clear.at(), clear.text, "clear width as scheduled"))
                    else:
                        r.add(e, "clear_width", _clear_from_leaf(iv, w.at(), txt))
                elif not NONE_CELL.match(txt):
                    r.skip(w.at(), txt, f"door {mark} width: not a readable length")
                if hgt:
                    hiv = length(hgt, bare=True)
                    if hiv:
                        r.add(e, "height", _interval(hiv, w.at(), txt, "height"))
        hc = cell(height_c)
        if hc is not None:
            conf = min(t.confidence for t in hc.tokens)
            iv = length(hc.text, bare=True)
            if conf < MIN_CONFIDENCE:
                r.skip(hc.at(), hc.text, f"door {mark} height: low-confidence OCR ({conf:.2f})")
            elif iv:
                r.add(e, "height", _interval(iv, hc.at(), hc.text, "height"))
            elif not NONE_CELL.match(hc.text):
                r.skip(hc.at(), hc.text, f"door {mark} height: not a readable length")
        fc = cell(fire_c)
        if fc is not None and not NONE_CELL.match(fc.text):
            conf = min(t.confidence for t in fc.tokens)
            if conf < MIN_CONFIDENCE:
                r.skip(fc.at(), fc.text, f"door {mark} fire rating: low-confidence OCR ({conf:.2f})")
            elif re.search(r"\d|HR|MIN|LABEL|[ABC]\b", fc.text, re.I):
                r.add(e, "fire_rating", _one(fc.text.upper(), fc.at(), fc.text))


def _clear_from_leaf(iv: tuple[str, str], at: str, quote: str) -> list[dict]:
    from normir.quantity import Quantity

    lo, hi = Quantity.parse(iv[0]), Quantity.parse(iv[1])
    mm = 25.4  # Quantity's base unit is the inch
    a = round(lo.base * mm - CLEAR_WIDTH_DEDUCTION_MM[1], 1)
    b = round(hi.base * mm - CLEAR_WIDTH_DEDUCTION_MM[0], 1)
    note = (f'"{_q(quote)}" leaf width less {CLEAR_WIDTH_DEDUCTION_MM[0]} to {CLEAR_WIDTH_DEDUCTION_MM[1]} mm for leaf thickness and stop '
            f"(no clear width scheduled; deduction as adapters/ifc.py)")
    return [{"value": f"{a:g} mm", "at": at, "note": note}, {"value": f"{b:g} mm", "at": at, "note": note}]


ROOM_HEAD = re.compile(r"(?<![A-Z])(?:ROOM\s*(?:NO\.?|#|NUMBER)|NO\.?|RM\.?\s*(?:NO\.?|#))(?![A-Z])")


def read_room_schedule(r: Reading, ls: list[Line]) -> list[tuple]:
    """Room rows of a finish or room schedule: number and name (and area if a column has it)."""
    tags = []
    for hl in ls:
        if hl.angle != 0:
            continue
        for m in ROOM_HEAD.finditer(hl.text.upper()):
            head = hl.part(m.start(), m.end())[2]
            tok = head[0]
            cols = _columns(head, ls)
            num_c = next(c for c in cols if any(t is tok for t in c[3]))
            if not num_c[0].replace(" ", "").startswith(("ROOM", "RM")):
                continue
            name_c = next((c for c in cols if c[0].replace(" ", "").endswith("ROOMNAME") or c[0] == "NAME"), None)
            area_c = next((c for c in cols if c[0].replace(" ", "") in ("AREA", "AREA(SF)", "AREA(M2)", "AREASF", "FLOORAREA")), None)
            if name_c is None:
                continue
            h = tok.bbox[3] - tok.bbox[1]
            body = sorted((t for l in ls if l.angle == 0 for t in l.tokens if t.bbox[1] > tok.bbox[3] - 0.2 * h), key=lambda t: t.bbox[1])

            def in_col(c, t):
                cx = (t.bbox[0] + t.bbox[2]) / 2
                return c[1] <= cx < c[2]

            last = tok.bbox[3]
            for n in (t for t in body if in_col(num_c, t) and ROOM_NUMBER.match(norm(t.text).upper())):
                if n.bbox[1] - last > 4 * h + 3 * (n.bbox[3] - n.bbox[1]):
                    break
                last = n.bbox[3]
                cy, nh = (n.bbox[1] + n.bbox[3]) / 2, n.bbox[3] - n.bbox[1]
                row = [t for t in body if abs((t.bbox[1] + t.bbox[3]) / 2 - cy) <= 0.45 * nh]
                names = sorted((t for t in row if in_col(name_c, t)), key=lambda t: t.bbox[0])
                if not names or n.confidence < MIN_CONFIDENCE or min(t.confidence for t in names) < MIN_CONFIDENCE:
                    if names:
                        r.skip(locator(n.sheet, union([n.bbox] + [t.bbox for t in names])), f"{n.text} {' '.join(t.text for t in names)}",
                               "room schedule row: low-confidence OCR")
                    continue
                nl = Line(names)
                if NONE_CELL.match(nl.text) or re.search(r"NOT\s*USED", nl.text, re.I):
                    continue
                number = norm(n.text).upper()
                e = r.element("Space", f"space:{number}", locator(n.sheet, union([n.bbox] + [t.bbox for t in names])))
                r.scheduled.add(f"space:{number}")
                r.add(e, "number", _one(number, locator(n.sheet, n.bbox), n.text))
                r.add(e, "name", _one(nl.text, nl.at(), nl.text))
                if area_c is not None:
                    ac = sorted((t for t in row if in_col(area_c, t)), key=lambda t: t.bbox[0])
                    if ac:
                        al = Line(ac)
                        unit = "M2" if "M2" in area_c[0].replace(" ", "") else "SF"
                        iv = area(al.text) or area(f"{al.text} {unit}")
                        if iv and min(t.confidence for t in ac) >= MIN_CONFIDENCE:
                            r.add(e, "floor_area", _interval(iv, al.at(), al.text, "room area"))
    return tags


# --- one sheet ---------------------------------------------------------------------------

def read(sheet: Sheet, tokens: list[Token]) -> Reading:
    """Every fact the sheet's text states. Sets sheet.number and sheet.title from the title block."""
    r = Reading()
    small = [t for t in tokens if t.source == "ocr" and _height(t) < MIN_OCR_TEXT_PT]
    if small:
        r.skipped.append({"at": locator(sheet, (0, 0, sheet.width, sheet.height)), "text": f"{len(small)} of {len(tokens)} tokens",
                          "reason": f"OCR text under {MIN_OCR_TEXT_PT:g} pt: too small to read reliably at the OCR resolution, not read for facts"})
        tokens = [t for t in tokens if not (t.source == "ocr" and _height(t) < MIN_OCR_TEXT_PT)]
    ls = lines(tokens)
    ph = phrases(ls)
    number, title, _ = title_block(sheet, ls)
    sheet.number = sheet.number or number
    sheet.title = sheet.title or title
    read_notes(r, ph)
    read_stairs(r, ph)
    # room tags are read on plans only: on details and schedules a word over a number is a note or a header
    tags = room_tags(ls) if PLAN_TITLE.search(sheet.title or "") else []
    read_rooms(r, ls, tags)
    read_life_safety(r, sheet, ls, ph, tags)
    read_corridors(r, sheet, ph)
    read_door_schedule(r, ls)
    read_room_schedule(r, ls)
    low = [t for t in tokens if t.confidence < MIN_CONFIDENCE]
    if low:
        r.skipped.append({"at": locator(sheet, (0, 0, sheet.width, sheet.height)), "text": f"{len(low)} of {len(tokens)} tokens",
                          "reason": f"low-confidence OCR (< {MIN_CONFIDENCE}): not read for facts"})
    return r
