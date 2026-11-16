"""Reading a customer's regulation document into numbered lines.

PDF (text layer, via pdfplumber), DOCX (word/document.xml with the standard library), HTML (html.parser), Markdown
and plain text. Every format comes out as a list of non-empty lines with normalised whitespace, numbered 1, 2, ...
in reading order; a PDF line also carries its page. The numbering is what clauses cite, so it depends only on the
file's bytes.
"""

from __future__ import annotations

import hashlib
import html as html_mod
import re
import unicodedata
import zipfile
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from xml.etree import ElementTree as ET

MAX_BYTES = 50_000_000
KINDS = {".pdf": "pdf", ".docx": "docx", ".html": "html", ".htm": "html", ".xhtml": "html",
         ".md": "md", ".markdown": "md", ".txt": "txt", ".text": "txt", ".rst": "txt"}
LEGACY = {".doc": "save it as .docx", ".rtf": "save it as .docx or PDF", ".odt": "save it as .docx or PDF",
          ".pages": "export it as PDF", ".xls": "export it as PDF", ".xlsx": "export it as PDF"}
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"   # an encrypted .docx is an OLE container, as is a legacy .doc


class RegulationError(RuntimeError):
    """A problem with the customer's document or the compilation, with a message meant for the user."""


@dataclass
class Line:
    no: int            # 1-based within the file, counting kept (non-empty) lines
    page: int | None   # PDF page, from 1
    text: str


@dataclass
class Document:
    file: str
    sha256: str
    kind: str          # pdf | docx | html | md | txt
    pages: int | None
    lines: list[Line]


# ---------------------------------------------------------------- normalisation

_INVISIBLE = dict.fromkeys(map(ord, "\u00ad\u200b\u200c\u200d\u2060\ufeff"), None)


def _clean(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(_INVISIBLE)
    # Symbol-font bullets (Wingdings, Symbol) come out as private-use code points.
    text = "".join("•" if unicodedata.category(c) == "Co" else " " if unicodedata.category(c) == "Cc" else c for c in text)
    text = re.sub(r"(?:\. ?){5,}|…{2,}", " … ", text)   # table-of-contents leader dots
    return re.sub(r"\s+", " ", text).strip()


def _number(rows: list[tuple[int | None, str]]) -> list[Line]:
    out = []
    for page, raw in rows:
        text = _clean(raw)
        if text:
            out.append(Line(len(out) + 1, page, text))
    return out


def _decode(data: bytes, rel: str, html: bool = False) -> str:
    for bom, enc in ((b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16")):
        if data.startswith(bom):
            return data.decode(enc, errors="replace")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        m = re.search(rb"""<meta[^>]+charset=["']?([\w-]+)""", data[:4096], re.I) if html else None
        enc = m.group(1).decode("ascii", "replace") if m else None
        if enc is None:   # undeclared: detect it (Shift_JIS, GB18030, cp1252...) rather than assume Western European
            from charset_normalizer import from_bytes
            best = from_bytes(data).best()
            enc = best.encoding if best is not None else "cp1252"
        try:
            text = data.decode(enc, errors="replace")
        except LookupError:
            text = data.decode("cp1252", errors="replace")
        if text.count("\ufffd") > max(3, len(text) // 200):
            raise RegulationError(f"{rel}: the text encoding could not be recognised; save it as UTF-8")
    if "\x00" in text:
        raise RegulationError(f"{rel} does not look like a text file (it contains binary data)")
    return text


# ---------------------------------------------------------------- PDF

def _pdf(path: Path, rel: str) -> tuple[list[tuple[int | None, str]], int]:
    import pdfplumber

    try:
        pdf = pdfplumber.open(path)
    except Exception as e:  # pdfminer raises many types; the class name says whether it is encryption
        name = type(e).__name__
        if "Password" in name or "Encrypt" in name:
            raise RegulationError(f"{rel} is encrypted (password-protected); upload an unprotected copy") from e
        raise RegulationError(f"{rel} could not be read as a PDF ({name}); the file may be damaged") from e
    pages: list[list[str]] = []
    try:
        with pdf:
            for page in pdf.pages:
                pages.append(_page_text(page))
    except Exception as e:
        name = type(e).__name__
        if "Password" in name or "Encrypt" in name:
            raise RegulationError(f"{rel} is encrypted (password-protected); upload an unprotected copy") from e
        raise RegulationError(f"{rel} could not be read as a PDF ({name}); the file may be damaged") from e
    if not any(_clean(t) for p in pages for t in p):
        raise RegulationError(f"{rel} has no text layer; scanned PDFs are not supported yet")
    repeated = _running_heads(pages)
    rows = [(i + 1, t) for i, p in enumerate(pages) for t in p if _shape(t) not in repeated]
    return rows, len(pages)


RUN = re.compile(r"[A-Za-z,.;:()'’-]{22,}")
LONE = re.compile(r"[b-hj-zB-HJ-Z]")


def _malformed(lines: list[str]) -> int:
    """Tokens that are not words: letters run together with no spaces, or a word split into single letters."""
    words = [w for t in lines for w in t.split()]
    return sum(1 for w in words if (RUN.fullmatch(w) and not re.search(r"https?|www\.|\.(gov|org|com|net)", w)) or LONE.fullmatch(w))


def _page_text(page) -> list[str]:
    """A page's lines. Where most of the page is upright, rotated text (a margin note running up the side, a
    diagonal watermark) is left out. Words are split at gaps wider than a fixed 3 points; when that reading has
    malformed tokens, readings with glyphs drawn twice in one place (fake bold) counted once, and with gaps judged
    against 15% of the font size (PDFs that set spaces as narrow gaps), are tried too, and the one with the fewest
    malformed tokens is kept."""
    chars = page.chars
    if chars and sum(1 for c in chars if c.get("upright", True)) >= 0.5 * len(chars):
        page = page.filter(lambda o: o.get("object_type") != "char" or o.get("upright", True))
    best = (page.extract_text() or "").split("\n")
    bad = _malformed(best)
    if bad:
        once = page.dedupe_chars()
        for kw_page, kw in ((once, {}), (once, {"x_tolerance_ratio": 0.15})):
            lines = (kw_page.extract_text(**kw) or "").split("\n")
            n = _malformed(lines)
            if n < bad:
                best, bad = lines, n
    return best


def _shape(text: str) -> str:
    return re.sub(r"\d+", "#", _clean(text)).lower()


def _running_heads(pages: list[list[str]]) -> set[str]:
    """Page headers and footers: a line among the first or last two lines of at least 60% of the pages, in a
    document of three pages or more. Its numbers may differ between pages only as page numbers do: from one page
    to a later one each rises by no more than the pages passed and never falls, unless a number before it changed
    ('3-12' after '2-30'). A heading whose number jumps ('Article 7', 'Article 14' on consecutive pages) is text;
    a line with no words is furniture."""
    if len(pages) < 3:
        return set()
    seen: dict[str, list[tuple[int, list[int]]]] = {}
    for i, p in enumerate(pages):
        kept = [t for t in p if _clean(t)]
        for t in {t: None for t in kept[:2] + kept[-2:]}:
            seen.setdefault(_shape(t), []).append((i, [int(n) for n in re.findall(r"\d+", _clean(t))]))
    out = set()
    for s, occ in seen.items():
        if not s or len({i for i, _ in occ}) < max(3, 0.6 * len(pages)):
            continue
        # a line of numbers alone is page furniture however they run (a reader may double a glyph: '1111' for 11)
        if not re.search(r"[^\W\d_#]", s) or all(_paged(a, b) for a, b in zip(occ, occ[1:])):
            out.add(s)
    return out


def _paged(a: tuple[int, list[int]], b: tuple[int, list[int]]) -> bool:
    """Whether the numbers of a line on page b[0] can follow those on page a[0] as page numbering does."""
    gap = b[0] - a[0]
    for x, y in zip(a[1], b[1]):
        if not 0 <= y - x <= gap:
            return False
        if y != x:
            return True   # later numbers may restart: a chapter-page number after a new chapter
    return True


# ---------------------------------------------------------------- DOCX

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _roman(n: int) -> str:
    out = ""
    for v, s in ((1000, "m"), (900, "cm"), (500, "d"), (400, "cd"), (100, "c"), (90, "xc"), (50, "l"), (40, "xl"),
                 (10, "x"), (9, "ix"), (5, "v"), (4, "iv"), (1, "i")):
        while n >= v:
            out, n = out + s, n - v
    return out


def _letter(n: int) -> str:
    return chr(ord("a") + (n - 1) % 26) * ((n - 1) // 26 + 1) if n > 0 else ""


def _fmt(fmt: str, n: int) -> str:
    return {"lowerLetter": _letter(n), "upperLetter": _letter(n).upper(), "lowerRoman": _roman(n),
            "upperRoman": _roman(n).upper(), "decimalZero": f"{n:02d}", "bullet": "•", "none": ""}.get(fmt, str(n))


class _Numbering:
    """Word list numbering: numbering.xml defines the levels of each list, paragraphs (or their styles) say which
    list and level they are in, and the printed label ('4.2.1', 'a)') is computed by counting."""

    def __init__(self, numbering: ET.Element | None, styles: ET.Element | None):
        self.levels: dict[str, dict[int, tuple[str, str, int]]] = {}
        self.abstract_of: dict[str, str] = {}
        self.counters: dict[str, dict[int, int]] = {}
        self.style_num: dict[str, tuple[str, int]] = {}
        if numbering is not None:
            for a in numbering.iter(W + "abstractNum"):
                lv = {}
                for lvl in a.iter(W + "lvl"):
                    fmt, text, start = lvl.find(W + "numFmt"), lvl.find(W + "lvlText"), lvl.find(W + "start")
                    lv[int(lvl.get(W + "ilvl", "0"))] = (fmt.get(W + "val", "decimal") if fmt is not None else "decimal",
                                                       text.get(W + "val", "") if text is not None else "",
                                                       int(start.get(W + "val", "1")) if start is not None else 1)
                self.levels[a.get(W + "abstractNumId")] = lv
            for n in numbering.iter(W + "num"):
                a = n.find(W + "abstractNumId")
                if a is not None:
                    self.abstract_of[n.get(W + "numId")] = a.get(W + "val")
        if styles is not None:
            based, direct = {}, {}
            for s in styles.iter(W + "style"):
                sid = s.get(W + "styleId")
                b = s.find(W + "basedOn")
                if b is not None:
                    based[sid] = b.get(W + "val")
                np = s.find(f"{W}pPr/{W}numPr")
                if np is not None:
                    direct[sid] = self._numpr(np, (None, 0))
            for sid in set(based) | set(direct):
                seen, cur = set(), sid
                while cur and cur not in direct and cur not in seen:
                    seen.add(cur)
                    cur = based.get(cur)
                if cur in direct and direct[cur][0]:
                    self.style_num[sid] = direct[cur]

    @staticmethod
    def _numpr(np: ET.Element, default: tuple) -> tuple:
        nid, ilvl = np.find(W + "numId"), np.find(W + "ilvl")
        return (nid.get(W + "val") if nid is not None else default[0],
                int(ilvl.get(W + "val", "0")) if ilvl is not None else default[1])

    def label(self, p: ET.Element) -> str:
        ppr = p.find(W + "pPr")
        style = ppr.find(W + "pStyle") if ppr is not None else None
        num = self.style_num.get(style.get(W + "val")) if style is not None else None
        np = ppr.find(W + "numPr") if ppr is not None else None
        if np is not None:
            num = self._numpr(np, num or (None, 0))
        if not num or not num[0] or num[0] == "0" or num[0] not in self.abstract_of:
            return ""
        aid, ilvl = self.abstract_of[num[0]], num[1]
        levels = self.levels.get(aid, {})
        if ilvl not in levels:
            return ""
        c = self.counters.setdefault(aid, {})
        c[ilvl] = c.get(ilvl, levels[ilvl][2] - 1) + 1
        for deeper in [k for k in c if k > ilvl]:
            del c[deeper]
        fmt, text, _ = levels[ilvl]
        if fmt == "bullet":
            return "•"

        def sub(m: re.Match) -> str:
            k = int(m.group(1)) - 1
            f, _, start = levels.get(k, ("decimal", "", 1))
            return _fmt(f, c.get(k, start))
        return re.sub(r"%(\d)", sub, text).strip()


def _paragraph(p: ET.Element, numbering: _Numbering) -> list[str]:
    parts: list[str] = []
    for el in p.iter():
        if el.tag == W + "t" and el.text:
            parts.append(el.text)
        elif el.tag in (W + "tab", W + "noBreakHyphen"):
            parts.append(" " if el.tag == W + "tab" else "-")
        elif el.tag in (W + "br", W + "cr"):
            parts.append("\n")
    text = "".join(parts)
    label = numbering.label(p) if text.strip() else ""
    rows = text.split("\n")
    if label:
        rows[0] = f"{label} {rows[0].strip()}"
    return rows


def _docx_blocks(parent: ET.Element, numbering: _Numbering, out: list[str]) -> None:
    for el in parent:
        if el.tag == W + "p":
            out.extend(_paragraph(el, numbering))
        elif el.tag == W + "tbl":
            for tr in el.iter(W + "tr"):   # a row is one line, its cells joined by " | ", as in HTML
                cells = []
                for tc in tr.findall(W + "tc"):
                    cell: list[str] = []
                    for p in tc.iter(W + "p"):
                        cell.extend(_paragraph(p, numbering))
                    cells.append(" ".join(c.strip() for c in cell if c.strip()))
                out.append(" | ".join(cells))
        elif el.tag in (W + "sdt", W + "sdtContent", W + "customXml", W + "ins"):
            _docx_blocks(el, numbering, out)


def _docx(path: Path, rel: str) -> list[tuple[int | None, str]]:
    with path.open("rb") as f:
        if f.read(8) == OLE_MAGIC:
            raise RegulationError(f"{rel} is encrypted (password-protected) or a legacy Word file; "
                                  "upload an unprotected .docx or a PDF")
    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
            if "word/document.xml" not in names:
                raise RegulationError(f"{rel} is not a Word document (no word/document.xml)")
            doc = ET.fromstring(z.read("word/document.xml"))
            numbering = ET.fromstring(z.read("word/numbering.xml")) if "word/numbering.xml" in names else None
            styles = ET.fromstring(z.read("word/styles.xml")) if "word/styles.xml" in names else None
    except zipfile.BadZipFile as e:
        raise RegulationError(f"{rel} could not be read as a .docx file (not a valid zip archive)") from e
    except ET.ParseError as e:
        raise RegulationError(f"{rel} could not be read: its document XML is damaged ({e})") from e
    body = doc.find(W + "body")
    out: list[str] = []
    if body is not None:
        _docx_blocks(body, _Numbering(numbering, styles), out)
    return [(None, t) for t in out]


# ---------------------------------------------------------------- HTML

BLOCK = {"address", "article", "aside", "blockquote", "caption", "dd", "details", "dialog", "div", "dl", "dt",
         "fieldset", "figcaption", "figure", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li",
         "main", "ol", "p", "pre", "section", "summary", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "ul",
         "body", "html", "br", "legend", "option"}
SKIP = {"script", "style", "noscript", "template", "svg", "head", "nav", "iframe", "object", "canvas", "math",
        "button", "select"}
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


LANDMARKS = {"navigation", "banner", "contentinfo", "search", "menu", "menubar", "toolbar"}
CELLS = {"td", "th"}


class _Html(HTMLParser):
    """Text in reading order, a block element per line. A table row is one line with its cells joined by " | ", so a
    row's label stays with its values. Site furniture (role navigation, banner, contentinfo or search; <footer>;
    aria-hidden) is left out."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[str] = []
        self.buf: list[str] = []
        self.skip = 0
        self.pre = 0
        self.lists: list[int | None] = []   # an ordered list's next number, None for a bullet list
        self.label = ""                      # a list item's number, written before its first text
        self.open: list[tuple[str, bool]] = []   # open elements: (tag, starts site furniture)
        self.furniture = 0
        self.cells: list[int] = []           # per open table row: cells started so far
        self.incell = 0

    def flush(self) -> None:
        text = "".join(self.buf)
        self.buf = []
        self.rows.extend(text.split("\n") if self.pre else [text])

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in SKIP:
            self.skip += tag not in VOID
            return
        if tag not in VOID:
            starts = not self.furniture and (tag == "footer" or (a.get("role") or "").lower() in LANDMARKS
                                             or (a.get("aria-hidden") or "").lower() == "true")
            self.open.append((tag, starts))
            self.furniture += starts
        if self.skip or self.furniture:
            return
        if tag == "tr":
            self.flush()
            self.cells.append(0)
            return
        if tag in CELLS and self.cells:
            if self.cells[-1]:
                self.buf.append(" | ")
            self.cells[-1] += 1
            self.incell += 1
            return
        if tag == "sup":
            self.buf.append(" ")
        if tag in BLOCK:
            if self.incell and tag != "pre":
                self.buf.append(" ")   # a paragraph or line break inside a cell stays in the row
            else:
                self.flush()
        if tag == "pre":
            self.pre += 1
        if tag in ("ol", "ul"):
            start = a.get("start")
            self.lists.append((int(start) if start and start.isdigit() else 1) if tag == "ol" else None)
        if tag == "li":
            if self.lists and self.lists[-1] is not None:
                self.label = f"{self.lists[-1]}. "
                self.lists[-1] += 1
            else:
                self.label = "• "

    def handle_endtag(self, tag):
        if tag in SKIP:
            self.skip = max(0, self.skip - 1)
            return
        if any(t == tag for t, _ in self.open):     # close it and anything left open inside it
            while self.open:
                t, starts = self.open.pop()
                self.furniture -= starts
                if t == tag:
                    break
        if self.skip or self.furniture:
            return
        if tag == "tr" and self.cells:
            self.cells.pop()
            self.incell = 0
            self.flush()
            return
        if tag in CELLS and self.incell:
            self.incell -= 1
            return
        if tag == "sup":
            self.buf.append(" ")
        if tag in BLOCK:
            if self.incell and tag != "pre":
                self.buf.append(" ")
            else:
                self.flush()
        if tag == "pre":
            self.pre = max(0, self.pre - 1)
        if tag in ("ol", "ul") and self.lists:
            self.lists.pop()
        if tag == "table":
            self.cells, self.incell = [], 0

    def handle_data(self, data):
        if self.skip or self.furniture:
            return
        if self.label and data.strip():
            self.buf.append(self.label)
            self.label = ""
        self.buf.append(data if self.pre else data.replace("\n", " "))


def _html(text: str) -> list[tuple[int | None, str]]:
    p = _Html()
    p.feed(text)
    p.close()
    p.flush()
    return [(None, t) for t in p.rows]


# ---------------------------------------------------------------- Markdown

TEMPLATE = re.compile(r"\{%-?.*?-?%\}|\{\{[<%].*?[>%]\}\}", re.S)   # Liquid/Jinja tags, Hugo shortcodes
HTML_LINE = re.compile(r"^\s*</?[A-Za-z][\w-]*(\s[^>]*)?/?>")


def _markdown(text: str) -> list[tuple[int | None, str]]:
    """Markdown as lines. Comments and template directives are dropped; a run of lines that are HTML (a table
    written as HTML) is read as HTML, so its rows stay rows; other inline tags are dropped, their text kept."""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = TEMPLATE.sub("", text)
    out: list[tuple[int | None, str]] = []
    block: list[str] = []
    depth = 0
    for row in text.splitlines():
        opens = len(re.findall(r"<(table|ul|ol|dl|div|details)\b", row, re.I))
        closes = len(re.findall(r"</(table|ul|ol|dl|div|details)>", row, re.I))
        if depth or HTML_LINE.match(row):
            block.append(row)
            depth = max(0, depth + opens - closes)
            if not depth:
                out += _html("\n".join(block))
                block = []
            continue
        out.append((None, html_mod.unescape(re.sub(r"</?[A-Za-z][\w-]*(\s[^>]*)?/?>", "", row))))
    if block:
        out += _html("\n".join(block))
    return out


# ---------------------------------------------------------------- entry point

def read(path: Path, rel: str) -> Document:
    """The document at `path` as numbered lines; `rel` is the name it is cited by (an upload's file name)."""
    path = Path(path)
    suffix = Path(rel).suffix.lower() or path.suffix.lower()
    kind = KINDS.get(suffix)
    if kind is None:
        hint = LEGACY.get(suffix)
        raise RegulationError(f"{rel}: unsupported file type '{suffix or '(none)'}'"
                              + (f"; {hint}" if hint else "; upload a PDF, Word (.docx), HTML, Markdown or text file"))
    try:
        data = path.read_bytes()
    except OSError as e:
        raise RegulationError(f"{rel} could not be read ({e.strerror or e})") from e
    if not data:
        raise RegulationError(f"{rel} is empty")
    if len(data) > MAX_BYTES:
        raise RegulationError(f"{rel} is too large ({len(data) // 1_000_000} MB; the limit is {MAX_BYTES // 1_000_000} MB)")
    pages = None
    if kind == "pdf":
        if not data.lstrip()[:5] == b"%PDF-":
            raise RegulationError(f"{rel} is not a PDF file")
        rows, pages = _pdf(path, rel)
    elif kind == "docx":
        rows = _docx(path, rel)
    elif kind == "html":
        rows = _html(_decode(data, rel, html=True))
    elif kind == "md":
        rows = _markdown(_decode(data, rel))
    else:
        rows = [(None, t) for t in _decode(data, rel).splitlines()]
    lines = _number(rows)
    if not lines:
        raise RegulationError(f"{rel} contains no text")
    return Document(rel, hashlib.sha256(data).hexdigest(), kind, pages, lines)
