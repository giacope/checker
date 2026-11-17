#!/usr/bin/env python3
"""Fuzzer for the input readers: regulation documents, uploads and zips, IFC, DXF, PDF/image sheets, code repositories,
evidence documents and rule packs.

    uv run python bench/fuzz_inputs.py --target regulation --cases 500 --seed 1
    uv run --with ifcopenshell python bench/fuzz_inputs.py --target ifc --cases 200 --seed 1
    uv run python bench/fuzz_inputs.py --repro <target> <repro file>      # replay one saved input
    uv run python bench/fuzz_inputs.py --report                           # merge the per-target results into REPORT.md

Targets: regulation, upload, zips, ifc, dxf, drawings, code, evidence, pack. The first cases of every target are
hand-written adversarial inputs (in a fixed order); the rest mutate real seeds (the regulation PDFs, the IFC models,
the DXF drawings and drawing sheets under .amp/in/orb-backup/inputs, the seed repositories, bench/evidence, packs/):
truncation, byte flips, chunk duplication, NULs and control characters, swapped chunks, extreme sizes, re-encoding,
and format-aware changes (STEP attributes, DXF group values, XML attributes, YAML type confusion). Every case is
derived from (--seed, target, case number), so a run is reproducible.

Each case runs in a forked child of a parent that has already imported the readers: RLIMIT_AS is the parent's address
space plus --mem-mb, faulthandler dumps the stack on a fatal signal and when the case passes --timeout, and the parent
kills it shortly after. A case is
  ok       valid output, or the documented error (RegulationError, ProjectError, ValueError from create(), a parser
           refusing the file at open: ifcopenshell.open, ezdxf, yaml)
  crash    any other exception, or death by a signal
  hang     over --timeout seconds
  memory   MemoryError, or killed near the memory cap
  garbage  output that is wrong without an error (see the oracles in each run_* function)
Problems are deduplicated by (class, exception type or symptom, innermost repository frame); the smallest input that
showed each one is saved under .amp/in/orb-backup/fuzz/<target>/ with the command that replays it.

No model is ever called: OPENAI_API_KEY and ANTHROPIC_API_KEY are removed, NORMIR_LLM_PROVIDER=none, HOME and
CODEX_HOME point to an empty directory (adapters.code_llm.codex_logged_in() reads $CODEX_HOME or ~/.codex/auth.json),
the model entry points are replaced by stubs that raise, and the OSV client of adapters.deps is disabled.
"""

from __future__ import annotations

import argparse
import atexit
import base64
import copy
import faulthandler
import io
import json
import os
import random
import re
import resource
import shutil
import signal
import stat
import struct
import sys
import tarfile
import tempfile
import time
import traceback
import zipfile
import zlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / ".amp" / "in" / "orb-backup" / "inputs"
OUT = ROOT / ".amp" / "in" / "orb-backup" / "fuzz"
# The source tree under test (code, packs, bench/evidence): the checkout, or a snapshot (FUZZ_SRC) so that a run is not
# disturbed by edits made to the checkout while it runs. Seeds and results stay in the checkout.
SRC = Path(os.environ.get("FUZZ_SRC") or ROOT).resolve()
SELF = Path(__file__).resolve()
TARGETS = ["regulation", "upload", "zips", "ifc", "dxf", "drawings", "code", "evidence", "pack"]

# ---------------------------------------------------------------- environment: no model, no network, no user state

# RLIMIT_AS caps address space, and glibc reserves 64 MB of it per thread for malloc arenas: onnxruntime's thread pool
# alone would use the cap up at ~200 MB RSS. Two arenas keep the cap about memory actually used. Read at startup only.
if os.environ.get("MALLOC_ARENA_MAX") != "2":
    os.environ["MALLOC_ARENA_MAX"] = "2"
    os.execv(sys.executable, [sys.executable, *sys.argv])

SANDBOX = Path(tempfile.mkdtemp(prefix="normir-fuzz-"))
_HOME = SANDBOX / "home"
_HOME.mkdir()
for _k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "NORMIR_LLM_MODEL", "GITHUB_TOKEN"):
    os.environ.pop(_k, None)
os.environ.update({"HOME": str(_HOME), "CODEX_HOME": str(_HOME / "no-codex"), "NORMIR_LLM_PROVIDER": "none",
                   "NORMIR_DATA": str(SANDBOX / "data"), "NORMIR_CACHE": str(SANDBOX / "cache"),
                   "XDG_CACHE_HOME": str(SANDBOX / "xdg")})
sys.path[:0] = [str(SRC), str(SRC / "engine")]


def _cleanup() -> None:
    if os.getpid() == _PARENT:
        shutil.rmtree(SANDBOX, ignore_errors=True)


_PARENT = os.getpid()
atexit.register(_cleanup)


def guard_models() -> str:
    """Replace every model entry point with a stub that raises, and confirm no provider is configured."""
    import adapters.code_llm as L

    def blocked(*a, **k):
        raise RuntimeError("fuzz_inputs: a model call was attempted")
    for name in ("complete", "_complete", "codex_complete"):
        if hasattr(L, name):
            setattr(L, name, blocked)
    if L.provider_from_env() is not None or L.codex_logged_in():
        sys.exit("fuzz_inputs: a model provider is configured; refusing to run")
    try:
        import adapters.deps as D
        D._client = blocked
    except ImportError:
        pass
    loaded = Path(L.__file__).resolve()
    if SRC not in loaded.parents:
        sys.exit(f"fuzz_inputs: adapters were imported from {loaded}, not from {SRC}")
    return (f"source under test: {SRC}; model guard: provider_from_env()={L.provider_from_env()} codex_logged_in()={L.codex_logged_in()} "
            f"HOME={os.environ['HOME']} NORMIR_LLM_PROVIDER={os.environ['NORMIR_LLM_PROVIDER']}")


# ---------------------------------------------------------------- small helpers

def src_line(rel: str, needle: str) -> str:
    """'path:line' of the first source line containing `needle` (for garbage findings, which have no traceback)."""
    try:
        for i, line in enumerate((SRC / rel).read_text().splitlines(), 1):
            if needle in line:
                return f"{rel}:{i}"
    except OSError:
        pass
    return rel


def put(case: "Case", rel: str, data: bytes | str) -> Path:
    p = case.inp / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data.encode() if isinstance(data, str) else data)
    return p


def issue(symptom: str, frame: str, detail: str = "") -> dict:
    return {"symptom": symptom, "frame": frame, "detail": detail[:600]}


def verdict(issues: list[dict], detail: str = "") -> dict:
    return {"class": "garbage" if issues else "ok", "issues": issues, "detail": detail}


def dir_bytes(p: Path) -> int:
    total = 0
    for dp, dns, fns in os.walk(p):
        for f in fns:
            try:
                total += os.lstat(os.path.join(dp, f)).st_size
            except OSError:
                pass
    return total


def walk_all(top: Path) -> set[str]:
    out = set()
    for dp, dns, fns in os.walk(top, followlinks=False):
        for n in dns + fns:
            out.add(os.path.join(dp, n))
    return out


NUMS = [b"0", b"-1", b"1", b"-0", b"2147483648", b"4294967296", b"18446744073709551616", b"1e308", b"1e309", b"-1e309",
        b"NaN", b"nan", b"inf", b"-inf", b"0.000000001", b"99999999999999999999999999", b"1.E400", b"-1.E400", b"0.", b"-"]
CTRL = [b"\x00", b"\x01", b"\x07", b"\x08", b"\x0b", b"\x0c", b"\x1b", b"\x7f", b"\r", b"\xc2\x85", b"\xe2\x80\xa8",
        b"\xe2\x80\xae", b"\xef\xbb\xbf", b"\xff", b"\xfe", b"\xc0\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80"]


def mutate_bytes(rng: random.Random, data: bytes, ops: int | None = None) -> tuple[bytes, str]:
    """1-4 generic mutations. Returns the bytes and the operations applied."""
    data = bytearray(data)
    done = []
    for _ in range(ops or rng.randint(1, 4)):
        n = len(data)
        if n == 0:
            data += b"\x00"
            continue
        op = rng.choice(["flip", "flip", "trunc", "dup", "nul", "ctrl", "swap", "delete", "num", "num", "repeat"])
        done.append(op)
        if op == "flip":
            for _ in range(rng.randint(1, 16)):
                i = rng.randrange(n)
                data[i] = data[i] ^ (1 << rng.randrange(8)) if rng.random() < 0.5 else rng.randrange(256)
        elif op == "trunc":
            data = data[:rng.randrange(n)]
        elif op == "dup":
            a = rng.randrange(n)
            chunk = bytes(data[a:a + rng.randint(1, 4096)]) * rng.choice([1, 1, 2, 16, 256])
            i = rng.randrange(n + 1)
            data[i:i] = chunk
        elif op == "nul":
            for _ in range(rng.randint(1, 4)):
                i = rng.randrange(len(data) + 1)
                data[i:i] = b"\x00" * rng.choice([1, 1, 4, 100])
        elif op == "ctrl":
            for _ in range(rng.randint(1, 8)):
                i = rng.randrange(len(data) + 1)
                data[i:i] = rng.choice(CTRL)
        elif op == "swap" and n > 16:
            k = rng.randint(1, min(1024, n // 4))
            a, b = sorted(rng.sample(range(n - k), 2)) if n - k > 2 else (0, 0)
            if b - a >= k:
                data[a:a + k], data[b:b + k] = data[b:b + k], data[a:a + k]
        elif op == "delete":
            a = rng.randrange(n)
            del data[a:a + rng.randint(1, 4096)]
        elif op == "num":
            start = rng.randrange(n)
            window = bytes(data[start:start + 4096])
            ms = list(re.finditer(rb"-?\d+(?:\.\d*)?(?:[eE][-+]?\d+)?", window))
            if ms:
                m = rng.choice(ms)
                data[start + m.start():start + m.end()] = rng.choice(NUMS)
        elif op == "repeat":
            i = rng.randrange(n)
            data[i:i] = bytes([data[i]]) * rng.choice([1000, 100_000])
    return bytes(data), "+".join(done)


ENCODINGS = ["utf-16", "utf-16-le", "utf-16-be", "utf-32", "cp1252", "latin-1", "shift_jis", "utf-8-sig", "crlf", "cr",
             "gb18030", "utf-7"]


def reencode(rng: random.Random, data: bytes, enc: str | None = None) -> tuple[bytes, str]:
    text = data.decode("utf-8", "replace")
    enc = enc or rng.choice(ENCODINGS)
    if enc == "crlf":
        return text.replace("\r\n", "\n").replace("\n", "\r\n").encode(), enc
    if enc == "cr":
        return text.replace("\r\n", "\n").replace("\n", "\r").encode(), enc
    return text.encode(enc, "replace"), enc


# ---------------------------------------------------------------- PDF, DOCX, PNG, zip builders

def _pdf_str(s: str) -> bytes:
    return b"(" + s.encode("latin-1", "replace").replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)") + b")"


def text_content(lines: list[str], size: float = 10, x: float = 72, y: float = 740, leading: float = 13) -> bytes:
    out = [f"BT /F1 {size} Tf {x} {y} Td {leading} TL".encode()]
    for t in lines:
        out.append(_pdf_str(t) + b" Tj T*")
    out.append(b"ET")
    return b"\n".join(out)


def pdf_stream(content: bytes, flate: bool = False, extra: str = "") -> bytes:
    if flate:
        content = zlib.compress(content)
        extra += " /Filter /FlateDecode"
    return f"<< /Length {len(content)}{extra} >>\nstream\n".encode() + content + b"\nendstream"


def make_pdf(pages: list[dict], objs: dict[int, bytes] | None = None, pages_obj: bytes | None = None,
             trailer_extra: str = "", flate: bool = False) -> bytes:
    """A PDF from page dicts {content, mediabox, extra, fonts}; object numbers 1-3 and 4.. are taken."""
    o: dict[int, bytes] = {1: b"<< /Type /Catalog /Pages 2 0 R >>",
                           3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"}
    kids, n = [], 4
    for p in pages:
        o[n + 1] = p["stream"] if "stream" in p else pdf_stream(p.get("content", b""), flate)
        o[n] = (f"<< /Type /Page /Parent 2 0 R /MediaBox [{p.get('mediabox', '0 0 612 792')}] "
                f"/Resources << /Font << /F1 3 0 R {p.get('fonts', '')} >> >> /Contents {n + 1} 0 R {p.get('extra', '')} >>").encode()
        kids.append(n)
        n += 2
    o[2] = pages_obj or f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] /Count {len(kids)} >>".encode()
    o.update(objs or {})
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offs = {}
    for k in sorted(o):
        offs[k] = len(out)
        out += f"{k} 0 obj\n".encode() + o[k] + b"\nendobj\n"
    xref, top = len(out), max(o)
    out += f"xref\n0 {top + 1}\n0000000000 65535 f \n".encode()
    for k in range(1, top + 1):
        out += (f"{offs[k]:010d} 00000 n \n" if k in offs else "0000000000 65535 f \n").encode()
    out += f"trailer\n<< /Size {top + 1} /Root 1 0 R {trailer_extra} >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def pdf_pages(path_or_bytes, pages: list[int]) -> bytes:
    """The given pages of a PDF as a new PDF (pypdfium2)."""
    import pypdfium2 as pdfium

    src = pdfium.PdfDocument(path_or_bytes)
    dst = pdfium.PdfDocument.new()
    dst.import_pages(src, [p for p in pages if p < len(src)])
    buf = io.BytesIO()
    dst.save(buf)
    dst.close()
    src.close()
    return buf.getvalue()


def drawing_content(H: float = 792, tokens: list | None = None) -> bytes:
    items = tokens or [
        (1080, 760, 14, "A-101"), (1080, 740, 9, "FIRST FLOOR PLAN"), (1080, 726, 7, "SCALE: 1/8\" = 1'-0\""),
        (300, 300, 7, "OFFICE"), (300, 310, 7, "101"), (520, 300, 7, "CORRIDOR"), (520, 310, 7, "102"),
        (400, 380, 6, "3'-0\" x 7'-0\""), (400, 390, 6, "DOOR 101"), (700, 300, 7, "STAIR 1"),
        (700, 312, 6, "18 R @ 7\" 17 T @ 11\""), (200, 600, 6, "44\" CLEAR"), (200, 620, 6, "OCCUPANT LOAD: 49"),
        (200, 640, 6, "TRAVEL DISTANCE 120'-0\""), (200, 660, 6, "OCCUPANCY GROUP B"), (850, 500, 6, "1200"),
        (850, 520, 6, "EXIT"), (600, 450, 6, "RAMP 1:12"), (620, 470, 6, "WIDTH 36\""),
    ]
    out = [b"0.5 w 100 100 m 1000 100 l 1000 700 l 100 700 l h S 450 100 m 450 700 l S 650 100 m 650 700 l S"]
    for x, y, s, t in items:
        out.append(f"BT /F1 {s} Tf {x} {H - y} Td ".encode() + _pdf_str(t) + b" Tj ET")
    return b"\n".join(out)


W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
CT = ('<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
      '<Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" '
      'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')


def _x(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def docx_parts(lines: list[str], ilvl: str = "1", start: str = "1", lvl_ilvl: str = "0", fmt0: str = "decimal",
               lvltext0: str = "%1.", nest: int = 0, body_extra: str = "") -> dict[str, bytes]:
    paras = []
    for i, t in enumerate(lines):
        if i % 7 == 0:
            ppr = '<w:pPr><w:pStyle w:val="Heading1"/></w:pPr>'
        elif i % 3 == 0:
            ppr = f'<w:pPr><w:numPr><w:ilvl w:val="{ilvl}"/><w:numId w:val="1"/></w:numPr></w:pPr>'
        else:
            ppr = ""
        paras.append(f'<w:p>{ppr}<w:r><w:t xml:space="preserve">{_x(t)}</w:t></w:r></w:p>')
    table = ('<w:tbl><w:tr><w:tc><w:p><w:r><w:t>Width</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>1200 mm</w:t></w:r></w:p>'
             '</w:tc></w:tr></w:tbl>')
    body = "".join(paras) + table + body_extra
    if nest:
        body = "<w:sdt><w:sdtContent>" * nest + body + "</w:sdtContent></w:sdt>" * nest
    doc = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="{W_NS}"><w:body>{body}</w:body></w:document>'
    numbering = (f'<?xml version="1.0" encoding="UTF-8"?><w:numbering xmlns:w="{W_NS}"><w:abstractNum w:abstractNumId="7">'
                 f'<w:lvl w:ilvl="{lvl_ilvl}"><w:start w:val="{start}"/><w:numFmt w:val="{fmt0}"/><w:lvlText w:val="{lvltext0}"/></w:lvl>'
                 '<w:lvl w:ilvl="1"><w:start w:val="1"/><w:numFmt w:val="lowerLetter"/><w:lvlText w:val="%1.%2)"/></w:lvl>'
                 '<w:lvl w:ilvl="2"><w:start w:val="1"/><w:numFmt w:val="lowerRoman"/><w:lvlText w:val="(%3)"/></w:lvl>'
                 '</w:abstractNum><w:num w:numId="1"><w:abstractNumId w:val="7"/></w:num></w:numbering>')
    styles = (f'<?xml version="1.0" encoding="UTF-8"?><w:styles xmlns:w="{W_NS}"><w:style w:styleId="Heading1"><w:pPr>'
              '<w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr></w:pPr></w:style>'
              '<w:style w:styleId="Heading2"><w:basedOn w:val="Heading1"/></w:style></w:styles>')
    return {"[Content_Types].xml": CT.encode(), "word/document.xml": doc.encode(), "word/numbering.xml": numbering.encode(),
            "word/styles.xml": styles.encode()}


def zip_bytes(parts: dict[str, bytes], compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as z:
        for name, data in parts.items():
            z.writestr(name, data)
    return buf.getvalue()


def png_bytes(w: int, h: int, bitdepth: int = 1, color: int = 0, dpi: float | None = None) -> bytes:
    """A blank PNG of any size, written without holding the image (decompression-bomb inputs)."""
    def chunk(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    channels = {0: 1, 2: 3, 4: 2, 6: 4}[color]
    row = b"\x00" + b"\x00" * ((w * bitdepth * channels + 7) // 8)
    c = zlib.compressobj(9)
    idat = b"".join(c.compress(row) for _ in range(h)) + c.flush()
    out = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, bitdepth, color, 0, 0, 0))
    if dpi:
        ppm = min(int(dpi / 0.0254), 0xFFFFFFFF)
        out += chunk(b"pHYs", struct.pack(">IIB", ppm, ppm, 1))
    return out + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def cached_blob(name: str, make) -> bytes:
    p = SANDBOX / "blobs" / name
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(make())
    return p.read_bytes()


def flate_bomb_stream(n_bytes: int, fill: bytes = b" ") -> bytes:
    c = zlib.compressobj(9)
    chunk = fill * (16 << 20)
    data = b"".join(c.compress(chunk) for _ in range(n_bytes // len(chunk))) + c.flush()
    return f"<< /Length {len(data)} /Filter /FlateDecode >>\nstream\n".encode() + data + b"\nendstream"


def bomb_pdf() -> bytes:
    return cached_blob("bomb.pdf", lambda: make_pdf([{"stream": flate_bomb_stream(1_700_000_000)}]))


def bomb_docx() -> bytes:
    def make():
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", CT)
            with z.open("word/document.xml", "w", force_zip64=True) as f:
                f.write(f'<w:document xmlns:w="{W_NS}"><w:body><w:p><w:r><w:t>'.encode())
                chunk = b"a" * (16 << 20)
                for _ in range(1_700_000_000 // len(chunk)):
                    f.write(chunk)
                f.write(b"</w:t></w:r></w:p></w:body></w:document>")
        return buf.getvalue()
    return cached_blob("bomb.docx", make)


# ---------------------------------------------------------------- cases

@dataclass
class Case:
    target: str
    idx: int
    dir: Path
    label: str = ""
    meta: dict = field(default_factory=dict)

    @property
    def inp(self) -> Path:
        return self.dir / "input"


def only_file(d: Path) -> Path:
    files = sorted(p for p in d.rglob("*") if p.is_file())
    if len(files) != 1:
        raise RuntimeError(f"fuzz_inputs: expected one input file in {d}, found {len(files)}")
    return files[0]


# ================================================================ target: regulation (adapters/regulation/documents.py)

DOC = "adapters/regulation/documents.py"


def seeds_regulation() -> dict:
    from adapters.regulation.documents import read

    ctx: dict = {"pdf": [], "lines": []}
    for p in sorted(INPUTS.glob("regulations/*/*.pdf")):
        data = p.read_bytes()
        ctx["pdf"] += [(p.name, data), ("p1-2-" + p.name, pdf_pages(data, [0, 1]))]
        ctx["lines"] += [ln.text for ln in read(p, p.name).lines[:120]]
    jp = []
    for y in sorted((SRC / "packs" / "jp-bsa-egress").glob("*.yaml")):
        jp += re.findall(r"quote:\s*(.+)", y.read_text())[:40]
    ctx["jp"] = [t.strip(" >|\"'") for t in jp if t.strip(" >|\"'")][:60] or ["階段の幅は、120センチメートル以上とすること。"]
    lines = ctx["lines"]
    ctx["txt"] = [("reg.txt", "\n".join(lines).encode())]
    ctx["md"] = [(p.name, p.read_bytes()) for p in sorted(INPUTS.glob("regulations/*/SOURCES.md"))] + [("README.md", (SRC / "README.md").read_bytes())]
    ctx["html"] = [("reg.html", make_html(lines).encode())]
    ctx["docx"] = [("reg.docx", zip_bytes(docx_parts(lines[:80])))]
    return ctx


def make_html(lines: list[str], head: str = '<meta charset="utf-8"><title>Regulation</title><style>p{}</style>',
              close_head: bool = True, ol_start: str = "3") -> str:
    import html as H
    li = "".join(f"<li>{H.escape(t)}</li>" for t in lines[1:8])
    ps = "".join(f"<p>{H.escape(t)}</p>" for t in lines[8:])
    return (f"<!doctype html><html><head>{head}{'</head>' if close_head else ''}<body><nav>Home | Codes</nav>"
            f"<h1>{H.escape(lines[0])}</h1><ol start=\"{ol_start}\">{li}</ol>{ps}<pre>Table 1\n  width  1200 mm\n</pre>"
            "<table><tr><td>Rise</td><td>180 mm</td></tr></table><script>var x = '<p>not text</p>';</script></body></html>")


def _reg_hand() -> list:
    def h(name, fn):
        return (name, fn)

    def docx_case(case, ctx, **kw):
        put(case, "reg.docx", zip_bytes(docx_parts(ctx["lines"][:30], **kw)))

    def html_raw(case, ctx, data: bytes, name="reg.html"):
        put(case, name, data)

    def pdf_case(case, ctx, data, name="reg.pdf"):
        put(case, name, data)

    lines = lambda ctx, n=40: ctx["lines"][:n]  # noqa: E731
    cid_font = {900: b"<< /Type /Font /Subtype /Type0 /BaseFont /Foo /Encoding /Identity-H /DescendantFonts [901 0 R] >>",
                901: b"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Foo /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /DW 1000 >>"}
    cid_content = b"\n".join(b"BT /F2 12 Tf 72 %d Td <%s> Tj ET" % (700 - 20 * i, ("0041004200430044" * 4).encode()) for i in range(20))
    eq = lambda case, ref, var, sym, frame=DOC: case.meta.update(file=var, same_as=ref, symptom=sym, frame=frame)  # noqa: E731

    def jp_sjis(case, ctx):
        text = "\n".join(ctx["jp"])
        put(case, "ref.txt", text.encode())
        put(case, "reg.txt", text.encode("shift_jis", "replace"))
        eq(case, "ref.txt", "reg.txt", "Shift_JIS text decoded as cp1252 mojibake", src_line(DOC, 'enc = "cp1252"'))

    def txt_crlf(case, ctx):
        put(case, "ref.txt", ctx["txt"][0][1])
        put(case, "reg.txt", ctx["txt"][0][1].replace(b"\n", b"\r\n"))
        eq(case, "ref.txt", "reg.txt", "CRLF text reads differently")

    def utf16_nobom(case, ctx):
        put(case, "ref.txt", ctx["txt"][0][1])
        put(case, "reg.txt", ctx["txt"][0][1].decode().encode("utf-16-le"))
        eq(case, "ref.txt", "reg.txt", "UTF-16 text without BOM rejected as binary", src_line(DOC, 'does not look like a text file'))

    def html_nohead(case, ctx):
        put(case, "reg.html", make_html(lines(ctx), close_head=False).encode())
        case.meta.update(expect_ok=True, min_lines=10, symptom="valid HTML without </head> loses the body",
                         frame=src_line(DOC, 'SKIP = {"script"'))

    def pdf_leading_ws(case, ctx):
        put(case, "ref.pdf", ctx["pdf"][1][1])
        put(case, "reg.pdf", b"\r\n  \n" + ctx["pdf"][1][1])
        eq(case, "ref.pdf", "reg.pdf", "PDF with whitespace before %PDF- reads differently", src_line(DOC, 'data.lstrip()[:5]'))

    def pdf_trailing(case, ctx):
        put(case, "ref.pdf", ctx["pdf"][1][1])
        put(case, "reg.pdf", ctx["pdf"][1][1] + b"\n%junk after EOF\n" + b"\x00" * 64)
        eq(case, "ref.pdf", "reg.pdf", "PDF with bytes after %%EOF reads differently")

    def html_cp1252(case, ctx):
        body = make_html(["Größe und Breite – “Treppe”", *lines(ctx, 20)], head='<meta charset="windows-1252">')
        put(case, "ref.html", body.replace("windows-1252", "utf-8").encode())
        put(case, "reg.html", body.encode("cp1252", "replace"))
        eq(case, "ref.html", "reg.html", "cp1252 HTML with meta charset reads differently")

    def docx_stored(case, ctx):
        parts = docx_parts(lines(ctx))
        put(case, "ref.docx", zip_bytes(parts))
        put(case, "reg.docx", zip_bytes(parts, zipfile.ZIP_STORED))
        eq(case, "ref.docx", "reg.docx", "stored (uncompressed) .docx reads differently")

    def big_txt(case, ctx, unit: bytes, name="big.txt"):
        put(case, name, unit * (49_000_000 // len(unit)))

    def many_pages(case, ctx):
        ls = ctx["lines"]
        pages = [{"content": text_content([f"Section {i}.{j} {ls[(i * 40 + j) % len(ls)]}" for j in range(45)])} for i in range(800)]
        put(case, "code-book.pdf", make_pdf(pages, flate=True))

    return [
        h("docx: numPr ilvl not an integer", lambda c, x: docx_case(c, x, ilvl="one")),
        h("docx: lvl start not an integer", lambda c, x: docx_case(c, x, start="1.5")),
        h("docx: lvl ilvl attribute not an integer", lambda c, x: docx_case(c, x, lvl_ilvl="x")),
        h("docx: upperRoman start 10^10 (quadratic string build)", lambda c, x: docx_case(c, x, ilvl="0", fmt0="upperRoman", start="10000000000")),
        h("docx: lowerLetter start 10^11 (huge label)", lambda c, x: docx_case(c, x, ilvl="0", fmt0="lowerLetter", start="100000000000")),
        h("docx: 5000 nested sdt blocks", lambda c, x: docx_case(c, x, nest=5000)),
        h("docx: billion laughs entities", lambda c, x: put(c, "reg.docx", zip_bytes({**docx_parts(lines(x)), "word/document.xml": (
            '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY a "aaaaaaaaaa">' + "".join(f'<!ENTITY {chr(98 + i)} "{("&" + chr(97 + i) + ";") * 10}">' for i in range(9))
            + f']><w:document xmlns:w="{W_NS}"><w:body><w:p><w:r><w:t>&j;</w:t></w:r></w:p></w:body></w:document>').encode()}))),
        h("docx: document.xml decompresses to 1.7 GB", lambda c, x: put(c, "reg.docx", bomb_docx())),
        h("docx: OLE container (encrypted)", lambda c, x: put(c, "reg.docx", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600)),
        h("docx: no word/document.xml", lambda c, x: put(c, "reg.docx", zip_bytes({"[Content_Types].xml": CT.encode()}))),
        h("docx: stored .docx equals deflated", docx_stored),
        h("html: <ol start> superscript digit", lambda c, x: html_raw(c, x, make_html(lines(x), ol_start="²").encode())),
        h("html: <ol start> 5000 digits", lambda c, x: html_raw(c, x, make_html(lines(x), ol_start="9" * 5000).encode())),
        h("html: meta charset idna on non-UTF-8 bytes", lambda c, x: html_raw(c, x, b'<meta charset="idna"><p>Caf\xe9 stair width</p>')),
        h("html: meta charset punycode on non-UTF-8 bytes", lambda c, x: html_raw(c, x, b'<meta charset="punycode"><p>Caf\xe9 stair width</p>')),
        h("html: meta charset utf-16 on cp1252 bytes", lambda c, x: html_raw(c, x, b'<meta charset="utf-16"><p>The stair width shall be at least 1200 mm. Caf\xe9</p>' * 20)),
        h("html: meta charset rot13", lambda c, x: html_raw(c, x, b'<meta charset="rot13"><p>Caf\xe9</p>')),
        h("html: cp1252 with meta equals utf-8", html_cp1252),
        h("html: valid HTML with </head> omitted", html_nohead),
        h("txt: Shift_JIS Japanese text", jp_sjis),
        h("txt: CRLF equals LF", txt_crlf),
        h("txt: UTF-16LE without BOM", utf16_nobom),
        h("txt: 49 MB single line", lambda c, x: big_txt(c, x, b"stair width shall be 1200 mm ")),
        h("txt: 49 MB of leader dots", lambda c, x: big_txt(c, x, b". . . . . . ")),
        h("txt: 49 MB of combining marks", lambda c, x: big_txt(c, x, "a\u0301\u0302\u0303".encode())),
        h("md: only zero-width characters", lambda c, x: put(c, "reg.md", "\u200b\u200c\ufeff\n" * 100)),
        h("pdf: Identity-H font without ToUnicode", lambda c, x: pdf_case(c, x, make_pdf(
            [{"content": cid_content, "fonts": "/F2 900 0 R"}], objs=cid_font))),
        h("pdf: content stream decompresses to 1.7 GB", lambda c, x: pdf_case(c, x, bomb_pdf())),
        h("pdf: page tree loop", lambda c, x: pdf_case(c, x, make_pdf([{"content": text_content(lines(x))}],
                                                                    pages_obj=b"<< /Type /Pages /Kids [2 0 R 4 0 R] /Count 2 >>"))),
        h("pdf: /Encrypt in trailer", lambda c, x: pdf_case(c, x, make_pdf([{"content": text_content(lines(x))}], objs={
            50: b"<< /Filter /Standard /V 1 /R 2 /O (xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx) /U (xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx) /P -4 >>"},
            trailer_extra="/Encrypt 50 0 R /ID [<00112233445566778899aabbccddeeff> <00112233445566778899aabbccddeeff>]"))),
        h("pdf: no xref, no trailer", lambda c, x: pdf_case(c, x, make_pdf([{"content": text_content(lines(x))}]).split(b"xref")[0])),
        h("pdf: whitespace before %PDF-", pdf_leading_ws),
        h("pdf: junk after %%EOF", pdf_trailing),
        h("pdf: 800-page code book", many_pages),
        h("pdf: one page with 300k characters", lambda c, x: pdf_case(c, x, make_pdf([{"content": text_content(
            [("stair width 1200 mm " * 40)[:700]] * 430, size=1, leading=1.5), "mediabox": "0 0 612 792"}], flate=True))),
        h("pdf: named .txt", lambda c, x: put(c, "reg.txt", x["pdf"][1][1])),
        h("docx: named .html", lambda c, x: put(c, "reg.html", x["docx"][0][1])),
        h("png: named .md", lambda c, x: put(c, "reg.md", png_bytes(50, 50))),
    ]


def gen_regulation(ctx: dict, rng: random.Random, case: Case) -> None:
    r = rng.random()
    if r < 0.12:  # equivalent re-encodings of a text seed: an oracle on the decoding
        kind = rng.choice(["txt", "md", "html"])
        name, data = rng.choice(ctx[kind])
        enc = rng.choice(["crlf", "cr", "utf-8-sig", "utf-16"])
        var, _ = reencode(rng, data, enc) if enc != "utf-16" else (b"\xff\xfe" + data.decode("utf-8", "replace").encode("utf-16-le"), enc)
        suffix = Path(name).suffix
        put(case, "ref" + suffix, data)
        put(case, "var" + suffix, var)
        case.meta.update(file="var" + suffix, same_as="ref" + suffix, symptom=f"{enc} {kind} reads differently")
        case.label = f"equiv:{kind}:{enc}"
        return
    if r < 0.22:  # docx with mutated parts, re-zipped
        parts = docx_parts(rng.sample(ctx["lines"], 40))
        part = rng.choice(["word/document.xml", "word/numbering.xml", "word/styles.xml"])
        data = parts[part]
        if rng.random() < 0.5:
            vals = ["", "-1", "x", "999999", "1.5", "0", "%9", "%0", "bullet", "none", "decimalZero", "upperRoman", "9" * 30]
            attrs = list(re.finditer(rb'w:val="([^"]*)"', data))
            for m in rng.sample(attrs, min(len(attrs), rng.randint(1, 4))):
                data = data.replace(m.group(0), b'w:val="' + rng.choice(vals).encode() + b'"', 1)
            how = "attr"
        else:
            data, how = mutate_bytes(rng, data)
        parts[part] = data
        if rng.random() < 0.2:
            del parts[rng.choice(["word/numbering.xml", "word/styles.xml"])]
        put(case, "reg.docx", zip_bytes(parts))
        case.label = f"docx:{part}:{how}"
        case.meta["single"] = True
        return
    if r < 0.30:  # kind confusion
        src = rng.choice(["pdf", "docx", "html", "txt", "md"])
        name, data = rng.choice(ctx[src])
        suffix = rng.choice([".pdf", ".docx", ".html", ".htm", ".xhtml", ".md", ".markdown", ".txt", ".text"])
        put(case, "doc" + suffix, data)
        case.label = f"confuse:{src}->{suffix}"
        case.meta["single"] = True
        return
    kind = rng.choices(["pdf", "docx", "html", "txt", "md"], [4, 2, 2, 1, 1])[0]
    name, data = rng.choice(ctx[kind])
    if kind in ("txt", "md", "html") and rng.random() < 0.3:
        data, how = reencode(rng, data)
    else:
        data, how = mutate_bytes(rng, data)
    put(case, "doc" + Path(name).suffix, data)
    case.label = f"mut:{kind}:{how}"
    case.meta["single"] = True


def check_document(doc, raw: bytes) -> list[dict]:
    out = []
    texts = [ln.text for ln in doc.lines]
    if [ln.no for ln in doc.lines] != list(range(1, len(texts) + 1)) or any(not t or t != t.strip() for t in texts):
        out.append(issue("line numbering or empty lines", src_line(DOC, "def _number")))
    if doc.kind == "pdf" and any(not ln.page or ln.page > (doc.pages or 0) for ln in doc.lines):
        out.append(issue("PDF line on a page that does not exist", src_line(DOC, "rows = [(i + 1, t)")))
    cid = sum(bool(re.search(r"\(cid:\d+\)", t)) for t in texts) / max(1, len(texts))
    if cid > 0.3:
        out.append(issue("PDF glyph codes returned as text: (cid:N)", src_line(DOC, "page.extract_text()"),
                         f"{cid:.0%} of {len(texts)} lines, e.g. {texts[0][:80]!r}"))
    chars = sum(len(t) for t in texts) or 1
    fffd = sum(t.count("\ufffd") for t in texts) / chars
    if fffd > 0.2:
        out.append(issue("text mostly U+FFFD replacement characters", src_line(DOC, "def _decode"), f"{fffd:.0%}"))
    if doc.kind in ("txt", "md", "html") and raw:
        ascii_in = sum(32 <= b < 127 or b in (9, 10, 13) for b in raw) / len(raw)
        ascii_out = sum(ord(c) < 128 for t in texts for c in t) / chars
        if ascii_in > 0.95 and ascii_out < 0.5:
            out.append(issue("ASCII document decoded as non-ASCII mojibake", src_line(DOC, "enc = m.group(1)"),
                             f"{ascii_out:.0%} ASCII out of {ascii_in:.0%} ASCII in; first line {texts[0][:60]!r}"))
    return out


def run_regulation(case: Case) -> dict:
    from adapters.regulation.documents import RegulationError, read

    m = case.meta
    path = case.inp / m["file"] if "file" in m else only_file(case.inp)
    rel = m.get("rel", path.name)
    try:
        doc = read(path, rel)
    except RegulationError as e:
        ref_ok = bool(m.get("expect_ok"))
        if m.get("same_as"):
            try:
                read(case.inp / m["same_as"], m["same_as"])
                ref_ok = True
            except RegulationError:
                ref_ok = False
        if ref_ok:
            return verdict([issue(m.get("symptom", "valid input rejected"), m.get("frame", DOC), f"RegulationError: {e}")])
        raise
    issues = check_document(doc, path.read_bytes())
    if m.get("same_as"):
        ref = read(case.inp / m["same_as"], m["same_as"])
        a, b = [ln.text for ln in doc.lines], [ln.text for ln in ref.lines]
        if a != b:
            i = next((k for k in range(min(len(a), len(b))) if a[k] != b[k]), min(len(a), len(b)))
            issues.append(issue(m.get("symptom", "equivalent input reads differently"), m.get("frame", DOC),
                                f"{len(a)} vs {len(b)} lines; first difference at line {i + 1}: "
                                f"{(a[i] if i < len(a) else None)!r:.120} vs {(b[i] if i < len(b) else None)!r:.120}"))
    if m.get("min_lines") and len(doc.lines) < m["min_lines"]:
        issues.append(issue(m.get("symptom", "too few lines"), m.get("frame", DOC), f"{len(doc.lines)} lines"))
    return verdict(issues, f"{doc.kind}: {len(doc.lines)} lines, {doc.pages} pages")


# ================================================================ target: upload (app/regulations.py create/safe_name)

REGS_PY = "app/regulations.py"


def seeds_upload() -> dict:
    return {"names": ["ADK-2013-sections-1-2-stairs-ramps.pdf", "OWASP_SCP_Quick_Reference_Guide_v2.pdf", "Building Code.docx",
                      "建築基準法施行令_第五章_避難施設等.pdf", "policy.md", "rules.HTML", "notes.txt", "index.htm", "a.markdown"],
            "data": [b"%PDF-1.4\n%%EOF\n", b"The stair width shall be at least 1200 mm.\n", b"<p>x</p>", b"\x00\x01binary"]}


NAME_MUTATORS = [
    lambda r, n: "../" * r.randint(1, 8) + n, lambda r, n: "..\\" * r.randint(1, 8) + n, lambda r, n: "/etc/" + n,
    lambda r, n: "C:\\Users\\x\\" + n, lambda r, n: n.replace(".", "\x00.", 1), lambda r, n: "\x01\x1b[31m" + n,
    lambda r, n: "建" * r.choice([50, 90, 130]) + Path(n).suffix, lambda r, n: "𝔸" * r.choice([40, 70, 119]) + Path(n).suffix,
    lambda r, n: "a" * r.choice([100, 116, 117, 120, 200, 300]) + Path(n).suffix, lambda r, n: n + ".",
    lambda r, n: n + " ", lambda r, n: " " + n, lambda r, n: "." + Path(n).suffix, lambda r, n: ".." + Path(n).suffix,
    lambda r, n: "?*" + Path(n).suffix, lambda r, n: n.upper(), lambda r, n: n + ".pdf", lambda r, n: n.replace(".", ". "),
    lambda r, n: "\u202e" + n, lambda r, n: "e\u0301" + n, lambda r, n: n.replace(".", "\u2024"), lambda r, n: "CON" + Path(n).suffix,
    lambda r, n: "a/" * 50 + n, lambda r, n: n, lambda r, n: n, lambda r, n: "-" + n, lambda r, n: "~" + n,
    lambda r, n: "%2e%2e%2f" + n, lambda r, n: n.replace(".", "\u3002"), lambda r, n: "\ud800" + n,
]


def _upload_hand() -> list:
    def files(case, specs, name="", domain="building"):
        put(case, "files.json", json.dumps({"name": name, "domain": domain, "files": [
            {"name": n, "b64": base64.b64encode(d).decode()} for n, d in specs]}))
        case.meta["single"] = True
    d = b"The stair width shall be at least 1200 mm.\n"
    return [
        ("name: 116 chars + .pdf (extension truncated)", lambda c, x: files(c, [("a" * 116 + ".pdf", d)])),
        ("name: 100 CJK chars + .pdf (UTF-8 bytes > 255)", lambda c, x: files(c, [("建" * 100 + ".pdf", d)])),
        ("name: 70 astral chars + .md", lambda c, x: files(c, [("𝔸" * 70 + ".md", d)])),
        ("name: '..pdf'", lambda c, x: files(c, [("..pdf", d)])),
        ("name: '. .txt'", lambda c, x: files(c, [(". .txt", d)])),
        ("name: '_.pdf' (dots-only stem)", lambda c, x: files(c, [("....pdf", d)])),
        ("name: traversal", lambda c, x: files(c, [("../../../../tmp/evil.txt", d), ("..\\..\\evil.md", d)])),
        ("name: NUL", lambda c, x: files(c, [("a\x00.pdf.txt", d)])),
        ("name: lone surrogate", lambda c, x: files(c, [("\ud800x.txt", d)])),
        ("name: duplicates x3", lambda c, x: files(c, [("a.txt", d), ("a.txt", d + b"2"), ("a.txt", d + b"3"), ("a-1.txt", d)])),
        ("name: dedupe of a 120-char name", lambda c, x: files(c, [("b" * 116 + ".txt", d), ("b" * 116 + ".txt", d + b"2")])),
        ("name: empty", lambda c, x: files(c, [("", d)])),
        ("name: '.pdf'", lambda c, x: files(c, [(".pdf", d)])),
        ("title: 10k chars and control characters", lambda c, x: files(c, [("a.txt", d)], name="\x00\x1b" + "T" * 10000)),
        ("domain: unknown", lambda c, x: files(c, [("a.txt", d)], domain="bim")),
        ("files: 2000 small files", lambda c, x: files(c, [(f"f{i}.txt", d) for i in range(2000)])),
    ]


def gen_upload(ctx: dict, rng: random.Random, case: Case) -> None:
    specs = []
    for _ in range(rng.randint(1, 4)):
        n = rng.choice(ctx["names"])
        for _ in range(rng.randint(0, 2)):
            n = rng.choice(NAME_MUTATORS)(rng, n)
        data = rng.choice(ctx["data"]) if rng.random() > 0.05 else b""
        specs.append((n, data))
    if rng.random() < 0.2:
        specs.append(specs[0])
    put(case, "files.json", json.dumps({"name": rng.choice(["", "  ", "Reg", "\u202eReg", "x" * 300]),
                                        "domain": rng.choice(["building", "code", "building", "Code", ""]),
                                        "files": [{"name": n, "b64": base64.b64encode(dd).decode()} for n, dd in specs]}))
    case.meta["single"] = True
    case.label = "names:" + "|".join(repr(n)[:40] for n, _ in specs)


def run_upload(case: Case) -> dict:
    import app.regulations as R
    from adapters.regulation.documents import KINDS, RegulationError, read

    spec = json.loads(only_file(case.inp).read_text())
    files = [(f["name"], base64.b64decode(f["b64"])) for f in spec["files"]]
    work = case.dir / "work"
    R.REGS = work / "regs"
    R.REGS.mkdir(parents=True)
    rid = R.create(spec.get("name", ""), spec.get("domain", "building"), files)
    issues = []
    regdir = R.REGS / rid
    outside = [p for p in walk_all(work) if not p.startswith(str(regdir))]
    if [p for p in outside if p != str(R.REGS)]:
        issues.append(issue("upload written outside its regulation directory", src_line(REGS_PY, "def safe_name"), str(outside[:3])))
    stored = sorted((regdir / "files").iterdir())
    req = json.loads((regdir / "request.json").read_text())
    if len(stored) != len(files) or sorted(req["files"]) != sorted(p.name for p in stored):
        issues.append(issue("stored file count differs from the upload", src_line(REGS_PY, "while n in names"),
                            f"{len(files)} uploaded, {len(stored)} stored"))
    for (fname, data), name in zip(files, req["files"]):
        p = regdir / "files" / name
        if p.read_bytes() != data:
            issues.append(issue("stored bytes differ from the upload", src_line(REGS_PY, "write_bytes(data)"), name))
        if Path(name).suffix.lower() not in KINDS:
            try:
                read(p, name)
                why = "read() accepted it"
            except RegulationError as e:
                why = str(e)
            before = re.sub(r"[^\w.\- ()]+", "_", Path(fname.replace("\\", "/")).name).strip(" .")
            sym = ("accepted upload stored without its extension (name truncated to 120 chars)" if len(before) > 120 and Path(before).suffix
                   else "accepted upload stored without its extension (sanitised away)")
            frame = src_line(REGS_PY, "return base[:120]") if "truncated" in sym else src_line(REGS_PY, '.strip(" .") or "document"')
            issues.append(issue(sym, frame, f"{fname!r:.80} -> {name!r:.80}; compile then fails: {why}"))
    return verdict(issues, f"stored {[p.name[:40] for p in stored][:5]}")


# ================================================================ target: zips (app/buildings.py expand_zips/inventory)

BLD = "app/buildings.py"


def seeds_zips() -> dict:
    regs = sorted(INPUTS.glob("regulations/*/*.pdf"))
    small = pdf_pages(regs[0].read_bytes(), [0]) if regs else make_pdf([{"content": text_content(["x"])}])
    dxf = sorted(INPUTS.glob("dxf/innerscene-studio/*.dxf"))
    return {"members": [("sheet.pdf", small), ("plan.dxf", dxf[0].read_bytes() if dxf else b"0\nEOF\n"),
                        ("model.ifc", IFC_MINI.encode()), ("scan.png", png_bytes(64, 64)), ("readme.txt", b"hello")],
            "names": ["A-101.pdf", "Drawings/Level 1/A-101 Floor Plan.pdf", "model.ifc", "plan.dxf", "photo.JPG", "notes.txt",
                      "__MACOSX/._A-101.pdf", "dir/", "x.tif"]}


def zip_with(entries: list[dict]) -> bytes:
    """entries: {name, data, compress, attr (external_attr), flag (flag_bits), dir}"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for e in entries:
            zi = zipfile.ZipInfo(e["name"], date_time=(2020, 1, 1, 0, 0, 0))
            zi.compress_type = e.get("compress", zipfile.ZIP_DEFLATED)
            if "attr" in e:
                zi.external_attr = e["attr"]
            z.writestr(zi, e.get("data", b""))
    data = bytearray(buf.getvalue())
    for e in entries:
        if e.get("flag") or e.get("method") is not None:  # patch both headers after writing
            nm = e["name"].encode()
            for sig, off_flag, off_meth in ((b"PK\x03\x04", 6, 8), (b"PK\x01\x02", 8, 10)):
                i = 0
                while (i := data.find(sig, i)) >= 0:
                    name_off = 30 if sig == b"PK\x03\x04" else 46
                    if data[i + name_off:i + name_off + len(nm)] == nm:
                        if e.get("flag"):
                            data[i + off_flag] |= e["flag"]
                        if e.get("method") is not None:
                            data[i + off_meth:i + off_meth + 2] = struct.pack("<H", e["method"])
                    i += 4
    return bytes(data)


def _lie_sizes(z: bytes, declared: int) -> bytes:
    """Rewrite every header's uncompressed size to `declared` (a zip whose sizes lie)."""
    data = bytearray(z)
    for sig, off in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):
        i = 0
        while (i := data.find(sig, i)) >= 0:
            data[i + off:i + off + 4] = struct.pack("<I", declared)
            i += 4
    return bytes(data)


def ratio_bomb() -> bytes:
    def make():
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            with z.open("plans/A-101.pdf", "w", force_zip64=True) as f:
                chunk = b"\x00" * (16 << 20)
                for _ in range(1_000_000_000 // len(chunk)):
                    f.write(chunk)
        return buf.getvalue()
    return cached_blob("ratio-bomb.zip", make)


def _zips_hand() -> list:
    def one(case, entries, name="set.zip"):
        put(case, name, zip_with(entries))
        case.meta["single"] = True
    pdf = lambda x: x["members"][0][1]  # noqa: E731
    lnk = (stat.S_IFLNK | 0o777) << 16
    return [
        ("traversal ../ and absolute names", lambda c, x: one(c, [{"name": "../../../evil.pdf", "data": pdf(x)}, {"name": "/tmp/abs.pdf", "data": pdf(x)},
                                                                    {"name": "..\\..\\win.pdf", "data": pdf(x)}, {"name": "C:/x/drive.pdf", "data": pdf(x)}])),
        ("symlink member", lambda c, x: one(c, [{"name": "link.pdf", "data": b"/etc/passwd", "attr": lnk}, {"name": "ok.pdf", "data": pdf(x)}])),
        ("symlink dir then file through it", lambda c, x: one(c, [{"name": "d", "data": b"/tmp", "attr": lnk}, {"name": "d/x.pdf", "data": pdf(x)}])),
        ("duplicate member names", lambda c, x: one(c, [{"name": "A-101.pdf", "data": pdf(x)}, {"name": "A-101.pdf", "data": b"%PDF-1.4 other"}])),
        ("names equal after sanitising", lambda c, x: one(c, [{"name": "A?101.pdf", "data": pdf(x)}, {"name": "A*101.pdf", "data": b"%PDF-1.4 other"},
                                                               {"name": "a/../A_101.pdf", "data": b"%PDF third"}])),
        ("file and directory with the same name", lambda c, x: one(c, [{"name": "a.pdf", "data": pdf(x)}, {"name": "a.pdf/b.pdf", "data": pdf(x)}])),
        ("member name '..' only", lambda c, x: one(c, [{"name": "ok.pdf", "data": pdf(x)}, {"name": "../", "data": b""}, {"name": "./.pdf", "data": b"x"}])),
        ("member name 300-char component", lambda c, x: one(c, [{"name": "a" * 300 + ".pdf", "data": pdf(x)}])),
        ("member path 200 levels deep", lambda c, x: one(c, [{"name": "d/" * 200 + "x.pdf", "data": pdf(x)}])),
        ("member name with NUL", lambda c, x: one(c, [{"name": "a\x00b.pdf", "data": pdf(x)}])),
        ("encrypted member (flag bit)", lambda c, x: one(c, [{"name": "e.pdf", "data": pdf(x), "flag": 1}])),
        ("unsupported compression method 99", lambda c, x: one(c, [{"name": "m.pdf", "data": pdf(x), "method": 99}])),
        ("bzip2 and lzma members", lambda c, x: one(c, [{"name": "b.pdf", "data": pdf(x), "compress": zipfile.ZIP_BZIP2},
                                                         {"name": "l.pdf", "data": pdf(x), "compress": zipfile.ZIP_LZMA}])),
        ("corrupt deflate data", lambda c, x: put(c, "set.zip", (lambda z: z[:60] + bytes(b ^ 0x55 for b in z[60:200]) + z[200:])(
            zip_with([{"name": "c.pdf", "data": pdf(x)}])))),
        ("declared sizes lie (small)", lambda c, x: put(c, "set.zip", _lie_sizes(zip_with([{"name": "ok.pdf", "data": pdf(x)},
                                                                                              {"name": "big.pdf", "data": b"\x00" * 3_000_000}]), 10))),
        ("ratio bomb: 1 MB zip -> 1 GB", lambda c, x: put(c, "set.zip", ratio_bomb())),
        ("5001 members", lambda c, x: one(c, [{"name": f"f{i}.pdf", "data": b"x"} for i in range(5001)])),
        ("100k directory entries", lambda c, x: one(c, [{"name": f"d{i}/", "data": b""} for i in range(100_000)] + [{"name": "a.pdf", "data": pdf(x)}])),
        ("nested zip of drawings", lambda c, x: one(c, [{"name": "arch.zip", "data": zip_with([{"name": "A-101.pdf", "data": pdf(x)}])},
                                                         {"name": "readme.txt", "data": b"see arch.zip"}])),
        ("uppercase .ZIP", lambda c, x: put(c, "DRAWINGS.ZIP", zip_with([{"name": "A-101.pdf", "data": pdf(x)}]))),
        ("a directory named x.zip", lambda c, x: (put(c, "x.zip/A-101.pdf", pdf(x)), put(c, "set.zip", zip_with([{"name": "b.pdf", "data": pdf(x)}])))),
        ("zip extracting over an uploaded file", lambda c, x: (put(c, "plan.pdf", pdf(x)), put(c, "plan.pdf.zip", zip_with([{"name": "p1.pdf", "data": pdf(x)}])))),
        ("two zips with the same stem", lambda c, x: (put(c, "set.zip", zip_with([{"name": "a.pdf", "data": pdf(x)}])),
                                                      put(c, "set/x.zip", zip_with([{"name": "b.pdf", "data": pdf(x)}])))),
        ("truncated zip", lambda c, x: put(c, "set.zip", zip_with([{"name": "a.pdf", "data": pdf(x)}, {"name": "b.pdf", "data": pdf(x)}])[:-30])),
        ("zip with prepended junk (SFX)", lambda c, x: put(c, "set.zip", b"MZ" + b"\x00" * 5000 + zip_with([{"name": "a.pdf", "data": pdf(x)}]))),
        ("empty zip", lambda c, x: one(c, [])),
        ("not a zip", lambda c, x: put(c, "set.zip", b"PK\x03\x04garbage")),
    ]


def gen_zips(ctx: dict, rng: random.Random, case: Case) -> None:
    entries = []
    for _ in range(rng.randint(1, 8)):
        name = rng.choice(ctx["names"])
        for _ in range(rng.randint(0, 2)):
            name = rng.choice(NAME_MUTATORS)(rng, name)
        mname, data = rng.choice(ctx["members"])
        if rng.random() < 0.3:
            data, _ = mutate_bytes(rng, data, 1)
        e = {"name": name, "data": data, "compress": rng.choice([zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])}
        if rng.random() < 0.05:
            e["attr"] = (stat.S_IFLNK | 0o777) << 16
        entries.append(e)
    if rng.random() < 0.1:
        entries.append({"name": "inner.zip", "data": zip_with(entries[:2])})
    try:
        z = zip_with(entries)
    except Exception:  # noqa: BLE001 - zipfile refuses some names (surrogates); keep the case, fix the name
        for e in entries:
            e["name"] = e["name"].encode("utf-8", "replace").decode("utf-8")
        z = zip_with(entries)
    how = "plain"
    if rng.random() < 0.3:
        z, how = mutate_bytes(rng, z, rng.randint(1, 2))
    elif rng.random() < 0.1:
        z, how = _lie_sizes(z, rng.choice([0, 1, 10, 0xFFFFFFFF])), "lie"
    put(case, rng.choice(["set.zip", "Drawings.zip", "a b.zip", "x.ZIP", "set.zip"]), z)
    case.meta["single"] = True
    case.label = f"zip:{len(entries)} entries:{how}"


def run_zips(case: Case) -> dict:
    import app.buildings as B

    work = case.dir / "work"
    files = work / "project" / "files"
    shutil.copytree(case.inp, files, symlinks=True)
    (work / "outside-marker").write_text("x")
    before_out = {p for p in walk_all(work) if not p.startswith(str(files) + os.sep)}
    before_files = walk_all(files)
    zips = []
    for z in sorted(p for p in files.rglob("*.zip") if p.is_file()):  # the zips expand_zips opens (case-sensitive)
        rec = {"zip": z, "bytes": z.stat().st_size, "declared": 0, "targets": {}, "nested": [], "bad": False}
        try:
            with zipfile.ZipFile(z) as zf:
                infos = [i for i in zf.infolist() if not i.is_dir()]
                rec["declared"] = sum(i.file_size for i in infos)
                dest = z.with_suffix("")
                for i in infos:
                    if stat.S_ISLNK(i.external_attr >> 16):
                        continue
                    if i.filename.lower().endswith(".zip"):
                        rec["nested"].append(i.filename)
                    try:
                        rel = B.safe_name(i.filename)
                    except B.ProjectError:
                        continue
                    if Path(rel).suffix.lower() in B.ACCEPTED - {".zip"} and "__MACOSX" not in rel:
                        rec["targets"].setdefault(str(dest / rel), []).append(i.filename)
        except Exception:  # noqa: BLE001
            rec["bad"] = True
        zips.append(rec)
    notes = B.expand_zips(files)
    kinds = B.inventory(files)
    issues = []
    after_out = {p for p in walk_all(work) if not p.startswith(str(files) + os.sep)}
    if after_out - before_out:
        issues.append(issue("zip member written outside the project files", src_line(BLD, "out = (dest / rel).resolve()"),
                            str(sorted(after_out - before_out)[:3])))
    links = [p for p in walk_all(files) if os.path.islink(p) and p not in before_files]
    if links:
        issues.append(issue("symlink created by unpacking", src_line(BLD, "S_ISLNK"), str(links[:3])))
    left = [p for ps in kinds.values() for p in ps if p.suffix.lower() == ".zip"]
    if left:
        issues.append(issue("uploaded zip never unpacked (reported as an unreadable format)", src_line(BLD, 'rglob("*.zip")'),
                            ", ".join(str(p.relative_to(files)) for p in left[:3])))
    written = sum(os.lstat(p).st_size for p in walk_all(files) - before_files if os.path.isfile(p) and not os.path.islink(p))
    declared = sum(r["declared"] for r in zips if not r["bad"])
    if written > declared + 1024 and declared:
        issues.append(issue("more bytes unpacked than the zip declares", src_line(BLD, "sum(i.file_size for i in infos)"),
                            f"{written} written, {declared} declared"))
    zip_bytes_total = sum(r["bytes"] for r in zips) or 1
    if written > 200_000_000 and written / zip_bytes_total > 100:
        issues.append(issue("zip bomb by compression ratio unpacked to disk", src_line(BLD, "MAX_UNZIPPED ="),
                            f"{zip_bytes_total} bytes -> {written} bytes ({written // zip_bytes_total}:1)"))
    for r in zips:
        dup = {k: v for k, v in r["targets"].items() if len(v) > 1}
        if dup and not notes:
            k, v = next(iter(dup.items()))
            issues.append(issue("members unpacked to the same path overwrite each other silently", src_line(BLD, "rel = safe_name(i.filename)"),
                                f"{v} -> {Path(k).name}"))
        if r["nested"] and not any("zip" in n.lower() and "nested" in n.lower() for n in notes):
            issues.append(issue("nested zip dropped without a note", src_line(BLD, 'ACCEPTED - {".zip"}'), str(r["nested"][:3])))
        if any("not a readable zip" in n for n in notes) and r["zip"].with_suffix("").is_dir():
            left_files = [p for p in r["zip"].with_suffix("").rglob("*") if p.is_file()]
            if left_files and r["zip"].name in " ".join(notes):
                issues.append(issue("zip reported as skipped but its members were unpacked (some truncated)",
                                    src_line(BLD, "except zipfile.BadZipFile"), f"{len(left_files)} files left: {[p.name for p in left_files[:3]]}"))
    return verdict(issues, f"notes={notes[:2]} kinds={ {k: len(v) for k, v in kinds.items()} } written={written}")


# ================================================================ target: ifc (adapters/ifc.py extract)

IFC_MINI = """ISO-10303-21;
HEADER;
FILE_DESCRIPTION(('ViewDefinition [ReferenceView]'),'2;1');
FILE_NAME('fuzz.ifc','2026-11-16T00:00:00',(''),(''),'','','');
FILE_SCHEMA(('IFC4'));
ENDSEC;
DATA;
#1=IFCPROJECT('0YvctVUKr0kugbFTf53O9L',$,'P',$,$,$,$,(#20),#10);
#10=IFCUNITASSIGNMENT((#11,#12,#13));
#11=IFCSIUNIT(*,.LENGTHUNIT.,.MILLI.,.METRE.);
#12=IFCSIUNIT(*,.AREAUNIT.,$,.SQUARE_METRE.);
#13=IFCSIUNIT(*,.VOLUMEUNIT.,$,.CUBIC_METRE.);
#20=IFCGEOMETRICREPRESENTATIONCONTEXT($,'Model',3,1.E-05,#21,$);
#21=IFCAXIS2PLACEMENT3D(#22,$,$);
#22=IFCCARTESIANPOINT((0.,0.,0.));
#30=IFCSITE('1YvctVUKr0kugbFTf53O9L',$,'Site',$,$,#31,$,$,.ELEMENT.,$,$,$,$,$);
#31=IFCLOCALPLACEMENT($,#21);
#40=IFCBUILDING('2YvctVUKr0kugbFTf53O9L',$,'B',$,$,#41,$,$,.ELEMENT.,$,$,$);
#41=IFCLOCALPLACEMENT(#31,#21);
#50=IFCBUILDINGSTOREY('3YvctVUKr0kugbFTf53O9L',$,'Level 1',$,$,#51,$,$,.ELEMENT.,0.);
#51=IFCLOCALPLACEMENT(#41,#21);
#52=IFCBUILDINGSTOREY('3YvctVUKr0kugbFTf53O9M',$,'Level 2',$,$,#53,$,$,.ELEMENT.,3500.);
#53=IFCLOCALPLACEMENT(#41,#54);
#54=IFCAXIS2PLACEMENT3D(#55,$,$);
#55=IFCCARTESIANPOINT((0.,0.,3500.));
#60=IFCRELAGGREGATES('4YvctVUKr0kugbFTf53O9L',$,$,$,#1,(#30));
#61=IFCRELAGGREGATES('5YvctVUKr0kugbFTf53O9L',$,$,$,#30,(#40));
#62=IFCRELAGGREGATES('6YvctVUKr0kugbFTf53O9L',$,$,$,#40,(#50,#52));
#70=IFCSPACE('7YvctVUKr0kugbFTf53O9L',$,'101',$,$,#71,#72,'Office',.ELEMENT.,.SPACE.,$);
#71=IFCLOCALPLACEMENT(#51,#21);
#72=IFCPRODUCTDEFINITIONSHAPE($,$,(#73));
#73=IFCSHAPEREPRESENTATION(#20,'Body','SweptSolid',(#74));
#74=IFCEXTRUDEDAREASOLID(#75,#21,#77,3000.);
#75=IFCRECTANGLEPROFILEDEF(.AREA.,$,#76,6000.,4000.);
#76=IFCAXIS2PLACEMENT2D(#78,$);
#77=IFCDIRECTION((0.,0.,1.));
#78=IFCCARTESIANPOINT((3000.,2000.));
#80=IFCSPACE('8YvctVUKr0kugbFTf53O9L',$,'102',$,$,#81,#82,'Corridor',.ELEMENT.,.SPACE.,$);
#81=IFCLOCALPLACEMENT(#51,#21);
#82=IFCPRODUCTDEFINITIONSHAPE($,$,(#83));
#83=IFCSHAPEREPRESENTATION(#20,'Body','SweptSolid',(#84));
#84=IFCEXTRUDEDAREASOLID(#85,#21,#77,3000.);
#85=IFCRECTANGLEPROFILEDEF(.AREA.,$,#86,2000.,4000.);
#86=IFCAXIS2PLACEMENT2D(#87,$);
#87=IFCCARTESIANPOINT((7000.,2000.));
#88=IFCRELAGGREGATES('9YvctVUKr0kugbFTf53O9L',$,$,$,#50,(#70,#80));
#90=IFCDOOR('AYvctVUKr0kugbFTf53O9L',$,'D101',$,$,#91,#92,'101',2100.,915.,.DOOR.,.SINGLE_SWING_LEFT.,$);
#91=IFCLOCALPLACEMENT(#51,#93);
#93=IFCAXIS2PLACEMENT3D(#94,$,$);
#94=IFCCARTESIANPOINT((6000.,1500.,0.));
#92=IFCPRODUCTDEFINITIONSHAPE($,$,(#95));
#95=IFCSHAPEREPRESENTATION(#20,'Body','SweptSolid',(#96));
#96=IFCEXTRUDEDAREASOLID(#97,#21,#77,2100.);
#97=IFCRECTANGLEPROFILEDEF(.AREA.,$,#98,200.,915.);
#98=IFCAXIS2PLACEMENT2D(#99,$);
#99=IFCCARTESIANPOINT((0.,457.5));
#100=IFCSTAIRFLIGHT('BYvctVUKr0kugbFTf53O9L',$,'Stair 1',$,$,#101,$,$,18,17,175.,280.,.STRAIGHT.);
#101=IFCLOCALPLACEMENT(#51,#21);
#102=IFCSTAIR('CYvctVUKr0kugbFTf53O9L',$,'Stair 1',$,$,#101,$,$,.STRAIGHT_RUN_STAIR.);
#110=IFCRELCONTAINEDINSPATIALSTRUCTURE('DYvctVUKr0kugbFTf53O9L',$,$,$,(#90,#100,#102),#50);
#120=IFCPROPERTYSET('EYvctVUKr0kugbFTf53O9L',$,'Pset_DoorCommon',$,(#121,#122,#123));
#121=IFCPROPERTYSINGLEVALUE('IsExternal',$,IFCBOOLEAN(.T.),$);
#122=IFCPROPERTYSINGLEVALUE('FireExit',$,IFCBOOLEAN(.T.),$);
#123=IFCPROPERTYSINGLEVALUE('HandicapAccessible',$,IFCBOOLEAN(.T.),$);
#124=IFCRELDEFINESBYPROPERTIES('FYvctVUKr0kugbFTf53O9L',$,$,$,(#90),#120);
#130=IFCPROPERTYSET('GYvctVUKr0kugbFTf53O9L',$,'Pset_StairFlightCommon',$,(#131,#132,#133));
#131=IFCPROPERTYSINGLEVALUE('RiserHeight',$,IFCPOSITIVELENGTHMEASURE(175.),$);
#132=IFCPROPERTYSINGLEVALUE('TreadLength',$,IFCPOSITIVELENGTHMEASURE(280.),$);
#133=IFCPROPERTYSINGLEVALUE('NumberOfRiser',$,IFCCOUNTMEASURE(18),$);
#134=IFCRELDEFINESBYPROPERTIES('HYvctVUKr0kugbFTf53O9L',$,$,$,(#100),#130);
#140=IFCELEMENTQUANTITY('IYvctVUKr0kugbFTf53O9L',$,'Qto_SpaceBaseQuantities',$,$,(#141,#142));
#141=IFCQUANTITYAREA('NetFloorArea',$,$,24.,$);
#142=IFCQUANTITYLENGTH('Height',$,$,3000.,$);
#143=IFCRELDEFINESBYPROPERTIES('JYvctVUKr0kugbFTf53O9L',$,$,$,(#70),#140);
#150=IFCPROPERTYSET('KYvctVUKr0kugbFTf53O9L',$,'Pset_SpaceOccupancyRequirements',$,(#151));
#151=IFCPROPERTYSINGLEVALUE('OccupancyNumber',$,IFCCOUNTMEASURE(12),$);
#152=IFCRELDEFINESBYPROPERTIES('LYvctVUKr0kugbFTf53O9L',$,$,$,(#70),#150);
ENDSEC;
END-ISO-10303-21;
"""
IFC_TYPES = re.compile(rb"^#\d+\s*=\s*IFC(DOOR|SPACE|BUILDINGSTOREY|SIUNIT|CONVERSIONBASEDUNIT|MEASUREWITHUNIT|PROPERTYSINGLEVALUE|"
                       rb"QUANTITY\w+|STAIR\w*|CARTESIANPOINT|LOCALPLACEMENT|AXIS2PLACEMENT3D|EXTRUDEDAREASOLID|RECTANGLEPROFILEDEF|"
                       rb"RELCONTAINEDINSPATIALSTRUCTURE|RELAGGREGATES|RELSPACEBOUNDARY|OPENINGELEMENT|RELFILLSELEMENT|RELVOIDSELEMENT|"
                       rb"DOORLININGPROPERTIES|ARBITRARYCLOSEDPROFILEDEF|POLYLINE|COLUMN|SLAB|BUILDING|UNITASSIGNMENT)\b", re.M)
IFC_TOKEN = re.compile(rb"-?\d+\.\d*(?:E[-+]?\d+)?|#\d+|'[^']*'|\.[A-Z_]+\.|\$|\b\d+\b")


def seeds_ifc() -> dict:
    seeds = [("mini.ifc", IFC_MINI.encode())]
    for p in [INPUTS / "tuwien-escape-route/RealWorldTestModel-EscapeRouteAnalysis-ZDB-v2.ifc", INPUTS / "nibs-office/Office_A_20110811.ifc",
              INPUTS / "nibs-clinic/Clinic_A_20110906.ifc"]:
        if p.exists():
            seeds.append((p.name, p.read_bytes()))
    ctx = {"seeds": []}
    for name, data in seeds:
        lines = [(m.start(), data.find(b"\n", m.start())) for m in IFC_TYPES.finditer(data)]
        ctx["seeds"].append((name, data, lines))
    return ctx


def mutate_ifc_line(rng: random.Random, line: bytes, max_ref: int) -> bytes:
    toks = list(IFC_TOKEN.finditer(line, line.find(b"(")))
    if not toks:
        return line
    m = rng.choice(toks)
    t = m.group(0)
    if t.startswith(b"#"):
        new = rng.choice([b"#999999999", b"#0", b"$", b"*", t, b"#" + str(rng.randint(1, max_ref)).encode(), line.split(b"=")[0].strip()])
    elif t.startswith(b"'"):
        new = rng.choice([b"''", b"'" + b"A" * 5000 + b"'", b"'\\X2\\D83DDE00\\X0\\'", b"'\\X\\FF'", b"'..\\..'", b"'Stair'", b"'Corridor'",
                          b"'Open to below'", b"'0YvctVUKr0kugbFTf53O9L'", b"'\x00'"])
    elif t.startswith(b".") and t.endswith(b"."):
        new = rng.choice([b".T.", b".F.", b".U.", b".NOTDEFINED.", b".EXA.", b".MILLI.", b".FOOT.", b".DOUBLE_DOOR_DOUBLE_SWING.", b".XYZ."])
    elif t == b"$":
        new = rng.choice([b"0.", b"-1.", b"''", b"#1", b".T."])
    else:
        new = rng.choice([b"0.", b"-0.", b"-1.", b"-915.", b"1.E308", b"-1.E308", b"1.E400", b"1.E-300", b"0", b"-1", b"999999999999",
                          b"3.5", b"NaN", b"1.#INF", t + t])
    return line[:m.start()] + new + line[m.end():]


def _ifc_hand() -> list:
    def v(case, old, new, name="m.ifc"):
        put(case, name, IFC_MINI.replace(old, new))
        case.meta["single"] = True
    return [
        ("door OverallWidth negative", lambda c, x: v(c, "2100.,915.,.DOOR.", "2100.,-915.,.DOOR.")),
        ("door OverallWidth 1.E400 (inf)", lambda c, x: v(c, "2100.,915.,.DOOR.", "2100.,1.E400,.DOOR.")),
        ("door OverallWidth 0", lambda c, x: v(c, "2100.,915.,.DOOR.", "0.,0.,.DOOR.")),
        ("storey Elevation 1.E400 (inf)", lambda c, x: v(c, ".ELEMENT.,3500.);", ".ELEMENT.,1.E400);")),
        ("storey Elevation -1.E400 and $", lambda c, x: v(c, ".ELEMENT.,0.);", ".ELEMENT.,-1.E400);")),
        ("stair riser negative and count 0", lambda c, x: v(c, "18,17,175.,280.", "0,-17,-175.,0.")),
        ("Pset riser height 1.E400", lambda c, x: v(c, "IFCPOSITIVELENGTHMEASURE(175.)", "IFCPOSITIVELENGTHMEASURE(1.E400)")),
        ("space area negative", lambda c, x: v(c, "'NetFloorArea',$,$,24.", "'NetFloorArea',$,$,-24.")),
        ("space profile 0 x 0", lambda c, x: v(c, "#86,2000.,4000.", "#86,0.,0.")),
        ("space profile 1.E300", lambda c, x: v(c, "#76,6000.,4000.", "#76,1.E300,1.E300")),
        ("extrusion depth 0", lambda c, x: v(c, "#77,3000.);\n#75", "#77,0.);\n#75")),
        ("length unit EXA", lambda c, x: v(c, ".MILLI.,.METRE.", ".EXA.,.METRE.")),
        ("length unit conversion factor 0", lambda c, x: v(c, "#11=IFCSIUNIT(*,.LENGTHUNIT.,.MILLI.,.METRE.);",
                                                           "#11=IFCCONVERSIONBASEDUNIT(#14,.LENGTHUNIT.,'FOOT',#15);\n#14=IFCDIMENSIONALEXPONENTS(1,0,0,0,0,0,0);\n"
                                                           "#15=IFCMEASUREWITHUNIT(IFCLENGTHMEASURE(0.),#16);\n#16=IFCSIUNIT(*,.LENGTHUNIT.,$,.METRE.);")),
        ("no units", lambda c, x: v(c, "#10=IFCUNITASSIGNMENT((#11,#12,#13));", "#10=IFCUNITASSIGNMENT(());")),
        ("placement cycle", lambda c, x: v(c, "#41=IFCLOCALPLACEMENT(#31,#21);", "#41=IFCLOCALPLACEMENT(#51,#21);")),
        ("aggregation cycle", lambda c, x: v(c, "#62=IFCRELAGGREGATES('6YvctVUKr0kugbFTf53O9L',$,$,$,#40,(#50,#52));",
                                             "#62=IFCRELAGGREGATES('6YvctVUKr0kugbFTf53O9L',$,$,$,#40,(#50,#52));\n"
                                             "#63=IFCRELAGGREGATES('6YvctVUKr0kugbFTf53O9X',$,$,$,#50,(#40));")),
        ("duplicate entity ids", lambda c, x: v(c, "#91=IFCLOCALPLACEMENT(#51,#93);", "#91=IFCLOCALPLACEMENT(#51,#93);\n#91=IFCCARTESIANPOINT((1.,1.,1.));")),
        ("dangling references", lambda c, x: v(c, "(#90,#100,#102),#50)", "(#90,#100,#102,#99999),#99998)")),
        ("schema IFC9", lambda c, x: v(c, "FILE_SCHEMA(('IFC4'))", "FILE_SCHEMA(('IFC9'))")),
        ("schema IFC2X3 with IFC4 attributes", lambda c, x: v(c, "FILE_SCHEMA(('IFC4'))", "FILE_SCHEMA(('IFC2X3'))")),
        ("header only", lambda c, x: v(c, IFC_MINI[IFC_MINI.index("#1="):IFC_MINI.index("ENDSEC;\nEND")], "")),
        ("empty file", lambda c, x: (put(c, "m.ifc", b""), c.meta.update(single=True))),
        ("UTF-8 BOM and CRLF", lambda c, x: (put(c, "m.ifc", b"\xef\xbb\xbf" + IFC_MINI.replace("\n", "\r\n").encode()), c.meta.update(single=True))),
        ("ifcZIP named .ifc", lambda c, x: (put(c, "m.ifc", zip_bytes({"m.ifc": IFC_MINI.encode()})), c.meta.update(single=True))),
        ("10000 storeys", lambda c, x: v(c, "ENDSEC;\nEND", "".join(
            f"#{10000 + i}=IFCBUILDINGSTOREY('S{i:021d}',$,'L{i}',$,$,#51,$,$,.ELEMENT.,{i * 3000.});\n" for i in range(10000)) + "ENDSEC;\nEND")),
        ("door with string-typed width", lambda c, x: v(c, "2100.,915.,.DOOR.", "'2100','915',.DOOR.")),
        ("property value text where a length is expected", lambda c, x: v(c, "IFCPOSITIVELENGTHMEASURE(175.)", "IFCLABEL('one hundred')")),
    ]


def gen_ifc(ctx: dict, rng: random.Random, case: Case) -> None:
    weights = [5, 3, 2, 1][:len(ctx["seeds"])]
    name, data, lines = rng.choices(ctx["seeds"], weights)[0]
    if rng.random() < 0.25 or not lines:
        out, how = mutate_bytes(rng, data)
    else:
        out = bytearray(data)
        picks = sorted(rng.sample(lines, min(len(lines), rng.randint(1, 6))), reverse=True)
        max_ref = len(lines) * 3
        ops = []
        for a, b in picks:
            op = rng.choice(["tok", "tok", "tok", "del", "dup", "trunc"])
            ops.append(op)
            line = bytes(out[a:b])
            if op == "tok":
                for _ in range(rng.randint(1, 3)):
                    line = mutate_ifc_line(rng, line, max_ref)
                out[a:b] = line
            elif op == "del":
                out[a:b] = b""
            elif op == "dup":
                out[b:b] = b"\n" + line
            else:
                cut = rng.randrange(max(1, len(line)))
                out[a:b] = line[:cut] + b");"
        out, how = bytes(out), "lines:" + "+".join(ops)
    put(case, Path(name).stem[:20] + ".ifc", out)
    case.meta["single"] = True
    case.label = f"{name[:20]}:{how}"


SIZE_ATTR = re.compile(r"width|height|area|length|rise|riser|going|tread|thickness|distance|travel|depth|clear|count|number_of|risers|treads|occupant|elevation")
# 10 km, 2 km2 (the largest buildings: 1.7 km2), in inch^dim; Quantity.dim is 1/2 before 7aa436a and "length"/"area" since
MAX_BASE = {1: 10_000 * 1000 / 25.4, 2: 2e6 * (1000 / 25.4) ** 2, "length": 10_000 * 1000 / 25.4, "area": 2e6 * (1000 / 25.4) ** 2}


def bad_numbers(doc: dict, adapter: str) -> list[dict]:
    """Non-finite or negative sizes anywhere in an evidence document."""
    from normir import Quantity

    out = []
    try:
        json.dumps(doc, allow_nan=False, default=str)
    except ValueError as e:
        out.append(issue("non-finite number (NaN/inf) in the evidence document", adapter, str(e)))

    def check(type_, attr, obs):
        for o in obs if isinstance(obs, list) else []:
            v = o.get("value") if isinstance(o, dict) else o
            s = str(v)
            if isinstance(v, float) and v != v or re.search(r"(?i)\b(nan|inf|infinity)\b", s):
                out.append(issue(f"non-finite {attr} value", f"{adapter} ({type_}.{attr})", f"{s[:60]} at {o.get('at') if isinstance(o, dict) else ''}"))
                return
            if SIZE_ATTR.search(attr):
                q = Quantity.parse(s) if isinstance(v, str) else None
                num = q.base if q else v if isinstance(v, (int, float)) and not isinstance(v, bool) else None
                if num is not None and num < 0 and "elevation" not in attr:  # a basement is below the datum
                    out.append(issue(f"negative {attr}", f"{adapter} ({type_}.{attr})", f"{s[:60]} at {o.get('at') if isinstance(o, dict) else ''}"))
                    return
                if q is not None and q.base > MAX_BASE.get(q.dim, float("inf")):
                    out.append(issue(f"implausible {attr} (over 10 km or 2 km2)", f"{adapter} ({type_}.{attr})",
                                     f"{s[:60]} at {o.get('at') if isinstance(o, dict) else ''}"))
                    return
    for k, obs in (doc.get("facts") or {}).items():
        check("subject", k, obs)
    for e in doc.get("elements") or []:
        for k, obs in (e.get("facts") or {}).items():
            check(e.get("type"), k, obs)
    seen, uniq = set(), []
    for i in out:
        if i["symptom"] + i["frame"] not in seen:
            seen.add(i["symptom"] + i["frame"])
            uniq.append(i)
    return uniq


def run_ifc(case: Case) -> dict:
    from adapters import ifc

    doc = ifc.extract(only_file(case.inp))
    return verdict(bad_numbers(doc, "adapters/ifc.py"), f"{len(doc.get('elements') or [])} elements")


# ================================================================ target: dxf (adapters/dxf.py analyse_file)

DXF_FLOAT_CODES = set(range(10, 60)) | set(range(110, 150)) | set(range(210, 240)) | set(range(1010, 1060))
DXF_INT_CODES = set(range(60, 100)) | set(range(170, 180)) | set(range(270, 290)) | set(range(370, 390))
DXF_ENT = ["LINE", "ARC", "CIRCLE", "LWPOLYLINE", "POLYLINE", "INSERT", "TEXT", "MTEXT", "DIMENSION", "HATCH", "SPLINE", "ELLIPSE", "ATTRIB", "BLOCK", "VIEWPORT"]


def synth_dxf(insunits: int = 4, radius: float = 915.0, extra=None) -> bytes:
    import ezdxf

    doc = ezdxf.new("R2018", setup=True)
    doc.header["$INSUNITS"] = insunits
    for name in ("A-DOOR", "A-AREA", "A-WALL", "A-FLOR-STRS", "A-ANNO-TEXT", "A-ANNO-DIMS"):
        doc.layers.add(name)
    blk = doc.blocks.new("DOOR-915")
    blk.add_line((0, 0), (radius, 0), dxfattribs={"layer": "A-DOOR"})
    blk.add_arc((0, 0), radius, 0, 90, dxfattribs={"layer": "A-DOOR"})
    msp = doc.modelspace()
    msp.add_lwpolyline([(0, 0), (6000, 0), (6000, 4000), (0, 4000)], close=True, dxfattribs={"layer": "A-AREA"})
    msp.add_lwpolyline([(6000, 0), (8000, 0), (8000, 4000), (6000, 4000)], close=True, dxfattribs={"layer": "A-AREA"})
    for a, b in [((0, 0), (8000, 0)), ((8000, 0), (8000, 4000)), ((8000, 4000), (0, 4000)), ((0, 4000), (0, 0)), ((6000, 0), (6000, 1500)), ((6000, 2500), (6000, 4000))]:
        msp.add_line(a, b, dxfattribs={"layer": "A-WALL"})
    msp.add_blockref("DOOR-915", (6000, 1500), dxfattribs={"layer": "A-DOOR", "rotation": 90})
    msp.add_text("OFFICE", dxfattribs={"layer": "A-ANNO-TEXT", "height": 200}).set_placement((2500, 2000))
    msp.add_text("101", dxfattribs={"layer": "A-ANNO-TEXT", "height": 200}).set_placement((2500, 1700))
    msp.add_text("CORRIDOR", dxfattribs={"layer": "A-ANNO-TEXT", "height": 200}).set_placement((6300, 2000))
    msp.add_mtext("STAIR 1\\P18 R @ 175", dxfattribs={"layer": "A-ANNO-TEXT", "char_height": 150}).set_location((8500, 1000))
    for i in range(18):
        msp.add_line((8500, 1500 + 280 * i), (9700, 1500 + 280 * i), dxfattribs={"layer": "A-FLOR-STRS"})
    msp.add_linear_dim(base=(0, -600), p1=(0, 0), p2=(6000, 0), dxfattribs={"layer": "A-ANNO-DIMS"}).render()
    if extra:
        extra(doc, msp)
    s = io.StringIO()
    doc.write(s)
    return s.getvalue().encode()


def seeds_dxf() -> dict:
    seeds = [("synth.dxf", synth_dxf())]
    for p in sorted(INPUTS.glob("dxf/innerscene-*/*.dxf")):
        seeds.append((p.name, p.read_bytes()))
    farm = next(iter(sorted(INPUTS.glob("dxf/freefarmhouse/*.dxf"))), None)
    if farm:
        seeds.append((farm.name, farm.read_bytes()))
    return {"seeds": seeds}


def _dxf_hand() -> list:
    def s(case, **kw):
        put(case, "h.dxf", synth_dxf(**kw))
        case.meta["single"] = True

    def recursive(doc, msp):
        b = doc.blocks.new("LOOP")
        b.add_line((0, 0), (1000, 0))
        b.add_blockref("LOOP", (10, 10))
        msp.add_blockref("LOOP", (0, 0))

    def mutual(doc, msp):
        a, b = doc.blocks.new("A"), doc.blocks.new("B")
        a.add_blockref("B", (1, 1), dxfattribs={"xscale": 2, "yscale": 2})
        b.add_blockref("A", (1, 1), dxfattribs={"xscale": 2, "yscale": 2})
        a.add_arc((0, 0), 900, 0, 90, dxfattribs={"layer": "A-DOOR"})
        msp.add_blockref("A", (0, 0))

    def scale(v):
        return lambda doc, msp: msp.add_blockref("DOOR-915", (100, 100), dxfattribs={"layer": "A-DOOR", "xscale": v, "yscale": v})

    def many_texts(doc, msp):
        for i in range(60000):
            msp.add_text(f"DOOR {i}", dxfattribs={"layer": "A-ANNO-TEXT", "height": 100}).set_placement((i % 300 * 400, i // 300 * 400))

    def huge_poly(doc, msp):
        msp.add_lwpolyline([(i, (i * 7919) % 10000) for i in range(200000)], close=True, dxfattribs={"layer": "A-AREA"})

    def bulge(v):
        return lambda doc, msp: msp.add_lwpolyline([(0, 0, 0, 0, v), (5000, 0, 0, 0, v), (5000, 5000), (0, 5000)], format="xyseb",
                                                   close=True, dxfattribs={"layer": "A-AREA"})

    def big_circle(doc, msp):
        msp.add_circle((0, 0), 1e12, dxfattribs={"layer": "A-AREA"})
        msp.add_arc((0, 0), 1e12, 0, 90, dxfattribs={"layer": "A-DOOR"})

    def hatch(doc, msp):
        h = msp.add_hatch(dxfattribs={"layer": "A-AREA"})
        h.paths.add_polyline_path([(0, 0), (10, 10), (10, 0), (0, 10)], is_closed=True)  # self-intersecting
        h2 = msp.add_hatch(dxfattribs={"layer": "A-AREA"})
        ep = h2.paths.add_edge_path()
        ep.add_arc((0, 0), 1e9, 0, 359)

    def nan_text(case, x):
        d = synth_dxf().decode()
        put(case, "h.dxf", d.replace("6000.0", "nan", 3).replace("2500.0", "inf"))
        case.meta["single"] = True

    def dims_nan(doc, msp):
        msp.add_linear_dim(base=(0, -600), p1=(0, 0), p2=(1e-12, 0), dxfattribs={"layer": "A-ANNO-DIMS"}).render()
        msp.add_aligned_dim(p1=(0, 0), p2=(0, 0), distance=500, dxfattribs={"layer": "A-ANNO-DIMS"}).render()

    return [
        ("arc radius 1e12 / circle 1e12", lambda c, x: s(c, extra=big_circle)),
        ("door block radius 1e12", lambda c, x: s(c, radius=1e12)),
        ("door block radius 0", lambda c, x: s(c, radius=0.0)),
        ("recursive block", lambda c, x: s(c, extra=recursive)),
        ("mutually recursive blocks with scale 2", lambda c, x: s(c, extra=mutual)),
        ("insert scale 0", lambda c, x: s(c, extra=scale(0))),
        ("insert scale 1e300", lambda c, x: s(c, extra=scale(1e300))),
        ("insert scale -1", lambda c, x: s(c, extra=scale(-1))),
        ("bulge 1e10 polyline room", lambda c, x: s(c, extra=bulge(1e10))),
        ("bulge 1e-12 polyline room", lambda c, x: s(c, extra=bulge(1e-12))),
        ("200k-vertex room polygon", lambda c, x: s(c, extra=huge_poly)),
        ("60k text entities", lambda c, x: s(c, extra=many_texts)),
        ("self-intersecting hatch and 1e9 arc edge", lambda c, x: s(c, extra=hatch)),
        ("zero-length dimensions", lambda c, x: s(c, extra=dims_nan)),
        ("nan/inf coordinates", nan_text),
        ("INSUNITS 8 (microinch)", lambda c, x: s(c, insunits=8)),
        ("INSUNITS 11 (angstrom)", lambda c, x: s(c, insunits=11)),
        ("INSUNITS 7 (km)", lambda c, x: s(c, insunits=7)),
        ("INSUNITS 0, no MEASUREMENT", lambda c, x: s(c, insunits=0)),
        ("empty file", lambda c, x: (put(c, "h.dxf", b""), c.meta.update(single=True))),
        ("binary DXF sentinel", lambda c, x: (put(c, "h.dxf", b"AutoCAD Binary DXF\r\n\x1a\x00" + b"\x00" * 200), c.meta.update(single=True))),
        ("only EOF", lambda c, x: (put(c, "h.dxf", b"  0\nEOF\n"), c.meta.update(single=True))),
        ("UTF-16 encoded DXF", lambda c, x: (put(c, "h.dxf", b"\xff\xfe" + synth_dxf().decode().encode("utf-16-le")), c.meta.update(single=True))),
        ("odd number of lines", lambda c, x: (put(c, "h.dxf", synth_dxf()[:-1] + b"\n999\n"), c.meta.update(single=True))),
    ]


def gen_dxf(ctx: dict, rng: random.Random, case: Case) -> None:
    seeds = ctx["seeds"]
    name, data = rng.choices(seeds, [4] + [3] * (len(seeds) - 2) + [1] if len(seeds) > 2 else [1] * len(seeds))[0]
    if rng.random() < 0.25:
        out, how = mutate_bytes(rng, data)
    else:
        text = data.decode("latin-1")
        lines = text.split("\n")
        ops = []
        for _ in range(rng.randint(1, 6)):
            op = rng.choice(["val", "val", "val", "layer", "ent_del", "ent_dup", "ent_type", "units"])
            ops.append(op)
            n = len(lines)
            if n < 4:
                break
            if op in ("val", "layer"):
                for _ in range(20):
                    i = rng.randrange(1, n, 2) if n > 2 else 1
                    try:
                        code = int(lines[i - 1].strip())
                    except ValueError:
                        continue
                    if op == "layer" and code in (8, 2):
                        lines[i] = rng.choice(["A-DOOR", "A-AREA", "ROOM", "STAIR", "A-FLOR-STRS", "DOOR", "D-915", "A-WALL", "0", "", "部屋", "a" * 300])
                        break
                    if op == "val" and code in DXF_FLOAT_CODES:
                        lines[i] = rng.choice(["nan", "inf", "-inf", "1e308", "-1e308", "1e20", "-1e20", "0", "1e-300", "123456789012345678901234567890", "-0", "1e12", "x"])
                        break
                    if op == "val" and code in DXF_INT_CODES:
                        lines[i] = rng.choice(["-1", "0", "32767", "99999999999", "abc", "-32768", "256"])
                        break
            elif op == "units":
                try:
                    j = lines.index("$INSUNITS")
                    lines[j + 2] = str(rng.choice([0, 1, 2, 3, 6, 7, 8, 11, 12, 13, 21, 22, 99, -1]))
                except (ValueError, IndexError):
                    pass
            else:
                starts = [i for i in range(0, n - 1, 2) if lines[i].strip() == "0" and lines[i + 1].strip() in DXF_ENT]
                if not starts:
                    continue
                a = rng.choice(starts)
                b = next((i for i in range(a + 2, n - 1, 2) if lines[i].strip() == "0"), n)
                if op == "ent_del":
                    del lines[a:b]
                elif op == "ent_dup":
                    lines[b:b] = lines[a:b] * rng.choice([1, 2, 50])
                else:
                    lines[a + 1] = rng.choice(DXF_ENT)
        out, how = "\n".join(lines).encode("latin-1"), "pairs:" + "+".join(ops)
    put(case, "d.dxf", out)
    case.meta["single"] = True
    case.label = f"{name[:24]}:{how}"


def run_dxf(case: Case) -> dict:
    from adapters import dxf

    p = only_file(case.inp)
    r = dxf.analyse_file(p, p.name)
    doc = {"facts": r.get("facts"), "elements": r.get("elements"), "sheets": r.get("sheets")}
    issues = bad_numbers(doc, "adapters/dxf.py")
    return verdict(issues, f"{len(r.get('elements') or [])} elements, {len(r.get('skipped') or [])} skipped")


# ================================================================ target: drawings (adapters/drawings analyse)

DRW = "adapters/drawings/reader.py"


def seeds_drawings() -> dict:
    seeds = [("synth.pdf", make_pdf([{"content": drawing_content(), "mediabox": "0 0 1224 792"}]))]
    q = INPUTS / "mlit-eizen-bim-drawings/eizen-qa.pdf"
    if q.exists():
        seeds.append(("eizen-qa-p1.pdf", pdf_pages(q.read_bytes(), [0])))
    for p in sorted(INPUTS.glob("regulations/*/*.pdf"))[:1]:
        seeds.append(("reg-p1.pdf", pdf_pages(p.read_bytes(), [0])))
    return {"seeds": seeds}


def _drawings_hand() -> list:
    def one(case, data, name="s.pdf"):
        put(case, name, data)
        case.meta["single"] = True

    def mb(box, content=None, extra=""):
        return make_pdf([{"content": content if content is not None else drawing_content(), "mediabox": box, "extra": extra}])

    def png_pair(case, x):
        from PIL import Image, ImageDraw
        im = Image.new("RGB", (400, 200), "white")
        ImageDraw.Draw(im).text((20, 80), "DOOR 101  3'-0\" x 7'-0\"", fill="black")
        b = io.BytesIO()
        im.save(b, "PNG")
        put(case, "a.png", b.getvalue())
        put(case, "b.png", png_bytes(30000, 30000))

    def tiff_frames(case, x):
        from PIL import Image
        frames = [Image.new("L", (16, 16), 255) for _ in range(400)]
        b = io.BytesIO()
        frames[0].save(b, "TIFF", save_all=True, append_images=frames[1:])
        one(case, b.getvalue(), "s.tif")

    def dpi_png(dpi):
        def f(case, x):
            from PIL import Image
            b = io.BytesIO()
            Image.new("RGB", (300, 300), "white").save(b, "PNG", dpi=(dpi, dpi))
            one(case, b.getvalue(), "s.png")
        return f

    pages500 = lambda: make_pdf([{"content": drawing_content(tokens=[(100, 100, 10, f"A-{i:03d}"), (100, 200, 8, "DOOR 101 3'-0\" x 7'-0\""),  # noqa: E731
                                                                    (300, 300, 8, "STAIR 1 18 R @ 7\" 17 T @ 11\""), (300, 330, 8, "OFFICE 101 CORRIDOR 102 EXIT")])}
                                 for i in range(500)], flate=True)
    return [
        ("MediaBox 200000 x 200000 pt, no text (render for OCR)", lambda c, x: one(c, mb("0 0 200000 200000", b"0 0 m 10 10 l S"))),
        ("MediaBox 14400 x 14400 pt, no text", lambda c, x: one(c, mb("0 0 14400 14400", b"0 0 m 10 10 l S"))),
        ("MediaBox 0 x 0", lambda c, x: one(c, mb("0 0 0 0"))),
        ("MediaBox inverted", lambda c, x: one(c, mb("1224 792 0 0"))),
        ("MediaBox negative size", lambda c, x: one(c, mb("0 0 -1224 -792"))),
        ("Rotate 45", lambda c, x: one(c, mb("0 0 1224 792", extra="/Rotate 45"))),
        ("Rotate -270", lambda c, x: one(c, mb("0 0 1224 792", extra="/Rotate -270"))),
        ("UserUnit 75000", lambda c, x: one(c, mb("0 0 1224 792", extra="/UserUnit 75000"))),
        ("text with font size 0 and 1e6", lambda c, x: one(c, mb("0 0 1224 792", drawing_content().replace(b" Tf ", b" Tf 0 Tz ").replace(b"/F1 7 Tf", b"/F1 1000000 Tf")))),
        ("text matrix singular", lambda c, x: one(c, mb("0 0 1224 792", drawing_content().replace(b" Td ", b" Td 0 0 0 0 0 0 Tm ")))),
        ("invisible text (3 Tr)", lambda c, x: one(c, mb("0 0 1224 792", b"3 Tr\n" + drawing_content()))),
        ("content stream decompresses to 1.7 GB", lambda c, x: one(c, bomb_pdf())),
        ("page tree loop", lambda c, x: one(c, make_pdf([{"content": drawing_content()}], pages_obj=b"<< /Type /Pages /Kids [2 0 R 4 0 R] /Count 2 >>"))),
        ("500-page sheet set", lambda c, x: one(c, pages500())),
        ("PNG after a normal PNG: 30000x30000 bomb", png_pair),
        ("PNG 30000x30000 alone", lambda c, x: one(c, png_bytes(30000, 30000), "s.png")),
        ("PNG with 100 million dpi", dpi_png(100_000_000)),
        ("PNG with 1 dpi", dpi_png(1)),
        ("TIFF with 400 frames", tiff_frames),
        ("JPEG truncated", lambda c, x: one(c, b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 50, "s.jpg")),
        ("PDF named .png", lambda c, x: one(c, x["seeds"][0][1], "s.png")),
        ("PNG named .pdf", lambda c, x: one(c, png_bytes(100, 100), "s.pdf")),
        ("empty .pdf", lambda c, x: one(c, b"", "s.pdf")),
    ]


def gen_drawings(ctx: dict, rng: random.Random, case: Case) -> None:
    name, data = rng.choice(ctx["seeds"])
    if name == "synth.pdf" and rng.random() < 0.5:
        content = drawing_content()
        content, how = mutate_bytes(rng, content, rng.randint(1, 3)) if rng.random() < 0.3 else (content, "")
        nums = list(re.finditer(rb"-?\d+(?:\.\d+)?", content))
        for m in sorted(rng.sample(nums, min(len(nums), rng.randint(1, 5))), key=lambda m: -m.start()):
            content = content[:m.start()] + rng.choice([b"0", b"-1", b"1e38", b"-1e38", b"99999999", b"0.0001", b"-0"]) + content[m.end():]
        box = rng.choice(["0 0 1224 792", "0 0 1224 792", "0 0 0 0", "0 0 99999 99999", "-500 -500 1224 792", "0 0 1 1", "0 0 1224 -792"])
        extra = rng.choice(["", "", "/Rotate 90", "/Rotate 180", "/Rotate 33", "/UserUnit 10"])
        out = make_pdf([{"content": content, "mediabox": box, "extra": extra}])
        how = f"content:{how}:box={box}:{extra}"
    else:
        out, how = mutate_bytes(rng, data)
    put(case, "s.pdf", out)
    case.meta["single"] = True
    case.label = f"{name}:{how}"


def run_drawings(case: Case) -> dict:
    import adapters.drawings as D

    files = sorted(p for p in case.inp.rglob("*") if p.is_file())
    t0 = time.time()
    doc = D.analyse(files, case.inp)
    reader_seconds = round(time.time() - t0, 2)  # the oracle below has its own budget; a hang is the reader's time
    issues = bad_numbers({k: v for k, v in doc.items() if k != "sources"}, "adapters/drawings")
    for s in doc.get("sheets") or []:
        w, h = s.get("width"), s.get("height")
        if not (isinstance(w, (int, float)) and isinstance(h, (int, float)) and 0 < w < 1e7 and 0 < h < 1e7):
            issues.append(issue("sheet with a zero, negative or absurd size", src_line(DRW, "Sheet(file=name, page=i + 1, width=round(pdf[i]"), f"{s['file']} p{s['page']}: {w} x {h}"))
    class OracleTimeout(Exception):
        pass

    def alarm(*_):
        raise OracleTimeout
    for f in files:
        if f.suffix.lower() != ".pdf":
            continue
        # the oracle's own reading gets 10 s: a corrupt stream can take pdfminer minutes, and that is not the reader's time
        old = signal.signal(signal.SIGALRM, alarm)
        signal.alarm(10)
        try:
            import pdfplumber
            with pdfplumber.open(str(f)) as pdf:
                # visible characters only: on the page, with a real size (text drawn at scale 0 or off the sheet is not text)
                layer = [sum(1 for ch in pg.chars if ch.get("text", "").strip() and ch["x1"] - ch["x0"] > 0.5 and ch["bottom"] - ch["top"] > 0.5
                             and ch["x0"] >= 0 and ch["top"] >= 0 and ch["x1"] <= pg.width and ch["bottom"] <= pg.height) for pg in pdf.pages[:50]]
        except Exception:  # noqa: BLE001 - the independent check could not read it either (or ran out of time)
            continue
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
        for s in doc.get("sheets") or []:
            if s["file"] == f.name and s["page"] <= len(layer) and layer[s["page"] - 1] >= 100 and s.get("text") != "layer":
                issues.append(issue("page with a text layer read as having none", src_line(DRW, "MIN_LAYER_CHARS ="),
                                    f"{f.name} p{s['page']}: pdfplumber sees {layer[s['page'] - 1]} chars, reader says text={s.get('text')}"))
    skipped = [x for x in (doc["sources"][0].get("skipped") or []) if isinstance(x, dict) and "not readable" in str(x.get("reason"))]
    return {**verdict(issues, f"{len(doc.get('sheets') or [])} sheets, {len(doc.get('elements') or [])} elements, {len(skipped)} unreadable"),
            "seconds": reader_seconds}


# ================================================================ target: code (app.scan.collect, model disabled)

CODE_SUFFIX = {".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".rb", ".rake", ".ex", ".exs", ".erb", ".yml", ".yaml", ".json", ".env", ".html", ".heex", ".pem"}
MANIFEST_NAMES = {"package.json", "Gemfile", "Gemfile.lock", "mix.exs", "mix.lock", "requirements.txt", "pyproject.toml", "package-lock.json", "Pipfile"}


def seeds_code() -> dict:
    repos = {}
    for repo in sorted(p for p in (INPUTS / "repos").iterdir() if p.is_dir()):
        files, manifests = [], {}
        for dp, dns, fns in os.walk(repo):
            dns[:] = sorted(d for d in dns if d not in {".git", "node_modules", "vendor", "deps", "_build", "dist", "build"})
            for fn in sorted(fns):
                p = Path(dp) / fn
                rel = p.relative_to(repo).as_posix()
                try:
                    size = p.stat().st_size
                except OSError:
                    continue
                if fn in MANIFEST_NAMES and "/" not in rel and size < 3_000_000:
                    manifests[rel] = p.read_bytes()
                elif p.suffix.lower() in CODE_SUFFIX and size < 60_000 and not p.is_symlink():
                    files.append(rel)
        step = max(1, len(files) // 250)
        repos[repo.name] = {"root": repo, "files": files[::step], "manifests": manifests}
    return {"repos": repos}


def _code_hand() -> list:
    def repo(case, files: dict, links: dict | None = None):
        for rel, data in files.items():
            put(case, rel, data)
        for rel, target in (links or {}).items():
            p = case.inp / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(target, p)
    srv = "const express = require('express');\nconst app = express();\napp.get('/u', (req, res) => db.query('SELECT * FROM u WHERE id=' + req.query.id));\n"
    py = "import hashlib\n\ndef set_password(user, password):\n    user.pw = hashlib.md5(password.encode()).hexdigest()\n"
    rb = "class User < ApplicationRecord\n  def self.digest(password)\n    Digest::MD5.hexdigest(password)\n  end\nend\n"
    ex = "defmodule App.Accounts do\n  def weak(password), do: :crypto.hash(:md5, password)\nend\n"

    def equiv(case, rel, text: str, how: str):
        var = {"crlf": text.replace("\n", "\r\n").encode(), "bom": b"\xef\xbb\xbf" + text.encode(), "cr": text.replace("\n", "\r").encode(),
               "u2028": text.replace("\n", "\n// \u2028\n" if rel.endswith(".js") else "\n# \u2028\n", 1).encode()}[how]
        ref = text.replace("\n", "\n// x\n" if rel.endswith(".js") else "\n# x\n", 1).encode() if how == "u2028" else text.encode()
        put(case, f"ref/{rel}", ref)
        put(case, f"repo/{rel}", var)
        case.meta.update(equiv=True, symptom=f"{how} line endings change findings in {Path(rel).suffix}")
    return [
        ("only a Gemfile", lambda c, x: repo(c, {"Gemfile": "source 'https://rubygems.org'\ngem 'rails', '7.1.3'\n"})),
        ("only a Gemfile.lock with garbage", lambda c, x: repo(c, {"Gemfile.lock": b"GEM\n  specs:\n    rails (\xff\xfe)\n    (((\n"})),
        ("empty files named like code", lambda c, x: repo(c, {f"app/empty{e}": b"" for e in (".py", ".js", ".ts", ".tsx", ".rb", ".ex", ".exs", ".erb", ".yml", ".json", ".env", ".pem")})),
        ("binary named .js", lambda c, x: repo(c, {"server.js": png_bytes(64, 64), "package.json": '{"dependencies": {"express": "4.0.0"}}'})),
        ("NUL after 4096 bytes in .py/.rb/.ex/.js", lambda c, x: repo(c, {"a.py": py + "#" * 5000 + "\x00\n", "b.rb": rb + "#" * 5000 + "\x00\n",
                                                                        "c.ex": ex + "#" * 5000 + "\x00\n", "d.js": srv + "//" + "x" * 2900 + "\n" + "\x00\n"})),
        ("package.json is a list", lambda c, x: repo(c, {"server.js": srv, "package.json": "[]"})),
        ("package.json dependencies is a list", lambda c, x: repo(c, {"server.js": srv, "package.json": '{"dependencies": ["express"]}'})),
        ("package.json dependencies is a string", lambda c, x: repo(c, {"server.js": srv, "package.json": '{"dependencies": "express"}'})),
        ("package.json not UTF-8", lambda c, x: repo(c, {"server.js": srv, "package.json": b'{"name": "\xff\xfe"}'})),
        ("package-lock packages is a list", lambda c, x: repo(c, {"server.js": srv, "package.json": '{"dependencies": {"express": "4"}}',
                                                                  "package-lock.json": '{"packages": [1, 2]}'})),
        ("package-lock v1 dependency is a string", lambda c, x: repo(c, {"server.js": srv, "package.json": '{"dependencies": {"express": "4"}}',
                                                                         "package-lock.json": '{"dependencies": {"express": "4.17.1"}}'})),
        ("config.json nested 50000 deep", lambda c, x: repo(c, {"config/settings.json": "[" * 50000 + "]" * 50000, "app.py": py})),
        ("config.yml billion laughs", lambda c, x: repo(c, {"config/secrets.yml": "a: &a [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n" + "".join(
            f"{chr(98 + i)}: &{chr(98 + i)} [{','.join(['*' + chr(97 + i)] * 9)}]\n" for i in range(10)), "app.py": py})),
        ("Python 30000-term expression", lambda c, x: repo(c, {"deep.py": "x = " + "+".join(["password"] * 30000) + "\n", "app.py": py})),
        ("Python 900 nested calls", lambda c, x: repo(c, {"deep.py": "import hashlib\nx = " + "f(" * 900 + "password" + ")" * 900 + "\n"})),
        ("Python 100 nested defs", lambda c, x: repo(c, {"deep.py": "".join("    " * i + f"def f{i}(password):\n" for i in range(100)) + "    " * 100 + "return hashlib.md5(password)\n"})),
        ("JS 20000 nested arrays", lambda c, x: repo(c, {"deep.js": "const x = " + "[\n" * 20000 + "1" + "]\n" * 20000, "package.json": "{}"})),
        ("JS 20000 nested calls", lambda c, x: repo(c, {"deep.js": "const x = " + "f(\n" * 20000 + "req.query.id" + ")\n" * 20000, "package.json": "{}"})),
        ("JS 999 KB of 2999-char lines", lambda c, x: repo(c, {"big.js": ("var a = '" + "x" * 2985 + "';\n") * 333})),
        ("JS 5 MB minified one line", lambda c, x: repo(c, {"bundle.js": "var a=1;" * 600_000, "app.js": srv})),
        ("Ruby 10000 nested blocks", lambda c, x: repo(c, {"Gemfile.lock": "GEM\n  specs:\n    rails (7.1.3)\n", "app/models/deep.rb": "x = " + "[" * 10000 + "]" * 10000 + "\n"})),
        ("Elixir 10000 nested lists", lambda c, x: repo(c, {"mix.exs": "defmodule A.MixProject do\nend\n", "lib/deep.ex": "defmodule D do\n  def f, do: " + "[" * 10000 + "]" * 10000 + "\nend\n"})),
        ("mix.lock garbage", lambda c, x: repo(c, {"mix.exs": "defmodule A.MixProject do\nend\n", "mix.lock": "%{\"phoenix\": {:hex, :phoenix, 1, [], []}, ((", "lib/a.ex": ex})),
        ("Gemfile.lock with odd versions", lambda c, x: repo(c, {"Gemfile.lock": "GEM\n  specs:\n    rails (abc)\n    psych (99999999999999999999999.0)\n\nRUBY VERSION\n   ruby x\n",
                                                                 "config/application.rb": "module App\n  class Application < Rails::Application\n    config.load_defaults 'x'\n  end\nend\n", "app/models/u.rb": rb})),
        ("symlink loop dirs", lambda c, x: repo(c, {"app.py": py}, {"loop": ".", "a/b": "..", "a/c": "../a"})),
        ("package.json symlink to /dev/zero", lambda c, x: repo(c, {"server.js": srv}, {"package.json": "/dev/zero"})),
        (".git/HEAD binary", lambda c, x: repo(c, {".git/HEAD": b"\xff\xfe\x00ref", "app.py": py})),
        (".git/HEAD ref to a binary file", lambda c, x: repo(c, {".git/HEAD": "ref: refs/heads/main\n", ".git/refs/heads/main": b"\xff\xfe", "app.py": py})),
        (".git is a file pointing to /", lambda c, x: repo(c, {".git": "gitdir: /\n", "app.py": py})),
        ("3000 tiny JS files", lambda c, x: repo(c, {f"src/m{i}.js": f"module.exports = {i};\n" for i in range(3000)})),
        ("unusual extensions", lambda c, x: repo(c, {"APP.PY": py, ".py": py, "a.py.bak": py, "x.env": b"\xff\xfeSECRET=1", ".env.production": "API_KEY=sk_live_abcdefghijklmnop1234\n",
                                                     "key.pem": "-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 900_000 + "\n", "Makefile": "all:\n"})),
        ("utf-16 .py with BOM", lambda c, x: repo(c, {"app.py": b"\xff\xfe" + py.encode("utf-16-le")})),
        ("latin-1 .rb", lambda c, x: repo(c, {"Gemfile.lock": "GEM\n  specs:\n    rails (7.1.3)\n", "app/models/u.rb": ("# caf\xe9\n" + rb).encode("latin-1")})),
        ("CRLF .py equals LF", lambda c, x: equiv(c, "app/auth.py", py * 3, "crlf")),
        ("CRLF .js equals LF", lambda c, x: equiv(c, "server.js", srv * 3, "crlf")),
        ("CRLF .rb equals LF", lambda c, x: equiv(c, "app/models/user.rb", rb * 3, "crlf")),
        ("CRLF .ex equals LF", lambda c, x: equiv(c, "lib/app/accounts.ex", ex * 3, "crlf")),
        ("BOM .py equals no BOM", lambda c, x: equiv(c, "app/auth.py", py * 3, "bom")),
        ("BOM .js equals no BOM", lambda c, x: equiv(c, "server.js", srv * 3, "bom")),
        ("CR-only .py equals LF", lambda c, x: equiv(c, "app/auth.py", py * 3, "cr")),
        ("U+2028 in a .js comment", lambda c, x: equiv(c, "server.js", srv * 3, "u2028")),
        ("U+2028 in a .py comment", lambda c, x: equiv(c, "app/auth.py", py * 3, "u2028")),
    ]


def gen_code(ctx: dict, rng: random.Random, case: Case) -> None:
    name = rng.choice(sorted(ctx["repos"]))
    r = ctx["repos"][name]
    if not r["files"]:
        put(case, "app.py", "x = 1\n")
        return
    picked = rng.sample(r["files"], min(len(r["files"]), rng.randint(1, 5)))
    equiv = rng.random() < 0.15
    base = "repo/" if equiv else ""
    blobs = {rel: (r["root"] / rel).read_bytes() for rel in picked}
    if rng.random() < 0.6:
        blobs.update(r["manifests"])
    how = "copy"
    if equiv:
        rel = rng.choice(picked)
        enc = rng.choice(["crlf", "crlf", "utf-8-sig"])
        for k, v in blobs.items():
            put(case, f"ref/{k}", v)
        blobs[rel] = reencode(rng, blobs[rel], enc)[0]
        case.meta.update(equiv=True, symptom=f"{'BOM' if enc == 'utf-8-sig' else 'CRLF'} changes findings in {Path(rel).suffix}")
        how = f"equiv:{enc}:{rel}"
    else:
        target = rng.choice(list(blobs))
        x = rng.random()
        if x < 0.5:
            blobs[target], how = mutate_bytes(rng, blobs[target])
        elif x < 0.7:
            blobs[target], how = reencode(rng, blobs[target])
        elif target.endswith(".json"):
            try:
                data = json.loads(blobs[target])
                data, how = mutate_structure(rng, data)
                blobs[target] = json.dumps(data).encode()
            except ValueError:
                blobs[target], how = mutate_bytes(rng, blobs[target])
        else:
            blobs[target], how = mutate_bytes(rng, blobs[target], 1)
        how = f"{target}:{how}"
    for k, v in blobs.items():
        put(case, base + k, v)
    case.label = f"{name}:{how}"[:200]


_RECORDED: list = []


def _wrap_adapters() -> None:
    import importlib
    for mod in ("adapters.code_static", "adapters.code_ruby", "adapters.code_elixir", "adapters.deps"):
        try:
            m = importlib.import_module(mod)
        except ImportError:
            continue
        orig = m.analyse
        if getattr(orig, "_fuzz", False):
            continue

        def wrapped(*a, _orig=orig, **k):
            try:
                return _orig(*a, **k)
            except Exception as e:  # noqa: BLE001 - collect() turns this into a note; the fuzzer wants the traceback
                _RECORDED.append(e)
                raise
        wrapped._fuzz = True
        m.analyse = wrapped


def collect_docs(root: Path) -> tuple[list, list]:
    import app.scan as S

    _wrap_adapters()
    _RECORDED.clear()
    docs, notes = S.collect(root, "fuzz", use_reader=False, offline=True)
    if _RECORDED:
        raise _RECORDED[0]
    return docs, notes


def _ats(docs):
    for d in docs:
        for e in d.get("elements") or []:
            ats = e.get("at") if isinstance(e.get("at"), list) else [e.get("at")]
            for a in ats:
                yield d["sources"][0]["id"], e.get("type"), a, json.dumps(e.get("facts"), sort_keys=True, default=str)
        for k, obs in (d.get("facts") or {}).items():
            for o in obs:
                yield d["sources"][0]["id"], "fact:" + k, o.get("at"), json.dumps(o.get("value"), default=str)


def run_code(case: Case) -> dict:
    issues = []
    if case.meta.get("equiv"):
        ref, _ = collect_docs(case.inp / "ref")
        docs, notes = collect_docs(case.inp / "repo")
        a, b = sorted(map(str, _ats(docs))), sorted(map(str, _ats(ref)))
        if a != b:
            only_var, only_ref = sorted(set(a) - set(b)), sorted(set(b) - set(a))
            ext = case.meta.get("symptom", "").rsplit(" ", 1)[-1]
            frame = {".py": "adapters/code_static/pyast.py", ".js": "adapters/code_static/jsast.py", ".ts": "adapters/code_static/jsast.py",
                     ".rb": "adapters/code_ruby", ".ex": "adapters/code_elixir"}.get(ext, "adapters/code_static/config.py")
            issues.append(issue(case.meta.get("symptom", "equivalent repository gives different findings"), frame,
                                f"only with variant: {only_var[:2]}; only in reference: {only_ref[:2]}"))
        root = case.inp / "repo"
    else:
        docs, notes = collect_docs(case.inp)
        root = case.inp
    for src, typ, at, _ in _ats(docs):
        m = re.fullmatch(r"(.+):(\d+)(?:-\d+)?", str(at or ""))
        if not m:
            continue
        p = root / m[1]
        if p.is_file() and not p.is_symlink():
            data = p.read_bytes()
            n = max(data.count(b"\n"), data.count(b"\r")) + 1
            if not 1 <= int(m[2]) <= n:
                issues.append(issue("locator line outside the file", f"adapters ({src})", f"{at} but the file has {n} lines"))
                break
    return verdict(issues, f"{len(docs)} docs, {sum(len(d.get('elements') or []) for d in docs)} elements, notes={[n[:60] for n in notes][:3]}")


# ================================================================ YAML/JSON structure mutation (evidence, packs, configs)

POOL = [None, 0, -1, 1.5e308, float("nan"), float("inf"), "", "x" * 10000, "1e400 mm", "-1 mm", "nan mm", "9" * 400 + " mm",
        "😀\u202e", True, [], {}, [None], {"value": None}, [[[[[[[[[[[["deep"]]]]]]]]]]]], {"a": {"b": {"c": {"d": {}}}}},
        "0 in", "-0 mm", "1210 mm", "Stair", "ifc:x", "a.py:999999999", 10**30, -(10**30), "\x00"]


def _containers(obj, path=()):
    yield path, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                yield from _containers(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:200]):
            if isinstance(v, (dict, list)):
                yield from _containers(v, path + (i,))


def mutate_structure(rng: random.Random, data, ops: int | None = None):
    data = copy.deepcopy(data)
    done = []
    for _ in range(ops or rng.randint(1, 3)):
        conts = [(p, c) for p, c in _containers(data) if c]
        if not conts:
            return rng.choice(POOL), "root"
        path, c = rng.choice(conts)
        key = rng.choice(list(c)) if isinstance(c, dict) else rng.randrange(len(c))
        op = rng.choice(["replace", "replace", "replace", "delete", "dup", "wrap", "multiply", "rename", "swap_ids"])
        done.append(f"{op}@{'/'.join(map(str, path + (key,)))[:60]}")
        if op == "replace":
            c[key] = copy.deepcopy(rng.choice(POOL))
        elif op == "delete":
            del c[key]
        elif op == "dup" and isinstance(c, list):
            c.insert(key, copy.deepcopy(c[key]))
        elif op == "wrap":
            v = c[key]
            for _ in range(rng.choice([1, 2, 30])):
                v = [v] if rng.random() < 0.5 else {"value": v}
            c[key] = v
        elif op == "multiply" and isinstance(c, list):
            c.extend(copy.deepcopy(c[key]) for _ in range(rng.choice([10, 100, 1000])))
        elif op == "rename" and isinstance(c, dict):
            c[rng.choice(["id", "type", "value", "facts", "at", "name", "for", "require", "fact", "😀", "", "Stair", "norms"])] = c.pop(key)
        elif op == "swap_ids":
            c[key] = rng.choice(["id-1", "", "😀", "Stair@x:1", "None", "\u0000"])
    return data, "+".join(done)


def dump_yaml(data) -> bytes:
    import yaml
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=False).encode()


# ================================================================ target: evidence (normir.evidence load_evidence; app evaluate)

def seeds_evidence() -> dict:
    import yaml
    from adapters import dxf
    docs = []
    for p in sorted((SRC / "bench" / "evidence").glob("*.static.yaml")):
        if p.stat().st_size < 70_000:
            docs.append((p.name, "code", yaml.safe_load(p.read_text())))
    for p in sorted(INPUTS.glob("dxf/innerscene-*/*.dxf")):
        d = dxf.analyse([p], p.parent)
        d.pop("sheets", None)
        docs.append((p.stem + ".yaml", "building", json.loads(json.dumps(d, default=str))))
    return {"docs": docs}


def _evidence_hand() -> list:
    def raw(case, text, domain="code", name="doc.yaml"):
        put(case, name, text)
        case.meta["domain"] = domain

    def doc(case, d, domain="code", name="doc.yaml"):
        put(case, name, dump_yaml(d))
        case.meta["domain"] = domain
    src = [{"id": "static", "kind": "static_analysis"}]
    el = lambda i, **f: {"type": "Secret", "id": f"Secret@a{i}.py:1", "at": f"a{i}.py:{i % 9000 + 1}", "facts": {k: [{"value": v}] for k, v in f.items()}}  # noqa: E731
    return [
        ("document is a list", lambda c, x: raw(c, "- a\n- b\n")),
        ("document is a string", lambda c, x: raw(c, "just text\n")),
        ("document is empty", lambda c, x: raw(c, "")),
        ("sources is a string", lambda c, x: doc(c, {"sources": "static", "elements": []})),
        ("source without id", lambda c, x: doc(c, {"sources": [{}], "elements": []})),
        ("source id is a list", lambda c, x: doc(c, {"sources": [{"id": ["a"]}], "elements": [el(1, kind="api_key")]})),
        ("facts is a list", lambda c, x: doc(c, {"sources": src, "facts": ["a"], "elements": []})),
        ("observation is a string", lambda c, x: doc(c, {"sources": src, "facts": {"password_auth": ["yes"]}})),
        ("observation without value", lambda c, x: doc(c, {"sources": src, "facts": {"password_auth": [{"source": "static"}]}})),
        ("value is a list", lambda c, x: doc(c, {"sources": src, "facts": {"password_min_length": [{"value": [8, 12]}]}})),
        ("value is a dict", lambda c, x: doc(c, {"sources": src, "elements": [{"type": "PasswordStore", "id": "p", "facts": {"algorithm": [{"value": {"x": 1}}]}}]})),
        ("elements is a dict", lambda c, x: doc(c, {"sources": src, "elements": {"a": 1}})),
        ("element without id", lambda c, x: doc(c, {"sources": src, "elements": [{"type": "Secret"}]})),
        ("element without type", lambda c, x: doc(c, {"sources": src, "elements": [{"id": "x"}]})),
        ("element at is an int", lambda c, x: doc(c, {"sources": src, "elements": [el(1), {**el(2), "at": 5}]})),
        ("element at is a dict", lambda c, x: doc(c, {"sources": src, "elements": [el(1), {**el(2), "at": {"p": 1}}]})),
        ("subject is a string", lambda c, x: doc(c, {"subject": "repo", "sources": src, "facts": {"password_auth": [{"value": True}]}})),
        ("ids null, unicode and duplicate", lambda c, x: doc(c, {"sources": src, "elements": [{**el(1), "id": None}, {**el(2), "id": None, "type": "Query"},
                                                                                            {**el(3), "id": "😀\u202e"}, {**el(4), "id": "😀\u202e"}]})),
        ("20000 elements (quadratic reconciliation)", lambda c, x: doc(c, {"sources": src, "elements": [el(i, kind="api_key") for i in range(20000)]})),
        ("one fact with 5000 values", lambda c, x: doc(c, {"sources": src, "facts": {"password_min_length": [{"value": i} for i in range(5000)],
                                                                                      "password_auth": [{"value": True}]}})),
        ("40 facts with 2 values each", lambda c, x: doc(c, {"sources": src, "facts": {**{f"password_{k}": [{"value": True}, {"value": False}] for k in
            ("auth", "min_length", "max_length", "composition_rules", "breach_check", "hint", "expiry", "unicode", "truncation", "paste_blocked")},
            "password_min_length": [{"value": v} for v in (1, 8, 12, 15, 64)]}})),
        ("values 1e400-digit quantities", lambda c, x: doc(c, {"sources": [{"id": "ifc"}], "elements": [{"type": "Door", "id": "d", "facts": {
            "clear_width": [{"value": "9" * 400 + " mm"}, {"value": "-0 mm"}]}}]}, "building")),
        ("YAML nested 50000 deep", lambda c, x: raw(c, "facts: {a: [{value: " + "[" * 50000 + "]" * 50000 + "}]}\n")),
        ("YAML billion laughs", lambda c, x: raw(c, "sources: [{id: s}]\nfacts:\n  a: &a [{value: 1},{value: 2},{value: 3},{value: 4},{value: 5},{value: 6},{value: 7},{value: 8},{value: 9}]\n"
                                                   + "".join(f"  {chr(98 + i)}: &{chr(98 + i)} [{','.join(['*' + chr(97 + i)] * 9)}]\n" for i in range(8)))),
        ("10 MB string value", lambda c, x: doc(c, {"sources": src, "facts": {"password_auth": [{"value": "x" * 10_000_000}]}})),
        ("non-string fact names", lambda c, x: raw(c, "sources: [{id: s}]\nfacts: {1: [{value: 1}], null: [{value: 2}], [a]: x}\n")),
        ("YAML python tag", lambda c, x: raw(c, "!!python/object/apply:os.system ['echo pwned']\n")),
    ]


def gen_evidence(ctx: dict, rng: random.Random, case: Case) -> None:
    name, domain, d = rng.choice(ctx["docs"])
    if rng.random() < 0.8:
        d, how = mutate_structure(rng, d)
        try:
            data = dump_yaml(d)
        except Exception:  # noqa: BLE001 - deep values the dumper refuses
            data, how = json.dumps(d, default=str).encode(), how + ":json"
    else:
        data, how = mutate_bytes(rng, dump_yaml(d))
    put(case, Path(name).stem[:30] + ".yaml", data)
    if rng.random() < 0.2:  # a second, unmutated document to reconcile against
        n2, dom2, d2 = rng.choice([x for x in ctx["docs"] if x[1] == domain])
        put(case, "second-" + Path(n2).stem[:30] + ".yaml", dump_yaml(d2))
    case.meta["domain"] = domain
    case.label = f"{name}:{how}"[:200]


def run_evidence(case: Case) -> dict:
    import yaml
    from normir.evidence import conflicts, load_evidence

    paths = sorted(p for p in case.inp.rglob("*") if p.is_file())
    ev = load_evidence(*paths)
    conflicts(ev)
    raws = [yaml.safe_load(p.read_text()) for p in paths]
    domain = case.meta.get("domain")
    if not domain:
        kinds = {s.get("kind") for r in raws if isinstance(r, dict) for s in (r.get("sources") or []) if isinstance(s, dict)}
        domain = "code" if kinds & {"static_analysis", "dependencies", "llm"} else "building"
    if domain == "code":
        import app.scan as S
        res = S.evaluate(raws, ["nist"])
    else:
        import app.buildings as B
        res = B.evaluate(raws, ["ada"])
    rows = sum(len(r["rows"]) for r in res["results"].values())
    return verdict([], f"{len(ev.elements)} elements, {len(ev.facts)} facts, {rows} rows")


# ================================================================ target: pack (normir.load / validate, then run)

def seeds_pack() -> dict:
    return {"packs": [("nist-800-63b-4", ["nist-800-63b-4"], "code"), ("ada-2010", ["ada-2010"], "building"),
                      ("austin-2024", ["austin-2024", "ibc-2024"], "building"), ("uk-gdpr", ["uk-gdpr", "gdpr"], "code")]}


def _copy_pack(case: Case, dirs: list[str]) -> None:
    for d in dirs:
        shutil.copytree(SRC / "packs" / d, case.inp / d)


def _pack_hand() -> list:
    def p(case, pack="ada-2010", files=None, dirs=None, domain="building"):
        _copy_pack(case, dirs or [pack])
        for rel, text in (files or {}).items():
            put(case, f"{pack}/{rel}", text)
        case.meta.update(pack=pack, domain=domain)

    def rm(case, rel):
        (case.inp / rel).unlink()
    deep = "require: " + "{all: [" * 3000 + "true" + "]}" * 3000 + "\n"
    laughs = ("terms:\n  - name: laugh\n    for: {d: Door}\n    cite: {section: '1'}\n    value: &a0 {all: [true, true, true, true, true, true, true, true, true, true]}\n"
              + "".join(f"  - name: laugh{i}\n    cite: {{section: '1'}}\n    value: &a{i} {{all: [{', '.join(['*a' + str(i - 1)] * 10)}]}}\n" for i in range(1, 9)))
    return [
        ("package.yaml empty", lambda c, x: p(c, files={"package.yaml": ""})),
        ("package.yaml without 'package'", lambda c, x: p(c, files={"package.yaml": "title: x\n"})),
        ("package.yaml is a list", lambda c, x: p(c, files={"package.yaml": "- a\n"})),
        ("extends itself", lambda c, x: p(c, files={"package.yaml": "package: ada-2010\nextends: ada-2010\n"})),
        ("extends a missing pack", lambda c, x: p(c, files={"package.yaml": "package: ada-2010\nextends: nope\n"})),
        ("extends outside the packs", lambda c, x: p(c, files={"package.yaml": "package: ada-2010\nextends: ../../../../../../etc\n"})),
        ("patches without op", lambda c, x: p(c, "austin-2024", dirs=["austin-2024", "ibc-2024"], files={"package.yaml": "package: austin-2024\nextends: ibc-2024\npatches: [{kind: norm}]\n"})),
        ("section is null", lambda c, x: p(c, files={"extra.yaml": "norms:\n"})),
        ("section is a mapping", lambda c, x: p(c, files={"extra.yaml": "norms: {a: 1}\n"})),
        ("items are strings", lambda c, x: p(c, files={"extra.yaml": "norms: [a, b]\n"})),
        ("item without name", lambda c, x: p(c, files={"extra.yaml": "norms: [{title: x}]\n"})),
        ("item name is a list", lambda c, x: p(c, files={"extra.yaml": "predicates: [{name: [a, b]}]\n"})),
        ("file is a list", lambda c, x: p(c, files={"extra.yaml": "- norms\n"})),
        ("norm without cite", lambda c, x: p(c, files={"extra.yaml": "norms: [{name: X1, for: {d: Door}, require: true}]\n"})),
        ("norm require is a number", lambda c, x: p(c, files={"extra.yaml": "norms: [{name: X1, for: {d: Door}, cite: {section: '1'}, require: 5}]\n"})),
        ("norm require unknown operator", lambda c, x: p(c, files={"extra.yaml": "norms: [{name: X1, for: {d: Door}, cite: {section: '1'}, require: {nope: [1, 2]}}]\n"})),
        ("norm for is a list", lambda c, x: p(c, files={"extra.yaml": "norms: [{name: X1, for: [Door], cite: {section: '1'}, require: true}]\n"})),
        ("norm cite is a string", lambda c, x: p(c, files={"extra.yaml": "norms: [{name: X1, cite: '1', require: true}]\n"})),
        ("require nested 3000 deep", lambda c, x: p(c, files={"extra.yaml": "norms:\n  - name: X1\n    cite: {section: '1'}\n    " + deep})),
        ("terms billion laughs", lambda c, x: p(c, files={"extra.yaml": laughs})),
        ("YAML python tag", lambda c, x: p(c, files={"extra.yaml": "norms: !!python/object/apply:os.system ['echo pwned']\n"})),
        ("no package.yaml", lambda c, x: (p(c), rm(c, "ada-2010/package.yaml"))),
        ("predicate values not a list", lambda c, x: p(c, "nist-800-63b-4", domain="code", files={"extra.yaml": "predicates: [{name: system.x_flag, type: symbol, values: 5}]\n"})),
    ]


def gen_pack(ctx: dict, rng: random.Random, case: Case) -> None:
    import yaml
    pack, dirs, domain = rng.choice(ctx["packs"])
    _copy_pack(case, dirs)
    files = sorted((case.inp / pack).glob("*.yaml"))
    f = rng.choice(files)
    if rng.random() < 0.75:
        data = yaml.safe_load(f.read_text())
        data, how = mutate_structure(rng, data)
        try:
            f.write_bytes(dump_yaml(data))
        except Exception:  # noqa: BLE001
            f.write_text(json.dumps(data, default=str))
    else:
        data, how = mutate_bytes(rng, f.read_bytes())
        f.write_bytes(data)
    case.meta.update(pack=pack, domain=domain)
    case.label = f"{pack}/{f.name}:{how}"[:200]


def run_pack(case: Case) -> dict:
    from normir import load, validate
    from normir.evidence import Evidence, load_evidence, run

    rs = load(case.inp / case.meta["pack"])
    errors, warnings = validate(rs)
    if errors:
        return verdict([], f"validate: {len(errors)} errors, e.g. {str(errors[0])[:100]}")
    ev_doc = (SRC / "bench/evidence/NodeGoat.static.yaml") if case.meta.get("domain") == "code" else None
    evs = [Evidence({}, {}, [], [])] + ([load_evidence(ev_doc)] if ev_doc else [])
    if case.meta.get("domain") == "building":
        evs.append(load_evidence({"sources": [{"id": "ifc"}], "elements": [
            {"type": t, "id": f"{t}-1", "facts": {}} for t in ("Door", "Stair", "Space", "Ramp", "Route", "Corridor", "Exit", "Storey", "WaterCloset")]}))
    for ev in evs:
        try:
            run(rs, ev, {})
        except Exception as e:
            e.add_note("validate() reported no errors for this pack; run() then failed")
            raise
    return verdict([], f"validate ok ({len(warnings)} warnings), run ok")


# ================================================================ dispatch

SEEDS = {"regulation": seeds_regulation, "upload": seeds_upload, "zips": seeds_zips, "ifc": seeds_ifc, "dxf": seeds_dxf,
         "drawings": seeds_drawings, "code": seeds_code, "evidence": seeds_evidence, "pack": seeds_pack}
HAND = {"regulation": _reg_hand, "upload": _upload_hand, "zips": _zips_hand, "ifc": _ifc_hand, "dxf": _dxf_hand,
        "drawings": _drawings_hand, "code": _code_hand, "evidence": _evidence_hand, "pack": _pack_hand}
GEN = {"regulation": gen_regulation, "upload": gen_upload, "zips": gen_zips, "ifc": gen_ifc, "dxf": gen_dxf,
       "drawings": gen_drawings, "code": gen_code, "evidence": gen_evidence, "pack": gen_pack}
RUN = {"regulation": run_regulation, "upload": run_upload, "zips": run_zips, "ifc": run_ifc, "dxf": run_dxf,
       "drawings": run_drawings, "code": run_code, "evidence": run_evidence, "pack": run_pack}
IMPORTS = {"regulation": ["adapters.regulation.documents"], "upload": ["app.regulations", "adapters.regulation.documents"],
           "zips": ["app.buildings"], "ifc": ["adapters.ifc"], "dxf": ["adapters.dxf", "ezdxf"],
           "drawings": ["adapters.drawings", "pdfplumber", "pypdfium2", "PIL.Image"],
           "code": ["app.scan", "adapters.code_static", "adapters.code_ruby", "adapters.code_elixir", "adapters.deps"],
           "evidence": ["normir.evidence", "app.scan", "app.buildings"], "pack": ["normir", "normir.evidence"]}


def documented(target: str, e: BaseException, repo_frame) -> str | None:
    """The documented way for this reader to refuse an input: returns how it refused, or None (a crash)."""
    name = type(e).__name__
    mod = type(e).__module__ or ""
    line = (repo_frame.line or "") if repo_frame else ""
    fname = repo_frame.filename if repo_frame else ""
    if target == "regulation" and name == "RegulationError":
        return "RegulationError"
    if target == "upload" and type(e) is ValueError and fname.endswith("app/regulations.py") and "raise ValueError" in line:
        return "ValueError"
    if target == "zips" and name == "ProjectError":
        return "ProjectError"
    if target == "ifc" and "ifcopenshell.open(" in line:
        return f"ifcopenshell.open: {name}"
    if target == "dxf" and fname.endswith("dxf_render.py") and (mod.startswith("ezdxf") or isinstance(e, OSError)):
        return f"ezdxf: {name}"
    if target in ("evidence", "pack") and (mod.startswith("yaml") or name in ("EvidenceError", "PackError", "YAMLInputError")):
        return f"{mod.split('.')[0]}: {name}"
    return None


def _repo_frames(tb_frames) -> list:
    out = []
    for f in tb_frames:
        if f.filename.startswith("<"):
            continue
        p = os.path.realpath(f.filename)
        if _in_src(p):
            out.append(f)
    return out


def _in_src(p: str) -> bool:
    return p.startswith(str(SRC) + os.sep) and "/.venv/" not in p and p != str(SELF)


def _rel(p: str) -> str:
    for base in (SRC, ROOT):
        try:
            return str(Path(os.path.realpath(p)).relative_to(base))
        except ValueError:
            pass
    return p


def child(case: Case, timeout: float, mem_bytes: int) -> None:
    os.setpgid(0, 0)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if mem_bytes:
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    fd = os.open(case.dir / "stderr.txt", os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    faulthandler.enable(file=sys.stderr, all_threads=True)
    faulthandler.dump_traceback_later(timeout, exit=False, file=sys.stderr)
    t0 = time.time()
    r: dict = {}
    try:
        r = RUN[case.target](case)
        payload = {"class": r["class"], "issues": r.get("issues", []), "detail": str(r.get("detail", ""))[:400]}
    except BaseException as e:  # noqa: BLE001 - classify everything
        try:
            frames = traceback.extract_tb(e.__traceback__)
            repo = _repo_frames(frames)
            rf = repo[-1] if repo else None
            how = documented(case.target, e, rf)
            chain, c = [], e
            while c is not None and len(chain) < 20:  # a documented error wrapping a MemoryError is still a blow-up
                chain.append(c)
                c = c.__cause__ or c.__context__
            cls = "memory" if any(isinstance(x, MemoryError) for x in chain) else "ok" if how else "crash"
            payload = {"class": cls, "rejected": how, "exc": type(e).__name__, "msg": (str(e) + " " + " ".join(getattr(e, "__notes__", [])))[:500],
                       "frame": f"{_rel(rf.filename)}:{rf.lineno}" if rf else "", "func": rf.name if rf else "",
                       "lib_frame": f"{_rel(frames[-1].filename)}:{frames[-1].lineno}" if frames else "",
                       "traceback": "".join(traceback.format_exception(e))[-4000:]}
        except BaseException:  # noqa: BLE001 - e.g. out of memory while formatting
            payload = {"class": "memory" if isinstance(e, MemoryError) else "crash", "exc": type(e).__name__, "msg": "", "frame": ""}
    faulthandler.cancel_dump_traceback_later()
    payload["seconds"] = r.get("seconds", round(time.time() - t0, 2))  # a run_* may report the reader's own time
    (case.dir / "result.json").write_text(json.dumps(payload, default=str))
    os._exit(0)


def _vmsize() -> int:
    for line in open("/proc/self/status"):
        if line.startswith("VmSize:"):
            return int(line.split()[1]) * 1024
    return 0


FH_FRAME = re.compile(r'File "([^"]+)", line (\d+) in (\S+)')


def _faulthandler_frame(text: str) -> tuple[str, str]:
    """Innermost repository frame of the thread running the case, from a faulthandler dump (most recent call first)."""
    blocks = [FH_FRAME.findall(b) for b in re.split(r"\n(?=(?:Current thread|Thread) 0x)", text)]
    # the case's thread: the one running this file; a deep stack is cut at 100 frames, so else the first with repo frames
    blocks.sort(key=lambda fr: (not any(os.path.realpath(f) == str(SELF) for f, _, _ in fr),
                                not any(_in_src(os.path.realpath(f)) for f, _, _ in fr)))
    for frames in blocks[:1]:
        if frames:
            for f, ln, fn in frames:
                p = os.path.realpath(f)
                if _in_src(p):
                    return f"{_rel(p)}:{ln}", fn
            if frames:
                return f"{_rel(frames[0][0])}:{frames[0][1]}", frames[0][2]
    return "", ""


def fork_case(case: Case, timeout: float, mem_mb: int) -> int:
    mem = _vmsize() + mem_mb * 2**20 if mem_mb else 0
    pid = os.fork()
    if pid == 0:
        try:
            child(case, timeout, mem)
        finally:
            os._exit(3)
    return pid


def classify_exit(case: Case, status: int, ru, killed: bool, mem_mb: int, timeout: float) -> dict:
    rss_mb = ru.ru_maxrss / 1024 if ru else 0
    err = (case.dir / "stderr.txt").read_text(errors="replace") if (case.dir / "stderr.txt").exists() else ""
    res = case.dir / "result.json"
    # faulthandler's timeout dump can itself kill a deep stack (SIGSEGV) just before the parent does: still a hang
    if killed or (not res.exists() and "Timeout (" in err):
        frame, fn = _faulthandler_frame(err)
        return {"class": "hang", "exc": f"over {timeout:.0f} s", "frame": frame, "func": fn, "msg": "", "seconds": timeout}
    if res.exists():
        r = json.loads(res.read_text())
        if r["class"] == "ok" and rss_mb > mem_mb:
            r.update({"class": "memory", "exc": "RSS", "msg": f"peak RSS {rss_mb:.0f} MB"})
        r["rss_mb"] = round(rss_mb)
        return r
    sig = os.WTERMSIG(status) if os.WIFSIGNALED(status) else None
    frame, fn = _faulthandler_frame(err)
    near = rss_mb > 0.85 * mem_mb or "bad_alloc" in err or "MemoryError" in err or "Cannot allocate" in err
    exc = f"signal {signal.Signals(sig).name}" if sig else f"exit {os.WEXITSTATUS(status)}"
    return {"class": "memory" if near else "crash", "exc": exc, "frame": frame, "func": fn, "msg": err.strip().splitlines()[-1][:300] if err.strip() else "",
            "rss_mb": round(rss_mb)}


def make_case(target: str, idx: int, seed: int, ctx: dict, hand: list, root: Path) -> Case:
    case = Case(target, idx, root / f"{idx:05d}")
    if case.dir.exists():
        shutil.rmtree(case.dir)
    case.inp.mkdir(parents=True)
    rng = random.Random(f"{seed}:{target}:{idx}")
    if idx < len(hand):
        case.label = "hand:" + hand[idx][0]
        hand[idx][1](case, ctx)
    else:
        GEN[target](ctx, rng, case)
    (case.dir / "meta.json").write_text(json.dumps(case.meta))
    return case


def problem_keys(rec: dict) -> list[tuple]:
    if rec["class"] == "ok":
        return []
    if rec["class"] == "garbage":
        return [("garbage", i["symptom"], i["frame"]) for i in rec.get("issues", [])]
    return [(rec["class"], rec.get("exc", ""), rec.get("frame", ""))]


def slug(s: str, n: int = 60) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:n].strip("-")


def save_repro(case_dir: Path, target: str, key: tuple, out: Path, used: set) -> str:
    cls, what, frame = key
    fr = Path(frame.split(":")[0]).stem if frame else ""
    line = frame.rsplit(":", 1)[-1] if ":" in frame else ""
    base = slug(f"{cls}-{what}-{fr}-{line}") or cls
    meta = json.loads((case_dir / "meta.json").read_text())
    files = sorted(p for p in (case_dir / "input").rglob("*") if p.is_file() or p.is_symlink())
    if meta.get("single") and len(files) == 1 and files[0].is_file() and not files[0].is_symlink():
        ext = "".join(files[0].suffixes[-1:]) or ".bin"
        name = base + ext
        while name in used:
            base += "-x"
            name = base + ext
        shutil.copyfile(files[0], out / name)
    else:
        name = base + ".tar"
        while name in used:
            base += "-x"
            name = base + ".tar"
        with tarfile.open(out / name, "w") as t:
            t.add(case_dir / "meta.json", "meta.json")
            t.add(case_dir / "input", "input")
    used.add(name)
    return name


def repro_cmd(target: str, path: str) -> str:
    src = f"FUZZ_SRC={os.path.relpath(SRC, ROOT)} " if SRC != ROOT else ""
    return f"{src}uv run{' --with ifcopenshell' if target == 'ifc' else ''} python bench/fuzz_inputs.py --repro {target} {path}"


ORACLE_EXTRA = {"drawings": 12}  # wall-clock seconds an oracle may add after the reader returns (its own time is not a hang)


def run_target(target: str, args) -> dict:
    import importlib
    t_start = time.time()
    for m in IMPORTS[target]:
        importlib.import_module(m)
    guard = guard_models()
    ctx = SEEDS[target]()
    hand = HAND[target]()
    root = SANDBOX / "cases" / target
    root.mkdir(parents=True, exist_ok=True)
    counts: Counter = Counter()
    ok_kinds: Counter = Counter()
    best: dict[tuple, dict] = {}
    seen: Counter = Counter()
    records = []
    running: dict[int, tuple[Case, float]] = {}
    nxt = 0
    gen_errors = []
    jobs = args.jobs or (2 if target in ("drawings", "ifc") else 3)

    def finish(case: Case, status, ru, killed):
        rec = classify_exit(case, status, ru, killed, args.mem_mb, args.timeout)
        rec.update(idx=case.idx, label=case.label, bytes=dir_bytes(case.inp))
        if rec["class"] in ("hang", "crash", "memory") and not rec.get("frame") and case.label.startswith("hand:"):
            rec["frame"] = f"(no repo frame; {case.label})"
        if rec["class"] == "ok" and rec.get("seconds", 0) > args.timeout:
            rec.update({"class": "hang", "exc": f"over {args.timeout:.0f} s", "frame": "", "msg": "finished late"})
        counts[rec["class"]] += 1
        if rec["class"] == "ok":
            ok_kinds["rejected" if rec.get("rejected") else "accepted"] += 1
        keys = problem_keys(rec)
        keep = False
        for k in keys:
            seen[k] += 1
            if k not in best or rec["bytes"] < best[k]["rec"]["bytes"]:
                if k in best and best[k]["dir"] != case.dir and not any(b["dir"] == best[k]["dir"] for kk, b in best.items() if kk != k):
                    shutil.rmtree(best[k]["dir"], ignore_errors=True)
                best[k] = {"rec": rec, "dir": case.dir}
                keep = True
        records.append({k: v for k, v in rec.items() if k != "traceback"})
        shutil.rmtree(case.dir / "work", ignore_errors=True)
        if not keep and not any(b["dir"] == case.dir for b in best.values()):
            shutil.rmtree(case.dir, ignore_errors=True)
        done = sum(counts.values())
        if done % 25 == 0 or done == args.cases:
            print(f"[{target}] {done}/{args.cases} {dict(counts)} distinct={len(best)} {time.time() - t_start:.0f}s", flush=True)

    while nxt < args.cases or running:
        while len(running) < jobs and nxt < args.cases:
            try:
                case = make_case(target, nxt, args.seed, ctx, hand, root)
            except Exception as e:  # noqa: BLE001 - a generator bug must not stop the run
                gen_errors.append(f"{nxt}: {type(e).__name__}: {e}")
                nxt += 1
                continue
            running[fork_case(case, args.timeout, args.mem_mb)] = (case, time.time())
            nxt += 1
        for pid, (case, t0) in list(running.items()):
            got, status, ru = os.wait4(pid, os.WNOHANG)
            if got:
                del running[pid]
                finish(case, status, ru, False)
            elif time.time() - t0 > args.timeout + 3 + ORACLE_EXTRA.get(target, 0):
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    os.kill(pid, signal.SIGKILL)
                _, status, ru = os.wait4(pid, 0)
                del running[pid]
                finish(case, status, ru, True)
        time.sleep(0.02)

    out = Path(args.out) / target
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    used: set = set()
    problems = []
    for key, b in sorted(best.items(), key=lambda kv: (kv[0][0], kv[0][2], kv[0][1])):
        rec = b["rec"]
        name = save_repro(b["dir"], target, key, out, used)
        rel = os.path.relpath(out / name, ROOT)
        detail = next((i["detail"] for i in rec.get("issues", []) if (i["symptom"], i["frame"]) == key[1:]), "") if key[0] == "garbage" else rec.get("msg", "")
        problems.append({"target": target, "class": key[0], "what": key[1], "frame": key[2], "count": seen[key], "repro": str(rel),
                         "command": repro_cmd(target, str(rel)), "case": rec["idx"], "label": rec.get("label"), "detail": detail,
                         "lib_frame": rec.get("lib_frame", ""), "seconds": rec.get("seconds"), "rss_mb": rec.get("rss_mb"),
                         "traceback": rec.get("traceback", "")[-2500:]})
    summary = {"target": target, "seed": args.seed, "cases": args.cases, "counts": dict(counts), "ok": dict(ok_kinds),
               "distinct": len(problems), "seconds": round(time.time() - t_start), "command": " ".join(sys.argv),
               "guard": guard, "generator_errors": gen_errors}
    (out / "problems.json").write_text(json.dumps(problems, indent=1, ensure_ascii=False))
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    with open(out / "cases.jsonl", "w") as f:
        for r in records:
            f.write(json.dumps(r, default=str) + "\n")   # ASCII escapes: a label may hold a lone surrogate
    print(json.dumps(summary, indent=1))
    for p in problems:
        print(f"  {p['class']:8} {p['count']:4}x {p['what'][:70]:70} {p['frame']}  -> {p['repro']}")
    return summary


def repro(target: str, path: str, args) -> None:
    import importlib
    for m in IMPORTS[target]:
        importlib.import_module(m)
    print(guard_models())
    case = Case(target, 0, SANDBOX / "repro")
    case.inp.mkdir(parents=True)
    src = Path(path)
    if src.suffix == ".tar":
        with tarfile.open(src) as t:
            t.extractall(case.dir, filter="fully_trusted")
        case.meta = json.loads((case.dir / "meta.json").read_text())
    else:
        shutil.copyfile(src, case.inp / src.name)
        case.meta = {"single": True}
        (case.dir / "meta.json").write_text(json.dumps(case.meta))
    pid = fork_case(case, args.timeout, args.mem_mb)
    t0, killed = time.time(), False
    while True:
        got, status, ru = os.wait4(pid, os.WNOHANG)
        if got:
            break
        if time.time() - t0 > args.timeout + 3 + ORACLE_EXTRA.get(target, 0):
            os.killpg(pid, signal.SIGKILL)
            _, status, ru = os.wait4(pid, 0)
            killed = True
            break
        time.sleep(0.05)
    rec = classify_exit(case, status, ru, killed, args.mem_mb, args.timeout)
    tb = rec.pop("traceback", "")
    print(json.dumps(rec, indent=1, ensure_ascii=False, default=str))
    if tb:
        print(tb)
    elif rec["class"] in ("hang", "crash", "memory"):
        print((case.dir / "stderr.txt").read_text(errors="replace")[-3000:])


def report(out: Path) -> str:
    lines = ["# Input fuzzing: results", "", "| target | cases | ok (accepted / rejected) | crash | hang | memory | garbage | distinct | seconds |",
             "|---|---|---|---|---|---|---|---|---|"]
    allp = []
    for t in TARGETS:
        s = out / t / "summary.json"
        if not s.exists():
            continue
        sm = json.loads(s.read_text())
        c = sm["counts"]
        lines.append(f"| {t} | {sm['cases']} | {c.get('ok', 0)} ({sm['ok'].get('accepted', 0)} / {sm['ok'].get('rejected', 0)}) | {c.get('crash', 0)} | "
                     f"{c.get('hang', 0)} | {c.get('memory', 0)} | {c.get('garbage', 0)} | {sm['distinct']} | {sm['seconds']} |")
        allp += json.loads((out / t / "problems.json").read_text())
    lines += ["", "| target | class | exception / symptom | innermost repo frame | count | repro | command |", "|---|---|---|---|---|---|---|"]
    for p in allp:
        lines.append(f"| {p['target']} | {p['class']} | {p['what'][:90].replace('|', '/')} | {p['frame']} | {p['count']} | {Path(p['repro']).name} | `{p['command']}` |")
    text = "\n".join(lines) + "\n"
    (out / "REPORT.md").write_text(text)
    return text


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--target", default="all", help=f"comma-separated: {', '.join(TARGETS)}, or all")
    ap.add_argument("--cases", type=int, default=200, help="cases per target (the hand-written ones come first)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=30.0, help="seconds; a case over this is a hang")
    ap.add_argument("--mem-mb", type=int, default=1536, help="address space a case may add (RLIMIT_AS), MB")
    ap.add_argument("--jobs", type=int, default=0, help="cases at once (default 3; 2 for ifc and drawings)")
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--repro", nargs=2, metavar=("TARGET", "FILE"))
    ap.add_argument("--report", action="store_true")
    args = ap.parse_args()
    if args.report:
        print(report(Path(args.out)))
        return
    if args.repro:
        repro(args.repro[0], args.repro[1], args)
        return
    targets = TARGETS if args.target == "all" else args.target.split(",")
    for t in targets:
        if t not in TARGETS:
            sys.exit(f"unknown target {t}")
        if t == "ifc":
            try:
                import ifcopenshell  # noqa: F401
            except ImportError:
                sys.exit("ifc needs ifcopenshell: uv run --with ifcopenshell python bench/fuzz_inputs.py --target ifc")
        run_target(t, args)
    print(report(Path(args.out)))


if __name__ == "__main__":
    main()
