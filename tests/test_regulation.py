"""The regulation compiler with the model mocked: reading formats, verified clause ranges, verified checks, and a
pack the engine evaluates."""

import json
import re
import struct
import time
import tracemalloc
import zipfile
import zlib
from pathlib import Path

import httpx
import pytest
import yaml

import adapters.regulation as regulation
from adapters.regulation import documents
from adapters.regulation import (Document, Line, RegulationError, build_pack, clauses, compile_checks, fact_attr, uncovered, upgrade,
                                 read)
from normir.evidence import load_evidence, run
from normir.model import load, validate

ROOT = Path(__file__).resolve().parents[1]
CODE = yaml.safe_load((ROOT / "vocab" / "code.yaml").read_text())
BIM = yaml.safe_load((ROOT / "vocab" / "bim.yaml").read_text())
DOCS = yaml.safe_load((ROOT / "vocab" / "documents.yaml").read_text())
PROVIDER = ("anthropic", "test-model", "k")


def reply(obj, status=200):
    text = obj if isinstance(obj, str) else "```json\n" + json.dumps(obj) + "\n```"
    return httpx.Response(status, json={"content": [{"type": "text", "text": text}]})


def transport(answer):
    """A transport answering Anthropic-style calls with answer(system, user), recording what it was sent."""
    sent = []

    def handler(request):
        body = json.loads(request.content)
        user = body["messages"][0]["content"]
        sent.append((body["system"], user))
        return answer(body["system"], user)
    return httpx.MockTransport(handler), sent


# ---------------------------------------------------------------- fixtures

HELVETICA = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"


def make_pdf(pages: list[list[str] | bytes], font: bytes = HELVETICA, flate: bool = False) -> bytes:
    """A minimal PDF with one text line per string in `font` (Helvetica), written by hand (no PDF writer is installed).
    A page given as bytes is its content stream as it is; `flate` compresses the content streams."""
    n = len(pages)
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            f"<< /Type /Pages /Kids [{' '.join(f'{4 + 2 * i} 0 R' for i in range(n))}] /Count {n} >>".encode(), font]
    for i, lines in enumerate(pages):
        ops = []
        for j, t in enumerate(lines if isinstance(lines, list) else []):
            esc = t.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            ops.append(f"({esc}) Tj" if j == 0 else f"0 -18 Td ({esc}) Tj")
        stream = lines if isinstance(lines, bytes) else ("BT /F1 12 Tf 72 720 Td " + " ".join(ops) + " ET").encode() if lines else b""
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> "
                    f"/Contents {5 + 2 * i} 0 R >>".encode())
        stream, filt = (zlib.compress(stream), b" /Filter /FlateDecode") if flate else (stream, b"")
        objs.append(b"<< /Length %d%s >>\nstream\n" % (len(stream), filt) + stream + b"\nendstream")
    out, offsets = b"%PDF-1.4\n", []
    for k, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % k + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1) + b"".join(b"%010d 00000 n \n" % o for o in offsets)
    return out + b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)


W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


def wp(*runs, num=None, style=None):
    ppr = ""
    if style or num:
        ppr = "<w:pPr>" + (f'<w:pStyle w:val="{style}"/>' if style else "")
        ppr += (f'<w:numPr><w:ilvl w:val="{num[1]}"/><w:numId w:val="{num[0]}"/></w:numPr>' if num else "") + "</w:pPr>"
    body = "".join(r if r.startswith("<") else f'<w:r><w:t xml:space="preserve">{r}</w:t></w:r>' for r in runs)
    return f"<w:p>{ppr}{body}</w:p>"


def make_docx(path: Path) -> Path:
    body = "".join([
        wp("Acme Secure Coding Standard"),
        wp("Passwords", style="Heading1"),                                   # numbered by its style: 1.
        wp("Hash passwords with ", "bcrypt.", num=(1, 1)),                   # 1.1
        wp("Sessions expire after 15", "<w:r><w:tab/></w:r>", "minutes.", num=(1, 1)),   # 1.2
        wp(),                                                                # empty: dropped
        wp("First half", "<w:r><w:br/></w:r>", "second half"),
        "<w:tbl><w:tr><w:tc>" + wp("REQ-7") + "</w:tc><w:tc>" + wp("Cookies are", ) + wp("Secure.") + "</w:tc></w:tr></w:tbl>",
        wp("Logging", style="Heading1"),                                     # 2.
        wp("Never log tokens.", num=(1, 1)),                                 # 2.1: the sub-level restarts
        wp("Use the shared logger.", num=(2, 0)),                            # a bullet
        wp('<w:del><w:r><w:delText>deleted text</w:delText></w:r></w:del>', "Kept text"),
    ])
    numbering = f"""<w:numbering {W}>
      <w:abstractNum w:abstractNumId="10">
        <w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="decimal"/><w:lvlText w:val="%1."/></w:lvl>
        <w:lvl w:ilvl="1"><w:start w:val="1"/><w:numFmt w:val="decimal"/><w:lvlText w:val="%1.%2"/></w:lvl>
      </w:abstractNum>
      <w:abstractNum w:abstractNumId="11">
        <w:lvl w:ilvl="0"><w:numFmt w:val="bullet"/><w:lvlText w:val="\uf0b7"/></w:lvl>
      </w:abstractNum>
      <w:num w:numId="1"><w:abstractNumId w:val="10"/></w:num>
      <w:num w:numId="2"><w:abstractNumId w:val="11"/></w:num>
    </w:numbering>"""
    styles = f"""<w:styles {W}><w:style w:styleId="Heading1"><w:pPr><w:numPr><w:numId w:val="1"/></w:numPr></w:pPr></w:style></w:styles>"""
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", f"<w:document {W}><w:body>{body}</w:body></w:document>")
        z.writestr("word/numbering.xml", numbering)
        z.writestr("word/styles.xml", styles)
    return path


def write_docx(path: Path, body: str, numbering: str = "") -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("word/document.xml", f"<w:document {W}><w:body>{body}</w:body></w:document>")
        if numbering:
            z.writestr("word/numbering.xml", f"<w:numbering {W}>{numbering}</w:numbering>")
    return path


def texts(doc: Document) -> list[str]:
    return [ln.text for ln in doc.lines]


# ---------------------------------------------------------------- reading

def test_read_pdf_keeps_pages_and_numbers_lines(tmp_path):
    p = tmp_path / "std.pdf"
    p.write_bytes(make_pdf([["1 Scope", "This   standard applies (to all) services."], ["2 Passwords", "2.1 Hash passwords."]]))
    doc = read(p, "policies/std.pdf")
    assert (doc.file, doc.kind, doc.pages) == ("policies/std.pdf", "pdf", 2)
    assert [(ln.no, ln.page, ln.text) for ln in doc.lines] == [
        (1, 1, "1 Scope"), (2, 1, "This standard applies (to all) services."), (3, 2, "2 Passwords"), (4, 2, "2.1 Hash passwords.")]
    assert re.fullmatch(r"[0-9a-f]{64}", doc.sha256)


def test_pdf_running_headers_and_footers_are_dropped(tmp_path):
    p = tmp_path / "std.pdf"
    body = [["Scope of the standard", "It covers services."], ["Passwords are hashed.", "Keys are rotated."], ["Logs omit tokens."]]
    # each page opens with an article of the same shape whose number is not the page's: that is text, kept
    p.write_bytes(make_pdf([["ACME Standard", f"Article {7 * i} fire doors", *rules, f"Page {i} of 3"]
                            for i, rules in enumerate(body, 1)]))
    doc = read(p, "std.pdf")
    assert [(ln.no, ln.page, ln.text) for ln in doc.lines] == [
        (1, 1, "Article 7 fire doors"), (2, 1, "Scope of the standard"), (3, 1, "It covers services."),
        (4, 2, "Article 14 fire doors"), (5, 2, "Passwords are hashed."), (6, 2, "Keys are rotated."),
        (7, 3, "Article 21 fire doors"), (8, 3, "Logs omit tokens.")]


def test_read_docx_paragraphs_numbering_and_cells(tmp_path):
    doc = read(make_docx(tmp_path / "std.docx"), "std.docx")
    assert (doc.kind, doc.pages) == ("docx", None)
    assert texts(doc) == [
        "Acme Secure Coding Standard",
        "1. Passwords",
        "1.1 Hash passwords with bcrypt.",
        "1.2 Sessions expire after 15 minutes.",
        "First half",
        "second half",
        "REQ-7 | Cookies are Secure.",          # a table row is one line, its cells joined
        "2. Logging",
        "2.1 Never log tokens.",
        "• Use the shared logger.",
        "Kept text",
    ]
    assert [ln.no for ln in doc.lines] == list(range(1, 12))


def test_read_html_blocks_lists_and_no_scripts(tmp_path):
    p = tmp_path / "std.html"
    p.write_text("""<html><head><title>T</title><style>p {color: red}</style>
      <script>var x = "<p>not text</p>";</script></head>
      <body><nav><a href="/">Home</a></nav><h1>Policy &amp; Rules</h1><p>Intro   text
      over two lines.</p><ol start="3"><li><p>Third item</p></li><li>Fourth <b>item</b></li></ol><ul><li>Bullet</li></ul>
      <table><tr><td>REQ-1</td><td>Use TLS</td></tr></table><pre>line a
line b</pre><script>alert(1)</script><p>After&nbsp;script<br>new line</p></body></html>""")
    doc = read(p, "std.html")
    assert texts(doc) == ["Policy & Rules", "Intro text over two lines.", "3. Third item", "4. Fourth item", "• Bullet",
                          "REQ-1 | Use TLS", "line a", "line b", "After script", "new line"]


def test_read_markdown_drops_blank_lines_and_numbers_kept_ones(tmp_path):
    p = tmp_path / "std.md"
    p.write_text("# Title\n\n\n  Line   with\tspaces  \n\n- item\n")
    doc = read(p, "std.md")
    assert (doc.kind, [(ln.no, ln.page, ln.text) for ln in doc.lines]) == ("md", [(1, None, "# Title"), (2, None, "Line with spaces"), (3, None, "- item")])



def test_html_rows_stay_rows_and_site_furniture_is_left_out(tmp_path):
    p = tmp_path / "std.html"
    p.write_text("""<body><header role="banner"><a>Skip to content</a></header><div role="navigation"><ul><li>Home</li></ul></div>
      <h2>Table 3</h2><table><tr><th>Zone</th><th>Min R-value</th></tr><tr><td><p>1</p></td><td>2.7<br>(roof)</td></tr></table>
      <p><sup>1</sup>Treppen sind zu sichern.<sup>2</sup>Sie müssen</p><footer>Copyright</footer><p>Last</p></body>""")
    assert texts(read(p, "std.html")) == ["Table 3", "Zone | Min R-value", "1 | 2.7 (roof)", "1 Treppen sind zu sichern. 2 Sie müssen", "Last"]


def test_markdown_tables_written_as_html_comments_and_template_tags(tmp_path):
    p = tmp_path / "std.md"
    p.write_text("# Pod Security\n<!-- the English original -->\n{% ifversion ghes %}Only on servers{% endif %}\n"
                 "Set <code>runAsNonRoot</code>.\n<table>\n<tr><td><strong>Privileged</strong></td>\n"
                 "<td><p>Must be <code>false</code>.</p></td></tr>\n</table>\nAfter.\n")
    assert texts(read(p, "std.md")) == ["# Pod Security", "Only on servers", "Set runAsNonRoot.", "Privileged | Must be false.", "After."]


def test_undeclared_encoding_is_detected_not_assumed(tmp_path):
    p = tmp_path / "std.txt"
    p.write_bytes("第1条 階段の幅は75センチメートル以上とすること。\n第2条 手すりを設けること。\n".encode("shift_jis"))
    assert texts(read(p, "std.txt")) == ["第1条 階段の幅は75センチメートル以上とすること。", "第2条 手すりを設けること。"]


def test_pdf_words_set_with_narrow_gaps_and_margin_text_running_up_the_page(tmp_path):
    # word spacing -0.9 leaves gaps of about 2.2 pt at 11 pt, under a fixed 3 pt tolerance; the margin note runs upwards
    said = ["Logs must never record session identifiers.", "Access to logs is limited to named staff.", "Log entries are hashed daily."]
    page = lambda t: (b"BT /F1 11 Tf -0.9 Tw 72 700 Td (%s) Tj ET " % t.encode()  # noqa: E731
                      + b"BT /F1 9 Tf 0 1 -1 0 30 200 Tm (Available free of charge) Tj ET")
    p = tmp_path / "std.pdf"
    p.write_bytes(make_pdf([page(t) for t in said]))
    assert texts(read(p, "std.pdf")) == said

@pytest.mark.parametrize("name, data, message", [
    ("std.doc", b"\xd0\xcf\x11\xe0", "unsupported file type '.doc'; save it as .docx"),
    ("std.exe", b"MZ", "unsupported file type '.exe'"),
    ("std.pdf", make_pdf([[], []]), "has no text layer; scanned PDFs are not supported yet"),
    ("std.pdf", b"hello", "is not a PDF file"),
    ("std.pdf", b"%PDF-1.4\ngarbage", "could not be read as a PDF"),
    ("std.docx", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 100, "encrypted (password-protected)"),
    ("std.docx", b"not a zip", "not a valid zip archive"),
    ("std.txt", b"", "is empty"),
    ("std.txt", "a\0b".encode("utf-16-le"), "binary data"),
])
def test_unreadable_files_are_user_facing_errors(tmp_path, name, data, message):
    p = tmp_path / name
    p.write_bytes(data)
    with pytest.raises(RegulationError, match=re.escape(message)):
        read(p, name)


NUMBERED = '<w:p><w:pPr><w:numPr><w:ilvl w:val="{ilvl}"/><w:numId w:val="1"/></w:numPr></w:pPr><w:r><w:t>Stairs are 1 m wide.</w:t></w:r></w:p>'


@pytest.mark.parametrize("ilvl, lvl, start, fmt, message", [
    ("0", "x", "1", "decimal", "list level 'x' is not a whole number"),
    ("0", "0", "1.5", "decimal", "list start '1.5' is not a whole number"),
    ("one", "0", "1", "decimal", "list level 'one' is not a whole number"),
    ("0", "0", "9" * 12, "decimal", "list start '999999999999' is not a whole number"),
    ("0", "0", "10000000", "upperRoman", "list item number 10000000 is too large to write in roman numerals"),
    ("0", "0", "100000000", "lowerLetter", "list item number 100000000 is too large to write in letters"),
])
def test_word_list_numbering_that_no_valid_document_has_is_an_error(tmp_path, ilvl, lvl, start, fmt, message):
    numbering = (f'<w:abstractNum w:abstractNumId="7"><w:lvl w:ilvl="{lvl}"><w:start w:val="{start}"/><w:numFmt w:val="{fmt}"/>'
                 '<w:lvlText w:val="%1."/></w:lvl></w:abstractNum><w:num w:numId="1"><w:abstractNumId w:val="7"/></w:num>')
    p = write_docx(tmp_path / "std.docx", NUMBERED.format(ilvl=ilvl), numbering)
    with pytest.raises(RegulationError, match=re.escape(f"its list numbering is damaged ({message})")):
        read(p, "std.docx")


def test_word_content_nested_thousands_deep_is_read(tmp_path):
    body = "<w:sdt><w:sdtContent><w:ins>" * 3000 + wp("Stairs are 1 m wide.") + "</w:ins></w:sdtContent></w:sdt>" * 3000
    assert texts(read(write_docx(tmp_path / "std.docx", body + wp("Ramps are 1:12.")), "std.docx")) == [
        "Stairs are 1 m wide.", "Ramps are 1:12."]


def _deflate_broken(z: bytearray) -> None:      # the first member's data starts with a reserved block type
    name_len, extra_len = struct.unpack_from("<HH", z, 26)
    z[30 + name_len + extra_len] = 0xFF


def _directory_misplaced(z: bytearray) -> None:  # the end record puts the central directory after where it is
    struct.pack_into("<I", z, len(z) - 6, struct.unpack_from("<I", z, len(z) - 6)[0] + 1000)


@pytest.mark.parametrize("damage, xml_decl, message", [
    (_deflate_broken, "", "not a valid zip archive"),
    (_directory_misplaced, "", "not a valid zip archive"),
    (None, '<?xml version="1.0" encoding="UTF-1"?>', "its document XML is damaged (unknown encoding: UTF-1)"),
    (None, '<?xml version="1.0" encoding="shift_jis"?>', "its document XML is damaged"),
])
def test_damaged_word_archives_and_xml_are_user_facing_errors(tmp_path, damage, xml_decl, message):
    p = tmp_path / "std.docx"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("word/document.xml", f"{xml_decl}<w:document {W}><w:body>{wp('Stairs are 1 m wide.')}</w:body></w:document>")
    if damage:
        data = bytearray(p.read_bytes())
        damage(data)
        p.write_bytes(data)
    with pytest.raises(RegulationError, match=re.escape(message)):
        read(p, "std.docx")


def test_compressed_parts_that_expand_past_the_limit_are_refused_unread(tmp_path, monkeypatch):
    monkeypatch.setattr(documents, "MAX_XML_BYTES", 50_000)
    monkeypatch.setattr(documents, "MAX_PDF_INFLATED", 50_000)
    docx = write_docx(tmp_path / "std.docx", wp("Stairs are 1 m wide." + " " * 60_000))
    with pytest.raises(RegulationError, match=re.escape("std.docx is too large: its word/document.xml expands to more than")):
        read(docx, "std.docx")
    pdf = tmp_path / "std.pdf"
    pdf.write_bytes(make_pdf([b"BT /F1 12 Tf 72 700 Td (Stairs are 1 m wide.) Tj ET" + b" " * 60_000], flate=True))
    with pytest.raises(RegulationError, match=re.escape("std.pdf is too large: its compressed content expands to more than")):
        read(pdf, "std.pdf")
    pdf.write_bytes(make_pdf([b"BT /F1 12 Tf 72 700 Td (Stairs are 1 m wide.) Tj ET" + b" " * 40_000], flate=True))
    assert texts(read(pdf, "std.pdf")) == ["Stairs are 1 m wide."]


def test_numbers_of_any_length_in_lists_and_page_furniture_are_read(tmp_path):
    p = tmp_path / "std.html"
    for start in ("²", "9" * 5000, "-x"):   # not integers browsers read: the list counts from 1
        p.write_text(f'<ol start="{start}"><li>Stairs</li><li>Ramps</li></ol>')
        assert texts(read(p, "std.html")) == ["1. Stairs", "2. Ramps"]
    p.write_text('<ol start=" -2"><li>Stairs</li></ol>')
    assert texts(read(p, "std.html")) == ["-2. Stairs"]
    p = tmp_path / "std.pdf"   # int() refuses a number of over 4300 digits, as in this header line of every page
    p.write_bytes(make_pdf([["7" * 5000, f"Article {7 * i} fire doors"] for i in range(1, 4)]))
    assert texts(read(p, "std.pdf")) == ["Article 7 fire doors", "Article 14 fire doors", "Article 21 fire doors"]


@pytest.mark.parametrize("charset", ["idna", "utf-16"])
def test_an_html_charset_the_bytes_cannot_be_in_is_not_trusted(tmp_path, charset):
    p = tmp_path / "std.html"
    p.write_bytes(f'<meta charset="{charset}">'.encode() + b"<p>Caf\xe9 stairs are at least 1200 mm wide.</p>" * 20)
    assert set(texts(read(p, "std.html"))) == {"Café stairs are at least 1200 mm wide."}


def test_html_whose_head_end_tag_is_left_out_keeps_its_body(tmp_path):
    p = tmp_path / "std.html"
    for doc in ("<html><head><title>T</title><style>p {}</style><body><p>Stairs</p></body></html>",
                "<head><meta charset=utf-8><title>T</title><h1>Stairs</h1>",
                "<head><title>T</title>Stairs"):
        p.write_text(doc)
        assert texts(read(p, "std.html")) == ["Stairs"]
    p.write_text("<head><noscript><p>Enable scripts</p></noscript><title>T</title></head><p>Stairs</p></head><p>Ramps</p>")
    assert texts(read(p, "std.html")) == ["Stairs", "Ramps"]


def test_html_with_carriage_return_line_ends_reads_as_with_newlines(tmp_path):
    p = tmp_path / "std.html"
    html = "<p>Stairs</p>\n<pre>Table 1\n  width  1200 mm\n</pre>\n<p>Ramps</p>\n"
    for ending in ("\n", "\r\n", "\r"):
        p.write_bytes(html.replace("\n", ending).encode())
        assert texts(read(p, "std.html")) == ["Stairs", "Table 1", "width 1200 mm", "Ramps"]


def test_a_long_run_of_leader_dots_takes_memory_in_proportion(tmp_path):
    p = tmp_path / "toc.txt"
    p.write_bytes(b"Contents " + b". " * 500_000 + b" 7")
    tracemalloc.start()
    try:
        assert texts(read(p, "toc.txt")) == ["Contents … 7"]
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 25 * p.stat().st_size   # a backtracking repeat kept about 60 bytes per dot


def test_pdf_pages_are_released_once_read(tmp_path):
    def peak(n):
        p = tmp_path / f"{n}.pdf"
        p.write_bytes(make_pdf([[f"{i}.{j} Stairs serving an exit are at least 1100 mm wide" for j in range(40)] for i in range(n)]))
        tracemalloc.start()
        try:
            assert len(read(p, p.name).lines) == 40 * n
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
    assert peak(12) < 2 * peak(3)   # every page's objects were kept: four times the pages, four times the memory


def test_a_pdf_page_with_many_glyphs_is_read_in_linear_time(tmp_path):
    # run-together words are malformed, so the reading with glyphs drawn twice counted once is tried as well;
    # pdfplumber's dedupe_chars restores the order with list.index, which took ~15 s on this page
    page = b"BT /F1 4 Tf 5 TL 10 780 Td " + b" ".join(b"(%d Stairwaysservinganexitareatleastwide) ' " % j for j in range(600)) + b" ET"
    p = tmp_path / "std.pdf"
    p.write_bytes(make_pdf([page]))
    t0 = time.monotonic()
    assert len(read(p, "std.pdf").lines) == 600
    assert time.monotonic() - t0 < 5


def test_pdf_glyph_codes_without_characters_are_an_error_not_text(tmp_path):
    identity = (b"<< /Type /Font /Subtype /Type0 /BaseFont /Foo /Encoding /Identity-H /DescendantFonts [<< /Type /Font "
                b"/Subtype /CIDFontType2 /BaseFont /Foo /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> "
                b"/DW 1000 >>] >>")
    p = tmp_path / "std.pdf"
    p.write_bytes(make_pdf([b"BT /F1 12 Tf 72 700 Td <0041004200430044> Tj ET"], font=identity))
    with pytest.raises(RegulationError, match=re.escape("std.pdf: page 1 has no text layer that can be read")):
        read(p, "std.pdf")


# ---------------------------------------------------------------- clauses

MD = """# Acme Standard
This standard applies to all services.
## 1 Passwords
1.1 Passwords must be hashed with bcrypt.
1.2 Passwords must be at least 12 characters
long and checked against a blocklist.
## 2 Transport
2.1 All traffic uses TLS.
2.2 Staff complete security training yearly.
Glossary: TLS means transport layer security.
"""


def test_clause_ranges_are_verified_and_text_comes_from_the_document(tmp_path):
    (tmp_path / "std.md").write_text(MD)
    (tmp_path / "annex.pdf").write_bytes(make_pdf([["A.1 Rotate keys every", "90 days."], ["(continued) and log it."]]))
    md, pdf = read(tmp_path / "std.md", "std.md"), read(tmp_path / "annex.pdf", "annex.pdf")
    md_reply = {"clauses": [
        {"start": 1, "end": 2, "ref": None, "title": "Scope", "requirement": False},
        {"start": 3, "end": 3, "ref": "1", "title": "Passwords", "requirement": False},
        {"start": 4, "end": 4, "ref": "1.1", "title": "Hash passwords", "requirement": True, "text": "INJECTED TEXT"},
        {"start": 5, "end": 6, "ref": "1.2", "title": "Password length", "requirement": True},
        {"start": 4, "end": 6, "ref": "1", "title": "Whole section", "requirement": True},     # contains others
        {"start": 6, "end": 8, "ref": None, "title": "Overlap", "requirement": True},          # overlaps 5-6
        {"start": 8, "end": 7, "ref": "2.1", "title": "Backwards", "requirement": True},       # ends before it starts
        {"start": 9, "end": 99, "ref": "2.2", "title": "Too far", "requirement": True},        # outside the file
        {"start": 0, "end": 1, "ref": None, "title": "Zero", "requirement": False},            # outside the file
        {"start": 10, "end": 10, "title": "No requirement flag"},                               # malformed
        {"start": "9", "end": "9", "ref": "2.2", "title": "Training", "requirement": "true"},   # numbers as strings
        "nonsense",
    ]}
    pdf_reply = {"clauses": [{"start": 1, "end": 3, "ref": "A.1", "title": "Key rotation", "requirement": True}]}
    t, sent = transport(lambda s, u: reply(md_reply if "=== std.md" in u else pdf_reply))
    seen = []
    out = clauses([md, pdf], provider=PROVIDER, transport=t, progress=seen.append)
    assert [(c["id"], c["file"], c["lines"], c["ref"], c["requirement"]) for c in out] == [
        ("c1", "std.md", [1, 2], None, False), ("c2", "std.md", [3, 3], "1", False), ("c3", "std.md", [4, 4], "1.1", True),
        ("c4", "std.md", [5, 6], "1.2", True), ("c5", "std.md", [9, 9], "2.2", True), ("c6", "annex.pdf", [1, 3], "A.1", True)]
    assert out[2]["text"] == "1.1 Passwords must be hashed with bcrypt."
    assert out[3]["text"] == "1.2 Passwords must be at least 12 characters\nlong and checked against a blocklist."
    assert out[3]["at"] == "std.md#L5-L6" and out[3]["pages"] is None and out[3]["title"] == "Password length"
    assert out[5]["pages"] == [1, 2] and out[5]["text"].endswith("(continued) and log it.")
    assert "dropped 7" in seen[-1]
    # what no clause covers is listed, not lost: here a requirement the splitter missed
    assert [(g["at"], g["text"]) for g in uncovered([md, pdf], out)] == [
        ("std.md#L7-L8", "## 2 Transport\n2.1 All traffic uses TLS."), ("std.md#L10-L10", "Glossary: TLS means transport layer security.")]
    # the model is shown numbered lines and never asked for text
    assert any("     4| 1.1 Passwords must be hashed with bcrypt." in u for _, u in sent)
    assert any("[page 2]" in u for _, u in sent)


def test_clauses_start_in_their_part_and_may_run_into_the_next(tmp_path, monkeypatch):
    monkeypatch.setattr(regulation, "CHUNK_CHARS", 200)
    lines = [f"{i}. " + "requirement text " * 2 + f"number {i}" for i in range(1, 9)]
    (tmp_path / "std.txt").write_text("\n".join(lines))
    doc = read(tmp_path / "std.txt", "std.txt")

    def answer(system, user):
        head = re.search(r"lines (\d+)-(\d+) of", user).groups()
        return reply({("1", "3"): {"clauses": [{"start": 1, "end": 3, "continues": True, "title": "A", "requirement": True},
                                               {"start": 4, "end": 4, "title": "starts in context", "requirement": True}]},
                      ("4", "6"): {"clauses": [{"start": 5, "end": 6, "title": "B", "requirement": True}]},
                      ("7", "8"): {"clauses": [{"start": 7, "end": 8, "title": "C", "requirement": False}]}}[head])
    t, sent = transport(answer)
    out = clauses([doc], provider=PROVIDER, transport=t)
    assert [c["lines"] for c in out] == [[1, 4], [5, 6], [7, 8]]
    assert out[0]["text"] == "\n".join(lines[:4])
    first = next(u for _, u in sent if "lines 1-3 of" in u)
    assert "--- context only ---" in first and "     4| 4." in first


def test_a_failed_split_is_an_error(tmp_path):
    (tmp_path / "std.md").write_text(MD)
    t, sent = transport(lambda s, u: reply("I cannot help with that."))
    with pytest.raises(RegulationError, match="could not split std.md"):
        clauses([read(tmp_path / "std.md", "std.md")], provider=PROVIDER, transport=t)
    assert len(sent) == 2   # a reply that is not JSON is retried once


def test_no_provider_is_an_error(monkeypatch, tmp_path):
    monkeypatch.setattr(regulation, "provider_from_env", lambda: None)
    with pytest.raises(RegulationError, match="no model provider"):
        clauses([Document("a.md", "0", "md", None, [Line(1, None, "x")])])


# ---------------------------------------------------------------- checks

def clause(n, text, requirement=True, ref=None):
    return {"id": f"c{n}", "file": "std.md", "lines": [n, n], "pages": None, "ref": ref, "title": text[:30], "text": text,
            "requirement": requirement, "at": f"std.md#L{n}-L{n}"}


CLAUSES = [
    clause(1, "This standard applies to all services.", requirement=False),
    clause(2, "Passwords must be hashed with bcrypt or Argon2.", ref="1.1"),
    clause(3, "Passwords must be at least 12 characters and checked against a blocklist.", ref="1.2"),
    clause(4, "Services must sit behind the web application firewall.", ref="2.1"),
    clause(5, "Staff complete security training yearly.", ref="2.2"),
    clause(6, "Error pages never show stack traces.", ref="3.1"),
    clause(7, "Queries use prepared statements.", ref="3.2"),
    clause(8, "Enforce a minimum password length.", ref="3.3"),
    clause(9, "Keep an inventory of third-party components.", ref="4.1"),
]
CHECKS = {
    "c2": [{"summary": "Stored passwords are hashed with bcrypt or Argon2.", "kind": "computed", "why": "PasswordStore.algorithm",
            "for": {"var": "p", "type": "PasswordStore"}, "require": {"in": [{"fact": "p.algorithm"}, ["bcrypt", "argon2"]]},
            "search": ["bcrypt", "argon2", "password_hash"]}],
    "c3": [{"summary": "Passwords have at least 12 characters and are checked against a blocklist.", "kind": "computed",
            "why": "system facts", "for": None, "search": ["min_length", "blocklist", "pwned"],
            "require": {"all": [{"le": [12, {"fact": "system.password_min_length"}]}, {"fact": "system.password_blocklist_check"}]}},
           {"kind": "magic", "summary": "not a kind"},
           {"summary": "", "kind": "assessed"}],
    "c4": [{"summary": "Services sit behind the WAF.", "kind": "computed", "why": "network control",
            "require": {"fact": "system.behind_waf"}, "search": ["waf", "modsecurity", "cloudflare"]}],
    "c5": [{"summary": "Staff complete security training every year.", "kind": "attested", "why": "organisational",
            "question": "Did every developer complete security training in the last 12 months?", "search": ["x"]}],
    "c6": [{"summary": "Error pages never show stack traces.", "kind": "assessed", "why": "visible in error handlers",
            "search": ["stack trace", "  ", 7]}],
    "c7": [{"summary": "Queries use prepared statements.", "kind": "computed", "why": "Query.construction",
            "for": {"var": "q", "type": "Query"}, "require": {"eq": [{"fact": "q.construction"}, "prepared"]},
            "search": ["prepare", "execute", "placeholder"]}],
    "c8": [{"summary": "A minimum password length is enforced.", "kind": "computed", "why": "number fact",
            "require": {"fact": "system.password_min_length"}, "search": ["min_length", "minlength", "length"]}],
}


def test_checks_are_verified_and_bad_computed_checks_are_demoted(monkeypatch):
    monkeypatch.setattr(regulation, "BATCH_CLAUSES", 7)   # c2..c8 in one call, c9 in another
    def answer(system, user):
        if "=== c9" in user:   # one batch fails for good
            return httpx.Response(400, json={"error": "bad request"})
        ids = re.findall(r"^=== (c\d+)", user, re.M)
        items = [{"clause": i, "checks": CHECKS[i]} for i in ids if i in CHECKS] + [{"clause": "c99", "checks": []}]
        return reply({"clauses": items})
    t, sent = transport(answer)
    checks, stats = compile_checks(CLAUSES, CODE, provider=PROVIDER, transport=t, workers=2)
    by_id = {c["id"]: c for c in checks}
    assert list(by_id) == ["k2-1", "k3-1", "k4-1", "k5-1", "k6-1", "k7-1", "k8-1"]   # document order, dropped items not numbered
    k = by_id["k2-1"]
    assert (k["clause"], k["kind"], k["enabled"], k["for"]) == ("c2", "computed", True, {"var": "p", "type": "PasswordStore"})
    assert k["search"] == ["bcrypt", "argon2", "password_hash"] and "demoted" not in k
    assert by_id["k3-1"]["require"] == {"all": [{"ge": [{"fact": "system.password_min_length"}, 12]},
                                                {"fact": "system.password_blocklist_check"}]}
    waf = by_id["k4-1"]
    assert waf["kind"] == "assessed" and "behind_waf" in waf["demoted"] and waf["search"] == ["waf", "modsecurity", "cloudflare"]
    assert "for" not in waf and "require" not in waf
    assert by_id["k5-1"]["question"].startswith("Did every developer") and "search" not in by_id["k5-1"]
    assert by_id["k6-1"]["search"][0] == "stack trace" and len(by_id["k6-1"]["search"]) == 3   # filled from the summary
    assert by_id["k7-1"]["kind"] == "assessed" and "'prepared' is not a value" in by_id["k7-1"]["demoted"]
    assert by_id["k8-1"]["kind"] == "assessed" and "not a condition" in by_id["k8-1"]["demoted"]
    assert {k: stats[k] for k in ("clauses_sent", "computed", "assessed", "attested", "demoted", "dropped", "failed_calls",
                                  "clauses_without_checks")} == {
        "clauses_sent": 8, "computed": 2, "assessed": 4, "attested": 1, "demoted": 3, "dropped": 3, "failed_calls": 1,
        "clauses_without_checks": 1}
    # only requirement clauses are sent, with the vocabulary in the instructions
    assert all("applies to all services" not in u for _, u in sent)
    assert "PasswordStore" in sent[0][0] and "password_blocklist_check" in sent[0][0]


@pytest.mark.parametrize("vocab", [CODE, BIM], ids=["code", "bim"])
def test_each_vocabulary_brings_worked_examples_that_compile(vocab):
    """The prompt's examples are the vocabulary's own, and each passes the checks the model's output must pass."""
    examples = vocab["compile"]["examples"]
    assert examples
    for n, e in enumerate(examples, 1):
        stats = {"dropped": 0, "dropped_reasons": {}, "demoted": 0}
        chk = regulation._check({"summary": e["clause"], "kind": "computed", "why": "example", "search": ["x"], **e["check"]},
                                clause(n, e["clause"]), 1, vocab, stats)
        assert chk["kind"] == "computed" and "demoted" not in chk and stats["demoted"] == 0, (e["clause"], chk)
    t, sent = transport(lambda s, u: reply({"clauses": []}))
    compile_checks([clause(1, "A requirement.")], vocab, provider=PROVIDER, transport=t)
    assert all(json.dumps(e["check"], ensure_ascii=False) in sent[0][0] for e in examples)
    assert vocab["compile"]["partial"] in sent[0][0]


@pytest.mark.parametrize("vocab", [CODE, BIM, DOCS], ids=["code", "bim", "documents"])
def test_the_compiler_describes_the_artifact_in_the_vocabularys_own_words(vocab):
    """What the artifact is and what it cannot show come from the vocabulary: documents hold the policies, procedures
    and records that code cannot show, so the compiler must not be told those are always asked of the user."""
    t, sent = transport(lambda s, u: reply({"clauses": []}))
    compile_checks([clause(1, "A requirement.")], vocab, provider=PROVIDER, transport=t)
    c = vocab["compile"]
    assert all(" ".join(c[k].split()) in " ".join(sent[0][0].split()) for k in ("artifact", "search_space", "search_kinds", "outside"))
    assert ("library names" in sent[0][0]) == (vocab is CODE)
    assert ("policies and procedures" in sent[0][0]) == (vocab is not DOCS)


def test_fallback_search_terms_come_from_a_summary_in_any_script():
    assert regulation.words("パスワードはbcryptでハッシュ化する") == ["パスワード", "ハッシュ", "bcrypt"]
    assert regulation.words("Les mots de passe sont hachés.") == ["mots", "passe", "sont", "hachés"]
    assert regulation._search([], "Fluchtwege müssen gekennzeichnet sein.") == ["fluchtwege", "müssen", "gekennzeichnet"]


def test_a_long_clause_is_cut_with_a_marker_and_its_checks_say_so(monkeypatch):
    monkeypatch.setattr(regulation, "MAX_CLAUSE_CHARS", 50)
    t, sent = transport(lambda s, u: reply({"clauses": [{"clause": "c1", "checks": [
        {"summary": "Passwords are hashed.", "kind": "assessed", "why": "x", "search": ["hash", "bcrypt", "argon2"]}]}]}))
    checks, _ = compile_checks([clause(1, "Passwords are hashed with a slow hash. " * 5)], CODE, provider=PROVIDER, transport=t)
    assert checks[0]["clause_cut"] == 50 and "[cut: the clause continues]" in sent[0][1]


def test_checks_work_for_the_building_vocabulary(tmp_path):
    rules = [clause(1, "Stairs are at least 44 inches wide."), clause(2, "Stairs have at least 30 m2 of width."),
             clause(3, "Ramps are not permitted."), clause(4, "The building complies."),
             clause(5, "Stairs are at least 110 cm wide.")]

    def answer(system, user):
        return reply({"clauses": [
            {"clause": "c1", "checks": [{"summary": "Stairs are at least 44 in wide.", "kind": "computed", "why": "Stair.width",
                                         "for": "Stair", "require": {"ge": [{"fact": "s.width"}, "44 in"]}, "search": ["stair", "width", "w"]}]},
            {"clause": "c2", "checks": [{"summary": "Nonsense.", "kind": "computed", "why": "x",
                                         "for": {"var": "s", "type": "Stair"}, "require": {"ge": [{"fact": "s.width"}, "30 m2"]},
                                         "search": ["stair", "width", "area"]}]},
            {"clause": "c3", "checks": [{"summary": "No ramps.", "kind": "computed", "why": "prohibition",
                                         "for": {"var": "r", "type": "Ramp"}, "require": False, "search": ["ramp", "slope", "incline"]}]},
            {"clause": "c4", "checks": [{"summary": "Complies.", "kind": "computed", "why": "always", "for": None, "require": True,
                                         "search": ["code", "compliance", "analysis"]}]},
            {"clause": "c5", "checks": [{"summary": "Stairs are at least 110 cm wide.", "kind": "computed", "why": "Stair.width",
                                         "for": {"var": "s", "type": "Stair"}, "require": {"ge": [{"fact": "s.width"}, "110 cm"]},
                                         "search": ["stair", "width", "cm"]}]}]})
    t, sent = transport(answer)
    checks, _ = compile_checks(rules, BIM, provider=PROVIDER, transport=t)
    assert checks[0]["kind"] == "computed" and checks[0]["for"] == {"var": "s", "type": "Stair"}
    assert checks[1]["kind"] == "assessed" and "'30 m2' is not a value of s.width" in checks[1]["demoted"]
    assert checks[2]["kind"] == "computed" and checks[2]["require"] is False   # a prohibition: every ramp fails
    assert checks[3]["kind"] == "assessed" and "reads no fact" in checks[3]["demoted"]
    assert checks[4]["kind"] == "computed" and "demoted" not in checks[4]   # any length unit is a length
    assert "building." in sent[0][0] and "drawings" in sent[0][0]
    out = build_pack({"id": "rb1", "name": "Stairs", "clauses": rules, "checks": checks}, BIM, tmp_path / "pack")
    rs = load(out)
    assert validate(rs)[0] == [] and rs.subject == "building"
    ev = load_evidence({"sources": [{"id": "ifc"}], "elements": [
        {"type": "Stair", "id": "stair:A", "facts": {"width": [{"value": "1200 mm"}]}},
        {"type": "Stair", "id": "stair:B", "facts": {"width": [{"value": "1000 mm"}]}},
        {"type": "Ramp", "id": "ramp:1", "facts": {"slope": [{"value": 0.05}]}}]})
    verdicts = {(r["norm"], r["element"]): r["verdict"] for r in run(rs, ev)}
    assert verdicts[("k1-1", "stair:A")] == "pass" and verdicts[("k1-1", "stair:B")] == "fail"
    assert verdicts[("k3-1", "ramp:1")] == "fail" and ("k4-1", "subject") in verdicts
    assert verdicts[("k5-1", "stair:A")] == "pass" and verdicts[("k5-1", "stair:B")] == "fail"


# ---------------------------------------------------------------- pack

def test_built_pack_validates_and_the_engine_decides_each_kind(tmp_path):
    long_text = "Queries must be parameterized. " + "x" * 2000
    rules = [clause(1, "Errors do not show stack traces.", ref="3.1"), clause(2, "Training is yearly."), clause(3, long_text, ref="3.2"),
             clause(4, "TLS is enforced.", ref=None), clause(5, "Disabled rule."), clause(6, "Secrets are rotated.")]
    checks = [
        {"id": "k1-1", "clause": "c1", "summary": "Error pages hide stack traces.", "kind": "assessed", "enabled": True,
         "why": "error handlers", "search": ["traceback"]},
        {"id": "k2-1", "clause": "c2", "summary": "Staff are trained yearly.", "kind": "attested", "enabled": True,
         "why": "organisational", "question": "Were all staff trained this year?"},
        {"id": "k3-1", "clause": "c3", "summary": "Queries are parameterized.", "kind": "computed", "enabled": True, "why": "Query",
         "for": {"var": "q", "type": "Query"}, "require": {"in": [{"fact": "q.construction"}, ["parameterized", "orm"]]}},
        {"id": "k3-2", "clause": "c3", "summary": "Request data reaches no query unparameterized.", "kind": "computed", "enabled": True,
         "why": "Query", "for": {"var": "x", "type": "Query"},
         "require": {"any": [{"not": {"fact": "x.untrusted_input"}}, {"ne": [{"fact": "x.construction"}, "interpolated"]}]}},
        {"id": "k4-1", "clause": "c4", "summary": "TLS is enforced.", "kind": "computed", "enabled": True, "why": "system fact",
         "for": None, "require": {"fact": "system.tls_enforced"}},
        {"id": "k5-1", "clause": "c5", "summary": "Disabled.", "kind": "attested", "enabled": False, "why": "", "question": "?"},
        {"id": "k6-1", "clause": "c6", "summary": "Secrets are rotated.", "kind": "assessed", "enabled": True, "why": "x",
         "search": ["rotate"], "demoted": "unknown fact 'system.rotation'"},
    ]
    reg = {"id": "r3f9a0b12c4", "name": "Acme Secure Coding Standard", "clauses": rules, "checks": checks}
    out = build_pack(reg, CODE, tmp_path / "pack")
    assert out == tmp_path / "pack" and sorted(p.name for p in out.iterdir()) == ["norms.yaml", "package.yaml", "predicates.yaml"]
    meta = yaml.safe_load((out / "package.yaml").read_text())
    assert meta == {"package": "reg-r3f9a0b12c4", "version": "1", "title": "Acme Secure Coding Standard", "subject": "system",
                    "text_policy": "public", "format": 2, "source": {"kind": "customer", "files": ["std.md"]}}
    rs = load(out)
    assert validate(rs)[0] == []
    assert fact_attr("r3f9a0b12c4", "k1-1") == "req_r3f9a0b12c4_k1_1"
    preds = {n: el.data for (k, n), el in rs.elements.items() if k == "predicate"}
    assert preds["system.req_r3f9a0b12c4_k1_1"] == {"name": "system.req_r3f9a0b12c4_k1_1", "label": "Error pages hide stack traces.",
                                                     "type": "enum", "values": ["met", "not_met", "not_applicable"],
                                                     "value_labels": {"met": "Yes, met", "not_met": "No, not met", "not_applicable": "Doesn't apply"},
                                                     "kind": "judged"}
    assert preds["system.req_r3f9a0b12c4_k2_1"]["kind"] == "given"
    assert preds["system.req_r3f9a0b12c4_k2_1"]["label"] == "Were all staff trained this year?"
    assert preds["Query.construction"]["values"] == CODE["types"]["Query"]["attrs"]["construction"]["values"]
    # a computed check over elements also gets an answer fact: what a reviewer judges when no element is found
    assert sorted(preds) == sorted(["system.req_r3f9a0b12c4_k1_1", "system.req_r3f9a0b12c4_k2_1", "system.req_r3f9a0b12c4_k6_1",
                                    "system.req_r3f9a0b12c4_k3_1", "system.req_r3f9a0b12c4_k3_2",
                                    "Query.construction", "Query.untrusted_input", "system.tls_enforced"])
    norms = {n: el.data for (k, n), el in rs.elements.items() if k == "norm"}
    assert "k5-1" not in norms
    n = norms["k3-1"]
    assert n["for"] == {"q": "Query"} and n["modality"] == "obligation" and n["status"] == "draft" and n["title"] == "Queries are parameterized."
    assert n["cite"]["section"] == "3.2" and n["cite"]["at"] == "std.md#L3-L3" and n["cite"]["url"] == "/regulations/r3f9a0b12c4#c3"
    assert n["cite"]["quote"].startswith("Queries must be parameterized.") and n["cite"]["quote"].endswith(" …")
    assert len(n["cite"]["quote"]) <= 1502
    assert norms["k4-1"]["cite"]["section"] == "TLS is enforced." and "for" not in norms["k4-1"]
    assert norms["k1-1"]["interpretation"] == {"by": "model", "note": "error handlers"}
    assert "unknown fact 'system.rotation'" in norms["k6-1"]["interpretation"]["note"]

    ev = load_evidence({
        "subject": {"kind": "system", "id": "demo"}, "sources": [{"id": "llm:test"}],
        "facts": {fact_attr(reg["id"], "k1-1"): [{"value": "met", "at": "app/errors.py:3"}],
                  fact_attr(reg["id"], "k2-1"): [{"value": "not_met"}]},
        "elements": [
            {"type": "Query", "id": "q1", "at": "app/db.py:3", "facts": {"construction": [{"value": "interpolated"}], "untrusted_input": [{"value": True}]}},
            {"type": "Query", "id": "q2", "at": "app/db.py:40", "facts": {"construction": [{"value": "parameterized"}], "untrusted_input": [{"value": True}]}},
        ]})
    verdicts = {(r["norm"], r["element"]): r["verdict"] for r in run(rs, ev)}
    assert verdicts == {
        ("k1-1", "demo"): "pass", ("k2-1", "demo"): "fail", ("k4-1", "demo"): "unknown", ("k6-1", "demo"): "unknown",
        ("k3-1", "q1"): "fail", ("k3-1", "q2"): "pass", ("k3-2", "q1"): "fail", ("k3-2", "q2"): "pass"}
    # the user's answer to an attested question arrives as a profile fact
    answered = {r["norm"]: r["verdict"] for r in run(rs, ev, {"system": {fact_attr(reg["id"], "k2-1"): "met"}})}
    assert answered["k2-1"] == "pass"
    # "doesn't apply" is its own verdict, for an assessed and an attested check alike
    na = {r["norm"]: r["verdict"] for r in run(rs, ev, {"system": {fact_attr(reg["id"], "k1-1"): "not_applicable",
                                                                  fact_attr(reg["id"], "k2-1"): "not_applicable"}})}
    assert na["k1-1"] == na["k2-1"] == "not_applicable"
    # no Query found: the check is not silently not applicable; it rests on the reviewer's answer, open until given
    none = load_evidence({"subject": {"kind": "system", "id": "demo"}, "sources": [{"id": "llm:test"}],
                          "facts": {fact_attr(reg["id"], "k3-1"): [{"value": "not_met", "basis": "absence"}]}})
    rows = {r["norm"]: r for r in run(rs, none)}
    assert (rows["k3-1"]["verdict"], rows["k3-1"]["none_found"]) == ("fail", "Query")
    assert rows["k3-2"]["verdict"] == "unknown" and rows["k3-2"]["open"] == ["system.req_r3f9a0b12c4_k3_2"]
    # an answer stored before "doesn't apply" existed (true/false) reads as met / not met
    old = upgrade({"facts": {fact_attr(reg["id"], "k1-1"): [{"value": False, "basis": "absence"}], "tls_enforced": [{"value": True}]}})
    assert old["facts"] == {fact_attr(reg["id"], "k1-1"): [{"value": "not_met", "basis": "absence"}], "tls_enforced": [{"value": True}]}


def test_checks_from_two_regulations_never_share_a_fact(tmp_path):
    rules = [clause(1, "Training is yearly.")]
    chk = [{"id": "k1-1", "clause": "c1", "summary": "Trained.", "kind": "attested", "enabled": True, "why": "", "question": "Trained?"}]
    a = load(build_pack({"id": "ra", "name": "A", "clauses": rules, "checks": chk}, CODE, tmp_path / "a"))
    b = load(build_pack({"id": "rb", "name": "B", "clauses": rules, "checks": chk}, CODE, tmp_path / "b"))
    assert a.get("norm", "k1-1").data["require"] != b.get("norm", "k1-1").data["require"]


def test_build_pack_refuses_a_directory_with_other_yaml(tmp_path):
    (tmp_path / "rules.yaml").write_text("norms: []\n")
    with pytest.raises(RegulationError, match="other YAML files"):
        build_pack({"id": "r1", "name": "x", "clauses": [], "checks": []}, CODE, tmp_path)


def test_build_pack_rejects_a_computed_check_without_an_expression(tmp_path):
    chk = {"id": "k1-1", "clause": "c1", "summary": "x", "kind": "computed", "enabled": True, "why": "", "search": ["a"]}
    with pytest.raises(RegulationError, match="k1-1 is computed but has no valid 'require'"):
        build_pack({"id": "r1", "name": "x", "clauses": [clause(1, "x")], "checks": [chk]}, CODE, tmp_path)


def test_a_check_without_search_terms_gets_the_same_content_words_wherever_it_is_derived():
    """The compiler's fallback, an assessed check's requirement, and a check switched to assessed by the user."""
    summary = "The operator must ensure that staff handling food are trained."
    assert regulation.summary_terms(summary) == ["operator", "staff", "handling", "food", "trained"]
    req = regulation.requirements({"id": "r1", "clauses": [], "checks": [
        {"id": "k1-1", "clause": "c1", "kind": "assessed", "enabled": True, "summary": summary}]})
    assert req[0]["search"] == regulation.summary_terms(summary)
    assert regulation._search([], summary) == ["operator", "staff", "handling"]
