"""A set of documents as the corpus the assessor reads: a case file, a plan, a contract, records.

The documents are read by the regulation reader (adapters.regulation.read: PDF, DOCX, HTML, Markdown, text), so a
case file is numbered line by line exactly as a regulation is. Each document is cut into fixed windows of WINDOW
lines, headed `file#L<first>-L<last>` with its pages; a window is one excerpt, so excerpts retrieved for different
requirements merge by header. Locators are `file#L<n>` or `file#L<first>-L<last>` (at most MAX_SPAN lines).
"""

from __future__ import annotations

import re

from adapters.regulation.documents import Document

from . import rank

WINDOW = 40
MAX_SPAN = 30
LOCATOR = re.compile(r"^(?P<file>.+?)(?:#L|:)(?P<a>\d{1,9})(?:-L?(?P<b>\d{1,9}))?$")


def _row(ln) -> str:
    return f"{ln.no:5}  {ln.text}".rstrip()


class DocumentCorpus:
    prompt_notes = ("The artifact is a set of documents (for example a case file, a plan, a contract, or records). Each "
                    "excerpt is a window of one document, headed `file#L<first>-L<last>` with its pages; every line "
                    "carries its line number in the left margin. Cite `file#L<n>` or `file#L<first>-L<last>` for a "
                    "short span, the file name exactly as in the header. Judge only from what the documents say: a "
                    "statement that something was done is evidence that it is recorded as done, not that it happened. "
                    "When the documents do not address a requirement, say so rather than infer it.")

    def __init__(self, docs: list[Document], name: str):
        self.name = name
        self.revision = None
        self._lines = {d.file: d.lines for d in docs}
        self._blocks = []
        self._header: dict[tuple[str, int], str] = {}   # (file, line) -> the window that shows it
        for d in docs:
            for i in range(0, len(d.lines), WINDOW):
                part = d.lines[i:i + WINDOW]
                pages = sorted({ln.page for ln in part if ln.page is not None})
                where = (f" p{pages[0]}" + (f"-{pages[-1]}" if pages[-1] != pages[0] else "")) if pages else ""
                head = f"{d.file}#L{part[0].no}-L{part[-1].no}{where}"
                body = "\n".join(_row(ln) for ln in part)
                for ln in part:
                    self._header[(d.file, ln.no)] = head
                self._blocks.append((head, body, "\n".join(ln.text for ln in part).lower()))

    def search(self, terms: list[str], budget: int) -> list[tuple[str, str]]:
        return rank(self._blocks, terms, budget)

    def everything(self) -> list[tuple[str, str]]:
        return [(h, t) for h, t, _ in self._blocks]

    def _span(self, locator: str):
        m = LOCATOR.match(str(locator or "").strip().strip("`'\""))
        if not m or m["file"] not in self._lines:
            return None
        a, b = int(m["a"]), int(m["b"] or m["a"])
        lines = self._lines[m["file"]]
        if not 1 <= a <= b <= len(lines) or b - a >= MAX_SPAN:
            return None
        return m["file"], a, b

    def verify(self, locator: str) -> str | None:
        s = self._span(locator)
        return None if s is None else f"{s[0]}#L{s[1]}" + (f"-L{s[2]}" if s[2] != s[1] else "")

    def excerpt(self, locator: str) -> str:
        s = self._span(locator)
        return "" if s is None else "\n".join(ln.text for ln in self._lines[s[0]][s[1] - 1:s[2]])

    def rendered(self, locator: str) -> list[tuple[str, str]]:
        s = self._span(locator)
        return [] if s is None else [(self._header[(s[0], ln.no)], _row(ln)) for ln in self._lines[s[0]][s[1] - 1:s[2]]]

    def snippet(self, locator: str, context: int = 2) -> dict | None:
        """The cited lines with `context` lines around them, for a report: {file, line, end, pages, lines: [(no, text)]}."""
        s = self._span(locator)
        if s is None:
            return None
        file, a, b = s
        rows = self._lines[file][max(0, a - 1 - context):b + context]
        pages = sorted({ln.page for ln in self._lines[file][a - 1:b] if ln.page is not None})
        return {"file": file, "line": a, "end": b, "pages": pages, "lines": [(ln.no, ln.text) for ln in rows]}
