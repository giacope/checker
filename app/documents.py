"""Document sets: a case file, a plan, a contract or records in, a report against the user's regulations out.

    upload (PDF, Word, HTML, Markdown, text)
      -> adapters.regulation.read     (each file as numbered lines, the same reader regulations go through)
      -> adapters.assess.documents    (the lines as the corpus a model reads; every answer cites lines it was shown)
      -> evidence in vocab/documents.yaml terms (one subject, the matter; no elements)
      -> each regulation's compiled pack, with the user's answers to its attested checks

Nothing is extracted from such documents deterministically, so every check of a documents regulation is assessed
by the model or asked of the user; without a model, the assessed ones stay open as questions too.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from normir import load
from normir.evidence import load_evidence, run

from adapters.assess.documents import DocumentCorpus
from adapters.regulation import answer, upgrade
from adapters.regulation.documents import Document, Line, RegulationError, read

from . import regulations as regs
from . import report as report_mod
from .buildings import assessments


class DocumentsError(Exception):
    """Input the documents check cannot use; the message is shown to the user."""


def process(files_dir: Path, name: str, progress=lambda m: None, requirements: list[dict] = ()) -> dict:
    """Read every file and have a model assess `requirements` (app.regulations.assessed) from their text.
    Returns {docs, documents, files, notes, seconds}: the evidence documents and the documents as read."""
    started = time.time()
    read_docs, notes = [], []
    for p in sorted(p for p in files_dir.rglob("*") if p.is_file()):
        rel = str(p.relative_to(files_dir))
        progress(f"Reading {rel}")
        try:
            read_docs.append(read(p, rel))
        except RegulationError as e:
            notes.append(f"{e}; skipped.")
    if not read_docs:
        raise DocumentsError(" ".join(["None of the uploaded files could be read.", *notes]))
    files = [{"file": d.file, "kind": d.kind, "pages": d.pages, "lines": len(d.lines), "sha256": d.sha256} for d in read_docs]
    docs = [{"subject": {"kind": "matter", "id": name},
             "sources": [{"id": "documents", "kind": "documents", "adapter": "adapters.regulation.documents", "files": files}],
             "facts": {}, "elements": []}]
    if requirements:
        from adapters.code_llm import provider_from_env
        if provider_from_env() is None:
            notes.append(f"{len(requirements)} requirements of your regulations are judged by a model, and none is configured: "
                         "they stay open as questions.")
        else:
            from adapters.assess import assess
            progress(f"Assessing {len(requirements)} requirements of your regulations")
            try:
                docs.append(assess(list(requirements), DocumentCorpus(read_docs, name), progress=progress,
                                   subject={"kind": "matter", "id": name}, cache=regs.DATA / "assess-cache"))
            except Exception as e:  # noqa: BLE001 - the checks stay open; the reason is the user's to know
                notes.append(f"Assessing your regulations' requirements failed: {e}. Those checks stay open.")
    return {"docs": docs, "documents": [asdict(d) for d in read_docs], "files": files, "notes": notes,
            "seconds": round(time.time() - started, 1)}


def corpus(data: dict, name: str) -> DocumentCorpus:
    """The stored documents (process()["documents"]) as the corpus they were assessed from."""
    return DocumentCorpus([Document(**{**d, "lines": [Line(**ln) for ln in d["lines"]]}) for d in data["documents"]], name)


def evaluate(docs: list[dict], codes: list[str], answers: dict | None = None) -> dict:
    """Run each regulation's pack; `answers` is {"subject": {attr: value}}, the user's answers to its questions."""
    ev = load_evidence(*(upgrade(d) for d in docs))
    profile = {k: answer(v) for k, v in ((answers or {}).get("subject") or {}).items()}
    out = {}
    for cid in codes:
        req = regs.ready(cid[4:], "documents")
        if req is None:
            continue
        rs = load(regs.pack_dir(cid[4:]))
        out[cid] = {"pack": f"regulations/{cid[4:]}", "label": req["name"], "short": req["name"], "rs": rs, "norms": None,
                    "rows": run(rs, ev, dict(profile))}
    return {"evidence": ev, "results": out}


def locate(c: DocumentCorpus, at: str) -> dict:
    s = c.snippet(at)
    if s is None:
        return {"at": at, "label": str(at), "snippet": None}
    lines = f"L{s['line']}" + (f"–{s['end']}" if s["end"] != s["line"] else "")
    pages = f" · p{s['pages'][0]}" + (f"–{s['pages'][-1]}" if len(s["pages"]) > 1 else "") if s["pages"] else ""
    return {"at": at, "label": f"{s['file']} {lines}{pages}", "snippet": s}


def build(project: dict, data: dict, evaluation: dict, answers: dict | None = None) -> dict:
    c = corpus(data, project["name"])
    loc = lambda a: locate(c, a)  # noqa: E731
    standards, questions = report_mod.sections(evaluation, loc)
    assessed = assessments(evaluation, loc, {})
    for s in standards:
        for e in s["entries"]:
            e["assessment"] = assessed.get((s["id"], e["norm"]))
    given = (answers or {}).get("subject") or {}
    for q in questions.values():
        q["answer"] = given.get(q["attr"]) if q["element"] == "_subject" else None
    labels = {str(el.data.get("vocab") or name).rpartition(".")[2]: el.data.get("label") for res in evaluation["results"].values()
              for (kind, name), el in res["rs"].elements.items() if kind == "predicate"}
    return {
        "project": project, "files": data.get("files", []), "seconds": data.get("seconds"),
        "notes": report_mod.source_limits(data["docs"]) + data.get("notes", []),
        "sources": [s for d in data["docs"] for s in d.get("sources", [])],
        "standards": standards,
        "questions": sorted((q for q in questions.values() if q["answer"] is None), key=lambda q: q["attr"]),
        "answered": [{"attr": a, "value": v, "label": labels.get(a) or a} for a, v in given.items()],
        "totals": dict(Counter(e["verdict"] for s in standards for e in s["entries"])),
    }
