"""Questions asked of a scanned repository, a building project, customer regulations, or a project together with
its regulations (adapters.research), quick or as deep research.

Stored under NORMIR_DATA/questions/<id>/: request.json ({question, mode, artifact: {kind, id} | null, regulations:
[rid]}), status.json, answer.json (adapters.research.ask's result). A scan keeps the text files it read under
scans/<id>/source (app.scan.keep_source), so questions about code read the commit that was scanned.
"""

from __future__ import annotations

import re
import secrets
import time
import traceback
from pathlib import Path
from urllib.parse import quote

from . import regulations as regs
from .regulations import _read, _write, status

QID = re.compile(r"^[a-z0-9]{12}$")
FOLDERS = {"scan": "scans", "project": "projects", "documents": "documents"}   # artifact kind -> its folder under DATA
KINDS = tuple(FOLDERS)


class QuestionError(ValueError):
    pass


def qdir(qid: str) -> Path:
    if not QID.match(qid or "") or not (regs.DATA / "questions" / qid).is_dir():
        raise QuestionError("No such question")
    return regs.DATA / "questions" / qid


def _artifact_dir(kind: str, aid: str) -> Path:
    d = regs.DATA / FOLDERS.get(kind, "") / aid
    if not QID.match(aid or "") or not d.is_dir():
        raise QuestionError(f"No such {kind}")
    if (_read(d, "status.json", {}) or {}).get("state") != "done":
        raise QuestionError(f"The {kind} has not finished")
    return d


def create(question: str, mode: str, artifact: dict | None, regulations: list[str], history: list[dict] = (),
           chat: str | None = None) -> str:
    """Validate and store a question; returns its id. Raises QuestionError for bad input. `history`: the earlier turns
    of the chat it continues ([{question, answer}])."""
    from adapters.research import MODES
    question = " ".join(str(question or "").split())[:2000]
    if len(question) < 3:
        raise QuestionError("Ask a question.")
    if mode not in MODES:
        raise QuestionError(f"Mode is one of {', '.join(MODES)}.")
    if artifact:
        if artifact.get("kind") not in KINDS:
            raise QuestionError("Ask about a scan, a building project or a document set.")
        d = _artifact_dir(artifact["kind"], artifact.get("id"))
        if artifact["kind"] == "scan" and not (d / "source").is_dir():
            raise QuestionError("This scan kept no copy of the code. Scan the repository again to ask questions about it.")
    rids = list(dict.fromkeys(r for r in regulations if r))[:12]
    for rid in rids:
        try:
            reg = regs.load_reg(rid) if regs.REG_ID.match(rid) else None
        except regs.RegulationNotFound:
            reg = None
        if reg is None:
            raise QuestionError(f"No compiled regulation {rid}.")
    if not artifact and not rids:
        raise QuestionError("Choose what to ask about.")
    qid = secrets.token_hex(6)
    d = regs.DATA / "questions" / qid
    d.mkdir(parents=True)
    _write(d, "request.json", {"id": qid, "question": question, "mode": mode, "artifact": artifact or None, "regulations": rids,
                               "history": list(history or []), "chat": chat,
                               "created": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())})
    status(d, state="queued", step="Queued", log=["Queued"])
    return qid


def corpus_of(req: dict):
    """The corpus a question reads: the artifact, its regulations, or a Union tagging the artifact A and the
    regulations R1, R2, ..."""
    from adapters.research import RegulationCorpus, Union
    parts = {}
    art = req.get("artifact")
    if art:
        d = _artifact_dir(art["kind"], art["id"])
        if art["kind"] == "scan":
            from adapters.assess import CodeCorpus
            data = _read(d, "scan.json")
            parts["A"] = CodeCorpus(d / "source", f"{data['repo']['owner']}/{data['repo']['name']}")
        elif art["kind"] == "documents":
            from .documents import corpus
            parts["A"] = corpus(_read(d, "data.json"), _read(d, "request.json")["name"])
        else:
            from adapters.assess.building import BuildingCorpus
            data, preq = _read(d, "data.json"), _read(d, "request.json")
            parts["A"] = BuildingCorpus.from_project(d / "files", data["docs"], data.get("sheets") or [], preq["name"])
    for i, rid in enumerate(req.get("regulations") or [], 1):
        parts[f"R{i}"] = RegulationCorpus(regs.load_reg(rid))
    return next(iter(parts.values())) if len(parts) == 1 else Union(parts)


def run(qid: str) -> None:
    """Answer the question. Runs in the app's worker pool."""
    from adapters.research import ask
    d = regs.DATA / "questions" / qid
    req = _read(d, "request.json")
    log: list[str] = []

    def progress(msg: str) -> None:
        log.append(msg)
        status(d, state="running", step=msg, log=log[-40:])
    try:
        progress("Reading the material")
        res = ask(req["question"], corpus_of(req), req["mode"], cache=regs.DATA / "research-cache", progress=progress,
                  history=req.get("history") or [])
        _write(d, "answer.json", res)
        status(d, state="done", step="Done", seconds=res["stats"]["seconds"])
    except Exception as e:  # noqa: BLE001 - shown to the user; the trace is kept on disk
        (d / "error.txt").write_text(traceback.format_exc())
        msg = str(e) if type(e).__name__ in ("ReaderError", "QuestionError") else f"{type(e).__name__}: {e}"
        status(d, state="error", error=msg)


def recent(artifact: dict | None = None, regulation: str | None = None, limit: int = 8) -> list[dict]:
    """The latest questions about an artifact or a regulation, newest first."""
    root = regs.DATA / "questions"
    if not root.is_dir():
        return []
    out = []
    for d in sorted(root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        req = _read(d, "request.json")
        if not req or (artifact and req.get("artifact") != artifact) or (regulation and regulation not in (req.get("regulations") or [])):
            continue
        st = _read(d, "status.json", {}) or {}
        ans = _read(d, "answer.json", {}) if st.get("state") == "done" else {}
        out.append({**req, "state": st.get("state"), "status": (ans or {}).get("status")})
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------- showing an answer

def parts_of(req: dict) -> dict[str, dict]:
    """tag -> {kind, id, name, href} for each part of the question's material (a single part has tag "")."""
    out = {}
    art = req.get("artifact")
    rids = req.get("regulations") or []
    single = (1 if art else 0) + len(rids) == 1
    if art:
        d = regs.DATA / FOLDERS[art["kind"]] / art["id"]
        if art["kind"] == "scan":
            data = _read(d, "scan.json") or {}
            repo = data.get("repo") or {}
            out["" if single else "A"] = {"kind": "scan", "id": art["id"], "name": f"{repo.get('owner')}/{repo.get('name')}",
                                         "href": f"/scans/{art['id']}", "repo": repo}
        elif art["kind"] == "documents":
            out["" if single else "A"] = {"kind": "documents", "id": art["id"], "name": (_read(d, "request.json") or {}).get("name"),
                                         "href": f"/documents/{art['id']}"}
        else:
            preq = _read(d, "request.json") or {}
            data = _read(d, "data.json") or {}
            out["" if single else "A"] = {"kind": "project", "id": art["id"], "name": preq.get("name"), "href": f"/projects/{art['id']}",
                                         "sheets": {(s["file"], s.get("page") or s.get("layout")): s for s in data.get("sheets") or []}}
    for i, rid in enumerate(rids, 1):
        reg = regs.load_reg(rid) or {}
        out["" if single else f"R{i}"] = {"kind": "regulation", "id": rid, "name": reg.get("name") or rid, "href": f"/regulations/{rid}",
                                          "clauses": {c["id"]: c for c in reg.get("clauses") or []}}
    return out


def citation(loc: str, quoted: str, parts: dict[str, dict]) -> dict:
    """What the page shows for one cited locator: {label, href, part, kind, lines | text | img}."""
    from .scan import mask
    tag, _, own = loc.partition("|") if "|" in loc and loc.split("|", 1)[0] in parts else ("", "", loc)
    p = parts.get(tag) or {}
    out = {"at": loc, "part": p.get("name") if tag else None, "kind": p.get("kind"),
           "ref": {"kind": p.get("kind"), "id": p.get("id"), "at": own}}   # what the chat's preview opens
    if p.get("kind") == "scan":
        m = re.match(r"^(.+):(\d+)(?:-(\d+))?$", own)
        path, a, b = (m[1], int(m[2]), int(m[3] or m[2])) if m else (own, 1, 1)
        repo = p["repo"]
        out.update(label=own, href=f"{repo.get('url')}/blob/{repo.get('commit')}/{quote(path)}#L{a}" + (f"-L{b}" if b != a else ""),
                   lines=[[a + i, mask(t[:240])] for i, t in enumerate(quoted.split("\n"))])
    elif p.get("kind") == "regulation":
        c = p["clauses"].get(own) or {}
        out.update(label=" ".join(x for x in (c.get("ref"), c.get("title")) if x) or own, href=f"{p['href']}#{own}", text=quoted)
    elif p.get("kind") == "documents":
        m = re.match(r"^(.+)#L(\d+)(?:-L(\d+))?$", own)
        a = int(m[2]) if m else 1
        out.update(label=own, href=p["href"], lines=[[a + i, t[:240]] for i, t in enumerate(quoted.split("\n"))])
    elif p.get("kind") == "project":
        from .buildings import locate
        where = locate(p["id"], p["sheets"], own)
        out.update(label=where["label"], href=where.get("img") or p["href"], img=where.get("img"), text=quoted)
    else:
        out.update(label=own, href=None, text=quoted)
    return out


def page(qid: str) -> dict:
    """Everything the question page shows."""
    d = qdir(qid)
    req, st = _read(d, "request.json"), status(d)
    ans = _read(d, "answer.json") if st.get("state") == "done" else None
    parts = parts_of(req)
    cites = {}
    if ans:
        for loc, text in (ans.get("quotes") or {}).items():
            cites[loc] = citation(loc, text, parts)
    return {"qid": qid, "req": req, "st": st, "a": ans, "parts": parts, "cites": cites}
