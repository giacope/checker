"""Chats: a conversation about one artifact (a scan, a building project, a document set) and the regulations read
with it. Each turn is a question (app.questions), quick or deep research; a follow-up carries the earlier turns as
context. Citations, and the locators in the context's checks, open as previews: the code file around the cited
lines, the PDF page and its lines, a drawing sheet, the 3D model with the cited element, or the regulation clause
with the checks compiled from it.

Stored under NORMIR_DATA/chats/<id>/chat.json: {id, title, created, artifact: {kind, id} | null, regulations: [rid],
turns: [question id]}.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote

from . import questions as qs
from . import regulations as regs
from .regulations import _read, _write

CID = re.compile(r"^[a-z0-9]{12}$")
HISTORY_TURNS = 6           # earlier turns a follow-up carries
CODE_WINDOW = 400           # lines of a long file shown on each side of a citation
MAX_FILE_BYTES = 2_000_000  # a larger source file is shown around the citation only
MESH_SECONDS = 180
MESH_FORMAT = 2                 # of what app.model_mesh writes; names the kept file and the browser-cached URL, so a
                                # changed format is neither reused from disk nor from a browser cache


class ChatError(ValueError):
    pass


def _root() -> Path:
    return regs.DATA / "chats"


def cdir(cid: str) -> Path:
    if not CID.match(cid or "") or not (_root() / cid / "chat.json").is_file():
        raise ChatError("No such chat")
    return _root() / cid


# ---------------------------------------------------------------- conversations

def create(question: str, mode: str, artifact: dict | None, regulations: list[str]) -> tuple[str, str]:
    """A new chat and its first turn: (chat id, question id). Raises QuestionError for bad input."""
    cid = secrets.token_hex(6)
    d = _root() / cid
    d.mkdir(parents=True)
    _write(d, "chat.json", {"id": cid, "title": " ".join(question.split())[:80], "artifact": artifact or None,
                            "regulations": list(dict.fromkeys(r for r in regulations if r)), "turns": [],
                            "created": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())})
    try:
        return cid, add_turn(cid, question, mode)
    except Exception:
        shutil.rmtree(d, ignore_errors=True)
        raise


def _said(qid: str) -> dict | None:
    """A finished turn as context for the next: the question and what the answer said, its claims included."""
    try:
        d = qs.qdir(qid)
    except qs.QuestionError:
        return None
    req, ans = _read(d, "request.json"), _read(d, "answer.json")
    if not ans:
        return None
    claims = [c["text"] for s in ans.get("sections") or [] for c in s.get("claims") or []]
    return {"question": req["question"], "answer": " ".join([ans.get("answer") or ""] + [f"- {c}" for c in claims[:12]])}


def add_turn(cid: str, question: str, mode: str) -> str:
    d = cdir(cid)
    chat = _read(d, "chat.json")
    history = [h for h in (_said(q) for q in chat["turns"][-HISTORY_TURNS:]) if h]
    qid = qs.create(question, mode, chat["artifact"], chat["regulations"], history, chat=cid)
    chat["turns"].append(qid)
    _write(d, "chat.json", chat)
    return qid


def chats(limit: int = 40) -> list[dict]:
    root = _root()
    if not root.is_dir():
        return []
    out = []
    for d in sorted(root.iterdir(), key=lambda p: (p / "chat.json").stat().st_mtime if (p / "chat.json").is_file() else 0, reverse=True):
        c = _read(d, "chat.json")
        if c:
            out.append({"id": c["id"], "title": c["title"], "created": c["created"], "turns": len(c["turns"])})
        if len(out) >= limit:
            break
    return out


def _parts(chat: dict) -> list[dict]:
    parts = qs.parts_of({"artifact": chat["artifact"], "regulations": chat["regulations"]})
    return [{"tag": t, "kind": p["kind"], "id": p["id"], "name": p["name"], "href": p["href"]} for t, p in parts.items()]


def view(cid: str) -> dict:
    """The chat as the page shows it: its context and every turn, finished or still running."""
    d = cdir(cid)
    chat = _read(d, "chat.json")
    turns = []
    for qid in chat["turns"]:
        try:
            pg = qs.page(qid)
        except qs.QuestionError:
            continue
        st, a = pg["st"], pg["a"]
        turns.append({"qid": qid, "question": pg["req"]["question"], "mode": pg["req"]["mode"], "created": pg["req"]["created"],
                      "state": st.get("state"), "step": st.get("step"), "log": st.get("log") or [], "error": st.get("error"),
                      "answer": {k: a.get(k) for k in ("status", "answer", "sections", "conflicts", "open", "coverage", "stats")} if a else None,
                      "cites": pg["cites"]})
    return {"id": cid, "title": chat["title"], "created": chat["created"], "artifact": chat["artifact"],
            "regulations": chat["regulations"], "parts": _parts(chat), "turns": turns}


# ---------------------------------------------------------------- what a chat can be about

def contexts() -> dict:
    """Finished artifacts and compiled regulations a chat can be about, newest first."""
    arts = []
    for kind, folder in qs.FOLDERS.items():
        root = regs.DATA / folder
        for d in sorted(root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True) if root.is_dir() else []:
            if (_read(d, "status.json", {}) or {}).get("state") != "done":
                continue
            req = _read(d, "request.json") or {}
            if kind == "scan":
                if not (d / "source").is_dir():
                    continue
                repo = (_read(d, "scan.json") or {}).get("repo") or {}
                name, own = f"{repo.get('owner')}/{repo.get('name')}", req.get("standards") or []
            else:
                name, own = req.get("name") or d.name, req.get("codes") or []
            arts.append({"kind": kind, "id": d.name, "name": name, "domain": {"scan": "code", "project": "building"}.get(kind, kind),
                         "regulations": [c[4:] for c in own if c.startswith("reg:")], "created": req.get("created")})
    return {"artifacts": arts,
            "regulations": [{"id": r["id"], "name": r["name"], "domain": r["domain"]} for r in regs.regulations() if r["state"] == "done"]}


def checks(rep: dict) -> dict:
    """The context's report as the chat shows it: verdict counts per standard, and the checks that fail or are
    uncertain first, each with its requirement, reasons and locators (which open as previews). All of them: the
    chat filters and counts them by verdict."""
    stds, entries = [], []
    for s in rep.get("standards") or []:
        stds.append({"id": s["id"], "label": s["label"], "summary": s.get("summary") or {}})
        for e in s["entries"]:
            reasons = [n["note"] for f in e.get("findings") or [] for n in f.get("notes") or [] if n.get("note")]
            ats = [a for f in e.get("findings") or [] for a in f.get("at") or []]
            m = e.get("assessment")
            if m:
                reasons.insert(0, m.get("note") or "")
                ats = list(m.get("at") or []) + ats
            seen, cites = set(), []
            for a in ats:
                at = a.get("at") if isinstance(a, dict) else a
                if at and at not in seen:
                    seen.add(at)
                    cites.append({"at": at, "label": (a.get("label") if isinstance(a, dict) else None) or at})
            entries.append({"standard": s["label"], "norm": e["norm"], "section": e.get("section"), "title": e.get("title"),
                            "verdict": e["verdict"], "quote": (e.get("quote") or "")[:3000] or None,
                            "interpretation": e.get("interpretation") or None, "url": e.get("url"),
                            "reasons": [r[:600] for r in dict.fromkeys(reasons) if r][:4], "at": cites[:8],
                            "open": [o for f in e.get("findings") or [] for o in f.get("open_labels") or []][:6]})
    order = {"fail": 0, "uncertain": 1, "unknown": 2, "pass": 3, "not_applicable": 4}
    entries.sort(key=lambda e: order.get(e["verdict"], 5))
    totals: dict[str, int] = {}
    for e in entries:
        totals[e["verdict"]] = totals.get(e["verdict"], 0) + 1
    return {"standards": stds, "totals": totals, "entries": entries}


# ---------------------------------------------------------------- previews

def _artifact(kind: str, aid: str) -> Path:
    if kind not in qs.FOLDERS or not CID.match(aid or ""):
        raise ChatError(f"No such {kind}")
    d = regs.DATA / qs.FOLDERS[kind] / aid
    if not d.is_dir():
        raise ChatError(f"No such {kind}")
    return d


def _inside(root: Path, rel: str) -> Path:
    p = (root / rel).resolve()
    if root.resolve() not in p.parents or not p.is_file():
        raise ChatError("No such file")
    return p


def preview(kind: str, aid: str, at: str) -> dict:
    """What a locator shows in the preview pane: {type: code | document | sheet | model | clause | text, label, ...}."""
    at = str(at or "")[:2000]
    if kind == "scan":
        return _code(_artifact(kind, aid), at)
    if kind == "documents":
        return _document(_artifact(kind, aid), aid, at)
    if kind == "project":
        return _building(_artifact(kind, aid), aid, at)
    if kind == "regulation":
        try:
            reg = regs.load_reg(aid) or {}
        except regs.RegulationNotFound:
            raise ChatError("No such regulation") from None
        c = next((x for x in reg.get("clauses") or [] if x["id"] == at.split("#")[0]), None)
        if c is None:
            raise ChatError("No such clause")
        return {"type": "clause", "label": " ".join(x for x in (c.get("ref"), c.get("title")) if x) or c["id"],
                "regulation": reg.get("name"), "text": c.get("text") or "", "at": c.get("at"), "href": f"/regulations/{aid}#{c['id']}",
                "checks": [{"id": k["id"], "summary": k.get("summary"), "kind": k.get("kind"), "question": k.get("question"),
                            "enabled": k.get("enabled", True)} for k in reg.get("checks") or [] if k.get("clause") == c["id"]]}
    raise ChatError(f"Nothing to preview for {kind}")


def _code(d: Path, at: str) -> dict:
    from .scan import mask
    m = re.match(r"^(.+?):(\d+)(?:\s*[-–]\s*(\d+))?$", at)
    path, a, b = (m[1], int(m[2]), int(m[3] or m[2])) if m else (at.split("#")[0], 0, 0)
    f = _inside(d / "source", path)
    raw = f.read_bytes()[:MAX_FILE_BYTES * 4]
    lines = raw.decode("utf-8", errors="replace").split("\n")
    first, last = 1, len(lines)
    if len(raw) > MAX_FILE_BYTES or len(lines) > 2 * CODE_WINDOW + 200:
        first, last = max(1, (a or 1) - CODE_WINDOW), min(len(lines), max(a, b, 1) + CODE_WINDOW)
    repo = (_read(d, "scan.json") or {}).get("repo") or {}
    href = f"{repo['url']}/blob/{repo['commit']}/{quote(path)}" + (f"#L{a}" + (f"-L{b}" if b != a else "") if a else "") \
        if repo.get("url") and repo.get("commit") else None
    return {"type": "code", "label": at, "path": path, "start": first, "lines": [mask(t[:400]) for t in lines[first - 1:last]],
            "total": len(lines), "focus": [a, b] if a else None, "href": href, "language": Path(path).suffix.lstrip(".")}


def _document(d: Path, aid: str, at: str) -> dict:
    m = re.match(r"^(.+?)(?:#[Ll](\d+)(?:\s*[-–]\s*[Ll]?(\d+))?)?$", at)
    file, a = m[1], int(m[2] or 0)
    b = int(m[3] or a)
    doc = next((x for x in (_read(d, "data.json") or {}).get("documents") or [] if x["file"] == file), None)
    if doc is None:
        raise ChatError("No such document in this set")
    lines = doc.get("lines") or []
    by_no = {ln["no"]: ln for ln in lines}
    pages = sorted({by_no[n]["page"] for n in range(a, b + 1) if n in by_no and by_no[n].get("page")})
    if pages:
        shown = [ln for ln in lines if pages[0] <= (ln.get("page") or 0) <= pages[-1]]
    else:
        lo = max(1, (a or 1) - 60)
        shown = [ln for ln in lines if lo <= ln["no"] <= max(b, a) + 60]
    pdf = file.lower().endswith(".pdf") and (d / "files" / file).is_file()
    return {"type": "document", "label": at, "file": file, "pages": pages, "page_count": doc.get("pages"),
            "lines": [[ln["no"], ln.get("page"), ln["text"][:600]] for ln in shown[:1500]], "focus": [a, b] if a else None,
            "images": [f"/api/documents/{aid}/page?file={quote(file)}&page={p}" for p in pages[:3]] if pdf else [],
            "href": f"/documents/{aid}"}


def _building(d: Path, pid: str, at: str) -> dict:
    from .buildings import locate
    data = _read(d, "data.json") or {}
    sheets = {(s["file"], s.get("page") or s.get("layout")): s for s in data.get("sheets") or []}
    where = locate(pid, sheets, at)
    if where["kind"] == "sheet":
        from adapters.drawings.tokens import parse_locator
        loc = parse_locator(at)
        full = f"/projects/{pid}/thumb?file={quote(loc['file'])}" + (f"&page={loc['page']}" if loc["page"] else f"&layout={quote(loc['layout'])}")
        return {"type": "sheet", "label": where["label"], "img": where["img"], "full": full, "href": f"/projects/{pid}"}
    if where["kind"] == "ifc":
        gid = at[4:]
        el = next((e for doc in data.get("docs") or [] for e in doc.get("elements") or []
                   if at in (e["at"] if isinstance(e.get("at"), list) else [e.get("at")]) or e.get("id") == gid), None)
        facts = {k: sorted({str(o.get("value")) for o in v})[:4] for k, v in (el or {}).get("facts", {}).items()}
        return {"type": "model", "label": where["label"], "gid": gid, "model": f"/api/projects/{pid}/model.json?v={MESH_FORMAT}",
                "element": {"type": el.get("type"), "id": el.get("id"), "facts": facts} if el else None, "href": f"/projects/{pid}"}
    return {"type": "text", "label": where["label"], "href": f"/projects/{pid}"}


def model_mesh(pid: str) -> Path:
    """The project's IFC models as one mesh file (app.model_mesh), built once in a child process and kept."""
    d = _artifact("project", pid)
    out = d / f"mesh-{MESH_FORMAT}.json"
    if out.is_file():
        return out
    ifcs = sorted(p for p in (d / "files").rglob("*") if p.suffix.lower() == ".ifc" and p.is_file())
    if not ifcs:
        raise ChatError("This project has no IFC model")
    merged = {"elements": [], "bbox": None, "triangles": 0, "skipped": 0, "files": []}
    for f in ifcs:
        tmp = d / f".mesh-{hashlib.sha1(str(f).encode()).hexdigest()[:10]}.json"
        try:   # a geometry kernel that crashes or hangs on a damaged model takes only this child down
            subprocess.run([sys.executable, "-m", "app.model_mesh", str(f), str(tmp)], timeout=MESH_SECONDS, check=True,
                           capture_output=True, cwd=Path(__file__).resolve().parents[1])
            m = json.loads(tmp.read_text())
        except (subprocess.SubprocessError, OSError, ValueError):
            merged["skipped_files"] = merged.get("skipped_files", []) + [f.name]
            continue
        finally:
            tmp.unlink(missing_ok=True)
        merged["elements"] += m["elements"]
        merged["triangles"] += m["triangles"]
        merged["skipped"] += m["skipped"]
        merged["files"].append(f.name)
        if m["bbox"]:
            lo, hi = merged["bbox"] or [[float("inf")] * 3, [float("-inf")] * 3]
            merged["bbox"] = [[min(x, y) for x, y in zip(lo, m["bbox"][0])], [max(x, y) for x, y in zip(hi, m["bbox"][1])]]
    if not merged["elements"]:
        raise ChatError("The model's geometry could not be read")
    part = out.with_suffix(".part")
    part.write_text(json.dumps(merged))
    part.replace(out)
    return out
