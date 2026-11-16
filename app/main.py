"""Web app: link a GitHub repository, get an OWASP ASVS / NIST / GDPR report with citations.

uv run uvicorn app.main:app --port 8000

Scans run in a small background pool; each scan's evidence is stored under NORMIR_DATA (default .data/), so
answering a question the report asks re-evaluates the packs without scanning again.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import shutil
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from . import buildings
from . import regulations as regs
from . import report as report_mod
from .scan import STANDARDS, ScanError, evaluate, parse_repo_url, scan

HERE = Path(__file__).parent
DATA = Path(os.environ.get("NORMIR_DATA", HERE.parent / ".data")).resolve()
SCANS = DATA / "scans"
SCANS.mkdir(parents=True, exist_ok=True)
PROJECTS = DATA / "projects"
PROJECTS.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD = int(os.environ.get("NORMIR_MAX_UPLOAD_MB", "1024")) * 1_000_000
POOL = ThreadPoolExecutor(max_workers=int(os.environ.get("NORMIR_WORKERS", "2")))
LOCK = threading.Lock()
SCAN_ID = re.compile(r"^[a-z0-9]{12}$")

@contextlib.asynccontextmanager
async def lifespan(_app):
    """With NORMIR_SEED=1, build any missing example projects in the background (see app/seed.py)."""
    if os.environ.get("NORMIR_SEED") == "1":
        from .seed import seed_all
        POOL.submit(seed_all)
    yield


app = FastAPI(title="Compliance check", lifespan=lifespan)
templates = Jinja2Templates(directory=HERE / "templates")
templates.env.filters["short"] = lambda s, n=12: (s or "")[:n]


# ---------------------------------------------------------------- storage

def _dir(sid: str) -> Path:
    if not SCAN_ID.match(sid):
        raise HTTPException(404)
    d = SCANS / sid
    if not d.is_dir():
        raise HTTPException(404, "No such scan")
    return d


def _read(d: Path, name: str, default=None):
    p = d / name
    return json.loads(p.read_text()) if p.is_file() else default


def _write(d: Path, name: str, data) -> None:
    tmp = d / f".{name}.tmp"
    tmp.write_text(json.dumps(data, ensure_ascii=False, default=str))
    tmp.replace(d / name)


def _status(d: Path, **kw) -> None:
    with LOCK:
        st = _read(d, "status.json", {})
        st.update(kw, updated=time.time())
        _write(d, "status.json", st)


def _run(sid: str) -> None:
    d = SCANS / sid
    req = _read(d, "request.json")
    work = d / "work"
    work.mkdir(exist_ok=True)
    log = []

    def progress(msg: str) -> None:
        log.append(msg)
        _status(d, state="running", step=msg, log=log[-30:])
    try:
        progress("Queued")
        own = [x[4:] for x in req["standards"] if x.startswith("reg:")]
        data = scan(req["url"], work, req.get("branch") or None, progress=progress, requirements=regs.assessed(own))
        _write(d, "scan.json", data)
        _status(d, state="done", step="Done", seconds=data["seconds"])
    except ScanError as e:
        _status(d, state="error", error=str(e))
    except Exception as e:  # noqa: BLE001 - shown to the user, with the trace kept on disk
        (d / "error.txt").write_text(traceback.format_exc())
        _status(d, state="error", error=f"{type(e).__name__}: {e}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _report(d: Path) -> dict:
    req, data = _read(d, "request.json"), _read(d, "scan.json")
    answers = _read(d, "answers.json", {}) or {}
    ev = evaluate(data["docs"], req["standards"], int(req["asvs_level"]), answers)
    return report_mod.build(data, ev, int(req["asvs_level"]), answers)


# ---------------------------------------------------------------- pages

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    recent = []
    for d in sorted(SCANS.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)[:12]:
        req, st = _read(d, "request.json"), _read(d, "status.json", {})
        if req:
            recent.append({"id": d.name, "url": req["url"], "state": st.get("state", "queued"), "created": req.get("created")})
    from adapters.code_llm import provider_from_env
    p = provider_from_env()
    return templates.TemplateResponse(request, "index.html", {
        "standards": STANDARDS, "recent": recent, "regulations": [r for r in regs.regulations("code") if r["state"] == "done"], "reader": " ".join(x for x in p[:2] if x) if p else None,
        "private": bool(os.environ.get("GITHUB_TOKEN"))})


@app.post("/scans")
def create(url: str = Form(...), branch: str = Form(""), asvs_level: int = Form(2), standards: list[str] = Form([])):
    try:
        parse_repo_url(url)
    except ScanError as e:
        raise HTTPException(400, str(e)) from e
    standards = [s for s in standards if s in STANDARDS or (s.startswith("reg:") and regs.ready(s[4:], "code"))] or ["asvs", "nist", "gdpr"]
    if "gdpr" in standards and "uk-gdpr" in standards:
        standards.remove("gdpr")  # UK GDPR extends the EU pack: one report section, not two
    sid = secrets.token_hex(6)
    d = SCANS / sid
    d.mkdir()
    _write(d, "request.json", {"url": url.strip(), "branch": branch.strip(), "asvs_level": max(1, min(3, asvs_level)),
                               "standards": standards, "created": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())})
    _status(d, state="queued", step="Queued")
    POOL.submit(_run, sid)
    return RedirectResponse(f"/scans/{sid}", status_code=303)


@app.get("/scans/{sid}", response_class=HTMLResponse)
def show(request: Request, sid: str):
    d = _dir(sid)
    st = _read(d, "status.json", {})
    req = _read(d, "request.json")
    if st.get("state") != "done":
        return templates.TemplateResponse(request, "progress.html", {"sid": sid, "req": req, "st": st})
    rep = _report(d)
    return templates.TemplateResponse(request, "report.html", {"sid": sid, "req": req, "r": rep,
                                                               "VERDICT": report_mod.VERDICT_LABEL, "TYPE": report_mod.TYPE_LABEL})


@app.get("/scans/{sid}/status")
def status(sid: str):
    return _read(_dir(sid), "status.json", {})


def _coerce(value: str, kind: str, values):
    if value == "":
        return None
    if kind == "bool":
        return {"true": True, "false": False}.get(value)
    if kind == "number":
        try:
            n = float(value)
        except ValueError:
            return None
        return int(n) if n.is_integer() else n
    if kind == "enum":
        return value if not values or value in values else None
    return value[:300]


@app.post("/scans/{sid}/answers")
async def answer(request: Request, sid: str):
    d = _dir(sid)
    form = await request.form()
    rep = _report(d)
    known = {q["key"]: q for q in rep["questions"]}
    answers = _read(d, "answers.json", {}) or {}
    for key, raw in form.items():
        if key.startswith("clear::"):
            el, _, attr = key[7:].partition("::")
            (answers.get("subject") or {}).pop(attr, None) if el == "_subject" else (answers.get("elements", {}).get(el) or {}).pop(attr, None)
            continue
        q = known.get(key)
        if q is None:
            continue
        v = _coerce(str(raw), q["value_type"], q["values"])
        if v is None:
            continue
        if q["element"] == "_subject":
            answers.setdefault("subject", {})[q["attr"]] = v
        else:
            answers.setdefault("elements", {}).setdefault(q["element"], {})[q["attr"]] = v
    _write(d, "answers.json", answers)
    return RedirectResponse(f"/scans/{sid}#questions", status_code=303)


@app.get("/scans/{sid}/report.md", response_class=PlainTextResponse)
def report_md(sid: str):
    d = _dir(sid)
    if _read(d, "status.json", {}).get("state") != "done":
        raise HTTPException(409, "The scan has not finished")
    rep = _report(d)
    name = f"compliance-{rep['repo']['owner']}-{rep['repo']['name']}.md"
    return PlainTextResponse(report_mod.markdown(rep), headers={"content-disposition": f'attachment; filename="{name}"'})


@app.get("/scans/{sid}/report.json")
def report_json(sid: str):
    d = _dir(sid)
    if _read(d, "status.json", {}).get("state") != "done":
        raise HTTPException(409, "The scan has not finished")
    return JSONResponse(json.loads(json.dumps(_report(d), default=str)))


# ---------------------------------------------------------------- customer regulations

def _reg(rid: str) -> Path:
    try:
        return regs.reg_dir(rid)
    except regs.RegulationNotFound:
        raise HTTPException(404, "No such regulation") from None


@app.get("/regulations", response_class=HTMLResponse)
def regulations_index(request: Request):
    return templates.TemplateResponse(request, "regulations.html", {"regs": regs.regulations(), "suffixes": sorted(regs.SUFFIXES),
                                                                    "max_mb": regs.MAX_FILE // 1_000_000})


@app.post("/regulations")
async def create_regulation(name: str = Form(""), domain: str = Form("code"), files: list[UploadFile] = File(...)):
    got = []
    for f in files:
        if not f.filename:
            continue
        data = await f.read(regs.MAX_FILE + 1)
        got.append((f.filename, data))
    try:
        rid = regs.create(name, domain, got)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    POOL.submit(regs.compile_regulation, rid)
    return RedirectResponse(f"/regulations/{rid}", status_code=303)


@app.get("/regulations/{rid}", response_class=HTMLResponse)
def show_regulation(request: Request, rid: str):
    d = _reg(rid)
    req, st = _read(d, "request.json"), regs.status(d)
    reg = regs.load_reg(rid) if st.get("state") == "done" else None
    clauses = {c["id"]: c for c in (reg or {}).get("clauses") or []}
    by_clause: dict[str, list] = {}
    for k in (reg or {}).get("checks") or []:
        by_clause.setdefault(k["clause"], []).append(k)
    voc = regs.vocab(req["domain"]) if reg else {}
    rules = {k["id"]: regs.rule_text(k, voc) for k in (reg or {}).get("checks") or []}
    return templates.TemplateResponse(request, "regulation.html", {"rid": rid, "req": req, "st": st, "reg": reg, "clauses": clauses,
                                                                   "by_clause": by_clause, "kinds": regs.KINDS, "rules": rules})


@app.get("/regulations/{rid}/status")
def regulation_status(rid: str):
    return regs.status(_reg(rid))


@app.post("/regulations/{rid}/checks")
async def regulation_checks(request: Request, rid: str):
    d = _reg(rid)
    if regs.status(d).get("state") != "done":
        raise HTTPException(409, "The regulation is still being compiled")
    form = await request.form()
    changes: dict[str, dict] = {}
    for key, value in form.multi_items():
        field, _, cid = key.partition("::")
        if field == "seen":
            changes.setdefault(cid, {})["enabled"] = False
        elif field == "kind":
            changes.setdefault(cid, {})["kind"] = str(value)
    for key in form.keys():
        field, _, cid = key.partition("::")
        if field == "enabled":
            changes.setdefault(cid, {})["enabled"] = True
    regs.update_checks(rid, changes)
    return RedirectResponse(f"/regulations/{rid}#checks", status_code=303)


# ---------------------------------------------------------------- building projects

def _pdir(pid: str) -> Path:
    if not SCAN_ID.match(pid):
        raise HTTPException(404)
    d = PROJECTS / pid
    if not d.is_dir():
        raise HTTPException(404, "No such project")
    return d


def run_project(pid: str) -> None:
    """Read every uploaded file with the adapters and store the evidence. Runs in the pool, or inline when seeding."""
    d = PROJECTS / pid
    req = _read(d, "request.json")
    log = []

    def progress(msg: str) -> None:
        log.append(msg)
        _status(d, state="running", step=msg, log=log[-40:])
    try:
        progress("Queued")
        own = [c[4:] for c in req["codes"] if c.startswith("reg:")]
        data = buildings.process(d / "files", req["name"], progress=progress, requirements=regs.assessed(own))
        _write(d, "data.json", data)
        _status(d, state="done", step="Done", seconds=data["seconds"])
    except buildings.ProjectError as e:
        _status(d, state="error", error=str(e))
    except Exception as e:  # noqa: BLE001 - shown to the user, with the trace kept on disk
        (d / "error.txt").write_text(traceback.format_exc())
        _status(d, state="error", error=f"{type(e).__name__}: {e}")


def new_project(name: str, codes: list[str], seed: str | None = None) -> tuple[str, Path]:
    pid = secrets.token_hex(6)
    d = PROJECTS / pid
    (d / "files").mkdir(parents=True)
    codes = [c for c in codes if c in buildings.CODES or (c.startswith("reg:") and regs.ready(c[4:], "building"))] or ["ibc"]
    _write(d, "request.json", {"name": name.strip()[:120] or "Untitled project", "codes": codes, "seed": seed,
                               "created": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())})
    _status(d, state="queued", step="Queued")
    return pid, d


def _project_report(pid: str, d: Path) -> dict:
    req, data = _read(d, "request.json"), _read(d, "data.json")
    answers = _read(d, "answers.json", {}) or {}
    ev = buildings.evaluate(data["docs"], req["codes"], answers)
    return buildings.build(pid, {"id": pid, **req}, data, ev, answers)


def _projects(seeded: bool | None = None, limit: int = 30) -> list[dict]:
    out = []
    for d in sorted(PROJECTS.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        req, st = _read(d, "request.json"), _read(d, "status.json", {})
        if req and (seeded is None or bool(req.get("seed")) == seeded):
            out.append({"id": d.name, **req, "state": st.get("state", "queued"), "step": st.get("step")})
    return out[:limit]


@app.get("/buildings", response_class=HTMLResponse)
def buildings_index(request: Request):
    return templates.TemplateResponse(request, "buildings_index.html", {
        "codes": buildings.CODES, "examples": _projects(seeded=True), "recent": _projects(seeded=False),
        "regulations": [r for r in regs.regulations("building") if r["state"] == "done" and regs.ready(r["id"], "building")],
        "max_mb": MAX_UPLOAD // 1_000_000})


@app.post("/projects")
async def create_project(name: str = Form(""), codes: list[str] = Form([]), files: list[UploadFile] = File(...)):
    pid, d = new_project(name or (files[0].filename if files else ""), codes)
    total = 0
    try:
        for f in files:
            if not f.filename:
                continue
            rel = buildings.safe_name(f.filename)
            if Path(rel).suffix.lower() not in buildings.ACCEPTED:
                raise HTTPException(400, f"{f.filename}: upload IFC, DXF, PDF, PNG, JPEG or TIFF files, or a .zip of them.")
            dest = d / "files" / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "wb") as out:
                while chunk := await f.read(1 << 20):
                    total += len(chunk)
                    if total > MAX_UPLOAD:
                        raise HTTPException(413, f"The upload is larger than {MAX_UPLOAD // 1_000_000} MB.")
                    out.write(chunk)
    except (HTTPException, buildings.ProjectError) as e:
        shutil.rmtree(d, ignore_errors=True)
        raise e if isinstance(e, HTTPException) else HTTPException(400, str(e)) from e
    if total == 0:
        shutil.rmtree(d, ignore_errors=True)
        raise HTTPException(400, "No files were uploaded.")
    POOL.submit(run_project, pid)
    return RedirectResponse(f"/projects/{pid}", status_code=303)


@app.get("/projects/{pid}", response_class=HTMLResponse)
def show_project(request: Request, pid: str):
    d = _pdir(pid)
    st, req = _read(d, "status.json", {}), _read(d, "request.json")
    if st.get("state") != "done":
        codes = {**buildings.CODES, **{c: (None, (regs.ready(c[4:], "building") or {}).get("name", c), "your regulation")
                                         for c in req["codes"] if c.startswith("reg:")}}
        return templates.TemplateResponse(request, "project_progress.html", {"pid": pid, "req": req, "st": st, "codes": codes})
    return templates.TemplateResponse(request, "project_report.html", {
        "pid": pid, "req": req, "r": _project_report(pid, d), "VERDICT": report_mod.VERDICT_LABEL, "TYPE": buildings.TYPE_LABEL})


@app.get("/projects/{pid}/status")
def project_status(pid: str):
    return _read(_pdir(pid), "status.json", {})


@app.post("/projects/{pid}/answers")
async def project_answer(request: Request, pid: str):
    d = _pdir(pid)
    form = await request.form()
    known = {q["key"]: q for q in _project_report(pid, d)["questions"]}
    answers = _read(d, "answers.json", {}) or {}

    def bucket(element: str) -> dict:
        if element == "_subject":
            return answers.setdefault("subject", {})
        if element[:1].isupper() and ":" not in element:  # a type name: the answer covers every element of the type
            return answers.setdefault("types", {}).setdefault(element, {})
        return answers.setdefault("elements", {}).setdefault(element, {})
    for key, raw in form.items():
        if key.startswith("clear::"):
            el, _, attr = key[7:].partition("::")
            bucket(el).pop(attr, None)
            continue
        q = known.get(key)
        if q is None:
            continue
        v = _coerce(str(raw).strip(), q["value_type"], q["values"])
        if v is not None:
            bucket(q["element"])[q["attr"]] = v
    _write(d, "answers.json", answers)
    return RedirectResponse(f"/projects/{pid}#questions", status_code=303)


@app.get("/projects/{pid}/crop")
def project_crop(pid: str, at: str):
    d = _pdir(pid)
    try:
        png = buildings.crop(d / "files", d / "crops", at)
    except buildings.ProjectError as e:
        raise HTTPException(404, str(e)) from e
    return Response(png, media_type="image/png", headers={"cache-control": "private, max-age=86400"})


@app.get("/projects/{pid}/thumb")
def project_thumb(pid: str, file: str, page: int | None = None, layout: str | None = None):
    d = _pdir(pid)
    try:
        png = buildings.thumbnail(d / "files", d / "crops", file, page, layout)
    except buildings.ProjectError as e:
        raise HTTPException(404, str(e)) from e
    return Response(png, media_type="image/png", headers={"cache-control": "private, max-age=86400"})


@app.get("/projects/{pid}/report.md", response_class=PlainTextResponse)
def project_md(request: Request, pid: str):
    d = _pdir(pid)
    if _read(d, "status.json", {}).get("state") != "done":
        raise HTTPException(409, "The project has not finished processing")
    rep = _project_report(pid, d)
    name = re.sub(r"[^\w.-]+", "-", rep["project"]["name"]).strip("-") or pid
    return PlainTextResponse(buildings.markdown(rep, str(request.base_url).rstrip("/")),
                             headers={"content-disposition": f'attachment; filename="building-report-{name}.md"'})


@app.get("/projects/{pid}/report.json")
def project_json(pid: str):
    d = _pdir(pid)
    if _read(d, "status.json", {}).get("state") != "done":
        raise HTTPException(409, "The project has not finished processing")
    return JSONResponse(json.loads(json.dumps(_project_report(pid, d), default=str)))


@app.get("/healthz")
def healthz():
    return {"ok": True}
