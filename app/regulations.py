"""Customer regulations: documents a customer uploads, compiled into rule packs the engine evaluates.

    upload (PDF, Word, HTML, Markdown, text)
      -> adapters.regulation.read          lines, with page numbers
      -> adapters.regulation.clauses       the model splits the text into clauses; the clause text is the document's own
      -> adapters.regulation.compile_checks
           computed   a rule over the facts the readers extract (validated; demoted to assessed when it doesn't validate)
           assessed   the model judges it from the artifact at check time, citing what it read (adapters.assess)
           attested   the artifact can't show it: a question for the user
      -> adapters.regulation.build_pack    packs live in .data/regulations/<id>/pack and run like any other pack

The customer reviews the checks on the regulation's page and can switch each one off or change its kind; the pack is
rebuilt on every change. Stored under NORMIR_DATA/regulations/<id>/: files/, request.json, status.json,
regulation.json (clauses and checks), pack/.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import threading
import time
import traceback
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(os.environ.get("NORMIR_DATA", ROOT / ".data")).resolve()
REGS = DATA / "regulations"
REGS.mkdir(parents=True, exist_ok=True)
VOCABS = {"code": ROOT / "vocab" / "code.yaml", "building": ROOT / "vocab" / "bim.yaml"}
SUFFIXES = {".pdf", ".docx", ".html", ".htm", ".md", ".markdown", ".txt"}
MAX_FILE = int(os.environ.get("NORMIR_MAX_REGULATION_MB", "40")) * 1_000_000
REG_ID = re.compile(r"^r[a-z0-9]{10}$")
KINDS = ("computed", "assessed", "attested")
LOCK = threading.Lock()


class RegulationNotFound(LookupError):
    pass


def vocab(domain: str) -> dict:
    return yaml.safe_load(VOCABS[domain].read_text())


def reg_dir(rid: str) -> Path:
    if not REG_ID.match(rid or ""):
        raise RegulationNotFound(rid)
    d = REGS / rid
    if not d.is_dir():
        raise RegulationNotFound(rid)
    return d


def _read(d: Path, name: str, default=None):
    p = d / name
    return json.loads(p.read_text()) if p.is_file() else default


def _write(d: Path, name: str, data) -> None:
    tmp = d / f".{name}.tmp"
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1, default=str))
    tmp.replace(d / name)


def status(d: Path, **kw) -> dict:
    with LOCK:
        st = _read(d, "status.json", {})
        if kw:
            st.update(kw, updated=time.time())
            _write(d, "status.json", st)
        return st


def safe_name(name: str) -> str:
    base = Path(name.replace("\\", "/")).name
    base = re.sub(r"[^\w.\- ()]+", "_", base).strip(" .") or "document"
    return base[:120]


def create(name: str, domain: str, files: list[tuple[str, bytes]]) -> str:
    """Store the uploaded documents and return the new regulation's id. Raises ValueError for bad input."""
    if domain not in VOCABS:
        raise ValueError(f"unknown domain {domain!r}")
    if not files:
        raise ValueError("Upload at least one document.")
    for fname, data in files:
        if Path(fname).suffix.lower() not in SUFFIXES:
            raise ValueError(f"{fname}: only PDF, Word (.docx), HTML, Markdown and text files are read.")
        if len(data) > MAX_FILE:
            raise ValueError(f"{fname}: larger than {MAX_FILE // 1_000_000} MB.")
        if not data:
            raise ValueError(f"{fname}: the file is empty.")
    rid = "r" + secrets.token_hex(5)
    d = REGS / rid
    (d / "files").mkdir(parents=True)
    names = []
    for fname, data in files:
        n = safe_name(fname)
        while n in names:
            n = f"{Path(n).stem}-{len(names)}{Path(n).suffix}"
        (d / "files" / n).write_bytes(data)
        names.append(n)
    title = name.strip()[:160] or Path(names[0]).stem
    _write(d, "request.json", {"id": rid, "name": title, "domain": domain, "files": names,
                               "created": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())})
    status(d, state="queued", step="Queued", log=["Queued"])
    return rid


def compile_regulation(rid: str) -> None:
    """Read, split, compile and build the pack. Runs in the app's worker pool."""
    from adapters import regulation as R

    d = reg_dir(rid)
    req = _read(d, "request.json")
    log: list[str] = []

    def progress(msg: str) -> None:
        log.append(msg)
        status(d, state="running", step=msg, log=log[-40:])
    try:
        t0 = time.time()
        progress("Reading the documents")
        docs = [R.read(d / "files" / f, f) for f in req["files"]]
        progress(f"Splitting {sum(len(x.lines) for x in docs)} lines into clauses")
        cl = R.clauses(docs, progress=progress)
        if not any(c["requirement"] for c in cl):
            raise R.RegulationError("No requirements were found in the documents.")
        progress(f"Turning {sum(c['requirement'] for c in cl)} requirements into checks")
        checks, stats = R.compile_checks(cl, vocab(req["domain"]), progress=progress)
        reg = {"id": rid, "name": req["name"], "domain": req["domain"], "files": [
                   {"file": x.file, "sha256": x.sha256, "kind": x.kind, "pages": x.pages, "lines": len(x.lines)} for x in docs],
               "clauses": cl, "checks": checks, "stats": stats, "seconds": round(time.time() - t0, 1)}
        _write(d, "regulation.json", reg)
        rebuild(rid, reg)
        status(d, state="done", step="Done", seconds=reg["seconds"])
    except Exception as e:  # noqa: BLE001 - shown to the user; the trace is kept on disk
        (d / "error.txt").write_text(traceback.format_exc())
        msg = str(e) if type(e).__name__ in ("RegulationError", "ReaderError") else f"{type(e).__name__}: {e}"
        status(d, state="error", error=msg)


def load_reg(rid: str) -> dict | None:
    return _read(reg_dir(rid), "regulation.json")


def rebuild(rid: str, reg: dict | None = None) -> Path:
    from adapters.regulation import build_pack

    d = reg_dir(rid)
    reg = reg or load_reg(rid)
    out = d / "pack"
    tmp = d / ".pack.tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir()
    build_pack(reg, vocab(reg["domain"]), tmp)
    shutil.rmtree(out, ignore_errors=True)
    tmp.replace(out)
    return out


def update_checks(rid: str, changes: dict[str, dict]) -> dict:
    """Apply {check id: {"enabled": bool, "kind": kind}} from the review page and rebuild the pack.
    A check becomes computed only if it has a rule; an assessed check needs search terms, an attested one a question."""
    with LOCK:
        reg = load_reg(rid)
        by_id = {k["id"]: k for k in reg["checks"]}
        for cid, ch in changes.items():
            k = by_id.get(cid)
            if k is None:
                continue
            if "enabled" in ch:
                k["enabled"] = bool(ch["enabled"])
            kind = ch.get("kind")
            if kind in KINDS and kind != k["kind"]:
                if kind == "computed" and not k.get("require"):
                    continue
                if kind == "assessed" and not k.get("search"):
                    k["search"] = [w for w in re.findall(r"[A-Za-z_]{4,}", k["summary"])][:8]
                if kind == "attested" and not k.get("question"):
                    k["question"] = f"Is this met: {k['summary'].rstrip('.')}?"
                k["kind"] = kind
                k["edited"] = True
        _write(reg_dir(rid), "regulation.json", reg)
    rebuild(rid, reg)
    return reg


def regulations(domain: str | None = None) -> list[dict]:
    out = []
    for d in sorted(REGS.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        req = _read(d, "request.json")
        if not req or (domain and req["domain"] != domain):
            continue
        st = _read(d, "status.json", {})
        reg = _read(d, "regulation.json") or {}
        checks = reg.get("checks") or []
        out.append({**req, "state": st.get("state"), "error": st.get("error"), "clauses": len(reg.get("clauses") or []),
                    "checks": sum(1 for k in checks if k.get("enabled")),
                    "kinds": {k: sum(1 for c in checks if c.get("enabled") and c["kind"] == k) for k in KINDS}})
    return out


def ready(rid: str, domain: str) -> dict | None:
    """The regulation's request if it can be checked against (compiled, this domain), else None."""
    try:
        d = reg_dir(rid)
    except RegulationNotFound:
        return None
    req = _read(d, "request.json")
    if req and req["domain"] == domain and (d / "pack" / "package.yaml").is_file():
        return req
    return None


def rule_text(check: dict, voc: dict) -> str | None:
    """A computed check's rule in words, with each fact named by its vocabulary label."""
    from types import SimpleNamespace

    from normir.evaluate import describe

    if "require" not in check:
        return None
    types = voc.get("types") or {}
    var, typ = (check.get("for") or {}).get("var"), (check.get("for") or {}).get("type")
    labels = {f"system.{a}": s.get("label", a) for a, s in ((types.get("system") or {}).get("attrs") or {}).items()}
    if var:
        labels.update({f"{var}.{a}": s.get("label", a) for a, s in ((types.get(typ) or {}).get("attrs") or {}).items()})
    req = check["require"]
    if req in (False, {"value": False}) and typ:
        return f"No {typ} may exist."
    shim = SimpleNamespace(has=lambda kind, key: key in labels, get=lambda kind, key: SimpleNamespace(data={"label": labels[key]}))
    text = describe(req, shim)
    return f"For every {typ}: {text}" if typ else text


def pack_dir(rid: str) -> Path:
    return reg_dir(rid) / "pack"


def assessed(rids: list[str]) -> list[dict]:
    """The enabled assessed checks of these regulations, as adapters.assess requirements."""
    if not rids:
        return []
    from adapters.regulation import fact_attr

    out = []
    for rid in rids:
        reg = load_reg(rid) or {}
        clauses = {c["id"]: c for c in reg.get("clauses") or []}
        for k in reg.get("checks") or []:
            if k.get("enabled") and k["kind"] == "assessed":
                out.append({"attr": fact_attr(rid, k["id"]), "summary": k["summary"],
                            "clause": clauses.get(k["clause"], {}).get("text", "")[:3000], "search": k.get("search") or []})
    return out
