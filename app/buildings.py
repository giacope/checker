"""Building projects: uploaded models and drawings in, a code report with sheet-level citations out.

    upload (IFC, DXF, PDF, images, or a .zip of them)
      -> adapters.ifc       (IFC model: elements, quantities, travel distances from geometry)
      -> adapters.dxf       (CAD drawings: room polygons, door blocks, dimensions, text)
      -> adapters.drawings  (PDF and image sheets: text layer or OCR, then annotations)
      -> evidence in vocab/bim.yaml terms, one document per source
      -> the jurisdiction packs, with the project profile the user answers in the report

Sources are not ranked: where the model and the drawings give different values for a fact a verdict
turns on, the verdict is "uncertain" and names both, which is what a plan reviewer wants to see.
"""

from __future__ import annotations

import hashlib
import importlib
import re
import shutil
import stat
import time
import zipfile
from collections import Counter
from pathlib import Path
from urllib.parse import quote

from normir import Quantity, load
from normir.evidence import conflicts, load_evidence, run

from . import report as report_mod

ROOT = Path(__file__).resolve().parents[1]

# id -> (pack directory, label, what it covers)
CODES = {
    "ibc": ("ibc-2024", "IBC 2024 (US model code)", "Chapter 10 means of egress"),
    "austin": ("austin-2024", "Austin, TX: IBC 2024 as amended (Ord. 20250410-045)", "Chapter 10 means of egress"),
    "ada": ("ada-2010", "2010 ADA Standards for Accessible Design", "doors, routes, ramps, stairs, toilets"),
    "uk-adb": ("uk-adb-v2", "England: Approved Document B, Volume 2", "means of escape (requirement B1)"),
    "jp-bsa": ("jp-bsa-egress", "Japan: 建築基準法施行令 避難規定", "階段・廊下・直通階段・歩行距離"),
}

DRAWING_EXT = {".pdf", ".png", ".jpg", ".jpeg", ".tif", ".tiff"}
ACCEPTED = DRAWING_EXT | {".ifc", ".dxf", ".zip"}
MAX_UNZIPPED = 2_000_000_000
MAX_ZIP_ENTRIES = 5000

TYPE_LABEL = {"Stair": "stair", "Door": "door", "Space": "space", "Storey": "storey", "Corridor": "corridor", "Ramp": "ramp",
              "Exit": "exit", "EscapeRoute": "escape route", "Room": "room", "Floor": "floor", "Route": "accessible route",
              "TurningSpace": "turning space", "Handrail": "handrail", "WaterCloset": "water closet"}

# Words a code-analysis note uses for an IBC occupancy group.
STATED_GROUP = [(r"\bBUSINESS\b", "B"), (r"\bMERCANTILE\b", "M"), (r"\bEDUCATIONAL\b", "E"), (r"\bFACTORY\b", "F-1"),
                (r"\bSTORAGE\b", "S-1"), (r"\bUTILITY\b", "U"), (r"\bGROUP\s+([A-Z](?:-\d)?)\b", None),
                (r"\bOCCUPANCY\s*(?:GROUP|CLASSIFICATION)?\s*[:=]?\s*([A-Z](?:-\d)?)\b", None)]


class ProjectError(Exception):
    pass


# ---------------------------------------------------------------- files

def safe_name(name: str) -> str:
    """A file name from an upload, reduced to a safe relative path (no directories above, no odd characters)."""
    parts = [re.sub(r"[^\w.\- ()&#+,]", "_", p).strip(" .") for p in Path(name.replace("\\", "/")).parts if p not in ("", ".", "..", "/")]
    parts = [p for p in parts if p]
    if not parts:
        raise ProjectError(f"Unusable file name: {name!r}")
    return "/".join(parts)


def expand_zips(files_dir: Path) -> list[str]:
    """Unpack every .zip in place (drawing sets usually arrive zipped). Refuses path traversal, links and zip bombs."""
    notes = []
    for z in sorted(files_dir.rglob("*.zip")):
        try:
            with zipfile.ZipFile(z) as zf:
                infos = [i for i in zf.infolist() if not i.is_dir()]
                if len(infos) > MAX_ZIP_ENTRIES or sum(i.file_size for i in infos) > MAX_UNZIPPED:
                    raise ProjectError(f"{z.name} is too large to unpack ({len(infos)} files).")
                dest = z.with_suffix("")
                for i in infos:
                    if stat.S_ISLNK(i.external_attr >> 16):
                        continue
                    rel = safe_name(i.filename)
                    if Path(rel).suffix.lower() not in ACCEPTED - {".zip"} or "__MACOSX" in rel:
                        continue
                    out = (dest / rel).resolve()
                    if files_dir.resolve() not in out.parents:
                        continue
                    out.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(i) as src, open(out, "wb") as dst:
                        shutil.copyfileobj(src, dst, 1 << 20)
            z.unlink()
        except zipfile.BadZipFile:
            notes.append(f"{z.name} is not a readable zip file; skipped.")
            z.unlink()
    return notes


def inventory(files_dir: Path) -> dict[str, list[Path]]:
    kinds: dict[str, list[Path]] = {"ifc": [], "dxf": [], "drawings": [], "other": []}
    for p in sorted(files_dir.rglob("*")):
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        kinds["ifc" if ext == ".ifc" else "dxf" if ext == ".dxf" else "drawings" if ext in DRAWING_EXT else "other"].append(p)
    return kinds


def _adapter(name: str):
    try:
        return importlib.import_module(name)
    except ImportError:
        return None


# ---------------------------------------------------------------- processing

def process(files_dir: Path, name: str, progress=lambda m: None) -> dict:
    """Run every adapter that applies and return {docs, sheets, notes, files, seconds}."""
    started = time.time()
    notes = expand_zips(files_dir)
    kinds = inventory(files_dir)
    rel = lambda p: str(p.relative_to(files_dir))  # noqa: E731
    files = [{"file": rel(p), "kind": k, "bytes": p.stat().st_size} for k, ps in kinds.items() for p in ps]
    if not any(kinds[k] for k in ("ifc", "dxf", "drawings")):
        raise ProjectError("No IFC model, DXF drawing, PDF or image sheet was found in the upload.")
    for p in kinds["other"]:
        notes.append(f"{rel(p)}: not a format this checker reads (IFC, DXF, PDF, PNG, JPEG, TIFF); skipped.")
    docs, sheets = [], []

    ifc = _adapter("adapters.ifc")
    for p in kinds["ifc"]:
        progress(f"Reading IFC model {rel(p)}")
        try:
            doc = ifc.analyse(p, describes=name, progress=progress)
            for s in doc.get("sources", []):
                s.setdefault("file", rel(p))
            docs.append(doc)
        except Exception as e:  # noqa: BLE001 - one bad file must not lose the others
            notes.append(f"IFC model {rel(p)} could not be read: {type(e).__name__}: {e}")

    for kind, module, label in (("dxf", "adapters.dxf", "DXF drawings"), ("drawings", "adapters.drawings", "PDF and image sheets")):
        if not kinds[kind]:
            continue
        mod = _adapter(module)
        if mod is None or not hasattr(mod, "analyse"):
            notes.append(f"{label}: no reader is installed; {len(kinds[kind])} file(s) were not read.")
            continue
        progress(f"Reading {label} ({len(kinds[kind])} file{'s' if len(kinds[kind]) != 1 else ''})")
        try:
            doc = mod.analyse(kinds[kind], files_dir, describes=name, progress=progress)
            sheets += [{**s, "reader": kind} for s in doc.pop("sheets", [])]
            docs.append(doc)
        except Exception as e:  # noqa: BLE001
            notes.append(f"{label} could not be read: {type(e).__name__}: {e}")
    if not docs:
        raise ProjectError("None of the uploaded files could be read. " + " ".join(notes))
    return {"docs": docs, "sheets": sheets, "notes": notes, "files": files, "seconds": round(time.time() - started, 1)}


# ---------------------------------------------------------------- evaluation

def profile_of(answers: dict) -> dict:
    """{"subject": {attr: v}, "types": {Type: {attr: v}}, "elements": {id: {attr: v}}} -> an evidence.run profile."""
    return {**(answers.get("subject") or {}), **(answers.get("types") or {}), "elements": answers.get("elements") or {}}


def evaluate(docs: list[dict], codes: list[str], answers: dict | None = None) -> dict:
    ev = load_evidence(*docs)
    profile = profile_of(answers or {})
    out = {}
    for cid in codes:
        pack, label, _ = CODES[cid]
        rs = load(ROOT / "packs" / pack)
        out[cid] = {"pack": pack, "label": label, "rs": rs, "norms": None, "rows": run(rs, ev, dict(profile))}
    return {"evidence": ev, "results": out}


def disagree(values: list[dict]) -> bool:
    """Whether sources really disagree: a model's 915 mm and a drawing's printed-precision 914.5 to 915.5 mm
    agree. Lengths and areas disagree when the sources' ranges are apart by more than 1 mm or 0.2 %. Text
    (a room name abbreviated on a schedule) is not a disagreement no verdict reads; counts and flags are."""
    by_source: dict[str, list[float]] = {}
    for v in values:
        q = Quantity.parse(str(v["value"]))
        if q is None:
            return all(re.fullmatch(r"-?\d+(\.\d+)?|True|False", str(x["value"])) for x in values)
        for s in v["sources"]:
            by_source.setdefault(s, []).append(q.base)
    if len(by_source) < 2:
        return False
    lo = max(min(vs) for vs in by_source.values())
    hi = min(max(vs) for vs in by_source.values())
    return lo - hi > max(1 / 25.4, 0.002 * abs(lo))


def _value(f) -> str | None:
    vs = f.values() if f is not None else []
    return " / ".join(str(v) for v in vs) if vs else None


def skipped_summary(docs: list[dict]) -> list[dict]:
    """What the readers saw but did not use, grouped by reason, with examples: the honest limits of a run."""
    groups: dict[str, list[str]] = {}
    for d in docs:
        for src in d.get("sources", []):
            for n in src.get("skipped") or []:
                reason = n.get("reason", "") if isinstance(n, dict) else str(n).split(":", 1)[-1].strip()
                text = _note(n) if not isinstance(n, dict) else f"{n.get('text', '')}"
                file = ""
                if isinstance(n, dict):
                    from adapters.drawings.tokens import parse_locator
                    file = (parse_locator(n.get("at", "")) or {}).get("file", "")
                groups.setdefault(f"{src.get('id')}: {reason}", []).append(f"{text} ({file})" if file else text)
    return sorted(({"reason": k, "count": len(v), "examples": v[:4]} for k, v in groups.items()), key=lambda g: -g["count"])


def suggestions(ev) -> dict[str, str]:
    """Answers the drawings themselves suggest (a code-analysis note), keyed by attribute. A reviewer confirms them."""
    out = {}
    stated = _value(ev.facts.get("stated_occupancy_classification"))
    if stated:
        for pat, group in STATED_GROUP:
            m = re.search(pat, stated.upper())
            if m:
                out["occupancy_group"] = group or m.group(1)
                break
    return out


# ---------------------------------------------------------------- report

def locate(pid: str, sheets: dict, at: str) -> dict:
    from adapters.drawings.tokens import parse_locator
    loc = parse_locator(at)
    if loc:
        s = sheets.get((loc["file"], loc["page"] or loc["layout"]))
        where = f"p{loc['page']}" if loc["page"] else loc["layout"]
        label = f"{s['number']} · {loc['file']} {where}" if s and s.get("number") else f"{loc['file']} {where}"
        return {"at": at, "label": label, "img": f"/projects/{pid}/crop?at={quote(at, safe='')}", "kind": "sheet"}
    if str(at).startswith("ifc:"):
        return {"at": at, "label": "IFC " + str(at)[4:], "kind": "ifc"}
    return {"at": at, "label": str(at), "kind": "text"}


def _focus(f: dict, el, loc) -> None:
    """Point a finding at the values its verdict turns on: the crop shows the deciding dimension, not the
    stair's name tag; one citation per sheet region; and a range from one source's printed precision is
    told apart from two sources disagreeing."""
    first = []
    if el is not None:
        for fact in list(f["deciding"]) + f["open"]:
            attr = fact.rpartition(".")[2]
            for k, x in el.facts.items():
                if k == attr or fact.endswith("." + k):
                    first += [o["at"] for o in x.observations if o.get("at")]
    seen, ats = set(), []
    for a in [loc(x) for x in first] + f["at"]:
        if a["label"] not in seen and a["at"] not in {x["at"] for x in ats}:
            seen.add(a["label"])
            ats.append(a)
    f["at"] = ats[:3]
    for k, vs in f["deciding"].items():
        kinds = {src.split(" @ ")[0] for d in vs for src in d["sources"]}
        for d in vs:
            d["sources"] = sorted({src.split(" @ ")[0] for src in d["sources"]})
        f.setdefault("precision_only", {})[k] = len(kinds) == 1


def _note(n) -> str:
    """A skipped-reading record as one sentence."""
    if isinstance(n, dict):
        from adapters.drawings.tokens import parse_locator
        loc = parse_locator(n.get("at", "")) or {}
        where = f" ({loc['file']})" if loc.get("file") else ""
        return f"{n.get('reason', '')}: {n.get('text', '')}{where}".strip(": ")
    return str(n)


def build(pid: str, project: dict, data: dict, evaluation: dict, answers: dict | None = None) -> dict:
    answers = answers or {}
    ev = evaluation["evidence"]
    sheets = {(s["file"], s.get("page") or s.get("layout")): s for s in data.get("sheets", [])}
    loc = lambda a: locate(pid, sheets, a)  # noqa: E731
    standards, questions = report_mod.sections(evaluation, loc, by_type=True)
    by_id = {e.id: e for e in ev.elements}
    for s in standards:
        s["covers"] = CODES[s["id"]][2]
        for e in s["entries"]:
            for f in e["findings"]:
                _focus(f, by_id.get(f["element"]), loc)
    given = {("_subject", k): v for k, v in (answers.get("subject") or {}).items()}
    given |= {(t, k): v for t, fs in (answers.get("types") or {}).items() for k, v in fs.items()}
    given |= {(e, k): v for e, fs in (answers.get("elements") or {}).items() for k, v in fs.items()}
    suggest = suggestions(ev)
    for q in questions.values():
        q["answer"] = given.get((q["element"], q["attr"]))
        q["suggested"] = suggest.get(q["attr"]) if q["element"] == "_subject" else None
        if q["suggested"] and q.get("values") and q["suggested"] not in q["values"]:
            q["suggested"] = None
    labels = {}
    for res in evaluation["results"].values():
        for (kind, name), el in res["rs"].elements.items():
            if kind == "predicate":
                labels.setdefault(str(el.data.get("vocab") or name).rpartition(".")[2], el.data.get("label"))
    answered = [{"element": e, "attr": a, "value": v, "label": labels.get(a) or a} for (e, a), v in given.items()]
    by_type = Counter(e.type for e in ev.elements)
    facts = [{"name": k, "value": _value(f), "at": [loc(o["at"]) for o in f.observations if o.get("at")][:2],
              "sources": sorted({o.get("source", "") for o in f.observations})} for k, f in sorted(ev.facts.items())]
    elements = []
    for e in sorted(ev.elements, key=lambda e: (e.type, e.id)):
        elements.append({"id": e.id, "type": e.type, "sources": sorted(e.sources),
                         "facts": {k: _value(f) for k, f in e.facts.items()}, "at": [loc(a) for a in e.at[:2]]})
    confl = []
    for c in conflicts(ev):
        if not disagree(c["values"]):
            continue
        el = next((x for x in ev.elements if x.id == c["element"]), None)
        obs = el.facts[c["fact"]].observations if el is not None and c["fact"] in el.facts else []
        seen = {}
        for o in obs:
            if o.get("at"):
                a = loc(o["at"])
                seen.setdefault(a["label"], a)
        values = {}
        for v in c["values"]:  # one row per source: "915 mm (ifc)", "914.5 mm to 915.5 mm (drawings)"
            for src in v["sources"]:
                values.setdefault(src.split(" @ ")[0], []).append(v["value"])
        same_unit = lambda vs: len({str(v).split()[-1] for v in vs}) == 1  # noqa: E731
        confl.append({**c, "by_source": {k: vs[0] if len(vs) == 1 else f"{vs[0]} to {vs[-1]}" if same_unit(vs) and len(vs) == 2 else " / ".join(vs)
                                         for k, vs in values.items()},
                      "at": list(seen.values())[:4]})
    return {
        "project": project, "files": data.get("files", []), "sheets": data.get("sheets", []), "notes": data.get("notes", []),
        "skipped": skipped_summary(data["docs"]),
        "checks": dict(Counter(r["verdict"] for res in evaluation["results"].values() for r in res["rows"])),
        "seconds": data.get("seconds"),
        "sources": [s for d in data["docs"] for s in d.get("sources", [])],
        "standards": standards,
        "questions": sorted((q for q in questions.values() if q["answer"] is None),
                            key=lambda q: (q["scope"] != "subject", -len(q["decides"]), q["attr"])),
        "answered": answered, "facts": facts, "elements": elements, "element_counts": dict(by_type.most_common()),
        "conflicts": confl[:200],
        "totals": dict(Counter(e["verdict"] for s in standards for e in s["entries"])),
    }


def markdown(rep: dict, base_url: str = "") -> str:
    p = rep["project"]
    out = [f"# Building code report: {p['name']}", "",
           f"Codes: {', '.join(s['label'] for s in rep['standards'])}",
           f"Files: {', '.join(f['file'] for f in rep['files'])}", ""]
    out += ["## Summary", "", "| Code | Fails | Uncertain | Needs input | Passes | Not applicable |", "|---|---|---|---|---|---|"]
    for s in rep["standards"]:
        c = s["summary"]
        out.append(f"| {s['label']} | {c.get('fail', 0)} | {c.get('uncertain', 0)} | {c.get('unknown', 0)} | {c.get('pass', 0)} | {c.get('not_applicable', 0)} |")
    out.append("")
    for s in rep["standards"]:
        out += [f"## {s['label']}", ""]
        for e in s["entries"]:
            if e["verdict"] == "not_applicable":
                continue
            head = f"### {report_mod.VERDICT_LABEL[e['verdict']]}: {e['section']} {e['title']}"
            out += [head, "", f"Requirement: [{e['section']}]({e['url']})" if e.get("url") else f"Requirement: {e['section']}", ""]
            for f in e["findings"][:40]:
                where = "; ".join(f"[{a['label']}]({base_url}{a['img']})" if a.get("img") else a["label"] for a in f["at"]) or "the building as a whole"
                facts = ", ".join(f"{k} {'/'.join(v)}" for k, v in f["facts"].items())
                line = f"- **{report_mod.VERDICT_LABEL[f['verdict']]}** {TYPE_LABEL.get(f['type'] or '', f['type'] or 'building')} `{f['element']}` at {where}"
                if facts:
                    line += f" ({facts})"
                for k, vs in f["deciding"].items():
                    if (f.get("precision_only") or {}).get(k):
                        line += f". {k} as printed allows {' to '.join(d['value'] for d in vs)}; the limit falls inside that range"
                    else:
                        line += f". Sources disagree on {k}: " + " vs ".join(f"{d['value']} ({', '.join(d['sources'])})" for d in vs)
                if f["open"]:
                    line += ". Open: " + ", ".join(f["open"])
                out.append(line)
            if e["verdict"] == "pass":
                out.append(f"Checked {e['checked']} {'place' if e['checked'] == 1 else 'places'}; all pass.")
            if e.get("guidance") and e["verdict"] != "pass":
                out += ["", f"What to do: {e['guidance']}"]
            out.append("")
    if rep["questions"]:
        out += ["## Open questions", ""]
        for q in rep["questions"]:
            scope = "the building" if q["scope"] == "subject" else f"every {TYPE_LABEL.get(q['type'], q['type'])}"
            out.append(f"- {q['label']} ({scope}); decides {', '.join(q['decides'])}")
        out.append("")
    if rep["answered"]:
        out += ["## Profile answers given by the reviewer", ""] + [f"- {a['label']}: {a['value']} ({a['element']})" for a in rep["answered"]] + [""]
    out += ["## Sources", ""] + [f"- {s.get('id')}: {s.get('adapter') or s.get('kind')} {s.get('file') or ''}" for s in rep["sources"]]
    out += ["", "Automated assessment from draft rule packs. Not a plan review, approval, or certification."]
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- crops

def crop(files_dir: Path, cache: Path, at: str) -> bytes:
    """PNG of the sheet region a locator names, with the region outlined. Cached per locator."""
    from adapters.drawings.tokens import parse_locator
    loc = parse_locator(at)
    if not loc:
        raise ProjectError("Not a sheet locator")
    path = (files_dir / loc["file"]).resolve()
    if files_dir.resolve() not in path.parents or not path.is_file():
        raise ProjectError("No such file in this project")
    cache.mkdir(parents=True, exist_ok=True)
    out = cache / (hashlib.sha1(at.encode()).hexdigest() + ".png")
    if out.is_file():
        return out.read_bytes()
    if loc["layout"]:
        png = importlib.import_module("adapters.dxf").render(path, loc["layout"], bbox=loc["bbox"])
    else:
        png = importlib.import_module("adapters.drawings").render(path, loc["page"], bbox=loc["bbox"])
    out.write_bytes(png)
    return png


def thumbnail(files_dir: Path, cache: Path, file: str, page: int | None, layout: str | None) -> bytes:
    path = (files_dir / file).resolve()
    if files_dir.resolve() not in path.parents or not path.is_file():
        raise ProjectError("No such file in this project")
    cache.mkdir(parents=True, exist_ok=True)
    out = cache / (hashlib.sha1(f"{file}|{page}|{layout}".encode()).hexdigest() + ".png")
    if out.is_file():
        return out.read_bytes()
    if layout:
        png = importlib.import_module("adapters.dxf").render(path, layout, bbox=None)
    else:
        png = importlib.import_module("adapters.drawings").render(path, page or 1, bbox=None, dpi=36)
    out.write_bytes(png)
    return png
