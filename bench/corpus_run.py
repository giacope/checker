"""Run the open corpus (bench/corpus/*.yaml) through the app's own pipeline and check what needs no labels.

    uv run --with ifcopenshell python bench/corpus_run.py [--model] [--kinds regulation,code,building] [--jobs 3]
                                                          [--slugs a,b] [--limit N]

Kinds, each item in its own process (a time and address-space limit, as app.main.isolated gives a job):
  regulation  adapters.regulation.read on every file. With --model, also what app.regulations.compile_regulation
              does: split into clauses, compile checks, build the pack, and validate it.
  code        fetch the pinned commit, app.scan.collect (static readers and dependencies; with --model the model reader
              and OSV advisories too), evaluate ASVS, NIST 800-63B and GDPR, build the report and its Markdown.
  building    app.buildings.process on a scratch copy of the files, evaluate every built-in code, build the report.

Invariants, none needing labels:
  - no exception escapes; a documented rejection (RegulationError, ProjectError) is recorded as one
  - every locator a fact or verdict cites resolves: a file and line in the checkout, a sheet page of an uploaded file,
    an IFC GlobalId in the model, a clause of the regulation
  - every verdict carries its reason: a pass or fail on an element cites it, a system-level one cites what it read
    or says no element of the type was found, an uncertain one names the deciding facts, an unknown one the open facts
  - the same input gives the same evidence twice (static run only: the readers, caches included, are deterministic)
  - a compiled pack validates, and each check's clause exists

Writes bench/results/corpus/<static|model>/<kind>/<slug>.json and <static|model>/summary.json, and prints a table.
The corpus files live in .amp/in/corpus/ (fetched by the scripts named in the manifests); checkouts in
$CORPUS_REPOS (default /tmp/corpus-repos).
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "engine"))
CORPUS = ROOT / ".amp" / "in" / "corpus"
REPOS = Path(os.environ.get("CORPUS_REPOS", "/tmp/corpus-repos"))
MANIFESTS = {"regulation": ["regulations-code.yaml", "regulations-building.yaml"], "code": ["code-projects.yaml"],
             "building": ["building-projects.yaml"]}
SECONDS = {"regulation": 900, "code": 1800, "building": 900}   # per item; a compile or a model scan takes minutes
MEMORY_MB = 4096
EXAMPLES = 5   # violations kept per invariant and item


def items(kind: str) -> list[dict]:
    import yaml
    out = []
    for m in MANIFESTS[kind]:
        for e in yaml.safe_load((ROOT / "bench" / "corpus" / m).read_text()):
            e["_domain"] = "building" if "building" in m else "code"
            out.append(e)
    return out


# ---------------------------------------------------------------- invariants

class Check:
    def __init__(self):
        self.counts: Counter = Counter()
        self.info: Counter = Counter()   # worth counting, not a violation
        self.examples: dict[str, list] = {}

    def fail(self, name: str, example) -> None:
        self.counts[name] += 1
        ex = self.examples.setdefault(name, [])
        if len(ex) < EXAMPLES:
            ex.append(example)

    def out(self) -> dict:
        return {"violations": dict(self.counts), "info": dict(self.info), "examples": self.examples}


def reasons(chk: Check, results: dict) -> Counter:
    """Every row's verdict carries its reason. Returns the verdict counts."""
    verdicts = Counter()
    for sid, res in results.items():
        for r in res["rows"]:
            v = r["verdict"]
            verdicts[v] += 1
            where = f"{sid} {r['norm']} {r['element']}"
            if v in ("pass", "fail") and not r.get("at") and not r.get("none_found"):
                if r.get("type") or not r.get("outcomes"):
                    chk.fail(f"{v} without a citation", where)
                else:
                    chk.fail(f"system {v} without a citation", where)
            if v == "uncertain" and not r.get("deciding") and not r.get("error"):
                chk.fail("uncertain without deciding facts", where)
            if v == "unknown" and not r.get("open") and not r.get("error"):
                chk.fail("unknown without open facts", where)
    return verdicts


def all_locators(docs: list[dict]):
    for d in docs:
        for k, obs in (d.get("facts") or {}).items():
            for o in obs if isinstance(obs, list) else []:
                for a in _ats(o):
                    yield a, f"fact {k}"
        for e in d.get("elements") or []:
            for a in _ats(e):
                yield a, f"{e.get('type')} {e.get('id')}"
            for k, obs in (e.get("facts") or {}).items():
                for o in obs if isinstance(obs, list) else []:
                    for a in _ats(o):
                        yield a, f"{e.get('type')}.{k}"


def _ats(x) -> list[str]:
    at = x.get("at") if isinstance(x, dict) else None
    return [str(a) for a in (at if isinstance(at, list) else [at]) if a]


CODE_AT = re.compile(r"^(?P<path>.+?)(?::|#L)(?P<a>\d+)(?:-L?(?P<b>\d+))?$")


def code_locators(chk: Check, root: Path, docs: list[dict]) -> int:
    lines: dict[str, int | None] = {}
    n = 0
    for at, what in all_locators(docs):
        n += 1
        m = CODE_AT.match(at)
        path = m["path"] if m else at
        p = root / path
        if path not in lines:
            try:
                lines[path] = sum(1 for _ in p.open("rb")) if p.is_file() and p.resolve().is_relative_to(root.resolve()) else None
            except OSError:
                lines[path] = None
        if lines[path] is None:
            chk.fail("locator names no file in the checkout", f"{at} ({what})")
        elif m and not 1 <= int(m["a"]) <= max(int(m["b"] or m["a"]), int(m["a"])) <= lines[path] + 1:
            chk.fail("locator line outside the file", f"{at} ({what}; {lines[path]} lines)")
    return n


def building_locators(chk: Check, files: Path, docs: list[dict], data: dict) -> int:
    from adapters.drawings.tokens import parse_locator
    guids: set[str] = set()
    for f in files.rglob("*"):
        if f.suffix.lower() == ".ifc":
            guids |= set(re.findall(rb"IFC[A-Z0-9]+\(\s*'([0-9A-Za-z_$]{22})'", f.read_bytes()))
    guids = {g.decode() for g in guids}
    sheets = {(s.get("file"), s.get("page") or s.get("layout")) for s in data.get("sheets") or []}
    n = 0
    for at, what in all_locators(docs):
        n += 1
        loc = parse_locator(at)
        if at.startswith("ifc:"):
            if re.split(r"[\s#/]", at[4:], maxsplit=1)[0] not in guids:   # "ifc:<GlobalId> <what was read>"
                chk.fail("IFC locator names no GlobalId in the model", f"{at} ({what})")
        elif loc:
            if not (files / loc["file"]).is_file():
                chk.fail("sheet locator names no uploaded file", f"{at} ({what})")
            elif sheets and (loc["file"], loc["page"] or loc["layout"]) not in sheets:
                chk.fail("sheet locator names no sheet that was read", f"{at} ({what})")
            if any(v != v or abs(v) == float("inf") for v in loc["bbox"]):
                chk.fail("sheet locator with a non-finite box", f"{at} ({what})")
        else:   # a derived fact (a sum over storeys) cites how it was derived; the parts it sums carry locators
            chk.info["derived facts citing a description"] += 1
    return n


def _stable(docs: list[dict]) -> str:
    """Evidence without timings, for comparing two runs."""
    drop = {"seconds", "read_seconds", "ocr_seconds", "ocr_cached", "cached", "cached_calls", "timings_s"}

    def clean(x):
        if isinstance(x, dict):
            return {k: clean(v) for k, v in x.items() if k not in drop}
        if isinstance(x, list):
            return [clean(v) for v in x]
        return x
    return json.dumps(clean(docs), sort_keys=True, default=str)


# ---------------------------------------------------------------- one item per kind

def run_regulation(e: dict, model: bool) -> dict:
    from adapters import regulation as R
    from app import regulations as regs
    chk = Check()
    folder = CORPUS / "regulations" / e["_domain"] / e["slug"]
    t0 = time.time()
    docs = []
    for f in e["files"]:
        doc = R.read(folder / f["name"], f["name"])
        again = R.read(folder / f["name"], f["name"])
        if [(x.no, x.page, x.text) for x in doc.lines] != [(x.no, x.page, x.text) for x in again.lines]:
            chk.fail("reading twice gives different lines", f["name"])
        if [x.no for x in doc.lines] != list(range(1, len(doc.lines) + 1)):
            chk.fail("line numbers not consecutive", f["name"])
        tags = sum(1 for x in doc.lines if re.match(r"\s*</?[a-zA-Z][\w-]*(\s[^>]*)?>", x.text))
        if tags > 0.05 * max(1, len(doc.lines)):
            chk.fail("over 5% of lines are markup", f"{f['name']}: {tags} of {len(doc.lines)}")
        docs.append(doc)
    out = {"lines": sum(len(d.lines) for d in docs), "read_seconds": round(time.time() - t0, 2)}
    if model:
        voc = regs.vocab(e["_domain"])
        cl = R.clauses(docs)
        gaps = R.uncovered(docs, cl)
        checks, stats = R.compile_checks(cl, voc)
        reg = {"id": "r" + re.sub(r"[^a-z0-9]", "", e["slug"])[:10].ljust(10, "0"), "name": e["title"], "domain": e["_domain"],
               "clauses": cl, "checks": checks}
        ids = {c["id"] for c in cl}
        for k in checks:
            if k["clause"] not in ids:
                chk.fail("check cites no clause", k["id"])
        by_file = {d.file: d for d in docs}
        for c in cl:
            d = by_file.get(c["file"])
            s, t = c["lines"]
            if d is None or "\n".join(x.text for x in d.lines[s - 1:t]) != c["text"]:
                chk.fail("clause text is not the document's", c["id"])
        from normir import load, validate
        with tempfile.TemporaryDirectory() as tmp:
            errors = validate(load(R.build_pack(reg, voc, Path(tmp) / "pack")))[0]
        for err in errors:
            chk.fail("compiled pack does not validate", err[:200])
        uncovered = sum(g["lines"][1] - g["lines"][0] + 1 for g in gaps)
        out.update(clauses=len(cl), requirements=sum(c["requirement"] for c in cl), uncovered_lines=uncovered,
                   uncovered_share=round(uncovered / max(1, out["lines"]), 3),
                   checks={k: stats[k] for k in ("computed", "assessed", "attested", "demoted", "dropped", "failed_calls")},
                   kinds_demoted=Counter(k["demoted"].split(":")[0][:60] for k in checks if k.get("demoted")).most_common(5))
    return {**out, **chk.out()}


def fetch(e: dict) -> Path:
    dest = REPOS / e["slug"]
    if (dest / ".git").is_dir() and subprocess.run(["git", "-C", dest, "rev-parse", "HEAD"], capture_output=True,
                                                   text=True).stdout.strip() == e["commit"]:
        return dest
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    git = ["git", "-c", "core.symlinks=false", "-c", "core.hooksPath=/dev/null", "-C", str(dest)]
    subprocess.run(git[:5] + ["init", "-q", str(dest)], check=True)
    subprocess.run(git + ["fetch", "-q", "--depth", "1", "--filter=blob:limit=5m", e["url"], e["commit"]], check=True, timeout=600)
    subprocess.run(git + ["checkout", "-q", "FETCH_HEAD"], check=True, timeout=600)
    return dest


def run_code(e: dict, model: bool) -> dict:
    from app import report
    from app.scan import collect, evaluate, snippets
    chk = Check()
    t0 = time.time()
    root = fetch(e)
    fetched = time.time() - t0
    name = "/".join(e["url"].rstrip("/").split("/")[-2:])
    t0 = time.time()
    docs, notes = collect(root, name, use_reader=model, offline=not model)
    seconds = time.time() - t0
    if not model:
        again, _ = collect(root, name, use_reader=False, offline=True)
        if _stable(again) != _stable(docs):
            chk.fail("the same commit gives different evidence twice", name)
    n_at = code_locators(chk, root, docs)
    ev = evaluate(docs, ["asvs", "nist", "gdpr"])
    verdicts = reasons(chk, ev["results"])
    repo = {"url": e["url"], "owner": name.split("/")[0], "name": name.split("/")[1], "commit": e["commit"]}
    rep = report.build({"repo": repo, "docs": docs, "notes": notes, "snippets": snippets(root, docs)}, ev)
    report.markdown(rep)
    return {"fetch_seconds": round(fetched, 1), "seconds": round(seconds, 1), "notes": notes,
            "elements": dict(Counter(el.get("type") for d in docs for el in d.get("elements") or [])),
            "sources": [s.get("id") for d in docs for s in d.get("sources") or []], "locators": n_at,
            "verdicts": dict(verdicts), "report_totals": rep["totals"], **chk.out()}


def run_building(e: dict, model: bool) -> dict:
    from app import buildings
    chk = Check()
    src = CORPUS / "projects" / "building" / e["slug"] / "files"
    with tempfile.TemporaryDirectory() as tmp:
        runs = []
        for i in range(1 if model else 2):
            files = Path(tmp) / f"run{i}"
            shutil.copytree(src, files)
            t0 = time.time()
            data = buildings.process(files, e["slug"])
            runs.append((files, data, time.time() - t0))
        files, data, seconds = runs[0]
        if len(runs) == 2 and _stable(runs[1][1]["docs"]) != _stable(data["docs"]):
            chk.fail("the same files give different evidence twice", e["slug"])
        n_at = building_locators(chk, files, data["docs"], data)
        ev = buildings.evaluate(data["docs"], list(buildings.CODES))
        verdicts = reasons(chk, ev["results"])
        rep = buildings.build("corpus", {"name": e["slug"], "codes": list(buildings.CODES)}, data, ev)
        buildings.markdown(rep)
    return {"seconds": round(seconds, 1), "second_run_seconds": round(runs[-1][2], 1) if len(runs) == 2 else None,
            "notes": data["notes"][:20], "elements": dict(Counter(el.get("type") for d in data["docs"] for el in d.get("elements") or [])),
            "sheets": len(data.get("sheets") or []), "locators": n_at, "verdicts": dict(verdicts), **chk.out()}


RUN = {"regulation": run_regulation, "code": run_code, "building": run_building}
REJECTIONS = {"RegulationError", "ProjectError", "ScanError"}


def one(kind: str, slug: str, model: bool, out: Path) -> None:
    """The child: run one item and write its result, whatever happens short of a native crash."""
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_MB << 20, MEMORY_MB << 20))
    e = next(x for x in items(kind) if x["slug"] == slug)
    t0 = time.time()
    try:
        res = {"status": "ok", **RUN[kind](e, model)}
    except Exception as ex:  # noqa: BLE001 - recorded: that is what this runner is for
        name = type(ex).__name__
        res = {"status": "rejected" if name in REJECTIONS else "crash", "error": f"{name}: {str(ex)[:500]}",
               "trace": traceback.format_exc()[-3000:] if name not in REJECTIONS else None}
    res.update(kind=kind, slug=slug, wall_seconds=round(time.time() - t0, 1))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=1, ensure_ascii=False, default=str))


def launch(kind: str, slug: str, model: bool, out: Path) -> dict:
    cmd = [sys.executable, "-I", __file__, "--one", kind, slug, "--out", str(out)] + (["--model"] if model else [])
    env = {**os.environ, "MALLOC_ARENA_MAX": "2"}
    if not model:
        env.pop("OPENAI_API_KEY", None)
        env.pop("ANTHROPIC_API_KEY", None)
        env["NORMIR_LLM_PROVIDER"] = "none"
    out.unlink(missing_ok=True)
    t0 = time.time()
    try:
        p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=SECONDS[kind], cwd=ROOT)
        if out.is_file():
            return json.loads(out.read_text())
        how = f"signal {-p.returncode}" if p.returncode < 0 else f"exit {p.returncode}"
        res = {"status": "crash", "error": f"process died ({how})", "trace": p.stderr[-3000:]}
    except subprocess.TimeoutExpired:
        res = {"status": "hang", "error": f"over {SECONDS[kind]} s"}
    res.update(kind=kind, slug=slug, wall_seconds=round(time.time() - t0, 1))
    out.write_text(json.dumps(res, indent=1, ensure_ascii=False))
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", action="store_true")
    ap.add_argument("--kinds", default="regulation,code,building")
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--slugs", default="")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--one", nargs=2)
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.one:
        return one(a.one[0], a.one[1], a.model, Path(a.out))
    if not a.model:
        os.environ["NORMIR_LLM_PROVIDER"] = "none"
    phase = "model" if a.model else "static"
    base = ROOT / "bench" / "results" / "corpus" / phase
    todo = [(k, e["slug"]) for k in a.kinds.split(",") for e in items(k)
            if not a.slugs or e["slug"] in a.slugs.split(",")]
    todo = todo[:a.limit] if a.limit else todo
    results = []
    with cf.ThreadPoolExecutor(max_workers=a.jobs) as pool:
        futs = {pool.submit(launch, k, s, a.model, base / k / f"{s}.json"): (k, s) for k, s in todo}
        for n, f in enumerate(cf.as_completed(futs), 1):
            r = f.result()
            results.append(r)
            v = sum((r.get("violations") or {}).values())
            print(f"[{n}/{len(todo)}] {r['kind']:10} {r['slug'][:44]:44} {r['status']:8} {r['wall_seconds']:7.1f} s"
                  + (f"  {v} violations" if v else "") + (f"  {r['error'][:90]}" if r.get("error") else ""), flush=True)
    summarise(base, phase)


def summarise(base: Path, phase: str) -> None:
    rows = [json.loads(p.read_text()) for p in sorted(base.glob("*/*.json"))]
    out = {}
    for kind in sorted({r["kind"] for r in rows}):
        rs = [r for r in rows if r["kind"] == kind]
        viol = Counter()
        for r in rs:
            viol.update(r.get("violations") or {})
        secs = sorted(r["wall_seconds"] for r in rs)
        out[kind] = {"items": len(rs), "status": dict(Counter(r["status"] for r in rs)),
                     "seconds": {"total": round(sum(secs), 1), "median": secs[len(secs) // 2], "max": secs[-1]},
                     "items_with_violations": sum(1 for r in rs if r.get("violations")), "violations": dict(viol),
                     "not_ok": {r["slug"]: r.get("error") for r in rs if r["status"] != "ok"}}
        if kind != "regulation":
            out[kind]["verdicts"] = dict(sum((Counter(r.get("verdicts") or {}) for r in rs), Counter()))
    (base / "summary.json").write_text(json.dumps(out, indent=1, ensure_ascii=False))
    print(f"\n{phase}:")
    for kind, s in out.items():
        print(f"  {kind:10} {s['items']:4} items  {s['status']}  {s['seconds']['total']:.0f} s total, median "
              f"{s['seconds']['median']} s, max {s['seconds']['max']} s")
        for name, n in sorted(s["violations"].items(), key=lambda x: -x[1]):
            print(f"      {n:6}  {name}")


if __name__ == "__main__":
    main()
