"""Deterministic static adapter: a codebase in, an evidence document (vocab/code.yaml) out.

Nothing from the analysed repository is imported, executed, or installed: Python files are parsed with the
standard library `ast`, JavaScript and TypeScript with tree-sitter grammars, configuration with PyYAML's
composer (no object construction), and git metadata is read from files under .git without running git.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .common import SOURCE, Collector
from .config import scan_config, scan_key_file, scan_template
from .facts import derive
from .files import discover, read_text
from .jsast import JSAnalyser
from .models import load_models
from .pyast import PyAnalyser

VERSION = "0.1.0"
ATTR_ORDER = ["algorithm", "salted", "construction", "untrusted_input", "is_session", "secure", "http_only", "same_site",
              "verifies_signature", "allows_none_alg", "kind", "test_or_example", "logs_credentials", "logs_personal_data",
              "recipient", "personal_data", "third_country"]
TYPE_ORDER = ["PasswordStore", "Query", "Cookie", "TokenVerification", "Secret", "LogStatement", "Transfer"]


def git_commit(root: Path) -> str | None:
    """HEAD of the repository, read from .git files (git itself is not run)."""
    git = root / ".git"
    if git.is_file():  # worktree or submodule: "gitdir: <path>"
        m = re.match(r"gitdir:\s*(.+)", git.read_text().strip())
        git = (root / m.group(1)).resolve() if m else git
    head = git / "HEAD"
    if not head.is_file():
        return None
    h = head.read_text().strip()
    if not h.startswith("ref:"):
        return h if re.fullmatch(r"[0-9a-f]{40,64}", h) else None
    ref = h[4:].strip()
    for base in (git, git / "commondir"):
        f = base / ref
        if f.is_file():
            return f.read_text().strip()
    packed = git / "packed-refs"
    if packed.is_file():
        for line in packed.read_text().splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref:
                return parts[0]
    return None


def npm_context(root: Path, files) -> dict:
    """Declared npm dependencies of server-side packages, and versions nested under them in a lock file."""
    deps: dict[str, str] = {}
    nested: dict[str, str] = {}
    candidates = sorted({f.abs.parent for f in files if f.kind in {"js", "ts"} and not f.client} | {root})
    for d in candidates:
        for parent in [d, *d.parents]:
            pj = parent / "package.json"
            if pj.is_file() and pj.stat().st_size < 1_000_000:
                try:
                    data = json.loads(pj.read_text())
                except ValueError:
                    data = {}
                for k, v in (data.get("dependencies") or {}).items():
                    if isinstance(v, str):
                        deps.setdefault(k, v)
                lock = parent / "package-lock.json"
                if lock.is_file() and lock.stat().st_size < 50_000_000:
                    try:
                        ld = json.loads(lock.read_text())
                    except ValueError:
                        ld = {}
                    for key, info in (ld.get("packages") or {}).items():
                        segs = key.split("node_modules/")[1:]
                        segs = [s.rstrip("/") for s in segs]
                        if isinstance(info, dict) and info.get("version"):
                            if len(segs) == 1 and segs[0] in deps:
                                deps[segs[0]] = info["version"]
                            elif len(segs) == 2:
                                nested[f"{segs[0]}/{segs[1]}"] = info["version"]
                    for name, info in (ld.get("dependencies") or {}).items():  # lockfile v1
                        if isinstance(info, dict) and info.get("version") and name in deps:
                            deps[name] = info["version"]
                        for sub, si in ((info or {}).get("dependencies") or {}).items():
                            if isinstance(si, dict) and si.get("version"):
                                nested[f"{name}/{sub}"] = si["version"]
                break
            if parent == root:
                break
    return {"npm_deps": deps, "npm_nested": nested}


MANIFESTS = ("package.json", "pyproject.toml", "setup.py", "requirements.txt", "Pipfile", "manage.py", "Dockerfile")


def app_root(root: Path, rel: str) -> str:
    """The nearest directory above a file that holds an application manifest ("" for the repository root)."""
    parts = rel.split("/")[:-1]
    for i in range(len(parts), 0, -1):
        d = root.joinpath(*parts[:i])
        if any((d / m).is_file() for m in MANIFESTS):
            return "/".join(parts[:i])
    return ""


def _python_taint(py: PyAnalyser):
    """Intra-function taint from request objects, plus one name-based step into callees in other functions."""
    seeds: dict = {}
    by_name: dict = {}
    for pf in py.files:
        for f in pf.funcs:
            nm = pf.func_name(f)
            if nm:
                by_name.setdefault(nm, []).append((pf, f))
    for _ in range(3):
        for pf in py.files:
            pf.compute_taint(seeds)
        new = False
        for pf in py.files:
            if pf.sf.client:
                continue
            for name, pos in pf.tainted_calls():
                for tf, f in by_name.get(name, []):
                    ps = tf.params(f)
                    if ps and ps[0] in {"self", "cls"}:
                        ps = ps[1:]
                    if isinstance(pos, int):
                        target = ps[pos] if pos < len(ps) else None
                    else:
                        target = pos if pos in ps else None
                    if target:
                        key = (tf.sf.rel, f.lineno, tf.func_name(f))
                        if target not in seeds.get(key, set()):
                            seeds.setdefault(key, set()).add(target)
                            new = True
        if not new:
            break
    for pf in py.files:
        pf.compute_taint(seeds)


def analyse(repo: str | Path, describes: str | None = None, models: list[str | Path] = ()) -> dict:
    """`models`: customer framework model files or directories (models.py), applied before the built-in ones."""
    root = Path(repo).resolve()
    fm = load_models(models)
    files = discover(root)
    out = Collector()
    py_files, js_files = [], []
    for f in files:
        text = read_text(f)
        if text is None:
            continue
        if f.kind == "py":
            py_files.append((f, text))
        elif f.kind in {"js", "ts", "tsx"}:
            js_files.append((f, text))
        elif f.kind == "config":
            scan_config(f, text, out)
        elif f.kind == "key":
            scan_key_file(f, text, out)
        elif f.kind == "template":
            scan_template(f, text, out)
    ctx = npm_context(root, files)
    ctx["models"] = fm
    py = PyAnalyser(py_files, ctx)
    _python_taint(py)
    py.prepare()
    py.run(out)
    js = JSAnalyser(js_files, ctx)
    js.prepare()
    js.run(out)

    def obs(value, at):  # an observation, naming the customer model whose rule produced it
        return {"value": value, "source": SOURCE, "at": at, **({"model": out.via[at]} if at in out.via else {})}

    elements = []
    for (type_, at), facts in out.elements.items():
        ordered = {k: [obs(facts[k], at)] for k in ATTR_ORDER if k in facts}
        elements.append({"type": type_, "id": f"{type_}@{at}", "at": at, "facts": ordered})

    def key(e):
        path, _, line = e["at"].rpartition(":")
        return (TYPE_ORDER.index(e["type"]), path, int(line))
    elements.sort(key=key)
    client = {f.rel for f in files if f.client}
    facts = derive(out, lambda rel: app_root(root, rel), lambda rel: rel in client)
    for observations in facts.values():
        for o in observations:
            if o["at"] in out.via:
                o["model"] = out.via[o["at"]]
    source = {"id": SOURCE, "kind": "static_analysis", "describes": describes or root.name,
              "adapter": "adapters.code_static", "adapter_version": VERSION, "commit": git_commit(root),
              "files_analysed": len(files), "unparsed": sorted(py.unparsed)}
    if fm.sources:
        used = {}
        for m in out.via.values():
            used[m] = used.get(m, 0) + 1
        source["models"] = [{**m, "places": used.get(m["model"], 0)} for m in fm.sources]
    return {
        "subject": {"kind": "system", "id": describes or root.name},
        "sources": [source],
        "facts": facts,
        "elements": elements,
    }
