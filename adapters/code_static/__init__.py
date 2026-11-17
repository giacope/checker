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


MAX_GIT_FILE = 16_000_000        # bytes of .git/HEAD, a ref, or packed-refs read
MAX_PACKAGE_JSON = 1_000_000
MAX_PACKAGE_LOCK = 50_000_000
COMMIT = re.compile(r"[0-9a-f]{40,64}")


def _git_text(p: Path) -> str | None:
    """A text file under .git, or None when it is missing, larger than MAX_GIT_FILE, or not UTF-8 text."""
    try:
        if not p.is_file() or p.stat().st_size > MAX_GIT_FILE:
            return None
        return p.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def git_commit(root: Path) -> str | None:
    """HEAD of the repository, read from .git files (git itself is not run)."""
    git = root / ".git"
    if git.is_file():  # worktree or submodule: "gitdir: <path>"
        m = re.match(r"gitdir:\s*(.+)", (_git_text(git) or "").strip())
        git = (root / m.group(1)).resolve() if m else git
    h = (_git_text(git / "HEAD") or "").strip()
    if not h.startswith("ref:"):
        return h if COMMIT.fullmatch(h) else None
    ref = h[4:].strip()
    for base in (git, git / "commondir"):
        sha = (_git_text(base / ref) or "").strip()
        if sha:
            return sha if COMMIT.fullmatch(sha) else None
    for line in (_git_text(git / "packed-refs") or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == ref:
            return parts[0] if COMMIT.fullmatch(parts[0]) else None
    return None


def _json_object(p: Path, max_bytes: int) -> dict:
    """A JSON file holding an object, or {} when it is missing, too large, not JSON, or JSON of another kind."""
    try:
        if not p.is_file() or p.stat().st_size >= max_bytes:
            return {}
        data = json.loads(p.read_bytes())
    except (OSError, ValueError, RecursionError):  # ValueError includes a file that is not UTF-8
        return {}
    return data if isinstance(data, dict) else {}


def _object(v) -> dict:
    return v if isinstance(v, dict) else {}


def npm_context(root: Path, files) -> dict:
    """Declared npm dependencies of server-side packages, and versions nested under them in a lock file.
    Manifests are read as found: a field of the wrong kind (a list for `dependencies`) is skipped."""
    deps: dict[str, str] = {}
    nested: dict[str, str] = {}
    candidates = sorted({f.abs.parent for f in files if f.kind in {"js", "ts"} and not f.client} | {root})
    version = lambda info: info.get("version") if isinstance(info, dict) and isinstance(info.get("version"), str) else None  # noqa: E731
    for d in candidates:
        for parent in [d, *d.parents]:
            pj = parent / "package.json"
            if pj.is_file() and pj.stat().st_size < MAX_PACKAGE_JSON:
                data = _json_object(pj, MAX_PACKAGE_JSON)
                for k, v in _object(data.get("dependencies")).items():
                    if isinstance(v, str):
                        deps.setdefault(k, v)
                ld = _json_object(parent / "package-lock.json", MAX_PACKAGE_LOCK)
                for key, info in _object(ld.get("packages")).items():
                    segs = key.split("node_modules/")[1:]
                    segs = [s.rstrip("/") for s in segs]
                    if version(info):
                        if len(segs) == 1 and segs[0] in deps:
                            deps[segs[0]] = version(info)
                        elif len(segs) == 2:
                            nested[f"{segs[0]}/{segs[1]}"] = version(info)
                for name, info in _object(ld.get("dependencies")).items():  # lockfile v1
                    if version(info) and name in deps:
                        deps[name] = version(info)
                    for sub, si in _object(_object(info).get("dependencies")).items():
                        if version(si):
                            nested[f"{name}/{sub}"] = version(si)
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
