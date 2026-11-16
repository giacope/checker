"""Scan a GitHub repository and evaluate rule packs on it: the pipeline behind the web app.

    clone (shallow, no hooks, no symlinks, nothing executed)
      -> adapters, one evidence document each:
           code_static (Python, JS/TS), code_ruby, code_elixir   deterministic, per language present
           deps                                                  lock files + OSV advisories
           code_llm                                              any language, when a model key or Codex sign-in is configured
      -> reconcile (engine/normir/evidence.py): elements matched by file and line; where sources disagree the model
         reader's value is used and the static value is kept as a reported conflict (reader-first precedence: it
         scored highest of the combinations in bench/code_check.py)
      -> evaluate each selected pack with the user's answers as the profile
      -> report data (app/report.py renders it)

Evidence is kept with the scan, so answering a question the report asks re-evaluates without scanning again.
"""

from __future__ import annotations

import base64
import importlib
import os
import re
import shutil
import subprocess
import time
from collections import Counter
from pathlib import Path

import yaml

from adapters.code_static import git_commit
from normir import load
from normir.evidence import load_evidence, prefer_sources, rank_by_kind, run

ROOT = Path(__file__).resolve().parents[1]
VOCAB = yaml.safe_load((ROOT / "vocab" / "code.yaml").read_text())
READER_FIRST = rank_by_kind(VOCAB, {k: ["llm", "static"] for k in ("measured", "judged", "given")})
GITHUB = re.compile(r"^https://github\.com/(?P<owner>[A-Za-z0-9][A-Za-z0-9-]{0,38})/(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$")
BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$")
MAX_REPO_BYTES = 800_000_000

# Standards the app offers: id -> (pack directory, label). GDPR variants are alternatives.
STANDARDS = {
    "asvs": ("owasp-asvs-5", "OWASP ASVS 5.0.0"),
    "nist": ("nist-800-63b-4", "NIST SP 800-63B-4 (passwords)"),
    "gdpr": ("gdpr", "GDPR (EU) 2016/679"),
    "uk-gdpr": ("uk-gdpr", "UK GDPR"),
    "appi": ("jp-appi", "個人情報保護法 (APPI, Japan)"),
}
# Deterministic adapters: module, the file kinds (adapters.code_static.files) that call for it, label.
STATIC_ADAPTERS = [
    ("adapters.code_static", {"py", "js", "ts", "tsx"}, "Python and JavaScript/TypeScript"),
    ("adapters.code_ruby", {"rb"}, "Ruby"),
    ("adapters.code_elixir", {"ex"}, "Elixir"),
]
LANG_EXT = {".py": "Python", ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript",
            ".tsx": "TypeScript", ".rb": "Ruby", ".rake": "Ruby", ".erb": "Ruby (ERB)", ".ex": "Elixir", ".exs": "Elixir",
            ".heex": "Elixir (HEEx)", ".go": "Go", ".php": "PHP", ".java": "Java", ".kt": "Kotlin", ".cs": "C#", ".rs": "Rust",
            ".scala": "Scala", ".swift": "Swift", ".c": "C", ".cpp": "C++", ".clj": "Clojure", ".erl": "Erlang"}


class ScanError(RuntimeError):
    pass


def parse_repo_url(url: str) -> tuple[str, str]:
    m = GITHUB.match(url.strip())
    if not m:
        raise ScanError("Give a GitHub repository URL like https://github.com/owner/name")
    return m["owner"], m["repo"]


def clone(url: str, dest: Path, branch: str | None = None, token: str | None = None) -> None:
    """Shallow clone. Hooks are disabled, symlinks become plain files, LFS objects are not fetched, nothing runs."""
    owner, repo = parse_repo_url(url)
    if branch and not BRANCH.match(branch):
        raise ScanError("That branch name is not valid")
    remote = f"https://github.com/{owner}/{repo}.git"
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(dest.parent), "GIT_TERMINAL_PROMPT": "0",
           "GIT_LFS_SKIP_SMUDGE": "1", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false", "-c", "protocol.file.allow=never",
           "-c", "submodule.recurse=false"]
    if token:  # passed in the environment, not argv, so it does not show in the process list
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                    "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}"})
    cmd += ["clone", "--depth", "1", "--single-branch", "--no-tags", *(["--branch", branch] if branch else []), "--", remote, str(dest)]
    try:
        p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired as e:
        raise ScanError("Cloning took longer than 5 minutes") from e
    if p.returncode != 0:
        msg = p.stderr.strip().splitlines()[-1] if p.stderr.strip() else "git clone failed"
        if "not found" in msg.lower() or "could not read" in msg.lower():
            msg = "Repository not found, or it is private (private repositories need GITHUB_TOKEN on the server)"
        raise ScanError(msg)
    size = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file() and ".git" not in f.parts)
    if size > MAX_REPO_BYTES:
        raise ScanError(f"Repository is too large to scan ({size // 1_000_000} MB of files)")


def languages(root: Path) -> dict[str, int]:
    skip = {".git", "node_modules", "vendor", "deps", "_build", "dist", "build", "target", ".venv", "venv"}
    c: Counter = Counter()
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip]
        for f in files:
            lang = LANG_EXT.get(Path(f).suffix.lower())
            if lang:
                c[lang] += 1
    return dict(c.most_common())


def _adapter(module: str):
    try:
        return importlib.import_module(module)
    except ImportError:
        return None


def collect(root: Path, name: str, models: list[Path] = (), use_reader: bool = True, offline: bool = False, progress=lambda m: None,
            requirements: list[dict] = ()) -> tuple[list[dict], list[str]]:
    """Evidence documents from every adapter that applies, and notes on what could not run. `requirements` are the
    assessed checks of the customer regulations being checked (app.regulations.assessed): the model judges each one
    from the code, citing the lines it read."""
    from adapters.code_static.files import discover
    kinds = Counter(f.kind for f in discover(root))
    docs, notes = [], []
    for module, wants, label in STATIC_ADAPTERS:
        if not (set(kinds) & wants):
            continue
        mod = _adapter(module)
        if mod is None:
            notes.append(f"{label}: no deterministic adapter is installed; only the model reader read this code.")
            continue
        progress(f"Static analysis ({label})")
        try:
            docs.append(mod.analyse(root, name, models))
        except Exception as e:  # noqa: BLE001 - one adapter failing must not lose the others' evidence
            notes.append(f"{label} static analysis failed: {type(e).__name__}: {e}")
    deps = _adapter("adapters.deps")
    if deps is not None:
        progress("Dependencies and published advisories (OSV)")
        try:
            docs.append(deps.analyse(root, name, offline=offline))
        except Exception as e:  # noqa: BLE001
            notes.append(f"Dependency check failed: {type(e).__name__}: {e}")
    else:
        notes.append("Dependency check is not installed; vulnerable third-party components were not checked.")
    llm = _adapter("adapters.code_llm")
    if use_reader and llm is not None and llm.provider_from_env() is not None:
        progress("Model reader")
        try:
            docs.append(llm.analyse(root, name, progress=progress))
        except Exception as e:  # noqa: BLE001
            notes.append(f"Model reader failed: {e}. The report rests on static analysis only.")
    elif use_reader:
        notes.append("No model reader is configured (ANTHROPIC_API_KEY or OPENAI_API_KEY on the server, or a `codex login`). "
                     "Judged facts such as whether a secret is a test fixture stay open, and languages without a "
                     "static adapter are not read.")
    if requirements:
        if llm is not None and llm.provider_from_env() is not None:
            from adapters.assess import CodeCorpus, assess
            progress(f"Assessing {len(requirements)} requirements of your regulations")
            try:
                docs.append(assess(list(requirements), CodeCorpus(root, name), progress=progress))
            except Exception as e:  # noqa: BLE001
                notes.append(f"Assessing your regulations' requirements failed: {e}. Those checks stay open.")
        else:
            notes.append(f"{len(requirements)} requirements of your regulations are judged by a model, and none is configured: "
                         "they stay open as questions.")
    return docs, notes


def snippets(root: Path, docs: list[dict], context: int = 2) -> dict[str, dict]:
    """Source lines around every locator, for the report. String literals on Secret lines are masked."""
    def ats_of(e):  # an element's "at" is one locator or a list of them
        return e["at"] if isinstance(e.get("at"), list) else [e.get("at")]
    secret_at = {a for d in docs for e in d.get("elements", []) if e["type"] == "Secret" for a in ats_of(e)}
    ats = {a for d in docs for e in d.get("elements", []) for a in ats_of(e) if a}
    ats |= {o["at"] for d in docs for obs in d.get("facts", {}).values() for o in obs if o.get("at")}
    cache: dict[str, list[str] | None] = {}
    out = {}
    for at in ats:
        path, _, line = str(at).rpartition(":")
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", line)  # path:line, or path:a-b from a model's citation
        if not path or not m:
            continue
        if path not in cache:
            p = (root / path).resolve()
            ok = p.is_file() and root.resolve() in p.parents and p.stat().st_size < 2_000_000
            cache[path] = p.read_text(errors="replace").split("\n") if ok else None
        rows = cache[path]
        if not rows:
            continue
        n = int(m[1])
        end = max(n, min(int(m[2] or n), n + 29))
        lo, hi = max(1, n - context), min(len(rows), end + context)
        lines = []
        for i in range(lo, hi + 1):
            text = rows[i - 1][:240]
            if at in secret_at or re.search(r"(secret|passw|token|api_?key|private)", text, re.I):
                text = re.sub(r"(['\"])(?:(?!\1).){4,}\1", r"\1•••\1", text)
                text = re.sub(r"(-----BEGIN[^-]*-----).*", r"\1 •••", text)
            lines.append([i, text])
        out[at] = {"path": path, "line": n, "end": end, "lines": lines}
    return out


def advisory_details(docs: list[dict], offline: bool = False) -> dict:
    """Summary, severity, and fixed versions of every advisory the dependency check found, for the report."""
    deps = _adapter("adapters.deps")
    ids = sorted({i.strip() for d in docs for e in d.get("elements", []) if e["type"] == "Dependency"
                  for o in e["facts"].get("advisories", []) for i in str(o["value"]).split(",") if i.strip()})
    if not ids or deps is None or not hasattr(deps, "advisory_details") or offline:
        return {}
    try:
        return deps.advisory_details(ids)
    except Exception:  # noqa: BLE001 - the report still lists the advisory ids
        return {}


def scan(url: str, workdir: Path, branch: str | None = None, models: list[Path] = (), use_reader: bool = True,
         offline: bool = False, progress=lambda m: None, requirements: list[dict] = ()) -> dict:
    """Clone, run the adapters, and return {repo, evidence docs, snippets, notes}. The clone is deleted after."""
    owner, repo = parse_repo_url(url)
    dest = workdir / "checkout"
    if dest.exists():
        shutil.rmtree(dest)
    started = time.time()
    progress("Cloning")
    clone(url, dest, branch, os.environ.get("GITHUB_TOKEN"))
    try:
        commit = git_commit(dest)
        langs = languages(dest)
        docs, notes = collect(dest, f"{owner}/{repo}", list(models), use_reader, offline, progress, requirements)
        snips = snippets(dest, docs)
        advisories = advisory_details(docs, offline)
    finally:
        shutil.rmtree(dest, ignore_errors=True)
    return {"repo": {"url": f"https://github.com/{owner}/{repo}", "owner": owner, "name": repo, "branch": branch, "commit": commit},
            "languages": langs, "docs": docs, "snippets": snips, "advisories": advisories, "notes": notes, "seconds": round(time.time() - started, 1)}


def evaluate(docs: list[dict], standards: list[str], asvs_level: int = 2, answers: dict | None = None) -> dict:
    """Run each selected pack. `answers` is the user's profile: {"subject": {attr: value}, "elements": {id: {attr: value}}}."""
    ev = prefer_sources(load_evidence(*docs), READER_FIRST)
    answers = answers or {}
    out = {}
    for sid in standards:
        if sid.startswith("reg:"):  # a customer regulation (app.regulations): its compiled pack
            from . import regulations
            req = regulations.ready(sid[4:], "code")
            if req is None:
                continue
            pack_dir, label = f"regulations/{sid[4:]}", req["name"]  # shown in reports: not the server path
            rs = load(regulations.pack_dir(sid[4:]))
        else:
            pack_dir, label = STANDARDS[sid]
            rs = load(ROOT / "packs" / pack_dir)
        profile = {**(answers.get("subject") or {}), "elements": answers.get("elements") or {}}
        if sid == "asvs":
            profile["norms"] = [n for (k, n), el in rs.elements.items() if k == "norm" and int(el.data.get("level", 1)) <= asvs_level]
        out[sid] = {"pack": pack_dir, "label": label, "short": label if sid.startswith("reg:") else None, "rs": rs, "norms": profile.get("norms"), "rows": run(rs, ev, profile)}
    return {"evidence": ev, "results": out}
