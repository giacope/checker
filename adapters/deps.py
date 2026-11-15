"""Dependency adapter: lock files in, Dependency elements (vocab/code.yaml) out, with OSV advisories.

    uv run python -m adapters.deps <repo> -o out.yaml [--name N] [--offline]

Nothing in the repository is executed or installed. Lock files are read as data: JSON with the standard library
decoder, TOML with tomllib, pnpm-lock.yaml with PyYAML's composer (no object construction), the rest line by line.
The commit is read from .git files (git is not run).

Lock files: Gemfile.lock (RubyGems), mix.lock (Hex), package-lock.json v1-v3 and npm-shrinkwrap.json, yarn.lock
(v1; Berry lock files are read the same way), pnpm-lock.yaml v5-v9 (npm), poetry.lock, uv.lock, Pipfile.lock, and
requirements*.txt (or *.txt under a requirements/ directory) lines pinned with `==` (PyPI). Directories skipped are
those adapters.code_static.files skips (dependencies, vendored code, build output, tests, docs, hidden directories).
Only registry packages are listed: git, path, file, link, and workspace entries are not.

One Dependency element per (ecosystem, name, version), with id `Dependency@<ecosystem>/<name>@<version>`. Each fact
observation's `at` is `<lockfile>:<line>` of the first entry that pins the package (the vocabulary's locator form). The
element's own `at` lists every such entry as `<lockfile>#L<line>`: normir.evidence.load_evidence treats two elements of
one type whose `at` are `path:line` within 5 lines of each other as the same element, which would merge neighbouring
lock file entries (consecutive requirements.txt lines), so the element locator avoids that form; the id matches
Dependency elements across documents. PyPI names are normalised (PEP 503). Where the lock file itself
marks an entry as a development dependency (npm `dev`, pnpm `dev`, Pipfile `develop`, poetry `category`/`groups`)
and every entry for the package is marked so, the element carries `dev: true` beside its facts; the vocabulary has
no such attribute, so packs do not read it.

Advisories come from OSV (https://osv.dev): POST /v1/querybatch (at most 1000 queries per request), then
GET /v1/vulns/<id> for each advisory. Responses are cached on disk (default ~/.cache/normir/osv) by query and by
advisory id, for 24 hours. Records that alias each other (GHSA-..., PYSEC-..., CVE-...) are one advisory:
- vulnerable: OSV lists at least one advisory for the version;
- fix_available: every advisory has, for this package and ecosystem, a `fixed` event in a SEMVER or ECOSYSTEM
  range that is greater than the locked version in the ecosystem's version order;
- max_severity: per advisory, GitHub's `database_specific.severity` (LOW, MODERATE, HIGH, CRITICAL) where a record
  has it, else the highest CVSS v3.x or v4.0 base score among its vectors; the highest across advisories that have
  one, and `unknown` only when none has;
- advisories: one id per advisory (the GHSA id where there is one) followed by its CVE aliases, comma-separated.
Packages with no advisory get `vulnerable: false` and no advisory facts. With offline=True only the inventory
(ecosystem, name, version) is emitted.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import json.decoder
import json.scanner
import math
import os
import re
import sys
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import httpx
import yaml

from ._cvss4 import cvss4_score
from .code_static import git_commit
from .code_static.files import _skip_dir

VERSION = "0.1.0"
SOURCE = "deps"
OSV_API = "https://api.osv.dev/v1"
BATCH = 1000                 # OSV's limit on queries per querybatch request
TTL = 24 * 3600              # cache entries older than this are fetched again
TIMEOUT = httpx.Timeout(30.0, connect=10.0)
RETRIES = 4
BACKOFF = 1.0                # seconds; doubled after every failed attempt
WORKERS = 8                  # parallel GET /v1/vulns requests
MAX_LOCK_BYTES = 64_000_000
DEFAULT_CACHE = Path.home() / ".cache" / "normir" / "osv"
SEVERITIES = ["none", "low", "moderate", "high", "critical"]


class OSVError(RuntimeError):
    """OSV could not be reached after retries, or answered with an error."""


@dataclass
class Entry:
    ecosystem: str
    name: str
    version: str
    at: str                  # lockfile:line
    dev: bool | None = None  # True/False where the lock file says; None where it does not


@dataclass
class Package:
    ecosystem: str
    name: str
    version: str
    at: list[str] = field(default_factory=list)
    dev: list[bool | None] = field(default_factory=list)

    @property
    def id(self) -> str:
        return f"Dependency@{self.ecosystem}/{self.name}@{self.version}"


# ---------------------------------------------------------------- discovery

def _lock_format(parts: tuple[str, ...], fn: str) -> str | None:
    low = fn.lower()
    if fn == "Gemfile.lock" or low == "gems.locked":
        return "gemfile.lock"
    if low in {"mix.lock", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
               "uv.lock", "pipfile.lock"}:
        return low
    if low.endswith(".txt") and (low.startswith("requirements") or (parts and parts[-1].lower() == "requirements")):
        return "requirements.txt"
    return None


def find_lockfiles(root: Path) -> list[tuple[str, str]]:
    """(path relative to root, format) of every lock file outside skipped directories."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        parts = Path(dirpath).relative_to(root).parts
        dirnames[:] = sorted(d for d in dirnames
                             if not _skip_dir(Path(dirpath), parts, d) and not os.path.islink(os.path.join(dirpath, d)))
        for fn in sorted(filenames):
            fmt = _lock_format(parts, fn)
            p = Path(dirpath) / fn
            if fmt and not p.is_symlink() and p.is_file():
                out.append(("/".join(parts + (fn,)), fmt))
    return out


# ---------------------------------------------------------------- parsers

class _LineDict(dict):
    """A JSON object that remembers the 1-based line of its opening brace."""
    __slots__ = ("line",)


def _json_with_lines(text: str):
    newlines = [m.start() for m in re.finditer("\n", text)]

    def parse_object(s_and_end, strict, scan_once, object_hook, object_pairs_hook, memo=None):
        obj, end = json.decoder.JSONObject(s_and_end, strict, scan_once, object_hook, object_pairs_hook, memo)
        obj.line = bisect.bisect_left(newlines, s_and_end[1] - 1) + 1
        return obj, end

    dec = json.JSONDecoder(object_pairs_hook=_LineDict)
    dec.parse_object = parse_object
    dec.scan_once = json.scanner.py_make_scanner(dec)  # the C scanner does not call parse_object
    return dec.decode(text)


SEMVERISH = re.compile(r"^v?\d+(\.\d+)*([-+.][0-9A-Za-z.+-]*)?$")


def _parse_npm(rel: str, text: str) -> list[Entry]:
    doc = _json_with_lines(text)
    out: list[Entry] = []
    packages = doc.get("packages")
    if isinstance(packages, dict) and int(doc.get("lockfileVersion") or 1) >= 2:
        for key, e in packages.items():
            if "node_modules/" not in key or not isinstance(e, dict) or e.get("link"):
                continue  # "" is the root project; keys without node_modules/ are workspace sources
            name = e.get("name") or key.rsplit("node_modules/", 1)[1]
            version = e.get("version")
            resolved = e.get("resolved") or ""
            if not isinstance(version, str) or not SEMVERISH.match(version) or str(resolved).startswith(("git", "file:")):
                continue
            out.append(Entry("npm", name, version, f"{rel}:{e.line}", e.get("dev") is True))
        return out

    def walk(deps: dict) -> None:
        for name, e in deps.items():
            if not isinstance(e, dict):
                continue
            version = e.get("version")
            if isinstance(version, str) and version.startswith("npm:"):  # alias: "npm:real-name@1.2.3"
                target = version[4:]
                at = target.rfind("@")
                if at > 0:
                    name, version = target[:at], target[at + 1:]
            if isinstance(version, str) and SEMVERISH.match(version):
                out.append(Entry("npm", name, version, f"{rel}:{e.line}", e.get("dev") is True))
            walk(e.get("dependencies") or {})
    walk(doc.get("dependencies") or {})
    return out


def _yarn_name(spec: str) -> tuple[str, str]:
    at = spec.find("@", 1)  # a leading @ belongs to the scope
    name, rng = (spec[:at], spec[at + 1:]) if at > 0 else (spec, "")
    if rng.startswith("npm:"):
        target = rng[4:]
        sep = target.find("@", 1)
        if sep > 0:  # alias "name@npm:real-name@range"
            name = target[:sep]
    return name, rng


def _parse_yarn(rel: str, text: str) -> list[Entry]:
    out: list[Entry] = []
    header, skip = None, True
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            header = line.rstrip().rstrip(":").strip()
            spec = header.split(",")[0].strip().strip('"')
            name, rng = _yarn_name(spec)
            skip = header == "__metadata" or rng.startswith(("workspace:", "link:", "portal:", "file:", "patch:", "exec:",
                                                             "git", "http", "github:"))
            continue
        m = re.match(r'^  version:?\s+"?([^"\s]+)"?\s*$', line)
        if m and header and not skip:
            if SEMVERISH.match(m[1]):
                out.append(Entry("npm", name, m[1], f"{rel}:{i}"))
            header = None
    return out


def _pnpm_key(key: str) -> tuple[str, str] | None:
    k = re.sub(r"\(.*\)$", "", key.lstrip("/"))                       # v6/v9 peer suffix: a@1.0.0(b@2.0.0)
    m = re.match(r"^((?:@[^/@]+/)?[^/@]+)@(\d[^@/:]*)$", k)            # v6, v9: name@version
    if m:
        return m[1], m[2]
    m = re.match(r"^((?:@[^/@]+/)?[^/@]+)/(\d[^/_:]*)(?:_.*)?$", k)    # v5: name/version_peers
    if m:
        return m[1], m[2]
    return None


def _parse_pnpm(rel: str, text: str) -> list[Entry]:
    node = yaml.compose(text, Loader=yaml.SafeLoader)
    out: list[Entry] = []
    if not isinstance(node, yaml.MappingNode):
        return out
    for k, v in node.value:
        if k.value != "packages" or not isinstance(v, yaml.MappingNode):
            continue
        for pk, pv in v.value:
            parsed = _pnpm_key(str(pk.value))
            if not parsed:
                continue
            dev = None
            if isinstance(pv, yaml.MappingNode):
                dev = next((x.value == "true" for y, x in pv.value if y.value == "dev" and isinstance(x, yaml.ScalarNode)), None)
            out.append(Entry("npm", parsed[0], parsed[1], f"{rel}:{pk.start_mark.line + 1}", dev))
    return out


GEM_PLATFORM = re.compile(r"^(x86|x64|i[3-6]86|arm|aarch64|universal|java|jruby|mingw|mswin|darwin|linux|freebsd|"
                          r"openbsd|netbsd|solaris|cygwin|wasm|powerpc|ppc|s390|riscv|loongarch|sparc)", re.I)


def _parse_gemfile(rel: str, text: str) -> list[Entry]:
    out: list[Entry] = []
    section, specs = None, False
    for i, line in enumerate(text.splitlines(), 1):
        if line and not line[0].isspace():
            section, specs = line.strip(), False
            continue
        if line.strip() == "specs:":
            specs = True
            continue
        m = re.match(r"^    ([^\s(]+) \(([^)\s]+)\)\s*$", line)  # 4 spaces: a locked gem; 6: one of its requirements
        if m and section == "GEM" and specs:
            version = m[2]
            head, sep, tail = version.partition("-")
            if sep and GEM_PLATFORM.match(tail):
                version = head  # nokogiri (1.16.2-x86_64-linux): the platform is not part of the version
            out.append(Entry("RubyGems", m[1], version, f"{rel}:{i}"))
    return out


def _parse_mix(rel: str, text: str) -> list[Entry]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r'^\s*"([^"]+)":\s*\{:hex,\s*:"?([A-Za-z0-9_\-]+)"?,\s*"([^"]+)"', line)
        if m:
            out.append(Entry("Hex", m[2], m[3], f"{rel}:{i}"))
    return out


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _toml_packages(rel: str, text: str) -> list[tuple[dict, str]]:
    """[[package]] tables of poetry.lock / uv.lock with the line of each table's `name`."""
    pkgs = tomllib.loads(text).get("package") or []
    lines = text.splitlines()
    heads = [i for i, line in enumerate(lines) if line.strip() == "[[package]]"]
    out = []
    for n, p in enumerate(pkgs):
        line = 1
        if len(heads) == len(pkgs):
            line = heads[n] + 1
            for j in range(heads[n] + 1, min(len(lines), heads[n] + 6)):
                if re.match(r"^name\s*=", lines[j]):
                    line = j + 1
                    break
        out.append((p, f"{rel}:{line}"))
    return out


def _parse_poetry(rel: str, text: str) -> list[Entry]:
    out = []
    for p, at in _toml_packages(rel, text):
        if (p.get("source") or {}).get("type") in {"git", "directory", "file", "url"} or "name" not in p or "version" not in p:
            continue
        groups = p.get("groups")
        dev = p.get("category") == "dev" if "category" in p else ("main" not in groups if isinstance(groups, list) else None)
        out.append(Entry("PyPI", _pep503(p["name"]), str(p["version"]), at, dev))
    return out


def _parse_uv(rel: str, text: str) -> list[Entry]:
    return [Entry("PyPI", _pep503(p["name"]), str(p["version"]), at)
            for p, at in _toml_packages(rel, text)
            if "registry" in (p.get("source") or {}) and "name" in p and "version" in p]


def _parse_pipfile(rel: str, text: str) -> list[Entry]:
    doc = _json_with_lines(text)
    out = []
    for section in ("default", "develop"):
        for name, e in (doc.get(section) or {}).items():
            v = e.get("version") if isinstance(e, dict) else None
            if isinstance(v, str) and v.startswith("==") and "*" not in v:
                out.append(Entry("PyPI", _pep503(name), v[2:].strip(), f"{rel}:{e.line}", section == "develop"))
    return out


REQ_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s;#,\\*]*)\s*(?:$|[;#\\]|--)")


def _parse_requirements(rel: str, text: str) -> list[Entry]:
    out = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start, line = i + 1, lines[i]
        while line.rstrip().endswith("\\") and i + 1 < len(lines):  # continuation lines
            i += 1
            line = line.rstrip()[:-1] + " " + lines[i]
        i += 1
        s = line.strip()
        if not s or s.startswith(("#", "-")):
            continue
        m = REQ_PIN.match(s)
        if m:
            out.append(Entry("PyPI", _pep503(m[1]), m[2], f"{rel}:{start}"))
    return out


PARSERS = {
    "gemfile.lock": _parse_gemfile, "mix.lock": _parse_mix, "package-lock.json": _parse_npm,
    "npm-shrinkwrap.json": _parse_npm, "yarn.lock": _parse_yarn, "pnpm-lock.yaml": _parse_pnpm,
    "poetry.lock": _parse_poetry, "uv.lock": _parse_uv, "pipfile.lock": _parse_pipfile,
    "requirements.txt": _parse_requirements,
}
ECOSYSTEM = {"gemfile.lock": "RubyGems", "mix.lock": "Hex", "package-lock.json": "npm", "npm-shrinkwrap.json": "npm",
             "yarn.lock": "npm", "pnpm-lock.yaml": "npm", "poetry.lock": "PyPI", "uv.lock": "PyPI",
             "pipfile.lock": "PyPI", "requirements.txt": "PyPI"}


def inventory(root: Path) -> tuple[list[dict], list[Package]]:
    """Lock files found (with entry counts or a parse error) and the packages they pin, deduplicated."""
    lockfiles, packages = [], {}
    for rel, fmt in find_lockfiles(root):
        info = {"path": rel, "format": fmt, "ecosystem": ECOSYSTEM[fmt]}
        try:
            p = root / rel
            if p.stat().st_size > MAX_LOCK_BYTES:
                raise ValueError(f"larger than {MAX_LOCK_BYTES} bytes")
            entries = PARSERS[fmt](rel, p.read_text(encoding="utf-8", errors="replace"))
        except Exception as e:  # noqa: BLE001 - a malformed lock file is reported, not fatal
            lockfiles.append({**info, "entries": 0, "error": f"{type(e).__name__}: {e}"[:300]})
            continue
        lockfiles.append({**info, "entries": len(entries)})
        for e in entries:
            pkg = packages.setdefault((e.ecosystem, e.name, e.version), Package(e.ecosystem, e.name, e.version))
            if e.at not in pkg.at:
                pkg.at.append(e.at)
            pkg.dev.append(e.dev)
    return lockfiles, sorted(packages.values(), key=lambda p: (p.ecosystem, p.name.lower(), p.name, p.version))


# ---------------------------------------------------------------- version order

def _semver_key(v: str):
    m = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]*)?$", v.strip())
    if not m:
        return None
    release = tuple(int(x or 0) for x in m.groups()[:4])
    if m[5] is None:
        return release + ((1,),)
    ids = tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in m[5].split("."))
    return release + ((0,) + ids,)


_PEP440 = re.compile(
    r"^v?(?:(?P<epoch>\d+)!)?(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<pre_l>a|alpha|b|beta|rc|c|pre|preview)[-_.]?(?P<pre_n>\d+)?)?"
    r"(?:-(?P<post_n1>\d+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?)?"
    r"(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?"
    r"(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$", re.I)


def _pep440_key(v: str):
    m = _PEP440.match(v.strip())
    if not m:
        return None
    release = [int(x) for x in m["release"].split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    post = m["post_n1"] or (m["post_n2"] or "0" if m["post_l"] else None)
    dev = (m["dev_n"] or "0") if m["dev_l"] else None
    if m["pre_l"]:
        letter = m["pre_l"].lower()
        letter = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}.get(letter, letter)
        pre = (1, letter, int(m["pre_n"] or 0))
    elif post is None and dev is not None:
        pre = (0, "", 0)   # 1.0.dev1 sorts before 1.0a1
    else:
        pre = (2, "", 0)
    local = ((0, 0, ""),) if not m["local"] else tuple(
        (2, int(p), "") if p.isdigit() else (1, 0, p.lower()) for p in re.split(r"[-_.]", m["local"]))
    return (int(m["epoch"] or 0), tuple(release), pre,
            (0, 0) if post is None else (1, int(post)),
            (1, 0) if dev is None else (0, int(dev)), local)


def _gem_key(v: str):
    v = v.strip()
    if not re.match(r"^[0-9]+(?:[.-]?[0-9A-Za-z]+)*$", v):
        return None
    v = v.replace("-", ".pre.")
    segs = [(1, int(s), "") if s.isdigit() else (0, 0, s) for s in re.findall(r"[0-9]+|[A-Za-z]+", v)]
    # Gem::Version#canonical_segments: drop zeros before the first prerelease segment and at the end
    first_str = next((i for i, s in enumerate(segs) if s[0] == 0), len(segs))
    head, tail = segs[:first_str], segs[first_str:]
    while head and head[-1] == (1, 0, ""):
        head.pop()
    while tail and tail[-1] == (1, 0, ""):
        tail.pop()
    return tuple(head + tail) + ((0.5, 0, ""),)  # terminal: below any further number, above any prerelease


def version_key(ecosystem: str, version: str):
    """A sort key in the ecosystem's version order, or None if the version cannot be read."""
    if ecosystem == "PyPI":
        return _pep440_key(version)
    if ecosystem == "RubyGems":
        return _gem_key(version)
    return _semver_key(version)  # npm and Hex use semantic versioning


def is_newer(ecosystem: str, a: str, b: str) -> bool | None:
    """a > b in the ecosystem's order; None when either cannot be read."""
    ka, kb = version_key(ecosystem, a), version_key(ecosystem, b)
    return None if ka is None or kb is None else ka > kb


# ---------------------------------------------------------------- CVSS

_V3 = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44}, "UI": {"N": 0.85, "R": 0.62},
       "CIA": {"H": 0.56, "L": 0.22, "N": 0.0}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """CVSS v3.0/v3.1 base score from a vector string (FIRST CVSS v3.1 specification, section 7.1)."""
    if not vector.startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _V3["CIA"][m["C"]]) * (1 - _V3["CIA"][m["I"]]) * (1 - _V3["CIA"][m["A"]])
        expl = 8.22 * _V3["AV"][m["AV"]] * _V3["AC"][m["AC"]] * pr * _V3["UI"][m["UI"]]
    except KeyError:
        return None
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    return _roundup(min((1.08 if scope_changed else 1.0) * (impact + expl), 10))


def _rating(score: float) -> str:
    return "none" if score == 0 else "low" if score < 4 else "moderate" if score < 7 else "high" if score < 9 else "critical"


def record_severity(rec: dict) -> str:
    """low/moderate/high/critical for one OSV record, or unknown."""
    db = str((rec.get("database_specific") or {}).get("severity") or "").upper()
    mapped = {"LOW": "low", "MODERATE": "moderate", "MEDIUM": "moderate", "HIGH": "high", "CRITICAL": "critical"}.get(db)
    if mapped:
        return mapped
    scores = []
    for s in list(rec.get("severity") or []) + [s for a in rec.get("affected") or [] for s in a.get("severity") or []]:
        vector = str(s.get("score") or "")
        if s.get("type") == "CVSS_V3":
            score = cvss3_score(vector)
        elif s.get("type") == "CVSS_V4":
            score = cvss4_score(vector)
        else:
            score = None
        if score is not None:
            scores.append(score)
    return _rating(max(scores)) if scores else "unknown"


# ---------------------------------------------------------------- OSV client and cache

def _now() -> float:
    return time.time()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _client() -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, headers={"User-Agent": f"normir-adapters.deps/{VERSION}"})


class Cache:
    """One JSON file per query (sha256 of ecosystem, name, version) and per advisory id."""

    def __init__(self, root: str | Path | None = None):
        self.root = Path(root) if root else DEFAULT_CACHE

    def _vuln_path(self, vid: str) -> Path:
        safe = vid if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,120}", vid) else "h-" + hashlib.sha256(vid.encode()).hexdigest()
        return self.root / "vulns" / f"{safe}.json"

    def _query_path(self, key: tuple[str, str, str]) -> Path:
        return self.root / "queries" / (hashlib.sha256("\0".join(key).encode()).hexdigest() + ".json")

    @staticmethod
    def _read(path: Path) -> dict | None:
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return None

    @staticmethod
    def _write(path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(data))
        os.replace(tmp, path)

    def query(self, key, fresh_only: bool = True) -> dict | None:
        d = self._read(self._query_path(key))
        return d if d and (not fresh_only or _now() - d.get("fetched_at", 0) <= TTL) else None

    def put_query(self, key, ids: list[str], ts: float) -> None:
        self._write(self._query_path(key), {"fetched_at": ts, "query": list(key), "vulns": ids})

    def vuln(self, vid: str, fresh_only: bool = True) -> dict | None:
        d = self._read(self._vuln_path(vid))
        return d if d and (not fresh_only or _now() - d.get("fetched_at", 0) <= TTL) else None

    def put_vuln(self, vid: str, record: dict, ts: float) -> None:
        self._write(self._vuln_path(vid), {"fetched_at": ts, "record": record})

    def all_vulns(self):
        for p in sorted((self.root / "vulns").glob("*.json")):
            d = self._read(p)
            if d and isinstance(d.get("record"), dict):
                yield d


def _request(client: httpx.Client, method: str, url: str, body: dict | None = None) -> dict | None:
    last = None
    for attempt in range(RETRIES):
        try:
            r = client.request(method, url, json=body)
            if r.status_code == 404 and method == "GET":
                return None
            if r.status_code == 429 or r.status_code >= 500:
                last = f"HTTP {r.status_code}"
                wait = r.headers.get("Retry-After", "")
                delay = float(wait) if wait.replace(".", "", 1).isdigit() else BACKOFF * 2 ** attempt
            else:
                r.raise_for_status()
                return r.json()
        except httpx.HTTPStatusError as e:
            raise OSVError(f"{method} {url}: HTTP {e.response.status_code}") from e
        except (httpx.TransportError, ValueError) as e:
            last, delay = f"{type(e).__name__}: {e}", BACKOFF * 2 ** attempt
        if attempt < RETRIES - 1:
            time.sleep(min(delay, 30))
    raise OSVError(f"{method} {url}: failed after {RETRIES} attempts ({last})")


def _osv_query(p: Package) -> dict:
    return {"package": {"ecosystem": p.ecosystem, "name": p.name}, "version": p.version}


def fetch_advisories(packages: list[Package], cache: Cache, client: httpx.Client) -> tuple[dict, dict, float | None]:
    """{(ecosystem, name, version): [advisory ids]}, {id: record}, and the time of the oldest OSV answer used."""
    ids: dict[tuple, list[str]] = {}
    modified: dict[str, str] = {}
    times: list[float] = []
    todo = []
    for p in packages:
        key = (p.ecosystem, p.name, p.version)
        hit = cache.query(key)
        if hit is None:
            todo.append(p)
        else:
            ids[key] = hit["vulns"]
            times.append(hit["fetched_at"])
    for start in range(0, len(todo), BATCH):
        chunk = todo[start:start + BATCH]
        ts = _now()
        res = (_request(client, "POST", f"{OSV_API}/querybatch", {"queries": [_osv_query(p) for p in chunk]}) or {}).get("results") or []
        if len(res) != len(chunk):
            raise OSVError(f"querybatch returned {len(res)} results for {len(chunk)} queries")
        for p, r in zip(chunk, res):
            found = list(r.get("vulns") or [])
            token = r.get("next_page_token")
            while token:  # more advisories than fit in one page: ask again for this package alone
                more = _request(client, "POST", f"{OSV_API}/querybatch", {"queries": [{**_osv_query(p), "page_token": token}]})
                page = ((more or {}).get("results") or [{}])[0]
                found += page.get("vulns") or []
                token = page.get("next_page_token")
            key = (p.ecosystem, p.name, p.version)
            ids[key] = sorted({v["id"] for v in found})
            modified.update({v["id"]: v.get("modified", "") for v in found})
            cache.put_query(key, ids[key], ts)
        times.append(ts)

    records: dict[str, dict] = {}
    need = []
    for vid in sorted({i for v in ids.values() for i in v}):
        hit = cache.vuln(vid)
        if hit and (vid not in modified or hit["record"].get("modified", "") >= modified[vid]):
            records[vid] = hit["record"]
        else:
            need.append(vid)

    def get(vid: str):
        rec = _request(client, "GET", f"{OSV_API}/vulns/{vid}")
        if rec is not None:
            cache.put_vuln(vid, rec, _now())
        return vid, rec
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for vid, rec in pool.map(get, need):
            if rec is not None:
                records[vid] = rec
    return ids, records, (min(times) if times else None)


# ---------------------------------------------------------------- assessment

def _same_package(p: Package, affected: dict) -> bool:
    pk = affected.get("package") or {}
    if str(pk.get("ecosystem", "")).split(":")[0] != p.ecosystem:
        return False
    name = str(pk.get("name", ""))
    return _pep503(name) == p.name if p.ecosystem == "PyPI" else name.lower() == p.name.lower()


def fixed_versions(p: Package, rec: dict) -> list[str]:
    """`fixed` events of SEMVER and ECOSYSTEM ranges of the record's entries for this package."""
    return [ev["fixed"] for a in rec.get("affected") or [] if _same_package(p, a)
            for r in a.get("ranges") or [] if r.get("type") in {"SEMVER", "ECOSYSTEM"}
            for ev in r.get("events") or [] if ev.get("fixed")]


def _groups(records: list[dict]) -> list[list[dict]]:
    """Records that share an id or alias describe one advisory."""
    parent = list(range(len(records)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    seen: dict[str, int] = {}
    for i, rec in enumerate(records):
        for name in [rec["id"], *(rec.get("aliases") or [])]:
            if name in seen:
                parent[find(i)] = find(seen[name])
            else:
                seen[name] = i
    out: dict[int, list[dict]] = {}
    for i, rec in enumerate(records):
        out.setdefault(find(i), []).append(rec)
    return list(out.values())


def assess(p: Package, records: list[dict]) -> dict:
    """The advisory facts of one package from the OSV records that affect it."""
    if not records:
        return {"vulnerable": False}
    labels, fixed_all, severities = [], True, []
    for g in sorted(_groups(records), key=lambda g: min(r["id"] for r in g)):
        names = {n for r in g for n in [r["id"], *(r.get("aliases") or [])]}
        ghsa = sorted(r["id"] for r in g if r["id"].startswith("GHSA-")) or sorted(n for n in names if n.startswith("GHSA-"))
        main = (ghsa or sorted(r["id"] for r in g))[0]
        labels += [main] + sorted(n for n in names if n.startswith("CVE-") and n != main)
        fixed_all &= any(is_newer(p.ecosystem, f, p.version) for r in g for f in fixed_versions(p, r))
        ranked = [s for s in (record_severity(r) for r in g if r["id"].startswith("GHSA-")) if s != "unknown"]
        ranked = ranked or [s for s in (record_severity(r) for r in g) if s != "unknown"]
        if ranked:
            severities.append(max(ranked, key=SEVERITIES.index))
    return {"vulnerable": True, "fix_available": bool(fixed_all),
            "max_severity": max(severities, key=SEVERITIES.index) if severities else "unknown",
            "advisories": ", ".join(dict.fromkeys(labels))}


# ---------------------------------------------------------------- entry points

def analyse(repo: str | Path, describes: str | None = None, offline: bool = False, cache_dir: str | Path | None = None) -> dict:
    """Evidence document (engine/normir/evidence.py) with one Dependency element per locked package."""
    root = Path(repo).resolve()
    lockfiles, packages = inventory(root)
    source = {"id": SOURCE, "kind": "lockfile_osv", "describes": describes or root.name, "adapter": "adapters.deps",
              "adapter_version": VERSION, "commit": git_commit(root), "lockfiles": lockfiles,
              "osv_queried_at": None, "offline": bool(offline)}
    advice: dict[tuple, dict] = {}
    if not offline and packages:
        with _client() as client:
            ids, records, ts = fetch_advisories(packages, Cache(cache_dir), client)
        source["osv_queried_at"] = _iso(ts) if ts else None
        missing = sorted({i for v in ids.values() for i in v} - records.keys())
        if missing:
            source["osv_missing_records"] = missing
        for p in packages:
            key = (p.ecosystem, p.name, p.version)
            advice[key] = assess(p, [records[i] for i in ids.get(key, []) if i in records])
    elements = []
    for p in packages:
        facts = {"ecosystem": p.ecosystem, "name": p.name, "version": p.version, **advice.get((p.ecosystem, p.name, p.version), {})}
        where = [re.sub(r":(\d+)$", r"#L\1", a) for a in p.at]
        el = {"type": "Dependency", "id": p.id, "at": where[0] if len(where) == 1 else where,
              "facts": {k: [{"value": v, "source": SOURCE, "at": p.at[0]}] for k, v in facts.items()}}
        if p.dev and all(d is True for d in p.dev):
            el["dev"] = True
        elements.append(el)
    return {"subject": {"kind": "system", "id": describes or root.name}, "sources": [source], "facts": {}, "elements": elements}


def advisory_details(ids, cache_dir: str | Path | None = None) -> dict[str, dict]:
    """Report text for advisory ids (GHSA, PYSEC, CVE aliases, ...) from the OSV cache; ids not cached are left out.

    {id: {id, summary, severity, fixed: {"<ecosystem>/<name>": [versions]}, url, aliases, published, modified,
    fetched_at}}. `id` in the value is the OSV record the entry was read from (a GHSA record for a CVE alias where
    one is cached). Entries are returned whatever their age; `fetched_at` says when OSV was asked.
    """
    cache = Cache(cache_dir)
    found: dict[str, dict] = {}
    for vid in ids:
        hit = cache.vuln(vid, fresh_only=False)
        if hit:
            found[vid] = hit
    if len(found) < len(set(ids)):
        index: dict[str, dict] = {}
        for d in cache.all_vulns():
            rec = d["record"]
            for name in [rec.get("id", ""), *(rec.get("aliases") or [])]:
                if name not in index or (rec.get("id", "").startswith("GHSA-") and not index[name]["record"].get("id", "").startswith("GHSA-")):
                    index[name] = d
        found.update({vid: index[vid] for vid in ids if vid not in found and vid in index})
    out = {}
    for vid, d in found.items():
        rec = d["record"]
        fixed: dict[str, list[str]] = {}
        for a in rec.get("affected") or []:
            pk = a.get("package") or {}
            vs = [ev["fixed"] for r in a.get("ranges") or [] if r.get("type") in {"SEMVER", "ECOSYSTEM"}
                  for ev in r.get("events") or [] if ev.get("fixed")]
            if vs:
                fixed.setdefault(f"{pk.get('ecosystem')}/{pk.get('name')}", []).extend(v for v in vs if v not in fixed.get(f"{pk.get('ecosystem')}/{pk.get('name')}", []))
        summary = rec.get("summary") or (rec.get("details") or "").strip().split("\n")[0][:300]
        out[vid] = {"id": rec.get("id"), "summary": summary, "severity": record_severity(rec), "fixed": fixed,
                    "url": f"https://osv.dev/vulnerability/{rec.get('id')}", "aliases": list(rec.get("aliases") or []),
                    "published": rec.get("published"), "modified": rec.get("modified"), "fetched_at": _iso(d["fetched_at"])}
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m adapters.deps", description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", help="path to the repository (read only; nothing in it is executed)")
    ap.add_argument("-o", "--out", help="evidence YAML to write (default: stdout)")
    ap.add_argument("--name", help="subject id (default: the repository directory name)")
    ap.add_argument("--offline", action="store_true", help="list the locked packages only; do not query OSV")
    a = ap.parse_args(argv)
    if not Path(a.repo).is_dir():
        ap.error(f"not a directory: {a.repo}")
    try:
        doc = analyse(a.repo, a.name, offline=a.offline)
    except OSVError as e:
        print(f"adapters.deps: {e}; rerun with --offline for the inventory alone", file=sys.stderr)
        return 2
    text = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=120)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
