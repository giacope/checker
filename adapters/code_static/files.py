"""Which files of a repository are analysed, and how each is classified.

Exclusion rules (generic, by path segment or file name; nothing names a particular repository):
- hidden directories (.git, .github, .vscode, ...) and tool caches;
- dependencies and vendored code: node_modules, bower_components, vendor, vendors, third_party, site-packages, venv,
  and any directory holding a pyvenv.cfg;
- build output: dist, build, out, coverage, .next, .nuxt, .angular, target, __pycache__, generated API clients (*.gen.*);
- database migrations: migrations, alembic/versions;
- tests: test, tests, __tests__, spec, specs, e2e, cypress, playwright, testing, and test files by name
  (test_*.py, *_test.py, tests.py, conftest.py, *.spec.*, *.test.*, *.cy.*);
- documentation and walkthroughs: docs, doc, documentation, solutions, walkthrough, tutorial(s);
- static web assets served as-is (static, public, assets, wwwroot), translation catalogues (i18n, locales, ...);
- minified or bundled files (*.min.js, *.bundle.js, lines over 3000 characters), type declarations (*.d.ts), lock files.
Files named or placed as examples, samples, or fixtures (outside test directories) are read only for Secret
literals, which are then marked test_or_example.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {
    "node_modules", "bower_components", "jspm_packages", "vendor", "vendors", "third_party", "thirdparty", "site-packages",
    "venv", "virtualenv", "dist", "build", "out", "coverage", "target", "__pycache__", "migrations",
    "test", "tests", "__tests__", "__mocks__", "spec", "specs", "e2e", "cypress", "playwright", "testing", "test-results",
    "docs", "doc", "documentation", "solutions", "solution", "walkthrough", "walkthroughs", "tutorial", "tutorials",
    "static", "public", "assets", "wwwroot", "staticfiles", "i18n", "locales", "locale", "translations", "lang",
    "deps", "_build", "tmp", "log",  # Elixir dependencies and build output; Rails tmp/ and log/
}
EXAMPLE_DIRS = {"example", "examples", "sample", "samples", "fixture", "fixtures", "demo-data", "mocks", "mock"}
CODE_EXT = {".py": "py", ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "ts", ".mts": "ts", ".cts": "ts", ".tsx": "tsx",
            ".rb": "rb", ".rake": "rb", ".ex": "ex", ".exs": "ex"}
CONFIG_EXT = {".yml", ".yaml", ".json", ".ini", ".cfg", ".conf", ".toml", ".properties", ".env"}
TEMPLATE_EXT = {".html", ".htm", ".pug", ".jade", ".hbs", ".handlebars", ".ejs", ".njk", ".jinja", ".jinja2", ".j2", ".twig",
                ".erb", ".haml", ".slim", ".heex", ".eex", ".leex", ".sface"}
KEY_EXT = {".pem", ".key"}
LOCK_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "uv.lock", "poetry.lock", "pipfile.lock", "composer.lock",
              "npm-shrinkwrap.json", "bun.lockb", "cargo.lock", "gemfile.lock"}
TEST_FILE = re.compile(r"(^test_.*\.py$|_test\.py$|^tests?\.py$|^conftest\.py$|\.(spec|test|cy|e2e)\.[cm]?[jt]sx?$|^test\.[a-z]+$|"
                       r"_(spec|test)\.rb$|_test\.exs$)", re.I)
EXAMPLE_FILE = re.compile(r"(^|[._\-])(example|sample|template|dist|fixture|fixtures|mock|dummy)([._\-]|$)", re.I)
EXAMPLE_CODE_FILE = re.compile(r"(^|[._\-])(example|sample|fixture|fixtures|mock|mocks|dummy)([._\-]|$)", re.I)
CLIENT_DIRS = {"frontend", "client", "clients", "web", "webapp", "ui", "browser", "spa", "app-ui"}
MAX_BYTES = 1_000_000


@dataclass(frozen=True)
class SourceFile:
    rel: str          # path relative to the repository root, with forward slashes
    abs: Path
    kind: str         # py | js | ts | tsx | config | template | key
    example: bool     # example, sample, or fixture: only Secret literals are read, marked test_or_example
    client: bool      # front-end code (runs in the browser)


def _skip_dir(path: Path, rel_parts: tuple[str, ...], name: str) -> bool:
    low = name.lower()
    if name.startswith("."):
        return True
    if low in SKIP_DIRS:
        return True
    if (path / name / "pyvenv.cfg").exists():
        return True  # a virtual environment under any name
    if low == "versions" and rel_parts and rel_parts[-1].lower() == "alembic":
        return True
    return False


def discover(root: Path) -> list[SourceFile]:
    out: list[SourceFile] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root)
        parts = rel_dir.parts
        dirnames[:] = sorted(d for d in dirnames if not _skip_dir(Path(dirpath), parts, d) and not os.path.islink(os.path.join(dirpath, d)))
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            if p.is_symlink() or not p.is_file():
                continue
            low = fn.lower()
            ext = p.suffix.lower()
            if low in LOCK_FILES or low.endswith((".min.js", ".bundle.js", ".d.ts", ".map")) or re.search(r"\.gen\.[jt]sx?$", low):
                continue
            if TEST_FILE.search(fn) and ext in CODE_EXT:
                continue
            if low.startswith(".env") or low.endswith(".env"):
                kind = "config"
            elif ext in CODE_EXT:
                kind = CODE_EXT[ext]
            elif ext in CONFIG_EXT:
                if low in {"package.json", "tsconfig.json", "jsconfig.json"} or low.startswith(("tsconfig", ".eslintrc", ".prettierrc")):
                    continue
                kind = "config"
            elif ext in TEMPLATE_EXT:
                kind = "template"
            elif ext in KEY_EXT:
                kind = "key"
            else:
                continue
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                continue
            rel = "/".join(parts + (fn,))
            lowparts = [x.lower() for x in parts]
            stem = low if low.startswith(".env") else Path(low).stem
            name_rule = EXAMPLE_FILE if kind == "config" else EXAMPLE_CODE_FILE
            example = bool(set(lowparts) & EXAMPLE_DIRS) or bool(name_rule.search(stem)) or (TEST_FILE.search(fn) is not None)
            client = kind not in {"rb", "ex"} and (bool(set(lowparts) & CLIENT_DIRS) or ext in {".tsx", ".jsx"})  # Ruby and Elixir run on the server
            out.append(SourceFile(rel, p, kind, example, client))
    return out


def read_text(f: SourceFile) -> str | None:
    try:
        data = f.abs.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:4096]:
        return None
    text = data.decode("utf-8", errors="replace")
    if f.kind in {"js", "ts", "tsx"} and any(len(line) > 3000 for line in text.splitlines()):
        return None  # minified or bundled
    return text
