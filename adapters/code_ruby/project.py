"""What a Rails application declares about itself: gem versions (Gemfile.lock), gem groups (Gemfile), the Rails and Ruby
versions, `config.load_defaults`, per-environment configuration, and the database schema.

Everything is read as text or parsed with tree-sitter; no Ruby is run, so configuration that is computed at boot (a
value read from ENV, a method call) is left unknown rather than guessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from tree_sitter import Node

from .rb import RbFile, args, field as tfield, method_name, parts, sym_or_str, text, walk


def version(s: str | None) -> tuple[int, ...] | None:
    if not s:
        return None
    m = re.match(r"(\d+(?:\.\d+)*)", s.strip())
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


@dataclass
class Setting:
    key: str          # dotted name after `config.`: "force_ssl", "action_controller.default_protect_from_forgery"
    value: Node       # the assigned value, or the call node for `config.session_store :cookie_store, ...`
    at: str
    file: RbFile
    op: str = "="     # "=", "+=", "<<", or "call"


@dataclass
class Project:
    root: Path
    prefix: str = ""                                   # the Rails application's directory ("" or "sub/dir/")
    gems: dict[str, str] = field(default_factory=dict)            # Gemfile.lock: name -> version
    gem_groups: dict[str, set[str]] = field(default_factory=dict)  # Gemfile: name -> groups ("default" when none)
    gem_at: dict[str, str] = field(default_factory=dict)          # Gemfile: name -> locator
    ruby: tuple | None = None
    settings: dict[str, list[Setting]] = field(default_factory=dict)  # env ("all", "production", ...) -> settings
    tables: dict[str, dict[str, tuple[str, str]]] = field(default_factory=dict)  # table -> column -> (type, locator)
    is_rails: bool = False

    # ---------------------------------------------------------------- versions

    @property
    def rails(self) -> tuple | None:
        for g in ("rails", "railties", "actionpack", "activerecord"):
            if g in self.gems:
                return version(self.gems[g])
        return None

    def gem(self, name: str) -> tuple | None:
        return version(self.gems.get(name))

    @property
    def load_defaults(self) -> tuple[float | None, str | None]:
        s = self.setting("load_defaults")
        if s is None:
            return None, None
        pos, _ = args(s.value) if s.value.type == "call" else ([], {})
        if pos and re.fullmatch(r"\d+(\.\d+)?", text(pos[0]).strip("\"'")):
            return float(text(pos[0]).strip("\"'")), s.at
        return None, s.at

    def defaults_at_least(self, v: float) -> bool:
        """`config.load_defaults` is at least `v` (a newer framework default applies)."""
        ld, _ = self.load_defaults
        return ld is not None and ld >= v

    def psych_safe_load(self) -> bool | None:
        """`YAML.load` restricts classes: Psych 4 (Ruby 3.1 bundles it), unless the lock file pins an older Psych."""
        p = self.gem("psych")
        if p is not None:
            return p >= (4,)
        if self.ruby is not None:
            return self.ruby >= (3, 1)
        return None

    # ---------------------------------------------------------------- settings

    def setting(self, key: str, env: str = "production") -> Setting | None:
        """The effective value of `config.<key>` in an environment: the environment file wins over application.rb
        and initializers; the last assignment wins."""
        for scope in (env, "all"):
            got = [s for s in self.settings.get(scope, []) if s.key == key]
            if got:
                return got[-1]
        return None

    def all_settings(self, key: str, env: str = "production") -> list[Setting]:
        return [s for scope in ("all", env) for s in self.settings.get(scope, []) if s.key == key]

    def env_file(self, env: str) -> str | None:
        rel = f"{self.prefix}config/environments/{env}.rb"
        return rel if (self.root / rel).is_file() else None

    def gem_in_production(self, name: str) -> bool:
        groups = self.gem_groups.get(name)
        return groups is not None and bool(groups & {"default", "production"})

    # ---------------------------------------------------------------- loading

    def load(self, rb_files: list[RbFile], parse):
        apps = sorted((f.sf.rel for f in rb_files if f.sf.rel.endswith("config/application.rb")), key=lambda r: (r.count("/"), r))
        if apps:
            self.prefix = apps[0][: -len("config/application.rb")]
            self.is_rails = True
        base = self.root / self.prefix if self.prefix else self.root
        self._lock(base / "Gemfile.lock")
        self._gemfile(base / "Gemfile", parse)
        if self.ruby is None:
            rv = base / ".ruby-version"
            if rv.is_file():
                self.ruby = version(rv.read_text(errors="replace").strip().removeprefix("ruby-"))
        for f in rb_files:
            rel = f.sf.rel[len(self.prefix):] if f.sf.rel.startswith(self.prefix) else None
            if rel is None or f.sf.example:
                continue
            if rel == "config/application.rb" or rel.startswith("config/initializers/"):
                self._settings(f, "all")
            elif rel.startswith("config/environments/") and rel.endswith(".rb"):
                self._settings(f, rel[len("config/environments/"):-3])
            elif rel == "db/schema.rb":
                self._schema_rb(f)
        sql = base / "db" / "structure.sql"
        if not self.tables and sql.is_file() and sql.stat().st_size < 20_000_000:
            self._structure_sql(sql.read_text(errors="replace"), f"{self.prefix}db/structure.sql")

    def _lock(self, p: Path):
        if not p.is_file():
            return
        section = None
        lines = p.read_text(errors="replace").splitlines()
        for i, ln in enumerate(lines):
            if ln and not ln.startswith(" "):
                section = ln.strip()
                continue
            m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)$", ln)
            if m and section in {"GEM", "GIT", "PATH"}:
                self.gems.setdefault(m.group(1), m.group(2).split("-")[0])
            if section == "RUBY VERSION" and ln.strip().startswith("ruby "):
                self.ruby = version(ln.strip()[5:])

    def _gemfile(self, p: Path, parse):
        if not p.is_file():
            return
        src = p.read_text(errors="replace")
        tree = parse(src)
        rel = str(p.relative_to(self.root)).replace("\\", "/")
        for n in walk(tree.root_node):
            if n.type != "call" or method_name(n) != "gem" or tfield(n, "receiver") is not None:
                continue
            pos, kws = args(n)
            name = sym_or_str(pos[0]) if pos else None
            if not name:
                continue
            groups: set[str] = set()
            for k in ("group", "groups"):
                if k in kws:
                    v = kws[k]
                    groups |= {sym_or_str(x) or "" for x in ([v] if v.type != "array" else v.named_children)}
            a = n.parent
            while a is not None:
                if a.type in {"do_block", "block"} and a.parent is not None and a.parent.type == "call" and method_name(a.parent) == "group":
                    gp, _ = args(a.parent)
                    groups |= {sym_or_str(x) or "" for x in gp}
                a = a.parent
            if self.ruby is None and name == "ruby":
                continue
            self.gem_groups[name] = (groups - {""}) or {"default"}
            self.gem_at[name] = f"{rel}:{n.start_point[0] + 1}"
        if self.ruby is None:
            m = re.search(r"^\s*ruby\s+[\"']([\d.]+)", src, re.M)
            if m:
                self.ruby = version(m.group(1))

    def _settings(self, f: RbFile, env: str):
        for n in walk(f.root):
            if n.type in {"assignment", "operator_assignment"}:
                left, right = tfield(n, "left"), tfield(n, "right")
                key = _config_key(left)
                if key and right is not None:
                    op = "=" if n.type == "assignment" else text(tfield(n, "operator")) or "+="
                    self.settings.setdefault(env, []).append(Setting(key, right, f.at(n), f, op))
            elif n.type == "call":
                recv = tfield(n, "receiver")
                m = method_name(n)
                if recv is None or not m:
                    continue
                p = n.parent
                if p is not None and ((p.type in {"assignment", "operator_assignment"} and tfield(p, "left") is not None
                                       and tfield(p, "left").id == n.id)
                                      or (p.type == "call" and tfield(p, "receiver") is not None and tfield(p, "receiver").id == n.id)
                                      or (p.type == "binary" and tfield(p, "left") is not None and tfield(p, "left").id == n.id)):
                    continue  # part of a longer setting
                base = _config_key(recv, allow_root=True)
                if base is None:
                    continue
                key = f"{base}.{m}" if base else m
                if m == "<<":
                    continue
                self.settings.setdefault(env, []).append(Setting(key, n, f.at(n), f, "call"))
            elif n.type == "binary" and text(tfield(n, "operator")) == "<<":
                key = _config_key(tfield(n, "left"))
                if key:
                    self.settings.setdefault(env, []).append(Setting(key, tfield(n, "right"), f.at(n), f, "<<"))

    def _schema_rb(self, f: RbFile):
        for n in walk(f.root):
            if n.type == "call" and method_name(n) == "create_table" and tfield(n, "receiver") is None:
                pos, _ = args(n)
                table = sym_or_str(pos[0]) if pos else None
                blk = tfield(n, "block")
                if not table or blk is None:
                    continue
                cols = self.tables.setdefault(table, {})
                for c in walk(blk):
                    if c.type == "call" and tfield(c, "receiver") is not None and tfield(c, "receiver").type == "identifier":
                        cp, _ = args(c)
                        col = sym_or_str(cp[0]) if cp else None
                        typ = method_name(c)
                        if col and typ not in {"index", "timestamps", "references", "belongs_to"}:
                            cols[col] = (typ, f.at(c))
                        elif col and typ in {"references", "belongs_to"}:
                            cols[f"{col}_id"] = ("integer", f.at(c))

    def _structure_sql(self, sql: str, rel: str):
        for m in re.finditer(r"CREATE TABLE\s+(?:IF NOT EXISTS\s+)?(?:[\w\"`]+\.)?[\"`]?(\w+)[\"`]?\s*\((.*?)\n\);", sql, re.S | re.I):
            table = m.group(1)
            cols = self.tables.setdefault(table, {})
            start_line = sql.count("\n", 0, m.start(2)) + 1
            for i, ln in enumerate(m.group(2).splitlines()):
                cm = re.match(r"\s*[\"`]?(\w+)[\"`]?\s+([a-zA-Z ]+?)(?:\(|\s|,|$)", ln)
                if cm and cm.group(1).upper() not in {"CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN", "KEY"}:
                    typ = cm.group(2).strip().lower()
                    typ = "string" if any(x in typ for x in ("char", "text", "citext")) else typ
                    cols[cm.group(1)] = (typ, f"{rel}:{start_line + i}")

    # ---------------------------------------------------------------- models

    def table_for(self, model: str) -> str | None:
        """`User` -> users, `PaidTimeOff` -> paid_time_offs, `Api::V1::User` -> users."""
        base = model.split("::")[-1]
        snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", base).lower()
        for cand in (_plural(snake), snake, snake + "s"):
            if cand in self.tables:
                return cand
        return None

    def column_type(self, col: str) -> set[str]:
        return {cols[col][0] for cols in self.tables.values() if col in cols}


def _plural(s: str) -> str:
    if re.search(r"[^aeiou]y$", s):
        return s[:-1] + "ies"
    if re.search(r"(s|x|z|ch|sh)$", s):
        return s + "es"
    return s + "s"


def _config_key(n: Node | None, allow_root: bool = False) -> str | None:
    """`config.action_controller.allow_forgery_protection` -> "action_controller.allow_forgery_protection";
    `Rails.application.config.session_store` -> "session_store". With allow_root, bare `config` -> ""."""
    if n is None:
        return None
    ps = parts(n)
    if "config" not in ps or n.type not in {"call", "identifier"}:
        return None
    i = len(ps) - 1 - ps[::-1].index("config")
    if i > 0 and ps[i - 1] in {"I18n", "Sentry", "Rack", "SecureHeaders"}:
        return None
    rest = ps[i + 1:]
    if not rest:
        return "" if allow_root else None
    return ".".join(rest)
