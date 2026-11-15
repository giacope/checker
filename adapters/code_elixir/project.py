"""Project-level Elixir facts read from the tree: Mix dependencies and their locked versions, Config entries per
environment, and Phoenix routers (pipelines, scopes, routes).

mix.exs, mix.lock, and config/*.exs are Elixir code; they are parsed, never evaluated. A config value that is not a
literal (System.get_env/1, a variable) is kept as a node and read as unknown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .syntax import (L, T, arguments, atom, block_body, do_block, kids, kw, op, string, target,
                     word_list)

LOCK_LINE = re.compile(r'^\s*"(?P<key>[^"]+)":\s*\{:hex,\s*:"?(?P<name>[A-Za-z0-9_]+)"?,\s*"(?P<version>[^"]+)"')


def parse_version(v: str | None) -> tuple:
    if not v:
        return ()
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", v)
    return tuple(int(x) for x in m.groups() if x is not None) if m else ()


@dataclass
class Deps:
    declared: dict = field(default_factory=dict)  # name -> mix.exs locator
    locked: dict = field(default_factory=dict)    # name -> (version, mix.lock locator)

    def has(self, name: str) -> bool:
        return name in self.declared or name in self.locked

    def version(self, name: str) -> tuple:
        return parse_version(self.locked.get(name, (None, None))[0])

    def lock_at(self, name: str) -> str | None:
        return self.locked.get(name, (None, None))[1]


def read_deps(root, ex_files) -> Deps:
    d = Deps()
    for ef in ex_files:
        if ef.rel.rsplit("/", 1)[-1] != "mix.exs":
            continue
        for mod in ef.modules:
            for f in mod.funcs:
                if f.name != "deps":
                    continue
                for st in f.body:
                    for item in kids(st) if st.type == "list" else []:
                        if item.type == "tuple" and kids(item) and atom(kids(item)[0]):
                            d.declared.setdefault(atom(kids(item)[0]), f"{ef.rel}:{L(item)}")
    for lock in sorted(root.glob("mix.lock")) + sorted(root.glob("apps/*/mix.lock")):
        if not lock.is_file() or lock.stat().st_size > 5_000_000:
            continue
        rel = lock.relative_to(root).as_posix()
        for i, line in enumerate(lock.read_text(errors="replace").splitlines(), 1):
            m = LOCK_LINE.match(line)
            if m:
                d.locked.setdefault(m["name"], (m["version"], f"{rel}:{i}"))
    return d


# ---------------------------------------------------------------- config

FILE_ENV = {"config.exs": "all", "runtime.exs": "all", "releases.exs": "prod", "prod.exs": "prod", "dev.exs": "dev",
            "test.exs": "test"}
FILE_ORDER = {"config.exs": 0, "prod.exs": 1, "releases.exs": 2, "runtime.exs": 3}
PROD_ENVS = {"all", "prod"}


@dataclass
class ConfigEntry:
    rel: str
    env: str           # all | prod | dev | test | <other file stem>
    order: int         # precedence: config.exs < prod.exs < runtime.exs
    app: str
    key: str | None    # module alias or atom key (`config :app, App.Repo, ...`), None for `config :app, k: v`
    value: object      # the keyword list (or other value) node
    node: object

    @property
    def at(self) -> str:
        return f"{self.rel}:{L(self.node)}"

    def get(self, name: str):
        return kw(self.value).get(name)

    @property
    def prod(self) -> bool:
        return self.env in PROD_ENVS


def _env_of_condition(cond) -> str | None:
    t = T(cond).replace(" ", "")
    m = re.search(r"(?:config_env\(\)|Mix\.env\(\))==:(\w+)", t)
    if m:
        return m.group(1)
    m = re.search(r"(?:config_env\(\)|Mix\.env\(\))!=:(\w+)", t)
    if m:
        return "all" if m.group(1) in {"dev", "test"} else "notprod"
    return None


def config_entries(ex_files) -> list[ConfigEntry]:
    out = []
    for ef in ex_files:
        parts = ef.rel.split("/")
        if "config" not in parts[:-1] or not ef.rel.endswith(".exs"):
            continue
        name = parts[-1]
        env = FILE_ENV.get(name, name[:-4])
        order = FILE_ORDER.get(name, 1 if env == "prod" else 0)

        def visit(stmts, env):
            for s in stmts:
                if s.type != "call" or target(s) is None or target(s).type != "identifier":
                    continue
                t = T(target(s))
                if t == "config":
                    args = arguments(s)
                    if not args or atom(args[0]) is None:
                        continue
                    app = atom(args[0])
                    if len(args) == 2:
                        out.append(ConfigEntry(ef.rel, env, order, app, None, args[1], s))
                    elif len(args) >= 3:
                        k = atom(args[1]) if atom(args[1]) is not None else T(args[1])
                        out.append(ConfigEntry(ef.rel, env, order, app, k, args[2], s))
                elif t in {"if", "unless"}:
                    a = arguments(s)
                    cond_env = _env_of_condition(a[0]) if a else None
                    if t == "unless" and cond_env:
                        cond_env = "notprod" if cond_env == "prod" else ("all" if cond_env in {"dev", "test"} else None)
                    inner = cond_env if cond_env and env == "all" else env
                    visit(block_body(s), inner)
        visit(kids(ef.tree.root_node), env)
    return out


def effective(entries: list[ConfigEntry], pred) -> list[tuple[ConfigEntry, object]]:
    """(entry, value) pairs for a setting in production, highest precedence last; `pred(entry)` -> value node or None."""
    found = [(e, pred(e)) for e in entries if e.prod]
    found = [(e, v) for e, v in found if v is not None]
    return sorted(found, key=lambda x: (x[0].order, L(x[0].node)))


# ---------------------------------------------------------------- router

HTTP_VERBS = {"get", "post", "put", "patch", "delete", "options", "head", "match"}
WRITE_VERBS = {"post", "put", "patch", "delete", "match"}


@dataclass
class Plug:
    target: str      # ":protect_from_forgery" or "Plug.SSL" (alias-resolved)
    opts: list
    node: object
    when: object = None

    @property
    def line(self) -> int:
        return L(self.node)


@dataclass
class Route:
    verb: str
    path: str
    controller: str | None
    action: str | None
    pipelines: list
    node: object
    rel: str
    actions: list = field(default_factory=list)   # resources: the actions it defines

    @property
    def at(self) -> str:
        return f"{self.rel}:{L(self.node)}"


@dataclass
class Router:
    module: object
    pipelines: dict = field(default_factory=dict)   # name -> [Plug]
    pipeline_nodes: dict = field(default_factory=dict)
    routes: list = field(default_factory=list)


def plug_of(mod, call) -> Plug | None:
    args = arguments(call)
    if not args:
        return None
    t = args[0]
    when = None
    if op(t) == "when":
        when, t = t.child_by_field_name("right"), t.child_by_field_name("left")
    opts = list(args[1:])
    if opts and op(opts[-1]) == "when":
        when = opts[-1].child_by_field_name("right")
        opts[-1] = opts[-1].child_by_field_name("left")
    if t.type == "atom":
        name = T(t)
    elif t.type == "alias":
        name = mod.resolve(T(t))
    else:
        return None
    return Plug(name, opts, call, when)


RESOURCE_ACTIONS = ["index", "edit", "new", "show", "create", "update", "delete"]


def read_router(mod) -> Router:
    r = Router(mod)
    rel = mod.file.rel

    def visit(stmts, prefix: str, alias: str | None, pipes: list):
        pipes = list(pipes)
        for s in stmts:
            if s.type != "call" or target(s) is None or target(s).type != "identifier":
                continue
            t = T(target(s))
            args = arguments(s)
            if t == "pipeline" and args and atom(args[0]):
                r.pipelines[atom(args[0])] = [p for p in (plug_of(mod, x) for x in block_body(s)
                                                          if x.type == "call" and T(target(x)) == "plug") if p]
                r.pipeline_nodes[atom(args[0])] = s
            elif t == "pipe_through" and args:
                names = word_list(args[0]) if args[0].type == "list" else ([atom(args[0])] if atom(args[0]) else [])
                pipes += [n for n in names or [] if n]
            elif t == "scope":
                path, sub_alias = prefix, alias
                for a in args:
                    if string(a) is not None:
                        path = prefix.rstrip("/") + "/" + string(a).lstrip("/")
                    elif a.type == "alias":
                        sub_alias = f"{alias}.{T(a)}" if alias else mod.resolve(T(a))
                    elif a.type in {"keywords", "list"}:
                        k = kw(a)
                        if string(k.get("path")) is not None:
                            path = prefix.rstrip("/") + "/" + string(k["path"]).lstrip("/")
                        if k.get("alias") is not None and k["alias"].type == "alias":
                            sub_alias = f"{alias}.{T(k['alias'])}" if alias else T(k["alias"])
                visit(block_body(s), path, sub_alias, pipes)
            elif t in HTTP_VERBS | {"live", "resources", "forward"} and args:
                path = string(args[0]) if string(args[0]) is not None else (string(args[1]) if t == "match" and len(args) > 1 else None)
                rest = args[1:] if t != "match" else args[2:]
                if path is None:
                    continue
                ctrl = next((a for a in rest if a.type == "alias"), None)
                action = next((atom(a) for a in rest if atom(a) is not None), None)
                full_ctrl = (f"{alias}.{T(ctrl)}" if alias else mod.resolve(T(ctrl))) if ctrl is not None else None
                route = Route(t, prefix.rstrip("/") + "/" + path.lstrip("/"), full_ctrl, action, pipes, s, rel)
                if t == "resources":
                    acts = list(RESOURCE_ACTIONS)
                    opts = kw(rest[-1]) if rest and rest[-1].type in {"keywords", "list"} else {}
                    if opts.get("only") is not None:
                        acts = [a for a in (word_list(opts["only"]) or []) if a in RESOURCE_ACTIONS]
                    if opts.get("except") is not None:
                        acts = [a for a in acts if a not in (word_list(opts["except"]) or [])]
                    route.actions = acts
                r.routes.append(route)
                if do_block(s) is not None:  # resources with nested routes
                    visit(block_body(s), route.path, alias, pipes)
            elif t in {"live_session"}:
                visit(block_body(s), prefix, alias, pipes)
            elif t in {"if", "unless"}:
                visit(block_body(s), prefix, alias, pipes)
    body = []
    for s in kids(do_block(mod.node)) if do_block(mod.node) is not None else []:
        body.append(s)
    visit(body, "", None, [])
    return r


def route_writes(route: Route) -> bool:
    if route.verb == "resources":
        return any(a in {"create", "update", "delete"} for a in route.actions)
    return route.verb in WRITE_VERBS

