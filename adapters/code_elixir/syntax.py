"""Elixir syntax trees (tree-sitter, parsing only) and the project index: modules, aliases, attributes, functions.

Nothing is evaluated: literals are read from the tree, module attributes and aliases are resolved by name within
their module, and a call's callee is the alias-expanded dotted name written in the source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import tree_sitter as ts
import tree_sitter_elixir as tsex

LANGUAGE = ts.Language(tsex.language())
DEF_KEYWORDS = {"def", "defp"}


def parser() -> ts.Parser:
    return ts.Parser(LANGUAGE)


def T(n) -> str:
    return n.text.decode("utf-8", "replace") if n is not None else ""


def L(n) -> int:
    return n.start_point[0] + 1


def kids(n) -> list:
    return [c for c in n.named_children if c.type != "comment"] if n is not None else []


def walk(n):
    """Every node under `n`, in source order (comments included; they have no children)."""
    stack = [n]
    while stack:
        x = stack.pop()
        yield x
        stack.extend(reversed(x.children))


def op(n) -> str | None:
    if n is None or n.type != "binary_operator":
        return None
    o = n.child_by_field_name("operator")
    return T(o) if o is not None else None


def unary(n) -> str | None:
    if n is None or n.type != "unary_operator":
        return None
    o = n.child_by_field_name("operator")
    return T(o) if o is not None else None


def same(a, b) -> bool:
    return a is not None and b is not None and a.id == b.id


# ---------------------------------------------------------------- calls

def target(n):
    return n.child_by_field_name("target") if n is not None and n.type == "call" else None


def arguments(n) -> list:
    """Explicit arguments of a call (a trailing keyword list is one argument)."""
    for c in n.children:
        if c.type == "arguments":
            return kids(c)
    return []


def has_parens(n) -> bool:
    return any(c.type == "arguments" for c in n.children)


def do_block(n):
    for c in n.children:
        if c.type == "do_block":
            return c
    return None


def piped_into(n):
    """The left side of `x |> f(...)` when `n` is that f(...) call."""
    p = n.parent
    if p is not None and op(p) == "|>" and same(p.child_by_field_name("right"), n):
        return p.child_by_field_name("left")
    return None


def call_args(n) -> list:
    """Arguments as the callee sees them: the piped value first."""
    left = piped_into(n)
    return ([left] if left is not None else []) + arguments(n)


def block_body(n) -> list:
    """Statements of a call's do-block, or of its `do:` keyword."""
    b = do_block(n)
    if b is not None:
        return [c for c in kids(b) if c.type not in {"rescue_block", "catch_block", "else_block", "after_block", "stab_clause"}]
    args = arguments(n)
    if args and args[-1].type == "keywords":
        v = kw(args[-1]).get("do")
        return [v] if v is not None else []
    return []


# ---------------------------------------------------------------- literals

def kw(n) -> dict:
    """{key: value node} of a keyword list (`[a: 1]` or trailing `a: 1`)."""
    if n is None:
        return {}
    if n.type == "list":
        ks = kids(n)
        if len(ks) == 1 and ks[0].type == "keywords":
            n = ks[0]
        else:
            out = {}
            for k in ks:  # [{:a, 1}, ...]
                if k.type == "tuple" and len(kids(k)) == 2 and atom(kids(k)[0]) is not None:
                    out.setdefault(atom(kids(k)[0]), kids(k)[1])
            return out
    if n.type != "keywords":
        return {}
    out = {}
    for p in kids(n):
        if p.type != "pair":
            continue
        k, v = p.child_by_field_name("key"), p.child_by_field_name("value")
        if k is None or v is None:
            continue
        name = T(k).strip().rstrip(":").strip().strip('"')
        out.setdefault(name, v)
    return out


def kw_pairs(n) -> list:
    """[(key, key node, value node)] of a keyword list, in order."""
    if n is not None and n.type == "list":
        ks = kids(n)
        n = ks[0] if len(ks) == 1 and ks[0].type == "keywords" else None
    if n is None or n.type != "keywords":
        return []
    out = []
    for p in kids(n):
        k, v = p.child_by_field_name("key"), p.child_by_field_name("value")
        if k is not None and v is not None:
            out.append((T(k).strip().rstrip(":").strip().strip('"'), k, v))
    return out


def string(n) -> str | None:
    """The text of a string, charlist, or ~s/~S/~c sigil literal without interpolation."""
    if n is None:
        return None
    if n.type in {"string", "charlist"}:
        parts = []
        for c in n.named_children:
            if c.type == "interpolation":
                return None
            if c.type in {"quoted_content", "escape_sequence"}:
                parts.append(T(c))
        return "".join(parts)
    if n.type == "sigil":
        name = next((T(c) for c in n.named_children if c.type == "sigil_name"), "")
        if name not in {"s", "S", "c", "C"}:
            return None
        if any(c.type == "interpolation" for c in n.named_children):
            return None
        return "".join(T(c) for c in n.named_children if c.type in {"quoted_content", "escape_sequence"})
    return None


def has_interpolation(n) -> bool:
    return n is not None and n.type in {"string", "charlist", "sigil"} and any(c.type == "interpolation" for c in n.named_children)


def interpolations(n) -> list:
    return [kids(c)[0] for c in n.named_children if c.type == "interpolation" and kids(c)] if n is not None else []


def atom(n) -> str | None:
    if n is None:
        return None
    if n.type == "atom":
        return T(n)[1:]
    if n.type == "quoted_atom":
        return T(n)[2:-1]
    return None


def boolean(n) -> bool | None:
    if n is not None and n.type == "boolean":
        return T(n) == "true"
    return None


def integer(n) -> int | None:
    if n is None:
        return None
    if n.type == "integer":
        try:
            return int(T(n).replace("_", ""), 0)
        except ValueError:
            return None
    if op(n) == "*":  # 60 * 60 * 24
        a, b = integer(n.child_by_field_name("left")), integer(n.child_by_field_name("right"))
        return a * b if a is not None and b is not None else None
    return None


def word_list(n) -> list[str] | None:
    """Atoms or strings of a literal list, or of a ~w sigil."""
    if n is None:
        return None
    if n.type == "sigil" and next((T(c) for c in n.named_children if c.type == "sigil_name"), "") in {"w", "W"}:
        content = next((c for c in n.named_children if c.type == "quoted_content"), None)
        return T(content).split() if content is not None else []
    if n.type == "list":
        out = []
        for k in kids(n):
            v = atom(k) if atom(k) is not None else string(k)
            if v is None:
                return None
            out.append(v)
        return out
    return None


# ---------------------------------------------------------------- index

@dataclass(eq=False)
class Func:
    module: "Module"
    name: str
    node: object            # the def call
    params: list            # parameter pattern nodes
    body: list              # statement nodes (or the do: value)
    private: bool
    arity: int
    min_arity: int

    @property
    def line(self) -> int:
        return L(self.node)

    @property
    def key(self) -> tuple:
        return (self.module.file.rel, self.line, self.name)


@dataclass(eq=False)
class Module:
    name: str
    file: "ExFile"
    node: object
    aliases: dict = field(default_factory=dict)     # short name -> full dotted name
    imports: list = field(default_factory=list)      # full dotted names
    uses: list = field(default_factory=list)         # [(module, [arg nodes], node)]
    attrs: dict = field(default_factory=dict)        # name -> [value nodes] in order
    funcs: list = field(default_factory=list)
    plugs: list = field(default_factory=list)        # [(target node, [opt nodes], plug call node)] at module level
    statements: list = field(default_factory=list)   # module-level statements (outside functions)

    def uses_any(self, *names) -> bool:
        return any(u[0] in names or any(u[0].endswith("." + n) for n in names) for u in self.uses)

    def use_arg_atoms(self) -> set[str]:
        return {atom(a) for u in self.uses for a in u[1] if atom(a)}

    def attr(self, name: str, before_line: int | None = None):
        vals = self.attrs.get(name) or []
        if before_line is not None:
            earlier = [v for v in vals if L(v) <= before_line]
            vals = earlier or vals
        return vals[-1] if vals else None

    def resolve(self, dotted: str) -> str:
        if dotted == "__MODULE__":
            return self.name
        head, _, rest = dotted.partition(".")
        if head == "__MODULE__":
            return self.name + ("." + rest if rest else "")
        if head in self.aliases:
            return self.aliases[head] + ("." + rest if rest else "")
        return dotted


@dataclass(eq=False)
class ExFile:
    rel: str
    tree: object
    text: str
    sf: object
    modules: list = field(default_factory=list)
    script: Module | None = None   # top-level code outside any defmodule (config files, mix.exs, scripts)


def _func_head(def_call):
    args = arguments(def_call)
    if not args:
        return None, [], []
    head = args[0]
    if op(head) == "when":
        head = head.child_by_field_name("left")
    if head is None:
        return None, [], []
    if head.type == "identifier":
        return T(head), [], block_body(def_call)
    if head.type == "call" and target(head) is not None and target(head).type == "identifier":
        return T(target(head)), arguments(head), block_body(def_call)
    return None, [], []


def _module_name(n) -> str | None:
    args = arguments(n)
    if args and args[0].type == "alias":
        return T(args[0])
    return None


def _add_alias(mod: Module, n):
    args = arguments(n)
    if not args:
        return
    a = args[0]
    opts = kw(args[1]) if len(args) > 1 else {}
    if a.type == "alias" or (a.type == "dot" and T(a).startswith("__MODULE__")):
        full = mod.resolve(T(a))
        short = T(opts["as"]) if "as" in opts and opts["as"].type == "alias" else full.split(".")[-1]
        mod.aliases[short] = full
    elif a.type == "dot":  # alias A.B.{C, D}
        left, right = a.child_by_field_name("left"), a.child_by_field_name("right")
        if left is not None and right is not None and right.type == "tuple":
            base = mod.resolve(T(left))
            for c in kids(right):
                if c.type == "alias":
                    mod.aliases[T(c).split(".")[-1]] = f"{base}.{T(c)}"


def _scan_module(ef: ExFile, mod: Module, stmts: list, out: list):
    for s in stmts:
        if s.type == "unary_operator" and unary(s) == "@":
            operand = s.child_by_field_name("operand")
            if operand is not None and operand.type == "call" and target(operand) is not None and target(operand).type == "identifier":
                vals = arguments(operand)
                if vals:
                    mod.attrs.setdefault(T(target(operand)), []).append(vals[0])
            mod.statements.append(s)
            continue
        if s.type != "call" or target(s) is None:
            mod.statements.append(s)
            continue
        t = target(s)
        name = T(t) if t.type == "identifier" else None
        if name == "defmodule":
            sub = _module_name(s)
            if sub:
                full = sub if mod.name.startswith("<") else f"{mod.name}.{sub}"  # nesting prefixes the name
                inner = Module(full, ef, s)
                if not mod.name.startswith("<"):
                    mod.aliases.setdefault(sub.split(".")[0], f"{mod.name}.{sub.split('.')[0]}")
                    inner.aliases.update(mod.aliases)
                out.append(inner)
                _scan_module(ef, inner, block_body(s), out)
            continue
        if name in DEF_KEYWORDS:
            fname, params, body = _func_head(s)
            if fname:
                defaults = sum(1 for p in params if op(p) == "\\\\")
                mod.funcs.append(Func(mod, fname, s, params, body, name == "defp", len(params), len(params) - defaults))
            continue
        if name in {"defmacro", "defmacrop", "defdelegate", "defguard", "defguardp", "defstruct", "defexception"}:
            mod.statements.append(s)
            continue
        if name == "alias":
            _add_alias(mod, s)
        elif name == "import":
            a = arguments(s)
            if a and a[0].type == "alias":
                mod.imports.append(mod.resolve(T(a[0])))
        elif name == "use":
            a = arguments(s)
            if a and a[0].type == "alias":
                mod.uses.append((mod.resolve(T(a[0])), a[1:], s))
        elif name == "plug":
            a = arguments(s)
            if a:
                mod.plugs.append((a[0], a[1:], s))
        if name in {"if", "unless"} and do_block(s) is not None:
            mod.statements.append(s)
            _scan_module(ef, mod, block_body(s), out)  # `if code_reloading? do plug ... end`
            continue
        mod.statements.append(s)


def index_file(ef: ExFile) -> None:
    root = ef.tree.root_node
    script = Module(f"<script:{ef.rel}>", ef, root)
    mods: list[Module] = []
    _scan_module(ef, script, kids(root), mods)
    ef.modules = mods
    ef.script = script


def module_kind(mod: Module) -> set[str]:
    """controller | live | channel | router | endpoint | schema | repo | mailer | component | view"""
    kinds = set()
    atoms = mod.use_arg_atoms()
    last = mod.name.split(".")[-1]
    if "controller" in atoms or mod.uses_any("Phoenix.Controller") or (last.endswith("Controller") and mod.name.split(".")[0].endswith("Web")):
        kinds.add("controller")
    if atoms & {"live_view", "live_component"} or mod.uses_any("Phoenix.LiveView", "Phoenix.LiveComponent", "Surface.LiveView", "Surface.LiveComponent"):
        kinds.add("live")
    if "channel" in atoms or mod.uses_any("Phoenix.Channel"):
        kinds.add("channel")
    if "router" in atoms or mod.uses_any("Phoenix.Router"):
        kinds.add("router")
    if mod.uses_any("Phoenix.Endpoint"):
        kinds.add("endpoint")
    if mod.uses_any("Ecto.Schema") or any(s.type == "call" and T(target(s)) in {"schema", "embedded_schema"} for s in mod.statements if target(s) is not None):
        kinds.add("schema")
    if mod.uses_any("Ecto.Repo"):
        kinds.add("repo")
    if mod.uses_any("Swoosh.Mailer", "Bamboo.Mailer"):
        kinds.add("mailer")
    if atoms & {"html", "view", "component", "live_component"} or mod.uses_any("Phoenix.Component", "Phoenix.View", "Phoenix.HTML"):
        kinds.add("view")
    return kinds


def callee(mod: Module, n):
    """(segments, kind) of a call: kind is local | remote | erlang | var | attr | anon | None.
    `Repo.get(...)` in a module aliasing MyApp.Repo -> (["MyApp", "Repo", "get"], "remote")."""
    t = target(n)
    if t is None:
        return None, None
    if t.type == "identifier":
        return [T(t)], "local"
    if t.type != "dot":
        return None, None
    left, right = t.child_by_field_name("left"), t.child_by_field_name("right")
    if right is None:
        return None, "anon"   # f.(x)
    fn = T(right)
    if left is None:
        return None, None
    if left.type == "alias" or (left.type == "identifier" and T(left) == "__MODULE__") or (left.type == "dot" and T(left).startswith("__MODULE__")):
        return mod.resolve(T(left)).split(".") + [fn], "remote"
    if left.type == "atom":
        return [T(left), fn], "erlang"
    if left.type == "identifier":
        return [T(left), fn], "var"
    if unary(left) == "@":
        return ["@" + T(left.child_by_field_name("operand")), fn], "attr"
    return None, None


def call_name(mod: Module, n) -> str:
    segs, _ = callee(mod, n)
    return ".".join(segs) if segs else ""


IDENT_RE = re.compile(r"^[a-z_][A-Za-z0-9_]*[?!]?$")


def is_var_ref(n) -> bool:
    """An identifier used as a variable (not a call target, a field name, or a keyword)."""
    if n.type != "identifier" or not IDENT_RE.match(T(n)) or T(n) in {"__MODULE__", "__ENV__", "__CALLER__", "__STACKTRACE__"}:
        return False
    p = n.parent
    if p is None:
        return True
    if p.type == "call" and same(p.child_by_field_name("target"), n):
        return False
    if p.type == "dot" and same(p.child_by_field_name("right"), n):
        return False
    if p.type == "unary_operator" and unary(p) == "@":
        return False
    return True


def pattern_vars(n) -> set[str]:
    """Variables a pattern binds (pinned `^x` and `_x` excluded)."""
    out = set()
    if n is None:
        return out
    for x in walk(n):
        if x.type == "identifier" and is_var_ref(x) and not T(x).startswith("_"):
            p = x.parent
            if p is not None and p.type == "unary_operator" and unary(p) == "^":
                continue
            out.add(T(x))
    return out


def _quoted_statements(n) -> list:
    """Statements inside every `quote do ... end` under `n`."""
    out = []
    for x in walk(n):
        if x.type == "call" and target(x) is not None and T(target(x)) == "quote" and do_block(x) is not None:
            out += block_body(x)
    return out


def expand_uses(modules: dict, depth: int = 3) -> None:
    """Apply what `use` of a project module injects: the alias, import, and use statements quoted by its
    `__using__/1` macro, or by the function a `use MyAppWeb, :controller` atom names (the Phoenix web module idiom).
    Aliases and imports the module writes itself take precedence."""
    def injected(target_mod: Module, args: list) -> list:
        stmts = []
        names = {atom(a) for a in args if atom(a)}
        for x in walk(target_mod.node):
            if x.type == "call" and target(x) is not None and T(target(x)) == "defmacro":
                head = arguments(x)[0] if arguments(x) else None
                if head is not None and op(head) == "when":
                    head = head.child_by_field_name("left")
                if head is not None and T(target(head) if head.type == "call" else head) == "__using__":
                    stmts += _quoted_statements(x)
        for f in target_mod.funcs:
            if f.name in names:
                stmts += _quoted_statements(f.node)
        return stmts

    for mod in list(modules.values()):
        seen = set()
        queue = [(u[0], u[1], 0) for u in mod.uses]
        while queue:
            name, args, d = queue.pop(0)
            t = modules.get(name)
            if t is None or (name, tuple(T(a) for a in args)) in seen or d >= depth:
                continue
            seen.add((name, tuple(T(a) for a in args)))
            for s in injected(t, args):
                if s.type != "call" or target(s) is None or target(s).type != "identifier":
                    continue
                kind = T(target(s))
                a = arguments(s)
                if kind == "alias" and a:
                    tmp = Module(t.name, t.file, t.node, aliases=dict(t.aliases))
                    _add_alias(tmp, s)
                    for k, v in tmp.aliases.items():
                        if k not in t.aliases or t.aliases[k] != v:
                            mod.aliases.setdefault(k, v)
                elif kind == "import" and a and a[0].type == "alias":
                    full = t.resolve(T(a[0]))
                    if full not in mod.imports:
                        mod.imports.append(full)
                elif kind == "use" and a and a[0].type == "alias":
                    full = t.resolve(T(a[0]))
                    mod.uses.append((full, a[1:], s))
                    queue.append((full, a[1:], d + 1))
