"""Ruby source with tree-sitter (parsing only; nothing is loaded, required, or executed): node helpers, methods,
local bindings, and request taint."""

from __future__ import annotations

import re

import tree_sitter_ruby
from tree_sitter import Language, Node, Parser

from adapters.code_static.files import SourceFile

LANGUAGE = Language(tree_sitter_ruby.language())

# Request data in a Rails controller. `session` and signed/encrypted cookies are not: the client cannot forge them.
SOURCE_IDENTS = {"params", "cookies"}
REQUEST_DATA = {"params", "parameters", "body", "raw_post", "query_string", "query_parameters", "request_parameters",
                "path_parameters", "headers", "env", "cookies", "cookie_jar", "path", "fullpath", "original_fullpath", "url",
                "original_url", "referer", "referrer", "user_agent", "host", "host_with_port", "authorization", "GET", "POST",
                "filtered_parameters", "content_type", "raw_host_with_port"}
# Calls whose result request data cannot steer into a string (a number, a boolean, a size).
NON_STRING = {"ids", "to_i", "to_f", "to_r", "to_c", "size", "length", "count", "bytesize", "id", "hash", "to_sym", "class",
              "object_id", "positive?", "negative?", "zero?", "abs", "round", "floor", "ceil"}
SAFE_FUNCS = {"Integer", "Float", "Rational", "Complex"}
COMPARE = {"==", "!=", "<", ">", "<=", ">=", "=~", "!~", "<=>", "==="}
# A lookup returns a record, not the request text that selected it.
RECORD_LOOKUPS = {"find", "find_by", "find_by!", "where", "first", "last", "take", "find_or_create_by", "find_or_initialize_by",
                  "find_by_id", "exists?", "includes", "joins", "order", "limit", "find_each", "all", "authenticate",
                  "authenticate_by", "new", "create", "create!", "build", "pluck", "select"}


def parser() -> Parser:
    return Parser(LANGUAGE)


def text(n: Node | None) -> str:
    return n.text.decode("utf-8", "replace") if n is not None and n.text is not None else ""


def line(n: Node) -> int:
    return n.start_point[0] + 1


def walk(root: Node):
    """Named nodes in document order."""
    stack = [root]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.named_children))


def field(n: Node | None, name: str) -> Node | None:
    return n.child_by_field_name(name) if n is not None else None


def method_name(call: Node) -> str:
    if call.type == "call":
        return text(field(call, "method"))
    if call.type == "identifier":
        return text(call)
    return ""


def parts(n: Node | None) -> list[str]:
    """`Digest::MD5.hexdigest(x)` -> ['Digest', 'MD5', 'hexdigest']; `params[:a].to_s` -> ['params', 'to_s']."""
    out: list[str] = []
    while n is not None:
        t = n.type
        if t == "call":
            m = field(n, "method")
            if m is not None:
                out.append(text(m))
            n = field(n, "receiver")
        elif t == "scope_resolution":
            out.append(text(field(n, "name")))
            n = field(n, "scope")
        elif t == "element_reference":
            n = field(n, "object")
        elif t in {"identifier", "constant", "instance_variable", "self", "global_variable", "class_variable"}:
            out.append(text(n))
            break
        elif t == "parenthesized_statements" and n.named_child_count == 1:
            n = n.named_children[0]
        else:
            break
    return out[::-1]


def args(call: Node) -> tuple[list[Node], dict[str, Node]]:
    """Positional arguments and keyword (or trailing hash) arguments of a call."""
    al = field(call, "arguments")
    pos: list[Node] = []
    kws: dict[str, Node] = {}
    if al is None:
        return pos, kws
    for c in al.named_children:
        if c.type == "pair":
            k = key_name(field(c, "key"))
            if k is not None:
                kws[k] = field(c, "value") or field(c, "key")  # `id:` shorthand: the local of that name
        elif c.type == "hash" and c is al.named_children[-1]:
            for p in c.named_children:
                if p.type == "pair":
                    k = key_name(field(p, "key"))
                    if k is not None:
                        kws[k] = field(p, "value") or field(p, "key")
            pos.append(c)
        elif c.type in {"block_argument", "comment"}:
            continue
        else:
            pos.append(c)
    return pos, kws


def hash_pairs(h: Node | None) -> dict[str, Node]:
    out: dict[str, Node] = {}
    if h is None or h.type not in {"hash", "argument_list"}:
        return out
    for p in h.named_children:
        if p.type == "pair":
            k = key_name(field(p, "key"))
            if k is not None:
                out[k] = field(p, "value") or field(p, "key")
    return out


def key_name(k: Node | None) -> str | None:
    if k is None:
        return None
    if k.type == "hash_key_symbol":
        return text(k)
    return sym_or_str(k)


def sym_or_str(n: Node | None) -> str | None:
    """The value of a string or symbol literal without interpolation."""
    if n is None:
        return None
    if n.type == "simple_symbol":
        return text(n)[1:]
    if n.type in {"string", "delimited_symbol", "bare_string", "bare_symbol"}:
        if any(c.type == "interpolation" for c in n.named_children):
            return None
        return "".join(text(c) if c.type == "string_content" else _escape(text(c)) for c in n.named_children
                       if c.type in {"string_content", "escape_sequence"})
    if n.type == "hash_key_symbol":
        return text(n)
    return None


def _escape(s: str) -> str:
    return {"\\n": "\n", "\\t": "\t", "\\\"": "\"", "\\'": "'", "\\\\": "\\"}.get(s, s[1:] if s.startswith("\\") else s)


def is_literal(n: Node | None) -> bool:
    return n is not None and n.type in {"integer", "float", "true", "false", "nil", "simple_symbol", "rational", "complex"} or (
        n is not None and n.type in {"string", "delimited_symbol"} and sym_or_str(n) is not None)


def bool_value(n: Node | None) -> bool | None:
    if n is None:
        return None
    if n.type == "true":
        return True
    if n.type in {"false", "nil"}:
        return False
    return None


def int_value(n: Node | None) -> int | None:
    """An integer literal, `1.year`, `2.years.to_i`, `365.days`, `60 * 60 * 24`."""
    if n is None:
        return None
    t = text(n).replace("_", "").strip()
    if n.type == "integer" and re.fullmatch(r"\d+", t):
        return int(t)
    m = re.fullmatch(r"(\d+)\.(seconds?|minutes?|hours?|days?|weeks?|months?|years?)(\.to_i)?", t)
    if m:
        unit = {"second": 1, "minute": 60, "hour": 3600, "day": 86400, "week": 604800, "month": 2629746, "year": 31556952}
        return int(m.group(1)) * unit[m.group(2).rstrip("s")]
    if n.type == "binary" and text(field(n, "operator")) == "*":
        a, b = int_value(field(n, "left")), int_value(field(n, "right"))
        return a * b if a is not None and b is not None else None
    return None


def is_comment_only(text_: str) -> bool:
    return all(not ln.strip() or ln.lstrip().startswith("#") for ln in text_.splitlines())


class RbFile:
    """One parsed Ruby file: its methods, enclosing classes, local bindings, and taint."""

    def __init__(self, sf: SourceFile, src: str, tree, line_offset: int = 0):
        self.sf, self.src, self.tree, self.root = sf, src, tree, tree.root_node
        self.line_offset = line_offset  # for Ruby embedded in a template
        self.methods: list[Node] = []
        self.scope: dict[int, Node] = {}          # node id -> enclosing method (or the root)
        self.klass: dict[int, Node | None] = {}   # method node id -> enclosing class node
        self.bindings: dict[int, dict[str, list[Node]]] = {}  # scope id -> name -> assigned values
        self.ivar_bindings: list[tuple[str, Node, Node]] = []  # (ivar, value, scope)
        self.heredocs: dict[int, Node] = {}       # heredoc_beginning id -> heredoc_body
        self.scope_names: dict[int, str] = {}     # `scope :name, ->(a) { ... }` lambda id -> name
        self.taint: dict[int, set[str]] = {}
        self.partial: dict[int, dict[str, frozenset]] = {}  # scope id -> local -> hash keys that hold request data
        self.unparsed = self.root.has_error
        self._index()

    # ------------------------------------------------------------------ structure

    def at(self, n: Node) -> str:
        return f"{self.sf.rel}:{line(n) + self.line_offset}"

    def _index(self):
        begins, bodies = [], []
        stack: list[tuple[Node, Node, Node | None]] = [(self.root, self.root, None)]
        while stack:
            n, scope, cls = stack.pop()
            self.scope[n.id] = scope
            t = n.type
            if t == "heredoc_beginning":
                begins.append(n)
            elif t == "heredoc_body":
                bodies.append(n)
            if t == "lambda" and n.parent is not None and n.parent.type == "argument_list" and n.parent.parent is not None \
                    and method_name(n.parent.parent) == "scope" and n.parent.named_children[:1] \
                    and n.parent.named_children[0].type == "simple_symbol":
                self.scope_names[n.id] = text(n.parent.named_children[0])[1:]
                t = "method"
            if t in {"method", "singleton_method"}:
                self.methods.append(n)
                self.klass[n.id] = cls
                scope = n
            elif t in {"class", "module"}:
                cls = n
            elif t in {"assignment", "operator_assignment"}:
                self._bind(n, scope)
            elif t in {"block", "do_block"}:
                self._bind_block(n, scope)
            for c in reversed(n.named_children):
                stack.append((c, scope, cls))
        begins.sort(key=lambda x: x.start_byte)
        bodies.sort(key=lambda x: x.start_byte)
        for b, body in zip(begins, bodies):
            self.heredocs[b.id] = body

    def _bind(self, n: Node, scope: Node):
        left, right = field(n, "left"), field(n, "right")
        if left is None or right is None:
            return
        targets = [left] if left.type != "left_assignment_list" else [c for c in left.named_children]
        if right.type == "right_assignment_list":
            values = right.named_children
        else:
            values = [right] * len(targets)
        for tgt, val in zip(targets, values):
            if tgt.type == "rest_assignment" and tgt.named_child_count:
                tgt = tgt.named_children[0]
            if tgt.type == "identifier":
                self.bindings.setdefault(scope.id, {}).setdefault(text(tgt), []).append(val)
            elif tgt.type == "instance_variable":
                self.bindings.setdefault(scope.id, {}).setdefault(text(tgt), []).append(val)
                self.ivar_bindings.append((text(tgt), val, scope))

    def _bind_block(self, blk: Node, scope: Node):
        """`params[:ids].each do |id|`: the block parameters take values from the receiver."""
        call = blk.parent
        ps = next((c for c in blk.named_children if c.type == "block_parameters"), None)
        if call is None or call.type != "call" or ps is None:
            return
        recv = field(call, "receiver")
        if recv is None:
            return
        for p in ps.named_children:
            nm = p if p.type == "identifier" else field(p, "name")
            if nm is not None and nm.type == "identifier":
                self.bindings.setdefault(scope.id, {}).setdefault(text(nm), []).append(recv)

    def scope_of(self, n: Node) -> Node:
        return self.scope.get(n.id, self.root)

    def method_of(self, n: Node) -> Node | None:
        s = self.scope_of(n)
        return s if s.type in {"method", "singleton_method", "lambda"} else None

    def class_of(self, n: Node) -> Node | None:
        m = self.method_of(n)
        if m is not None:
            return self.klass.get(m.id)
        p = n.parent
        while p is not None:
            if p.type in {"class", "module"}:
                return p
            p = p.parent
        return None

    def resolve(self, name: str, at: Node) -> list[Node]:
        """Values assigned to a local (or instance variable) in the enclosing method before `at` (all of them if none
        come before)."""
        vals = self.bindings.get(self.scope_of(at).id, {}).get(name, [])
        before = [v for v in vals if v.start_byte < at.start_byte]
        return before or vals

    def body_of(self, n: Node) -> str:
        return text(n)

    def method_def_name(self, m: Node) -> str:
        return self.scope_names.get(m.id) or text(field(m, "name"))

    @staticmethod
    def params_of(m: Node) -> list[tuple[str, str]]:
        """[(name, kind)] with kind positional | keyword | rest."""
        ps = field(m, "parameters")
        if ps is None and m.type == "lambda":
            ps = next((c for c in m.named_children if c.type == "lambda_parameters"), None)
        out = []
        if ps is None:
            return out
        for p in ps.named_children:
            if p.type == "identifier":
                out.append((text(p), "positional"))
            elif p.type == "optional_parameter":
                out.append((text(field(p, "name")), "positional"))
            elif p.type == "keyword_parameter":
                out.append((text(field(p, "name")), "keyword"))
            elif p.type in {"splat_parameter", "hash_splat_parameter"} and field(p, "name") is not None:
                out.append((text(field(p, "name")), "rest"))
        return out

    def heredoc_body(self, n: Node) -> Node | None:
        return self.heredocs.get(n.id)

    # ------------------------------------------------------------------ taint

    def tainted(self, expr: Node | None, ctx: "Taint | None" = None) -> bool:
        """Request data can reach the value of `expr`."""
        if expr is None:
            return False
        names = self.taint.get(self.scope_of(expr).id, set())
        partial = self.partial.get(self.scope_of(expr).id, {})
        stack = [expr]
        while stack:
            n = stack.pop()
            t = n.type
            if t == "call":
                m = method_name(n)
                recv = field(n, "receiver")
                rname = text(recv) if recv is not None and recv.type == "identifier" else None
                if m in NON_STRING or m.endswith("?"):
                    continue
                if m in {"map", "collect", "flat_map"} and re.search(r"&:(id|to_i|to_f|size|length)\b", text(field(n, "arguments"))):
                    continue
                if rname == "cookies" and m in {"signed", "encrypted"}:
                    continue
                if rname == "request":
                    if m in REQUEST_DATA:
                        return True
                    continue
                if recv is None and m in SAFE_FUNCS:
                    continue
                if recv is None and ctx is not None and ctx.returns_tainted(self, n, m):
                    return True
                if (recv is None or text(recv) == "self") and ctx is not None and field(n, "arguments") is not None:
                    kt = ctx.key_taint(self, n, m)
                    if kt is not None:
                        if kt:
                            return True
                        continue
                    r = ctx.call_result(self, n, m)
                    if r is not None:
                        if r and (self.args_tainted(n, ctx) or ctx.reads_request(m)):
                            return True
                        blk = field(n, "block")
                        if blk is not None:
                            stack.append(blk)
                        continue  # a repository method whose result does not carry its arguments
                meth = field(n, "method")
                stack.extend(c for c in n.named_children if meth is None or c.id != meth.id)
                continue
            if t in {"if", "unless", "conditional", "if_modifier", "unless_modifier", "case", "when", "while_modifier"}:
                # the value is a branch's, not the condition's
                cond = field(n, "condition") or field(n, "value") or field(n, "pattern")
                stack.extend(c for c in n.named_children if cond is None or c.id != cond.id)
                continue
            if t == "binary":
                op = text(field(n, "operator"))
                left = field(n, "left")
                if op in COMPARE:
                    continue
                if op in {"-", "*", "/", "**"} and not (left is not None and left.type in {"string", "array"}):
                    continue  # arithmetic
            elif t == "identifier":
                nm = text(n)
                if nm in SOURCE_IDENTS or nm in names or partial.get(nm):
                    return True
                if ctx is not None and ctx.returns_tainted(self, n, nm):
                    return True
            elif t == "element_reference" and field(n, "object") is not None and field(n, "object").type in {"constant", "scope_resolution"}:
                continue  # a value from a fixed table, whatever key selects it
            elif t == "element_reference" and n.named_children[1:] and sym_or_str(n.named_children[1]) is not None \
                    and self.value_keys(field(n, "object"), ctx) is not None:
                if sym_or_str(n.named_children[1]) in self.value_keys(field(n, "object"), ctx):
                    return True
                continue  # a key of a hash whose other keys hold request data
            elif t == "instance_variable":
                if text(n) in names or partial.get(text(n)) or (ctx is not None and (ctx.ivar_tainted(self, text(n))
                                                                                     or ctx.ivar_keys_of(self, text(n)))):
                    return True
            elif t == "heredoc_beginning":
                body = self.heredoc_body(n)
                if body is not None:
                    stack.append(body)
            elif t in {"block_parameters", "lambda_parameters"}:
                continue
            elif t == "pair":
                v = field(n, "value")
                if v is not None:
                    stack.append(v)
                continue
            stack.extend(n.named_children)
        return False

    def args_tainted(self, call: Node, ctx: "Taint | None" = None) -> bool:
        pos, kws = args(call)
        return any(self.tainted(a, ctx) for a in pos + list(kws.values()))

    def value_keys(self, v: Node | None, ctx: "Taint | None" = None) -> frozenset | None:
        """For a hash some of whose keys hold request data: those keys. None when the value is not such a hash."""
        if v is None:
            return None
        if v.type == "identifier":
            return self.partial.get(self.scope_of(v).id, {}).get(text(v)) if text(v) not in self.taint.get(self.scope_of(v).id, set()) else None
        if v.type == "instance_variable":
            if text(v) in self.taint.get(self.scope_of(v).id, set()):
                return None
            got = self.partial.get(self.scope_of(v).id, {}).get(text(v))
            return got if got is not None else (ctx.ivar_keys_of(self, text(v)) if ctx is not None else None)
        if v.type == "call" and ctx is not None and (field(v, "receiver") is None or text(field(v, "receiver")) == "self") \
                and field(v, "arguments") is not None:
            return ctx.key_taint(self, v, method_name(v))
        return None

    def compute_taint(self, seeds: dict, ctx: "Taint | None" = None):
        self.taint = {}
        self.partial = {}
        for m in self.methods:
            got = seeds.get((self.sf.rel, line(m), self.method_def_name(m)), {})
            self.taint[m.id] = {n for n, k in got.items() if k is None}
            self.partial[m.id] = {n: k for n, k in got.items() if k is not None}
        for _ in range(5):
            changed = False
            for scope_id, names in self.bindings.items():
                cur = self.taint.setdefault(scope_id, set())
                part = self.partial.setdefault(scope_id, {})
                for name, vals in names.items():
                    if name in cur:
                        continue
                    for v in vals:
                        kt = self.value_keys(v, ctx)
                        if kt is not None:
                            if not kt <= part.get(name, frozenset()) or name not in part:
                                part[name] = part.get(name, frozenset()) | kt
                                changed = True
                        elif self.tainted(v, ctx) and not _is_lookup(v):
                            cur.add(name)
                            part.pop(name, None)
                            changed = True
                            break
            if not changed:
                break

    def tainted_calls(self, ctx: "Taint | None" = None):
        """(callee name, parameter position or keyword, tainted keys or None for the whole value) for every call
        passing request data."""
        for n in walk(self.root):
            if n.type != "call":
                continue
            m = method_name(n)
            pos, kws = args(n)
            for i, a in enumerate(pos):
                if a.type == "hash":
                    continue
                kt = self.value_keys(a, ctx)
                if kt:
                    yield m, i, kt
                elif kt is None and self.tainted(a, ctx):
                    yield m, i, None
            for k, v in kws.items():
                kt = self.value_keys(v, ctx)
                if kt:
                    yield m, k, kt
                elif kt is None and self.tainted(v, ctx):
                    yield m, k, None


def _is_lookup(v: Node) -> bool:
    """A value that is a record (or relation) found with request data, not the request data itself:
    `Story.where(short_id: params[:id]).first!`, `User.find_by(...)&.name` is not (an attribute is read)."""
    if v is not None and v.type in {"if", "unless", "conditional", "parenthesized_statements", "begin", "then", "else", "case", "when"}:
        outs = _results(v)
        return bool(outs) and all(_is_lookup(o) or o.type == "nil" for o in outs)
    if v is not None and v.type == "element_reference":
        v = field(v, "object")
    first = True
    while v is not None and v.type == "call":
        m = method_name(v)
        if m in RECORD_LOOKUPS or re.match(r"(find_by_|find_or_|find_sole_by)", m) or m in {"first!", "last!", "take!", "sole", "find!"}:
            return True
        if not first and m not in RECORD_CHAIN:
            return False
        if first and m not in RECORD_CHAIN | {"to_s", "strip", "downcase", "presence", "to_str", "squish", "upcase"}:
            return False
        first = False
        v = field(v, "receiver")
    return False


def _results(v: Node) -> list[Node]:
    """The expressions whose value a conditional or block of statements produces."""
    t = v.type
    if t in {"if", "unless", "conditional"}:
        out = []
        for k in ("consequence", "alternative"):
            b = field(v, k)
            if b is not None:
                out += _results(b)
        return out
    if t == "case":
        return [r for c in v.named_children if c.type in {"when", "else"} for r in _results(c)]
    if t in {"then", "else", "when", "parenthesized_statements", "begin", "body_statement"}:
        body = field(v, "body") if t == "when" else v
        kids = [c for c in (body.named_children if body is not None else []) if c.type not in {"comment"}
                and not (t == "when" and c.type == "pattern")]
        return _results(kids[-1]) if kids else []
    return [v]


RECORD_CHAIN = {"first", "last", "take", "includes", "preload", "eager_load", "joins", "left_joins", "order", "limit", "offset",
                "not", "or", "merge", "unscoped", "distinct", "readonly", "lock", "active", "visible", "references", "first!",
                "last!", "take!", "sole", "where", "find", "find_by"}


class Taint:
    """Cross-file taint: helper methods that return request data (`user_params`), and instance variables a
    controller fills with request data (read by its views)."""

    def __init__(self, files: list[RbFile]):
        self.files = files
        self.returning: dict[str, set[str]] = {}   # file -> method names whose value is request data
        self.global_returning: set[str] = set()     # controller/helper methods, unique by name in the repository
        self.ivars: dict[str, set[str]] = {}       # controller views dir ("users", "admin/users") -> tainted ivars
        self.all_ivars: set[str] = set()
        self._defs: dict[str, list[tuple[RbFile, Node]]] = {}
        for f in files:
            for m in f.methods:
                self._defs.setdefault(f.method_def_name(m), []).append((f, m))
        self._results: dict[str, bool] = {}
        self._keys: dict[str, frozenset | None] = {}
        self._busy: set[str] = set()
        self.ivar_keys: dict[str, dict[str, frozenset]] = {}  # views dir -> ivar -> hash keys holding request data

    def reads_request(self, name: str) -> bool:
        defs = self._defs.get(name, [])
        return len(defs) == 1 and bool(re.search(r"\b(params|cookies|request\.)", text(defs[0][1])))

    def key_taint(self, f: RbFile, n: Node, name: str) -> frozenset | None:
        """A call to a repository method that returns hash literals: the keys whose values carry request data."""
        defs = self._defs.get(name, [])
        if len(defs) != 1 or defs[0][1].type not in {"method", "singleton_method"}:
            return None
        if name not in self._keys:
            if name in self._busy:
                return None
            self._busy.add(name)
            tf, m = defs[0]
            outs = [r for e in _method_results(m) for r in _results(e)]
            hashes = [o for o in outs if o.type == "hash"]
            others = [o for o in outs if o.type != "hash"]
            if not hashes or any(o.type not in {"nil", "constant", "scope_resolution", "true", "false"} for o in others):
                got = None
            else:
                got = frozenset(k for h in hashes for k, v in hash_pairs(h).items() if tf.tainted(v, self))
            self._busy.discard(name)
            self._keys[name] = got
        got = self._keys[name]
        if got is None:
            return None
        return got if (f.args_tainted(n, self) or self.reads_request(name)) else frozenset()

    def ivar_keys_of(self, f: RbFile, ivar: str) -> frozenset | None:
        if not f.sf.rel.startswith("app/views/"):
            return None
        return self.ivar_keys.get(view_dir(f.sf.rel), {}).get(ivar)

    def call_result(self, f: RbFile, n: Node, name: str) -> bool | None:
        """For a call to a method defined once in the repository: whether its result carries request data (given
        the parameters the cross-method step marked). None for other callees (their result is assumed to)."""
        defs = self._defs.get(name, [])
        if len(defs) != 1 or not defs[0][1].type in {"method", "singleton_method"}:
            return None
        if name in self._results:
            return self._results[name]
        if name in self._busy:
            return False
        self._busy.add(name)
        tf, m = defs[0]
        outs = [r for e in _method_results(m) for r in _results(e)]
        got = any(tf.tainted(o, self) and not _is_lookup(o) for o in outs)
        self._busy.discard(name)
        self._results[name] = got
        return got

    def returns_tainted(self, f: RbFile, n: Node, name: str) -> bool:
        if name in self.returning.get(f.sf.rel, set()):
            return True
        return name in self.global_returning and f.sf.rel.startswith(("app/controllers/", "app/helpers/", "app/views/"))

    def ivar_tainted(self, f: RbFile, ivar: str) -> bool:
        if not f.sf.rel.startswith("app/views/"):
            return False
        d = view_dir(f.sf.rel)
        if d in self.ivars:
            return ivar in self.ivars[d]
        return ivar in self.all_ivars if d.split("/")[0] in {"layouts", "shared", "application"} else False

    def run(self):
        seeds: dict = {}
        for _ in range(4):
            self._results, self._keys = {}, {}
            for f in self.files:
                f.compute_taint(seeds, self)
            new = self._returns() | self._ivars()
            for f in self.files:
                for name, pos, keys in f.tainted_calls(self):
                    for tf, m in self._defs.get(name, []):
                        ps = tf.params_of(m)
                        target = None
                        if isinstance(pos, int):
                            positional = [p for p, k in ps if k == "positional"]
                            target = positional[pos] if pos < len(positional) else None
                        else:
                            target = pos if any(p == pos and k == "keyword" for p, k in ps) else None
                        if target:
                            key = (tf.sf.rel, line(m), tf.method_def_name(m))
                            cur = seeds.setdefault(key, {})
                            if target not in cur:
                                cur[target] = keys
                                new = True
                            elif cur[target] is not None and (keys is None or not keys <= cur[target]):
                                cur[target] = None if keys is None else cur[target] | keys
                                new = True
            if not new:
                break
        self._results, self._keys = {}, {}
        for f in self.files:
            f.compute_taint(seeds, self)
        self._results, self._keys = {}, {}

    def _returns(self) -> bool:
        changed = False
        counts: dict[str, int] = {}
        for f in self.files:
            if f.sf.rel.startswith(("app/controllers/", "app/helpers/")):
                for m in f.methods:
                    counts[f.method_def_name(m)] = counts.get(f.method_def_name(m), 0) + 1
        for f in self.files:
            for m in f.methods:
                name = f.method_def_name(m)
                if name in self.returning.get(f.sf.rel, set()) or f.params_of(m):
                    continue
                last = _last_expr(m)
                if last is not None and f.tainted(last, self) and not _is_lookup(last):
                    self.returning.setdefault(f.sf.rel, set()).add(name)
                    if counts.get(name) == 1 and f.sf.rel.startswith(("app/controllers/", "app/helpers/")):
                        self.global_returning.add(name)
                    changed = True
        return changed

    def _ivars(self) -> bool:
        changed = False
        for f in self.files:
            if not f.sf.rel.startswith("app/controllers/"):
                continue
            d = controller_views(f.sf.rel)
            for ivar, val, _scope in f.ivar_bindings:
                if ivar in self.ivars.get(d, set()):
                    continue
                kt = f.value_keys(val, self) if val.type != "instance_variable" else None
                if kt is not None:
                    cur = self.ivar_keys.setdefault(d, {})
                    if ivar not in cur or not kt <= cur[ivar]:
                        cur[ivar] = cur.get(ivar, frozenset()) | kt
                        changed = True
                    continue
                if f.tainted(val, self) and not _is_lookup(val):
                    self.ivars.setdefault(d, set()).add(ivar)
                    self.all_ivars.add(ivar)
                    changed = True
        return changed


def _last_expr(m: Node) -> Node | None:
    body = field(m, "body")
    if m.type == "lambda":
        blk = next((c for c in m.named_children if c.type in {"block", "do_block"}), None)
        body = next((c for c in blk.named_children if c.type in {"block_body", "body_statement"}), None) if blk is not None else None
    if body is None:
        return None
    kids = [c for c in body.named_children if c.type != "comment"]
    return kids[-1] if kids else None


def _method_results(m: Node) -> list[Node]:
    last = _last_expr(m)
    outs = [last] if last is not None else []
    outs += [c.named_children[0] for c in walk(m) if c.type == "return" and c.named_children]
    return [o.named_children[0] if o.type == "argument_list" and o.named_children else o for o in outs]


def controller_views(rel: str) -> str:
    """app/controllers/admin/users_controller.rb -> admin/users"""
    p = rel[len("app/controllers/"):]
    return re.sub(r"_controller\.rb$", "", p)


def view_dir(rel: str) -> str:
    """app/views/admin/users/show.html.erb -> admin/users"""
    p = rel[len("app/views/"):]
    return p.rsplit("/", 1)[0] if "/" in p else ""
