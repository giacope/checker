"""JavaScript and TypeScript analysis on tree-sitter syntax trees (parsing only; nothing is executed)."""

from __future__ import annotations

import re

import tree_sitter as ts
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts

from .common import (dedicated_hasher, deletes_a_person, length_bound, rejects_words, Collector, model_policy, session_cookie_name, PW_EXPIRY, LOCKOUT, ERASURE_REQUEST, analyse_password_regex, external_host, is_credential_name, is_password_name,
                     is_personal_name, is_record_field, is_stored_password_name, PERSONAL_TYPES, is_user_object_name, literal_secret_kind,
                     plausible_secret_value, secret_kind_for_name, words, PW_WORDS, TRACKER_HOSTS, USER_OBJECTS)
from .files import SourceFile
from .models import Models, arg as model_arg

LANGS = {"js": ts.Language(tsjs.language()), "ts": ts.Language(tsts.language_typescript()),
         "tsx": ts.Language(tsts.language_tsx())}
FUNC_TYPES = {"function_declaration", "function_expression", "function", "arrow_function", "method_definition",
              "generator_function_declaration", "generator_function"}
OWNER_TYPES = FUNC_TYPES | {"class_declaration", "class"}  # what a node is inside of, for advisory()
WRAPPERS = {"parenthesized_expression", "as_expression", "non_null_expression", "await_expression", "satisfies_expression",
            "type_assertion"}
REQUEST_NAMES = {"req", "request"}
SOURCE_PROPS = {"body", "query", "params", "headers", "cookies", "signedCookies", "files", "file"}
SOURCE_CALLS = {"get", "header", "param"}
SQL_WORDS = re.compile(r"^\s*\(?\s*(select|insert|update|delete|create|drop|alter|pragma|replace|with)\b", re.I)
SQL_ANY = re.compile(r"\b(select\s.+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b", re.I | re.S)
RAW_SQL_METHODS = {"query", "raw", "execute", "run", "all", "get", "each", "prepare", "exec", "unsafe", "$queryRawUnsafe",
                   "$executeRawUnsafe", "queryRaw", "executeRaw"}
DOC_METHODS = {"find", "findOne", "findOneAndUpdate", "findOneAndDelete", "findOneAndReplace", "findOneAndRemove", "update",
               "updateOne", "updateMany", "deleteOne", "deleteMany", "remove", "count", "countDocuments", "aggregate",
               "distinct", "replaceOne", "findAll", "findAndCountAll", "destroy", "findOrCreate", "findById",
               "findByIdAndUpdate", "findByIdAndDelete", "findByPk", "where"}
DOC_MODULES = {"mongodb", "mongoose", "marsdb", "monk", "mongojs", "nedb", "@seald-io/nedb", "mongoist"}
LOG_METHODS = {"log", "info", "warn", "warning", "error", "debug", "trace", "fatal", "verbose", "silly"}
LOGIN_PATH = re.compile(r"(^|/)(login|signin|sign-in|log-in|authenticate|auth/local|session|sessions|token)(/|$|\?)", re.I)
SET_FN = re.compile(r"(^|_)(set|create|register|registration|signup|sign_up|add|new|change|reset|update|save|insert|seed)(_|$)")
POLICY_GENERIC = {"rules", "rule", "validators", "validator", "options", "opts", "config", "schema", "validation", "value",
                  "constraints", "controls", "control", "form", "fields", "field", "props", "args", "params", "register"}
PW_NEGATIVE = {"confirm", "confirmation", "repeat", "current", "old", "previous", "verify", "again"}
HTTP_CLIENTS = {"axios", "node-fetch", "got", "request", "superagent", "needle", "undici", "cross-fetch", "isomorphic-fetch"}
SDK_SENDERS = {"stripe": "Stripe", "@sendgrid/mail": "SendGrid", "nodemailer": "email (SMTP relay via nodemailer)",
               "openai": "OpenAI", "@anthropic-ai/sdk": "Anthropic", "twilio": "Twilio", "mailgun.js": "Mailgun",
               "analytics-node": "Segment", "@segment/analytics-node": "Segment", "mixpanel": "Mixpanel",
               "posthog-node": "PostHog", "@sentry/node": "Sentry", "@aws-sdk/client-ses": "AWS SES"}


def T(n) -> str:
    return n.text.decode("utf-8", "replace") if n is not None else ""


def L(n) -> int:
    return n.start_point[0] + 1


def unwrap(n):
    while n is not None and n.type in WRAPPERS:
        kids = [c for c in n.named_children if c.type != "comment"]
        if not kids:
            break
        n = kids[0]
    return n


def kids(n):
    return [c for c in n.named_children if c.type != "comment"] if n is not None else []


def _branch(n) -> str | None:
    """"reject" when a branch rejects the input (throws, returns anything but true, sends a 4xx, records an error),
    "accept" when it returns true, else None."""
    if n is None:
        return None
    stack, names = [n], []
    while stack:
        x = stack.pop()
        if x.type == "throw_statement":
            return "reject"
        if x.type == "return_statement":
            kids = [c for c in x.named_children if c.type != "comment"]
            return "accept" if kids and T(kids[0]) == "true" else "reject"
        if x.type in ("identifier", "property_identifier"):
            names.append(T(x))
        elif x.type == "number" and T(x).isdigit() and 400 <= int(T(x)) <= 499:
            return "reject"
        if x.type not in ("function_declaration", "arrow_function", "function_expression", "function"):
            stack += reversed(x.named_children)
    return "reject" if rejects_words(names) else None


def _invalid_when(n) -> bool | None:
    """Whether condition `n` holding means the code rejects the input there (True), accepts it (False), or the
    context does not say (None). `!` flips it; `&&`, `||` and parentheses pass it through."""
    holds = True
    while True:
        p = n.parent
        if p is None:
            return None
        if p.type == "unary_expression" and T(p.child_by_field_name("operator")) == "!":
            holds = not holds
        elif p.type == "parenthesized_expression" or (p.type == "binary_expression" and T(p.child_by_field_name("operator")) in ("&&", "||")):
            pass
        elif p.type == "if_statement" and p.child_by_field_name("condition") is not None and p.child_by_field_name("condition").id == n.id:
            alt = p.child_by_field_name("alternative")
            body, orelse = _branch(p.child_by_field_name("consequence")), _branch(alt)
            if body == "reject" or orelse == "accept":
                return holds
            if body == "accept" or orelse == "reject":
                return not holds
            return None
        elif p.type == "return_statement" or (p.type == "arrow_function" and p.child_by_field_name("body") is not None
                                              and p.child_by_field_name("body").id == n.id):
            return not holds        # returned: what holds is what passes
        else:
            return None
        n = p


def str_value(n) -> str | None:
    n = unwrap(n)
    if n is None:
        return None
    if n.type == "string":
        return "".join(T(c) for c in n.named_children if c.type in ("string_fragment", "escape_sequence"))
    if n.type == "template_string" and not any(c.type == "template_substitution" for c in n.named_children):
        return "".join(T(c) for c in n.named_children if c.type in ("string_fragment", "escape_sequence"))
    return None


def template_text(n) -> list[str]:
    """Constant fragments of a string, template, or concatenation."""
    n = unwrap(n)
    if n is None:
        return []
    if n.type in ("string", "template_string"):
        return ["".join(T(c) for c in n.named_children if c.type in ("string_fragment", "escape_sequence"))]
    if n.type == "binary_expression" and T(n.child_by_field_name("operator")) == "+":
        return template_text(n.child_by_field_name("left")) + template_text(n.child_by_field_name("right"))
    return []


def dotted(n) -> list[str]:
    """`req.body.email` -> ['req', 'body', 'email']; calls and wrappers in the chain are looked through."""
    out = []
    while n is not None:
        n = unwrap(n)
        if n is None:
            break
        t = n.type
        if t == "member_expression":
            out.append(T(n.child_by_field_name("property")))
            n = n.child_by_field_name("object")
        elif t == "subscript_expression":
            s = str_value(n.child_by_field_name("index"))
            out.append(s if s is not None else "[]")
            n = n.child_by_field_name("object")
        elif t == "call_expression":
            n = n.child_by_field_name("function")
        elif t == "new_expression":
            n = n.child_by_field_name("constructor")
        elif t in ("identifier", "this", "property_identifier", "shorthand_property_identifier", "type_identifier"):
            out.append(T(n))
            break
        else:
            break
    return out[::-1]


def walk(n):
    stack = [n]
    while stack:
        x = stack.pop()
        if x.type == "comment":
            continue
        yield x
        stack.extend(reversed(x.children))


def walk_no_funcs(n):
    stack = [n]
    while stack:
        x = stack.pop()
        if x.type == "comment":
            continue
        yield x
        if x is not n and x.type in FUNC_TYPES:
            continue
        stack.extend(reversed(x.children))


def pattern_names(p) -> list[str]:
    if p is None:
        return []
    t = p.type
    if t in ("identifier", "shorthand_property_identifier_pattern"):
        return [T(p)]
    if t in ("required_parameter", "optional_parameter"):
        return pattern_names(p.child_by_field_name("pattern"))
    if t == "assignment_pattern":
        return pattern_names(p.child_by_field_name("left"))
    if t == "pair_pattern":
        return pattern_names(p.child_by_field_name("value"))
    if t in ("object_pattern", "array_pattern", "rest_pattern", "object_assignment_pattern"):
        return [x for c in kids(p) for x in pattern_names(c)]
    return []


def literal_bool(n):
    n = unwrap(n)
    if n is None:
        return None
    if n.type == "true":
        return True
    if n.type == "false":
        return False
    return None


def obj_pairs(n) -> dict:
    """Pairs of an object literal, by key."""
    n = unwrap(n)
    out = {}
    if n is None or n.type != "object":
        return out
    for c in kids(n):
        if c.type == "pair":
            k = c.child_by_field_name("key")
            key = str_value(k) if k.type == "string" else T(k)
            out[key] = c.child_by_field_name("value")
        elif c.type == "shorthand_property_identifier":
            out[T(c)] = c
        elif c.type == "method_definition":
            out[T(c.child_by_field_name("name"))] = c
    return out


def loose_password(name: str) -> bool:
    ws = words(name)
    return any(w in PW_WORDS or w.endswith("password") for w in ws) and not any(w in PW_NEGATIVE for w in ws)


ADVISORY = re.compile(r"strength|meter|entropy|score|indicator", re.I)


LOGIN_FORM = re.compile(r"login|log-in|signin|sign-in|sign_in", re.I)


def advisory(jf, n) -> bool:
    """Code in a password strength meter, or in a login form (it checks input; it sets no password policy)."""
    fname = jf.sf.rel.rsplit("/", 1)[-1]
    if ADVISORY.search(fname) or (jf.sf.client and LOGIN_FORM.search(fname)):
        return True
    p = jf.owner_of(n)
    while p is not None:
        nm = p.child_by_field_name("name")
        if nm is not None and (ADVISORY.search(T(nm)) or (jf.sf.client and LOGIN_FORM.search(T(nm)))):
            return True
        p = jf.owner_of(p)
    return False


def parse_version(spec: str | None):
    if not spec:
        return None
    m = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", spec)
    if not m:
        return None
    return tuple(int(x or 0) for x in m.groups())


class JSFile:
    def __init__(self, sf: SourceFile, text: str, models: Models):
        self.sf, self.text, self.models = sf, text, models
        parser = ts.Parser(LANGS[sf.kind])
        self.tree = parser.parse(text.encode("utf-8"))
        self.root = self.tree.root_node
        # walk(), recording each node's innermost enclosing function and function-or-class on the way down: a
        # tree-sitter node finds its parent from the root, so walking up from every node of a deep tree is cubic
        self.nodes = []
        self._fn_cache: dict = {}  # node id -> innermost enclosing function node (None at module level)
        self._owner: dict = {}     # node id -> innermost enclosing function or class node
        stack = [(self.root, None, None)]
        while stack:
            x, fn, owner = stack.pop()
            if x.type == "comment":
                continue
            self.nodes.append(x)
            self._fn_cache[x.id], self._owner[x.id] = fn, owner
            inner = (x if x.type in FUNC_TYPES else fn, x if x.type in OWNER_TYPES else owner)
            stack.extend((c, *inner) for c in reversed(x.children))
        self.funcs = [n for n in self.nodes if n.type in FUNC_TYPES]
        self.aliases: dict[str, str] = {}
        self.alias_src: dict[str, tuple[str, list[str]]] = {}  # local name -> (module, members), for framework models
        self._rules: dict = {}
        self.decls: dict = {}   # scope id -> name -> [value nodes]
        self.bindings: dict = {}  # scope id -> [(names, value)]
        self.taint: dict = {}
        self._tainted: dict = {}  # frozenset of tainted names -> node id -> tainted (see tainted)
        self._imports()
        self._bind()

    def at(self, n) -> str:
        return f"{self.sf.rel}:{L(n)}"

    def _imports(self):
        for n in self.nodes:
            if n.type == "import_statement":
                src = str_value(n.child_by_field_name("source")) or ""
                for c in walk(n):
                    if c.type == "import_clause":
                        for d in kids(c):
                            if d.type == "identifier":
                                self.aliases[T(d)] = src
                                self.alias_src[T(d)] = (src, [])
                    elif c.type == "namespace_import":
                        ids = [x for x in kids(c) if x.type == "identifier"]
                        if ids:
                            self.aliases[T(ids[0])] = src
                            self.alias_src[T(ids[0])] = (src, [])
                    elif c.type == "import_specifier":
                        name = T(c.child_by_field_name("name"))
                        alias = c.child_by_field_name("alias")
                        self.aliases[T(alias) if alias else name] = f"{src}.{name}"
                        self.alias_src[T(alias) if alias else name] = (src, [name])
                    elif c.type == "import_require_clause":
                        ids = [x for x in kids(c) if x.type == "identifier"]
                        req = str_value(c.child_by_field_name("source"))
                        if ids and req:
                            self.aliases[T(ids[0])] = req
                            self.alias_src[T(ids[0])] = (req, [])
            elif n.type == "variable_declarator":
                v = unwrap(n.child_by_field_name("value"))
                if v is None:
                    continue
                base, tail = v, []
                while base is not None and base.type == "member_expression":
                    tail.insert(0, T(base.child_by_field_name("property")))
                    base = unwrap(base.child_by_field_name("object"))
                if base is not None and base.type == "call_expression" and T(base.child_by_field_name("function")) == "require":
                    args = kids(base.child_by_field_name("arguments"))
                    mod = str_value(args[0]) if args else None
                    if not mod:
                        continue
                    full = ".".join([mod] + tail)
                    name = n.child_by_field_name("name")
                    if name.type == "identifier":
                        self.aliases[T(name)] = full
                        self.alias_src[T(name)] = (mod, tail)
                    elif name.type == "object_pattern":
                        for c in kids(name):
                            if c.type == "shorthand_property_identifier_pattern":
                                self.aliases[T(c)] = f"{full}.{T(c)}"
                                self.alias_src[T(c)] = (mod, tail + [T(c)])
                            elif c.type == "pair_pattern":
                                self.aliases[T(c.child_by_field_name("value"))] = f"{full}.{T(c.child_by_field_name('key'))}"
                                self.alias_src[T(c.child_by_field_name("value"))] = (mod, tail + [T(c.child_by_field_name("key"))])

    def callee(self, n) -> tuple[list[str], bool]:
        """The callee for framework-model matching: ([module or first name, member, ...], first name is imported)."""
        parts = dotted(n)
        if not parts or parts[0] not in self.alias_src:
            return parts, False
        mod, members = self.alias_src[parts[0]]
        return [mod, *members, *parts[1:]], True

    def rule(self, call, kind: str):
        key = (call.id, kind)
        if key not in self._rules:
            self._rules[key] = self.models.match("javascript", self.callee(unwrap(call.child_by_field_name("function"))), kind)
        return self._rules[key]

    def module_of(self, n) -> str:
        parts = dotted(n)
        return self.aliases.get(parts[0], "") if parts else ""

    def qual(self, n) -> str:
        parts = dotted(n)
        if not parts:
            return ""
        head = self.aliases.get(parts[0], parts[0])
        return ".".join([head] + parts[1:])

    # ---------------------------------------------------------------- scopes
    def owner_of(self, n):
        """Innermost enclosing function or class node (None for module level)."""
        if n.id in self._owner:
            return self._owner[n.id]
        p = n.parent
        while p is not None and p.type not in OWNER_TYPES:
            p = p.parent
        return p

    def fn_of(self, n):
        """Innermost enclosing function node (None for module level)."""
        key = n.id
        if key in self._fn_cache:
            return self._fn_cache[key]
        p = n.parent
        while p is not None and p.type not in FUNC_TYPES:
            p = p.parent
        self._fn_cache[key] = p
        return p

    def chain(self, n):
        out = []
        f = n if n.type in FUNC_TYPES else self.fn_of(n)
        while f is not None:
            out.append(f.id)
            f = self.fn_of(f)
        out.append(0)
        return out

    def scope_id(self, n) -> int:
        f = self.fn_of(n)
        return f.id if f is not None else 0

    def func_name(self, f) -> str | None:
        if f is None:
            return None
        nm = f.child_by_field_name("name")
        if nm is not None:
            return T(nm)
        p = f.parent
        while p is not None and p.type in WRAPPERS | {"arguments"} and p.type != "arguments":
            p = p.parent
        if p is None:
            return None
        if p.type == "variable_declarator":
            return T(p.child_by_field_name("name"))
        if p.type == "pair":
            return str_value(p.child_by_field_name("key")) or T(p.child_by_field_name("key"))
        if p.type == "assignment_expression":
            d = dotted(p.child_by_field_name("left"))
            return d[-1] if d else None
        if p.type in ("public_field_definition", "field_definition"):
            return T(p.child_by_field_name("name"))
        return None

    def params(self, f) -> list[list[str]]:
        single = f.child_by_field_name("parameter")
        if single is not None:
            return [pattern_names(single)]
        ps = f.child_by_field_name("parameters")
        return [pattern_names(c) for c in kids(ps)] if ps is not None else []

    def _bind(self):
        for n in self.nodes:
            t = n.type
            pairs = []
            if t == "variable_declarator":
                v = n.child_by_field_name("value")
                if v is not None:
                    names = pattern_names(n.child_by_field_name("name"))
                    pairs.append((names, v))
                    for nm in names:
                        self.decls.setdefault(self.scope_id(n), {}).setdefault(nm, []).append(v)
            elif t in ("assignment_expression", "augmented_assignment_expression"):
                left = unwrap(n.child_by_field_name("left"))
                right = n.child_by_field_name("right")
                if left is not None and left.type == "identifier":
                    pairs.append(([T(left)], right))
                    self.decls.setdefault(self.scope_id(n), {}).setdefault(T(left), []).append(right)
                elif left is not None and left.type in ("object_pattern", "array_pattern"):
                    pairs.append((pattern_names(left), right))
                elif left is not None and left.type in ("member_expression", "subscript_expression"):
                    d = dotted(left)
                    if d and d[0] not in ("this", "module", "exports"):
                        pairs.append(([d[0]], right))
            elif t in ("assignment_pattern", "optional_parameter", "required_parameter") and n.child_by_field_name("value") is not None \
                    and n.child_by_field_name("left" if t == "assignment_pattern" else "pattern") is not None:
                name = n.child_by_field_name("left" if t == "assignment_pattern" else "pattern")
                if name.type == "identifier":
                    self.decls.setdefault(self.scope_id(n) if self.fn_of(n) is None else self.fn_of(n).id, {}).setdefault(T(name), []).append(n.child_by_field_name("value"))
            elif t == "for_in_statement":
                pairs.append((pattern_names(n.child_by_field_name("left")), n.child_by_field_name("right")))
            if pairs:
                self.bindings.setdefault(self.scope_id(n), []).extend(pairs)

    def resolve(self, name: str, at) -> list:
        for s in self.chain(at):
            vals = self.decls.get(s, {}).get(name)
            if vals:
                return vals
        return []

    # ---------------------------------------------------------------- taint
    def request_params(self, f) -> set[str]:
        names = [p[0] if p else None for p in self.params(f)]
        out = {n for n in names if n in REQUEST_NAMES}
        return out

    def is_source(self, n) -> bool:
        if n.type == "member_expression":
            d = dotted(n)
            return len(d) >= 2 and d[0] in REQUEST_NAMES and d[1] in SOURCE_PROPS
        if n.type == "call_expression":
            d = dotted(n.child_by_field_name("function"))
            return (len(d) == 2 and d[0] in REQUEST_NAMES and d[1] in SOURCE_CALLS) or bool(self.rule(n, "source"))
        return False

    def tainted(self, expr, at=None) -> bool:
        """Request data reaches `expr`: a source or a tainted name in it, outside nested functions and sanitizer
        calls. Whether a node is tainted depends only on its subtree and the tainted names in scope, so it is
        kept per node for each set of names: checking every argument of 20,000 nested calls stays linear."""
        if expr is None or expr.type == "comment":
            return False
        names = frozenset().union(*(self.taint.get(s, ()) for s in self.chain(at if at is not None else expr)))
        memo = self._tainted.setdefault(names, {})
        if expr.id in memo:
            return memo[expr.id]
        # inside `expr`, comments and nested functions do not count; `expr` itself may be a function
        inner = lambda x: [c for c in x.children if c.type != "comment" and c.type not in FUNC_TYPES]  # noqa: E731
        stack = [(expr, False)]
        while stack:
            x, measured = stack.pop()
            if measured:
                memo[x.id] = any(memo[c.id] for c in inner(x))
                continue
            if x.id in memo:
                continue
            t = x.type
            if t == "call_expression" and self.rule(x, "sanitizer"):
                memo[x.id] = False  # its result is not controlled by the request
                continue
            if t in ("identifier", "shorthand_property_identifier") and T(x) in names:
                p = x.parent
                if not (p is not None and p.type == "member_expression" and p.child_by_field_name("property") == x):
                    memo[x.id] = True
                    continue
            if self.is_source(x):
                memo[x.id] = True
                continue
            stack.append((x, True))
            stack.extend((c, False) for c in inner(x))
        return memo[expr.id]

    def compute_taint(self, seeds: dict):
        self.taint = {0: set()}
        for f in self.funcs:
            s = set(seeds.get((self.sf.rel, f.id), set()))
            self.taint[f.id] = s
        for _ in range(5):
            changed = False
            for scope, pairs in self.bindings.items():
                for names, value in pairs:
                    if names and value is not None and self.tainted(value, value):
                        new = set(names) - self.taint.setdefault(scope, set())
                        if new:
                            self.taint[scope] |= new
                            changed = True
            if not changed:
                break

    def tainted_calls(self):
        for n in self.nodes:
            if n.type == "call_expression":
                d = dotted(n.child_by_field_name("function"))
                if not d:
                    continue
                for i, a in enumerate(kids(n.child_by_field_name("arguments"))):
                    if self.tainted(a, n):
                        yield d[-1], i


# ==================================================================== analysis

class JSAnalyser:
    def __init__(self, files: list[tuple[SourceFile, str]], ctx):
        self.ctx = ctx
        self.fm: Models = ctx["models"]
        self.files: list[JSFile] = []
        for sf, text in files:
            try:
                self.files.append(JSFile(sf, text, ctx["models"]))
            except Exception:  # noqa: BLE001 - a file the grammar cannot read is skipped
                continue
        self.helpers: dict[str, tuple] = {}   # function name -> (algorithm, salted, at of the primitive)
        self.repo_functions: set[str] = set()
        self.model_hashes_password = False
        self.deps = ctx.get("npm_deps", {})
        self.nested = ctx.get("npm_nested", {})
        self.doc_db = bool(set(self.deps) & DOC_MODULES)

    # ------------------------------------------------------------ preparation
    def by_name(self):
        idx: dict[str, list] = {}
        for jf in self.files:
            for f in jf.funcs:
                nm = jf.func_name(f)
                if nm:
                    idx.setdefault(nm, []).append((jf, f))
        return idx

    def prepare(self):
        idx = self.by_name()
        self.repo_functions = set(idx)
        seeds: dict = {}
        for jf in self.files:
            for f in jf.funcs:
                rp = jf.request_params(f)
                if rp:
                    seeds.setdefault((jf.sf.rel, f.id), set()).update(rp)
        # name-based interprocedural taint: a parameter is tainted when some call passes request data in that position
        for _ in range(3):
            for jf in self.files:
                jf.compute_taint(seeds)
            new = False
            for jf in self.files:
                if jf.sf.client:
                    continue
                for name, pos in jf.tainted_calls():
                    for tf, f in idx.get(name, []):
                        ps = tf.params(f)
                        if pos < len(ps):
                            key = (tf.sf.rel, f.id)
                            add = set(ps[pos]) - seeds.get(key, set())
                            if add:
                                seeds.setdefault(key, set()).update(add)
                                new = True
            if not new:
                break
        for jf in self.files:
            jf.compute_taint(seeds)
        # helpers: repo functions that hash one of their parameters
        for jf in self.files:
            for f in jf.funcs:
                nm = jf.func_name(f)
                if not nm:
                    continue
                ps = {x for p in jf.params(f) for x in p}
                for n in walk_no_funcs(f):
                    if n.type == "call_expression":
                        prim = self.primitive(jf, n)
                        if prim and any(x.type == "identifier" and T(x) in ps for i in prim[2] for x in walk(i)):
                            self.helpers.setdefault(nm, (prim[0], prim[1], jf.at(n)))
                            break
        # a model attribute setter or a save hook that hashes the password
        for jf in self.files:
            for n in jf.nodes:
                if n.type == "pair" and is_stored_password_name(T(n.child_by_field_name("key")).strip("'\"")):
                    v = n.child_by_field_name("value")
                    for m in walk(v):
                        if m.type == "method_definition" and T(m.child_by_field_name("name")) == "set":
                            if any(c.type == "call_expression" and (self.primitive(jf, c) or self.helper_of(c)) for c in walk(m)):
                                self.model_hashes_password = True
                if n.type == "call_expression":
                    d = dotted(n.child_by_field_name("function"))
                    a = kids(n.child_by_field_name("arguments"))
                    if d and d[-1] == "pre" and a and str_value(a[0]) in {"save", "validate"} and any(
                            c.type == "call_expression" and (self.primitive(jf, c) or self.helper_of(c)) for x in a[1:] for c in walk(x)):
                        self.model_hashes_password = True

    def helper_of(self, c):
        d = dotted(c.child_by_field_name("function"))
        return self.helpers.get(d[-1]) if d else None

    def primitive(self, jf: JSFile, c):
        """(algorithm, salted, password input nodes) for a call that hashes, encrypts, or encodes its input."""
        fn = unwrap(c.child_by_field_name("function"))
        args = kids(c.child_by_field_name("arguments"))
        d = dotted(fn)
        if not d:
            return None
        rule = jf.rule(c, "password_hash")
        if rule:
            pw = model_arg(rule.spec.get("password", 0), args)
            inputs = [pw] if pw is not None else []
            salted = rule.spec["salted"]
            if salted == "infer":
                salted = any("salt" in words(T(x)) for i in inputs for x in walk(i) if x.type in ("identifier", "property_identifier"))
            return rule.spec["algorithm"], salted, inputs
        last = d[-1]
        mod = jf.module_of(fn)
        if last == "update" and fn.type == "member_expression":
            inputs = list(args)
            obj = unwrap(fn.child_by_field_name("object"))
            while obj is not None and obj.type == "call_expression":
                f2 = unwrap(obj.child_by_field_name("function"))
                d2 = dotted(f2)
                a2 = kids(obj.child_by_field_name("arguments"))
                if d2 and d2[-1] in ("createHash", "createHmac"):
                    alg = (str_value(a2[0]) or "").lower() if a2 else ""
                    alg = {"md5": "md5", "sha1": "sha1", "sha256": "sha256", "sha512": "sha512", "sha384": "sha512",
                           "sha224": "sha256"}.get(alg.replace("-", ""), "other")
                    salted = d2[-1] == "createHash" and any("salt" in words(T(x)) for i in inputs for x in walk(i) if x.type in ("identifier", "property_identifier"))
                    return alg, salted, inputs
                if d2 and d2[-1] in ("createCipher", "createCipheriv"):
                    return "reversible", False, inputs
                if d2 and d2[-1] == "update" and f2.type == "member_expression":
                    inputs += a2
                    obj = unwrap(f2.child_by_field_name("object"))
                    continue
                break
            return None
        if "bcrypt" in mod or (d[0] == "bcrypt" and not mod):
            return None  # its hashing calls are in models/javascript.yaml
        if (mod in ("crypto", "node:crypto") or d[0] == "crypto") and last in {"pbkdf2", "pbkdf2Sync", "scrypt", "scryptSync"}:
            salt = args[1] if len(args) > 1 else None
            return ("pbkdf2" if "pbkdf2" in last else "scrypt"), salt is not None and str_value(salt) is None, args[:1]
        if last == "btoa" or (last == "toString" and args and str_value(args[0]) == "base64" and fn.type == "member_expression"
                              and dotted(fn.child_by_field_name("object"))[:2] == ["Buffer", "from"]):
            inner = unwrap(fn.child_by_field_name("object")) if last == "toString" else None
            return "reversible", False, kids(inner.child_by_field_name("arguments")) if inner is not None else args
        return None

    # ------------------------------------------------------------ main pass
    def run(self, out: Collector):
        for jf in self.files:
            self.secrets(jf, out)
            if jf.sf.example:
                continue
            hashed = self.hashed_vars(jf)
            for n in jf.nodes:
                t = n.type
                if t == "call_expression":
                    self.call(jf, n, out, hashed)
                elif t == "new_expression":
                    self.new(jf, n, out, hashed)
                elif t == "binary_expression":
                    self.binary(jf, n, out, hashed)
                elif t == "object":
                    self.object(jf, n, out, hashed)
                elif t == "assignment_expression" and jf.sf.client:
                    left = dotted(n.child_by_field_name("left"))
                    if left[-2:] == ["document", "cookie"]:
                        self.client_cookie(jf, n, str_value(n.child_by_field_name("right")) or T(n.child_by_field_name("right")), None, out)
                elif t in ("identifier", "property_identifier", "shorthand_property_identifier"):
                    j = "_".join(words(T(n)))
                    if PW_EXPIRY.search(j):
                        out.signal("pw_expiry", jf.at(n))
                    if not jf.sf.client and LOCKOUT.search(j):
                        out.signal("lockout", jf.at(n))
                    if not jf.sf.client and ERASURE_REQUEST.search(j) and any(jf.taint.get(x, set()) & REQUEST_NAMES for x in jf.chain(n)):
                        out.signal("erasure_request", jf.at(n))  # where a request records it
                elif t == "member_expression" and not jf.sf.client:
                    if jf.is_source(n) and is_password_name(dotted(n)[-1]):
                        out.signal("pw_auth", jf.at(n))

    def hashed_vars(self, jf: JSFile) -> set[str]:
        out = set()
        for scope, names in jf.decls.items():
            for name, vals in names.items():
                for v in vals:
                    if v is not None and any(c.type == "call_expression" and (self.primitive(jf, c) or self.helper_of(c)) for c in walk(v)):
                        out.add(name)
        return out

    def raw_password(self, jf: JSFile, expr, hashed: set[str]) -> bool:
        expr = unwrap(expr)
        if expr is None:
            return False
        if any(c.type == "call_expression" and (self.primitive(jf, c) or self.helper_of(c)) for c in walk(expr)):
            return False
        if expr.type in ("identifier", "shorthand_property_identifier"):
            return is_password_name(T(expr)) and T(expr) not in hashed
        if expr.type == "member_expression":
            d = dotted(expr)
            return is_password_name(d[-1]) and (jf.is_source(expr) or not (len(d) > 1 and is_user_object_name(d[-2])))
        return False

    def mentions_password(self, nodes) -> bool:
        for i in nodes:
            for x in walk(i):
                if x.type in ("identifier", "property_identifier", "shorthand_property_identifier") and is_password_name(T(x)):
                    return True
        return False

    def enclosing_name(self, jf: JSFile, n) -> str:
        f = jf.fn_of(n)
        while f is not None:
            nm = jf.func_name(f)
            if nm:
                return nm
            f = jf.fn_of(f)
        return ""

    def password_store(self, jf: JSFile, n, out: Collector, algorithm, salted, tainted=False):
        at = jf.at(n)
        out.element("PasswordStore", at, algorithm=algorithm, salted=salted)
        out.signal("pw_auth", at)
        name = "_".join(words(self.enclosing_name(jf, n)))
        if SET_FN.search(name) and not re.search(r"login|signin|sign_in|auth|verify|check|compare", name):
            out.signal("pw_set_site", at)

    def call(self, jf: JSFile, c, out: Collector, hashed: set[str]):
        fn = unwrap(c.child_by_field_name("function"))
        args = kids(c.child_by_field_name("arguments"))
        d = dotted(fn)
        if not d:
            return
        last = d[-1]
        q = jf.qual(fn)
        mod = jf.module_of(fn)
        at = jf.at(c)
        client = jf.sf.client
        if client:
            self.client_call(jf, c, fn, args, d, out)
            self.policy(jf, c, fn, args, d, out)
            return
        # ---- PasswordStore
        prim = self.primitive(jf, c)
        # a password-hashing API hashes a password whatever the variable is called (`secret`, `motDePasse`)
        if prim and (self.mentions_password(prim[2]) or (prim[2] and dedicated_hasher(prim[0], jf.rule(c, "password_hash") is not None))):
            self.password_store(jf, c, out, prim[0], prim[1], any(jf.tainted(i, c) for i in prim[2]))
            out.mark(at, jf.rule(c, "password_hash"))
        elif not prim:
            h = self.helper_of(c)
            if h and self.mentions_password(args):
                self.password_store(jf, c, out, h[0], h[1], any(jf.tainted(a, c) for a in args))
                site = h[2]
                out.element("PasswordStore", site, algorithm=h[0], salted=h[1])
            elif h is None and last in self.repo_functions and re.search(r"(^|_)(compare|check|verify|match|matches|equals?)(_|$)", "_".join(words(last))) \
                    and any(self.raw_password(jf, a, hashed) for a in args) and any(
                        unwrap(a).type == "member_expression" and is_stored_password_name(dotted(a)[-1]) and not jf.is_source(unwrap(a)) for a in args):
                self.password_store(jf, c, out, "plaintext", False)  # a repository helper compares the stored value as is
        # ---- Query
        self.query(jf, c, fn, args, d, out, hashed)
        # ---- TokenVerification
        rule = jf.rule(c, "token_verification")
        if rule:
            out.element("TokenVerification", at, **rule.spec)
            out.mark(at, rule)
        else:
            self.token(jf, c, fn, args, d, mod, out)
        # ---- Cookie
        rule = jf.rule(c, "cookie")
        if rule:
            self.model_cookie(jf, c, args, rule, out)
        elif last == "cookie" and len(args) >= 2 and len(d) >= 2 and d[-2] in {"res", "response", "reply"}:
            self.res_cookie(jf, c, args, out)
        elif len(d) >= 2 and d[-2] == "cookies" and last == "set" and len(args) >= 2:
            self.res_cookie(jf, c, args, out, defaults=(False, True, "lax"))
        if mod in {"express-session", "cookie-session", "koa-session", "@fastify/session", "@fastify/secure-session"} or \
                q in {"express-session", "cookie-session"}:
            self.session_cookie(jf, c, args, mod or q, out)
        # ---- LogStatement
        rule = jf.rule(c, "log")
        if rule:
            self.log(jf, c, args, out)
            out.mark(at, rule if ("LogStatement", at) in out.elements else None)
        elif (d[0] == "console" and last in LOG_METHODS) or (len(d) >= 2 and last in LOG_METHODS and "log" in d[-2].lower()) or (
                last in self.repo_functions and {"log", "audit", "logger"} & set(words(last))):  # the repository's own log helper
            self.log(jf, c, args, out)
        # ---- Transfer
        self.transfer(jf, c, fn, args, d, mod, out)
        # ---- routes, rate limits, policy, erasure
        self.route(jf, c, args, d, out)
        self.policy(jf, c, fn, args, d, out)
        recv = dotted(fn.child_by_field_name("object")) if fn.type == "member_expression" else []
        if last in {"init", "define", "model"} and ((recv and is_user_object_name(recv[-1].removesuffix("Model"))) or (
                args and str_value(args[0]) and is_user_object_name(str_value(args[0])))):
            out.signal("user_model", at)
        if last in {"destroy", "deleteOne", "deleteMany", "remove", "findOneAndDelete", "findByIdAndDelete", "findOneAndRemove",
                    "findByIdAndRemove", "delete"} and recv and any(w in USER_OBJECTS for p in recv[-2:] for w in words(p)) \
                and "session" not in recv and self.request_reachable(jf, c, args):
            out.signal("user_delete", at)
        elif deletes_a_person(last) and self.request_reachable(jf, c, args):
            out.signal("user_delete", at)   # the repository's own helper: deleteUser(userId)
        rule = jf.rule(c, "erasure")
        if rule and self.request_reachable(jf, c, args):
            out.signal("user_delete", at)
            out.mark(at, rule)
        rule = jf.rule(c, "rate_limit")
        if rule and rule.spec.get("scope") == "global":
            out.signal("rate_limit", at, scope="global")  # app-wide, whatever it is attached to
            out.mark(at, rule)

    def request_reachable(self, jf: JSFile, c, args) -> bool:
        """Inside a request handler, or passed request data (so not a seed or maintenance script)."""
        if any(jf.tainted(a, c) for a in args):
            return True
        return any(jf.taint.get(s, set()) & REQUEST_NAMES for s in jf.chain(c))

    def new(self, jf: JSFile, n, out: Collector, hashed):
        ctor = dotted(n.child_by_field_name("constructor"))
        args = kids(n.child_by_field_name("arguments"))
        if ctor and ctor[-1] == "Schema" and args:
            self.personal_object(jf, args[0], out, model=True, person=self.defines_person(n, ctor))

    # ------------------------------------------------------------ queries
    def classify(self, jf: JSFile, expr, at, depth=0):
        expr = unwrap(expr)
        if expr is None or depth > 4:
            return None, []
        t = expr.type
        if t == "string":
            return "parameterized", [str_value(expr) or ""]
        if t == "template_string":
            subs = any(c.type == "template_substitution" for c in expr.named_children)
            return ("interpolated" if subs else "parameterized"), ["".join(T(c) for c in expr.named_children if c.type == "string_fragment")]
        if t == "binary_expression" and T(expr.child_by_field_name("operator")) == "+":
            lc, lt = self.classify(jf, expr.child_by_field_name("left"), at, depth + 1)
            rc, rt = self.classify(jf, expr.child_by_field_name("right"), at, depth + 1)
            if lc == rc == "parameterized":
                return "parameterized", lt + rt
            return "concatenated", lt + rt
        if t == "identifier":
            best, texts = None, []
            rank = {"orm": 0, "parameterized": 1, "interpolated": 2, "concatenated": 3}
            for v in jf.resolve(T(expr), at):
                c, tx = self.classify(jf, v, at, depth + 1)
                texts += tx
                if c and (best is None or rank[c] > rank[best]):
                    best = c
            return best, texts
        if t == "call_expression":
            d = dotted(expr.child_by_field_name("function"))
            if d and d[-1] in {"concat", "join"}:
                return "concatenated", []
            if d and d[-1] in {"format", "replace"}:
                return "interpolated", template_text(expr.child_by_field_name("function"))
        return None, []

    def resolve_object(self, jf: JSFile, n, at):
        n = unwrap(n)
        if n is not None and n.type == "identifier":
            for v in jf.resolve(T(n), at):
                v = unwrap(v)
                if v is not None and v.type == "object":
                    return v
        if n is not None and n.type == "call_expression" and unwrap(n.child_by_field_name("function")).type == "identifier":
            # a local function that builds the filter: take the object it returns (one with $where first)
            name = T(unwrap(n.child_by_field_name("function")))
            objs = []
            for f in jf.funcs:
                if jf.func_name(f) == name:
                    body = f.child_by_field_name("body")
                    if unwrap(body) is not None and unwrap(body).type == "object":
                        objs.append(unwrap(body))
                    for r in walk_no_funcs(f):
                        if r.type == "return_statement" and kids(r) and unwrap(kids(r)[0]).type == "object":
                            objs.append(unwrap(kids(r)[0]))
            if objs:
                return next((o for o in objs if "$where" in obj_pairs(o)), objs[0])
        return n

    def query(self, jf: JSFile, c, fn, args, d, out: Collector, hashed):
        last = d[-1]
        at = jf.at(c)
        rule = jf.rule(c, "query")
        if rule:
            untrusted = any(jf.tainted(a, c) for a in args)
            construction = rule.spec.get("construction")
            if "text" in rule.spec:
                construction, _ = self.classify(jf, model_arg(rule.spec["text"], args), c)
            if untrusted or (construction is not None and "text" in rule.spec):
                out.element("Query", at, construction=construction, untrusted_input=untrusted)
                out.mark(at, rule)
            return
        if fn.type != "member_expression" and last not in {"query"}:
            return
        if last in RAW_SQL_METHODS and args:
            construction, texts = self.classify(jf, args[0], c)
            sql = " ".join(texts)
            if not texts or not (SQL_WORDS.search(sql) or SQL_ANY.search(sql)):
                return
            if last in {"get", "all", "run", "each", "exec", "prepare"} and not SQL_WORDS.search(sql):
                return
            untrusted = any(jf.tainted(a, c) for a in args[:2])
            out.element("Query", at, construction=construction, untrusted_input=untrusted)
            if re.search(r"\bpassword\b", sql, re.I):
                subs = [x for x in walk(args[0]) if x.type in ("template_substitution",)]
                vals = [kids(s)[0] for s in subs if kids(s)] + [x for x in walk(args[0]) if x.type == "member_expression"]
                vals += [x for a in args[1:2] for x in walk(a) if x.type in ("identifier", "member_expression")]
                for v in vals:
                    if self.raw_password(jf, v, hashed):
                        self.password_store(jf, c, out, "plaintext", False, jf.tainted(v, c))
                        break
                for v in vals:
                    for x in walk(v):
                        if x.type == "call_expression" and self.helper_of(x) and self.mentions_password(kids(x.child_by_field_name("arguments"))):
                            pass  # reported by call()
            if re.search(r"\bdelete\s+from\s+\W?(users?|accounts?|customers?)\b", sql, re.I):
                out.signal("user_delete", at)
            return
        if last not in DOC_METHODS or not args:
            return
        first = unwrap(args[0])
        if first is None or first.type in FUNC_TYPES:
            return
        obj = self.resolve_object(jf, first, c)
        pairs = obj_pairs(obj)
        tainted = any(jf.tainted(a, c) for a in args[:2]) or (obj is not first and jf.tainted(obj, c))
        recv = dotted(fn.child_by_field_name("object"))
        model_like = bool(recv) and (recv[-1][:1].isupper() or any(w in {"collection", "col", "model", "db", "coll"} for w in words(recv[-1])))
        if "where" in pairs or last in {"findAll", "findAndCountAll", "findByPk", "findOrCreate", "destroy"}:
            if tainted:
                out.element("Query", at, construction="orm", untrusted_input=True)
            return
        if last == "update" and len(args) > 1 and "where" in obj_pairs(self.resolve_object(jf, args[1], c)):
            if tainted:
                out.element("Query", at, construction="orm", untrusted_input=True)
            return
        if not (self.doc_db or model_like) or not model_like:
            return
        if "$where" in pairs:
            cons, _ = self.classify(jf, pairs["$where"], c)
            out.element("Query", at, construction=cons if cons in {"concatenated", "interpolated"} else "operator_object",
                        untrusted_input=jf.tainted(pairs["$where"], c) or tainted)
            return
        if last in {"findById", "findByIdAndUpdate", "findByIdAndDelete"}:
            if tainted:
                out.element("Query", at, construction="orm", untrusted_input=True)
            return
        if tainted and (obj is None or obj.type in ("object", "identifier", "member_expression", "call_expression")):
            out.element("Query", at, construction="operator_object", untrusted_input=True)

    # ------------------------------------------------------------ tokens
    def jwt_version_none(self, pkg: str):
        nested = self.nested.get(pkg)
        v = parse_version(nested or self.deps.get(pkg))
        return v

    def token(self, jf: JSFile, c, fn, args, d, mod, out: Collector):
        last = d[-1]
        at = jf.at(c)
        head_mod = mod or ("jsonwebtoken" if d[0] == "jwt" else ("jws" if d[0] == "jws" else ""))
        if head_mod == "jsonwebtoken" and len(d) >= 2:
            if last == "decode":
                out.element("TokenVerification", at, verifies_signature=False, allows_none_alg=True)
            elif last == "verify":
                opts = obj_pairs(args[2]) if len(args) > 2 else {}
                v = parse_version(self.deps.get("jsonwebtoken"))
                out.element("TokenVerification", at, verifies_signature=True,
                            allows_none_alg=self._algs(opts.get("algorithms"), v, (4, 2, 2)))
        elif head_mod == "jws" and len(d) >= 2:
            if last == "decode":
                out.element("TokenVerification", at, verifies_signature=False, allows_none_alg=True)
            elif last == "verify":
                if len(args) >= 3:
                    alg = (str_value(args[1]) or "")
                    allows = alg.lower() == "none" if str_value(args[1]) is not None else None
                else:
                    allows = True  # the algorithm is taken from the token's own header
                out.element("TokenVerification", at, verifies_signature=True, allows_none_alg=allows)
        elif mod.split(".")[0] in {"express-jwt", "koa-jwt"} and (len(d) == 1 or last in {"expressjwt", "expressJwt"}):
            opts = obj_pairs(args[0]) if args else {}
            pkg = mod.split(".")[0]
            v = parse_version(self.deps.get(pkg))
            nested = parse_version(self.nested.get(f"{pkg}/jsonwebtoken"))
            if "algorithms" in opts:
                allows = self._algs(opts["algorithms"], nested, (4, 2, 2))
            elif nested is not None:
                allows = nested < (4, 2, 2) or None
            elif pkg == "express-jwt" and v is not None and v < (1, 0, 0):
                allows = True  # express-jwt 0.x bundles a jsonwebtoken from before the 2015 alg=none fix
            else:
                allows = None
            out.element("TokenVerification", at, verifies_signature=True, allows_none_alg=allows)
        elif mod.startswith("jose") and last in {"jwtVerify", "compactVerify", "decodeJwt", "decodeProtectedHeader"}:
            if last.startswith("decode"):
                out.element("TokenVerification", at, verifies_signature=False, allows_none_alg=True)
            else:
                opts = obj_pairs(args[2]) if len(args) > 2 else {}
                out.element("TokenVerification", at, verifies_signature=True, allows_none_alg=self._algs(opts.get("algorithms"), None, None) or False)

    def _algs(self, node, version, fixed):
        """allows_none_alg from an `algorithms` option and the library version."""
        node = unwrap(node)
        if node is not None and node.type == "array":
            vals = [str_value(x) for x in kids(node)]
            if any(v is None for v in vals):
                return None
            low = [v.lower() for v in vals]
            if "none" in low:
                return True
            fam = {v[:2] for v in low}
            return bool("hs" in fam and fam & {"rs", "es", "ps"})  # algorithm confusion: HMAC next to public-key algorithms
        if node is not None:
            return None
        if version is not None and fixed is not None:
            return True if version < fixed else False
        return None

    # ------------------------------------------------------------ cookies
    def _cookie_opts(self, pairs, defaults):
        sec_d, ho_d, ss_d = defaults

        def b(key, default):
            if key not in pairs:
                return default
            return literal_bool(pairs[key])
        ss = ss_d
        if "sameSite" in pairs or "samesite" in pairs:
            v = pairs.get("sameSite", pairs.get("samesite"))
            s = str_value(v)
            lb = literal_bool(v)
            ss = s.lower() if s and s.lower() in {"strict", "lax", "none"} else ("strict" if lb is True else ("unset" if lb is False else None))
        return b("secure", sec_d), b("httpOnly", ho_d), ss

    def res_cookie(self, jf: JSFile, c, args, out: Collector, defaults=(False, False, "unset")):
        name = str_value(args[0])
        opts = obj_pairs(self.resolve_object(jf, args[2], c)) if len(args) > 2 else {}
        sec, ho, ss = self._cookie_opts(opts, defaults)
        is_sess = True if name and session_cookie_name(name) else None
        out.element("Cookie", jf.at(c), secure=sec, http_only=ho, same_site=ss, is_session=is_sess)

    def session_cookie(self, jf: JSFile, c, args, mod, out: Collector):
        opts = obj_pairs(self.resolve_object(jf, args[0], c)) if args else {}
        if mod.startswith("cookie-session"):
            pairs = opts
        else:
            pairs = obj_pairs(self.resolve_object(jf, opts.get("cookie"), c)) if opts.get("cookie") is not None else {}
        sec, ho, ss = self._cookie_opts(pairs, (False, True, "unset"))
        out.element("Cookie", jf.at(c), is_session=True, secure=sec, http_only=ho, same_site=ss)

    def model_cookie(self, jf: JSFile, c, args, rule, out: Collector):
        s = dict(rule.spec)
        name_arg = s.pop("name", None)
        options = s.pop("options", {}) or {}
        if "is_session" not in s and name_arg is not None:
            name = str_value(model_arg(name_arg, args))
            s["is_session"] = True if name and session_cookie_name(name) else None
        pairs = obj_pairs(self.resolve_object(jf, args[-1], c)) if args and options else {}
        for fact, key in options.items():
            if key in pairs:
                if fact == "same_site":
                    v = str_value(pairs[key])
                    s[fact] = v.lower() if v and v.lower() in {"strict", "lax", "none"} else None
                else:
                    s[fact] = literal_bool(pairs[key])
        out.element("Cookie", jf.at(c), **s)
        out.mark(jf.at(c), rule)

    def client_cookie(self, jf: JSFile, n, name, opts, out: Collector):
        is_sess = True if name and session_cookie_name(name) else None
        if isinstance(opts, str):  # document.cookie = "a=b; Secure; SameSite=Lax"
            sec = bool(re.search(r";\s*secure", opts, re.I))
            m = re.search(r"samesite=(strict|lax|none)", opts, re.I)
            ss = m.group(1).lower() if m else "unset"
        else:
            sec, _, ss = self._cookie_opts(opts or {}, (False, False, "unset"))
        out.element("Cookie", jf.at(n), secure=sec, http_only=False, same_site=ss, is_session=is_sess)

    def client_call(self, jf: JSFile, c, fn, args, d, out: Collector):
        last = d[-1]
        recv = d[-2].lower() if len(d) >= 2 else ""
        if last in {"put", "set"} and ("cookie" in recv) and len(args) >= 2:
            opts = obj_pairs(self.resolve_object(jf, args[2], c)) if len(args) > 2 else {}
            name = str_value(args[0]) or T(args[0])
            self.client_cookie(jf, c, name, opts, out)
        self.transfer(jf, c, fn, args, d, jf.module_of(fn), out)

    # ------------------------------------------------------------ logs and transfers
    def log(self, jf: JSFile, c, args, out: Collector):
        creds = personal = False
        for a in args:
            for x in walk_no_funcs(a):
                if x.type in ("string", "template_string") and x.type != "template_string":
                    continue
                if x.type in ("identifier", "shorthand_property_identifier"):
                    p = x.parent
                    owner = None
                    nm = T(x)
                    if is_credential_name(nm) and nm not in {"req", "request"}:
                        creds = True
                    if is_personal_name(nm) or is_user_object_name(nm) and not (p is not None and p.type == "member_expression"):
                        personal = True
                elif x.type == "member_expression":
                    dd = dotted(x)
                    nm = dd[-1] if dd else ""
                    owner = dd[-2] if len(dd) > 1 else None
                    if is_credential_name(nm):
                        creds = True
                    if is_personal_name(nm, owner):
                        personal = True
                    whole = not (x.parent is not None and x.parent.type in ("member_expression", "subscript_expression")
                                 and x.parent.child_by_field_name("object") == x)
                    if whole and jf.is_source(x) and len(dd) == 2 and dd[1] in {"body", "cookies", "headers"}:
                        creds = True  # the whole body, cookie jar, or header set
        if creds or personal:
            out.element("LogStatement", jf.at(c), logs_credentials=creds, logs_personal_data=personal)

    def url_host(self, jf: JSFile, node, at):
        node = unwrap(node)
        if node is None:
            return None
        s = str_value(node)
        if s is None and node.type == "template_string":
            frags = template_text(node)
            s = frags[0] if frags else None
        if s is None and node.type == "binary_expression":
            frags = template_text(node)
            s = frags[0] if frags else None
        if s is None and node.type == "identifier":
            for v in jf.resolve(T(node), at):
                s = str_value(v) or (template_text(v)[0] if template_text(v) else None)
                if s:
                    break
        return external_host(s) if s else None

    def transfer(self, jf: JSFile, c, fn, args, d, mod, out: Collector):
        last = d[-1]
        at = jf.at(c)
        rule = jf.rule(c, "transfer")
        if rule:
            personal = rule.spec.get("personal_data", "infer")
            if personal == "infer":
                personal = self._personal(args) or None
            out.element("Transfer", at, recipient=rule.spec["recipient"], personal_data=personal,
                        third_country=rule.spec.get("third_country"))
            out.mark(at, rule)
            return
        top = mod.split(".")[0] if mod else ""
        body = []
        host = None
        if d == ["fetch"] or top in HTTP_CLIENTS or (len(d) >= 2 and d[-2] in {"http", "https", "axios", "$http", "httpClient", "http_"} and
                                                      last in {"post", "put", "patch", "request", "get"}):
            if args:
                host = self.url_host(jf, args[0], c)
                if host is None and unwrap(args[0]) is not None and unwrap(args[0]).type == "object":
                    pairs = obj_pairs(args[0])
                    host = self.url_host(jf, pairs.get("url") or pairs.get("uri") or pairs.get("host"), c)
                    body = [pairs[k] for k in ("body", "data", "json", "form", "qs", "params") if k in pairs]
                if len(args) > 1:
                    o = obj_pairs(args[1])
                    body += [o[k] for k in ("body", "data", "json", "form") if k in o] or ([args[1]] if last in {"post", "put", "patch"} else [])
            sends = body or last in {"post", "put", "patch"}
            if host is None and args and sends:
                key = self.configured(jf, args[0], c)
                if key:
                    host = f"configured endpoint ({key})"
            if host and sends:
                out.element("Transfer", at, recipient=host, personal_data=self._personal(body) or None)
            return
        if mod in {"ai.streamText", "ai.generateText", "ai.streamObject", "ai.generateObject", "ai.embed", "ai.embedMany"}:
            out.element("Transfer", at, recipient=self.llm_provider(jf, c), personal_data=None)
            return
        if top in SDK_SENDERS and (last in {"send", "sendMail", "create", "capture", "track", "identify", "messages"} or len(d) == 1):
            if top == "nodemailer" and last != "sendMail":
                return
            out.element("Transfer", at, recipient=SDK_SENDERS[top], personal_data=True if last in {"send", "sendMail", "identify"} else (self._personal(args) or None))
        elif last == "sendMail" and len(args) >= 1:
            out.element("Transfer", at, recipient="email (SMTP relay)", personal_data=True)

    def configured(self, jf: JSFile, node, at, depth=0) -> str | None:
        """The environment variable or configuration key a URL is read from."""
        node = unwrap(node)
        if node is None or depth > 3:
            return None
        d = dotted(node)
        if d[:2] == ["process", "env"] and len(d) == 3:
            return d[2]
        if node.type == "call_expression" and d and d[-1] == "get" and len(d) >= 2 and d[-2] in {"config", "settings", "nconf", "convict"}:
            a = kids(node.child_by_field_name("arguments"))
            return str_value(a[0]) if a else None
        if node.type == "identifier":
            for v in jf.resolve(T(node), at):
                k = self.configured(jf, v, at, depth + 1)
                if k:
                    return k
        if node.type == "binary_expression":
            return self.configured(jf, node.child_by_field_name("left"), at, depth + 1)
        return None

    def llm_provider(self, jf: JSFile, c) -> str:
        mods = set(jf.aliases.values())
        names = {"@ai-sdk/openai": "OpenAI", "@ai-sdk/anthropic": "Anthropic", "@ai-sdk/google": "Google Gemini",
                 "@ai-sdk/mistral": "Mistral", "@ai-sdk/azure": "Azure OpenAI", "@ai-sdk/amazon-bedrock": "AWS Bedrock",
                 "@ai-sdk/groq": "Groq", "@ai-sdk/cohere": "Cohere"}
        for m in sorted(mods):
            base = m.split(".")[0] if not m.startswith("@") else "/".join(m.split("/")[:2]).split(".")[0]
            if base in names:
                return names[base]
            if base == "@ai-sdk/openai-compatible":
                for n in jf.nodes:
                    if n.type == "pair" and T(n.child_by_field_name("key")) == "baseURL":
                        key = self.configured(jf, n.child_by_field_name("value"), n)
                        host = self.url_host(jf, n.child_by_field_name("value"), n)
                        return f"LLM API, OpenAI-compatible ({host or key or 'configured base URL'})"
                return "LLM API, OpenAI-compatible"
        return "LLM API"

    def _personal(self, nodes) -> bool:
        for n in nodes:
            for x in walk(n):
                if x.type in ("identifier", "property_identifier", "shorthand_property_identifier") and (is_personal_name(T(x)) or is_user_object_name(T(x))):
                    return True
        return False

    # ------------------------------------------------------------ routes and policy
    def route(self, jf: JSFile, c, args, d, out: Collector):
        last = d[-1]
        if len(d) < 2 or last not in {"post", "get", "put", "patch", "use", "all", "route"}:
            return
        path = str_value(args[0]) if args else None
        handlers = args[1:] if path is not None else args
        limited = any(self.is_limiter(jf, h, c) for h in handlers)
        if limited:
            for h in handlers:
                if unwrap(h) is not None and unwrap(h).type == "call_expression":
                    out.mark(jf.at(c), jf.rule(unwrap(h), "rate_limit"))
        if path is not None and LOGIN_PATH.search(path) and last in {"post", "all", "use", "route"} and not re.search(r"logout|reset|forgot|2fa|totp|oauth|callback|refresh", path, re.I):
            out.signal("login_route", jf.at(c), path=path)
            if limited:
                out.signal("rate_limit", jf.at(c), scope="login", route_at=jf.at(c))
        elif limited:
            out.signal("rate_limit", jf.at(c), scope="global" if path is None and last == "use" else "other")

    def is_limiter(self, jf: JSFile, h, at) -> bool:
        h = unwrap(h)
        if h is None:
            return False
        if h.type == "call_expression":
            fn = h.child_by_field_name("function")
            d = dotted(fn)
            if jf.rule(h, "rate_limit"):
                return True
            if d and re.search(r"rate_?limit|slow_?down|limiter|brute", d[-1], re.I):
                return True
        if h.type == "member_expression":
            d = dotted(h)
            if d and d[-1] == "prevent":
                return True
        if h.type == "identifier":
            if re.search(r"limit|brute|throttl", T(h), re.I):
                return True
            return any(self.is_limiter(jf, v, at) for v in jf.resolve(T(h), at) if unwrap(v) is not None and unwrap(v).type == "call_expression")
        return False

    def context_is_password(self, n) -> bool:
        p = n.parent
        steps = 0
        while p is not None and steps < 14:
            name = None
            if p.type == "pair":
                k = p.child_by_field_name("key")
                name = str_value(k) if k.type == "string" else T(k)
            elif p.type in ("variable_declarator", "public_field_definition", "field_definition"):
                name = T(p.child_by_field_name("name"))
            elif p.type == "assignment_expression":
                dd = dotted(p.child_by_field_name("left"))
                name = dd[-1] if dd else None
            elif p.type == "jsx_attribute":
                name = T(kids(p)[0]) if kids(p) else None
            elif p.type == "call_expression":
                a = kids(p.child_by_field_name("arguments"))
                fnd = dotted(p.child_by_field_name("function"))
                if a and str_value(a[0]) is not None and fnd and fnd[-1] in {"body", "check", "param", "field", "register", "query", "string", "object"}:
                    name = str_value(a[0])
            if name is not None:
                ws = set(words(name))
                if loose_password(name):
                    return True
                if ws & PW_NEGATIVE or not ws <= POLICY_GENERIC | {"is", "required", "new", "user", "signup", "sign", "up", "registration"}:
                    if not ws <= POLICY_GENERIC:
                        return False
            p = p.parent
            steps += 1
        return False

    def regex_of(self, jf: JSFile, n, at):
        n = unwrap(n)
        if n is None:
            return None
        if n.type == "regex":
            return T(n.child_by_field_name("pattern"))
        if n.type == "identifier":
            for v in jf.resolve(T(n), at):
                v = unwrap(v)
                if v is not None and v.type == "regex":
                    return T(v.child_by_field_name("pattern"))
                if v is not None and v.type == "new_expression" and dotted(v.child_by_field_name("constructor")) == ["RegExp"]:
                    a = kids(v.child_by_field_name("arguments"))
                    return str_value(a[0]) if a else None
        if n.type == "new_expression" and dotted(n.child_by_field_name("constructor")) == ["RegExp"]:
            a = kids(n.child_by_field_name("arguments"))
            return str_value(a[0]) if a else None
        return None

    def policy(self, jf: JSFile, c, fn, args, d, out: Collector):
        last = d[-1]
        at = jf.at(c)
        side = "client" if jf.sf.client else "server"
        rule = jf.rule(c, "password_policy")
        if rule:
            model_policy(rule, at, side, out)
        if advisory(jf, c):
            return  # a strength meter scores a password; it does not enforce anything
        # RE.test(password) / password.match(RE)
        if last in {"test", "match", "search"} and fn.type == "member_expression" and args:
            obj = fn.child_by_field_name("object")
            pat, target = (self.regex_of(jf, obj, c), args[0]) if last == "test" else (self.regex_of(jf, args[0], c), obj)
            if pat is not None and target is not None and any(loose_password(T(x)) for x in walk(target)
                                                               if x.type in ("identifier", "property_identifier")):
                self._regex_policy(pat, at, side, out)
        nums = [int(T(unwrap(a))) for a in args if unwrap(a) is not None and unwrap(a).type == "number" and T(unwrap(a)).isdigit()]
        if last in {"min", "minLength"} and nums and fn.type == "member_expression" and nums[0] < max(self.chain_numbers(c, last), default=0):
            return  # z.string().min(1).min(8): the larger bound is the rule, the smaller one only says "required"
        field = unwrap(args[0]) if args and last in {"minLength", "maxLength", "pattern", "min", "max"} else None
        if field is not None and field.type in ("member_expression", "identifier") and nums and len(args) >= 2:
            if not loose_password(dotted(field)[-1] if dotted(field) else ""):
                return  # Angular signal forms: minLength(s.newPassword, 5) names the field it constrains
            pw_ctx = True
        else:
            pw_ctx = None
        ctx_ok = (lambda: True) if pw_ctx else (lambda: self.context_is_password(c))
        if last in {"minLength", "min", "minlength"} and nums and ctx_ok():
            out.signal("pw_min", at, nums[0], side=side)
            out.signal("pw_validation", at, side=side)
        elif last in {"maxLength", "max", "maxlength"} and nums and ctx_ok():
            out.signal("pw_max", at, nums[0], side=side)
            out.signal("pw_validation", at, side=side)
        elif last in {"isLength", "length", "len"} and args and self.context_is_password(c):
            o = obj_pairs(args[0])
            for key, sig in (("min", "pw_min"), ("max", "pw_max")):
                v = unwrap(o.get(key))
                if v is not None and v.type == "number":
                    out.signal(sig, at, int(float(T(v))), side=side)
                    out.signal("pw_validation", at, side=side)
            if len(nums) >= 1 and last == "length":
                out.signal("pw_min", at, nums[0], side=side)
                if len(nums) > 1:
                    out.signal("pw_max", at, nums[1], side=side)
                out.signal("pw_validation", at, side=side)
        elif last in {"pattern", "matches", "regex"} and args and self.context_is_password(c):
            pat = self.regex_of(jf, args[0], c) or str_value(args[0])
            if pat:
                self._regex_policy(pat, at, side, out)
        elif last == "isStrongPassword" and self.context_is_password(c):
            o = obj_pairs(args[0]) if args else {}
            mn = unwrap(o.get("minLength"))
            out.signal("pw_min", at, int(T(mn)) if mn is not None and mn.type == "number" else 8, side=side)
            out.signal("pw_composition", at, side=side)
            out.signal("pw_validation", at, side=side)
        if jf.module_of(fn).split(".")[0] in {"zxcvbn", "hibp", "pwnedpasswords", "@zxcvbn-ts/core"} or any(
                "pwnedpasswords" in (str_value(a) or "") for a in args):
            out.signal("pw_blocklist", at)
        if last == "includes" and args and fn.type == "member_expression" and loose_password(T(args[0])) and any(
                w in {"common", "blocklist", "blacklist", "banned", "weak", "pwned", "breached", "compromised", "denylist"}
                for w in words(T(fn.child_by_field_name("object")))):
            out.signal("pw_blocklist", at)

    def chain_numbers(self, c, method: str) -> list[int]:
        """Numeric first arguments of every `.method(n)` call in the method chain that contains `c`."""
        top = c
        while top.parent is not None and top.parent.type in {"member_expression", "call_expression"} | WRAPPERS:
            top = top.parent
        out = []
        for x in walk_no_funcs(top):
            if x.type == "call_expression":
                d = dotted(x.child_by_field_name("function"))
                a = kids(x.child_by_field_name("arguments"))
                if d and d[-1] == method and a and unwrap(a[0]).type == "number" and T(unwrap(a[0])).isdigit():
                    out.append(int(T(unwrap(a[0]))))
        return out

    def _regex_policy(self, pat, at, side, out: Collector):
        r = analyse_password_regex(pat)
        if "min" in r:
            out.signal("pw_min", at, r["min"], side=side)
        if "max" in r:
            out.signal("pw_max", at, r["max"], side=side)
        if r.get("composition"):
            out.signal("pw_composition", at, side=side)
        out.signal("pw_validation", at, side=side)

    def binary(self, jf: JSFile, n, out: Collector, hashed):
        if advisory(jf, n):
            return
        op = T(n.child_by_field_name("operator"))
        left, right = unwrap(n.child_by_field_name("left")), unwrap(n.child_by_field_name("right"))
        at = jf.at(n)
        side = "client" if jf.sf.client else "server"
        if op in {"===", "==", "!==", "!="}:
            for a, b in ((left, right), (right, left)):
                if a is None or b is None:
                    continue
                if not jf.sf.client and a.type == "member_expression" and is_stored_password_name(dotted(a)[-1]) and not jf.is_source(a) \
                        and self.raw_password(jf, b, hashed) and not (b.type == "member_expression" and not jf.is_source(b)):
                    self.password_store(jf, n, out, "plaintext", False)
                s = str_value(b)
                if s is not None and a.type in ("identifier", "member_expression") and is_password_name((dotted(a) or [""])[-1]) \
                        and plausible_secret_value(s, "password"):
                    out.element("Secret", at, kind="password", test_or_example=True if jf.sf.example else None)
        for a, b, o in ((left, right, op), (right, left, {"<": ">", ">": "<", "<=": ">=", ">=": "<="}.get(op))):
            if a is not None and b is not None and o and a.type == "member_expression" and dotted(a)[-1:] == ["length"] \
                    and loose_password((dotted(a) or ["", ""])[-2] if len(dotted(a)) > 1 else "") and b.type in ("number", "identifier"):
                k = _int_value(jf, b)   # a literal, or a top-level constant (const MIN_LENGTH = 8)
                bound = length_bound(o, k, _invalid_when(n)) if k is not None else None
                if bound:
                    out.signal("pw_min" if bound[0] == "min" else "pw_max", at, bound[1], side=side)
                out.signal("pw_validation", at, side=side)

    def object(self, jf: JSFile, n, out: Collector, hashed):
        if jf.sf.client:
            pairs = obj_pairs(n)
            for key in ("minLength", "maxLength", "pattern"):
                if key in pairs and self.context_is_password(n):
                    v = unwrap(pairs[key])
                    if v is not None and v.type == "object":
                        v = unwrap(obj_pairs(v).get("value"))
                    if v is None:
                        continue
                    if key == "pattern":
                        pat = self.regex_of(jf, v, n)
                        if pat:
                            self._regex_policy(pat, jf.at(pairs[key]), "client", out)
                    elif v.type == "number" and T(v).isdigit():
                        out.signal("pw_min" if key == "minLength" else "pw_max", jf.at(pairs[key]), int(T(v)), side="client")
                        out.signal("pw_validation", jf.at(pairs[key]), side="client")
            return
        p = n.parent
        call = None
        if p is not None and p.type == "arguments":
            call = p.parent
        recv_name = ""
        if call is not None and call.type in ("call_expression", "new_expression"):
            fd = dotted(call.child_by_field_name("function") or call.child_by_field_name("constructor"))
            recv_name = fd[-1] if fd else ""
        holder = None
        if p is not None and p.type == "variable_declarator":
            holder = T(p.child_by_field_name("name"))
        db_call = recv_name in {"create", "insert", "insertOne", "insertMany", "save", "update", "updateOne", "build", "upsert",
                                "bulkCreate", "findOrCreate", "set", "findOneAndUpdate", "replaceOne"} or (recv_name[:1].isupper() and recv_name not in {"Error", "Promise", "Date"})
        user_holder = holder is not None and is_user_object_name(holder)
        if recv_name in {"init", "define", "Schema"}:
            self.personal_object(jf, n, out, model=True, person=self.defines_person(call, fd))
        elif recv_name == "object" or (db_call or user_holder) and any(is_personal_name(k) for k in obj_pairs(n)):
            self.personal_object(jf, n, out)   # a record written, or a validation schema (zod, Joi, yup)
        if not (db_call or user_holder):
            return
        for key, v in obj_pairs(n).items():
            if key and is_stored_password_name(key) and self.raw_password(jf, v, hashed):
                if self.model_hashes_password and not user_holder:
                    out.signal("pw_set_site", jf.at(v))
                    continue
                self.password_store(jf, v, out, "plaintext", False, jf.tainted(v, v))

    def personal_object(self, jf: JSFile, n, out: Collector, model=False, person=False):
        """Fields that hold personal data: named so, typed or validated as an email, phone number or IP address
        (`isEmail`, `z.string().email()`), or any field of a model of a person, whatever language it is named in."""
        for key, v in obj_pairs(n).items():
            text = T(v)
            typed = set(re.findall(r"\w+", text)) & (PERSONAL_TYPES - {"email"}) or re.search(r"\.email\s*\(", text)
            if key and (is_personal_name(key) or typed or person and is_record_field(key)):
                out.signal("personal_field", jf.at(v), model=model)

    @staticmethod
    def defines_person(call, fd) -> bool:
        """The model a schema call defines is a record about a person: `User.init({…})`, `define('User', {…})`,
        `const UserSchema = new Schema({…})`, `model('User', new Schema({…}))`."""
        names = [fd[-2]] if len(fd) >= 2 else []
        args = kids(call.child_by_field_name("arguments"))
        if args and str_value(args[0]):
            names.append(str_value(args[0]))
        up = call.parent
        if up is not None and up.type == "variable_declarator":
            names.append(T(up.child_by_field_name("name")))
        elif up is not None and up.type == "arguments":
            outer = kids(up)
            if outer and str_value(outer[0]):
                names.append(str_value(outer[0]))
        return any(is_user_object_name(re.sub(r"(Schema|Model)$", "", x)) for x in names if x)

    # ------------------------------------------------------------ secrets
    def secrets(self, jf: JSFile, out: Collector):
        ex = True if jf.sf.example else None
        seen = set()
        for n in jf.nodes:
            pairs = []
            t = n.type
            if t == "variable_declarator":
                pairs.append((T(n.child_by_field_name("name")), n.child_by_field_name("value")))
            elif t == "assignment_expression":
                dd = dotted(n.child_by_field_name("left"))
                if dd:
                    pairs.append((dd[-1], n.child_by_field_name("right")))
            elif t == "pair":
                k = n.child_by_field_name("key")
                pairs.append((str_value(k) if k.type == "string" else T(k), n.child_by_field_name("value")))
            elif t in ("public_field_definition", "field_definition"):
                pairs.append((T(n.child_by_field_name("name")), n.child_by_field_name("value")))
            elif t == "call_expression":
                fn = n.child_by_field_name("function")
                d = dotted(fn)
                a = kids(n.child_by_field_name("arguments"))
                mod = jf.module_of(fn)
                if d and d[-1] in {"sign", "verify"} and (mod == "jsonwebtoken" or d[0] in {"jwt", "jws"}) and len(a) > 1:
                    pairs.append(("signing_key", a[1]))
                if d and d[-1] == "createHmac" and len(a) > 1:
                    pairs.append(("hmac_key", a[1]))
                if mod.split(".")[0] in {"cookie-parser"} and a:
                    pairs.append(("cookie_secret", a[0]))
            for name, v in pairs:
                s = str_value(v)
                if s is None or not name:
                    continue
                kind = literal_secret_kind(s) or secret_kind_for_name(name)
                if kind and plausible_secret_value(s, kind):
                    out.element("Secret", jf.at(v), kind=kind, test_or_example=ex)
                    seen.add(v.id)
        for n in jf.nodes:
            if n.type in ("string_fragment",) and n.parent is not None and n.parent.id not in seen:
                kind = literal_secret_kind(T(n))
                if kind:
                    out.element("Secret", jf.at(n), kind=kind, test_or_example=ex)


def _int_value(jf: JSFile, node) -> int | None:
    """A whole-number literal, or an identifier the file declares once at its top level as one."""
    if node.type == "number":
        return int(T(node)) if T(node).isdigit() else None
    if node.type != "identifier":
        return None
    vals = []
    for decl in jf.root.children:
        decl = decl.child_by_field_name("declaration") or decl if decl.type == "export_statement" else decl
        if decl is None or decl.type not in ("lexical_declaration", "variable_declaration"):
            continue
        for d in decl.children:
            if d.type == "variable_declarator" and T(d.child_by_field_name("name") or d) == T(node):
                v = d.child_by_field_name("value")
                vals.append(int(T(v)) if v is not None and v.type == "number" and T(v).isdigit() else None)
    return vals[0] if len(vals) == 1 else None
