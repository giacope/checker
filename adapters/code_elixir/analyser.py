"""Elements and signals from Elixir source: Phoenix, Plug, Ecto, and the libraries Phoenix apps use.

Taint (request data) starts at a Phoenix controller action's second argument, `conn.params` and the other request
fields of a conn, LiveView `handle_event/3` and `handle_params/3` params, and channel payloads. It flows through `=`
and `<-` matches, `case` clauses, pipes, and standard-library transformations (String, Enum, Map, ...), and steps
into project functions by name and arity (a tainted argument taints that parameter in the callee). A project
function's return value is not tainted by its arguments, so `user = Repo.get_by(User, email: email)` is not request
data; stored user content is recognised separately, by the fields request data is cast into (see `user_writable`).
"""

from __future__ import annotations

import re

from adapters.code_static.common import (PW_EXPIRY, Collector, external_host, is_credential_name,
                                         is_password_name, is_personal_name, is_record_field, is_stored_password_name,
                                         is_user_object_name, literal_secret_kind, plausible_secret_value,
                                         secret_kind_for_name, session_cookie_name, words)
from adapters.code_static.models import Models, arg as model_arg

from .syntax import (ExFile, Func, Module, L, T, arguments, atom, boolean, call_args, callee, do_block,
                     has_interpolation, has_parens, integer, interpolations, is_var_ref, kids, kw, module_kind, op, parser, pattern_vars, piped_into, same, string, target, unary, walk, word_list)

SOURCE_FIELDS = {"params", "body_params", "query_params", "path_params", "req_cookies", "cookies", "req_headers",
                 "query_string"}
SOURCE_CALLS = {"get_req_header", "read_body", "fetch_query_params", "fetch_cookies", "parse_query", "get_peer_data"}
PROPAGATE_MODULES = {"String", "Enum", "Map", "List", "Base", "URI", "Jason", "Poison", "JSON", "Kernel",
                     "Tuple", "Path", "IO", "Access", "Stream", "MapSet", "Regex", "Ecto.Changeset", ":erlang",
                     ":binary", ":unicode", ":string", ":lists", "Plug.Conn.Query"}
PROPAGATE_LOCALS = {"inspect", "to_string", "elem", "hd", "tl", "get_in", "binary_part", "to_charlist", "put_in",
                    "update_in", "then", "tap", "struct", "struct!", "get_change", "get_field", "fetch_change",
                    "fetch_field", "apply_changes", "max", "min", "sigil_s", "sigil_S", "sigil_c"}
CONTROL = {"case", "if", "unless", "cond", "with", "for", "try", "receive", "fn", "quote"}
SANITIZING = {"to_integer", "to_float", "to_existing_atom", "parse", "length", "byte_size", "count", "html_escape",
              "safe_to_string", "escape", "uuid?", "cast"}

HASHERS = {"Bcrypt": "bcrypt", "Argon2": "argon2", "Pbkdf2": "pbkdf2", "Comeonin.Bcrypt": "bcrypt",
           "Comeonin.Argon2": "argon2", "Comeonin.Pbkdf2": "pbkdf2", "Bcrypt.Base": "bcrypt", "Argon2.Base": "argon2",
           "Pbkdf2.Base": "pbkdf2"}
HASHER_DEPS = {"bcrypt_elixir": "bcrypt", "argon2_elixir": "argon2", "pbkdf2_elixir": "pbkdf2"}
HASH_SET = {"hash_pwd_salt": 0, "add_hash": 0, "hashpwsalt": 0, "hash_password": 0}
HASH_VERIFY = {"verify_pass": 0, "check_pass": 1, "checkpw": 0}
CRYPTO_ALGS = {"md5": "md5", "md4": "other", "sha": "sha1", "sha224": "sha256", "sha256": "sha256", "sha3_256": "sha256",
               "sha384": "sha512", "sha512": "sha512", "sha3_512": "sha512", "blake2b": "other", "blake2s": "other"}
PW_FIELDS = {"password", "hashed_password", "password_hash", "encrypted_password", "crypted_password", "passwd", "pwd"}

REPO_RAW = {"query", "query!", "query_many", "query_many!"}
SQL_ADAPTER = {"Ecto.Adapters.SQL.query", "Ecto.Adapters.SQL.query!", "Ecto.Adapters.SQL.query_many",
               "Ecto.Adapters.SQL.query_many!", "Ecto.Adapters.SQL.stream", "Postgrex.query", "Postgrex.query!",
               "Postgrex.prepare_execute", "Postgrex.prepare_execute!", "MyXQL.query", "MyXQL.query!",
               "Exqlite.Sqlite3.execute", "Ecto.Adapters.SQL.explain"}
ORM_FUNCS = {"get", "get!", "get_by", "get_by!", "all", "one", "one!", "insert", "insert!", "update", "update!",
             "delete", "delete!", "insert_all", "update_all", "delete_all", "exists?", "aggregate", "paginate",
             "stream", "insert_or_update", "insert_or_update!"}
QUERY_MACROS = {"from", "where", "or_where", "join", "order_by", "select", "having", "group_by", "limit", "offset",
                "distinct", "preload", "subquery"}

LOG_LEVELS = {"debug", "info", "notice", "warning", "warn", "error", "critical", "alert", "emergency", "log"}
USER_TABLES = {"users", "user", "accounts", "customers", "members", "people", "persons", "profiles", "patients",
               "employees", "students", "clients"}
PRIVILEGED = {"role", "roles", "admin", "is_admin", "superuser", "is_superuser", "staff", "is_staff", "permissions",
              "user_id", "owner_id", "account_id", "org_id", "organization_id", "tenant_id", "team_id", "balance",
              "credits", "is_verified", "verified", "user_role", "access_level"}
SALT_WORD = re.compile(r"(^|_)salt(_|$)", re.I)
PLACEHOLDER = re.compile(r"(change[_\-]?me|example|your[_\-]|xxx+|placeholder|dummy|replace[_\-]?me|todo|<[^>]+>|"
                         r"^secret$|^password$|^test|fake|sample|insecure)", re.I)
HTTP_POST = {"post", "post!", "put", "put!", "patch", "patch!"}
MAIL_ADAPTERS = {"Sendgrid": "SendGrid", "Mailgun": "Mailgun", "Postmark": "Postmark", "SMTP": "email (SMTP relay)",
                 "AmazonSES": "AWS SES", "ExAwsAmazonSES": "AWS SES", "Mandrill": "Mailchimp Mandrill",
                 "Sendinblue": "Brevo", "Brevo": "Brevo", "SparkPost": "SparkPost", "Mailjet": "Mailjet",
                 "Gmail": "Google Gmail", "SocketLabs": "SocketLabs", "Mailtrap": "Mailtrap", "Resend": "Resend",
                 "Scaleway": "Scaleway", "Loops": "Loops", "MailPace": "MailPace", "ProtonBridge": "email (SMTP relay)",
                 "SendGridAdapter": "SendGrid", "MailgunAdapter": "Mailgun", "PostmarkAdapter": "Postmark",
                 "SMTPAdapter": "email (SMTP relay)", "SesAdapter": "AWS SES", "MandrillAdapter": "Mailchimp Mandrill",
                 "SparkPostAdapter": "SparkPost"}
SAAS = [  # (module prefix, functions or None for any, recipient, personal data from the call's arguments)
    ("Stripe", None, "Stripe"), ("ExTwilio", None, "Twilio"), ("Segment.Analytics", None, "Segment"),
    ("Segment", {"track", "identify", "page", "screen"}, "Segment"), ("Mixpanel", {"track", "people_set"}, "Mixpanel"),
    ("Posthog", {"capture", "identify"}, "PostHog"), ("Sentry", {"capture_exception", "capture_message"}, "Sentry"),
    ("Appsignal", {"send_error", "set_error"}, "AppSignal"), ("Honeybadger", {"notify"}, "Honeybadger"),
    ("ExAws.SES", None, "AWS SES"), ("OpenAI", None, "OpenAI"), ("OpenaiEx", None, "OpenAI"), ("Anthropix", None, "Anthropic"),
    ("Mailchimp", None, "Mailchimp"), ("Intercom", None, "Intercom"), ("Hubspot", None, "HubSpot"),
]
RATE_LIMIT_MODULES = {"Hammer": "check_rate|hit|check_rate_inc|inc", "ExRated": "check_rate|inspect_bucket",
                      ":fuse": "ask|melt|run"}


def _norm(name: str) -> str:
    return name[:-1] if name.endswith(("?", "!")) else name


class Analyser:
    def __init__(self, files: list[ExFile], ctx: dict, out: Collector):
        self.files = files
        self.ctx = ctx
        self.out = out
        self.fm: Models = ctx["models"]
        self.deps = ctx["deps"]
        self.modules: dict[str, Module] = {}
        self.funcs: list[Func] = []
        self.by_node: dict[int, Func] = {}
        self.heads: set[int] = set()
        for ef in files:
            for m in ef.modules:
                self.modules.setdefault(m.name, m)
                for f in m.funcs:
                    self.funcs.append(f)
                    self.by_node[f.node.id] = f
                    a = arguments(f.node)
                    if a:
                        h = a[0]
                        self.heads.add(h.id)
                        if op(h) == "when" and h.child_by_field_name("left") is not None:
                            self.heads.add(h.child_by_field_name("left").id)
        self.kinds = {m.name: module_kind(m) for m in self.modules.values()}
        self.user_schemas = set()
        for m in self.modules.values():
            if "schema" in self.kinds[m.name]:
                for s in walk(m.node):
                    if s.type == "call" and T(target(s)) == "schema" and arguments(s) and (string(arguments(s)[0]) or "").lower() in USER_TABLES:
                        self.user_schemas.add(m.name)
                        break
        self.taint: dict[int, set] = {}      # id(func) -> tainted variable names
        self.seeds: dict[int, set] = {}      # id(func) -> tainted parameter positions
        self.reach_entries: dict[int, set] = {}  # id(func) -> entry modules that reach it
        self.user_writable: set[str] = set()
        self.user_delete_any: list[str] = []
        self.login_actions: dict[tuple, list[str]] = {}   # (controller, action) -> login route locators
        self._calls: dict[int, list] = {}
        self._bindings: dict[int, list] = {}
        self._defs: dict[int, dict] = {}
        self._memo: dict = {}

    # ------------------------------------------------------------ helpers

    def kind(self, mod: Module) -> set:
        return self.kinds.get(mod.name, set())

    def at(self, mod: Module, n) -> str:
        return f"{mod.file.rel}:{L(n)}"

    def project_module(self, segs: list[str]) -> Module | None:
        return self.modules.get(".".join(segs))

    def is_repo(self, mod: Module, segs: list[str]) -> bool:
        m = self.modules.get(".".join(segs))
        if m is not None:
            return "repo" in self.kinds.get(m.name, set())
        return bool(segs) and segs[-1] in {"Repo", "RepoBase", "ReadRepo", "ReplicaRepo"}

    def calls_in(self, f: Func) -> list:
        if id(f) not in self._calls:
            self._calls[id(f)] = [n for n in walk(f.node) if n.type == "call" and n.id not in self.heads and not same(n, f.node)]
        return self._calls[id(f)]

    def resolve(self, mod: Module, n) -> list[Func]:
        segs, kind = callee(mod, n)
        if not segs:
            return []
        arity = len(call_args(n))
        if kind == "local":
            cands = [f for f in mod.funcs if f.name == segs[0]]
            if not cands:
                for imp in mod.imports:
                    m = self.modules.get(imp)
                    if m is not None:
                        cands += [f for f in m.funcs if f.name == segs[0] and not f.private]
        elif kind == "remote":
            m = self.modules.get(".".join(segs[:-1]))
            if m is not None:
                cands = [f for f in m.funcs if f.name == segs[-1] and not f.private]
            elif len(segs) >= 2:  # an alias the scan could not expand (e.g. one `use` injects): match the last segment
                cands = [f for f in self.funcs if f.name == segs[-1] and not f.private and f.module.name.split(".")[-1] == segs[-2]]
            else:
                cands = []
        else:
            return []
        return [f for f in cands if f.min_arity <= arity <= f.arity]

    # ------------------------------------------------------------ taint

    def entry_positions(self, f: Func) -> set[int]:
        k = self.kind(f.module)
        if "controller" in k and not f.private and f.arity == 2 and f.name not in {"init", "call", "action"}:
            return {1}
        if "live" in k:
            if f.name == "handle_event" and f.arity == 3:
                return {1}
            if f.name in {"mount", "handle_params"} and f.arity == 3:
                return {0}
        if "channel" in k and f.name in {"handle_in", "join"} and f.arity == 3:
            return {1}
        return set()

    def bindings(self, f: Func) -> list:
        """(patterns, expressions they are matched against, scope) of every match in the function: `=`, `<-`,
        case clauses, and anonymous-function parameters. A callback passed to a standard-library function (Enum.map,
        then, ...) receives that call's other arguments; one passed to a project function receives what that function
        gives it, which is not request data. Clause and callback bindings hold within their clause only."""
        if id(f) in self._bindings:
            return self._bindings[id(f)]
        out = []
        for n in walk(f.node):
            o = op(n)
            if o in {"=", "<-"} and not self._in_head(f, n):
                out.append(([n.child_by_field_name("left")], [n.child_by_field_name("right")], f.node))
            elif n.type == "call" and target(n) is not None and T(target(n)) == "case" and do_block(n) is not None:
                a = arguments(n)
                subject = a[0] if a else piped_into(n)
                for c in kids(do_block(n)):
                    if c.type == "stab_clause" and subject is not None:
                        out.append((kids(c.child_by_field_name("left")), [subject], c))
            elif n.type == "anonymous_function":
                call = n.parent.parent if n.parent is not None and n.parent.type == "arguments" else None
                others = []
                if call is not None and call.type == "call":
                    segs, kind = callee(f.module, call)
                    if segs and ((kind in {"remote", "erlang"} and ".".join(segs[:-1]) in PROPAGATE_MODULES) or
                                 (kind == "local" and segs[0] in PROPAGATE_LOCALS)):
                        others = [a for a in call_args(call) if not same(a, n) and a.type != "anonymous_function"]
                for c in kids(n):
                    if c.type == "stab_clause":
                        out.append((kids(c.child_by_field_name("left")), others, c))
        self._bindings[id(f)] = out
        return out

    def _in_head(self, f: Func, n) -> bool:
        p = n
        while p is not None and not same(p, f.node):
            if p.id in self.heads:
                return True
            p = p.parent
        return False

    def tainted(self, f: Func | None, n, mode: str = "value") -> bool:
        """Request data can reach the value of `n` (mode "value"), or `n` is a whole request map whose keys the
        client chooses (mode "whole": params, a nested params map, Map.put/merge of one; not a map literal)."""
        if f is None or n is None:
            return False
        ts = self.taint.get((id(f), mode), set())
        key = (id(f), n.id, len(ts), mode)
        if key in self._memo:
            return self._memo[key]
        r = self._tainted(f, n, ts) if mode == "value" else self._whole(f, n, ts)
        self._memo[key] = r
        return r

    def defs(self, f: Func) -> dict:
        """name -> [(pattern, expressions, scope)] for every match that binds the name in the function."""
        if id(f) not in self._defs:
            d: dict = {}
            for pats, exprs, scope in self.bindings(f):
                for p in pats:
                    for v in pattern_vars(p):
                        d.setdefault(v, []).append((p, exprs, scope))
            self._defs[id(f)] = d
        return self._defs[id(f)]

    def _var(self, f: Func, n, ts: set, mode: str) -> bool:
        """A variable is tainted as the latest match that binds it before the use is (`attrs = %{...}` rebinds a
        tainted parameter; `fn organization -> ... end` shadows one); with none, as the function's parameters are."""
        if not is_var_ref(n) or T(n) not in ts:
            return False
        pos = n.start_byte
        reaching = [(p, exprs) for p, exprs, scope in self.defs(f).get(T(n), [])
                    if p.end_byte <= pos and scope.start_byte <= pos < scope.end_byte
                    and not any(e is not None and e.start_byte <= pos < e.end_byte for e in exprs)]
        if reaching:
            _, exprs = max(reaching, key=lambda x: x[0].start_byte)
            return any(self.tainted(f, e, mode) for e in exprs if e is not None)
        return True

    def _tainted(self, f: Func, n, ts: set) -> bool:
        t = n.type
        if t == "identifier":
            return self._var(f, n, ts, "value")
        if t in {"string", "charlist", "sigil"}:
            return any(self.tainted(f, x) for x in interpolations(n))
        if t in {"atom", "integer", "float", "boolean", "nil", "alias", "char", "quoted_atom", "comment", "keyword"}:
            return False
        if t == "anonymous_function" or unary(n) == "&":
            return False
        if op(n) == "|>":
            right = n.child_by_field_name("right")
            if right is not None and right.type == "call":
                return self.tainted(f, right)
            return any(self.tainted(f, c) for c in kids(n))
        if t == "call":
            mod = f.module
            segs, kind = callee(mod, n)
            if kind == "var" and not has_parens(n):   # field access: conn.params, user_params.email
                left = target(n).child_by_field_name("left")
                if segs[1] in SOURCE_FIELDS and (T(left) == "conn" or T(left).endswith("_conn")):
                    return True
                return self.tainted(f, left)
            if segs is None:
                return any(self.tainted(f, c) for c in call_args(n))
            name = segs[-1]
            if self.fm.match("elixir", (segs, kind != "local"), "source"):
                return True
            if self.fm.match("elixir", (segs, kind != "local"), "sanitizer"):
                return False
            if name in SOURCE_CALLS and (kind == "local" or ".".join(segs[:-1]) == "Plug.Conn"):
                return True
            if kind == "local" and name in CONTROL or do_block(n) is not None:
                return any(self.tainted(f, c) for c in kids(n) if c.type != "do_block") or any(
                    self.tainted(f, c) for b in [do_block(n)] if b is not None for c in walk_bodies(b))
            if name in SANITIZING or name.endswith("?"):
                return False
            module = ".".join(segs[:-1])
            if (kind == "local" and name in PROPAGATE_LOCALS) or (kind in {"remote", "erlang"} and module in PROPAGATE_MODULES):
                return any(self.tainted(f, a) for a in call_args(n))
            return False
        if t == "access_call":
            return self.tainted(f, n.child_by_field_name("target"))
        return any(self.tainted(f, c) for c in kids(n))

    def _whole(self, f: Func, n, ts: set) -> bool:
        t = n.type
        if t == "identifier":
            return self._var(f, n, ts, "whole")
        if op(n) == "|>":
            right = n.child_by_field_name("right")
            return right is not None and right.type == "call" and self.tainted(f, right, "whole")
        if t == "access_call":
            return self.tainted(f, n.child_by_field_name("target"), "whole")
        if t != "call":
            return False
        segs, kind = callee(f.module, n)
        if kind == "var" and not has_parens(n):
            left = target(n).child_by_field_name("left")
            if segs[1] in {"params", "body_params", "query_params", "path_params"} and (T(left) == "conn" or T(left).endswith("_conn")):
                return True
            return self.tainted(f, left, "whole")
        if segs is None:
            return False
        name = ".".join(segs)
        args = call_args(n)
        if name in {"Map.put", "Map.put_new", "Map.delete", "Map.drop", "Map.update", "Map.update!", "Map.replace",
                    "Map.replace!", "Map.new", "Enum.into", "Map.get", "Map.fetch!", "Access.get"} or (kind == "local" and name in {"get_in"}):
            return bool(args) and self.tainted(f, args[0], "whole")
        if name in {"Map.merge"}:
            return any(self.tainted(f, a, "whole") for a in args[:2])
        if kind == "local" and segs[0] in {"case", "if", "unless", "with", "cond"} or do_block(n) is not None:
            b = do_block(n)
            return b is not None and any(self.tainted(f, c, "whole") for c in walk_bodies(b))
        return False

    def compute_taint(self, f: Func, mode: str = "value"):
        ts = set()
        for i in self.seeds.get((id(f), mode), set()) | self.entry_positions(f):
            if i < len(f.params):
                p = f.params[i]
                if op(p) == "\\\\":
                    p = p.child_by_field_name("left")
                if any(x.type == "struct" for x in walk(p)):
                    continue   # `%User{} = user`: a struct, which request data (strings, lists, maps) never is
                ts |= pattern_vars(p)
        self.taint[(id(f), mode)] = ts
        for _ in range(6):
            changed = False
            for pats, exprs, _ in self.bindings(f):
                if any(self.tainted(f, e, mode) for e in exprs if e is not None):
                    new = set().union(*(pattern_vars(p) for p in pats)) - ts
                    if new:
                        ts |= new
                        self.taint[(id(f), mode)] = ts
                        changed = True
            if not changed:
                break

    def _has_sources(self, f: Func) -> bool:
        for n in self.calls_in(f):
            segs, kind = callee(f.module, n)
            if kind == "var" and not has_parens(n) and segs[1] in SOURCE_FIELDS:
                return True
            if segs and segs[-1] in SOURCE_CALLS:
                return True
            if segs and self.fm.match("elixir", (segs, kind != "local"), "source"):
                return True
        return False

    def run_taint(self):
        for mode in ("value", "whole"):
            active = [f for f in self.funcs if self.entry_positions(f) or self._has_sources(f)]
            seen = {id(f) for f in active}
            for _ in range(10):
                for f in active:
                    self.compute_taint(f, mode)
                new_active = []
                for f in active:
                    if not self.taint.get((id(f), mode)) and not self._has_sources(f):
                        continue
                    for c in self.calls_in(f):
                        hits = [i for i, a in enumerate(call_args(c)) if self.tainted(f, a, mode)]
                        if not hits:
                            continue
                        for g in self.resolve(f.module, c):
                            s = self.seeds.setdefault((id(g), mode), set())
                            add = {i for i in hits if i < g.arity} - s
                            if add:
                                s |= add
                                new_active.append(g)
                if not new_active:
                    break
                for g in new_active:
                    if id(g) not in seen:
                        seen.add(id(g))
                        active.append(g)
            for f in active:
                self.compute_taint(f, mode)

    def run_reach(self):
        """Which entry points (controller actions, LiveView callbacks) reach each function, by the call graph."""
        edges: dict[int, list] = {}
        for f in self.funcs:
            outs = []
            for c in self.calls_in(f):
                outs += self.resolve(f.module, c)
            edges[id(f)] = outs
        for e in self.funcs:
            if not self.entry_positions(e) and not ("controller" in self.kind(e.module) and not e.private):
                continue
            stack, seen = [e], {id(e)}
            while stack:
                x = stack.pop()
                self.reach_entries.setdefault(id(x), set()).add(e.module.name)
                for y in edges.get(id(x), []):
                    if id(y) not in seen:
                        seen.add(id(y))
                        stack.append(y)

    def reachable(self, f: Func | None) -> bool:
        return f is not None and bool(self.reach_entries.get(id(f)))

    # ------------------------------------------------------------ walk

    def run(self):
        self.run_taint()
        self.run_reach()
        code = [ef for ef in self.files if not ef.sf.example]
        for ef in code:   # casts first: stored user content is what request data was cast into
            self._walk(ef, self._mass_assignment_only)
        for ef in self.files:   # example, sample, and fixture files: only Secret literals, marked test_or_example
            self._walk(ef, self.visit if not ef.sf.example else self._secrets_only)
        for ef in code:
            self.schema_scan(ef)
        self.erasure_requests()
        if self.out.signals.get("erasure_request") and not self.out.signals.get("user_delete"):
            for at in self.user_delete_any:
                self.out.signal("user_delete", at)

    def _secrets_only(self, n, mod, func):
        if n.type == "binary_operator" and op(n) not in {"=", "=>", "||"}:
            return
        if n.type in {"pair", "binary_operator", "unary_operator", "string"}:
            self.visit(n, mod, None)

    def _walk(self, ef: ExFile, visit):
        mods = {m.node.id: m for m in ef.modules}
        stack = [(ef.tree.root_node, ef.script, None)]
        while stack:
            n, mod, func = stack.pop()
            if n.id in mods:
                mod = mods[n.id]
            elif n.id in self.by_node:
                func = self.by_node[n.id]
            if n.type != "comment":
                visit(n, mod, func)
            for c in reversed(n.children):
                stack.append((c, mod, func))

    def _mass_assignment_only(self, n, mod, func):
        if n.type == "call" and n.id not in self.heads:
            segs, kind = callee(mod, n)
            if segs and ((kind == "local" and segs[0] == "cast") or ".".join(segs) == "Ecto.Changeset.cast"):
                self.mass_assignment(n, mod, func)

    def visit(self, n, mod: Module, func: Func | None):
        t = n.type
        if t == "call":
            if n.id in self.heads:
                return
            self.on_call(n, mod, func)
        elif t == "binary_operator":
            o = op(n)
            if o in {"==", "===", "!=", "!=="}:
                self.compare(n, mod, func)
            elif o == "=" and n.child_by_field_name("left") is not None and n.child_by_field_name("left").type == "identifier":
                self.secret_binding(n, mod, T(n.child_by_field_name("left")), n.child_by_field_name("right"))
            elif o == "=>":
                k = string(n.child_by_field_name("left"))
                if k:
                    self.secret_binding(n, mod, k, n.child_by_field_name("right"))
            elif o == "||":
                self.env_default(n, mod)
        elif t == "pair":
            k, v = n.child_by_field_name("key"), n.child_by_field_name("value")
            if k is not None and v is not None:
                self.secret_binding(n, mod, T(k).strip().rstrip(":").strip('"'), v)
                if T(k).strip().rstrip(":") == "password" and func is not None:
                    self.password_keyword(n, v, mod, func)
        elif t == "unary_operator" and unary(n) == "@":
            operand = n.child_by_field_name("operand")
            if operand is not None and operand.type == "call" and target(operand) is not None and target(operand).type == "identifier":
                vals = arguments(operand)
                if vals:
                    self.secret_binding(n, mod, T(target(operand)), vals[0])
        elif t in {"string", "sigil"}:
            if t == "sigil":
                self.sigil_template(n, mod, func)
            s = string(n)
            if s and len(s) >= 16:
                kind = literal_secret_kind(s)
                if kind and plausible_secret_value(s, kind):
                    self.secret(mod, n, kind, s)
        elif t == "tuple":
            ks = kids(n)
            if len(ks) == 2 and atom(ks[0]) == "safe":
                self.safe_tuple(n, ks[1], mod, func)

    # ------------------------------------------------------------ calls

    def on_call(self, n, mod: Module, func: Func | None):
        segs, kind = callee(mod, n)
        if not segs:
            return
        name = ".".join(segs)
        last = segs[-1]
        modname = ".".join(segs[:-1])
        args = call_args(n)
        at = self.at(mod, n)
        if self.model_rules(n, segs, kind, args, mod, func, at):
            return

        # ---- passwords
        if last in HASH_SET or last in HASH_VERIFY:
            self.password_hash(n, segs, kind, args, mod, func, at)
        elif name == ":crypto.hash" and len(args) >= 2:
            self.crypto_hash(n, args, mod, func, at)
        elif name == ":crypto.pbkdf2_hmac" and len(args) >= 3 and self.mentions_password(args[1]):
            self.out.element("PasswordStore", at, algorithm="pbkdf2", salted=string(args[2]) is None)
            self.out.signal("pw_auth", at)
        elif (kind == "local" and last in {"put_change", "force_change"}) or name in {"Ecto.Changeset.put_change", "Ecto.Changeset.force_change"}:
            self.put_password_change(n, args, mod, func, at)
        elif name == "Plug.Crypto.secure_compare" and len(args) == 2:
            self.compare_pair(args[0], args[1], mod, func, at)
        if (kind == "local" and last in {"validate_length", "validate_format"}) or name in {"Ecto.Changeset.validate_length", "Ecto.Changeset.validate_format"}:
            self.password_policy(n, last, args, mod, at)
        if (re.search(r"(^|\.)\w*(Pwned|HaveIBeenPwned)\w*$", modname) and re.search(r"pass|breach|pwned|check", last)) or \
                re.fullmatch(r"(password_)?(breached|pwned|compromised)\??|(check|is)_pwned\w*|pwned_password\w*", last):
            # the check where a password is set; the client module itself and a check at login do not count
            if not self.in_login_action(func) and kind in {"remote", "local"} and not re.search(r"pwned", mod.name, re.I):
                self.out.signal("pw_blocklist", at)
        # ---- queries
        if name in SQL_ADAPTER:
            self.raw_query(n, args[1] if len(args) > 1 else None, args[2:], mod, func, at)
        elif kind == "remote" and last in REPO_RAW and self.is_repo(mod, segs[:-1]):
            self.raw_query(n, args[0] if args else None, args[1:], mod, func, at)
        elif kind == "local" and last in REPO_RAW and "repo" in self.kind(mod):
            self.raw_query(n, args[0] if args else None, args[1:], mod, func, at)
        elif kind == "local" and last in {"fragment", "unsafe_fragment"} and args and string(args[0]) is None \
                and not T(args[0]).startswith("unquote("):   # a macro's fragment text is fixed when it expands
            self.raw_query(n, args[0], args[1:], mod, func, at)
        elif kind == "remote" and last in ORM_FUNCS and self.is_repo(mod, segs[:-1]):
            self.orm_query(n, args, mod, func, at)
        elif last in QUERY_MACROS and (modname == "Ecto.Query" or (kind == "local" and "Ecto.Query" in mod.imports)):
            self.orm_query(n, args, mod, func, at)
        # ---- cookies, tokens, headers
        if last == "put_resp_cookie" and (kind == "local" or modname == "Plug.Conn"):
            self.cookie(n, args, mod, func, at)
        if last == "put_resp_header" and (kind == "local" or modname == "Plug.Conn") and len(args) >= 3:
            header = (string(args[1]) or "").lower()
            if header == "content-security-policy":
                self.out.signal("csp_header", at)
            elif header == "strict-transport-security":
                m = re.search(r"max-age=(\d+)", string(args[2]) or "")
                self.out.signal("hsts_header", at, int(m.group(1)) if m else None)
        self.token(n, segs, kind, name, args, mod, func, at)
        # ---- logs, transfers
        if (modname == "Logger" and last in LOG_LEVELS) or (modname == ":logger" and last in LOG_LEVELS) or name in {"IO.inspect", "IO.puts", "IO.warn"}:
            self.log(n, args, mod, func, at)
        self.transfer(n, segs, kind, name, args, mod, func, at)
        # ---- commands, html, deserialization
        if name in {"System.cmd", "System.shell", ":os.cmd", "Port.open", ":erlang.open_port", "MuonTrap.cmd", "Rambo.run",
                    "Exile.stream!", "Exile.stream", "ExCmd.stream!"}:
            self.command(n, name, args, mod, func, at)
        if (kind == "local" and last == "raw" and len(args) == 1 and not any(f.name == "raw" for f in mod.funcs)
                and self.html_module(mod)) or name == "Phoenix.HTML.raw":
            self.html_raw(args[0] if args else None, mod, func, at, template=False)
        if name in {":erlang.binary_to_term", "Plug.Crypto.non_executable_binary_to_term", "Plug.Crypto.safe_binary_to_term"}:
            self.deserialize(n, name, args, mod, func, at)
        # ---- system signals
        self.rate_limit_call(n, segs, kind, mod, func, at)
        if kind == "remote" and last in {"delete", "delete!"} and self.is_repo(mod, segs[:-1]) and args:
            self.user_delete(args[0], mod, func, at)
        elif name in {"Ecto.Multi.delete"} and len(args) >= 3:
            self.user_delete(args[2], mod, func, at)
        elif kind == "remote" and last == "delete_all" and self.is_repo(mod, segs[:-1]) and args:
            if any(self.is_user_schema(mod, T(x)) for x in walk(args[0]) if x.type == "alias"):
                if self.reachable(func):
                    self.out.signal("user_delete", at)
                else:
                    self.user_delete_any.append(at)

    def html_module(self, mod: Module) -> bool:
        if mod.name.startswith("<"):
            return False
        return bool(self.kind(mod) & {"view", "live", "controller"}) or "Phoenix.HTML" in mod.imports or any(
            u[0].endswith("Web") or u[0].startswith("Phoenix") for u in mod.uses)

    def model_rules(self, n, segs, kind, args, mod, func, at) -> bool:
        callee_ = (segs, kind != "local")
        hit = False
        for k in ("password_hash", "query", "token_verification", "log", "transfer", "rate_limit", "password_policy",
                  "erasure", "cookie"):
            rule = self.fm.match("elixir", callee_, k)
            if rule is None:
                continue
            s = rule.spec
            hit = True
            if k == "password_hash":
                pw = model_arg(s.get("password", 0), args)
                salted = s["salted"] if s["salted"] != "infer" else self.mentions_salt(pw)
                self.out.element("PasswordStore", at, algorithm=s["algorithm"], salted=salted)
                self.out.signal("pw_auth", at)
            elif k == "query":
                if "text" in s:
                    text = model_arg(s["text"], args)
                    construction, _ = self.classify(text, func, n)
                else:
                    construction, text = s["construction"], None
                untrusted = any(self.tainted(func, a) for a in args)
                self.out.element("Query", at, construction=construction, untrusted_input=untrusted)
            elif k == "token_verification":
                self.out.element("TokenVerification", at, **{x: s[x] for x in ("verifies_signature", "allows_none_alg") if x in s})
            elif k == "log":
                self.log(n, args, mod, func, at)
            elif k == "transfer":
                personal = s.get("personal_data", "infer")
                if personal == "infer":
                    personal = any(self.personal_in(a) for a in args) or None
                self.out.element("Transfer", at, recipient=s["recipient"], personal_data=personal, third_country=s.get("third_country"))
            elif k == "rate_limit":
                self.out.signal("rate_limit", at, scope=s.get("scope", "global") if s.get("scope") else "global")
            elif k == "password_policy":
                from adapters.code_static.common import model_policy
                model_policy(rule, at, "server", self.out)
            elif k == "erasure":
                if self.reachable(func):
                    self.out.signal("user_delete", at)
            elif k == "cookie":
                name_node = model_arg(s.get("name", 1), args)
                facts = {x: s[x] for x in ("is_session", "secure", "http_only", "same_site") if x in s}
                if "is_session" not in facts and string(name_node):
                    facts["is_session"] = session_cookie_name(string(name_node))
                self.out.element("Cookie", at, **facts)
            self.out.mark(at, rule)
            self.fm.used(rule)
        return hit

    # ------------------------------------------------------------ PasswordStore

    def mentions_password(self, n) -> bool:
        for x in walk(n) if n is not None else []:
            if x.type == "identifier" and is_var_ref(x) and is_password_name(T(x)):
                return True
            if x.type == "call" and callee_field(x) and is_password_name(callee_field(x)):
                return True
            if x.type == "access_call":
                k = x.child_by_field_name("key")
                key = string(k) or atom(k)
                if key and is_password_name(key):
                    return True
        return False

    def mentions_salt(self, n) -> bool:
        for x in walk(n) if n is not None else []:
            if x.type == "identifier" and SALT_WORD.search(T(x)):
                return True
            if x.type == "call" and callee_field(x) and SALT_WORD.search(callee_field(x)):
                return True
        return False

    def password_hash(self, n, segs, kind, args, mod, func, at):
        last = segs[-1]
        modname = ".".join(segs[:-1])
        algo = HASHERS.get(modname)
        if algo is None and kind in {"var", "attr"} or (algo is None and kind == "remote" and not self.project_module(segs[:-1])
                                                        and last in {"hash_pwd_salt", "verify_pass", "add_hash", "check_pass"}):
            present = sorted({a for d, a in HASHER_DEPS.items() if self.deps.has(d)})
            algo = present[0] if len(present) == 1 else None   # a hasher chosen in config: the one dependency there is
        if algo is None:
            return
        pos = HASH_SET.get(last, HASH_VERIFY.get(last, 0))
        pw = args[pos] if pos < len(args) else None
        if pw is not None and string(pw) is not None:
            return  # a constant: a dummy hash for timing, not a user's password
        self.out.element("PasswordStore", at, algorithm=algo, salted=True)
        self.out.signal("pw_auth", at)
        if last in HASH_SET:
            self.out.signal("pw_set_site", at)

    def crypto_hash(self, n, args, mod, func, at):
        alg = atom(args[0])
        data = args[1]
        if alg is None or not self.mentions_password(data):
            return
        if re.search(r"pwn|breach|hibp", mod.name + "." + (func.name if func else ""), re.I):
            return  # a k-anonymity prefix for a breached-password lookup, not the stored form
        self.out.element("PasswordStore", at, algorithm=CRYPTO_ALGS.get(alg, "other"), salted=self.mentions_salt(data))
        self.out.signal("pw_auth", at)

    def put_password_change(self, n, args, mod, func, at):
        if len(args) < 3 or atom(args[1]) not in PW_FIELDS:
            return
        v = args[2]
        if v.type == "call":
            segs, kind = callee(mod, v)
            if segs and ".".join(segs[:-1]) == "Base" and segs[-1].startswith(("encode", "url_encode")) and self.mentions_password(v):
                self.out.element("PasswordStore", at, algorithm="reversible", salted=False)
                self.out.signal("pw_auth", at)
                self.out.signal("pw_set_site", at)
            return
        if v.type == "identifier" and is_password_name(T(v)):
            self.out.element("PasswordStore", at, algorithm="plaintext", salted=False)
            self.out.signal("pw_auth", at)
            self.out.signal("pw_set_site", at)

    def stored_password(self, n) -> bool:
        if n is None:
            return False
        if n.type == "call" and callee_field(n):
            return is_stored_password_name(callee_field(n))
        if n.type == "access_call":
            k = n.child_by_field_name("key")
            key = string(k) or atom(k)
            return bool(key) and is_stored_password_name(key) and T(n.child_by_field_name("target")) not in {"params", "conn", "attrs"}
        return False

    def raw_password(self, n) -> bool:
        if n is None:
            return False
        if unary(n) == "^":
            n = n.child_by_field_name("operand")
        if n is not None and n.type == "identifier":
            return is_password_name(T(n))
        if n is not None and n.type == "access_call":
            k = n.child_by_field_name("key")
            return bool(string(k)) and is_password_name(string(k))
        return False

    def compare(self, n, mod, func):
        self.compare_pair(n.child_by_field_name("left"), n.child_by_field_name("right"), mod, func, self.at(mod, n))

    def compare_pair(self, a, b, mod, func, at):
        if (self.stored_password(a) and self.raw_password(b)) or (self.stored_password(b) and self.raw_password(a)):
            self.out.element("PasswordStore", at, algorithm="plaintext", salted=False)
            self.out.signal("pw_auth", at)

    def password_keyword(self, pair, v, mod, func):
        """`Repo.get_by(User, email: e, password: password)` or `%User{password: ^password}`: a stored password compared as is."""
        p = pair.parent
        while p is not None and p.type in {"keywords", "map_content", "map", "arguments", "list"}:
            p = p.parent
        if p is None:
            return
        if p.type == "call":
            segs, kind = callee(mod, p)
            if segs and kind == "remote" and segs[-1] in {"get_by", "get_by!"} and self.is_repo(mod, segs[:-1]) and self.raw_password(v):
                at = self.at(mod, pair)
                self.out.element("PasswordStore", at, algorithm="plaintext", salted=False)
                self.out.signal("pw_auth", at)
        if p.type == "binary_operator" and op(p) == "=" and unary(v) == "^" and self.raw_password(v):
            at = self.at(mod, pair)
            self.out.element("PasswordStore", at, algorithm="plaintext", salted=False)
            self.out.signal("pw_auth", at)

    def password_policy(self, n, last, args, mod, at):
        if len(args) < 3:
            return
        field_ = atom(args[1])
        if field_ is None or not (field_ == "password" or (is_password_name(field_) and "confirm" not in field_)):
            return
        if last == "validate_length":
            opts = kw(args[2])
            mn, mx, is_ = integer(opts.get("min")), integer(opts.get("max")), integer(opts.get("is"))
            if is_ is not None:
                mn = mx = is_
            if mn is not None:
                self.out.signal("pw_min", at, mn, side="server")
            if mx is not None:
                self.out.signal("pw_max", at, mx, side="server")
            self.out.signal("pw_validation", at, side="server")
        else:
            rx = args[2]
            body = T(next((c for c in rx.named_children if c.type == "quoted_content"), rx)) if rx.type == "sigil" else (string(rx) or "")
            from adapters.code_static.common import analyse_password_regex
            r = analyse_password_regex(body)
            if "min" in r:
                self.out.signal("pw_min", at, r["min"], side="server")
            if "max" in r:
                self.out.signal("pw_max", at, r["max"], side="server")
            if r.get("composition") or (re.search(r"\[[^\]]+\]|\\d|\\W|\\p\{|\[\[:", body) and not re.fullmatch(r"\^?\.\{\d+,\d*\}\$?", body)):
                self.out.signal("pw_composition", at)
            self.out.signal("pw_validation", at, side="server")

    # ------------------------------------------------------------ Query

    def assignments(self, func: Func | None, name: str, before) -> list:
        if func is None:
            return []
        out = []
        for pats, exprs, scope in self.bindings(func):
            p = pats[0] if len(pats) == 1 else None
            if scope is func.node and p is not None and p.type == "identifier" and T(p) == name and exprs and exprs[0] is not None:
                if exprs[0].start_byte < before.start_byte:
                    out.append(exprs[0])
        return out[-1:] if out else []

    def classify(self, n, func: Func | None, at_node, depth: int = 0):
        """(construction, texts) of a query or command string."""
        if n is None or depth > 4:
            return None, []
        if unary(n) == "^":
            return self.classify(n.child_by_field_name("operand"), func, at_node, depth + 1)
        s = string(n)
        if s is not None:
            return "parameterized", [s]
        if n.type in {"string", "sigil", "charlist"} and has_interpolation(n):
            text = "".join(T(c) for c in n.named_children if c.type == "quoted_content")
            if all(x.type in {"string", "integer", "atom"} or (x.type == "unary_operator" and unary(x) == "@") for x in interpolations(n)):
                return "parameterized", [text]
            return "interpolated", [text]
        o = op(n)
        if o in {"<>", "++"}:
            parts = [n.child_by_field_name("left"), n.child_by_field_name("right")]
            texts, worst = [], "parameterized"
            for p in parts:
                c, t = self.classify(p, func, at_node, depth + 1)
                texts += t
                if c is None or c in {"interpolated", "concatenated"}:
                    worst = "concatenated"
            return worst, texts
        if o == "|>":
            return self.classify(n.child_by_field_name("left"), func, at_node, depth + 1)
        if n.type == "identifier" and func is not None:
            vals = self.assignments(func, T(n), at_node)
            if vals:
                return self.classify(vals[0], func, at_node, depth + 1)
            return None, []
        if unary(n) == "@" and func is not None:
            operand = n.child_by_field_name("operand")
            v = func.module.attr(T(operand)) if operand is not None and operand.type == "identifier" else None
            return self.classify(v, None, at_node, depth + 1) if v is not None else (None, [])
        if n.type == "call":
            segs, kind = callee(func.module if func else None, n) if func else (None, None)
            if segs and segs[-1] in {"to_charlist", "to_string", "iodata_to_binary", "join"} and call_args(n):
                inner = call_args(n)[0]
                if segs[-1] == "join" and inner.type == "list":
                    parts = [self.classify(x, func, at_node, depth + 1) for x in kids(inner)]
                    if all(c == "parameterized" for c, _ in parts):
                        return "parameterized", [t for _, ts in parts for t in ts]
                    return "concatenated", [t for _, ts in parts for t in ts]
                return self.classify(inner, func, at_node, depth + 1)
        if n.type == "list":
            parts = [self.classify(x, func, at_node, depth + 1) for x in kids(n)]
            if parts and all(c == "parameterized" for c, _ in parts):
                return "parameterized", [t for _, ts in parts for t in ts]
            return ("concatenated" if parts else None), [t for _, ts in parts for t in ts]
        return None, []

    def raw_query(self, n, sql, params, mod, func, at):
        construction, _ = self.classify(sql, func, n)
        untrusted = self.tainted(func, sql) or any(self.tainted(func, p) for p in params)
        if construction is None and sql is not None and sql.type == "identifier":
            untrusted = untrusted or False
        self.out.element("Query", at, construction=construction, untrusted_input=untrusted)

    def pinned_tainted(self, func: Func, n) -> bool:
        """Ecto query macros take outside values only through `^`; bindings (`from u in User`) are not variables."""
        return any(unary(x) == "^" and self.tainted(func, x.child_by_field_name("operand")) for x in walk(n))

    def is_query_macro(self, mod, x) -> bool:
        segs, kind = callee(mod, x)
        return bool(segs) and segs[-1] in QUERY_MACROS and (".".join(segs[:-1]) == "Ecto.Query" or (kind == "local" and "Ecto.Query" in mod.imports))

    def orm_query(self, n, args, mod, func, at):
        if func is None:
            return
        macro = self.is_query_macro(mod, n)
        if macro:
            if not any(self.pinned_tainted(func, a) for a in arguments(n)):
                return
        elif not any(self.tainted(func, a) for a in args):
            return
        for a in arguments(n):  # reported at an inner query expression the request data reaches
            for x in walk(a):
                if x.type == "call" and not same(x, n) and self.is_query_macro(mod, x) and any(self.pinned_tainted(func, y) for y in arguments(x)):
                    return
        self.out.element("Query", at, construction="orm", untrusted_input=True)

    # ------------------------------------------------------------ Cookie

    def resolve_value(self, n, mod: Module, func: Func | None):
        """A literal behind a module attribute or a local variable, else the node itself."""
        for _ in range(3):
            if n is None:
                return None
            if unary(n) == "@":
                operand = n.child_by_field_name("operand")
                v = mod.attr(T(operand), L(n)) if operand is not None and operand.type == "identifier" else None
                if v is None:
                    return n
                n = v
                continue
            if n.type == "identifier" and func is not None:
                vals = self.assignments(func, T(n), n)
                if not vals:
                    return n
                n = vals[0]
                continue
            return n
        return n

    def cookie(self, n, args, mod, func, at):
        if len(args) < 3:
            return
        name = string(self.resolve_value(args[1], mod, func))
        opts_node = self.resolve_value(args[3], mod, func) if len(args) > 3 else None
        known = opts_node is None or opts_node.type in {"keywords", "list"}
        opts = kw(opts_node) if opts_node is not None else {}
        facts: dict = {}
        if name is not None:
            facts["is_session"] = session_cookie_name(name)
        elif args[2].type == "identifier" and is_credential_name(T(args[2])):
            facts["is_session"] = True
        self.cookie_flags(facts, opts, known)
        self.out.element("Cookie", at, **facts)

    def cookie_flags(self, facts: dict, opts: dict, known: bool):
        """Plug's defaults (plug lib/plug/conn.ex put_resp_cookie/4 and lib/plug/conn/cookies.ex encode/2, checked at
        elixir-plug/plug 0d5b5ea, v1.21.0-dev, and unchanged since :same_site arrived in v1.10.1): http_only defaults to
        true; secure is added only when the request's scheme is https (`maybe_secure_cookie/2`); same_site has no
        default, the attribute is omitted unless given. The scheme is https when Plug.SSL/force_ssl redirects
        plain HTTP (Plug.SSL also rewrites the scheme from x-forwarded-proto), so `secure` follows tls_enforced."""
        sec, ho, ss = opts.get("secure"), opts.get("http_only"), opts.get("same_site")
        if sec is not None:
            if boolean(sec) is not None:
                facts["secure"] = boolean(sec)
        elif known:
            facts["secure"] = self.ctx.get("tls_enforced", False)
        if ho is not None:
            if boolean(ho) is not None:
                facts["http_only"] = boolean(ho)
        elif known:
            facts["http_only"] = True
        if ss is not None:
            v = (string(ss) or atom(ss) or "").lower()
            if v in {"strict", "lax", "none"}:
                facts["same_site"] = v
        elif known:
            facts["same_site"] = "unset"

    # ------------------------------------------------------------ TokenVerification

    def verifies_here(self, mod: Module) -> bool:
        if mod.uses_any("Joken.Config", "Guardian"):
            return True
        for x in walk(mod.node):
            if x.type == "call":
                segs, kind = callee(mod, x)
                if segs and (".".join(segs) in VERIFYING or (segs[-1] in {"verify", "verify_and_validate", "verify_strict", "validate_jwt", "decode_and_verify"} and kind in {"remote", "local"})):
                    return True
        return False

    def token(self, n, segs, kind, name, args, mod, func, at):
        last = segs[-1]
        target_mod = self.project_module(segs[:-1]) if kind == "remote" else (mod if kind == "local" else None)
        if name in VERIFYING:
            none = False
            if name.endswith("verify_strict") and len(args) >= 2:
                algs = word_list(self.resolve_value(args[1], mod, func)) or []
                none = "none" in [a.lower() for a in algs]
            elif name in {"JOSE.JWT.verify", "JOSE.JWS.verify", ":jose_jwt.verify", ":jose_jws.verify"}:
                none = True  # the header's alg decides how the key is used (algorithm confusion)
            self.out.element("TokenVerification", at, verifies_signature=True, allows_none_alg=none)
        elif name in PEEKING:
            if not self.verifies_here(mod):
                self.out.element("TokenVerification", at, verifies_signature=False)
        elif target_mod is not None and target_mod.uses_any("Joken.Config") and last in {"verify", "verify_and_validate", "verify!", "verify_and_validate!"}:
            self.out.element("TokenVerification", at, verifies_signature=True, allows_none_alg=False)
        elif target_mod is not None and target_mod.uses_any("Guardian") and not target_mod.name.startswith("Guardian"):
            if last in {"decode_and_verify", "resource_from_token", "exchange", "refresh"}:
                self.out.element("TokenVerification", at, verifies_signature=True, allows_none_alg=False)
            elif last == "peek":
                self.out.element("TokenVerification", at, verifies_signature=False)

    # ------------------------------------------------------------ Secret

    def secret(self, mod: Module, n, kind: str, value: str | None):
        rel = mod.file.rel
        parts = rel.split("/")
        # config/<env>.exs for an environment other than production (dev, test, a CI or client-test env)
        other_env = len(parts) >= 2 and parts[-2] == "config" and parts[-1].endswith(".exs") and \
            parts[-1] not in {"config.exs", "prod.exs", "runtime.exs", "releases.exs"}
        example = mod.file.sf.example or other_env or bool(value and PLACEHOLDER.search(value))
        self.out.element("Secret", self.at(mod, n), kind=kind, test_or_example=True if example else None)

    def secret_binding(self, n, mod: Module, name: str, value):
        """A literal bound to a secret-like name. Phoenix's signing_salt / encryption_salt (endpoint session options and
        `live_view: [signing_salt: ...]`) are not secrets by design: keys derive from secret_key_base and the salt only
        separates purposes (Plug.Crypto.KeyGenerator; Phoenix docs on Plug.Session), so `*_salt` is never flagged."""
        s = string(value)
        if s is None or SALT_WORD.search(name):
            return
        literal = literal_secret_kind(s)
        kind = literal or secret_kind_for_name(name)
        if not kind or not plausible_secret_value(s, kind):
            return
        if not literal and kind != "password" and (len(s) < 8 or re.fullmatch(r"[a-z]+([_\-.][a-z]+)*", s)):
            return   # `secret_slot: "active"`, `client_secret: "client-secret"`: a word, not key material
        self.secret(mod, value, kind, s)

    def env_default(self, n, mod: Module):
        """`System.get_env("API_KEY") || "literal"`."""
        left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
        if left is None or right is None or left.type != "call":
            return
        segs, _ = callee(mod, left)
        if segs and ".".join(segs) in {"System.get_env", "System.fetch_env"} and arguments(left):
            env = string(arguments(left)[0])
            if env:
                self.secret_binding(n, mod, env, right)

    # ------------------------------------------------------------ LogStatement

    def names_in(self, n):
        """(name, owner) pairs of variables, fields, map keys, and keyword keys an expression writes out as they are
        or through string building and standard-library calls; what a project helper receives (`line(conn)`) is
        not followed, since the helper picks what it formats."""
        out = []
        for x in self.direct_nodes(n):
            if x.type == "identifier" and is_var_ref(x):
                p = x.parent
                if p is not None and (p.type == "dot" or (p.type == "access_call" and same(p.child_by_field_name("target"), x))):
                    continue   # `user.id`, `params["x"]`: the field is what is written, not the whole value
                out.append((T(x), None))
            elif x.type == "call" and callee_field(x):
                left = target(x).child_by_field_name("left")
                out.append((callee_field(x), T(left) if left is not None else None))
            elif x.type == "access_call":
                k = x.child_by_field_name("key")
                key = string(k) or atom(k)
                if key:
                    out.append((key, T(x.child_by_field_name("target"))))
            elif x.type == "pair":
                k = x.child_by_field_name("key")
                out.append((T(k).strip().rstrip(":"), None))
        return out

    def direct_nodes(self, n):
        stack = [n]
        while stack:
            x = stack.pop()
            yield x
            if x.type == "call" and has_parens(x) and target(x) is not None:
                segs, kind = callee(None, x) if target(x).type == "identifier" else (None, None)
                t = target(x)
                left = t.child_by_field_name("left") if t.type == "dot" else None
                module = T(left) if left is not None and left.type in {"alias", "atom"} else None
                local_ok = segs is not None and kind == "local" and segs[0] in PROPAGATE_LOCALS | {"inspect"}
                remote_ok = module is not None and module in PROPAGATE_MODULES | {"Kernel", "Logger"}
                if not (local_ok or remote_ok):
                    continue
            stack.extend(reversed(x.children))

    def personal_in(self, n) -> bool:
        return any(is_personal_name(nm, ow) or (ow is None and is_user_object_name(nm)) for nm, ow in self.names_in(n))

    def log(self, n, args, mod, func, at):
        creds = personal = False
        for a in args:
            if string(a) is not None:
                continue
            for nm, owner in self.names_in(a):
                if nm in {"conn"} and owner is None:
                    creds = personal = True   # the whole conn: cookies, authorization headers, params, remote ip
                elif is_credential_name(nm) and nm not in {"request"} and not (owner and words(owner)[-1:] == ["conn"] and nm in {"assigns"}):
                    creds = True
                if is_personal_name(nm, owner) or (owner is None and is_user_object_name(nm)):
                    personal = True
            for x in self.direct_nodes(a):   # the whole request params
                whole = (x.type == "identifier" and is_var_ref(x) and self.tainted(func, x, "whole") and
                         (x.parent is None or x.parent.type not in {"access_call", "dot"}))
                if x.type == "call" and callee_field(x) in SOURCE_FIELDS and T(target(x).child_by_field_name("left")) == "conn" \
                        and (x.parent is None or x.parent.type != "access_call"):
                    whole = True
                if whole:
                    text = T(mod.node)
                    if re.search(r"[\"':](password|passwd|token|secret)[\"']?", text):
                        creds = True
                    if re.search(r"[\"':](email|name|first_name|last_name|address|phone)[\"']?", text):
                        personal = True
        if creds or personal:
            self.out.element("LogStatement", at, logs_credentials=creds, logs_personal_data=personal)

    # ------------------------------------------------------------ Transfer

    def url_host(self, n, mod, func) -> str | None:
        n = self.resolve_value(n, mod, func)
        if n is None:
            return None
        if op(n) == "<>":
            return self.url_host(n.child_by_field_name("left"), mod, func)
        s = string(n)
        if s is None and n.type in {"string", "sigil"}:
            s = "".join(T(c) if c.type == "quoted_content" else "{x}" for c in n.named_children if c.type in {"quoted_content", "interpolation"})
        if s is None and n.type in {"keywords", "list"}:
            k = kw(n)
            for key in ("url", "base_url"):
                if k.get(key) is not None:
                    return self.url_host(k[key], mod, func)
        return external_host(s) if s else None

    def transfer(self, n, segs, kind, name, args, mod, func, at):
        last = segs[-1]
        modname = ".".join(segs[:-1])
        host = None
        body = []
        if modname in {"HTTPoison", "Req", "Tesla", ":hackney", "HTTPotion", "Finch"} or name in {":httpc.request"}:
            if modname in {"HTTPoison", "HTTPotion"} and last in HTTP_POST and args:
                host, body = self.url_host(args[0], mod, func), args[1:]
            elif modname in {"HTTPoison", "HTTPotion", ":hackney"} and last in {"request", "request!"} and len(args) >= 2 and atom(args[0]) in {"post", "put", "patch"}:
                host, body = self.url_host(args[1], mod, func), args[2:]
            elif modname == ":hackney" and last in {"post", "put", "patch"} and args:
                host, body = self.url_host(args[0], mod, func), args[1:]
            elif modname == "Req" and last in HTTP_POST and args:
                host, body = self.url_host(args[0], mod, func), args
            elif modname == "Req" and last in {"request", "request!"} and args:
                k = kw(args[-1])
                if atom(k.get("method")) in {"post", "put", "patch"}:
                    host, body = self.url_host(k.get("url") or args[0], mod, func), args
            elif modname == "Tesla" and last in HTTP_POST and len(args) >= 2:
                host, body = self.url_host(args[1], mod, func), args[2:]
            elif modname == "Finch" and last == "build" and len(args) >= 2 and atom(args[0]) in {"post", "put", "patch"}:
                host, body = self.url_host(args[1], mod, func), args[2:]
            elif name == ":httpc.request" and len(args) >= 2 and atom(args[0]) in {"post", "put", "patch"} and args[1].type == "tuple" and kids(args[1]):
                host, body = self.url_host(kids(args[1])[0], mod, func), kids(args[1])[1:]
        elif kind == "local" and last in {"post", "put", "patch"} and mod.uses_any("Tesla") and args:
            base = self.tesla_base(mod)
            host = self.url_host(args[0], mod, func) or base
            body = args[1:]
        if host:
            self.out.element("Transfer", at, recipient=host, personal_data=True if any(self.personal_in(b) for b in body) else None)
            return
        if kind == "remote" and last in {"deliver", "deliver!", "deliver_now", "deliver_now!", "deliver_later", "deliver_later!"}:
            m = self.project_module(segs[:-1])
            if m is not None and "mailer" in self.kind(m):
                rec = self.ctx["mailers"].get(m.name)
                if rec:
                    self.out.element("Transfer", at, recipient=rec, personal_data=True)
                return
        for prefix, fns, rec in SAAS:
            if (modname == prefix or modname.startswith(prefix + ".")) and (fns is None or last in fns) and kind == "remote":
                if fns is None and not re.match(r"(create|update|send|track|identify|upsert|post|capture|subscribe|add|charge)", last):
                    continue
                if prefix in {"Sentry", "Appsignal", "Honeybadger"} and self.ctx.get("monitoring", {}).get(rec):
                    continue  # reported once, at its configuration
                personal = True if any(self.personal_in(a) for a in args) else None
                self.out.element("Transfer", at, recipient=rec, personal_data=personal)
                return
        if modname == "ExAws.S3" and last in {"put_object", "upload", "initiate_multipart_upload"}:
            self.out.element("Transfer", at, recipient="AWS S3", personal_data=True if any(self.personal_in(a) for a in args) else None)

    def tesla_base(self, mod: Module) -> str | None:
        for t, opts, _ in mod.plugs:
            if T(t) in {"Tesla.Middleware.BaseUrl"} and opts:
                return self.url_host(opts[0], mod, None)
        return None

    # ------------------------------------------------------------ CommandExecution

    def command(self, n, name, args, mod, func, at):
        if not args:
            return
        if name in {"System.cmd", "MuonTrap.cmd", "Rambo.run"}:
            prog = string(self.resolve_value(args[0], mod, func))
            argv = args[1] if len(args) > 1 else None
            untrusted = self.tainted(func, args[0]) or self.tainted(func, argv)
            items = kids(argv) if argv is not None and argv.type == "list" else []
            if prog and prog.split("/")[-1] in {"sh", "bash", "zsh", "dash", "cmd", "cmd.exe", "powershell"} and len(items) >= 2 \
                    and string(items[0]) in {"-c", "/c", "-Command"}:
                construction, _ = self.classify(items[1], func, n)
                self.out.element("CommandExecution", at, construction=construction if construction != "parameterized" else "constant",
                                 untrusted_input=untrusted)
                return
            self.out.element("CommandExecution", at, construction="argv", untrusted_input=untrusted)
            return
        if name in {"Exile.stream!", "Exile.stream", "ExCmd.stream!"}:
            self.out.element("CommandExecution", at, construction="argv", untrusted_input=self.tainted(func, args[0]))
            return
        cmd = args[0]
        if name in {"Port.open", ":erlang.open_port"}:
            if cmd.type != "tuple" or len(kids(cmd)) != 2:
                return
            how, cmd = atom(kids(cmd)[0]), kids(cmd)[1]
            if how == "spawn_executable":
                opts = kw(args[1]) if len(args) > 1 else {}
                self.out.element("CommandExecution", at, construction="argv",
                                 untrusted_input=self.tainted(func, cmd) or self.tainted(func, opts.get("args")))
                return
            if how not in {"spawn"}:
                return
        construction, _ = self.classify(cmd, func, n)
        construction = {"parameterized": "constant"}.get(construction, construction)
        self.out.element("CommandExecution", at, construction=construction, untrusted_input=self.tainted(func, cmd))

    # ------------------------------------------------------------ HtmlOutput

    def sanitizer_call(self, n, mod: Module | None) -> bool:
        for x in walk(n) if n is not None else []:
            if x.type == "call":
                segs, kind = callee(mod, x) if mod else (None, None)
                if segs and segs[0] in {"HtmlSanitizeEx", "FastSanitize"}:
                    return True
                if segs and mod and self.fm.match("elixir", (segs, kind != "local"), "sanitizer"):
                    return True
                if segs and mod and kind in {"local", "remote"}:   # a helper that sanitizes
                    helpers = self.resolve(mod, x) if mod.file is not None else [f for f in self.funcs if f.name == segs[-1]]
                    for g in helpers:
                        if re.search(r"\b(HtmlSanitizeEx|FastSanitize)\.", T(g.node)):
                            return True
        return False

    def html_raw(self, x, mod: Module, func: Func | None, at: str, template: bool):
        if x is None:
            return
        x = self.resolve_value(x, mod, func) if not template else x
        facts = {"sanitized": self.sanitizer_call(x, mod)}
        if string(x) is not None:
            facts["untrusted_input"] = False
        elif not facts["sanitized"]:
            if func is not None and self.tainted(func, x):
                facts["untrusted_input"] = True
            elif self.user_content(x):
                facts["untrusted_input"] = True
        self.out.element("HtmlOutput", at, **facts)

    def user_content(self, n, depth: int = 0) -> bool:
        """The value is a field request data is cast into (`review.body`, `@bio`), so stored user content, written as
        is or through string building; a value passed to some other function is left undecided."""
        if n is None or depth > 6:
            return False
        if n.type == "call" and callee_field(n):
            return callee_field(n) in self.user_writable
        if unary(n) == "@":
            o = n.child_by_field_name("operand")
            return o is not None and o.type == "identifier" and T(o) in self.user_writable
        if n.type in {"string", "sigil"}:
            return any(self.user_content(x, depth + 1) for x in interpolations(n))
        if op(n) in {"<>", "++"}:
            return any(self.user_content(n.child_by_field_name(k), depth + 1) for k in ("left", "right"))
        if op(n) == "|>":
            return self.user_content(n.child_by_field_name("left"), depth + 1)
        if n.type == "access_call":
            k = n.child_by_field_name("key")
            return (atom(k) or string(k) or "") in self.user_writable
        if n.type == "call":
            segs, kind = callee(None, n) if target(n) is not None and target(n).type != "dot" else (None, None)
            t = target(n)
            if t is not None and t.type == "dot" and t.child_by_field_name("left") is not None and \
                    t.child_by_field_name("left").type == "alias" and T(t.child_by_field_name("left")) in PROPAGATE_MODULES:
                return any(self.user_content(a, depth + 1) for a in call_args(n))
            if segs and kind == "local" and segs[0] in PROPAGATE_LOCALS:
                return any(self.user_content(a, depth + 1) for a in call_args(n))
        return False

    def safe_tuple(self, n, x, mod, func):
        if not (has_interpolation(x) or op(x) == "<>"):
            return
        if re.search(r"html_escape|escape_html|HTML\.escape", T(x)):
            return
        facts = {"sanitized": self.sanitizer_call(x, mod)}
        if func is not None and self.tainted(func, x):
            facts["untrusted_input"] = True
        elif self.user_content(x):
            facts["untrusted_input"] = True
        self.out.element("HtmlOutput", self.at(mod, n), **facts)

    def sigil_template(self, n, mod, func):
        name = next((T(c) for c in n.named_children if c.type == "sigil_name"), "")
        if name not in {"H", "L", "E", "F", "LVN"}:
            return
        qc = next((c for c in n.named_children if c.type == "quoted_content"), None)
        if qc is not None:
            scan_template_raw(T(qc), qc.start_point[0], mod.file.rel, self, mod)

    # ------------------------------------------------------------ MassAssignment

    def cast_fields(self, n, mod, func) -> list[str] | None:
        n = self.resolve_value(n, mod, func)
        if n is None:
            return None
        if op(n) == "++":
            a = self.cast_fields(n.child_by_field_name("left"), mod, func)
            b = self.cast_fields(n.child_by_field_name("right"), mod, func)
            return (a or []) + (b or []) if a is not None or b is not None else None
        if op(n) == "--":   # every schema field but some: a denylist
            a = self.cast_fields(n.child_by_field_name("left"), mod, func)
            b = set(self.cast_fields(n.child_by_field_name("right"), mod, func) or [])
            return [f for f in a if f not in b] if a is not None else None
        wl = word_list(n)
        if wl is not None:
            return wl
        if n.type == "call" and "__schema__" in T(n):   # __schema__(:fields): every field of the schema
            return ["*"] + self.schema_fields(mod)
        return None

    def schema_fields(self, mod: Module) -> list[str]:
        out = []
        for x in walk(mod.node):
            if x.type == "call" and T(target(x)) in {"field", "belongs_to"} and arguments(x) and atom(arguments(x)[0]):
                name = atom(arguments(x)[0])
                out.append(name + "_id" if T(target(x)) == "belongs_to" else name)
        return out

    def mass_assignment(self, n, mod, func):
        """`cast(data, params, fields)` where params is a whole request map (its keys chosen by the client), not a
        map the code builds with fixed keys. Fields any request value is cast into are stored user content."""
        args = call_args(n)
        if len(args) < 3 or func is None or not self.tainted(func, args[1]):
            return
        fields = self.cast_fields(args[2], mod, func)
        self.user_writable.update(f for f in fields or [] if f != "*")
        if not self.tainted(func, args[1], "whole"):
            return
        at = self.at(mod, n)
        priv = None
        if fields is not None:
            granted = [f for f in fields if f in PRIVILEGED]
            priv = bool(granted) and not (self.admin_only(func) or self.dedicated(func, granted, fields))
        self.out.element("MassAssignment", at, allowlist=not (fields or [None])[0] == "*", privileged_assignable=priv)
        if fields and "password" in fields and "schema" in self.kind(mod):
            self.plaintext_cast(n, mod, at)

    def dedicated(self, func: Func, granted: list[str], fields: list[str]) -> bool:
        """A changeset whose purpose is to set that field (`change_role` casting only :role): the privilege change is
        the operation itself, authorised (or not) by its caller, not a field slipped into a bulk update."""
        named = set(words(func.name))
        return all(f in PRIVILEGED for f in fields) and any(set(words(g)) & named for g in granted)

    def admin_only(self, func: Func) -> bool:
        """A changeset for administrators: named so, or reached only from administration modules."""
        if re.search(r"admin", func.name, re.I) or re.search(r"(^|\.)Admin", func.module.name):
            return True
        entries = self.reach_entries.get(id(func), set())
        return bool(entries) and all(re.search(r"(^|\.)Admin|Admin\w*(Controller|Live)", e) for e in entries)

    def plaintext_cast(self, n, mod: Module, at: str):
        """A schema whose stored `password` field is cast from params with no hashing step in the module."""
        stored = False
        for x in walk(mod.node):
            if x.type == "call" and T(target(x)) == "field":
                a = arguments(x)
                if a and atom(a[0]) == "password" and not (len(a) > 2 and boolean(kw(a[-1]).get("virtual"))):
                    stored = True
        if not stored:
            return
        text = T(mod.node)
        if re.search(r"(update_change|put_change|force_change)\(\s*:(password|hashed_password|password_hash|encrypted_password)|"
                     r"(Bcrypt|Argon2|Pbkdf2|Comeonin)\.|put_pass_hash|hash_password|:crypto\.", text) or \
                re.search(r"\|>\s*(update_change|put_change)\(\s*:(password|hashed_password)", text):
            return
        self.out.element("PasswordStore", at, algorithm="plaintext", salted=False)
        self.out.signal("pw_auth", at)
        self.out.signal("pw_set_site", at)

    # ------------------------------------------------------------ Deserialization

    def deserialize(self, n, name, args, mod, func, at):
        if not args:
            return
        if name == ":erlang.binary_to_term":
            opts = word_list(args[1]) if len(args) > 1 else []
            safe = "safe" in (opts or [])
        else:
            safe = True
        facts = {"safe_mode": safe}
        if func is not None and self.tainted(func, args[0]):
            facts["untrusted_input"] = True
        elif string(args[0]) is not None:
            facts["untrusted_input"] = False
        self.out.element("Deserialization", at, **facts)

    # ------------------------------------------------------------ system signals

    def in_login_action(self, func: Func | None) -> bool:
        return func is not None and (func.module.name, func.name) in self.login_actions

    def rate_limit_call(self, n, segs, kind, mod, func, at):
        modname = ".".join(segs[:-1])
        last = segs[-1]
        m = self.project_module(segs[:-1]) if kind == "remote" else None
        hit = False
        if modname in RATE_LIMIT_MODULES and re.fullmatch(RATE_LIMIT_MODULES[modname], last):
            hit = True
        elif m is not None and m.uses_any("PlugAttack", "Hammer", "ExRated") and re.search(r"throttle|rate|limit|hit|check|fuse", last):
            hit = True
        if not hit:
            return
        routes = self.login_routes_reaching(func)
        for r in routes:
            self.out.signal("rate_limit", at, scope="login", route_at=r)
        if not routes:
            self.out.signal("rate_limit", at, scope="other")

    def login_routes_reaching(self, func: Func | None) -> list[str]:
        if func is None:
            return []
        out = []
        for (ctrl, action), ats in self.login_actions.items():
            if func.module.name == ctrl and func.name == action:
                out += ats
        if not out:  # one step: a helper the login action calls
            for (ctrl, action), ats in self.login_actions.items():
                m = self.modules.get(ctrl)
                for f in (m.funcs if m else []):
                    if f.name == action and any(func in self.resolve(m, c) for c in self.calls_in(f)):
                        out += ats
        return sorted(set(out))

    def is_user_schema(self, mod: Module, alias_text: str) -> bool:
        m = self.modules.get(mod.resolve(alias_text))
        return m is not None and m.name in self.user_schemas

    def user_delete(self, x, mod, func, at):
        if x.type == "identifier" and is_user_object_name(T(x)) or (x.type == "call" and callee_field(x) in {"current_user", "user"}) \
                or (x.type == "map" and any(c.type == "struct" and self.is_user_schema(mod, T(kids(c)[0])) for c in kids(x) if kids(c))):
            if self.reachable(func):
                self.out.signal("user_delete", at)
            else:
                self.user_delete_any.append(at)   # an operator task or a job: counts when a request asks for it

    def erasure_requests(self):
        """Where a user asks for their account to be deleted: an action or LiveView named so, or a stored request."""
        from adapters.code_static.common import ERASURE_REQUEST
        for f in self.funcs:
            if not self.entry_positions(f) and not ("controller" in self.kind(f.module) and not f.private):
                continue
            names = "_".join(words(f.module.name.split(".")[-1])) + "_" + "_".join(words(f.name))
            if ERASURE_REQUEST.search(names):
                self.out.signal("erasure_request", f"{f.module.file.rel}:{f.line}")

    def schema_scan(self, ef: ExFile):
        for mod in ef.modules:
            if "schema" not in self.kind(mod):
                continue
            for s in walk(mod.node):
                if s.type != "call" or T(target(s)) not in {"schema", "embedded_schema"}:
                    continue
                a = arguments(s)
                table = string(a[0]) if a else None
                is_user = bool(table and table.lower() in USER_TABLES) or mod.name.split(".")[-1] in {"User", "Account", "Customer", "Member"}
                if is_user and table is not None:
                    self.out.signal("user_model", f"{ef.rel}:{L(s)}")
                from adapters.code_static.common import ERASURE_REQUEST
                if table and ERASURE_REQUEST.search(table.lower()):
                    self.out.signal("erasure_request", f"{ef.rel}:{L(s)}")
                for f in walk(s):
                    if f.type == "call" and T(target(f)) in {"field", "embeds_one", "embeds_many"}:
                        fa = arguments(f)
                        fname = atom(fa[0]) if fa else None
                        if not fname:
                            continue
                        loc = f"{ef.rel}:{L(f)}"
                        if is_personal_name(fname, "user" if is_user else mod.name.split(".")[-1].lower()) or (
                                is_user and is_record_field(fname)):
                            self.out.signal("personal_field", loc, model=True)
                        if PW_EXPIRY.search(fname) and re.search(r"expir|max_age|must|force|require", fname):
                            self.out.signal("pw_expiry", loc)


VERIFYING = {"Joken.verify", "Joken.verify_and_validate", "Joken.Signer.verify", "JOSE.JWT.verify", "JOSE.JWS.verify",
             "JOSE.JWT.verify_strict", "JOSE.JWS.verify_strict", ":jose_jwt.verify", ":jose_jws.verify",
             ":jose_jwt.verify_strict", ":jose_jws.verify_strict", "Phoenix.Token.verify", "Phoenix.Token.decrypt",
             "Plug.Crypto.verify", "Plug.Crypto.decrypt", "Plug.Crypto.MessageVerifier.verify",
             "Plug.Crypto.MessageEncryptor.decrypt", "Guardian.decode_and_verify", "Guardian.resource_from_token",
             "Oidcc.Token.validate_jwt", "Oidcc.Token.validate_id_token", "Oidcc.Token.retrieve"}
PEEKING = {"Joken.peek_claims", "Joken.peek_header", "Joken.peek", "JOSE.JWT.peek", "JOSE.JWT.peek_payload",
           "JOSE.JWT.peek_protected", "JOSE.JWS.peek", "JOSE.JWS.peek_payload", "JOSE.JWS.peek_protected",
           ":jose_jwt.peek", ":jose_jwt.peek_payload", "Guardian.peek", "Guardian.peek_claims"}


def callee_field(n) -> str | None:
    """`user.email` (a field access, no parentheses) -> "email"."""
    t = target(n)
    if t is None or t.type != "dot" or has_parens(n):
        return None
    left, right = t.child_by_field_name("left"), t.child_by_field_name("right")
    if left is None or right is None or left.type == "alias" or left.type == "atom":
        return None
    return T(right)


def walk_bodies(block):
    for c in kids(block):
        yield c


# ---------------------------------------------------------------- templates

EEX_TAG = re.compile(r"<%(?!%)=?(?P<body>.*?)%>", re.S)
RAW_WORD = re.compile(r"\b(?:Phoenix\.HTML\.)?raw\b")
_PARSER = parser()


def _line_at(text: str, pos: int) -> int:
    return text.count("\n", 0, pos)


def _curly_exprs(text: str):
    """HEEx `{...}` expressions that call raw, as (start offset of the inner text, inner text)."""
    for m in re.finditer(r"\{\s*(?=(?:Phoenix\.HTML\.)?raw\b)", text):
        depth, i = 1, m.end()
        quote = None
        while i < len(text) and depth:
            ch = text[i]
            if quote:
                if ch == "\\":
                    i += 1
                elif ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        if depth == 0:
            yield m.end(), text[m.end():i - 1]


def scan_template_raw(text: str, line0: int, rel: str, an: Analyser, mod: Module | None):
    """raw/1 in EEx/HEEx: `<%= raw x %>`, `<%= raw(x) %>`, `{raw(x)}`. The inner expression is parsed as Elixir."""
    spans = [(m.start("body"), m.group("body")) for m in EEX_TAG.finditer(text) if RAW_WORD.search(m.group("body"))]
    spans += list(_curly_exprs(text))
    ctx_mod = mod if mod is not None else Module(f"<template:{rel}>", None, None)
    for start, body in spans:
        src = body.encode("utf-8")
        tree = _PARSER.parse(src)
        for x in walk(tree.root_node):
            if x.type != "call":
                continue
            t = target(x)
            name = T(t)
            if name not in {"raw", "Phoenix.HTML.raw"}:
                continue
            args = arguments(x)
            if len(args) != 1:
                continue
            offset = len(src[:x.start_byte].decode("utf-8", "replace"))
            line = line0 + _line_at(text, start + offset) + 1
            an.html_raw(args[0], ctx_mod, None, f"{rel}:{line}", template=True)
