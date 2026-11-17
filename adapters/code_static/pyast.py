"""Python analysis with the standard library `ast` (parsing only; nothing is imported or executed)."""

from __future__ import annotations

import ast
import re

from .common import (dedicated_hasher, Collector, model_policy, session_cookie_name, PW_EXPIRY, LOCKOUT, ERASURE_REQUEST, analyse_password_regex, external_host, is_credential_name, is_password_name,
                     is_personal_name, is_stored_password_name, is_user_object_name, literal_secret_kind,
                     plausible_secret_value, secret_kind_for_name, words, length_bound, rejects_words)
from .files import SourceFile
from .models import Models, arg as model_arg

SOURCE_ATTRS = {"GET", "POST", "body", "data", "args", "form", "values", "json", "files", "FILES", "cookies", "COOKIES",
                "headers", "META", "query_params", "path_params", "get_json", "stream", "query_string", "raw_post_data",
                "content", "text", "path", "url", "full_path", "query", "params", "path_info"}
REQUEST_NAMES = {"request", "req"}
ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete", "api_route", "websocket", "api_view", "head", "options"}
SQL_WORDS = re.compile(r"\b(select|insert|update|delete|create|drop|alter|pragma|replace|with)\b", re.I)
PASSWORD_APIS = ("werkzeug.security.generate_password_hash", "werkzeug.security.check_password_hash", "passlib.hash.",
                 "django.contrib.auth.hashers.")   # functions that only ever hash passwords
HASHLIB = {"md5": "md5", "sha1": "sha1", "sha224": "sha256", "sha256": "sha256", "sha384": "sha512", "sha512": "sha512",
           "sha3_256": "sha256", "sha3_512": "sha512", "blake2b": "other", "blake2s": "other"}
PASSLIB_SCHEMES = {"bcrypt": ("bcrypt", True), "bcrypt_sha256": ("bcrypt", True), "argon2": ("argon2", True),
                   "pbkdf2_sha256": ("pbkdf2", True), "pbkdf2_sha512": ("pbkdf2", True), "pbkdf2_sha1": ("pbkdf2", True),
                   "django_pbkdf2_sha256": ("pbkdf2", True), "scrypt": ("scrypt", True), "sha256_crypt": ("sha256", True),
                   "sha512_crypt": ("sha512", True), "md5_crypt": ("md5", True), "hex_md5": ("md5", False),
                   "hex_sha1": ("sha1", False), "hex_sha256": ("sha256", False), "plaintext": ("plaintext", False),
                   "des_crypt": ("other", True), "ldap_md5": ("md5", False), "ldap_salted_md5": ("md5", True)}
DJANGO_HASHERS = {"PBKDF2PasswordHasher": ("pbkdf2", True), "PBKDF2SHA1PasswordHasher": ("pbkdf2", True),
                  "Argon2PasswordHasher": ("argon2", True), "BCryptSHA256PasswordHasher": ("bcrypt", True),
                  "BCryptPasswordHasher": ("bcrypt", True), "ScryptPasswordHasher": ("scrypt", True),
                  "MD5PasswordHasher": ("md5", True), "UnsaltedMD5PasswordHasher": ("md5", False),
                  "SHA1PasswordHasher": ("sha1", True), "UnsaltedSHA1PasswordHasher": ("sha1", False),
                  "CryptPasswordHasher": ("other", True)}
LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log", "fatal"}
ORM_METHODS = {"filter", "filter_by", "exclude", "get", "get_or_create", "update_or_create", "create", "update", "where",
               "having", "extra", "values", "first_or_404", "get_or_404"}
NOT_MODEL_SUFFIX = ("Form", "Schema", "Create", "Update", "Register", "Registration", "In", "Request", "Input", "Payload",
                    "Dto", "DTO", "Body", "Credentials", "Login", "Field", "Exception", "Error", "Response", "Public")
MODEL_BASES = ("Model", "SQLModel", "Base", "Document", "AbstractUser", "AbstractBaseUser", "DeclarativeBase", "Table")
DJANGO_AUTH_FORMS = {"UserCreationForm", "BaseUserCreationForm", "SetPasswordForm", "PasswordChangeForm", "AdminPasswordChangeForm"}
SCRIPT_PARTS = {"scripts", "script", "bin", "tools", "artifacts", "management", "seed", "seeds", "fixtures", "commands"}


EXCEPT_TUPLE = re.compile(r"^(\s*except\*?\s+)(?!\()([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)+)(\s*:)", re.M)


def parse(text: str, rel: str):
    """Parse a module; newer syntax the running Python lacks is rewritten in place first (line numbers are kept)."""
    for attempt in (text, EXCEPT_TUPLE.sub(r"\1(\2)\3", text)):  # PEP 758: `except A, B:`
        try:
            return ast.parse(attempt, filename=rel)
        except (SyntaxError, ValueError, RecursionError):
            continue
    return None


def dotted(node) -> list[str]:
    """`request.POST.get` -> ['request', 'POST', 'get']; calls in the chain are looked through."""
    out = []
    while True:
        if isinstance(node, ast.Attribute):
            out.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Subscript):
            node = node.value
        elif isinstance(node, ast.Name):
            out.append(node.id)
            return out[::-1]
        else:
            return out[::-1]


def const_str(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        v = node.value
        return v.decode("utf-8", "replace") if isinstance(v, bytes) else v
    return None


def kw(call: ast.Call, name: str):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def names_in(expr) -> list[tuple[str, str | None]]:
    """Identifiers, attributes and constant subscript keys an expression reads, with their owner (for `user.name`)."""
    out = []
    for n in ast.walk(expr):
        if isinstance(n, ast.Name):
            out.append((n.id, None))
        elif isinstance(n, ast.Attribute):
            owner = n.value.id if isinstance(n.value, ast.Name) else (n.value.attr if isinstance(n.value, ast.Attribute) else None)
            out.append((n.attr, owner))
        elif isinstance(n, ast.Subscript):
            k = const_str(n.slice)
            if k:
                owner = n.value.id if isinstance(n.value, ast.Name) else None
                out.append((k, owner))
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get" and n.args:
            k = const_str(n.args[0])
            if k:
                out.append((k, None))
    return out


def _branch(stmts) -> str | None:
    """"reject" when a branch rejects the input (raises, returns anything but True, aborts, records an error),
    "accept" when it returns True, else None."""
    if not stmts:
        return None
    names = []
    for st in stmts:
        for x in ast.walk(st):
            if isinstance(x, ast.Raise):
                return "reject"
            if isinstance(x, ast.Return) and x in stmts:
                return "accept" if isinstance(x.value, ast.Constant) and x.value.value is True else "reject"
            if isinstance(x, ast.Call):
                names += dotted(x.func) + [k.arg for k in x.keywords if k.arg]
            elif isinstance(x, ast.Name):
                names.append(x.id)
            elif isinstance(x, ast.Constant) and isinstance(x.value, int) and 400 <= x.value <= 499:
                return "reject"
    return "reject" if rejects_words(names) else None


def _invalid_when(pf, node) -> bool | None:
    """Whether `node` (a condition) holding means the code rejects the input there (True), accepts it (False), or
    the context does not say (None). `not` flips it; `and`/`or` pass it through."""
    holds = True
    while True:
        parent = pf.parent.get(node)
        if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not):
            holds = not holds
        elif isinstance(parent, ast.BoolOp):
            pass
        elif isinstance(parent, ast.If) and node is parent.test:
            body, orelse = _branch(parent.body), _branch(parent.orelse)
            if body == "reject" or orelse == "accept":
                return holds
            if body == "accept" or orelse == "reject":
                return not holds
            return None
        elif isinstance(parent, (ast.Assert, ast.Return, ast.Lambda)):
            return not holds        # asserted or returned: what holds is what passes
        else:
            return None
        node = parent


class PyFile:
    def __init__(self, sf: SourceFile, text: str, tree: ast.Module, models: Models):
        self.sf, self.text, self.tree, self.models = sf, text, tree, models
        self.parent: dict = {}
        self.scope: dict = {}
        self.funcs: list = []
        self.aliases: dict[str, str] = {}
        self._rules: dict = {}
        self._index(tree, tree)
        self.taint: dict = {}
        self.assigns: dict = {}  # scope -> name -> [(line, value)]
        self.bindings: dict = {}  # scope -> [(names, value)]
        for n in ast.walk(tree):
            self._binding(n)
        self.imports_text = " ".join(sorted(set(self.aliases.values())))

    # ---------------------------------------------------------------- structure

    def _index(self, node, scope):
        for child in ast.iter_child_nodes(node):
            self.parent[child] = node
            self.scope[child] = scope
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                for a in child.names:
                    if isinstance(child, ast.Import):
                        self.aliases[(a.asname or a.name).split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
                    else:
                        self.aliases[a.asname or a.name] = f"{child.module or ''}.{a.name}"
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                self.funcs.append(child)
                self._index(child, child)
            else:
                self._index(child, scope)

    def qual(self, node) -> str:
        parts = dotted(node)
        if not parts:
            return ""
        head = self.aliases.get(parts[0], parts[0])
        return ".".join([head] + parts[1:])

    def callee(self, node) -> tuple[list[str], bool]:
        """The callee for framework-model matching: (qualified name segments, first name comes from an import)."""
        parts = dotted(node)
        if not parts or parts[0] not in self.aliases:
            return parts, False
        return self.aliases[parts[0]].split(".") + parts[1:], True

    def rule(self, call: ast.Call, kind: str):
        key = (id(call), kind)
        if key not in self._rules:
            self._rules[key] = self.models.match("python", self.callee(call.func), kind)
        return self._rules[key]

    def at(self, node) -> str:
        return f"{self.sf.rel}:{node.lineno}"

    def chain(self, node):
        """Enclosing scopes, innermost first."""
        s = self.scope.get(node, self.tree)
        out = []
        while s is not None:
            out.append(s)
            if s is self.tree:
                break
            s = self.scope.get(s, self.tree)
        return out

    def _binding(self, n):
        def targets_of(t):
            if isinstance(t, ast.Name):
                return [t.id]
            if isinstance(t, (ast.Tuple, ast.List)):
                return [x for e in t.elts for x in targets_of(e)]
            if isinstance(t, (ast.Attribute, ast.Subscript)):
                d = dotted(t)
                return [d[0]] if d else []
            if isinstance(t, ast.Starred):
                return targets_of(t.value)
            return []
        pairs = []
        if isinstance(n, ast.Assign):
            pairs = [(targets_of(t), n.value) for t in n.targets]
            for t in n.targets:
                if isinstance(t, ast.Name):
                    self.assigns.setdefault(self.scope[n], {}).setdefault(t.id, []).append((n.lineno, n.value))
        elif isinstance(n, ast.AnnAssign) and n.value is not None:
            pairs = [(targets_of(n.target), n.value)]
            if isinstance(n.target, ast.Name):
                self.assigns.setdefault(self.scope[n], {}).setdefault(n.target.id, []).append((n.lineno, n.value))
        elif isinstance(n, ast.AugAssign):
            pairs = [(targets_of(n.target), n.value)]
            if isinstance(n.target, ast.Name):
                self.assigns.setdefault(self.scope[n], {}).setdefault(n.target.id, []).append((n.lineno, ast.BinOp(ast.Name(n.target.id), n.op, n.value)))
        elif isinstance(n, (ast.For, ast.AsyncFor)):
            pairs = [(targets_of(n.target), n.iter)]
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            pairs = [(targets_of(i.optional_vars), i.context_expr) for i in n.items if i.optional_vars is not None]
        elif isinstance(n, ast.NamedExpr):
            pairs = [(targets_of(n.target), n.value)]
        elif isinstance(n, ast.comprehension):
            pairs = [(targets_of(n.target), n.iter)]
        if pairs:
            self.bindings.setdefault(self.scope.get(n, self.tree), []).extend(pairs)

    # ---------------------------------------------------------------- functions and taint

    def func_name(self, f) -> str | None:
        return getattr(f, "name", None)

    def params(self, f) -> list[str]:
        a = f.args
        return [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]

    def decorators(self, f) -> list:
        return getattr(f, "decorator_list", [])

    def is_route(self, f) -> bool:
        for d in self.decorators(f):
            parts = dotted(d)
            if parts and parts[-1] in ROUTE_DECORATORS and len(parts) >= 2:
                return True
            if parts and parts[-1] == "api_view":
                return True
        return False

    def route_path(self, f) -> str | None:
        for d in self.decorators(f):
            if isinstance(d, ast.Call) and dotted(d) and dotted(d)[-1] in ROUTE_DECORATORS and d.args:
                return const_str(d.args[0])
        return None

    def initial_taint(self, f, seeds: set[str]) -> set[str]:
        out = set(seeds)
        if isinstance(f, ast.Lambda):
            return out
        ps = self.params(f)
        plain = [p for p in ps if p not in {"self", "cls"}]
        if plain and plain[0] in REQUEST_NAMES:
            out |= set(plain[1:]) - {"args", "kwargs"}  # Django view: URL parameters
        if self.is_route(f):
            a = f.args
            defaults = dict(zip([x.arg for x in a.args][::-1], a.defaults[::-1]))
            for x in a.args + a.kwonlyargs:
                if x.arg in {"self", "cls"} | REQUEST_NAMES:
                    continue
                ann = ast.unparse(x.annotation) if x.annotation is not None else ""
                dflt = defaults.get(x.arg)
                dtxt = ast.unparse(dflt) if dflt is not None else ""
                injected = ("Depends" in ann or "Depends" in dtxt or re.search(r"(Dep|Session|User)\b", ann)) and "RequestForm" not in ann
                if not injected:
                    out.add(x.arg)
        return out

    def is_source(self, n) -> bool:
        if isinstance(n, ast.Attribute):
            parts = dotted(n)
            if len(parts) >= 2 and parts[0] in REQUEST_NAMES and parts[1] in SOURCE_ATTRS:
                return True
            if len(parts) >= 3 and parts[0] == "self" and parts[1] in REQUEST_NAMES and parts[2] in SOURCE_ATTRS:
                return True
        if isinstance(n, ast.Call) and self.rule(n, "source"):
            return True
        return False

    def tainted(self, expr, at_node=None) -> bool:
        if expr is None:
            return False
        names: set[str] = set()
        for s in self.chain(at_node if at_node is not None else expr):
            names |= self.taint.get(s, set())
        stack = [expr]
        while stack:
            n = stack.pop()
            if isinstance(n, ast.Call) and self.rule(n, "sanitizer"):
                continue  # its result is not controlled by the request
            if isinstance(n, ast.Name) and n.id in names:
                return True
            if self.is_source(n):
                return True
            stack.extend(ast.iter_child_nodes(n))
        return False

    def compute_taint(self, seeds: dict):
        self.taint = {}
        for f in self.funcs:
            self.taint[f] = self.initial_taint(f, seeds.get((self.sf.rel, f.lineno, self.func_name(f)), set()))
        self.taint.setdefault(self.tree, set())
        for _ in range(4):
            changed = False
            for scope, pairs in self.bindings.items():
                for names, value in pairs:
                    if names and self.tainted(value, value):
                        new = set(names) - self.taint.setdefault(scope, set())
                        if new:
                            self.taint[scope] |= new
                            changed = True
            if not changed:
                break

    def tainted_calls(self):
        """(callee name, parameter position or keyword) for every call passing tainted data."""
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Call):
                parts = dotted(n.func)
                if not parts:
                    continue
                name = parts[-1]
                for i, a in enumerate(n.args):
                    if self.tainted(a, n):
                        yield name, i
                for k in n.keywords:
                    if k.arg and self.tainted(k.value, n):
                        yield name, k.arg
                    elif k.arg is None and self.tainted(k.value, n):
                        yield name, "**"

    def resolve(self, name: str, at_node) -> list:
        for s in self.chain(at_node):
            vals = self.assigns.get(s, {}).get(name)
            if vals:
                return [v for line, v in vals if line <= at_node.lineno] or [v for _, v in vals]
        return []


# ==================================================================== analysis

class PyAnalyser:
    def __init__(self, files: list[tuple[SourceFile, str]], ctx):
        self.ctx = ctx
        self.fm: Models = ctx["models"]
        self.files: list[PyFile] = []
        self.unparsed: list[str] = []
        for sf, text in files:
            tree = parse(text, sf.rel)
            if tree is None:
                self.unparsed.append(sf.rel)
                continue
            self.files.append(PyFile(sf, text, tree, ctx["models"]))
        self.helpers: dict[str, tuple] = {}
        self.hash_instances: dict[str, tuple] = {}
        self.django_hasher = ("pbkdf2", True)
        self.django_project = False
        self.repo_functions: set[str] = set()
        self.constants: dict[str, set] = {}  # module-level NAME = "literal", across the repository
        for pf in self.files:
            for n in pf.tree.body:
                if isinstance(n, (ast.Assign, ast.AnnAssign)) and const_str(n.value) is not None:
                    for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                        if isinstance(t, ast.Name):
                            self.constants.setdefault(t.id, set()).add(const_str(n.value))

    # ------------------------------------------------------------ cross-file tables

    def functions(self):
        for pf in self.files:
            if pf.sf.example:
                continue
            for f in pf.funcs:
                name = pf.func_name(f)
                if name:
                    yield name, pf, f

    def prepare(self):
        self.repo_functions = {name for name, _, _ in self.functions()}
        for pf in self.files:
            if any(isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in {"INSTALLED_APPS", "MIDDLEWARE"} for t in n.targets) for n in pf.tree.body):
                self.django_project = True
                for n in pf.tree.body:
                    if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "PASSWORD_HASHERS" for t in n.targets):
                        if isinstance(n.value, (ast.List, ast.Tuple)) and n.value.elts:
                            first = const_str(n.value.elts[0]) or ""
                            self.django_hasher = DJANGO_HASHERS.get(first.rsplit(".", 1)[-1], ("other", True))
            if "django" in pf.imports_text:
                self.django_project = self.django_project or "django.contrib.auth" in pf.imports_text
        # hasher objects bound to a name: CryptContext, pwdlib PasswordHash, argon2 PasswordHasher
        for pf in self.files:
            for n in ast.walk(pf.tree):
                if isinstance(n, (ast.Assign, ast.AnnAssign)) and isinstance(getattr(n, "value", None), ast.Call):
                    tgt = n.targets[0] if isinstance(n, ast.Assign) else n.target
                    if isinstance(tgt, ast.Name):
                        algo = self.hasher_object(pf, n.value)
                        if algo:
                            self.hash_instances[tgt.id] = algo
        # repo functions that hash one of their parameters
        for _ in range(2):
            for name, pf, f in self.functions():
                if isinstance(f, ast.Lambda) or name in self.helpers:
                    continue
                ps = set(pf.params(f))
                for n in ast.walk(f):
                    if isinstance(n, ast.Call):
                        prim = self.primitive(pf, n)
                        if prim and prim[2] is not None and any(isinstance(x, ast.Name) and x.id in ps for x in ast.walk(prim[2])):
                            self.helpers[name] = prim[:2]
                            break

    def hasher_object(self, pf: PyFile, call: ast.Call):
        q = pf.qual(call.func)
        if q.endswith("CryptContext"):
            schemes = kw(call, "schemes")
            if isinstance(schemes, (ast.List, ast.Tuple)) and schemes.elts:
                return PASSLIB_SCHEMES.get(const_str(schemes.elts[0]) or "", ("other", True))
            return None
        if q.endswith("PasswordHash.recommended") or (q.endswith("PasswordHash") and "pwdlib" in q):
            if call.args and isinstance(call.args[0], (ast.Tuple, ast.List)) and call.args[0].elts:
                first = pf.qual(call.args[0].elts[0].func) if isinstance(call.args[0].elts[0], ast.Call) else ""
                return ("bcrypt", True) if "Bcrypt" in first else ("argon2", True)
            return ("argon2", True)
        if q.endswith("argon2.PasswordHasher") or q == "argon2.PasswordHasher":
            return ("argon2", True)
        return None

    def primitive(self, pf: PyFile, c: ast.Call):
        """(algorithm, salted, password input expression) for a call that hashes or encodes its input."""
        rule = pf.rule(c, "password_hash")
        if rule:
            s = rule.spec
            pw = model_arg(s.get("password", 0), c.args, {k.arg: k.value for k in c.keywords if k.arg})
            return s["algorithm"], self._salted(pw) if s["salted"] == "infer" else s["salted"], pw
        q = pf.qual(c.func)
        parts = q.split(".")
        first = c.args[0] if c.args else None
        if parts[0] == "hashlib" and len(parts) >= 2:
            alg = parts[1]
            if alg == "new" and c.args:
                return HASHLIB.get((const_str(c.args[0]) or "").lower(), "other"), self._salted(c.args[1] if len(c.args) > 1 else None), (c.args[1] if len(c.args) > 1 else None)
            if alg == "pbkdf2_hmac":
                salt = c.args[2] if len(c.args) > 2 else kw(c, "salt")
                return "pbkdf2", salt is not None and const_str(salt) is None, (c.args[1] if len(c.args) > 1 else kw(c, "password"))
            if alg == "scrypt":
                salt = kw(c, "salt")
                return "scrypt", salt is not None and const_str(salt) is None, first
        if q.startswith("passlib.hash.") and parts[-1] in {"hash", "verify", "encrypt"}:
            return (*PASSLIB_SCHEMES.get(parts[2], ("other", True)), first)
        if q.startswith("werkzeug.security.") and parts[-1] in {"generate_password_hash", "check_password_hash"}:
            method = const_str(kw(c, "method")) if kw(c, "method") is not None else None
            arg = c.args[1] if parts[-1] == "check_password_hash" and len(c.args) > 1 else first
            if method is None:
                return None, True, arg
            m = method.split(":")[0]
            return {"pbkdf2": "pbkdf2", "scrypt": "scrypt", "plain": "plaintext"}.get(m, "other"), m != "plain", arg
        if q in {"django.contrib.auth.hashers.make_password", "django.contrib.auth.hashers.check_password"}:
            return (*self.django_hasher, first)
        if isinstance(c.func, ast.Attribute) and c.func.attr in {"set_password", "check_password"} and self.django_project:
            return (*self.django_hasher, first)
        if isinstance(c.func, ast.Attribute) and c.func.attr in {"create_user", "create_superuser"} and self.django_project:
            pw = kw(c, "password") or (c.args[2] if len(c.args) > 2 else None)
            return (*self.django_hasher, pw) if pw is not None else None
        if q == "django.contrib.auth.authenticate" and kw(c, "password") is not None:
            return (*self.django_hasher, kw(c, "password"))
        if isinstance(c.func, ast.Attribute) and c.func.attr in {"encrypt"} and dotted(c.func)[:1] and (
                "cryptography" in pf.imports_text or "Crypto" in pf.imports_text):
            return "reversible", False, first
        if isinstance(c.func, ast.Attribute) and c.func.attr in {"hash", "verify", "encrypt", "verify_and_update", "hash_password"}:
            owner = dotted(c.func.value)
            if owner and owner[-1] in self.hash_instances:
                arg = first if c.func.attr != "verify" or len(c.args) < 2 else c.args[0]
                return (*self.hash_instances[owner[-1]], arg)
        return None

    def _salted(self, expr) -> bool:
        if expr is None:
            return False
        return any(("salt" in words(n)) for n, _ in names_in(expr))

    # ------------------------------------------------------------ run

    def run(self, out: Collector):
        for pf in self.files:
            if pf.sf.example:
                self.secrets(pf, out)
                continue
            self.secrets(pf, out)
            if pf.sf.client:
                continue
            self.settings(pf, out)
            self.models(pf, out)
            hashed_vars = self.hashed_vars(pf)
            for n in ast.walk(pf.tree):
                if isinstance(n, ast.Call):
                    self.call(pf, n, out, hashed_vars)
                elif isinstance(n, ast.Compare):
                    self.compare(pf, n, out, hashed_vars)
                elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.function(pf, n, out)
                elif isinstance(n, (ast.Name, ast.Attribute)):
                    nm = n.id if isinstance(n, ast.Name) else n.attr
                    if nm in DJANGO_AUTH_FORMS and "django" in pf.imports_text:
                        out.signal("django_validators_used", pf.at(n))  # these forms run AUTH_PASSWORD_VALIDATORS
                    j = "_".join(words(nm))
                    if PW_EXPIRY.search(j):
                        out.signal("pw_expiry", pf.at(n))
                    if LOCKOUT.search(j):
                        out.signal("lockout", pf.at(n))
                    if ERASURE_REQUEST.search(j) and self.request_reachable_node(pf, n):
                        out.signal("erasure_request", pf.at(n))  # where a request records it
            self.verifying_routes(pf, out)

    def verifying_routes(self, pf: PyFile, out: Collector):
        """A request handler that checks a submitted password against a stored one is a login route, whatever its name."""
        stores = {int(at.rpartition(":")[2]) for (t, at) in out.elements if t == "PasswordStore" and at.rpartition(":")[0] == pf.sf.rel}
        for f in pf.funcs:
            if isinstance(f, ast.Lambda) or not stores:
                continue
            ps = pf.params(f)
            if not (pf.is_route(f) or ps[:1] and ps[0] in REQUEST_NAMES or ps[1:2] and ps[0] == "self" and ps[1] in REQUEST_NAMES):
                continue
            if re.search(r"regist|signup|sign_up|reset|change|update|forgot|create|add|new|delete", f.name.lower()):
                continue
            if not any(f.lineno <= line <= (f.end_lineno or f.lineno) for line in stores):
                continue
            verifies = any(
                (isinstance(n, ast.Call) and dotted(n.func)[-1:] and re.search(r"verify|check|compare|authenticate", dotted(n.func)[-1]))
                or (isinstance(n, ast.Compare) and any(isinstance(o, (ast.Eq, ast.NotEq)) for o in n.ops) and self.mentions_password(pf, n))
                or (isinstance(n, ast.Call) and any(k.arg and is_stored_password_name(k.arg) for k in n.keywords)
                    and dotted(n.func)[-1:] and dotted(n.func)[-1] in {"filter_by", "filter", "get", "find_one", "first"})
                for n in ast.walk(f))
            if verifies and not any(s[1] == pf.at(f) for s in out.signals.get("login_route", [])):
                out.signal("login_route", pf.at(f), fn=f.name)

    def hashed_vars(self, pf: PyFile) -> set[str]:
        out = set()
        for scope, names in pf.assigns.items():
            for name, vals in names.items():
                for _, v in vals:
                    for c in ast.walk(v):
                        if isinstance(c, ast.Call) and (self.primitive(pf, c) or self.helper_of(pf, c)):
                            out.add(name)
        return out

    def helper_of(self, pf: PyFile, c: ast.Call):
        parts = dotted(c.func)
        if parts and parts[-1] in self.helpers:
            return self.helpers[parts[-1]]
        return None

    def raw_password(self, pf: PyFile, expr, hashed: set[str]) -> bool:
        """The expression is a cleartext password (not a hash of it)."""
        if expr is None:
            return False
        for c in ast.walk(expr):
            if isinstance(c, ast.Call) and (self.primitive(pf, c) or self.helper_of(pf, c)):
                return False
        if isinstance(expr, ast.Name):
            return is_password_name(expr.id) and expr.id not in hashed
        if isinstance(expr, ast.Attribute):
            return is_password_name(expr.attr)
        if isinstance(expr, ast.Subscript):
            k = const_str(expr.slice)
            return bool(k and is_password_name(k)) and pf.tainted(expr, expr)
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "get" and expr.args:
            k = const_str(expr.args[0])
            return bool(k and is_password_name(k)) and pf.tainted(expr, expr)
        return False

    def mentions_password(self, pf: PyFile, expr) -> bool:
        if expr is None:
            return False
        return any(is_password_name(n) for n, _ in names_in(expr))

    def call(self, pf: PyFile, c: ast.Call, out: Collector, hashed: set[str]):
        at = pf.at(c)
        parts = dotted(c.func)
        last = parts[-1] if parts else ""
        q = pf.qual(c.func)
        # ---- PasswordStore
        prim = self.primitive(pf, c)
        helper = None if prim else self.helper_of(pf, c)
        # a password-hashing API hashes a password whatever the variable is called (`secret_phrase`, `mot_de_passe`)
        dedicated = prim is not None and prim[2] is not None and (
            dedicated_hasher(prim[0], pf.rule(c, "password_hash") is not None) or q.startswith(PASSWORD_APIS)
            or (self.django_project and last in {"set_password", "check_password", "create_user", "create_superuser"}))
        if prim and (dedicated or self.mentions_password(pf, prim[2])):
            out.element("PasswordStore", at, algorithm=prim[0], salted=prim[1])
            out.mark(at, pf.rule(c, "password_hash"))
            if last in {"create_user", "create_superuser", "set_password", "make_password", "generate_password_hash", "hash", "hashpw"} and pf.tainted(prim[2], c):
                out.signal("pw_set_site", at)
            out.signal("pw_auth", at)
        elif helper and any(self.mentions_password(pf, a) for a in list(c.args) + [k.value for k in c.keywords]):
            out.element("PasswordStore", at, algorithm=helper[0], salted=helper[1])
            out.signal("pw_auth", at)
        else:
            pwkw = next((k for k in c.keywords if k.arg and (is_stored_password_name(k.arg) or is_password_name(k.arg))), None)
            callee_ok = (last in {"create", "get", "filter", "filter_by", "get_or_create", "update", "update_or_create", "insert",
                                  "insert_one", "update_one", "find_one", "find"}
                         or (last[:1].isupper() and not last.endswith(NOT_MODEL_SUFFIX) and last not in {"CharField", "PasswordInput"}))
            if pwkw is not None and callee_ok and self.raw_password(pf, pwkw.value, hashed):
                out.element("PasswordStore", at, algorithm="plaintext", salted=False)
                out.signal("pw_auth", at)
                if pf.tainted(pwkw.value, c) and last not in {"get", "filter", "filter_by", "find_one", "find"}:
                    out.signal("pw_set_site", at)
        if q == "django.contrib.auth.authenticate" or q.endswith("OAuth2PasswordRequestForm") or last == "OAuth2PasswordRequestForm":
            out.signal("pw_auth", at)
        if last == "include" and c.args and const_str(c.args[0]) in {"django.contrib.auth.urls", "allauth.urls", "allauth.account.urls"}:
            fw = "allauth" if const_str(c.args[0]).startswith("allauth") else "django"
            out.signal("login_route", at, fw=fw)
            out.signal("pw_auth", at)
        if last == "as_view" and isinstance(c.func, ast.Attribute) and dotted(c.func.value)[-1:] == ["LoginView"]:
            out.signal("login_route", at, fw="django")
            out.signal("pw_auth", at)
        # ---- Query
        self.query(pf, c, out, hashed)
        # ---- TokenVerification
        rule = pf.rule(c, "token_verification")
        if rule:
            out.element("TokenVerification", at, **rule.spec)
            out.mark(at, rule)
        elif q in {"jwt.decode", "jose.jwt.decode", "jwt.api_jwt.decode"} or (q.endswith("jwt.decode") and "jwt" in pf.imports_text):
            opts = kw(c, "options")
            verify = True
            if isinstance(opts, ast.Dict):
                for k, v in zip(opts.keys, opts.values):
                    if const_str(k) == "verify_signature" and isinstance(v, ast.Constant) and v.value is False:
                        verify = False
            v = kw(c, "verify")
            if isinstance(v, ast.Constant) and v.value is False:
                verify = False
            algs = kw(c, "algorithms")
            allows = None
            if not verify:
                allows = True
            elif isinstance(algs, (ast.List, ast.Tuple, ast.Set)):
                vals = [self._const(pf, e, c) for e in algs.elts]
                allows = None if any(v is None for v in vals) else _alg_risk([v.lower() for v in vals])
            elif isinstance(algs, ast.Constant):
                allows = str(algs.value).lower() == "none"
            elif algs is not None and isinstance(algs, ast.Name):
                vals = self._const_list(pf, algs, c)
                allows = _alg_risk(vals) if vals is not None else None
            out.element("TokenVerification", at, verifies_signature=verify, allows_none_alg=allows)
        elif q.endswith(("jwt.get_unverified_claims", "jwt.get_unverified_header", "jwt.get_unverified_headers")) and "jwt" in q:
            out.element("TokenVerification", at, verifies_signature=False, allows_none_alg=True)
        # ---- Cookie
        rule = pf.rule(c, "cookie")
        if rule:
            self.model_cookie(pf, c, rule, out)
        elif last in {"set_cookie", "set_signed_cookie"} and isinstance(c.func, ast.Attribute):
            self.cookie(pf, c, out)
        # ---- LogStatement
        rule = pf.rule(c, "log")
        if rule:
            self.log(pf, c, out)
            out.mark(at, rule if (("LogStatement", at) in out.elements) else None)
        elif (q == "print" and isinstance(c.func, ast.Name)) or (
                last in LOG_METHODS and len(parts) >= 2 and ("log" in parts[-2].lower() or parts[-2] == "logging")) or (
                last in self.repo_functions and {"log", "audit", "logger"} & set(words(last))):  # the repository's own log helper
            self.log(pf, c, out)
        # ---- Transfer
        self.transfer(pf, c, out)
        # ---- password policy and other subject signals
        self.policy_call(pf, c, out)
        if last == "delete" and not (set(x.lower() for x in pf.sf.rel.split("/")[:-1]) & SCRIPT_PARTS) and self.request_reachable(pf, c):
            recv = dotted(c.func.value) if isinstance(c.func, ast.Attribute) else []
            args = [dotted(a) for a in c.args]
            if any(is_user_object_name(p) or p in {"User", "UserModel", "Users"} for p in recv[:2] + recv[-1:]) or (
                    recv and recv[-1] in {"session", "db"} and args and args[0] and is_user_object_name(args[0][-1])):
                out.signal("user_delete", at)
        if q.endswith("Limiter") and (kw(c, "default_limits") is not None or kw(c, "application_limits") is not None):
            out.signal("rate_limit", at, scope="global")
        rule = pf.rule(c, "rate_limit")
        if rule:  # called rather than used as a decorator: app-wide, or inside the handler it guards
            fn = next((s for s in pf.chain(c) if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
            if rule.spec.get("scope") == "global" or fn is None:
                out.signal("rate_limit", at, scope="global")
            else:
                out.signal("rate_limit", at, scope="login", route_at=pf.at(fn))
            out.mark(at, rule)
        rule = pf.rule(c, "erasure")
        if rule and self.request_reachable(pf, c):
            out.signal("user_delete", at)
            out.mark(at, rule)

    def request_reachable_node(self, pf: PyFile, n) -> bool:
        for s in pf.chain(n):
            if s is pf.tree or isinstance(s, ast.Lambda):
                continue
            ps = pf.params(s)
            if pf.is_route(s) or (ps[:1] and ps[0] in REQUEST_NAMES) or (ps[1:2] and ps[0] == "self" and ps[1] in REQUEST_NAMES):
                return True
        return False

    def request_reachable(self, pf: PyFile, c) -> bool:
        """Inside a request handler, or passed request data (so not a seed or maintenance script)."""
        if any(pf.tainted(a, c) for a in list(c.args) + [k.value for k in c.keywords]):
            return True
        for s in pf.chain(c):
            if s is pf.tree or isinstance(s, ast.Lambda):
                continue
            ps = pf.params(s)
            if pf.is_route(s) or (ps[:1] and ps[0] in REQUEST_NAMES) or (ps[:2] and ps[0] == "self" and ps[1:2][0] in REQUEST_NAMES) \
                    or pf.taint.get(s):
                return True
        return False

    def _const_list(self, pf, name_node, at_node):
        for v in pf.resolve(name_node.id, at_node):
            if isinstance(v, (ast.List, ast.Tuple)):
                vals = [self._const(pf, e, at_node) for e in v.elts]
                return None if any(x is None for x in vals) else [x.lower() for x in vals]
        return None

    def _const(self, pf, e, at_node) -> str | None:
        """A string constant, a local name bound to one, or a module-level constant of that name in the repository."""
        s = const_str(e)
        if s is not None:
            return s
        name = e.id if isinstance(e, ast.Name) else (e.attr if isinstance(e, ast.Attribute) else None)
        if name is None:
            return None
        if isinstance(e, ast.Name):
            for v in pf.resolve(name, at_node):
                if const_str(v) is not None:
                    return const_str(v)
        vals = self.constants.get(name, set())
        return next(iter(vals)) if len(vals) == 1 else None

    # ------------------------------------------------------------ queries

    def classify(self, pf: PyFile, expr, at_node, depth=0):
        """(construction, SQL text fragments) for an expression that builds a query."""
        if expr is None or depth > 4:
            return None, []
        s = const_str(expr)
        if s is not None:
            return "parameterized", [s]
        if isinstance(expr, ast.JoinedStr):
            texts = [v.value for v in expr.values if isinstance(v, ast.Constant)]
            return ("interpolated" if any(isinstance(v, ast.FormattedValue) for v in expr.values) else "parameterized"), texts
        if isinstance(expr, ast.BinOp):
            if isinstance(expr.op, ast.Mod) and (const_str(expr.left) is not None or isinstance(expr.left, ast.Name)):
                c, t = self.classify(pf, expr.left, at_node, depth + 1)
                if t:
                    return "interpolated", t
            if isinstance(expr.op, ast.Add):
                lc, lt = self.classify(pf, expr.left, at_node, depth + 1)
                rc, rt = self.classify(pf, expr.right, at_node, depth + 1)
                if lt or rt:
                    if lc in {"parameterized"} and rc in {"parameterized"}:
                        return "parameterized", lt + rt
                    if "interpolated" in {lc, rc} and "concatenated" not in {lc, rc}:
                        return "interpolated" if lc and rc else "concatenated", lt + rt
                    return "concatenated", lt + rt
            return None, []
        if isinstance(expr, ast.Call):
            f = expr.func
            if isinstance(f, ast.Attribute) and f.attr == "format":
                _, t = self.classify(pf, f.value, at_node, depth + 1)
                if t:
                    return "interpolated", t
            if isinstance(f, ast.Attribute) and f.attr == "join":
                return "concatenated", []
            q = pf.qual(f)
            if q.endswith(("sqlalchemy.text", "sqlmodel.text", ".text")) or q == "text":
                return self.classify(pf, expr.args[0] if expr.args else None, at_node, depth + 1)
            if q.endswith(("sql.SQL", "psycopg2.sql.SQL", "psycopg.sql.SQL")):
                return "parameterized", [const_str(expr.args[0]) or ""] if expr.args else []
            head = dotted(f)
            if head and (head[0] in {"select", "insert", "update", "delete"} or "query" in head or "objects" in head):
                return "orm", []
            return None, []
        if isinstance(expr, ast.Name):
            best, texts = None, []
            rank = {"orm": 0, "parameterized": 1, "interpolated": 2, "concatenated": 3}
            for v in pf.resolve(expr.id, at_node):
                c, t = self.classify(pf, v, at_node, depth + 1)
                texts += t
                if c and (best is None or rank[c] > rank[best]):
                    best = c
            return best, texts
        return None, []

    def query(self, pf: PyFile, c: ast.Call, out: Collector, hashed: set[str]):
        parts = dotted(c.func)
        if not parts or not isinstance(c.func, (ast.Attribute, ast.Name)):
            return
        last = parts[-1]
        at = pf.at(c)
        rule = pf.rule(c, "query")
        if rule:
            kws = {k.arg: k.value for k in c.keywords if k.arg}
            untrusted = any(pf.tainted(a, c) for a in list(c.args) + [k.value for k in c.keywords])
            construction = rule.spec.get("construction")
            if "text" in rule.spec:
                construction, _ = self.classify(pf, model_arg(rule.spec["text"], c.args, kws), c)
            if untrusted or (construction is not None and "text" in rule.spec):
                out.element("Query", at, construction=construction, untrusted_input=untrusted)
                out.mark(at, rule)
            return
        q = pf.qual(c.func)
        raw_methods = {"execute", "executemany", "executescript", "mogrify", "exec"}
        is_text = (q.endswith(("sqlalchemy.text", "sqlmodel.text")) or (q == "text" and "sqlalchemy" in pf.imports_text))
        parent = pf.parent.get(c)
        if is_text and isinstance(parent, ast.Call) and dotted(parent.func)[-1:] and dotted(parent.func)[-1] in raw_methods:
            return  # reported at the execute() call
        if last in raw_methods or (last == "raw" and "objects" in parts) or last == "RawSQL" or is_text or (last == "extra" and "objects" in parts):
            if last == "exec" and isinstance(c.func, ast.Name):
                return  # builtin exec, not a query
            sql = c.args[0] if c.args else (kw(c, "sql") or kw(c, "query") or kw(c, "statement") or kw(c, "where"))
            if last == "extra":
                sql = kw(c, "where") or kw(c, "select")
                if isinstance(sql, (ast.List, ast.Tuple)) and sql.elts:
                    sql = sql.elts[0]
            construction, texts = self.classify(pf, sql, c)
            params = c.args[1:] + [k.value for k in c.keywords if k.arg in {"params", "parameters", "args", "parameters_"}]
            if texts and not any(SQL_WORDS.search(t) for t in texts):
                return
            untrusted = pf.tainted(sql, c) or any(pf.tainted(p, c) for p in params)
            if construction is None and not untrusted:
                return
            if construction is None and not (texts or last in {"execute", "executemany", "raw", "executescript"}):
                return
            if construction == "orm" and not untrusted:
                return
            if construction is None and isinstance(sql, ast.Name) and not any(isinstance(x, ast.Name) for x in [sql]):
                return
            out.element("Query", at, construction=construction, untrusted_input=untrusted)
            sqltext = " ".join(texts)
            if re.search(r"\bpassword\b", sqltext, re.I):
                vals = list(params)
                if sql is not None:
                    vals += [v.value for v in ast.walk(sql) if isinstance(v, ast.FormattedValue)]
                    vals += [n for n in ast.walk(sql) if isinstance(n, ast.Name)]
                for v in vals:
                    for e in ([*v.elts] if isinstance(v, (ast.Tuple, ast.List)) else [v]):
                        if self.raw_password(pf, e, hashed):
                            out.element("PasswordStore", at, algorithm="plaintext", salted=False)
                            out.signal("pw_auth", at)
            if re.search(r"\bdelete\s+from\s+\W?(users?|accounts?|customers?|auth_user)\b", sqltext, re.I):
                out.signal("user_delete", at)
            return
        # ORM calls reached by request data
        if last in ORM_METHODS and isinstance(c.func, ast.Attribute):
            recv = c.func.value
            chain_calls = [pf.qual(n.func) for n in ast.walk(recv) if isinstance(n, ast.Call)]
            ormish = "objects" in parts or any(x.split(".")[-1] in {"select", "query"} for x in chain_calls)
            if last == "get" and len(c.args) >= 2 and isinstance(c.args[0], ast.Name) and c.args[0].id[:1].isupper() and parts[-2:-1] and parts[-2] in {"session", "db", "s"}:
                ormish = True
            if ormish:
                args = list(c.args) + [k.value for k in c.keywords]
                if any(pf.tainted(a, c) for a in args):
                    out.element("Query", at, construction="orm", untrusted_input=True)

    # ------------------------------------------------------------ cookies, logs, transfers

    def cookie(self, pf: PyFile, c: ast.Call, out: Collector):
        name = const_str(c.args[0]) if c.args else const_str(kw(c, "key"))
        starlette = "fastapi" in pf.imports_text or "starlette" in pf.imports_text

        def flag(k, default):
            v = kw(c, k)
            if v is None:
                return default
            if isinstance(v, ast.Constant):
                return bool(v.value)
            return None
        same = kw(c, "samesite")
        if same is None:
            ss = "lax" if starlette else "unset"
        elif isinstance(same, ast.Constant):
            ss = "unset" if same.value is None or same.value is False else str(same.value).lower()
            ss = ss if ss in {"strict", "lax", "none"} else None
        else:
            ss = None
        out.element("Cookie", pf.at(c), secure=flag("secure", False), http_only=flag("httponly", False), same_site=ss,
                    is_session=True if name and session_cookie_name(name) else None)

    def model_cookie(self, pf: PyFile, c: ast.Call, rule, out: Collector):
        s = dict(rule.spec)
        name_arg = s.pop("name", None)
        options = s.pop("options", {}) or {}
        kws = {k.arg: k.value for k in c.keywords if k.arg}
        if "is_session" not in s and name_arg is not None:
            name = const_str(model_arg(name_arg, c.args, kws))
            s["is_session"] = True if name and session_cookie_name(name) else None
        for fact, key in options.items():
            v = kws.get(key)
            if v is not None:
                s[fact] = (str(v.value).lower() if v.value else "unset") if fact == "same_site" and isinstance(v, ast.Constant) else (
                    bool(v.value) if isinstance(v, ast.Constant) else None)
        out.element("Cookie", pf.at(c), **s)
        out.mark(pf.at(c), rule)

    def log(self, pf: PyFile, c: ast.Call, out: Collector):
        args = list(c.args) + [k.value for k in c.keywords]
        exprs = []
        for a in args:
            if isinstance(a, ast.JoinedStr):
                exprs += [v.value for v in a.values if isinstance(v, ast.FormattedValue)]
            elif const_str(a) is None:
                exprs.append(a)
        creds = personal = False
        for e in exprs:
            for n, owner in names_in(e):
                if is_credential_name(n) and n not in {"request"}:
                    creds = True
                if is_personal_name(n, owner) or (owner is None and is_user_object_name(n)):
                    personal = True
            if isinstance(e, ast.Attribute) and pf.is_source(e) and e.attr in {"POST", "body", "data", "form", "json"}:
                fn = pf.scope.get(c)
                if fn is not None and self.mentions_password(pf, fn if fn is not pf.tree else c):
                    creds = True
        if creds or personal:
            out.element("LogStatement", pf.at(c), logs_credentials=creds, logs_personal_data=personal)

    def transfer(self, pf: PyFile, c: ast.Call, out: Collector):
        at = pf.at(c)
        rule = pf.rule(c, "transfer")
        if rule:
            s = rule.spec
            personal = s.get("personal_data", "infer")
            if personal == "infer":
                data = [k.value for k in c.keywords] + list(c.args)
                personal = any(is_personal_name(k.arg or "") for k in c.keywords) or any(
                    is_personal_name(n, o) for d in data for n, o in names_in(d)) or None
            out.element("Transfer", at, recipient=s["recipient"], personal_data=personal, third_country=s.get("third_country"))
            out.mark(at, rule)
            return
        q = pf.qual(c.func)
        parts = q.split(".")
        last = parts[-1]
        if parts[0] in {"requests", "httpx", "aiohttp", "urllib3"} and last in {"post", "put", "patch", "request", "get", "urlopen"}:
            url = c.args[1] if last == "request" and len(c.args) > 1 else (c.args[0] if c.args else kw(c, "url"))
            host = self._url_host(pf, url, c)
            data = [kw(c, k) for k in ("data", "json", "params", "files", "content")]
            data = [d for d in data if d is not None]
            if host and (data or last in {"post", "put", "patch"}):
                personal = any(is_personal_name(n, o) or is_user_object_name(n) for d in data for n, o in names_in(d)) or None
                out.element("Transfer", at, recipient=host, personal_data=personal)
            return
        if last in {"sendmail", "send_message"} and "smtplib" in pf.imports_text:
            out.element("Transfer", at, recipient="email (SMTP relay)", personal_data=True)
        elif last == "send" and kw(c, "smtp") is not None and "emails" in pf.imports_text:
            out.element("Transfer", at, recipient="email (SMTP relay)", personal_data=True)
        elif q == "sentry_sdk.init":
            pii = kw(c, "send_default_pii")
            out.element("Transfer", at, recipient="Sentry", personal_data=True if isinstance(pii, ast.Constant) and pii.value is True else None)
        elif q.startswith("boto3.client") and c.args and const_str(c.args[0]) in {"ses", "sesv2", "sns", "pinpoint"}:
            out.element("Transfer", at, recipient=f"AWS {const_str(c.args[0]).upper()}", personal_data=True)

    def _url_host(self, pf, url, at_node):
        if url is None:
            return None
        s = const_str(url)
        if s is None and isinstance(url, ast.JoinedStr) and url.values and isinstance(url.values[0], ast.Constant):
            s = str(url.values[0].value)
        if s is None and isinstance(url, ast.BinOp):
            s = const_str(url.left)
        if s is None and isinstance(url, ast.Name):
            for v in pf.resolve(url.id, at_node):
                s = const_str(v) or (str(v.values[0].value) if isinstance(v, ast.JoinedStr) and v.values and isinstance(v.values[0], ast.Constant) else None)
                if s:
                    break
        return external_host(s) if s else None

    # ------------------------------------------------------------ password policy

    def policy_call(self, pf: PyFile, c: ast.Call, out: Collector):
        q = pf.qual(c.func)
        last = q.split(".")[-1]
        at = pf.at(c)
        rule = pf.rule(c, "password_policy")
        if rule:
            model_policy(rule, at, "server", out)
        if q.startswith("re.") and last in {"match", "fullmatch", "search", "compile"} and c.args:
            pat = const_str(c.args[0])
            target = c.args[1] if len(c.args) > 1 else None
            parent = pf.parent.get(c)
            named = isinstance(parent, ast.Assign) and any(isinstance(t, ast.Name) and is_password_name(t.id.replace("_RE", "").replace("_REGEX", "")) or (isinstance(t, ast.Name) and "pass" in t.id.lower()) for t in parent.targets)
            if pat and ((target is not None and self.mentions_password(pf, target)) or named):
                r = analyse_password_regex(pat)
                if "min" in r:
                    out.signal("pw_min", at, r["min"], side="server")
                if "max" in r:
                    out.signal("pw_max", at, r["max"], side="server")
                if r.get("composition") or re.fullmatch(r"\[[^\]]+\]|\\d|\\W|\[\^[^\]]+\]", pat):
                    out.signal("pw_composition", at)
                out.signal("pw_validation", at, side="server")
        if last == "any" and c.args and isinstance(c.args[0], ast.GeneratorExp):
            g = c.args[0]
            if any(self.mentions_password(pf, gen.iter) for gen in g.generators) and any(
                    isinstance(n, ast.Attribute) and n.attr in {"isupper", "islower", "isdigit", "isalpha", "isnumeric"} for n in ast.walk(g.elt)):
                out.signal("pw_composition", at)
                out.signal("pw_validation", at, side="server")
        if q.endswith("validate_password") and "django" in q:
            out.signal("django_validators_used", at)
        if any(const_str(a) and "pwnedpasswords" in const_str(a) for a in c.args) or q.startswith("zxcvbn"):
            out.signal("pw_blocklist", at)

    def compare(self, pf: PyFile, n: ast.Compare, out: Collector, hashed: set[str]):
        at = pf.at(n)
        left, ops, rights = n.left, n.ops, n.comparators
        if len(ops) != 1:
            return
        op, right = ops[0], rights[0]
        # plaintext comparison with the stored password
        if isinstance(op, (ast.Eq, ast.NotEq)):
            for a, b in ((left, right), (right, left)):
                stored = (isinstance(a, ast.Attribute) and is_stored_password_name(a.attr)) or (
                    isinstance(a, ast.Subscript) and const_str(a.slice) and is_stored_password_name(const_str(a.slice)))
                if stored and self.raw_password(pf, b, hashed) and not (isinstance(b, ast.Attribute) and is_stored_password_name(b.attr)):
                    out.element("PasswordStore", at, algorithm="plaintext", salted=False)
                    out.signal("pw_auth", at)
        # length checks
        for a, b, o in ((left, right, op), (right, left, _flip(op))):
            if isinstance(a, ast.Call) and isinstance(a.func, ast.Name) and a.func.id == "len" and a.args and self.mentions_password(pf, a.args[0]) \
                    and isinstance(b, ast.Constant) and isinstance(b.value, int) and o is not None:
                self._length(pf, n, o, b.value, at, out, "server")
        if isinstance(op, (ast.In, ast.NotIn)) and self.mentions_password(pf, left):
            if any(w in {"common", "blocklist", "blacklist", "banned", "weak", "pwned", "breached", "compromised", "denylist"}
                   for nm, _ in names_in(right) for w in words(nm)):
                out.signal("pw_blocklist", at)

    def _length(self, pf: PyFile, node, op, n, at, out, side):
        sym = {ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">="}.get(type(op))
        if sym is None:
            return
        bound = length_bound(sym, n, _invalid_when(pf, node))
        if bound:
            out.signal("pw_min" if bound[0] == "min" else "pw_max", at, bound[1], side=side)
        out.signal("pw_validation", at, side=side)

    def function(self, pf: PyFile, f, out: Collector):
        name = f.name.lower()
        path = pf.route_path(f)
        login = bool(re.search(r"(^|_)(login|signin|sign_in|log_in|authenticate|access_token)(_|$)", name)) or bool(
            path and re.search(r"login|signin|sign-in|access-token|/token\b|/auth\b", path, re.I))
        handler = pf.is_route(f) or (pf.params(f)[:1] and pf.params(f)[0] in REQUEST_NAMES) or (
            len(pf.params(f)) > 1 and pf.params(f)[0] == "self" and pf.params(f)[1] in REQUEST_NAMES)
        # A login route takes a password: /login/test-token only checks a token it was given.
        takes_password = any(
            (isinstance(n, ast.Name) and is_password_name(n.id)) or (isinstance(n, ast.Attribute) and is_password_name(n.attr))
            or (isinstance(n, ast.arg) and is_password_name(n.arg)) or (const_str(n) is not None and is_password_name(const_str(n)))
            or (isinstance(n, ast.Name) and n.id in {"OAuth2PasswordRequestForm", "AuthenticationForm"})
            or (isinstance(n, ast.Attribute) and n.attr in {"OAuth2PasswordRequestForm", "AuthenticationForm"})
            for n in ast.walk(f))
        if login and handler and takes_password:
            out.signal("login_route", pf.at(f), fn=name)
            out.signal("pw_auth", pf.at(f))
        for d in pf.decorators(f):
            parts = dotted(d)
            rule = self.fm.match("python", pf.callee(d.func if isinstance(d, ast.Call) else d), "rate_limit")
            if rule:
                out.signal("rate_limit", pf.at(d), scope="global" if rule.spec.get("scope") == "global" else ("login" if login else "other"),
                           route_at=pf.at(f))
                out.mark(pf.at(d), rule)
            elif parts and parts[-1] in {"limit", "ratelimit", "throttle", "rate_limit", "limits", "sleep_and_retry"}:
                out.signal("rate_limit", pf.at(d), scope="login" if login else "other", route_at=pf.at(f))

    # ------------------------------------------------------------ settings, models, secrets

    def settings(self, pf: PyFile, out: Collector):
        assigns = {}
        for n in pf.tree.body:
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        assigns[t.id] = n
        if "INSTALLED_APPS" in assigns or "MIDDLEWARE" in assigns:
            mw = assigns.get("MIDDLEWARE")
            site = None
            for holder in (mw, assigns.get("INSTALLED_APPS")):
                if holder is None or not isinstance(holder.value, (ast.List, ast.Tuple)):
                    continue
                for e in holder.value.elts:
                    s = const_str(e) or ""
                    if s.endswith("SessionMiddleware") or s == "django.contrib.sessions":
                        site = site or e
                    if s.split(".")[0] == "axes":
                        out.signal("rate_limit", pf.at(e), scope="global")
                    if s == "allauth.account":
                        # allauth's own forms run the password validators and rate-limit failed logins by default
                        out.signal("django_validators_used", pf.at(e))
                        rl = assigns.get("ACCOUNT_RATE_LIMITS")
                        if not (rl is not None and isinstance(rl.value, ast.Constant) and rl.value.value is False):
                            out.signal("rate_limit", pf.at(e), scope="framework", covers="allauth")
            if site is not None:
                def val(name, default):
                    n = assigns.get(name)
                    if n is None:
                        return default
                    return n.value.value if isinstance(n.value, ast.Constant) else "?"
                sec, ho, ss = val("SESSION_COOKIE_SECURE", False), val("SESSION_COOKIE_HTTPONLY", True), val("SESSION_COOKIE_SAMESITE", "Lax")
                ss = None if ss == "?" else ("unset" if ss in (None, False) else str(ss).lower())
                out.element("Cookie", pf.at(site), is_session=True, secure=None if sec == "?" else bool(sec),
                            http_only=None if ho == "?" else bool(ho), same_site=ss if ss in {"strict", "lax", "none", "unset", None} else None)
            v = assigns.get("AUTH_PASSWORD_VALIDATORS")
            if v is not None and isinstance(v.value, (ast.List, ast.Tuple)):
                for d in v.value.elts:
                    if not isinstance(d, ast.Dict):
                        continue
                    entries = {const_str(k): val for k, val in zip(d.keys, d.values) if k is not None}
                    name = const_str(entries.get("NAME")) or ""
                    if name.endswith("MinimumLengthValidator"):
                        n = 8
                        opts = entries.get("OPTIONS")
                        if isinstance(opts, ast.Dict):
                            for k, val in zip(opts.keys, opts.values):
                                if const_str(k) == "min_length" and isinstance(val, ast.Constant):
                                    n = val.value
                        out.signal("django_pw_min", pf.at(d), n)
                    elif name.endswith("CommonPasswordValidator"):
                        out.signal("django_pw_blocklist", pf.at(d))
                    elif name.endswith("NumericPasswordValidator"):
                        out.signal("django_pw_composition", pf.at(d))  # requires a non-digit character
                    out.signal("django_pw_validation", pf.at(d))
            for name in ("REST_FRAMEWORK",):
                if name in assigns and "THROTTLE" in ast.unparse(assigns[name].value):
                    out.signal("rate_limit", pf.at(assigns[name]), scope="global")
        # Flask session cookie
        flask_app = next((n for n in ast.walk(pf.tree) if isinstance(n, ast.Call) and pf.qual(n.func) == "flask.Flask"), None)
        if flask_app is not None and pf.aliases.get("session") == "flask.session":
            cfg = {}
            for n in ast.walk(pf.tree):
                if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Subscript) and dotted(n.targets[0])[-1:] == ["config"]:
                    k = const_str(n.targets[0].slice)
                    if k:
                        cfg[k] = n.value
                if isinstance(n, ast.Call) and dotted(n.func)[-2:] == ["config", "update"]:
                    for k in n.keywords:
                        cfg[k.arg] = k.value

            def fv(k, default):
                v = cfg.get(k)
                if v is None:
                    return default
                return v.value if isinstance(v, ast.Constant) else "?"
            sec, ho, ss = fv("SESSION_COOKIE_SECURE", False), fv("SESSION_COOKIE_HTTPONLY", True), fv("SESSION_COOKIE_SAMESITE", None)
            ss = None if ss == "?" else ("unset" if ss in (None, False) else str(ss).lower())
            out.element("Cookie", pf.at(flask_app), is_session=True, secure=None if sec == "?" else bool(sec),
                        http_only=None if ho == "?" else bool(ho), same_site=ss)

    def models(self, pf: PyFile, out: Collector):
        for cls in ast.walk(pf.tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            bases = [".".join(dotted(b)) for b in cls.bases]
            table = any(k.arg == "table" for k in cls.keywords)
            # a stored table (its max_length is a column size) vs an input schema (its max_length is a policy)
            is_table = table or any(b in {"models.Model", "db.Model", "Base", "Document", "AbstractUser", "AbstractBaseUser",
                                          "DeclarativeBase"} or b.endswith(("models.Model", "AbstractUser", "AbstractBaseUser")) for b in bases)
            schema = any(b.split(".")[-1].endswith(MODEL_BASES + ("Form", "Serializer", "Schema", "Base")) for b in bases)
            is_model = is_table or schema
            for st in cls.body:
                tname = None
                value = None
                if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name):
                    tname, value = st.target.id, st.value
                    ann = st.annotation
                elif isinstance(st, ast.Assign) and isinstance(st.targets[0], ast.Name):
                    tname, value, ann = st.targets[0].id, st.value, None
                else:
                    continue
                if is_model and (is_personal_name(tname) or tname in {"name", "first_name", "last_name"} and is_user_object_name(cls.name)):
                    out.signal("personal_field", pf.at(st), model=is_table)
                if is_model and is_password_name(tname) and not any(w in {"current", "old"} for w in words(tname)):
                    for call in [x for x in ast.walk(st) if isinstance(x, ast.Call)]:
                        mn = kw(call, "min_length")
                        mx = kw(call, "max_length")
                        if isinstance(mn, ast.Constant) and isinstance(mn.value, int):
                            out.signal("pw_min", pf.at(st), mn.value, side="server")
                            out.signal("pw_validation", pf.at(st), side="server")
                        if isinstance(mx, ast.Constant) and isinstance(mx.value, int) and not is_table:
                            out.signal("pw_max", pf.at(st), mx.value, side="server")
                            out.signal("pw_validation", pf.at(st), side="server")
            if is_model and is_user_object_name(cls.name):
                out.signal("user_model", pf.at(cls))
            if any(b.split(".")[-1] in {"UserCreationForm", "BaseUserCreationForm"} for b in bases) and self.django_project:
                # its save() hashes the password with the configured Django hasher
                out.element("PasswordStore", pf.at(cls), algorithm=self.django_hasher[0], salted=self.django_hasher[1])
                out.signal("pw_auth", pf.at(cls))
                out.signal("pw_set_site", pf.at(cls))
        for n in ast.walk(pf.tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in {"create_user", "create_superuser"} \
                    and "django.contrib.auth" in pf.imports_text:
                out.signal("personal_field", pf.at(n))
            s = const_str(n) if isinstance(n, ast.Constant) else None
            if s and re.search(r"create\s+table", s, re.I) and re.search(r"\b(email|first_?name|last_?name|full_?name|address|phone)\b", s, re.I):
                out.signal("personal_field", f"{pf.sf.rel}:{n.lineno}")

    def secrets(self, pf: PyFile, out: Collector):
        ex = True if pf.sf.example else None
        docstrings = set()
        for n in ast.walk(pf.tree):
            if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant):
                docstrings.add(n.value)
        for n in ast.walk(pf.tree):
            pairs: list[tuple[str, ast.AST]] = []
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    nm = t.id if isinstance(t, ast.Name) else (t.attr if isinstance(t, ast.Attribute) else (const_str(t.slice) if isinstance(t, ast.Subscript) else None))
                    if nm:
                        pairs.append((nm, n.value))
            elif isinstance(n, ast.AnnAssign) and n.value is not None:
                nm = n.target.id if isinstance(n.target, ast.Name) else (n.target.attr if isinstance(n.target, ast.Attribute) else None)
                if nm:
                    pairs.append((nm, n.value))
            elif isinstance(n, ast.Dict):
                for k, v in zip(n.keys, n.values):
                    if k is not None and const_str(k):
                        pairs.append((const_str(k), v))
            elif isinstance(n, ast.Call):
                q = pf.qual(n.func)
                last = q.split(".")[-1]
                for k in n.keywords:
                    if k.arg:
                        pairs.append((k.arg, k.value))
                if (q.endswith(("environ.get", "getenv", "environ.setdefault")) or last in {"config", "env", "get_env"}) and n.args:
                    envname = const_str(n.args[0])
                    default = n.args[1] if len(n.args) > 1 else kw(n, "default")
                    if envname and default is not None:
                        pairs.append((envname, default))
                if q in {"jwt.encode", "jose.jwt.encode", "jwt.decode", "jose.jwt.decode"} and len(n.args) > 1:
                    pairs.append(("signing_key", n.args[1]))
                if q == "hmac.new" and n.args:
                    pairs.append(("hmac_key", n.args[0]))
            for name, v in pairs:
                s = const_str(v)
                if s is None:
                    continue
                kind = literal_secret_kind(s) or secret_kind_for_name(name)
                if kind and plausible_secret_value(s, kind):
                    out.element("Secret", f"{pf.sf.rel}:{v.lineno}", kind=kind, test_or_example=ex)
        for n in ast.walk(pf.tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and n not in docstrings:
                kind = literal_secret_kind(n.value)
                if kind:
                    line = n.lineno
                    if kind == "private_key":
                        line = n.lineno
                    out.element("Secret", f"{pf.sf.rel}:{line}", kind=kind, test_or_example=ex)


def _alg_risk(algs: list[str]) -> bool:
    """`none` is accepted, or an HMAC algorithm sits next to public-key ones (algorithm confusion)."""
    fam = {a[:2] for a in algs}
    return "none" in algs or bool("hs" in fam and fam & {"rs", "es", "ps"})


def _flip(op):
    return {ast.Lt: ast.Gt(), ast.Gt: ast.Lt(), ast.LtE: ast.GtE(), ast.GtE: ast.LtE()}.get(type(op))
