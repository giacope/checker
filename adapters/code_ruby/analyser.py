"""Ruby and Rails analysis: vocabulary elements and subject signals from parsed Ruby (application code, configuration,
and the Ruby embedded in templates)."""

from __future__ import annotations

import re

from tree_sitter import Node

from adapters.code_static.common import (CRED_WORDS, ERASURE_REQUEST, LOCKOUT, Collector, analyse_password_regex, external_host,
                                         is_credential_name, is_password_name, is_personal_name, is_stored_password_name,
                                         is_user_object_name, literal_secret_kind, model_policy, plausible_secret_value,
                                         secret_kind_for_name, session_cookie_name, words)
from adapters.code_static.models import Models, arg as model_arg

from .project import Project
from .rb import (RbFile, Taint, args, bool_value, field, hash_pairs, int_value, is_literal, line, method_name, parts,
                 sym_or_str, text, walk)

LOG_METHODS = {"debug", "info", "warn", "error", "fatal", "unknown", "log", "add"}
CONSOLE = {"puts", "p", "pp", "print", "printf"}
SQL_RAW = {"execute", "exec_query", "exec_update", "exec_delete", "exec_insert", "select_all", "select_one", "select_value",
           "select_values", "select_rows", "find_by_sql", "count_by_sql", "exec_params", "async_exec"}
SQL_FRAGMENT = {"where", "rewhere", "having", "order", "reorder", "group", "select", "reselect", "pluck", "joins", "from",
                "lock", "not", "update_all", "delete_all", "exists?", "calculate", "minimum", "maximum", "sum", "average",
                "find_by", "find_by!", "in_order_of", "distinct"}
AR_ONLY = {"where", "rewhere", "having", "joins", "reorder", "order"}  # no Hash or Array method of these names
ORDER_LIKE = {"order", "reorder", "pluck", "in_order_of"}  # raw SQL refused for non-attribute arguments since Rails 6.0
ORM_ANY_RECEIVER = {"where", "rewhere", "find_by", "find_by!", "pluck", "order", "reorder", "not", "exists?",
                    "find_or_create_by", "find_or_create_by!", "find_or_initialize_by", "destroy_by", "delete_by"}
ORM_MODEL_RECEIVER = {"find", "create", "create!", "update", "update!", "update_all", "insert", "insert_all", "upsert",
                      "upsert_all", "first_or_create", "first_or_create!", "update_attribute", "update_column", "update_columns"}
WRITE_METHODS = {"new", "create", "create!", "update", "update!", "update_attributes", "update_attributes!", "assign_attributes",
                 "attributes=", "build", "first_or_create", "first_or_create!", "first_or_initialize", "find_or_create_by",
                 "find_or_create_by!", "find_or_initialize_by", "create_with", "insert", "upsert"}
PRIVILEGED = re.compile(r"^(is_)?(admin|administrator|superuser|super_admin|staff|moderator|root|owner)$|^roles?(_ids?)?$|"
                        r"^(user|account|owner|creator|author|organization|org|tenant|company|team)_ids?$|"
                        r"^(balance|credits?|karma|permissions?|privileges?|access_level|is_moderator|is_staff)$")
ESCAPING = {"sanitize", "strip_tags", "h", "html_escape", "escape_once", "html_escape_once", "escapeHTML", "escape_html",
            "json_escape", "escape_javascript", "j", "scrub!", "scrub", "fragment", "sanitize_css"}
SAFE_HELPERS = {"link_to", "content_tag", "tag", "button_to", "mail_to", "image_tag", "javascript_include_tag", "render",
                "stylesheet_link_tag", "t", "translate", "l", "localize", "time_ago_in_words", "distance_of_time_in_words",
                "number_to_currency", "number_with_delimiter", "number_to_human", "number_to_percentage", "pluralize",
                "simple_format", "truncate", "label_tag", "text_field_tag", "hidden_field_tag", "submit_tag", "check_box_tag",
                "select_tag", "options_for_select", "csrf_meta_tags", "javascript_tag", "safe_join", "auto_discovery_link_tag",
                "favicon_link_tag", "time_tag", "url_for", "asset_path", "image_path", "strftime", "iso8601", "to_fs",
                "to_formatted_s", "csp_meta_tag", "form_with", "form_for"}
PASSTHROUGH = {"to_s", "inspect", "strip", "squish", "upcase", "downcase", "capitalize", "titleize", "presence", "html_safe",
               "to_str", "freeze", "dup", "chomp", "lstrip", "rstrip", "humanize", "to_json", "as_json"}
SCRIPT_PREFIXES = ("db/", "script/", "bin/", "lib/tasks/", "Rakefile")
DEV_FILE = re.compile(r"(^|[._\-/])(fake|seeds?|samples?|demo|dummy|dev|development|test|tests|testing|fixtures?|examples?)([._\-/]|$)", re.I)
HASH_METHODS = {"hexdigest", "digest", "base64digest", "hexdigest!", "new", "update", "file"}
DIGESTS = {"MD5": "md5", "SHA1": "sha1", "SHA2": "sha256", "SHA256": "sha256", "SHA224": "sha256", "SHA384": "sha512",
           "SHA512": "sha512", "RMD160": "other"}
MAILER_RECIPIENTS = {"smtp": "email (SMTP relay)", "sendmail": "email (sendmail)", "postmark": "Postmark", "mailgun": "Mailgun",
                     "ses": "AWS SES", "ses_v2": "AWS SES", "sendgrid": "SendGrid", "sendgrid_actionmailer": "SendGrid",
                     "mailjet": "Mailjet", "sparkpost": "SparkPost", "resend": "Resend", "mandrill": "Mailchimp Transactional",
                     "brevo": "Brevo", "sendinblue": "Brevo", "mailersend": "MailerSend"}
HTTP_CLIENTS = {"HTTParty", "Faraday", "RestClient", "Excon", "HTTP", "Typhoeus", "HTTPX"}
HTTP_SEND = {"post", "put", "patch", "post_form", "request", "run", "start"}


def _str_parts(n: Node | None, f: RbFile) -> list[Node] | None:
    """Children of a string or heredoc: content and interpolations."""
    if n is None:
        return None
    if n.type == "heredoc_beginning":
        b = f.heredoc_body(n)
        return list(b.named_children) if b is not None else None
    if n.type in {"string", "subshell", "delimited_symbol"}:
        return list(n.named_children)
    return None


def _literal_text(n: Node | None, f: RbFile) -> str | None:
    ps = _str_parts(n, f)
    if ps is None:
        return sym_or_str(n)
    if any(p.type == "interpolation" for p in ps):
        return None
    return "".join(text(p) for p in ps if p.type in {"string_content", "heredoc_content", "escape_sequence"})


def _texts(n: Node | None, f: RbFile) -> list[str]:
    ps = _str_parts(n, f) or []
    return [text(p) for p in ps if p.type in {"string_content", "heredoc_content"}]


def _combine(vals: list[bool | None]) -> bool | None:
    if any(v is True for v in vals):
        return True
    if vals and all(v is False for v in vals):
        return False
    return None


def _model_name_of(recv_name: str) -> str:
    """`current_user` -> User, `@story` -> Story, `mod_note` -> ModNote."""
    n = recv_name.lstrip("@")
    n = re.sub(r"^(current|new|old|the|found|reset|showing)_", "", n)
    return "".join(w.capitalize() for w in n.split("_") if w)


class Analyser:
    def __init__(self, project: Project, files: list[RbFile], fm: Models, taint: Taint):
        self.p, self.files, self.fm, self.taint = project, files, fm, taint
        self.classes: dict[str, tuple[RbFile, Node, str]] = {}   # class name -> (file, node, superclass)
        self.models: set[str] = set()
        self.writable: set[str] = set()       # attributes a request can write
        self.safe_format: set[str] = set()    # attributes whose format validation admits no markup
        self.attr_accessible: dict[str, list[str]] = {}
        self.defs: dict[str, list[tuple[RbFile, Node]]] = {}
        self.constants: dict[str, set[str]] = {}
        self.permit_all = False
        self.param_names: set[str] = set()  # request parameter names the application reads

    # ================================================================ preparation

    def rel(self, f: RbFile) -> str:
        r = f.sf.rel
        return r[len(self.p.prefix):] if self.p.prefix and r.startswith(self.p.prefix) else r

    def prepare(self):
        for f in self.files:
            for m in f.methods:
                self.defs.setdefault(f.method_def_name(m), []).append((f, m))
            for n in walk(f.root):
                if n.type == "class":
                    name = text(field(n, "name"))
                    sup = field(n, "superclass")
                    sup_t = text(sup.named_children[0]) if sup is not None and sup.named_children else ""
                    self.classes.setdefault(name.split("::")[-1], (f, n, sup_t))
                elif n.type == "assignment" and field(n, "left") is not None and field(n, "left").type == "constant":
                    s = _literal_text(field(n, "right"), f)
                    if s is not None:
                        self.constants.setdefault(text(field(n, "left")), set()).add(s)
        changed = True
        while changed:
            changed = False
            for name, (f, _, sup) in self.classes.items():
                base = sup.split("::")[-1]
                if name not in self.models and (sup in {"ApplicationRecord", "ActiveRecord::Base", "Base"} and self.rel(f).startswith("app/models/")
                                                or base in self.models):
                    self.models.add(name)
                    changed = True
        s = self.p.setting("action_controller.permit_all_parameters")
        self.permit_all = s is not None and bool_value(s.value) is True
        for f in self.files:
            for n in walk(f.root):
                if n.type == "element_reference" and parts(n)[:1] == ["params"]:
                    self.param_names |= {sym_or_str(k) for k in n.named_children[1:] if sym_or_str(k)}
                if n.type == "call":
                    m = method_name(n)
                    if m == "permit" and "params" in parts(n):
                        self.writable |= set(self._permit_fields(n))
                        self.param_names |= set(self._permit_fields(n))
                    elif m in WRITE_METHODS:
                        pos, kws = args(n)
                        for k, v in kws.items():
                            if f.tainted(v, self.taint):
                                self.writable.add(k)
                        src = self.mass_source(f, pos[0]) if pos and pos[0].type != "hash" else None
                        if src is not None and src[0] is False:
                            table = self.table_of(f, n)
                            if table:
                                self.writable |= set(self.p.tables.get(table, {}))
                    elif m in {"validates", "validates_format_of"} and field(n, "receiver") is None:
                        self._format_validation(n)
                    elif m in {"attr_accessible"} and field(n, "receiver") is None:
                        cls = f.class_of(n)
                        if cls is not None:
                            pos, _ = args(n)
                            self.attr_accessible[text(field(cls, "name")).split("::")[-1]] = [sym_or_str(a) or "" for a in pos]
                elif n.type == "assignment":
                    left = field(n, "left")
                    if left is not None and left.type == "call" and f.tainted(field(n, "right"), self.taint):
                        self.writable.add(method_name(left).rstrip("="))

    def _permit_fields(self, call: Node) -> list[str]:
        out = []
        al = field(call, "arguments")
        for a in (al.named_children if al is not None else []):
            if a.type == "pair":
                k = sym_or_str(field(a, "key")) or text(field(a, "key"))
                out.append(k)
            elif a.type == "hash":
                out += [k for k in hash_pairs(a)]
            elif sym_or_str(a) is not None:
                out.append(sym_or_str(a))
            elif a.type == "array":
                out += [sym_or_str(x) for x in a.named_children if sym_or_str(x)]
        return out

    def _format_validation(self, n: Node):
        pos, kws = args(n)
        fields_ = [sym_or_str(a) for a in pos if sym_or_str(a)]
        fmt = kws.get("format")
        regex = None
        if fmt is not None and fmt.type == "hash":
            regex = hash_pairs(fmt).get("with")
        elif method_name(n) == "validates_format_of":
            regex = kws.get("with")
        if regex is not None and regex.type == "regex" and _markup_free(text(regex)):
            self.safe_format |= set(fields_)

    # ================================================================ helpers

    def table_of(self, f: RbFile, call: Node) -> str | None:
        recv = field(call, "receiver")
        ps = parts(recv) if recv is not None else []
        for p in ps:
            if p[:1].isupper():
                t = self.p.table_for(p)
                if t:
                    return t
        if ps:
            last = ps[-1]
            if last.startswith("@") or last[:1].islower():
                return self.p.table_for(_model_name_of(last))
        if recv is None:
            cls = f.class_of(call)
            if cls is not None:
                return self.p.table_for(text(field(cls, "name")))
        return None

    def model_receiver(self, f: RbFile, recv: Node | None) -> bool:
        if recv is None:
            return self.rel(f).startswith("app/models/")
        ps = parts(recv)
        if not ps or ps[0] in {"params", "request", "cookies", "session", "ENV", "Hash", "Array", "File", "Dir", "JSON", "YAML",
                               "Set", "Struct", "OpenStruct", "Time", "Date", "DateTime", "Rails", "URI", "CGI"}:
            return False
        for p in ps:
            if p in self.models or (p[:1].isupper() and self.p.table_for(p)):
                return True
        last = ps[-1].lstrip("@")
        return bool(last) and (last == "current_user" or _model_name_of(last) in self.models or bool(self.p.table_for(_model_name_of(last))))

    def hashing_model(self, table: str | None) -> bool:
        """The model of this table hashes passwords itself (has_secure_password, Devise)."""
        for name, (f, cls, _) in self.classes.items():
            if name in self.models and (table is None or self.p.table_for(name) == table):
                if re.search(r"^\s*(has_secure_password|devise\b)", text(cls), re.M):
                    return True
        return False

    def mentions_password(self, n: Node | None) -> bool:
        if n is None:
            return False
        for x in walk(n):
            if x.type in {"identifier", "instance_variable"} and is_password_name(text(x).lstrip("@")):
                return True
            if x.type == "call" and is_password_name(method_name(x)):
                return True
            if x.type in {"simple_symbol", "string"} and x.parent is not None and x.parent.type == "element_reference" \
                    and is_password_name(sym_or_str(x) or ""):
                return True
        return False

    def raw_password(self, f: RbFile, n: Node | None, hashed: set[str]) -> bool:
        """A cleartext password: request data named as one, or a local/attribute named as one that was not hashed."""
        if n is None:
            return False
        if any(x.type == "call" and self.hash_primitive(f, x) for x in walk(n)):
            return False
        t = n.type
        if t == "call" and method_name(n) in {"to_s", "strip", "to_str"}:
            return self.raw_password(f, field(n, "receiver"), hashed)
        if t in {"identifier", "instance_variable"}:
            return is_password_name(text(n).lstrip("@")) and text(n) not in hashed
        if t == "element_reference":
            keys = [sym_or_str(c) for c in n.named_children[1:]]
            return any(k and is_password_name(k) for k in keys) and f.tainted(n, self.taint)
        if t == "call" and field(n, "receiver") is not None and not field(n, "arguments"):
            return is_password_name(method_name(n)) and parts(n)[:1] != ["self"]
        return False

    def hashed_names(self, f: RbFile) -> set[str]:
        out = set()
        for names in f.bindings.values():
            for name, vals in names.items():
                if any(x.type == "call" and self.hash_primitive(f, x) for v in vals for x in walk(v)):
                    out.add(name)
        return out

    def rule(self, call: Node, kind: str):
        segs = parts(call)
        if not segs:
            return None
        return self.fm.match("ruby", (segs, segs[0][:1].isupper()), kind)

    def const_value(self, f: RbFile, n: Node | None) -> str | None:
        """A string literal, a local bound to one, or a repository constant with one value."""
        if n is None:
            return None
        s = _literal_text(n, f)
        if s is not None:
            return s
        if n.type == "identifier":
            for v in f.resolve(text(n), n):
                s = _literal_text(v, f)
                if s is not None:
                    return s
        if n.type in {"constant", "scope_resolution"}:
            name = text(n).split("::")[-1]
            vals = self.constants.get(name, set())
            return next(iter(vals)) if len(vals) == 1 else None
        return None

    # ================================================================ run

    def run(self, out: Collector):
        for f in self.files:
            self.secrets(f, out)
            if f.sf.example:
                continue
            hashed = self.hashed_names(f)
            rel = self.rel(f)
            for n in walk(f.root):
                t = n.type
                if t == "call":
                    self.call(f, n, out, hashed, rel)
                elif t == "identifier":
                    p = n.parent
                    if p is not None and p.type in {"body_statement", "program", "class", "then", "else", "block_body", "begin"}:
                        self.macro(f, n, text(n), [], {}, out, rel)
                    nm = text(n)
                    if rel.startswith("app/") and LOCKOUT.search("_".join(words(nm))):
                        out.signal("lockout", f.at(n))
                    if rel.startswith("app/controllers/") and ERASURE_REQUEST.search("_".join(words(nm))):
                        out.signal("erasure_request", f.at(n))
                elif t == "subshell":
                    self.command(f, n, [n], out, shell=True)
                elif t == "binary":
                    self.compare(f, n, out, hashed)
                elif t == "assignment":
                    self.assignment(f, n, out, rel)
                elif t == "class":
                    self.class_signals(f, n, out, rel)
            if rel.startswith("app/controllers/"):
                self.controller_methods(f, out)
            if getattr(f, "unescaped", None):
                for start, end in f.unescaped:
                    self.unescaped_tag(f, start, end, out)

    # ------------------------------------------------------------------ calls

    def call(self, f: RbFile, c: Node, out: Collector, hashed: set[str], rel: str):
        m = method_name(c)
        recv = field(c, "receiver")
        ps = parts(c)
        pos, kws = args(c)
        at = f.at(c)
        if recv is None:
            self.macro(f, c, m, pos, kws, out, rel)
        # ---- PasswordStore
        prim = self.hash_primitive(f, c)
        if prim is not None:
            alg, salted, pw = prim
            if self.mentions_password(pw) or (alg in {"bcrypt", "scrypt", "argon2"} and pw is not None):
                out.element("PasswordStore", at, algorithm=alg, salted=salted)
                out.signal("pw_auth", at)
                out.mark(at, self.rule(c, "password_hash"))
        if (m in {"where", "find_by", "find_by!", "exists?", "find_or_create_by", "create", "create!", "new"}
                or re.match(r"find_by_\w*password", m)) and self.model_receiver(f, recv):
            pw_vals = [(k, v) for k, v in kws.items() if is_stored_password_name(k) or is_password_name(k)]
            if re.match(r"find_by_\w*password", m):
                names = m[len("find_by_"):].split("_and_")
                pw_vals += [(nm, a) for nm, a in zip(names, pos) if is_password_name(nm) or is_stored_password_name(nm)]
            table = self.table_of(f, c)
            cols = self.p.tables.get(table, {}) if table else {}
            # `create(password: pw)` on a has_secure_password or Devise model goes through the hashing setter:
            # only a column of that name stores (or is compared with) the cleartext
            stored = [(k, v) for k, v in pw_vals if k in cols or (not cols and m not in {"create", "create!", "new"}
                                                                   and not self.hashing_model(table))]
            if any(self.raw_password(f, v, hashed) for _, v in stored):
                out.element("PasswordStore", at, algorithm="plaintext", salted=False)
                out.signal("pw_auth", at)
                if m in {"create", "create!", "new"} and any(f.tainted(v, self.taint) for _, v in stored):
                    out.signal("pw_set_site", at)
        if m in {"authenticate", "authenticate_by", "valid_password?"} and (pos or kws):
            out.signal("pw_auth", at)
        # ---- the rest
        self.query(f, c, m, recv, ps, pos, kws, out, hashed)
        self.token(f, c, m, ps, pos, kws, out)
        self.cookie_call(f, c, m, recv, pos, kws, out)
        self.log(f, c, m, recv, ps, pos, kws, out, rel)
        self.transfer(f, c, m, recv, ps, pos, kws, out)
        if (recv is None and m in {"system", "exec", "spawn"}) or ps in (["Kernel", "system"], ["Kernel", "exec"], ["Kernel", "spawn"],
                                                                          ["Process", "spawn"], ["PTY", "spawn"]) \
                or (ps[:1] == ["Open3"] and len(ps) == 2) or ps == ["IO", "popen"]:
            self.command(f, c, pos, out, shell=False, kws=kws)
        elif (recv is None or ps == ["Kernel", "open"]) and m == "open" and pos and (_texts(pos[0], f) or [""])[0].startswith("|"):
            self.command(f, c, [pos[0]], out, shell=True)
        self.html(f, c, m, recv, pos, out)
        self.deserialization(f, c, m, ps, pos, kws, out)
        if m in WRITE_METHODS and pos and pos[0].type != "hash" and self.model_receiver(f, recv):
            self.mass_assignment(f, c, pos[0], out)
        if re.fullmatch(r"(destroy|delete|really_destroy|anonymi[sz]e|wipe|erase|purge)(!|_account!?|_user!?|_all)?", m) \
                and rel.startswith("app/controllers/"):
            rp = parts(recv) if recv is not None else []
            if rp and (is_user_object_name(rp[-1].lstrip("@")) or rp[0] in {"User", "Account"}):
                out.signal("user_delete", at)
        rule = self.rule(c, "erasure")
        if rule and rel.startswith("app/"):
            out.signal("user_delete", at)
            out.mark(at, rule)
        rule = self.rule(c, "password_policy")
        if rule:
            model_policy(rule, at, "server", out)
        rule = self.rule(c, "rate_limit")
        if rule:
            out.signal("rate_limit", at, scope="global")
            out.mark(at, rule)
        if m in {"throttle", "blocklist", "track"} and (ps[:2] == ["Rack", "Attack"] or (recv is None and "Rack::Attack" in f.src)):
            self.rack_attack(f, c, m, out)

    # ------------------------------------------------------------------ class-body macros

    def macro(self, f: RbFile, n: Node, m: str, pos: list[Node], kws: dict, out: Collector, rel: str):
        at = f.at(n)
        if m == "has_secure_password":
            out.element("PasswordStore", at, algorithm="bcrypt", salted=True)
            out.signal("pw_auth", at)
            out.signal("pw_set_site", at)
            v = kws.get("validations")
            if not (v is not None and bool_value(v) is False):
                out.signal("pw_max", at, 72, side="server")  # ActiveModel::SecurePassword validates at most 72 (bytes since 7.1)
                out.signal("pw_validation", at, side="server")
            out.signal("user_model", at)
        elif m == "devise" and rel.startswith("app/models/"):
            self.devise(f, n, pos, out)
        elif m in {"validates", "validates_length_of", "validates_format_of"}:
            self.validation(f, n, m, pos, kws, out)
        elif m == "attr_accessible" and pos:
            fields_ = [sym_or_str(a) or "" for a in pos]
            out.element("MassAssignment", at, allowlist=True, privileged_assignable=any(PRIVILEGED.match(x) for x in fields_))
        elif m == "attr_protected" and pos:
            out.element("MassAssignment", at, allowlist=False)
        elif m in {"protect_from_forgery", "skip_forgery_protection"} or (
                m == "skip_before_action" and any(sym_or_str(a) == "verify_authenticity_token" for a in pos)):
            with_ = sym_or_str(kws.get("with")) if kws.get("with") is not None else None
            out.signal("rb_csrf", at, m != "protect_from_forgery", with_=with_, cls=self._class_name(f, n), rel=rel)
        elif m == "rate_limit" and "to" in kws and rel.startswith("app/controllers/"):
            only = kws.get("only")
            names = None
            if only is not None:
                names = {sym_or_str(x) for x in (only.named_children if only.type == "array" else [only])}
            cls = f.class_of(n) or n
            for mm in f.methods:
                if f.klass.get(mm.id) is not None and f.klass.get(mm.id).id == cls.id and (names is None or f.method_def_name(mm) in names):
                    out.signal("rate_limit", at, scope="login", route_at=f.at(mm))
        elif m == "devise_for" and rel == "config/routes.rb":
            skip = kws.get("skip")
            out.signal("rb_devise_routes", at, skip=text(skip) if skip is not None else "")
        elif m == "mail" and ("to" in kws or "bcc" in kws or "cc" in kws) and self._is_mailer(f, n):
            out.element("Transfer", at, recipient=self.mail_recipient(), personal_data=True)

    def _class_name(self, f: RbFile, n: Node) -> str:
        c = f.class_of(n)
        return text(field(c, "name")) if c is not None else ""

    def _is_mailer(self, f: RbFile, n: Node) -> bool:
        cls = f.class_of(n)
        while cls is not None:
            name = text(field(cls, "name")).split("::")[-1]
            sup = self.classes.get(name, (None, None, ""))[2]
            if sup in {"ActionMailer::Base", "ApplicationMailer"} or name.endswith("Mailer"):
                return True
            nxt = self.classes.get(sup.split("::")[-1])
            cls = nxt[1] if nxt and nxt[1].id != cls.id else None
        return False

    def mail_recipient(self) -> str:
        s = self.p.setting("action_mailer.delivery_method")
        method = sym_or_str(s.value) if s is not None else None
        if method == "smtp" or method is None:
            st = self.p.setting("action_mailer.smtp_settings")
            addr = None
            if st is not None and st.value.type == "hash":
                addr = _literal_text(hash_pairs(st.value).get("address"), st.file)
            if addr and external_host(f"https://{addr}"):
                return f"email (SMTP relay {addr})"
            return "email (SMTP relay)"
        return MAILER_RECIPIENTS.get(method, f"email ({method})")

    def devise(self, f: RbFile, n: Node, pos: list[Node], out: Collector):
        at = f.at(n)
        mods = {sym_or_str(a) for a in pos}
        out.signal("user_model", at)
        if "database_authenticatable" in mods:
            out.element("PasswordStore", at, algorithm="bcrypt", salted=True)  # Devise::Encryptor: BCrypt with config.stretches
            out.signal("pw_auth", at)
            out.signal("login_route", at, fw="devise")
            if "registerable" in mods or "recoverable" in mods:
                out.signal("pw_set_site", at)
        if "validatable" in mods:
            lo, hi = 6, 128  # Devise's default config.password_length
            s = self.p.setting("password_length", "all")
            if s is not None and s.value.type == "range" and len(s.value.named_children) == 2:
                a, b = (int_value(x) for x in s.value.named_children)
                lo, hi = (a if a is not None else lo), (b if b is not None else hi)
                at_cfg = s.at
            else:
                at_cfg = at
            out.signal("pw_min", at_cfg, lo, side="server")
            out.signal("pw_max", at_cfg, hi, side="server")
            out.signal("pw_validation", at_cfg, side="server")
        if "lockable" in mods:
            out.signal("lockout", at)
        if "pwned_password" in mods:
            out.signal("pw_blocklist", at)
            out.signal("pw_validation", at, side="server")
        if "password_expirable" in mods:
            out.signal("pw_expiry", at)
        if "registerable" in mods:
            out.signal("rb_devise_registerable", at)

    def validation(self, f: RbFile, n: Node, m: str, pos: list[Node], kws: dict, out: Collector):
        names = [sym_or_str(a) for a in pos if sym_or_str(a)]
        if not any(is_password_name(x) for x in names):
            return
        at = f.at(n)
        length = kws.get("length") if m == "validates" else n
        opts = hash_pairs(length) if length is not None and length.type == "hash" else (kws if m == "validates_length_of" else {})
        for k, v in opts.items():
            if k in {"within", "in"} and v.type == "range" and len(v.named_children) == 2:
                lo, hi = (int_value(x) for x in v.named_children)
                if lo is not None:
                    out.signal("pw_min", at, lo, side="server")
                if hi is not None:
                    out.signal("pw_max", at, hi - (1 if "..." in text(v) else 0), side="server")
            elif k in {"minimum", "is"} and int_value(v) is not None:
                out.signal("pw_min", at, int_value(v), side="server")
            elif k in {"maximum"} and int_value(v) is not None:
                out.signal("pw_max", at, int_value(v), side="server")
        fmt = kws.get("format") if m == "validates" else kws.get("with")
        regex = hash_pairs(fmt).get("with") if fmt is not None and fmt.type == "hash" else fmt
        if regex is not None and regex.type == "regex":
            body = text(regex).strip("/")
            r = analyse_password_regex(body)
            if r.get("composition"):
                out.signal("pw_composition", at)
            if "min" in r:
                out.signal("pw_min", at, r["min"], side="server")
        if kws.get("not_pwned") is not None or kws.get("pwned") is not None or kws.get("unpwned") is not None:
            out.signal("pw_blocklist", at)
        out.signal("pw_validation", at, side="server")

    # ------------------------------------------------------------------ password hashing primitives

    def hash_primitive(self, f: RbFile, c: Node):
        """(algorithm, salted, password expression) for a call that hashes or encodes its input."""
        if c.type != "call":
            return None
        rule = self.rule(c, "password_hash")
        pos, kws = args(c)
        if rule:
            s = rule.spec
            pw = model_arg(s.get("password", 0), pos, kws)
            salted = s["salted"] if s["salted"] != "infer" else self._salted(pw)
            return s["algorithm"], salted, pw
        ps = parts(c)
        m = method_name(c)
        first = pos[0] if pos else None
        if len(ps) >= 3 and ps[0] == "Digest" and ps[1] in DIGESTS and m in HASH_METHODS:
            return DIGESTS[ps[1]], self._salted(first), first
        if ps[:2] == ["OpenSSL", "Digest"] and len(ps) >= 4 and ps[2] in DIGESTS and m in HASH_METHODS:
            return DIGESTS[ps[2]], self._salted(first), first
        if ps[:3] == ["OpenSSL", "Digest", "digest"] or ps[:3] == ["OpenSSL", "Digest", "hexdigest"]:
            alg = (sym_or_str(first) or "").upper().replace("-", "")
            return DIGESTS.get(alg, "other"), self._salted(pos[1] if len(pos) > 1 else None), pos[1] if len(pos) > 1 else None
        if ps[:2] == ["BCrypt", "Password"] and m in {"create", "new"}:
            return "bcrypt", True, first
        if ps[:2] == ["BCrypt", "Engine"] and m == "hash_secret":
            return "bcrypt", True, first
        if ps[:2] == ["SCrypt", "Password"] and m == "create" or ps[:2] == ["OpenSSL", "KDF"] and m == "scrypt":
            return "scrypt", True if ps[0] == "SCrypt" else ("salt" in kws and not is_literal(kws["salt"])), first
        if ps[:2] == ["Argon2", "Password"] and m in {"create", "verify_password"}:
            return "argon2", True, first
        if (ps[:2] == ["OpenSSL", "PKCS5"] and m in {"pbkdf2_hmac", "pbkdf2_hmac_sha1"}) or (ps[:2] == ["OpenSSL", "KDF"] and m == "pbkdf2_hmac"):
            salt = pos[1] if len(pos) > 1 else kws.get("salt")
            return "pbkdf2", salt is not None and not is_literal(salt), first
        if ps[:1] == ["Base64"] and m in {"encode64", "strict_encode64", "urlsafe_encode64"}:
            return "reversible", False, first
        return None

    def _salted(self, n: Node | None) -> bool:
        if n is None:
            return False
        return any(x.type in {"identifier", "instance_variable", "constant"} and "salt" in words(text(x)) or
                   (x.type == "call" and "salt" in words(method_name(x))) for x in walk(n))

    # ------------------------------------------------------------------ queries

    def classify_sql(self, f: RbFile, n: Node | None, depth: int = 0):
        """(construction, SQL text fragments)."""
        if n is None or depth > 5:
            return None, []
        t = n.type
        ps = _str_parts(n, f)
        if ps is not None:
            texts = [text(p) for p in ps if p.type in {"string_content", "heredoc_content"}]
            return ("interpolated" if any(p.type == "interpolation" for p in ps) else "parameterized"), texts
        if t in {"simple_symbol", "hash", "pair"}:
            return "orm", []
        if t == "array":
            first = n.named_children[0] if n.named_children else None
            if first is not None and _str_parts(first, f) is not None:
                c, tx = self.classify_sql(f, first, depth + 1)
                return ("parameterized" if c == "parameterized" else c), tx
            return "orm", []
        if t == "binary":
            op = text(field(n, "operator"))
            if op in {"+", "<<"}:
                lc, lt = self.classify_sql(f, field(n, "left"), depth + 1)
                rc, rt = self.classify_sql(f, field(n, "right"), depth + 1)
                if lc == rc == "parameterized":
                    return "parameterized", lt + rt
                if lt or rt:
                    return "concatenated", lt + rt
                return None, []
            if op == "%":
                lc, lt = self.classify_sql(f, field(n, "left"), depth + 1)
                return ("interpolated", lt) if lt else (None, [])
            return None, []
        if t == "call":
            m = method_name(n)
            recv = field(n, "receiver")
            if m in {"squish", "strip", "freeze", "to_s", "dup", "gsub", "tr"} and recv is not None:
                return self.classify_sql(f, recv, depth + 1)
            if m == "join":
                return "concatenated", []
            if m in {"format", "sprintf"} and recv is None:
                pos, _ = args(n)
                _, tx = self.classify_sql(f, pos[0] if pos else None, depth + 1)
                return "interpolated", tx
            if m == "sql" and parts(n)[:1] == ["Arel"]:
                pos, _ = args(n)
                return self.classify_sql(f, pos[0] if pos else None, depth + 1)
            if m.startswith("sanitize_sql") or m in {"quote", "quote_string"}:
                return "parameterized", []
            if parts(n)[:1] == ["Arel"] or {"arel_table", "arel"} & set(parts(n)) or m in {"arel_table", "arel"}:
                return "orm", []
            return None, []
        if t in {"identifier", "instance_variable"}:
            best, texts = None, []
            rank = {"orm": 0, "parameterized": 1, "interpolated": 2, "concatenated": 3}
            for v in f.resolve(text(n), n):
                c, tx = self.classify_sql(f, v, depth + 1)
                texts += tx
                if c and (best is None or rank[c] > rank[best]):
                    best = c
            return best, texts
        if t in {"constant", "scope_resolution"}:
            s = self.const_value(f, n)
            return ("parameterized", [s]) if s is not None else (None, [])
        return None, []

    def query(self, f, c, m, recv, ps, pos, kws, out, hashed):
        at = f.at(c)
        rule = self.rule(c, "query")
        if rule:
            untrusted = any(f.tainted(a, self.taint) for a in pos + list(kws.values()))
            construction = rule.spec.get("construction")
            if "text" in rule.spec:
                construction, _ = self.classify_sql(f, model_arg(rule.spec["text"], pos, kws))
            if untrusted or (construction is not None and "text" in rule.spec):
                out.element("Query", at, construction=construction, untrusted_input=untrusted)
                out.mark(at, rule)
            return
        is_raw = m in SQL_RAW and (m in {"find_by_sql", "count_by_sql"} or "connection" in ps or (
            recv is not None and parts(recv)[-1:] and parts(recv)[-1].lower() in {"db", "conn", "connection", "sqlite", "pg", "client", "database"}))
        is_arel = ps[:2] == ["Arel", "sql"]
        is_fragment = m in SQL_FRAGMENT and (recv is None and self.rel(f).startswith("app/models/") or (
            recv is not None and self.ar_chain(f, recv)) or (m in AR_ONLY and recv is not None and parts(recv)[:1] not in (
                ["params"], ["request"], ["cookies"], ["session"], ["ENV"])))
        if not (is_raw or is_arel or is_fragment):
            if (m in ORM_ANY_RECEIVER and recv is not None and self.ar_chain(f, recv)) or (
                    (m in ORM_MODEL_RECEIVER or re.match(r"find_by_\w+$", m)) and self.model_receiver(f, recv)):
                if field(c, "block") is None and any(f.tainted(a, self.taint) for a in pos + list(kws.values())):
                    out.element("Query", at, construction="orm", untrusted_input=True)
            return
        if is_arel and c.parent is not None and c.parent.type == "argument_list":
            outer = c.parent.parent
            if outer is not None and outer.type == "call" and (method_name(outer) in SQL_FRAGMENT | SQL_RAW):
                return  # reported at the query method it is passed to
        sql = pos[0] if pos else None
        if sql is None:
            if kws and any(f.tainted(v, self.taint) for v in kws.values()):
                out.element("Query", at, construction="orm", untrusted_input=True)
            return
        construction, texts = self.classify_sql(f, sql)
        binds = pos[1:] + list(kws.values()) if sql.type != "hash" else []
        tainted_text = f.tainted(sql, self.taint) and sql.type not in {"hash", "array"}
        untrusted = f.tainted(sql, self.taint) or any(f.tainted(b, self.taint) for b in binds)
        if construction is None:
            if not tainted_text:
                return
            if self.direct_request(f, sql):
                # request text used as SQL; order/pluck refuse non-attribute strings since Rails 6.0
                construction = "orm" if m in ORDER_LIKE and (self.p.rails or (0,)) >= (6, 0) else "concatenated"
        if construction == "parameterized" and not untrusted and (not is_raw or self.rel(f).startswith("db/")):
            return  # a constant fragment, or a migration's fixed statement
        if construction == "orm" and not untrusted:
            return
        if sql.type == "hash" and (construction == "orm"):
            pass
        out.element("Query", at, construction=construction, untrusted_input=untrusted)
        sqltext = " ".join(texts)
        if re.search(r"\bpassword\b", sqltext, re.I):
            vals = binds + [x for x in walk(sql) if x.type == "interpolation"]
            for v in vals:
                inner = v.named_children[0] if v.type == "interpolation" and v.named_children else v
                if self.raw_password(f, inner, hashed):
                    out.element("PasswordStore", at, algorithm="plaintext", salted=False)
                    out.signal("pw_auth", at)
        if re.search(r"\bdelete\s+from\s+\W?(users?|accounts?)\b", sqltext, re.I) and self.rel(f).startswith("app/"):
            out.signal("user_delete", at)

    def direct_request(self, f: RbFile, n: Node, depth: int = 0) -> bool:
        """The value is request data itself (`params[:sort]`, a local bound to it), not something computed from it."""
        if depth > 4 or n is None:
            return False
        if n.type == "call" and method_name(n) in {"to_s", "strip", "downcase", "upcase", "presence", "squish"} and field(n, "receiver") is not None:
            return self.direct_request(f, field(n, "receiver"), depth + 1)
        if n.type == "element_reference":
            return parts(n)[:1] in (["params"], ["cookies"]) or self.direct_request(f, field(n, "object"), depth + 1)
        if n.type == "identifier":
            if text(n) in {"params", "cookies"}:
                return True
            return any(self.direct_request(f, v, depth + 1) for v in f.resolve(text(n), n))
        if n.type == "call" and parts(n)[:1] == ["request"]:
            return True
        if n.type == "call" and parts(n)[:1] == ["params"] and method_name(n) in {"fetch", "require", "dig", "[]"}:
            return True
        return False

    def ar_chain(self, f: RbFile, recv: Node) -> bool:
        """The receiver is an ActiveRecord model, relation, or association (not a Hash, Array, or params)."""
        ps = parts(recv)
        if not ps or ps[0] in {"params", "request", "cookies", "session", "ENV", "Hash", "Array", "File", "Dir", "JSON",
                               "YAML", "Set", "OpenStruct", "Rails", "URI", "CGI", "Time", "Date"}:
            return False
        if self.model_receiver(f, recv):
            return True
        if self.rel(f).startswith("app/models/") and recv.type == "call" and field(recv, "receiver") is None:
            return True  # a scope or class method of the model
        return any(p in {"where", "joins", "includes", "order", "unscoped", "all", "merge", "left_joins", "preload", "eager_load",
                         "scoping", "select", "group", "limit", "offset", "not", "or", "distinct"} for p in ps[1:])

    # ------------------------------------------------------------------ tokens, cookies

    def token(self, f, c, m, ps, pos, kws, out):
        at = f.at(c)
        rule = self.rule(c, "token_verification")
        if rule:
            out.element("TokenVerification", at, **rule.spec)
            out.mark(at, rule)
            return
        if ps[:2] != ["JWT", "decode"]:
            return
        verify = True
        if len(pos) >= 3:
            b = bool_value(pos[2])
            verify = b if b is not None else None
        opts = dict(kws)
        if len(pos) >= 4 and pos[3].type == "hash":
            opts.update(hash_pairs(pos[3]))
        algs = opts.get("algorithm") or opts.get("algorithms")
        allows = None
        if verify is False:
            allows = True
        elif algs is not None:
            vals = [self.const_value(f, x) for x in (algs.named_children if algs.type == "array" else [algs])]
            if all(v is not None for v in vals):
                fam = {v.lower()[:2] for v in vals}
                allows = any(v.lower() == "none" for v in vals) or bool("hs" in fam and fam & {"rs", "es", "ps"})
        elif verify is True and (self.p.gem("jwt") or (2,)) >= (2,):
            allows = False  # ruby-jwt 2.x verifies with HS256 unless told otherwise
        out.element("TokenVerification", at, verifies_signature=verify, allows_none_alg=allows)

    def cookie_defaults(self, session: bool) -> dict:
        """Cookie attributes Rails applies when the call does not set them (production configuration)."""
        fs = self.p.setting("force_ssl")
        ssl = fs is not None and bool_value(fs.value) is True
        so = self.p.setting("ssl_options")
        if ssl and so is not None and so.value.type == "hash":
            sc = hash_pairs(so.value).get("secure_cookies")
            ssl = not (sc is not None and bool_value(sc) is False)
        # same_site: config.action_dispatch.cookies_same_site_protection, :lax with load_defaults >= 6.1, else none set
        ss = self.p.setting("action_dispatch.cookies_same_site_protection")
        if ss is not None:
            v = sym_or_str(ss.value)
            same = v.lower() if v and v.lower() in {"strict", "lax", "none"} else ("unset" if ss.value.type == "nil" else None)
        elif self.p.defaults_at_least(6.1) and (self.p.rails or (6, 1)) >= (6, 1):
            same = "lax"
        else:
            same = "unset"
        return {"secure": True if ssl else False, "http_only": True if session else False, "same_site": same, "ssl": ssl}

    def cookie_call(self, f, c, m, recv, pos, kws, out):
        if m == "set_cookie" and recv is not None and text(recv) in {"response", "headers"} and pos:
            name = self.const_value(f, pos[0])
            opts = hash_pairs(pos[1]) if len(pos) > 1 and pos[1].type == "hash" else {}
            self._cookie(f, c, name, opts, out, session=False)
        elif m == "session_store" and "config" in parts(c):
            store = sym_or_str(pos[0]) if pos else None
            if store in {"disabled"}:
                return
            self._cookie(f, c, None, kws, out, session=True, store=store)

    def _cookie(self, f, n, name, opts: dict, out, session: bool, store=None):
        d = self.cookie_defaults(session)

        def flag(key, default):
            v = opts.get(key)
            if v is None:
                return default
            b = bool_value(v)
            if b is not None:
                return b
            if re.fullmatch(r"Rails\.env\.production\?", text(v)):
                return True
            return None
        secure = True if d["ssl"] else flag("secure", d["secure"])
        http_only = flag("httponly", d["http_only"])
        same = d["same_site"]
        if "same_site" in opts:
            v = sym_or_str(opts["same_site"])
            same = v.lower() if v and v.lower() in {"strict", "lax", "none"} else ("unset" if opts["same_site"].type in {"nil", "false"} else None)
        is_session = True if session or (name and session_cookie_name(name)) else None
        out.element("Cookie", f.at(n), is_session=is_session, secure=secure, http_only=http_only, same_site=same)

    def assignment(self, f: RbFile, n: Node, out: Collector, rel: str):
        left, right = field(n, "left"), field(n, "right")
        if left is None or right is None:
            return
        if left.type == "element_reference":
            obj = field(left, "object")
            op = parts(obj)
            if op and op[0] == "cookies" and all(x in {"cookies", "permanent", "signed", "encrypted"} for x in op):
                key = left.named_children[1] if left.named_children[1:] else None
                name = self.const_value(f, key)
                opts = hash_pairs(right) if right.type == "hash" else {}
                self._cookie(f, n, name, opts, out, session=False)
        elif left.type == "call" and is_password_name(method_name(left)) and rel.startswith("app/") \
                and parts(left)[:1] != ["params"] and f.tainted(right, self.taint):
            out.signal("pw_set_site", f.at(n))

    # ------------------------------------------------------------------ logs

    def log(self, f, c, m, recv, ps, pos, kws, out, rel):
        rule = self.rule(c, "log")
        is_log = bool(rule) or (m in LOG_METHODS and recv is not None and (
            ps[-2:-1] and ps[-2].lower() in {"logger", "log"} or text(recv).endswith(("logger", "Logger"))))
        # stdout of the server process ends up in its logs; elsewhere (lib/, extras/, script/) `puts` is usually an
        # operator's console helper printing what was asked for
        is_console = m in CONSOLE and (recv is None or text(recv) in {"$stdout", "STDOUT", "$stderr", "STDERR"}) \
            and rel.startswith("app/")
        if not (is_log or is_console) or rel.startswith(SCRIPT_PREFIXES):
            return
        exprs: list[Node] = []
        for a in pos + list(kws.values()):
            ps_ = _str_parts(a, f)
            if ps_ is not None:
                exprs += [p.named_children[0] for p in ps_ if p.type == "interpolation" and p.named_children]
            elif not is_literal(a):
                exprs.append(a)
        blk = field(c, "block")
        if blk is not None:
            for x in walk(blk):
                if x.type == "interpolation" and x.named_children:
                    exprs.append(x.named_children[0])
        creds = personal = False
        for k in kws:
            if "request" not in words(k):
                creds = creds or is_credential_name(k)
                personal = personal or is_personal_name(k)
        for e in exprs:
            for nm, owner in self._names(e):
                if is_credential_name(nm) and nm not in {"request", "session"}:
                    creds = True
                if is_personal_name(nm, owner):
                    personal = True
            whole = self._whole_request(f, e)
            if whole == "headers":
                creds = True
            elif whole == "params":
                cls = f.class_of(c)
                body = text(cls) if cls is not None else f.src
                if re.search(r"password|passwd|token|secret", body, re.I):
                    creds = True
                if re.search(r"\bemail|first_name|last_name|full_name|phone|address\b", body, re.I):
                    personal = True
            if e.type in {"identifier", "instance_variable"} and is_user_object_name(text(e).lstrip("@")):
                personal = True
        if creds or personal:
            out.element("LogStatement", f.at(c), logs_credentials=creds, logs_personal_data=personal)
            out.mark(f.at(c), rule)

    def _names(self, e: Node) -> list[tuple[str, str | None]]:
        """Names a logged value reads: a local, the last attribute of a chain with its owner, or a hash key. Inner links
        of a chain (`credentials` in `Rails.application.credentials.mastodon.instance_name`) are not the value."""
        out = []
        for x in walk(e):
            p = x.parent
            inner = p is not None and p.type == "call" and field(p, "receiver") is not None and field(p, "receiver").id == x.id \
                and x.id != e.id
            if x.type in {"identifier", "instance_variable"}:
                if p is not None and p.type == "call" and field(p, "method") is not None and field(p, "method").id == x.id:
                    continue
                if inner and text(x) not in {"params"}:
                    continue
                out.append((text(x).lstrip("@"), None))
            elif x.type == "call" and field(x, "receiver") is not None and not inner:
                rp = parts(field(x, "receiver"))
                out.append((method_name(x), rp[-1].lstrip("@") if rp else None))
            elif x.type == "element_reference":
                op = parts(field(x, "object"))
                for k in x.named_children[1:]:
                    s = sym_or_str(k)
                    if s:
                        out.append((s, op[-1] if op else None))
        return [(n, o) for n, o in out if "request" not in words(n)]  # request_id, request_token: a trace id

    def _whole_request(self, f: RbFile, e: Node) -> str | None:
        """The whole request parameters or headers are logged, not one named field."""
        n = e
        while n.type == "call" and method_name(n) in {"inspect", "to_s", "to_unsafe_h", "to_h", "to_json", "as_json", "permit!"}:
            n = field(n, "receiver")
            if n is None:
                return None
        if n.type == "identifier" and text(n) == "params":
            return "params"
        if n.type == "call" and parts(n) in (["request", "headers"], ["request", "env"], ["request", "cookies"]):
            return "headers"
        if n.type == "identifier" and text(n) == "cookies":
            return "headers"
        if n.type == "call" and parts(n) in (["request", "params"], ["request", "parameters"], ["request", "raw_post"], ["request", "body"]):
            return "params"
        return None

    # ------------------------------------------------------------------ transfers

    def transfer(self, f, c, m, recv, ps, pos, kws, out):
        at = f.at(c)
        rule = self.rule(c, "transfer")
        if rule:
            s = rule.spec
            personal = s.get("personal_data", "infer")
            if personal == "infer":
                personal = self._personal_payload(pos + list(kws.values()), kws) or None
            out.element("Transfer", at, recipient=s["recipient"], personal_data=personal, third_country=s.get("third_country"))
            out.mark(at, rule)
            return
        head = ps[0] if ps else ""
        if ps[:2] == ["Net", "HTTP"] and m in {"post", "post_form", "put", "patch"} and len(ps) == 3:
            host = self.url_host(f, pos[0] if pos else None)
            if host:
                out.element("Transfer", at, recipient=host, personal_data=self._personal_payload(pos[1:], kws) or None)
        elif ps[:3] in (["Net", "HTTP", "Post"], ["Net", "HTTP", "Put"], ["Net", "HTTP", "Patch"]) and m == "new":
            host = self.url_host(f, pos[0] if pos else None)
            if host:
                out.element("Transfer", at, recipient=host)
        elif head in HTTP_CLIENTS and m in {"post", "put", "patch"} and len(ps) == 2:
            host = self.url_host(f, pos[0] if pos else kws.get("url"))
            if host:
                out.element("Transfer", at, recipient=host, personal_data=self._personal_payload(pos[1:], kws) or None)
        elif m in {"post", "put", "patch"} and recv is not None and recv.type in {"identifier", "instance_variable"}:
            for v in f.resolve(text(recv), c):
                if v.type == "call" and parts(v)[:1] and parts(v)[0] in HTTP_CLIENTS | {"Net"} and method_name(v) in {"new", "start"}:
                    vp, vk = args(v)
                    host = self.url_host(f, vk.get("url") or (vp[0] if vp else None))
                    if host is None and vp and parts(v)[:2] == ["Net", "HTTP"]:
                        h = self.const_value(f, vp[0])
                        host = external_host(f"https://{h}") if h else None
                    if host:
                        out.element("Transfer", at, recipient=host, personal_data=self._personal_payload(pos[1:], kws) or None)
                        break
        elif head == "Sentry" and m in {"init", "set_user"} or head == "Raven" and m in {"configure", "user_context"}:
            personal = None
            if m in {"set_user", "user_context"}:
                personal = True if (self._personal_payload(pos, kws) or any(is_personal_name(k) for k in kws)) else None
            else:
                blk = field(c, "block")
                if blk is not None and re.search(r"send_default_pii\s*=\s*true", text(blk)):
                    personal = True
            out.element("Transfer", at, recipient="Sentry", personal_data=personal)
        elif head in {"Rollbar", "Honeybadger", "Bugsnag", "Airbrake", "Appsignal"} and m in {"configure", "init"}:
            out.element("Transfer", at, recipient=head)
        elif ps[:2] == ["Stripe", "Customer"] and m in {"create", "update"} or ps[:1] == ["Stripe"] and m in {"create", "update"} and len(ps) >= 3:
            out.element("Transfer", at, recipient="Stripe", personal_data=self._personal_payload(pos, kws) or None)
        elif head == "Twilio" and m == "new":
            out.element("Transfer", at, recipient="Twilio", personal_data=True)  # SMS and calls carry phone numbers
        elif ps[:2] == ["Mailgun", "Client"] and m == "new":
            out.element("Transfer", at, recipient="Mailgun", personal_data=True)
        elif ps[:1] == ["Aws"] and len(ps) >= 3 and ps[1] in {"SES", "SESV2", "SNS", "Pinpoint"} and m == "new":
            out.element("Transfer", at, recipient=f"AWS {ps[1].replace('V2', '')}", personal_data=True)
        elif (ps[:1] == ["Segment"] or ps[:1] == ["Analytics"] and "analytics-ruby" in self.p.gems) and m in {"identify", "track", "new"}:
            out.element("Transfer", at, recipient="Segment", personal_data=self._personal_payload(pos, kws) or None)
        elif ps[:2] == ["Mixpanel", "Tracker"] and m == "new":
            out.element("Transfer", at, recipient="Mixpanel")
        elif head in {"OpenAI", "Anthropic"} and m == "new":
            out.element("Transfer", at, recipient=head)

    def _personal_payload(self, vals: list[Node], kws: dict) -> bool:
        for k in kws:
            if is_personal_name(k):
                return True
        for v in vals:
            for nm, owner in self._names(v):
                if is_personal_name(nm, owner) or (owner is None and is_user_object_name(nm)):
                    return True
            for x in walk(v):
                if x.type == "pair" and is_personal_name(sym_or_str(field(x, "key")) or text(field(x, "key"))):
                    return True
        return False

    def url_host(self, f: RbFile, n: Node | None, depth: int = 0) -> str | None:
        if n is None or depth > 3:
            return None
        if n.type == "call" and (method_name(n) in {"parse", "URI"} and parts(n)[:1] in (["URI"],) or method_name(n) == "URI"):
            pos, _ = args(n)
            return self.url_host(f, pos[0] if pos else None, depth + 1)
        s = self.const_value(f, n)
        if s is None:
            ps = _str_parts(n, f)
            if ps and ps[0].type == "string_content":
                s = text(ps[0])
        if s is None and n.type in {"identifier", "instance_variable"}:
            for v in f.resolve(text(n), n):
                h = self.url_host(f, v, depth + 1)
                if h:
                    return h
        return external_host(s) if s else None

    # ------------------------------------------------------------------ commands, HTML, deserialization

    def command(self, f: RbFile, c: Node, pos: list[Node], out: Collector, shell: bool, kws: dict | None = None):
        if shell:
            n = pos[0]
            ps = _str_parts(n, f) or []
            construction = "interpolated" if any(p.type == "interpolation" for p in ps) else "constant"
            out.element("CommandExecution", f.at(c), construction=construction, untrusted_input=f.tainted(n, self.taint))
            return
        vals = list(pos)
        if vals and vals[0].type == "hash":
            vals = vals[1:]  # environment
        if not vals:
            return
        untrusted = any(f.tainted(v, self.taint) for v in vals)
        if len(vals) > 1 or vals[0].type == "array" or (vals[0].type in {"splat_argument"}):
            construction = "argv"
        else:
            construction = self.classify_command(f, vals[0])
        out.element("CommandExecution", f.at(c), construction=construction, untrusted_input=untrusted)

    def classify_command(self, f: RbFile, n: Node, depth: int = 0) -> str | None:
        if depth > 4:
            return None
        ps = _str_parts(n, f)
        if ps is not None:
            return "interpolated" if any(p.type == "interpolation" for p in ps) else "constant"
        if n.type == "binary" and text(field(n, "operator")) in {"+", "<<"}:
            return "concatenated"
        if n.type == "binary" and text(field(n, "operator")) == "%":
            return "interpolated"
        if n.type == "call" and method_name(n) == "join":
            return "concatenated"
        if n.type == "call" and method_name(n) in {"to_s", "strip", "freeze"} and field(n, "receiver") is not None:
            return self.classify_command(f, field(n, "receiver"), depth + 1)
        if n.type in {"constant", "scope_resolution"} and self.const_value(f, n) is not None:
            return "constant"
        if n.type in {"identifier", "instance_variable"}:
            got = [self.classify_command(f, v, depth + 1) for v in f.resolve(text(n), n)]
            got = [g for g in got if g]
            for k in ("concatenated", "interpolated", "argv", "constant"):
                if k in got:
                    return k
        return None

    def html(self, f: RbFile, c: Node, m: str, recv: Node | None, pos: list[Node], out: Collector):
        if re.search(r"\.(text|txt|json|csv|js|xml|rss|atom|ics|md)\.(erb|haml|slim|builder)$", f.sf.rel):
            return  # not an HTML document
        value = None
        sanitized = False
        if m == "raw" and recv is None and len(pos) == 1:
            value = pos[0]
        elif m == "html_safe" and recv is not None and not pos:
            value = recv
            if recv.type == "call" and method_name(recv) == "raw":
                return  # reported as raw()
        elif m == "sanitize" and recv is None and pos:
            value, sanitized = pos[0], True
        elif m in {"safe_concat"} and pos:
            value = pos[0]
        else:
            return
        self.html_element(f, c, value, sanitized, out)

    def html_element(self, f: RbFile, at_node: Node, value: Node, sanitized: bool, out: Collector):
        if not sanitized:
            sanitized = any(x.type == "call" and method_name(x) in ESCAPING for x in walk(value))
        untrusted = True if f.tainted(value, self.taint) else self.classify_html(f, value)
        facts = {"sanitized": sanitized}
        if untrusted is not None:
            facts["untrusted_input"] = untrusted
        out.element("HtmlOutput", f.at(at_node), **facts)

    def classify_html(self, f: RbFile, n: Node | None, depth: int = 0) -> bool | None:
        """Whether user-supplied data reaches an HTML value: True, False, or None when it cannot be told."""
        if n is None or depth > 5:
            return None
        if f.tainted(n, self.taint):
            return True
        t = n.type
        ps = _str_parts(n, f)
        if ps is not None:
            return _combine([self.classify_html(f, p.named_children[0], depth + 1) for p in ps
                             if p.type == "interpolation" and p.named_children] or [False])
        if is_literal(n) or t in {"nil", "integer", "float", "simple_symbol", "constant", "scope_resolution"}:
            return False
        if t in {"parenthesized_statements"} and n.named_children:
            return self.classify_html(f, n.named_children[-1], depth + 1)
        if t == "binary":
            op = text(field(n, "operator"))
            if op == "+" and any(x is not None and x.type in {"integer", "float"} for x in (field(n, "left"), field(n, "right"))):
                return False  # arithmetic
            if op in {"+", "<<"}:
                return _combine([self.classify_html(f, field(n, "left"), depth + 1), self.classify_html(f, field(n, "right"), depth + 1)])
            return False if op in {"-", "*", "/", "==", "!=", "<", ">", "<=", ">="} else None
        if t in {"conditional", "if", "unless"}:
            branches = [field(n, "consequence"), field(n, "alternative")]
            vals = [self.classify_html(f, b, depth + 1) for b in branches if b is not None]
            return _combine(vals)
        if t in {"then", "else"} and n.named_children:
            return self.classify_html(f, n.named_children[-1], depth + 1)
        if t == "call":
            m = method_name(n)
            recv = field(n, "receiver")
            pos, _ = args(n)
            if m.endswith(("_path", "_url")) or m in SAFE_HELPERS or m in ESCAPING:
                return False
            if m in {"id", "to_i", "to_f", "count", "size", "length", "to_param"} or m.endswith(("?", "_id", "_count", "_at")):
                return False
            if m in PASSTHROUGH and recv is not None:
                return self.classify_html(f, recv, depth + 1)
            if m == "raw" and recv is None and pos:
                return self.classify_html(f, pos[0], depth + 1)
            if recv is not None and not pos and field(n, "block") is None:
                types = self.p.column_type(m)
                if types and not types & {"string", "text", "citext", "json", "jsonb", "binary"}:
                    return False
                if m in self.safe_format:
                    return False  # validated to characters that cannot form markup
                if m in self.writable and (not types or types & {"string", "text", "citext"}):
                    return True
            return None
        if t in {"identifier", "instance_variable"}:
            vals = f.resolve(text(n), n)
            if vals:
                return _combine([self.classify_html(f, v, depth + 1) for v in vals])
            return None
        return None

    def unescaped_tag(self, f: RbFile, start: int, end: int, out: Collector):
        """`<%== expr %>` (ERB), `!= expr` (HAML), `== expr` (Slim)."""
        if re.search(r"\.(text|txt|json|csv|js|xml|rss|atom|ics|md)\.(erb|haml|slim)$", f.sf.rel):
            return
        best = None
        for n in walk(f.root):
            if n.start_byte >= start and n.end_byte <= end and n.type not in {"comment"}:
                best = n
                break
        if best is not None:
            self.html_element(f, best, best, False, out)

    def deserialization(self, f, c, m, ps, pos, kws, out):
        head = ps[:1]
        safe = None
        if head == ["Marshal"] and m in {"load", "restore"} and len(ps) == 2:
            safe = False
        elif head in (["YAML"], ["Psych"]) and len(ps) == 2:
            if m in {"unsafe_load", "unsafe_load_file", "load_stream"}:
                safe = False
            elif m in {"safe_load", "safe_load_file"}:
                safe = True
            elif m in {"load", "load_file"}:
                safe = self.p.psych_safe_load()  # Psych 4 (Ruby 3.1+) made load mean safe_load
                if safe is None:
                    safe = None
            else:
                return
        elif head == ["Oj"] and len(ps) == 2 and m in {"load", "load_file", "object_load", "safe_load", "strict_load", "compat_load"}:
            mode = sym_or_str(kws.get("mode")) if kws.get("mode") is not None else None
            if m == "object_load":
                safe = False
            elif m in {"safe_load", "strict_load", "compat_load"}:
                safe = True
            elif mode is not None:
                safe = mode != "object"
            else:
                safe = self._oj_default_safe()
        elif ps[:2] == ["JSON", "parse"] and kws.get("create_additions") is not None and bool_value(kws["create_additions"]) is True:
            safe = False
        else:
            return
        data = pos[0] if pos else None
        untrusted = None
        if data is not None:
            if f.tainted(data, self.taint):
                untrusted = True
            elif is_literal(data) or (data.type == "call" and parts(data)[:2] in (["File", "read"], ["IO", "read"], ["File", "open"])
                                      and all(is_literal(a) or "Rails" in text(a) or "__dir__" in text(a) for a in args(data)[0])):
                untrusted = False
        if m.endswith("_file") and data is not None and (is_literal(data) or "Rails.root" in text(data)):
            untrusted = False
        out.element("Deserialization", f.at(c), safe_mode=safe, untrusted_input=untrusted)

    def _oj_default_safe(self) -> bool:
        """Oj.load defaults to :object mode unless the application sets another default mode."""
        for f in self.files:
            if "Oj.default_options" in f.src or "Oj.mimic_JSON" in f.src or "Oj.optimize_rails" in f.src:
                if re.search(r"Oj\.default_options\s*=\s*\{?[^}\n]*mode:\s*:(compat|strict|null|json|rails|custom)", f.src) or \
                        "Oj.optimize_rails" in f.src:
                    return True
        return False

    # ------------------------------------------------------------------ mass assignment

    def mass_source(self, f: RbFile, n: Node | None, depth: int = 0):
        """How request parameters reach a bulk assignment: (allowlist, fields) or None when they do not (or a plain
        ActionController::Parameters raises ForbiddenAttributesError)."""
        if n is None or depth > 5:
            return None
        t = n.type
        if t == "call":
            m = method_name(n)
            recv = field(n, "receiver")
            if m == "permit" and "params" in parts(n):
                return True, self._permit_fields(n)
            if m == "permit!" and "params" in parts(n):
                return False, []
            if m in {"to_unsafe_h", "to_unsafe_hash"} and recv is not None and f.tainted(recv, self.taint):
                return False, []
            if m in {"merge", "except", "reverse_merge", "with_indifferent_access", "compact", "reject", "select", "to_h",
                     "deep_symbolize_keys", "symbolize_keys", "stringify_keys", "filter", "transform_values", "dup"} and recv is not None:
                return self.mass_source(f, recv, depth + 1)
            if m == "slice" and recv is not None:
                inner = self.mass_source(f, recv, depth + 1)
                pos, _ = args(n)
                if inner is not None:
                    return True, [sym_or_str(a) or "" for a in pos]
                return None
            if m in {"require", "fetch"} and parts(n)[:1] == ["params"] or (recv is None and m == "params"):
                return self._raw_params()
            if recv is None and not field(n, "arguments"):
                return self._helper_source(f, n, m, depth)
            return None
        if t == "element_reference" and parts(n)[:1] == ["params"]:
            return self._raw_params()
        if t == "identifier":
            if text(n) == "params":
                return self._raw_params()
            got = [self.mass_source(f, v, depth + 1) for v in f.resolve(text(n), n)]
            got = [g for g in got if g is not None]
            if got:
                return min(got, key=lambda g: g[0])  # the least restrictive way in
            return self._helper_source(f, n, text(n), depth)
        if t == "instance_variable":
            got = [self.mass_source(f, v, depth + 1) for v in f.resolve(text(n), n)]
            got = [g for g in got if g is not None]
            return min(got, key=lambda g: g[0]) if got else None
        return None

    def _raw_params(self):
        if self.permit_all:
            return False, []
        rails = self.p.rails
        if rails is None or rails >= (4,) or "strong_parameters" in self.p.gems:
            return None  # raises ActiveModel::ForbiddenAttributesError
        return "accessible", []

    def _helper_source(self, f: RbFile, n: Node, name: str, depth: int):
        cands = [(tf, m) for tf, m in self.defs.get(name, []) if tf is f] or [
            (tf, m) for tf, m in self.defs.get(name, []) if tf.sf.rel.startswith(f"{self.p.prefix}app/controllers/")]
        for tf, m in cands[:1]:
            if tf.params_of(m):
                return None
            body = field(m, "body")
            kids = [k for k in (body.named_children if body is not None else []) if k.type != "comment"]
            if kids:
                return self.mass_source(tf, kids[-1], depth + 1)
        return None

    def mass_assignment(self, f: RbFile, c: Node, a: Node, out: Collector):
        src = self.mass_source(f, a)
        if src is None:
            return
        allow, fields_ = src
        table = self.table_of(f, c)
        if allow == "accessible":  # Rails 3: the model's attr_accessible list governs
            model = next((k for k in self.attr_accessible if self.p.table_for(k) == table), None)
            if model is None:
                allow, fields_ = False, []
            else:
                allow, fields_ = True, self.attr_accessible[model]
        if allow:
            priv = any(PRIVILEGED.match(x or "") for x in fields_)
        elif table:
            priv = any(PRIVILEGED.match(col) for col in self.p.tables.get(table, {}))
        else:
            priv = None
        out.element("MassAssignment", f.at(c), allowlist=allow, privileged_assignable=priv)

    # ------------------------------------------------------------------ comparisons and policy checks

    def compare(self, f: RbFile, n: Node, out: Collector, hashed: set[str]):
        op = text(field(n, "operator"))
        left, right = field(n, "left"), field(n, "right")
        if left is None or right is None:
            return
        at = f.at(n)
        if op in {"==", "!="}:
            for a, b in ((left, right), (right, left)):
                stored = a.type == "call" and field(a, "receiver") is not None and is_stored_password_name(method_name(a)) \
                    and parts(a)[:1] != ["params"]
                if stored and self.raw_password(f, b, hashed) and not (b.type == "call" and is_stored_password_name(method_name(b))):
                    out.element("PasswordStore", at, algorithm="plaintext", salted=False)
                    out.signal("pw_auth", at)
                    break
        if op in {"<", "<=", ">", ">="}:
            for a, b, o in ((left, right, op), (right, left, {"<": ">", ">": "<", "<=": ">=", ">=": "<="}[op])):
                if a.type == "call" and method_name(a) in {"length", "size", "bytesize"} and self.mentions_password(field(a, "receiver")) \
                        and int_value(b) is not None:
                    k = int_value(b)
                    if o == "<":
                        out.signal("pw_min", at, k, side="server")
                    elif o == ">=":
                        out.signal("pw_min", at, k, side="server") if k < 16 else out.signal("pw_max", at, k - 1, side="server")
                    elif o in {">", "<="}:
                        out.signal("pw_min", at, k + 1, side="server") if k < 16 else out.signal("pw_max", at, k, side="server")
                    out.signal("pw_validation", at, side="server")

    # ------------------------------------------------------------------ classes and controller actions

    def class_signals(self, f: RbFile, n: Node, out: Collector, rel: str):
        name = text(field(n, "name")).split("::")[-1]
        sup = field(n, "superclass")
        sup_t = text(sup.named_children[0]) if sup is not None and sup.named_children else ""
        if name in self.models and is_user_object_name(name) and name in {"User", "Account", "Customer", "Member", "Person"}:
            out.signal("user_model", f.at(n))
        if sup_t in {"ActionController::Base", "ActionController::API"}:
            out.signal("rb_controller_base", f.at(n), sup_t, cls=name, rel=rel)

    def controller_methods(self, f: RbFile, out: Collector):
        ctrl = self.rel(f).rsplit("/", 1)[-1][: -len("_controller.rb")] if self.rel(f).endswith("_controller.rb") else ""
        for m in f.methods:
            name = f.method_def_name(m)
            body = text(m)
            at = f.at(m)
            login_name = name in {"login", "sign_in", "signin", "log_in", "do_login", "authenticate"} or (
                name == "create" and re.search(r"session|login|sign_?in|auth", ctrl))
            excluded = re.search(r"regist|signup|sign_up|reset|forgot|recover|confirm|invit", ctrl + " " + name)
            takes_password = re.search(r"params(\[:\w+\]|\.require\(:\w+\))*\[:(password|passwd|pass|pwd)\]|\.authenticate(_by)?\b|"
                                       r"valid_password\?|permit\([^)]*:password", body)
            if login_name and not excluded and takes_password:
                out.signal("login_route", at, fn=name)
                out.signal("pw_auth", at)
            export_name = re.search(r"export|takeout|portab|data_request|my_data|personal_data|gdpr|download_(my_|account_|user_)?data",
                                    f"{ctrl} {name}")
            if export_name and re.search(r"current_user|@user\b|\buser\b", body) and re.search(
                    r"send_data|send_file|render\s*\(?\s*(json|xml|plain)\s*:|to_json|to_csv|format\.(json|csv|zip)", body):
                out.signal("rb_data_export", at)

    def rack_attack(self, f: RbFile, c: Node, m: str, out: Collector):
        if m != "throttle":
            return
        blk = field(c, "block")
        body = text(blk) if blk is not None else ""
        if re.search(r"login|sign_?in|session|/auth|password", body, re.I):
            out.signal("rate_limit", f.at(c), scope="global")
        elif not re.search(r"\.path|PATH_INFO|\.post\?|user_agent|\.params", body):
            out.signal("rate_limit", f.at(c), scope="global")

    # ------------------------------------------------------------------ secrets

    def dev_only(self, f: RbFile, n: Node) -> bool:
        """The literal is only used outside production: a development or test file, a seed or fake-data task, or a
        branch that does not run in production."""
        rel = self.rel(f)
        if f.sf.example or rel.startswith(("config/environments/development", "config/environments/test")) or (
                rel.startswith(("db/", "lib/tasks/", "script/")) and DEV_FILE.search(rel.rsplit("/", 1)[-1])):
            return True
        a, child = n.parent, n
        while a is not None:
            if a.type in {"if", "unless", "if_modifier", "unless_modifier", "elsif"}:
                cond = text(field(a, "condition"))
                in_else = field(a, "alternative") is not None and field(a, "alternative").start_byte <= child.start_byte \
                    and child.end_byte <= field(a, "alternative").end_byte
                positive = a.type in {"if", "if_modifier", "elsif"}
                if "Rails.env.production?" in cond and "!" not in cond and "||" not in cond:
                    if positive == in_else:
                        return True
                elif re.search(r"Rails\.env\.(development|test)\?", cond) and "production" not in cond and positive and not in_else:
                    return True
            child, a = a, a.parent
        return False

    def secrets(self, f: RbFile, out: Collector):
        pairs: list[tuple[str, Node]] = []
        for n in walk(f.root):
            t = n.type
            if t == "assignment":
                left, right = field(n, "left"), field(n, "right")
                nm = None
                if left is None or right is None:
                    continue
                if left.type in {"constant", "identifier", "instance_variable", "global_variable", "class_variable"}:
                    nm = text(left).lstrip("@$")
                elif left.type == "scope_resolution":
                    nm = text(field(left, "name"))
                elif left.type == "call":
                    nm = method_name(left)
                elif left.type == "element_reference" and left.named_children[1:]:
                    nm = sym_or_str(left.named_children[1])
                if nm:
                    pairs.append((nm, right))
            elif t == "pair":
                k = field(n, "key")
                nm = sym_or_str(k) if k is not None else None
                if nm:
                    pairs.append((nm, field(n, "value")))
            elif t == "call":
                ps = parts(n)
                pos, kws = args(n)
                if ps == ["ENV", "fetch"] and pos:
                    envname = sym_or_str(pos[0])
                    dflt = pos[1] if len(pos) > 1 else None
                    blk = field(n, "block")
                    if dflt is None and blk is not None:
                        body = [x for x in blk.named_children if x.type in {"block_body", "body_statement"}]
                        dflt = body[0].named_children[-1] if body and body[0].named_children else None
                    if envname and dflt is not None:
                        pairs.append((envname, dflt))
                elif ps[:2] == ["JWT", "encode"] and len(pos) > 1:
                    pairs.append(("signing_key", pos[1]))
                elif ps[:2] == ["JWT", "decode"] and len(pos) > 1:
                    pairs.append(("signing_key", pos[1]))
                elif ps[:2] == ["OpenSSL", "HMAC"] and len(pos) > 1:
                    pairs.append(("hmac_key", pos[1]))
            elif t == "binary" and text(field(n, "operator")) in {"||", "or"}:
                left = field(n, "left")
                if left is not None and left.type == "element_reference" and parts(left)[:1] == ["ENV"] and left.named_children[1:]:
                    envname = sym_or_str(left.named_children[1])
                    if envname:
                        pairs.append((envname, field(n, "right")))
        seen = set()
        routes = self.rel(f) == "config/routes.rb"
        for name, v in pairs:
            s = _literal_text(v, f) if v is not None else None
            if s is None or (routes and not literal_secret_kind(s)) or re.fullmatch(r"[\w/]+#\w+", s):
                continue  # a route ("controller#action"), not a credential
            kind = literal_secret_kind(s) or secret_kind_for_name(name)
            if kind and plausible_secret_value(s, kind):
                at = f.at(v)
                seen.add(at)
                out.element("Secret", at, kind=kind, test_or_example=True if self.dev_only(f, v) else None)
        for n in walk(f.root):
            if n.type in {"string", "heredoc_body"}:
                s = "".join(text(p) for p in n.named_children if p.type in {"string_content", "heredoc_content"})
                kind = literal_secret_kind(s)
                if kind and f.at(n) not in seen:
                    out.element("Secret", f.at(n), kind=kind, test_or_example=True if self.dev_only(f, n) else None)


def _markup_free(regex: str) -> bool:
    """An anchored (\\A...\\z) pattern whose character classes admit no markup characters."""
    body = regex.strip()
    m = re.fullmatch(r"/(.*)/[a-z]*", body, re.S)
    if not m:
        return False
    p = m.group(1)
    if not (p.startswith("\\A") and (p.endswith("\\z") or p.endswith("\\Z"))):
        return False
    inner = p[2:-2]
    if re.search(r"(?<!\\)\.|\\S|\\W|\\D|\[\^", inner):
        return False
    classes = re.findall(r"\[([^\]]*)\]", inner)
    outside = re.sub(r"\[[^\]]*\]", "", inner)
    allowed = re.compile(r"^(?:[A-Za-z0-9_\-]|\\[wd\-.]|\\.|a-z|A-Z|0-9)*$")
    for cls in classes:
        if not allowed.match(cls.replace("\\-", "").replace("-", "")):
            return False
    return not re.search(r"[<>&\"'`]", outside)
