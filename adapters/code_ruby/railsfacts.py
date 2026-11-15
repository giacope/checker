"""System facts a Rails application's configuration decides: CSRF protection, TLS and HSTS, CSP, debug features in
production, parameter filtering in logs, and account data export.

Rails defaults assumed (each depends on the version in Gemfile.lock or on `config.load_defaults`):
- CSRF: ActionController::Base checks the authenticity token when `default_protect_from_forgery` is on, which
  `load_defaults 5.2` (or later) sets; without it a controller is protected only by `protect_from_forgery`.
  `protect_from_forgery with: :null_session` counts as protection: a request without a valid token runs with an empty
  session and cookie jar, so a cookie cannot authenticate it. ActionController::API controllers set no cookies.
- TLS: `config.force_ssl = true` (production) redirects HTTP to HTTPS, sends HSTS, and flags cookies Secure, unless
  `ssl_options` turns HSTS or secure cookies off. The HSTS max-age default is 2 years from Rails 6.1, 1 year before.
- CSP: Rails sends no Content-Security-Policy unless `config.content_security_policy` defines one (the generated
  initializer is commented out); report-only does not count.
- Debug: production is debug-free unless it sets `consider_all_requests_local = true`, enables reloading, or turns off
  web-console's `development_only` (better_errors and web-console otherwise refuse to run in production).
- Log filtering: `config.filter_parameters` entries match parameter names partially and case-insensitively; with no
  entry nothing is filtered.
"""

from __future__ import annotations

import re

from adapters.code_static.common import SOURCE, Collector
from adapters.code_static.facts import MAX_LOCATORS, _merge

from .project import Project
from .rb import bool_value, field, hash_pairs, int_value, sym_or_str, text, walk

HSTS_2Y, HSTS_1Y = 63072000, 31536000
NON_COOKIE_CONTROLLER = re.compile(r"webhook|callback|hook|api|token|oauth|saml|health|status|ping", re.I)


def _o(value, at):
    return {"value": value, "source": SOURCE, "at": at}


def _first_line(p: Project, rel: str | None) -> str | None:
    return f"{rel}:1" if rel else None


def system_facts(p: Project, out: Collector, an, files) -> dict:
    if not p.is_rails:
        return {}
    facts: dict[str, list[dict]] = {}
    app_rb = f"{p.prefix}config/application.rb"
    prod = p.env_file("production")

    # ---- CSRF
    obs = []
    allow = p.setting("action_controller.allow_forgery_protection")
    if allow is not None and bool_value(allow.value) is False:
        obs.append(_o(False, allow.at))
    dflt = p.setting("action_controller.default_protect_from_forgery")
    ld, ld_at = p.load_defaults
    default_on = (dflt is not None and bool_value(dflt.value) is True) or (
        dflt is None and ld is not None and ld >= 5.2 and (p.rails or (5, 2)) >= (5, 2))
    calls = out.signals.get("rb_csrf", [])
    api_only = p.setting("api_only", "all")
    for sup, at, extra in out.signals.get("rb_controller_base", []):
        cls = extra["cls"]
        if sup == "ActionController::API":
            obs.append(_o(True, at))  # no cookies, so no cross-site request carries credentials
            continue
        protects = [s for s in calls if s[2]["cls"].split("::")[-1] == cls and s[0] is False]
        if protects:
            obs += [_o(True, s[1]) for s in protects]
        elif default_on:
            obs.append(_o(True, (dflt.at if dflt is not None else ld_at)))
        elif not (api_only is not None and bool_value(api_only.value) is True):
            obs.append(_o(False, at))
    for skip, at, extra in calls:
        if skip and not NON_COOKIE_CONTROLLER.search(extra["cls"] + " " + extra["rel"]):
            obs.append(_o(False, at))
    if obs:
        facts["csrf_protection"] = _merge(obs)

    # ---- TLS and HSTS
    fs = p.setting("force_ssl")
    ssl = fs is not None and bool_value(fs.value) is True
    hsts_header = _header_literal(files, "Strict-Transport-Security")
    if fs is not None and bool_value(fs.value) is not None:
        facts["tls_enforced"] = [_o(ssl, fs.at)]
    elif prod and fs is None:
        facts["tls_enforced"] = [_o(False, _first_line(p, prod))]
    if ssl:
        so = p.setting("ssl_options")
        h = hash_pairs(so.value).get("hsts") if so is not None and so.value.type == "hash" else None
        if h is not None and bool_value(h) is False:
            facts["hsts"] = [_o(False, so.at)]
        else:
            facts["hsts"] = [_o(True, fs.at)]
            exp = hash_pairs(h).get("expires") if h is not None and h.type == "hash" else None
            if exp is not None and int_value(exp) is not None:
                facts["hsts_max_age"] = [_o(int_value(exp), so.at)]
            elif exp is None and p.rails is not None:
                facts["hsts_max_age"] = [_o(HSTS_2Y if p.rails >= (6, 1) else HSTS_1Y, (so or fs).at)]
    elif hsts_header:
        at, value = hsts_header
        facts["hsts"] = [_o(True, at)]
        m = re.search(r"max-age=(\d+)", value)
        if m:
            facts["hsts_max_age"] = [_o(int(m.group(1)), at)]
    elif "tls_enforced" in facts:
        facts["hsts"] = [_o(False, facts["tls_enforced"][0]["at"])]

    # ---- Content-Security-Policy
    report_only = p.setting("content_security_policy_report_only")
    csp = [s for s in p.all_settings("content_security_policy") if s.op == "call" and _defines_policy(s.value)]
    csp_at = [s.at for s in csp]
    for f in files:
        for n in walk(f.root) if f.sf.rel.startswith(f"{p.prefix}app/controllers/") else []:
            if n.type == "call" and field(n, "receiver") is None and text(field(n, "method")) == "content_security_policy" \
                    and _defines_policy(n):
                csp_at.append(f.at(n))
    header = _header_literal(files, "Content-Security-Policy")
    if header:
        csp_at.append(header[0])
    if any("SecureHeaders::Configuration" in f.src and re.search(r"\.csp\s*=", f.src) for f in files):
        csp_at += [f"{f.sf.rel}:1" for f in files if "SecureHeaders::Configuration" in f.src][:1]
    if report_only is not None and bool_value(report_only.value) is True:
        facts["content_security_policy"] = [_o(False, report_only.at)]
    elif csp_at:
        facts["content_security_policy"] = [_o(True, a) for a in sorted(set(csp_at))[:MAX_LOCATORS]]
    else:
        init = f"{p.prefix}config/initializers/content_security_policy.rb"
        facts["content_security_policy"] = [_o(False, f"{init}:1" if (p.root / init).is_file() else f"{app_rb}:1")]

    # ---- debug features in production
    if prod:
        dbg = []
        for key, bad in (("consider_all_requests_local", True), ("enable_reloading", True), ("cache_classes", False),
                         ("web_console.development_only", False)):
            s = p.setting(key)
            if s is not None and bool_value(s.value) is not None:
                if bool_value(s.value) is bad:
                    dbg.append(_o(True, s.at))
                elif key == "consider_all_requests_local":
                    dbg.append(_o(False, s.at))
        if not dbg:
            dbg.append(_o(False, _first_line(p, prod)))
        facts["debug_in_production"] = [o for o in dbg if o["value"]] or _merge(dbg)

    # ---- request parameters filtered from logs
    entries, ats = [], []
    for s in p.all_settings("filter_parameters"):
        if s.op == "call":
            continue  # read (ParameterFilter.new(config.filter_parameters)), not set
        vals = s.value.named_children if s.value.type == "array" else [s.value]
        for v in vals:
            if v.type == "regex":
                entries.append(("re", text(v).strip("/").split("/")[0]))
            else:
                k = sym_or_str(v)
                if k:
                    entries.append(("s", k.lower()))
        ats.append(s.at)

    def covered(word: str) -> bool:
        for kind, e in entries:
            if kind == "s" and e in word:
                return True
            if kind == "re":
                try:
                    if re.search(e, word, re.I):
                        return True
                except re.error:
                    continue
        return False
    params_read = an.param_names
    needs = ["password"] + [w for w in ("token", "secret") if any(w in x.lower() for x in params_read)]
    missing = [w for w in needs if not covered(w)]
    facts["log_redacts_credentials"] = [_o(not missing, a) for a in ats] or [_o(False, f"{app_rb}:1")]

    # ---- account data export
    exports = out.signals.get("rb_data_export", [])
    if exports:
        facts["account_data_export"] = [_o(True, a) for a in sorted({s[1] for s in exports})[:MAX_LOCATORS]]
    elif out.signals.get("personal_field") and (out.signals.get("user_model") or out.signals.get("pw_auth")):
        cite = sorted({s[1] for s in out.signals.get("user_model") or out.signals.get("pw_auth")})[:4]
        facts["account_data_export"] = [_o(False, a) for a in cite]
    return facts


def _defines_policy(call) -> bool:
    blk = field(call, "block")
    return blk is not None and any(n.type == "call" for n in walk(blk))


def _header_literal(files, header: str):
    for f in files:
        for n in walk(f.root):
            if n.type == "pair" or n.type == "assignment":
                k = field(n, "key") if n.type == "pair" else field(n, "left")
                v = field(n, "value") if n.type == "pair" else field(n, "right")
                key = sym_or_str(k) if n.type == "pair" else (
                    sym_or_str(k.named_children[1]) if k is not None and k.type == "element_reference" and k.named_children[1:] else None)
                if key and key.lower() == header.lower() and v is not None:
                    return f.at(n), text(v)
    return None
