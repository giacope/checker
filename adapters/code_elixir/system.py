"""System facts of a Phoenix application read from its configuration, endpoint, and router.

Library defaults, each checked against the library's source (cited where it is applied):
- Plug.SSL (`force_ssl:` in the endpoint config, or `plug Plug.SSL`): `hsts` defaults to true and `expires` to
  31_536_000 seconds (elixir-plug/plug lib/plug/ssl.ex, hsts_header/1, at 0d5b5ea). Phoenix plugs Plug.SSL before
  everything else in the endpoint when `force_ssl` is set (phoenixframework/phoenix lib/phoenix/endpoint.ex,
  `if force_ssl = Phoenix.Endpoint.__force_ssl__(...)`).
- `put_secure_browser_headers/2` sends `content-security-policy: base-uri 'self'; frame-ancestors 'self';` from
  Phoenix v1.8.0 (commit af2f76ae, "Update secure browser headers") and no CSP before it (checked at v1.5, v1.6,
  v1.7.0 - v1.7.14 tags of lib/phoenix/controller.ex).
- Phoenix's `:filter_parameters` default is `["password"]` up to v1.8.6 and `["password", "token"]` from v1.8.7
  (mix.exs application env; commit a99c5e89 "Filter token parameters by default"). A filter matches every
  parameter whose name contains it (Phoenix.Logger.compile_filter/1, :binary.compile_pattern).
"""

from __future__ import annotations

import re

from adapters.code_static.common import SOURCE, Collector

from .project import ConfigEntry, Deps, Router, effective, route_writes
from .syntax import L, T, atom, boolean, integer, kids, kw, string, word_list

PLUG_SSL_HSTS_MAX_AGE = 31_536_000
LOGIN_PATH = re.compile(r"(^|/)(log[_-]?in|sign[_-]?in|session|sessions|authenticate|auth/password)(/|$)", re.I)
EXPORT_FN = re.compile(r"(^|_)(export|download|takeout|portability)(_|$)")
EXPORT_SUBJECT = re.compile(r"(^|_|\.)(data|account|user|users|personal|profile|gdpr|me|my|settings)(_|$|\.)", re.I)
RATE_LIMIT_PLUGS = {"Hammer.Plug", "PlugAttack", "ExRated.Plug", "PlugRateLimit", "RemoteIp.RateLimit"}
MONITORING = {"sentry": ("Sentry", "sentry"), "appsignal": ("AppSignal", "appsignal"),
              "honeybadger": ("Honeybadger", "honeybadger"), "new_relic_agent": ("New Relic", "new_relic_agent"),
              "rollbax": ("Rollbar", "rollbax"), "bugsnag": ("Bugsnag", "bugsnag")}
MAX_AT = 8


def obs(value, ats) -> list[dict]:
    return [{"value": value, "source": SOURCE, "at": a} for a in ats]


def _key(at: str):
    path, _, line = at.rpartition(":")
    return (path, int(line) if line.isdigit() else 0)


def _ats(ats, n=MAX_AT) -> list[str]:
    return sorted(set(ats), key=_key)[:n]


def endpoint_entries(entries: list[ConfigEntry]) -> list[ConfigEntry]:
    return [e for e in entries if isinstance(e.key, str) and e.key.split(".")[-1] == "Endpoint"]


def tls(entries: list[ConfigEntry], endpoints: list, routers: list[Router], toml_files: list) -> dict:
    """{tls: [(value, at)], hsts: [(value, at, max_age)]}."""
    ep = endpoint_entries(entries)
    forced = effective(ep, lambda e: e.get("force_ssl"))
    on, hsts = [], []
    if forced:
        e, v = forced[-1]
        if T(v) not in {"nil", "false"}:
            at = f"{e.rel}:{L(v)}"
            on.append(at)
            opts = kw(v)
            h = boolean(opts.get("hsts")) if opts.get("hsts") is not None else True
            hsts.append((h, at, integer(opts.get("expires")) or PLUG_SSL_HSTS_MAX_AGE))
    for mod in endpoints:
        for t, opts, node in mod.plugs:
            if mod.resolve(T(t)) == "Plug.SSL":
                at = f"{mod.file.rel}:{L(node)}"
                on.append(at)
                o = kw(opts[0]) if opts else {}
                h = boolean(o.get("hsts")) if o.get("hsts") is not None else True
                hsts.append((h, at, integer(o.get("expires")) or PLUG_SSL_HSTS_MAX_AGE))
    for r in routers:
        for plugs in r.pipelines.values():
            for p in plugs:
                if p.target == "Plug.SSL":
                    at = f"{r.module.file.rel}:{p.line}"
                    on.append(at)
                    o = kw(p.opts[0]) if p.opts else {}
                    hsts.append((boolean(o.get("hsts")) if o.get("hsts") is not None else True, at,
                                 integer(o.get("expires")) or PLUG_SSL_HSTS_MAX_AGE))
    for rel, text in toml_files:   # an HTTPS-only proxy configured in the repository (fly.io)
        for i, line in enumerate(text.splitlines(), 1):
            if re.match(r"\s*force_https\s*=\s*true\b", line):
                on.append(f"{rel}:{i}")
    return {"on": on, "hsts": hsts}


def config_sites(entries: list[ConfigEntry], endpoints: list) -> list[str]:
    """Where the production endpoint is configured (the place a missing setting would go)."""
    ep = [e for e in endpoint_entries(entries) if e.prod]
    prod = [e for e in ep if e.env == "prod"] or ep
    ats = [e.at for e in prod]
    if not ats:
        ats = [f"{m.file.rel}:{L(m.node)}" for m in endpoints]
    return _ats(ats, 4)


def html_pipelines(r: Router) -> list[str]:
    out = []
    for name, plugs in r.pipelines.items():
        for p in plugs:
            if p.target == ":accepts" and p.opts and "html" in (word_list(p.opts[0]) or []):
                out.append(name)
                break
            if p.target in {":put_root_layout", ":fetch_flash", ":fetch_live_flash", ":put_secure_browser_headers"}:
                out.append(name)
                break
    return out


def csp(routers: list[Router], deps: Deps, modules: dict, out: Collector) -> list[dict]:
    phoenix = deps.version("phoenix")
    yes, no = [], []
    for r in routers:
        rel = r.module.file.rel
        for name in html_pipelines(r):
            here = None
            for p in r.pipelines[name]:
                at = f"{rel}:{p.line}"
                if p.target == ":put_secure_browser_headers":
                    m = p.opts[0] if p.opts else None
                    if m is not None and re.search(r"[\"']content-security-policy[\"']", T(m), re.I):
                        here = here or at
                    elif phoenix and phoenix >= (1, 8, 0):
                        here = here or at   # Phoenix >= 1.8 sends a minimal CSP by default (module docstring)
                elif "ContentSecurityPolicy" in p.target or p.target in {"PlugContentSecurityPolicy"}:
                    here = at
                else:
                    m = modules.get(p.target)
                    if m is not None and re.search(r"[\"']content-security-policy[\"']", T(m.node), re.I):
                        here = at
            if here:
                yes.append(here)
            else:
                no += [f"{rel}:{p.line}" for p in r.pipelines[name] if p.target == ":put_secure_browser_headers"] or \
                      [f"{rel}:{L(r.pipeline_nodes[name])}"]
    if not routers:
        yes = [s[1] for s in out.signals.get("csp_header", [])]
    if yes:
        return obs(True, _ats(yes))
    if no:
        return obs(False, _ats(no))
    return []


def csrf(routers: list[Router], modules: dict) -> list[dict]:
    """State-changing routes behind a cookie session must pass through :protect_from_forgery (or Plug.CSRFProtection),
    in a pipeline or in the controller. LiveView routes are left out: their events arrive over the socket, whose
    connection Phoenix checks with the CSRF token when the session is shared."""
    protected, unprotected, protect_at, sessionless = [], [], [], []
    for r in routers:
        rel = r.module.file.rel
        for name, plugs in r.pipelines.items():
            for p in plugs:
                if p.target in {":protect_from_forgery", "Plug.CSRFProtection"}:
                    protect_at.append(f"{rel}:{p.line}")
        for route in r.routes:
            if route.verb in {"live", "forward"} or not route_writes(route):
                continue
            plugs = [p for name in route.pipelines for p in r.pipelines.get(name, [])]
            session = any(p.target in {":fetch_session", "Plug.Session"} for p in plugs)
            guard = any(p.target in {":protect_from_forgery", "Plug.CSRFProtection"} for p in plugs)
            ctrl = modules.get(route.controller or "")
            if ctrl is not None and any(mod_plug in {":protect_from_forgery", "Plug.CSRFProtection"} for mod_plug in
                                        (T(t) if t.type == "atom" else ctrl.resolve(T(t)) for t, _, _ in ctrl.plugs)):
                guard = True
            if not session:
                sessionless.append(route.at)
            elif guard:
                protected.append(route.at)
            else:
                unprotected.append(route.at)
    if unprotected:
        return obs(False, _ats(unprotected))
    if protected:
        return obs(True, _ats(protect_at or protected))
    if sessionless:
        return obs(True, _ats([f"{r.module.file.rel}:{L(r.module.node)}" for r in routers]))
    return []


def debug(entries: list[ConfigEntry], endpoints: list) -> list[dict]:
    ep = endpoint_entries(entries)
    on = []
    for key in ("debug_errors", "code_reloader"):
        found = effective(ep, lambda e: e.get(key))
        if found:
            e, v = found[-1]
            if boolean(v) is True:
                on.append(f"{e.rel}:{L(v)}")
            elif boolean(v) is None:
                return []   # computed at runtime: unknown
    if on:
        return obs(True, _ats(on))
    if any(e.env == "prod" or e.rel.endswith("runtime.exs") for e in ep):
        return obs(False, config_sites(entries, endpoints))
    return []


def log_filter(entries: list[ConfigEntry], deps: Deps) -> list[dict]:
    found = effective([e for e in entries if e.app == "phoenix"],
                      lambda e: e.value if e.key == "filter_parameters" else (e.get("filter_parameters") if e.key is None else None))
    if found:
        e, v = found[-1]
        at = f"{e.rel}:{L(v)}"
        if v.type == "tuple" and len(kids(v)) == 2 and atom(kids(v)[0]) == "keep":
            kept = word_list(kids(v)[1]) or []
            return obs(not any(re.search(r"pass|token|secret", k, re.I) for k in kept), [at])
        if v.type == "tuple" and len(kids(v)) == 2 and atom(kids(v)[0]) == "discard":
            v = kids(v)[1]
        filters = word_list(v) if v.type != "string" else [string(v) or ""]
        if filters is None:
            return []
        return obs(covers(filters), [at])
    if not deps.has("phoenix"):
        return []
    version = deps.version("phoenix")
    if not version:
        return []
    default = ["password", "token"] if version >= (1, 8, 7) else ["password"]
    return obs(covers(default), [deps.lock_at("phoenix")])


def covers(filters: list[str]) -> bool:
    """Password and token parameters are both filtered (a filter matches names that contain it)."""
    return all(any(f and f in word for f in filters) for word in ("password", "token"))


def mailers(entries: list[ConfigEntry], modules: dict, kinds: dict) -> dict:
    from .analyser import MAIL_ADAPTERS
    out = {}
    for name, m in modules.items():
        if "mailer" not in kinds.get(name, set()):
            continue
        found = effective([e for e in entries if e.key == name], lambda e: e.get("adapter"))
        if found:
            adapter = T(found[-1][1]).split(".")[-1]
            if adapter in MAIL_ADAPTERS:
                out[name] = MAIL_ADAPTERS[adapter]
    return out


def monitoring(entries: list[ConfigEntry], deps: Deps, endpoints: list, out: Collector) -> dict:
    """Error and performance monitoring configured for production (Sentry, AppSignal, ...): a Transfer at its config."""
    found = {}
    plug_context = any(m.resolve(T(t)) == "Sentry.PlugContext" for m in endpoints for t, _, _ in m.plugs)
    for app, (rec, dep) in sorted(MONITORING.items()):
        if not deps.has(dep):
            continue
        cfg = [e for e in entries if e.app == app and e.prod]
        if not cfg:
            continue
        with_dsn = [e for e in cfg if e.get("dsn") is not None or e.get("api_key") is not None or e.get("push_api_key") is not None
                    or e.get("license_key") is not None or e.get("access_token") is not None]
        if app == "appsignal" and not with_dsn:
            with_dsn = [e for e in cfg if e.key == "config"]
        if not with_dsn:
            continue
        e = sorted(with_dsn, key=lambda x: (x.order, L(x.node)))[-1]
        personal = True if app == "sentry" and plug_context else None   # request data and the client address
        out.element("Transfer", e.at, recipient=rec, personal_data=personal)
        found[rec] = e.at
    return found


def login_routes(routers: list[Router], modules: dict) -> dict:
    """(controller, action) -> [route locators] for POST routes that log a user in with a password."""
    out: dict = {}
    for r in routers:
        for route in r.routes:
            if route.verb not in {"post", "resources"} or not LOGIN_PATH.search(route.path):
                continue
            action = route.action or ("create" if route.verb == "resources" and "create" in route.actions else None)
            if action is None:
                continue
            ctrl = modules.get(route.controller or "")
            if ctrl is not None:
                fs = [f for f in ctrl.funcs if f.name == action]
                if not fs or not any(re.search(r"password", T(f.node)) for f in fs):
                    continue
            out.setdefault((route.controller, action), []).append(route.at)
    return out


def rate_limit_plugs(routers: list[Router], modules: dict, kinds: dict, logins: dict, endpoints: list, out: Collector):
    def limiter(name: str) -> bool:
        if name in RATE_LIMIT_PLUGS:
            return True
        m = modules.get(name)
        if m is None:
            return False
        return m.uses_any("PlugAttack", "Hammer", "Hammer.Plug") or bool(re.search(r"\b(Hammer|ExRated|PlugAttack)\.", T(m.node)))

    for m in endpoints:
        for t, _, node in m.plugs:
            if limiter(m.resolve(T(t))):
                out.signal("rate_limit", f"{m.file.rel}:{L(node)}", scope="global")
    login_by_route = {at: key for key, ats in logins.items() for at in ats}
    for r in routers:
        rel = r.module.file.rel
        for route in r.routes:
            if route.at not in login_by_route:
                continue
            for name in route.pipelines:
                for p in r.pipelines.get(name, []):
                    if limiter(p.target):
                        out.signal("rate_limit", f"{rel}:{p.line}", scope="login", route_at=route.at)
    for (ctrl, action), ats in logins.items():
        m = modules.get(ctrl or "")
        if m is None:
            continue
        for t, opts, node in m.plugs:
            name = m.resolve(T(t)) if t.type == "alias" else T(t)
            covered = True
            whole = T(node)
            if " when " in whole:
                covered = re.search(r":" + re.escape(action) + r"\b", whole.split(" when ", 1)[1]) is not None
            is_lim = limiter(name)
            if not is_lim and t.type == "atom":   # plug :rate_limit -> a local function that calls a limiter
                fn = [f for f in m.funcs if f.name == T(t)[1:]]
                is_lim = any(re.search(r"\b(Hammer|ExRated|PlugAttack|:fuse)\.|throttle|rate_limit", T(f.node)) for f in fn)
            if is_lim and covered:
                for at in ats:
                    out.signal("rate_limit", f"{m.file.rel}:{L(node)}", scope="login", route_at=at)


def data_export(an, out: Collector, routers: list[Router]) -> list[dict]:
    yes = []
    for f in an.funcs:
        if not (an.entry_positions(f) or ("controller" in an.kind(f.module) and not f.private)):
            continue
        name = f.name
        if EXPORT_FN.search(name) and (EXPORT_SUBJECT.search(name) or EXPORT_SUBJECT.search(f.module.name.split(".")[-1]
                                                                                          .replace("Controller", "").replace("Live", "").lower())):
            yes.append(f"{f.module.file.rel}:{f.line}")
        elif f.name == "handle_event" and f.params and re.search(r"[\"'](export|download)[_-]?(data|account|my_data)?[\"']", T(f.params[0])):
            yes.append(f"{f.module.file.rel}:{f.line}")
    if yes:
        return obs(True, _ats(yes))
    for r in routers:   # a JSON API that returns the signed-in user's own record may serve as the export: undecided
        for route in r.routes:
            if route.verb == "get" and re.search(r"/(me|users?/me|current_user|account|profile)(\.json)?/?$", route.path):
                return []
    personal = out.signals.get("personal_field", [])
    users = out.signals.get("user_model", [])
    if personal and users:
        return obs(False, _ats([s[1] for s in users], 4))
    return []

