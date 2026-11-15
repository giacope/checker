"""Deterministic static adapter for Elixir (Phoenix, Plug, Ecto): a codebase in, an evidence document (vocab/code.yaml) out.

Nothing from the analysed repository is compiled, evaluated, or installed: .ex/.exs files (including mix.exs and
config/*.exs) are parsed with the tree-sitter Elixir grammar, EEx/HEEx templates are scanned and the expressions in
them parsed the same way, mix.lock is read as text, and git metadata is read from files under .git without running
git. File discovery, the name classifiers, the collector, framework models, and the derivation of password-policy,
rate-limit, and personal-data facts are shared with adapters.code_static.

`sources[0].unparsed` lists Elixir files whose tree has syntax errors (tree-sitter recovers, and the rest of the file
is still analysed).
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from adapters.code_static import git_commit
from adapters.code_static.common import SOURCE, Collector
from adapters.code_static.config import scan_config, scan_key_file, scan_template
from adapters.code_static.facts import derive
from adapters.code_static.files import discover, read_text
from adapters.code_static.models import load_models

from . import system
from .analyser import Analyser, scan_template_raw
from .project import config_entries, read_deps, read_router
from .syntax import ExFile, expand_uses, index_file, module_kind, parser

VERSION = "0.1.0"
ADAPTER = "adapters.code_elixir"
TYPE_ORDER = ["PasswordStore", "Query", "Cookie", "TokenVerification", "Secret", "LogStatement", "Transfer",
              "CommandExecution", "HtmlOutput", "MassAssignment", "Deserialization"]
ATTR_ORDER = ["algorithm", "salted", "construction", "untrusted_input", "is_session", "secure", "http_only", "same_site",
              "verifies_signature", "allows_none_alg", "kind", "test_or_example", "logs_credentials", "logs_personal_data",
              "recipient", "personal_data", "third_country", "sanitized", "allowlist", "privileged_assignable", "safe_mode"]
FACT_ORDER = ["password_auth", "password_is_sole_factor", "password_min_length", "password_max_length",
              "password_composition_rules", "password_blocklist_check", "password_periodic_change", "login_rate_limited",
              "processes_personal_data", "account_erasure", "account_data_export", "csrf_protection", "tls_enforced",
              "hsts", "hsts_max_age", "content_security_policy", "debug_in_production", "log_redacts_credentials"]
ELIXIR_TEMPLATES = (".heex", ".eex", ".leex", ".sface")


def app_root(root: Path, rel: str) -> str:
    """The nearest directory above a file that holds a mix.exs ("" for the repository root)."""
    parts = rel.split("/")[:-1]
    for i in range(len(parts), 0, -1):
        if root.joinpath(*parts[:i], "mix.exs").is_file():
            return "/".join(parts[:i])
    return ""


def analyse(repo: str | Path, describes: str | None = None, models: list[str | Path] = ()) -> dict:
    """`models`: customer framework model files or directories (adapters/code_static/models.py, language elixir)."""
    root = Path(repo).resolve()
    fm = load_models(models)
    # database seeds are development data, read for Secret literals only, like examples,
    # and ExMachina factories (test data kept under lib/) are fixtures
    files = [replace(f, example=True) if f.rel.rsplit("/", 1)[-1] in {"seeds.exs", "factory.ex", "factories.ex"}
             or "/test/support/" in f"/{f.rel}" else f for f in discover(root)]
    out = Collector()
    p = parser()
    ex_files, templates, tomls, unparsed = [], [], [], []
    for f in files:
        text = read_text(f)
        if text is None:
            continue
        if f.kind == "ex":
            tree = p.parse(text.encode("utf-8"))
            if tree.root_node.has_error:
                unparsed.append(f.rel)
            ef = ExFile(f.rel, tree, text, f)
            index_file(ef)
            ex_files.append(ef)
        elif f.kind == "config":
            scan_config(f, text, out)
            if f.rel.rsplit("/", 1)[-1] == "fly.toml":
                tomls.append((f.rel, text))
        elif f.kind == "key":
            # phx.gen.cert writes a self-signed development key to priv/cert
            dev_cert = "priv/cert/" in f"/{f.rel}" or "selfsigned" in f.rel.lower()
            scan_key_file(replace(f, example=f.example or dev_cert), text, out)
        elif f.kind == "template":
            scan_template(f, text, out)
            if f.rel.lower().endswith(ELIXIR_TEMPLATES):
                templates.append((f, text))

    deps = read_deps(root, ex_files)
    entries = config_entries(ex_files)
    modules = {}
    for ef in ex_files:
        for m in ef.modules:
            modules.setdefault(m.name, m)
    expand_uses(modules)
    kinds = {name: module_kind(m) for name, m in modules.items()}
    endpoints = [m for name, m in sorted(modules.items()) if "endpoint" in kinds[name]]
    routers = [read_router(m) for name, m in sorted(modules.items()) if "router" in kinds[name]]
    tls = system.tls(entries, endpoints, routers, tomls)
    ctx = {"models": fm, "deps": deps, "tls_enforced": bool(tls["on"]),
           "mailers": system.mailers(entries, modules, kinds)}
    ctx["monitoring"] = system.monitoring(entries, deps, endpoints, out)

    an = Analyser(ex_files, ctx, out)
    an.login_actions = system.login_routes(routers, modules)
    for ats in an.login_actions.values():
        for at in ats:
            out.signal("login_route", at)
            out.signal("pw_auth", at)
    an.run()
    for f, text in templates:
        scan_template_raw(text, 0, f.rel, an, None)
    session_cookies(endpoints, an, out)
    system.rate_limit_plugs(routers, modules, kinds, an.login_actions, endpoints, out)

    def obs(value, at):  # an observation, naming the customer model whose rule produced it
        return {"value": value, "source": SOURCE, "at": at, **({"model": out.via[at]} if at in out.via else {})}

    elements = []
    for (type_, at), facts in out.elements.items():
        ordered = {k: [obs(facts[k], at)] for k in ATTR_ORDER if k in facts}
        elements.append({"type": type_, "id": f"{type_}@{at}", "at": at, "facts": ordered})

    def key(e):
        path, _, line = e["at"].rpartition(":")
        return (TYPE_ORDER.index(e["type"]), path, int(line))
    elements.sort(key=key)

    facts = derive(out, lambda rel: app_root(root, rel), lambda rel: False)
    hsts_obs, age_obs = [], []
    hsts_sites = list(tls["hsts"]) + [(True, s[1], s[0]) for s in out.signals.get("hsts_header", [])]
    if hsts_sites:
        hsts_obs = system.obs(True, [a for h, a, _ in hsts_sites if h]) + system.obs(False, [a for h, a, _ in hsts_sites if not h])
        age_obs = [o for h, a, age in hsts_sites if h and age for o in system.obs(age, [a])]
    elif endpoints or entries:
        hsts_obs = system.obs(False, system.config_sites(entries, endpoints))
    tls_obs = system.obs(True, sorted(set(tls["on"]))) if tls["on"] else (
        system.obs(False, system.config_sites(entries, endpoints)) if endpoints else [])
    extra = {
        "account_data_export": system.data_export(an, out, routers),
        "csrf_protection": system.csrf(routers, modules),
        "tls_enforced": tls_obs,
        "hsts": hsts_obs,
        "hsts_max_age": age_obs,
        "content_security_policy": system.csp(routers, deps, modules, out),
        "debug_in_production": system.debug(entries, endpoints),
        "log_redacts_credentials": system.log_filter(entries, deps),
    }
    for name, o in extra.items():
        if o and name not in facts:
            facts[name] = o
    facts = {k: facts[k] for k in FACT_ORDER if k in facts} | {k: v for k, v in facts.items() if k not in FACT_ORDER}
    for observations in facts.values():
        for o in observations:
            if o["at"] in out.via:
                o["model"] = out.via[o["at"]]
    source = {"id": SOURCE, "kind": "static_analysis", "describes": describes or root.name,
              "adapter": ADAPTER, "adapter_version": VERSION, "commit": git_commit(root),
              "files_analysed": len(files), "unparsed": sorted(unparsed)}
    if fm.sources:
        used = {}
        for m in out.via.values():
            used[m] = used.get(m, 0) + 1
        source["models"] = [{**m, "places": used.get(m["model"], 0)} for m in fm.sources]
    return {
        "subject": {"kind": "system", "id": describes or root.name},
        "sources": [source],
        "facts": facts,
        "elements": elements,
    }


def session_cookies(endpoints, an: Analyser, out: Collector):
    """The session cookie: `plug Plug.Session, @session_options` in the endpoint (store: :cookie or any other store;
    the cookie then carries the session id). Its flags follow put_resp_cookie's defaults (Plug.Session passes
    :secure, :http_only, :same_site, ... through to Plug.Conn.put_resp_cookie/4, plug lib/plug/session.ex)."""
    from .syntax import L, T, kw, unary
    for m in endpoints:
        for t, opts, node in m.plugs:
            if m.resolve(T(t)) != "Plug.Session" or not opts:
                continue
            o = opts[0]
            site = node
            if unary(o) == "@":
                v = m.attr(T(o.child_by_field_name("operand")), L(node))
                if v is None:
                    continue
                o, site = v, v
            if o.type not in {"keywords", "list"}:
                continue
            facts = {"is_session": True}
            an.cookie_flags(facts, kw(o), True)
            out.element("Cookie", f"{m.file.rel}:{L(site)}", **facts)
