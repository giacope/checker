"""Deterministic static adapter for Ruby (mainly Rails): a repository in, an evidence document (vocab/code.yaml) out.

Nothing from the analysed repository is loaded, required, installed, or executed: Ruby (including the Ruby inside ERB,
HAML, and Slim templates) is parsed with the tree-sitter Ruby grammar, YAML with PyYAML's composer (no object
construction), Gemfile and Gemfile.lock as text, and git metadata is read from files under .git without running git.
File discovery, name classifiers, the collector, and the derivation of password-policy, rate-limit, personal-data,
and erasure facts are shared with adapters.code_static; Rails configuration facts are in railsfacts.py.
"""

from __future__ import annotations

from pathlib import Path

from adapters.code_static import git_commit
from adapters.code_static.common import SOURCE, Collector, is_personal_name, is_record_field, is_user_object_name
from adapters.code_static.config import scan_template
from adapters.code_static.facts import derive
from adapters.code_static.files import discover, read_text
from adapters.code_static.models import load_models

from .analyser import Analyser
from .project import Project
from .railsfacts import system_facts
from .rb import RbFile, Taint, parser
from .templates import scan_config_file, scan_key, template_ruby

VERSION = "0.1.0"
ATTR_ORDER = ["algorithm", "salted", "construction", "untrusted_input", "is_session", "secure", "http_only", "same_site",
              "verifies_signature", "allows_none_alg", "kind", "test_or_example", "logs_credentials", "logs_personal_data",
              "recipient", "personal_data", "third_country", "sanitized", "allowlist", "privileged_assignable", "safe_mode"]
TYPE_ORDER = ["PasswordStore", "Query", "Cookie", "TokenVerification", "Secret", "LogStatement", "Transfer", "CommandExecution",
              "HtmlOutput", "MassAssignment", "Deserialization"]
SYSTEM_FACT_ORDER = ["csrf_protection", "tls_enforced", "hsts", "hsts_max_age", "content_security_policy", "debug_in_production",
                     "log_redacts_credentials", "account_data_export"]


def analyse(repo: str | Path, describes: str | None = None, models: list[str | Path] = ()) -> dict:
    """`models`: customer framework model files or directories (language: ruby), applied before the built-in ones."""
    root = Path(repo).resolve()
    fm = load_models(models)
    files = discover(root)
    out = Collector()
    p = parser()
    rb_files: list[RbFile] = []
    tpl_files: list[RbFile] = []
    unparsed: list[str] = []
    analysed = 0
    for f in files:
        if f.kind not in {"rb", "template", "config", "key"}:
            continue  # Python, JavaScript, Elixir: other adapters
        text = read_text(f)
        if text is None:
            continue
        analysed += 1
        if f.kind == "rb":
            rf = RbFile(f, text, p.parse(text.encode("utf-8")))
            rb_files.append(rf)
            if rf.unparsed:
                unparsed.append(f.rel)
        elif f.kind == "template":
            if not f.example:
                tpl_files += template_ruby(f, text, p)
                scan_template(f, text, out)
        elif f.kind == "config":
            scan_config_file(f, text, out)
        elif f.kind == "key":
            scan_key(f, text, out)
    project = Project(root)
    project.load(rb_files, lambda s: p.parse(s.encode("utf-8")))
    code = rb_files + tpl_files
    taint = Taint(code)
    taint.run()
    an = Analyser(project, code, fm, taint)
    an.prepare()
    an.run(out)
    _schema_signals(project, out)
    _devise_erasure(out)

    def obs(value, at):  # an observation, naming the customer model whose rule produced it
        return {"value": value, "source": SOURCE, "at": at, **({"model": out.via[at]} if at in out.via else {})}

    elements = []
    for (type_, at), fs in out.elements.items():
        ordered = {k: [obs(fs[k], at)] for k in ATTR_ORDER if k in fs and fs[k] is not None}
        elements.append({"type": type_, "id": f"{type_}@{at}", "at": at, "facts": ordered})

    def key(e):
        path, _, line = e["at"].rpartition(":")
        return (TYPE_ORDER.index(e["type"]), path, int(line))
    elements.sort(key=key)
    facts = derive(out, lambda rel: project.prefix.rstrip("/"))
    extra = system_facts(project, out, an, code)
    for name in SYSTEM_FACT_ORDER:
        if name in extra and name not in facts:
            facts[name] = extra[name]
    for observations in facts.values():
        for o in observations:
            if o["at"] in out.via:
                o["model"] = out.via[o["at"]]
    source = {"id": SOURCE, "kind": "static_analysis", "describes": describes or root.name,
              "adapter": "adapters.code_ruby", "adapter_version": VERSION, "commit": git_commit(root),
              "files_analysed": analysed, "unparsed": sorted(unparsed)}
    if fm.sources:
        used: dict = {}
        for m in out.via.values():
            used[m] = used.get(m, 0) + 1
        source["models"] = [{**m, "places": used.get(m["model"], 0)} for m in fm.sources if m["language"] == "ruby"]
    return {
        "subject": {"kind": "system", "id": describes or root.name},
        "sources": [source],
        "facts": facts,
        "elements": elements,
    }


def _schema_signals(project: Project, out: Collector):
    """Columns of the database schema that hold data about people."""
    for table in sorted(project.tables):
        owner = table[:-1] if table.endswith("s") else table
        for col, (_, at) in project.tables[table].items():
            if is_personal_name(col, owner) or (is_user_object_name(owner) and is_record_field(col)):
                out.signal("personal_field", at, model=True)


def _devise_erasure(out: Collector):
    """Devise :registerable routes registrations#destroy (a user deletes their own account) unless the routes skip it."""
    skipped = any("registrations" in s[2].get("skip", "") for s in out.signals.get("rb_devise_routes", []))
    if not skipped and out.signals.get("rb_devise_routes"):
        for s in out.signals.get("rb_devise_registerable", []):
            out.signal("user_delete", s[1])
