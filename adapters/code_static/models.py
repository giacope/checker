"""Framework models: what calls into a framework or library mean, written as data.

A model file tells the static adapter what an API does in vocab/code.yaml terms, so a framework the adapter's
code does not know (a customer's in-house platform library, a private package) is read without changing Python:

    model: acme-platform            # id recorded in the evidence
    version: "3.2"
    language: python                # python | javascript (JavaScript and TypeScript) | ruby | elixir
    rules:
      - call: acme_platform.crypto.hash_secret
        password_hash: {algorithm: argon2, salted: true, password: 0}
      - call: "*.run_sql"
        query: {text: 0}

`call` is the dotted name of the callee after import resolution (`from acme_platform import db; db.run_sql(...)` is
`acme_platform.db.run_sql`), or a list of them. In a pattern `*` matches within one segment and `**` any number of
segments, including none. `imported: true` matches only callees whose first name comes from an import. Arguments
are named by position (0, 1, ...) or, in Python, by keyword ("password"); a list tries each in turn.

One kind per rule:
  password_hash       {algorithm, salted: bool | infer, password: arg}       -> PasswordStore
  query               {text: arg} (construction from how the text is built) or {construction: orm | parameterized} -> Query
  token_verification  {verifies_signature, allows_none_alg}                  -> TokenVerification
  cookie              {is_session, secure, http_only, same_site, name: arg, options: {fact: keyword or option key}}
  log                 {}                                                     -> LogStatement (arguments are inspected)
  transfer            {recipient, personal_data: bool | infer, third_country} -> Transfer
  rate_limit          {scope: login | global}  a decorator, middleware, or app-wide limiter
  password_policy     {min_length, max_length, composition_rules, blocklist} a call that validates a new password
  erasure             {}  deletes a user's personal data (counts when a request can reach it)
  source              {}  returns request data (taint starts here)
  sanitizer           {}  returns a value request data cannot control (taint stops here)

Fact values are checked against vocab/code.yaml. Customer models are passed explicitly (`--models`); a repository
under review never supplies its own, since a model can declare a sanitizer or a rate limit and so clear a finding.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

import yaml

BUILTIN_DIR = Path(__file__).parent / "models"
VOCAB = Path(__file__).resolve().parents[2] / "vocab" / "code.yaml"
LANGUAGES = {"python", "javascript", "ruby", "elixir"}
ARG_KEYS = {"password", "text", "name"}
KINDS = {
    "password_hash": ("PasswordStore", {"algorithm", "salted", "password"}),
    "query": ("Query", {"text", "construction"}),
    "token_verification": ("TokenVerification", {"verifies_signature", "allows_none_alg"}),
    "cookie": ("Cookie", {"is_session", "secure", "http_only", "same_site", "name", "options"}),
    "log": ("LogStatement", set()),
    "transfer": ("Transfer", {"recipient", "personal_data", "third_country"}),
    "rate_limit": (None, {"scope"}),
    "password_policy": (None, {"min_length", "max_length", "composition_rules", "blocklist"}),
    "erasure": (None, set()),
    "source": (None, set()),
    "sanitizer": (None, set()),
}


@dataclass
class Rule:
    kind: str
    patterns: list[str]
    spec: dict
    model: str
    imported: bool = False
    builtin: bool = False


def _segments_match(pat: list[str], name: list[str]) -> bool:
    if not pat:
        return not name
    if pat[0] == "**":
        return any(_segments_match(pat[1:], name[i:]) for i in range(len(name) + 1))
    return bool(name) and fnmatchcase(name[0], pat[0]) and _segments_match(pat[1:], name[1:])


def matches(pattern: str, callee: list[str]) -> bool:
    """`callee` is [module or first name, member, ...]. A module name may itself hold dots ("socket.io",
    "../lib/db"), so the pattern's leading segments are tried together against it."""
    pat = pattern.split(".")
    if pat[0] == "**":
        return _segments_match(pat, callee)
    return bool(callee) and any(fnmatchcase(callee[0], ".".join(pat[:k])) and _segments_match(pat[k:], callee[1:])
                                for k in range(1, len(pat) + 1))


@dataclass
class Models:
    rules: dict[str, list[Rule]] = field(default_factory=dict)   # language -> rules
    sources: list[dict] = field(default_factory=list)            # customer model files, for the evidence record
    matched: dict[str, int] = field(default_factory=dict)        # model id -> rule matches
    _cache: dict = field(default_factory=dict)

    def match(self, lang: str, callee: tuple[list[str], bool], kind: str) -> Rule | None:
        """The first rule of `kind` naming the callee: ([module or first name, member, ...], head is imported)."""
        segs, imported = callee
        if not segs or not segs[0]:
            return None
        key = (lang, tuple(segs), kind, imported)
        if key not in self._cache:
            self._cache[key] = next((r for r in self.rules.get(lang, []) if r.kind == kind and (imported or not r.imported)
                                     and any(matches(p, segs) for p in r.patterns)), None)
        return self._cache[key]

    def used(self, rule: Rule) -> None:
        if not rule.builtin:
            self.matched[rule.model] = self.matched.get(rule.model, 0) + 1


def _vocab() -> dict:
    return yaml.safe_load(VOCAB.read_text())["types"]


def _check_value(vocab: dict, type_: str, attr: str, v, where: str) -> None:
    a = vocab[type_]["attrs"].get(attr)
    if a is None:
        raise ValueError(f"{where}: {type_} has no attribute '{attr}' in vocab/code.yaml")
    if a["type"] == "bool" and not (isinstance(v, bool) or (v == "infer" and attr in {"salted", "personal_data"})):
        raise ValueError(f"{where}: {type_}.{attr} must be true or false" + (" or infer" if attr in {"salted", "personal_data"} else ""))
    if a["type"] == "enum" and v not in a["values"]:
        raise ValueError(f"{where}: {type_}.{attr} must be one of {a['values']}, not {v!r}")
    if a["type"] == "text" and not isinstance(v, str):
        raise ValueError(f"{where}: {type_}.{attr} must be text")


def _check_arg(v, where: str) -> None:
    vs = v if isinstance(v, list) else [v]
    if not vs or not all(isinstance(x, (int, str)) and not isinstance(x, bool) for x in vs):
        raise ValueError(f"{where}: an argument is a position (0, 1, ...) or a keyword name, or a list of them")


def parse(doc: dict, origin: str, builtin: bool = False) -> tuple[str, str, list[Rule]]:
    """Validate one model document; (language, model id, rules)."""
    vocab = _vocab()
    for k in ("model", "language", "rules"):
        if k not in doc:
            raise ValueError(f"{origin}: missing '{k}'")
    unknown = set(doc) - {"model", "version", "language", "description", "rules"}
    if unknown:
        raise ValueError(f"{origin}: unknown keys {sorted(unknown)}")
    lang = doc["language"]
    if lang not in LANGUAGES:
        raise ValueError(f"{origin}: language must be one of {sorted(LANGUAGES)}")
    mid = str(doc["model"]) + (f"@{doc['version']}" if doc.get("version") is not None else "")
    rules = []
    for i, r in enumerate(doc["rules"] or []):
        where = f"{origin} rule {i + 1}"
        if not isinstance(r, dict) or "call" not in r:
            raise ValueError(f"{where}: needs 'call'")
        kinds = [k for k in r if k in KINDS]
        extra = set(r) - set(KINDS) - {"call", "imported", "note"}
        if len(kinds) != 1 or extra:
            raise ValueError(f"{where}: give exactly one of {sorted(KINDS)}" + (f"; unknown keys {sorted(extra)}" if extra else ""))
        kind = kinds[0]
        spec = r[kind] or {}
        type_, allowed = KINDS[kind]
        if not isinstance(spec, dict) or set(spec) - allowed:
            raise ValueError(f"{where}: {kind} takes {sorted(allowed) or 'no settings'}")
        for k, v in spec.items():
            if k in ARG_KEYS:
                _check_arg(v, f"{where} {k}")
            elif k == "options":
                if not isinstance(v, dict) or set(v) - {"secure", "http_only", "same_site"}:
                    raise ValueError(f"{where}: cookie options map secure, http_only, same_site to keyword or option names")
            elif kind == "query" and k == "construction":
                if v not in {"orm", "parameterized"}:
                    raise ValueError(f"{where}: a query rule with a fixed construction is orm or parameterized; use text: <arg> to classify")
            elif kind == "rate_limit":
                if v not in {"login", "global"}:
                    raise ValueError(f"{where}: rate_limit scope is login or global")
            elif kind == "password_policy":
                if k.endswith("_length") and not (isinstance(v, int) and not isinstance(v, bool) and v >= 0):
                    raise ValueError(f"{where}: {k} is a whole number of characters")
                if not k.endswith("_length") and not isinstance(v, bool):
                    raise ValueError(f"{where}: {k} is true or false")
            elif type_:
                _check_value(vocab, type_, k, v, where)
        if kind == "password_hash" and not {"algorithm", "salted"} <= set(spec):
            raise ValueError(f"{where}: password_hash needs algorithm and salted")
        if kind == "query" and len({"text", "construction"} & set(spec)) != 1:
            raise ValueError(f"{where}: query needs either text (an argument) or construction")
        if kind == "transfer" and "recipient" not in spec:
            raise ValueError(f"{where}: transfer needs recipient")
        pats = r["call"] if isinstance(r["call"], list) else [r["call"]]
        if not pats or not all(isinstance(p, str) and p for p in pats):
            raise ValueError(f"{where}: call is a dotted name or a list of them")
        rules.append(Rule(kind, pats, spec, mid, bool(r.get("imported")), builtin))
    return lang, mid, rules


def load_models(paths: list[str | Path] = ()) -> Models:
    """The built-in models, then customer model files in the order given (a customer rule is tried first)."""
    m = Models()
    customer: dict[str, list[Rule]] = {}
    for p in sorted(BUILTIN_DIR.glob("*.yaml")):
        lang, _, rules = parse(yaml.safe_load(p.read_text()), p.name, builtin=True)
        m.rules.setdefault(lang, []).extend(rules)
    files = []
    for p in paths:
        p = Path(p)
        files += sorted(p.glob("*.yaml")) + sorted(p.glob("*.yml")) if p.is_dir() else [p]
    for f in files:
        raw = f.read_bytes()
        lang, mid, rules = parse(yaml.safe_load(raw), str(f))
        customer.setdefault(lang, []).extend(rules)
        m.sources.append({"model": mid, "language": lang, "file": f.name, "sha256": hashlib.sha256(raw).hexdigest(),
                          "rules": len(rules)})
    for lang, rules in customer.items():
        m.rules[lang] = rules + m.rules.get(lang, [])
    return m


def arg(spec, args: list, keywords: dict | None = None):
    """The argument a spec names: a position, a keyword, or the first of a list that is present."""
    for s in spec if isinstance(spec, list) else [spec]:
        if isinstance(s, int) and s < len(args):
            return args[s]
        if isinstance(s, str) and keywords and s in keywords:
            return keywords[s]
    return None

