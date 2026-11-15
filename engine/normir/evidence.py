"""Evidence documents, reconciliation, and checks over value sets.

This module is domain-neutral: a building model and a codebase reach the kernel
the same way.

An *evidence document* is what one adapter or one reader extracted from one
source (an IFC model, a drawing set, a static analysis, a model reading the code):

    subject: {kind: building|system|..., id: "..."}
    sources: [{id: ifc, kind: model, describes: "Clinic_A_20110906.ifc"}]
    facts:                        # about the subject as a whole
      sprinkler_system: [{value: nfpa13, source: drawings, at: "A18-1 note 1"}]
    elements:
      - {type: Stair, id: "3NhaIUfh12PAdrGa$S3z3M", at: "ifc:3NhaIUfh12PAdrGa$S3z3M",
         facts: {width: [{value: 1000 mm, source: ifc, at: "PSet_Revit_Dimensions.Width"}]}}

Each fact is a list of observations. Several documents are *reconciled* into one:
observations of the same fact are pooled, so a fact holds every value some source
supports. A fact no source mentions is open. Elements from different sources are the
same element when their ids match, or, for code locators, when they are in the same
file within a few lines.

`check` evaluates a norm on every combination of the values in its facts' sets:
pass or fail when every combination agrees (certified), uncertain when the
combinations disagree (and the facts whose values flip it are named), unknown when a
fact the norm needs is open.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from .evaluate import Evaluator, Residual, facts_in
from .model import Ruleset
from .quantity import Quantity

LINE_TOLERANCE = 5
MAX_COMBINATIONS = 4096
CODE_LOCATOR = re.compile(r"^(?P<path>[^:]+):(?P<line>\d+)$")


def _key(v: Any) -> Any:
    """Canonical form, so 1210 mm and 1.21 m are the same value."""
    if isinstance(v, str):
        q = Quantity.parse(v)
        if q is not None:
            return ("q", round(q.base, 6), q.dim)
    return ("v", v)


@dataclass
class Fact:
    """A value set: every value some source supports, with who supports it."""

    observations: list[dict] = field(default_factory=list)
    overridden: list[dict] = field(default_factory=list)  # observations a preferred source outranked (prefer_sources)

    def values(self) -> list:
        seen, out = set(), []
        for o in self.observations:
            k = _key(o["value"])
            if k not in seen:
                seen.add(k)
                out.append(o["value"])
        return out

    def sources_of(self, value: Any) -> list[str]:
        return [f"{o.get('source', '?')}" + (f" @ {o['at']}" if o.get("at") else "") for o in self.observations if _key(o["value"]) == _key(value)]

    def conflict(self) -> bool:
        """Sources disagree. Several values from one source are a range, not a conflict."""
        by_source: dict[str, set] = {}
        for o in self.observations:
            by_source.setdefault(o.get("source", "?"), set()).add(_key(o["value"]))
        return len(by_source) > 1 and len({frozenset(v) for v in by_source.values()}) > 1


@dataclass
class Element:
    type: str
    id: str
    at: list[str]
    facts: dict[str, Fact]
    sources: set[str]


@dataclass
class Evidence:
    subject: dict
    facts: dict[str, Fact]
    elements: list[Element]
    sources: list[dict]


def _facts(raw: dict | None, default_source: str) -> dict[str, Fact]:
    out = {}
    for name, obs in (raw or {}).items():
        if not isinstance(obs, list):
            obs = [{"value": obs}]
        out[name] = Fact([{**o, "source": o.get("source", default_source)} for o in obs])
    return out


def _same(a: Element, b: Element) -> bool:
    if a.type != b.type:
        return False
    if a.id == b.id:
        return True
    # Only locators an adapter wrote: an element without `at` takes its id as locator, and ids such as
    # "door:101" and "door:102" are not code locations a line apart.
    for x in a.at if a.at != [a.id] else []:
        mx = CODE_LOCATOR.match(x)
        for y in b.at if b.at != [b.id] else []:
            my = CODE_LOCATOR.match(y)
            if mx and my and mx["path"] == my["path"] and abs(int(mx["line"]) - int(my["line"])) <= LINE_TOLERANCE:
                return True
    return False


def load_evidence(*docs: str | Path | dict) -> Evidence:
    """Read evidence documents and reconcile them into one."""
    subject: dict = {}
    facts: dict[str, Fact] = {}
    elements: list[Element] = []
    sources: list[dict] = []
    for doc in docs:
        d = doc if isinstance(doc, dict) else yaml.safe_load(Path(doc).read_text())
        src = [s["id"] for s in d.get("sources", [])] or ["unnamed"]
        sources += d.get("sources", [])
        subject = subject or d.get("subject", {})
        for name, f in _facts(d.get("facts"), src[0]).items():
            facts.setdefault(name, Fact()).observations += f.observations
        for e in d.get("elements", []):
            at = e.get("at", [e["id"]])
            new = Element(e["type"], str(e["id"]), at if isinstance(at, list) else [at], _facts(e.get("facts"), src[0]), set(src))
            match = next((x for x in elements if _same(x, new)), None)
            if match is None:
                elements.append(new)
                continue
            match.at += [a for a in new.at if a not in match.at]
            match.sources |= new.sources
            for name, f in new.facts.items():
                match.facts.setdefault(name, Fact()).observations += f.observations
    return Evidence(subject, facts, elements, sources)


def _source_kind(source: str) -> str:
    """'llm:claude-opus-5-5#2' -> 'llm'; 'static' -> 'static'."""
    return str(source).split(":", 1)[0].split("#", 1)[0]


def prefer_sources(ev: Evidence, rank: Callable[[str, str], list[str]]) -> Evidence:
    """Resolve facts the sources disagree on by precedence instead of pooling.

    `rank(type, attr)` lists source kinds best first (type is "subject" for subject facts), for example
    ["static", "llm"] for a measured fact and ["llm", "static"] for a judged one. Where the best-ranked source
    that observed a fact has observations, only those are kept; the rest move to `Fact.overridden`, so
    `conflicts` still reports them. Sources not in the list keep pooling with the winner. Pooling every source
    widens each value set and turns a wrong observation from any one source into an uncertain verdict; the code
    benchmark (bench/code_check.py) measured that, which is why precedence exists.
    """
    def resolve(type_: str, attr: str, f: Fact) -> Fact:
        order = rank(type_, attr) or []
        present = {_source_kind(o.get("source", "?")) for o in f.observations}
        best = next((k for k in order if k in present), None)
        if best is None:
            return Fact(list(f.observations), list(f.overridden))
        keep = [o for o in f.observations if _source_kind(o.get("source", "?")) == best or _source_kind(o.get("source", "?")) not in order]
        drop = [o for o in f.observations if o not in keep]
        return Fact(keep, list(f.overridden) + drop)

    facts = {k: resolve("subject", k, f) for k, f in ev.facts.items()}
    elements = [Element(e.type, e.id, list(e.at), {k: resolve(e.type, k, f) for k, f in e.facts.items()}, set(e.sources)) for e in ev.elements]
    return Evidence(ev.subject, facts, elements, ev.sources)


def rank_by_kind(vocab: dict, prefer: dict[str, list[str]]) -> Callable[[str, str], list[str]]:
    """A `prefer_sources` ranking from a vocabulary file's attribute kinds (measured, judged, given):
    `prefer` maps a kind to source kinds, best first. Subject facts use the vocabulary's subject type."""
    kinds = {(t, a): spec.get("kind") for t, td in vocab["types"].items() for a, spec in (td.get("attrs") or {}).items()}
    subject = vocab.get("subject", "system")
    return lambda type_, attr: prefer.get(kinds.get((subject if type_ == "subject" else type_, attr)), [])


def _vocab_map(rs: Ruleset, type_name: str) -> dict[str, str]:
    """Evidence attribute -> pack attribute, for packs that name a vocabulary attribute differently."""
    out = {}
    for (kind, name), el in rs.elements.items():
        if kind == "predicate" and name.startswith(type_name + "."):
            vocab = el.data.get("vocab")
            out[(vocab or name).split(".", 1)[1]] = name.split(".", 1)[1]
    return out


def check(rs: Ruleset, norm: str, subject: dict[str, Fact], instance: dict[str, Fact] | None = None) -> dict:
    """Evaluate one norm over every combination of the values the evidence allows."""
    fixed_s = {k: f.values()[0] for k, f in subject.items() if len(f.values()) == 1}
    fixed_i = {k: f.values()[0] for k, f in (instance or {}).items() if len(f.values()) == 1}
    varying = [("s", k, f) for k, f in subject.items() if len(f.values()) > 1]
    varying += [("i", k, f) for k, f in (instance or {}).items() if len(f.values()) > 1]
    # Only enumerate facts the norm can read: evaluate with the varying facts left open.
    probe = Evaluator(rs, fixed_s).norm(norm, fixed_i if instance is not None else None)
    if isinstance(probe, Residual):
        needed = set(facts_in(probe.expr))
        varying = [v for v in varying if any(n.endswith("." + v[1]) for n in needed)]
    else:
        varying = []
    combos = list(itertools.product(*(f.values() for _, _, f in varying)))[:MAX_COMBINATIONS]
    results: dict[str, list[tuple]] = {}
    open_facts: set[str] = set()
    for combo in combos:
        s, i = dict(fixed_s), dict(fixed_i)
        for (where, k, _), v in zip(varying, combo):
            (s if where == "s" else i)[k] = v
        r = Evaluator(rs, s).norm(norm, i if instance is not None else None)
        if isinstance(r, Residual):
            open_facts |= set(facts_in(r.expr))
            r = "unknown"
        results.setdefault(str(r), []).append(combo)
    outcomes = {k: len(v) for k, v in results.items()}
    if "unknown" in results:
        verdict = "unknown"
    elif len(results) == 1:
        verdict = "pass" if "True" in results else "fail"
    else:
        verdict = "uncertain"
    deciding = []
    if len(results) > 1:
        for j, (_, k, _) in enumerate(varying):
            groups: dict[tuple, set] = {}
            for r, cs in results.items():
                for c in cs:
                    groups.setdefault(c[:j] + c[j + 1:], set()).add(r)
            if any(len(g) > 1 for g in groups.values()):
                deciding.append(k)
    named = {k: f for _, k, f in varying}
    return {
        "verdict": verdict,
        "outcomes": outcomes,
        "deciding": {k: [{"value": str(v), "sources": named[k].sources_of(v)} for v in named[k].values()] for k in deciding},
        "open": sorted(open_facts),
    }


def _profile_facts(raw: dict) -> dict[str, Fact]:
    return {k: Fact([{"value": x, "source": "profile"} for x in (v if isinstance(v, list) else [v])]) for k, v in raw.items()}


def run(rs: Ruleset, ev: Evidence, profile: dict | None = None) -> list[dict]:
    """Check the norms of a pack against reconciled evidence.

    `profile` is one more source: the jurisdiction's classifications, which
    adapters do not produce. Its keys are
      - lowercase fact names, or a map under the pack's subject name ("building",
        "system"): facts about the subject;
      - a type name ("Stair"): facts added to every element of that type;
      - "elements": {element id: facts} for one element;
      - "norms": the norms to check (default: all).
    A list value is a value set: the classification is open between those values.
    A profile value replaces what the evidence says about that fact.
    """
    profile = dict(profile or {})
    only = profile.pop("norms", None)
    per_element = profile.pop("elements", {}) or {}
    per_type = {k: profile.pop(k) for k in list(profile) if k[:1].isupper()}
    subject_raw = profile.pop(rs.subject, {}) or {}
    subject_raw.update(profile)
    subject = {k: Fact(list(f.observations)) for k, f in ev.facts.items()}
    subject.update(_profile_facts(subject_raw))
    rows = []
    for (kind, name), el in sorted(rs.elements.items(), key=lambda kv: kv[0][1]):
        if kind != "norm" or (only is not None and name not in only):
            continue
        base = {"norm": name, "title": el.data.get("title", name), "section": el.data["cite"].get("section"), "url": el.data["cite"].get("url")}
        types = list((el.data.get("for") or {}).values())
        if not types:
            # A system-level norm is located where the facts it reads were observed.
            probe = Evaluator(rs, {}).norm(name, None)
            reads = list(dict.fromkeys(facts_in(probe.expr))) if isinstance(probe, Residual) else []
            keys = [k for n in reads for k in [n.rpartition(".")[2]] if k in subject]
            # Facts that are simply true (password_auth, processes_personal_data) usually only make the
            # norm apply; cite the facts that carry the requirement first.
            keys.sort(key=lambda k: subject[k].values() == [True])
            per_fact = [[o["at"] for o in subject[k].observations if o.get("at")] for k in keys]
            # One locator of each fact in turn, so the first few cite every fact the verdict rests on.
            at = list(dict.fromkeys(a for tier in itertools.zip_longest(*per_fact) for a in tier if a))
            rows.append({**base, "element": ev.subject.get("id", "subject"), "at": at, **check(rs, name, subject)})
            continue
        vmap = _vocab_map(rs, types[0])
        for e in ev.elements:
            if e.type != types[0]:
                continue
            inst = {vmap.get(k, k): f for k, f in e.facts.items()}
            for extra in (per_type.get(e.type, {}), per_element.get(e.id, {})):
                inst.update({vmap.get(k, k): f for k, f in _profile_facts(extra).items()})
            rows.append({**base, "element": e.id, "type": e.type, "at": e.at, "seen_by": sorted(e.sources), **check(rs, name, subject, inst)})
    return rows


def summarize(rows: list[dict]) -> dict[str, dict]:
    """One verdict per norm: fail if any element fails, then uncertain, then unknown;
    pass if every element passes; not_applicable when no element is of the norm's type."""
    out: dict[str, dict] = {}
    for r in rows:
        s = out.setdefault(r["norm"], {"verdicts": {}, "failing": [], "uncertain": []})
        s["verdicts"][r["verdict"]] = s["verdicts"].get(r["verdict"], 0) + 1
        if r["verdict"] == "fail":
            s["failing"] += r.get("at") or [r["element"]]
        if r["verdict"] in ("uncertain", "unknown"):
            s["uncertain"].append({"element": r["element"], "at": r.get("at"), "deciding": list(r["deciding"]) or r["open"]})
    for s in out.values():
        v = s["verdicts"]
        s["verdict"] = next((x for x in ("fail", "uncertain", "unknown") if x in v), "pass")
    return out


def conflicts(ev: Evidence) -> list[dict]:
    """Facts on which sources disagree, including disagreements prefer_sources resolved (with `overridden`)."""
    def row(f: Fact) -> dict:
        r = {"values": [{"value": str(v), "sources": f.sources_of(v)} for v in f.values()]}
        if f.overridden:
            used = {_key(v) for v in f.values()}
            r["overridden"] = [{"value": str(o["value"]), "sources": [f"{o.get('source', '?')}" + (f" @ {o['at']}" if o.get("at") else "")]}
                               for o in f.overridden if _key(o["value"]) not in used]
        return r

    def disputed(f: Fact) -> bool:
        return f.conflict() or bool(row(f).get("overridden"))
    out = [{"element": "subject", "fact": k, **row(f)} for k, f in ev.facts.items() if disputed(f)]
    for e in ev.elements:
        out += [{"element": e.id, "type": e.type, "fact": k, **row(f)} for k, f in e.facts.items() if disputed(f)]
    return out
