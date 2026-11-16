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
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from .evaluate import NOT_APPLICABLE, Evaluator, Residual, facts_in, met_if_applicable
from .model import Ruleset, walk
from .quantity import Quantity

LINE_TOLERANCE = 5
MAX_COMBINATIONS = 4096  # enumerated in full below this; split fact by fact above it
MAX_EVALUATIONS = 200_000
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


def _distance(a: Element, b: Element) -> int | None:
    """How far apart two elements of one type are: 0 for the same id, else the fewest lines between two of their
    code locators in one file, when that is within LINE_TOLERANCE; None when they are not the same element."""
    if a.type != b.type:
        return None
    if a.id == b.id:
        return 0
    # Only locators an adapter wrote: an element without `at` takes its id as locator, and ids such as
    # "door:101" and "door:102" are not code locations a line apart.
    best = None
    for x in a.at if a.at != [a.id] else []:
        mx = CODE_LOCATOR.match(x)
        for y in b.at if b.at != [b.id] else []:
            my = CODE_LOCATOR.match(y)
            if mx and my and mx["path"] == my["path"]:
                d = abs(int(mx["line"]) - int(my["line"]))
                if d <= LINE_TOLERANCE and (best is None or d < best):
                    best = d
    return best


def load_evidence(*docs: str | Path | dict) -> Evidence:
    """Read evidence documents and reconcile them into one."""
    subject: dict = {}
    facts: dict[str, Fact] = {}
    elements: list[Element] = []
    sources: list[dict] = []
    origin: dict[int, set[int]] = {}   # id(element) -> the documents it came from
    for n, doc in enumerate(docs):
        d = doc if isinstance(doc, dict) else yaml.safe_load(Path(doc).read_text())
        src = [s["id"] for s in d.get("sources", [])] or ["unnamed"]
        sources += d.get("sources", [])
        subject = subject or d.get("subject", {})
        for name, f in _facts(d.get("facts"), src[0]).items():
            facts.setdefault(name, Fact()).observations += f.observations
        for e in d.get("elements", []):
            at = e.get("at", [e["id"]])
            new = Element(e["type"], str(e["id"]), at if isinstance(at, list) else [at], _facts(e.get("facts"), src[0]), set(src))
            # The same id is the same element. Nearby lines are only how two documents describe one element (a
            # reader's query at line 9, the static analyser's at line 8); within one document two elements are two,
            # however close, and an element joins the nearest match.
            near = [(dist, i) for i, x in enumerate(elements)
                    if (dist := _distance(x, new)) is not None and (dist == 0 or n not in origin[id(x)])]
            if not near:
                elements.append(new)
                origin[id(new)] = {n}
                continue
            match = elements[min(near)[1]]
            origin[id(match)].add(n)
            match.at += [a for a in new.at if a not in match.at]
            match.sources |= new.sources
            for name, f in new.facts.items():
                match.facts.setdefault(name, Fact()).observations += f.observations
    return Evidence(subject, facts, elements, sources)


def _source_kind(source: str) -> str:
    """'llm:claude-opus-5-5#2' -> 'llm'; 'static' -> 'static'."""
    return str(source).split(":", 1)[0].split("#", 1)[0]


def prefer_sources(ev: Evidence, rank: Callable[[str, str], list[str]], narrow: bool = False) -> Evidence:
    """Resolve facts the sources disagree on by precedence instead of pooling.

    `rank(type, attr)` lists source kinds best first (type is "subject" for subject facts), for example
    ["static", "llm"] for a measured fact and ["llm", "static"] for a judged one. Where the best-ranked source
    that observed a fact has observations, only those are kept; the rest move to `Fact.overridden`, so
    `conflicts` still reports them. Sources not in the list keep pooling with the winner. Pooling every source
    widens each value set and turns a wrong observation from any one source into an uncertain verdict; the code
    benchmark (bench/code_check.py) measured that, which is why precedence exists.

    With `narrow`, where the best source's own observations disagree (one site measured true, another false),
    the next-ranked source that holds some but not all of those values narrows the fact to them: it can choose
    among what the best source saw, never add a value. The code benchmark measured that too.
    """
    def resolve(type_: str, attr: str, f: Fact) -> Fact:
        order = rank(type_, attr) or []
        kind = lambda o: _source_kind(o.get("source", "?"))  # noqa: E731
        present = {kind(o) for o in f.observations}
        best = next((k for k in order if k in present), None)
        if best is None:
            return Fact(list(f.observations), list(f.overridden))
        keep = [o for o in f.observations if kind(o) == best or kind(o) not in order]
        if narrow:
            seen = {_key(o["value"]) for o in f.observations if kind(o) == best}
            for k in order[order.index(best) + 1:]:
                theirs = {_key(o["value"]) for o in f.observations if kind(o) == k}
                if len(seen) > 1 and theirs and theirs < seen:
                    keep = [o for o in keep if kind(o) not in order or _key(o["value"]) in theirs] + \
                           [o for o in f.observations if kind(o) == k]
                    break
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


class _Budget(Exception):
    pass


def _evaluate(rs: Ruleset, norm: str, s: dict, i: dict | None, none: bool = False) -> Any:
    """One evaluation; a rule that cannot be evaluated on these values (a length compared with a symbol, a
    division by zero) is an error string, so one bad rule never stops the others."""
    try:
        return Evaluator(rs, s).norm(norm, i, none=none)
    except (TypeError, ValueError, ZeroDivisionError, KeyError, ArithmeticError) as e:
        return _Error(f"{type(e).__name__}: {e}")


@dataclass(frozen=True)
class _Error:
    message: str


def check(rs: Ruleset, norm: str, subject: dict[str, Fact], instance: dict[str, Fact] | None = None, none: bool = False) -> dict:
    """Evaluate one norm over every combination of the values the evidence allows.

    Verdict: pass or fail when every combination gives it, uncertain when they differ, unknown when a fact the
    norm needs is open. Up to MAX_COMBINATIONS combinations are enumerated, which also names the facts whose
    value flips the verdict. Past that, the combinations are split fact by fact, evaluating each partial
    assignment and stopping where the rule is already decided: exact, without enumerating the decided parts.
    If even that exceeds MAX_EVALUATIONS, or the rule cannot be evaluated, the verdict is unknown (uncertain if
    both outcomes were already seen) with a reason in `error`: never a pass or a fail that wasn't shown.
    """
    inst_type = next(iter((rs.get("norm", norm).data.get("for") or {}).values()), None)
    fixed_s = {k: f.values()[0] for k, f in subject.items() if len(f.values()) == 1}
    fixed_i = {k: f.values()[0] for k, f in (instance or {}).items() if len(f.values()) == 1}
    varying = [("s", k, f) for k, f in subject.items() if len(f.values()) > 1]
    varying += [("i", k, f) for k, f in (instance or {}).items() if len(f.values()) > 1]
    keyed = {(w, k): (f"{rs.subject}.{k}" if w == "s" else f"{inst_type}.{k}") for w, k, _ in varying}
    # Only enumerate facts the norm can read: evaluate with the varying facts left open.
    probe = _evaluate(rs, norm, fixed_s, fixed_i if instance is not None else None, none)
    if isinstance(probe, Residual):
        needed = set(facts_in(probe.expr))
        varying = [v for v in varying if keyed[(v[0], v[1])] in needed]
    else:
        varying = []
    total = math.prod(len(f.values()) for _, _, f in varying)
    results: dict[str, list[tuple]] = {}
    counts: dict[str, int] = {}
    open_facts: set[str] = set()
    errors: list[str] = []
    deciding: list[str] = []

    def outcome(r: Any) -> str:
        if isinstance(r, _Error):
            errors.append(r.message)
            return "error"
        if isinstance(r, Residual) and met_if_applicable(r.expr):
            return "True"
        if isinstance(r, Residual):
            nodes = list(walk(r.expr))
            needs = sorted({n["fact"] for n in nodes if "fact" in n})
            bad = [n["invalid"] for n in nodes if "invalid" in n]
            errors.extend(bad[:1])
            if bad and not needs:  # rests only on a part that cannot be evaluated
                return "error"
            open_facts.update(needs)
            return "unknown"
        return str(r)

    if total <= MAX_COMBINATIONS:
        for combo in itertools.product(*(f.values() for _, _, f in varying)):
            s, i = dict(fixed_s), dict(fixed_i)
            for (where, k, _), v in zip(varying, combo):
                (s if where == "s" else i)[k] = v
            results.setdefault(outcome(_evaluate(rs, norm, s, i if instance is not None else None, none)), []).append(combo)
        counts = {k: len(v) for k, v in results.items()}
        if len(results) > 1:
            for j, (_, k, _) in enumerate(varying):
                groups: dict[tuple, set] = {}
                for r, cs in results.items():
                    for c in cs:
                        groups.setdefault(c[:j] + c[j + 1:], set()).add(r)
                if any(len(g) > 1 for g in groups.values()):
                    deciding.append(k)
    else:
        budget = [MAX_EVALUATIONS]

        def split(s: dict, i: dict, rest: list, weight: int) -> set[str]:
            budget[0] -= 1
            if budget[0] < 0:
                raise _Budget
            r = _evaluate(rs, norm, s, i if instance is not None else None, none)
            needed = set(facts_in(r.expr)) if isinstance(r, Residual) else set()
            j = next((n for n, (w, k, _) in enumerate(rest) if keyed[(w, k)] in needed), None)
            if j is None:  # decided, or open only on facts no source gave: the same for every value of the rest
                o = outcome(r)
                counts[o] = counts.get(o, 0) + weight
                return {o}
            w, k, f = rest[j]
            vals = f.values()
            seen = [split({**s, k: v} if w == "s" else s, {**i, k: v} if w == "i" else i, rest[:j] + rest[j + 1:], weight // len(vals))
                    for v in vals]
            if len({frozenset(x) for x in seen}) > 1 and k not in deciding:
                deciding.append(k)
            return set().union(*seen)
        try:
            split(dict(fixed_s), dict(fixed_i), varying, total)
        except _Budget:
            errors.append(f"more than {MAX_EVALUATIONS} evaluations needed to cover {total} combinations of the evidence")
            counts["incomplete"] = total - sum(counts.values())
    seen = set(counts) - {"incomplete"}
    if "error" in seen or "incomplete" in counts:
        verdict = "uncertain" if {"True", "False"} <= seen else "unknown"
    elif "unknown" in seen:
        verdict = "unknown"
    elif seen == {NOT_APPLICABLE}:
        verdict = "not_applicable"
    elif seen <= {"True", NOT_APPLICABLE}:
        verdict = "pass"  # met wherever it applies
    elif seen == {"False"}:
        verdict = "fail"
    else:
        verdict = "uncertain"  # including fails if it applies and does not apply otherwise
    named = {k: f for _, k, f in varying}
    out = {
        "verdict": verdict,
        "outcomes": counts,
        "deciding": {k: [{"value": str(v), "sources": named[k].sources_of(v)} for v in named[k].values()] for k in deciding},
        "open": sorted(open_facts),
    }
    if errors:
        out["error"] = errors[0]
    return out


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
            probe = _evaluate(rs, name, {}, None)
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
        if "when_none" in el.data and not any(e.type == types[0] for e in ev.elements):
            # No element of the type was found: the norm's when_none says what that requires of the subject
            # (a project with no stairs passes a stair rule; a codebase with no log statements must still show
            # it logs security events). Without when_none the norm has no row and summarizes as not_applicable.
            rows.append({**base, "element": ev.subject.get("id", "subject"), "at": [], "none_found": types[0],
                         **check(rs, name, subject, none=True)})
            continue
        for e in ev.elements:
            if e.type != types[0]:
                continue
            inst = {vmap.get(k, k): f for k, f in e.facts.items()}
            for extra in (per_type.get(e.type, {}), per_element.get(e.id, {})):
                inst.update({vmap.get(k, k): f for k, f in _profile_facts(extra).items()})
            rows.append({**base, "element": e.id, "type": e.type, "at": e.at, "seen_by": sorted(e.sources), **check(rs, name, subject, inst)})
    return rows


def summarize(rows: list[dict]) -> dict[str, dict]:
    """One verdict per norm: fail if any element fails, then uncertain, then unknown; pass if every element
    passes or does not apply; not_applicable when none applies or no element is of the norm's type."""
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
        s["verdict"] = next((x for x in ("fail", "uncertain", "unknown", "pass") if x in v), "not_applicable")
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
