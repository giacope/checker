"""Property checks for the engine against brute-force oracles.

uv run python bench/engine_props.py [--cases 2000] [--seed 1] [--packs]

1. Partial evaluation is sound. For a generated rule and a full assignment of its facts, evaluating with any
   subset of the facts known gives either the full answer, or a residual that names only facts left unknown
   and that, evaluated with the rest of the facts, gives the full answer.
2. `check` over value sets agrees with enumerating every combination: pass when every combination passes,
   fail when every one fails, unknown when any leaves the rule undetermined, uncertain otherwise; the
   outcome counts match.
3. With --packs, property 1 for every norm of every pack in packs/, with facts drawn from the declared
   predicate types.

Rules are generated over every operator the evaluator implements (all, any, not, comparisons, in, max, min,
mul, div, ceil, cases, lookup, terms), typed so that a generated rule is well formed. Prints counts and the
first counterexamples; exits 1 when any property fails.
"""

from __future__ import annotations

import argparse
import itertools
import math
import random
import sys
from dataclasses import dataclass
from pathlib import Path

from normir.evaluate import Evaluator, Residual, facts_in
from normir import evidence
from normir.evidence import Fact, check
from normir.model import Element, Package, Ruleset, load, validate, walk

ROOT = Path(__file__).resolve().parents[1]
CITE = {"section": "1", "url": "https://example.org/1"}

BOOLS = [f"b{i}" for i in range(4)]
LENS = [f"q{i}" for i in range(3)]
NUMS = [f"n{i}" for i in range(2)]
ENUM_VALUES = ["a", "b", "c"]
DOOR = {"w": "length", "k": "enum", "f": "bool"}
# equal lengths written in different units; the last three pairs differ in the last bits of their float values
TIES = ["900 mm", "0.9 m", "36 in", "3 ft", "914.4 mm", "1000 mm", "1 m", "30 in", "762 mm", "2.5 ft",
        "170 mm", "0.17 m", "27 in", "685.8 mm", "16 in", "406.4 mm"]


def ruleset(norms: dict[str, dict]) -> Ruleset:
    """A pack in memory: subject predicates, a Door type, two terms and a table."""
    els: dict[tuple[str, str], Element] = {}

    def add(kind, name, data):
        els[(kind, name)] = Element(kind, name, {"name": name, "cite": CITE, **data}, "props")

    for b in BOOLS:
        add("predicate", f"system.{b}", {"type": "bool"})
    for q in LENS:
        add("predicate", f"system.{q}", {"type": "length"})
    for n in NUMS:
        add("predicate", f"system.{n}", {"type": "number"})
    add("predicate", "system.e0", {"type": "enum", "values": ENUM_VALUES})
    for a, t in DOOR.items():
        add("predicate", f"Door.{a}", {"type": t, **({"values": ENUM_VALUES} if t == "enum" else {})})
    # a subject term with an open condition per row, and an element term
    add("term", "t_len", {"value": {"cases": [
        {"when": {"fact": "system.b0"}, "then": "900 mm", "cite": CITE},
        {"when": {"eq": [{"fact": "system.e0"}, "b"]}, "then": "36 in", "cite": CITE},
        {"else": {"max": [{"fact": "system.q0"}, "800 mm"]}, "cite": CITE}]}})
    add("term", "t_door", {"for": {"d": "Door"}, "value": {"cases": [
        {"when": {"eq": [{"fact": "d.k"}, "a"]}, "then": {"mul": [{"fact": "d.w"}, 2]}, "cite": CITE},
        {"else": {"fact": "d.w"}, "cite": CITE}]}})
    add("term", "t_mixed", {"value": {"cases": [
        {"when": {"fact": "system.b3"}, "then": "not-permitted", "cite": CITE},
        {"else": {"fact": "system.q2"}, "cite": CITE}]}})
    add("table", "T1", {"key": "system.e0", "columns": ["min", "n"], "rows": [
        {"key": "a", "row": "A", "min": "30 in", "n": 2}, {"key": "b", "row": "B", "min": "1 m", "n": 3}]})
    for name, data in norms.items():
        add("norm", name, data)
    return Ruleset([Package("props", {"package": "props", "subject": "system"}, ROOT)], els, [])


class Gen:
    def __init__(self, r: random.Random, door: bool):
        self.r, self.door = r, door

    def pick(self, *opts):
        return self.r.choice(opts)()

    def lit_len(self):
        if self.r.random() < 0.6:
            return self.r.choice(TIES)
        u = self.r.choice(["mm", "in", "m", "ft"])
        v = {"mm": self.r.randint(500, 1500), "in": self.r.randint(20, 60), "m": round(self.r.uniform(0.5, 1.5), 2),
             "ft": round(self.r.uniform(2, 5), 1)}[u]
        return f"{v} {u}"

    def length(self, d):
        leaves = [lambda: {"fact": f"system.{self.r.choice(LENS)}"}, self.lit_len,
                  lambda: {"term": "t_len"}, lambda: {"lookup": "T1", "key": {"fact": "system.e0"}, "column": "min"}]
        if self.r.random() < 0.08:  # sometimes a value that may be a symbol: the rule can fail to evaluate
            leaves.append(lambda: {"term": "t_mixed"})
        if self.door:
            leaves += [lambda: {"fact": "d.w"}, lambda: {"term": "t_door", "of": "d"}]
        if d <= 0:
            return self.pick(*leaves)
        return self.pick(*leaves,
                         lambda: {self.r.choice(["max", "min"]): [self.length(d - 1) for _ in range(self.r.randint(1, 3))]},
                         lambda: {"mul": [self.length(d - 1), self.r.choice([0.5, 2, 3])]},
                         lambda: {"div": [self.length(d - 1), self.r.choice([2, 4])]},
                         lambda: {"cases": self.cases(d, self.length)})

    def number(self, d):
        leaves = [lambda: {"fact": f"system.{self.r.choice(NUMS)}"}, lambda: self.r.randint(0, 9),
                  lambda: {"lookup": "T1", "key": {"fact": "system.e0"}, "column": "n"}]
        if d <= 0:
            return self.pick(*leaves)
        return self.pick(*leaves,
                         lambda: {"ceil": {"div": [self.length(d - 1), self.lit_len()]}},
                         lambda: {"mul": [self.number(d - 1), self.r.choice([2, 0.5])]},
                         lambda: {self.r.choice(["max", "min"]): [self.number(d - 1) for _ in range(self.r.randint(1, 3))]},
                         lambda: {"cases": self.cases(d, self.number)})

    def enum_fact(self):
        return {"fact": self.r.choice(["system.e0"] + (["d.k"] if self.door else []))}

    def boolean(self, d):
        leaves = [lambda: {"fact": f"system.{self.r.choice(BOOLS)}"}, lambda: {"value": self.r.choice([True, False])},
                  lambda: {self.r.choice(["eq", "ne"]): [self.enum_fact(), self.r.choice(ENUM_VALUES)]},
                  lambda: {"in": [self.enum_fact(), self.r.sample(ENUM_VALUES, self.r.randint(1, 2))]}]
        if self.door:
            leaves.append(lambda: {"fact": "d.f"})
        if d <= 0:
            return self.pick(*leaves)
        cmp = ["lt", "le", "gt", "ge", "eq", "ne"]
        return self.pick(*leaves,
                         lambda: {self.r.choice(["all", "any"]): [self.boolean(d - 1) for _ in range(self.r.randint(1, 3))]},
                         lambda: {"not": self.boolean(d - 1)},
                         lambda: {self.r.choice(cmp): [self.length(d - 1), self.length(d - 1)]},
                         lambda: {self.r.choice(cmp): [self.number(d - 1), self.number(d - 1)]},
                         lambda: {"cases": self.cases(d, self.boolean)})

    def cases(self, d, then):
        rows = [{"when": self.boolean(d - 1), "then": then(d - 1), "cite": CITE} for _ in range(self.r.randint(1, 3))]
        if self.r.random() < 0.8:
            rows.append({"else": then(d - 1), "cite": CITE})
        return rows


def draw(r: random.Random, typ: str, values=None):
    if typ == "bool":
        return r.choice([True, False])
    if typ == "length":
        return Gen(r, False).lit_len()
    if typ == "area":
        return f"{round(r.uniform(1, 60), 1)} m2"
    if typ == "number":
        return r.choice([r.randint(0, 9), round(r.uniform(0, 9), 1)])
    return r.choice(values)


def subject_facts(r):
    out = {b: draw(r, "bool") for b in BOOLS} | {q: draw(r, "length") for q in LENS} | {n: draw(r, "number") for n in NUMS}
    return out | {"e0": r.choice(ENUM_VALUES)}


def door_facts(r):
    return {"w": draw(r, "length"), "k": r.choice(ENUM_VALUES), "f": draw(r, "bool")}


def same(a, b) -> bool:
    if isinstance(a, Residual) or isinstance(b, Residual):
        return isinstance(a, Residual) and isinstance(b, Residual)  # an undetermined table row ("see", "unlisted")
    return a == b


def finish(rs, residual, s, i):
    """Evaluate a residual with the remaining facts; residual facts are keyed by type ("Door.w", "system.b0")."""
    el = next(iter(e for (k, _), e in rs.elements.items() if k == "norm"))
    return Evaluator(rs, s).ev(settled(residual.expr), {"Door": ("Door", i)}, el)


def settled(expr):
    """A table row the rule leaves to the official ("see", "unlisted") is final: stand in a fact never known."""
    if isinstance(expr, list):
        return [settled(x) for x in expr]
    if not isinstance(expr, dict):
        return expr
    if "see" in expr or "unlisted" in expr or "invalid" in expr:
        return {"fact": "system.__undetermined"}
    return {k: settled(v) for k, v in expr.items()}


def soundness(rs, name, s, i, r, subsets=6):
    """Property 1 for one rule and one full assignment. Returns a counterexample or None."""
    truth = Evaluator(rs, s).norm(name, i)
    keys = [("s", k) for k in s] + [("i", k) for k in (i or {})]
    for _ in range(subsets):
        known = {k for k in keys if r.random() < r.choice([0.2, 0.5, 0.8])}
        gs = {k: v for k, v in s.items() if ("s", k) in known}
        gi = None if i is None else {k: v for k, v in i.items() if ("i", k) in known}
        v = Evaluator(rs, gs).norm(name, gi)
        if not isinstance(v, Residual):
            if not same(v, truth):
                return {"known": sorted(known), "partial": v, "full": truth}
            continue
        unknown = {f"system.{k}" for w, k in keys if w == "s" and ("s", k) not in known}
        unknown |= {f"Door.{k}" for w, k in keys if w == "i" and ("i", k) not in known}
        stray = set(facts_in(v.expr)) - unknown
        if stray:
            return {"known": sorted(known), "residual names known facts": sorted(stray), "residual": v.expr}
        got = finish(rs, v, s, i)
        if not same(got, truth):
            return {"known": sorted(known), "residual": v.expr, "residual then": got, "full": truth}
    return None


def brute(rs, name, subj: dict[str, list], inst: dict[str, list] | None) -> dict:
    """Every combination of every value set, by enumeration."""
    sk, ik = list(subj), list(inst or {})
    counts: dict[str, int] = {}
    for combo in itertools.product(*(subj[k] for k in sk), *((inst or {})[k] for k in ik)):
        s = {k: v for k, v in zip(sk, combo) if v is not None}
        i = None if inst is None else {k: v for k, v in zip(ik, combo[len(sk):]) if v is not None}
        res = Evaluator(rs, s).norm(name, i)
        if isinstance(res, Residual):
            key = "error" if not facts_in(res.expr) and any("invalid" in n for n in walk(res.expr)) else "unknown"
        else:
            key = str(res)
        counts[key] = counts.get(key, 0) + 1
    if "error" in counts:  # never a verdict the evaluation could not show
        verdict = "uncertain" if {"True", "False"} <= set(counts) else "unknown"
    else:
        verdict = "unknown" if "unknown" in counts else ("pass" if "True" in counts else "fail") if len(counts) == 1 else "uncertain"
    return {"verdict": verdict, "outcomes": counts}


# ---------------------------------------------------------------- reference semantics (independent of normir.evaluate)

UNDET = "undetermined"
INCH = {"in": 1.0, "ft": 12.0, "mm": 1 / 25.4, "m": 1000 / 25.4, "m2": (1000 / 25.4) ** 2, "sqft": 144.0}


def _q(v):
    """A length or area literal as (inches^dim, dim); anything else unchanged."""
    if isinstance(v, str):
        num, _, unit = v.strip().partition(" ")
        if unit in INCH:
            return (float(num) * INCH[unit], 2 if unit in ("m2", "sqft") else 1)
    return v


def _cmp(op, a, b):
    if isinstance(a, str) or isinstance(b, str):  # a symbol ("not-permitted") is only ever equal to itself
        if op not in ("eq", "ne"):
            raise TypeError(f"{op} on {a!r} and {b!r}")
        return (a == b) == (op == "eq")
    if isinstance(a, tuple):
        a, b = a[0], b[0]
    close = abs(a - b) <= 1e-9 * max(1.0, abs(a), abs(b)) if isinstance(a, float) or isinstance(b, float) else a == b
    return {"eq": close, "ne": not close, "lt": a < b and not close, "le": a < b or close, "gt": a > b and not close, "ge": a > b or close}[op]


@dataclass(frozen=True)
class Choice:
    """A value that is one of several, because the row of a table that applies is undetermined."""
    values: list


def ref(rs, e, s, i, var=None):
    """What a rule means, evaluated directly from the spec with every fact known. A table value whose row is
    undetermined is a Choice; a comparison decides when every choice agrees, any other use of it is undetermined."""
    def go(x):
        return ref(rs, x, s, i, var)

    def plain(x):
        v = go(x)
        return UNDET if isinstance(v, Choice) else v
    if isinstance(e, bool) or isinstance(e, (int, float)) or e is None:
        return e
    if isinstance(e, str):
        return _q(e)
    if "value" in e and len(e) == 1:
        return go(e["value"])
    if "fact" in e:
        root, _, attr = e["fact"].partition(".")
        src = s if root == rs.subject else i
        return _q(src[attr]) if attr in src else UNDET
    if "term" in e:
        return go(rs.get("term", e["term"]).data["value"])
    if "lookup" in e:
        k = plain(e["key"])
        row = next((r for r in rs.get("table", e["lookup"]).data["rows"] if r["key"] == k), None)
        return UNDET if row is None or "see" in row else go(row[e["column"]])
    if "cases" in e:
        # Rows whose condition is undetermined each remain possible, until a row that certainly applies.
        possible = []
        for row in e["cases"]:
            if "else" in row:
                possible.append(go(row["else"]))
                break
            w = plain(row["when"])
            if not isinstance(w, bool):
                w = UNDET
            if w is False:
                continue
            possible.append(go(row["then"]))
            if w is True:
                break
        else:
            return UNDET  # no row may match
        if len(possible) == 1:
            return possible[0]
        if any(v == UNDET or isinstance(v, Choice) for v in possible):
            return UNDET
        return Choice(possible)
    (op, args), = e.items()
    if op in ("all", "any"):
        undecided = False
        for x in args:  # left to right, stopping at the first deciding value: rules guard later arguments this way
            v = plain(x)
            if not isinstance(v, bool):
                undecided = True
            elif v is (op == "any"):
                return v
        return UNDET if undecided else op == "all"
    if op == "not":
        v = plain(args)
        return not v if isinstance(v, bool) else UNDET
    if op in ("eq", "ne", "lt", "le", "gt", "ge"):
        a, b = go(args[0]), go(args[1])
        if UNDET in (a, b):
            return UNDET
        try:
            got = {_cmp(op, x, y) for x in (a.values if isinstance(a, Choice) else [a]) for y in (b.values if isinstance(b, Choice) else [b])}
        except TypeError:  # cannot be compared: undetermined, like an open fact
            return UNDET
        return got.pop() if len(got) == 1 else UNDET
    if op == "in":
        a = plain(args[0])
        return UNDET if a == UNDET else a in args[1]
    if op in ("max", "min"):
        if len(args) == 1:  # the larger of one value is that value, even one of several possible rows
            return go(args[0])
        vals = [plain(x) for x in args]
        if UNDET in vals:
            return UNDET
        try:
            return (max if op == "max" else min)(vals, key=lambda v: v[0] if isinstance(v, tuple) else v)
        except TypeError:
            return UNDET
    if op in ("mul", "div", "ceil"):
        if op == "ceil":
            v = plain(args)
            return UNDET if v == UNDET or not isinstance(v, (int, float)) or isinstance(v, bool) else math.ceil(round(v, 9))
        a, b = plain(args[0]), plain(args[1])
        if UNDET in (a, b) or any(isinstance(x, (str, bool)) for x in (a, b)) or (isinstance(a, tuple) and isinstance(b, tuple) and op == "mul") \
                or (op == "div" and (isinstance(b, tuple) and not isinstance(a, tuple) or b in (0, 0.0) or (isinstance(b, tuple) and b[0] == 0))):
            return UNDET
        if op == "mul":
            return (a[0] * b, a[1]) if isinstance(a, tuple) else (b[0] * a, b[1]) if isinstance(b, tuple) else a * b
        if isinstance(a, tuple) and isinstance(b, tuple):
            return a[0] / b[0]
        return (a[0] / b, a[1]) if isinstance(a, tuple) else a / b
    raise ValueError(op)


def meaning(rs, name, s, i):
    """The engine's answer with every fact known, compared with the reference."""
    try:
        want = ref(rs, rs.get("norm", name).data["require"], s, i or {})
    except (TypeError, ZeroDivisionError):  # the rule cannot be evaluated on these facts: the engine must not decide
        want = UNDET
    want = UNDET if isinstance(want, Choice) else want
    got = Evaluator(rs, s).norm(name, i)
    if want == UNDET:
        return None if isinstance(got, Residual) else {"engine": got, "reference": "undetermined"}
    return None if got is want or got == want else {"engine": got, "reference": want}


def value_sets(r, facts: dict, sizes=(1, 1, 1, 2, 3), open_p=0.15) -> tuple[dict[str, Fact], dict[str, list]]:
    """Random value sets around one assignment: some facts open, some with several values."""
    fs, plain = {}, {}
    for k, v in facts.items():
        if r.random() < open_p:
            continue
        n = r.choice(sizes)
        vals = [v]
        typ = "bool" if isinstance(v, bool) else "enum" if v in ENUM_VALUES else "number" if isinstance(v, (int, float)) else "length"
        for _ in range(n - 1):
            vals.append(draw(r, typ, ENUM_VALUES))
        fs[k] = Fact([{"value": x, "source": f"src{j}"} for j, x in enumerate(vals)])
        plain[k] = fs[k].values()
    return fs, plain


errored = [0]


def generated(cases: int, seed: int, report) -> int:
    failures = 0
    r = random.Random(seed)
    for n in range(cases):
        door = r.random() < 0.5
        g = Gen(r, door)
        rule = {"require": g.boolean(r.randint(1, 4)), **({"for": {"d": "Door"}} if door else {})}
        rs = ruleset({"N": rule})
        errors = [e for e in validate(rs)[0]]
        if errors:  # every generated rule is well formed: the validator must accept it
            failures += 1
            report("validate rejected a well-formed rule", n, rule, None, None, errors[:3])
            continue
        s, i = subject_facts(r), (door_facts(r) if door else None)
        try:
            full = Evaluator(rs, s).norm("N", i)
            errored[0] += isinstance(full, Residual) and any("invalid" in x for x in walk(full.expr))
            cx = meaning(rs, "N", s, i) or soundness(rs, "N", s, i, r)
        except Exception as e:  # noqa: BLE001 - the validator accepted the rule, so a raise is the engine's bug
            cx = {"engine raised": repr(e)}
        if cx:
            failures += 1
            report("soundness", n, rule, s, i, cx)
            continue
        fs, plain = value_sets(r, s)
        fi, pi = value_sets(r, i) if door else (None, None)
        try:
            got = check(rs, "N", fs, fi)
            want = brute(rs, "N", {k: plain.get(k, [None]) for k in s}, None if not door else {k: pi.get(k, [None]) for k in i})
        except Exception as e:  # noqa: BLE001
            failures += 1
            report("check raised", n, rule, plain, pi, repr(e))
            continue
        if got["verdict"] != want["verdict"]:
            failures += 1
            report("check", n, rule, plain, pi, {"check": got["verdict"], "brute force": want["verdict"]})
            continue
        # The same value sets through the fact-by-fact path that `check` takes past MAX_COMBINATIONS: same verdict
        # and counts; the facts it names as deciding are among the ones enumeration names.
        cap = evidence.MAX_COMBINATIONS
        evidence.MAX_COMBINATIONS = 0
        try:
            split = check(rs, "N", fs, fi)
        finally:
            evidence.MAX_COMBINATIONS = cap
        if (split["verdict"], split["outcomes"]) != (got["verdict"], got["outcomes"]) or not set(split["deciding"]) <= set(got["deciding"]):
            failures += 1
            report("split", n, rule, plain, pi, {"enumerated": got, "split": split})
    return failures


def packs(seed: int, per_norm: int, report) -> tuple[int, int]:
    r = random.Random(seed)
    failures = norms = 0
    for pkg in sorted(ROOT.glob("packs/*/package.yaml")):
        rs = load(pkg.parent)
        preds = {n: el.data for (k, n), el in rs.elements.items() if k == "predicate"}
        for (k, name), el in sorted(rs.elements.items()):
            if k != "norm":
                continue
            norms += 1
            typ = next(iter((el.data.get("for") or {}).values()), None)
            for _ in range(per_norm):
                s = {p.split(".", 1)[1]: draw(r, d.get("type"), d.get("values")) for p, d in preds.items() if p.startswith(rs.subject + ".")}
                i = {p.split(".", 1)[1]: draw(r, d.get("type"), d.get("values")) for p, d in preds.items() if typ and p.startswith(typ + ".")} if typ else None
                try:
                    cx = soundness_typed(rs, name, s, i, r, typ)
                except Exception as e:  # noqa: BLE001 - a crash on well-typed facts is a finding
                    cx = {"crash": repr(e)}
                if cx:
                    failures += 1
                    report("pack", f"{pkg.parent.name}/{name}", None, None, None, cx)
                    break
    return failures, norms


def soundness_typed(rs, name, s, i, r, typ):
    """`soundness` for a real pack, whose element facts are keyed by their own type."""
    cx = meaning(rs, name, s, i)
    if cx:
        return cx
    truth = Evaluator(rs, s).norm(name, i)
    keys = [("s", k) for k in s] + [("i", k) for k in (i or {})]
    el = rs.get("norm", name)
    for _ in range(4):
        known = {k for k in keys if r.random() < r.choice([0.2, 0.5, 0.8])}
        gs = {k: v for k, v in s.items() if ("s", k) in known}
        gi = None if i is None else {k: v for k, v in i.items() if ("i", k) in known}
        v = Evaluator(rs, gs).norm(name, gi)
        if not isinstance(v, Residual):
            if not same(v, truth):
                return {"partial": v, "full": truth}
            continue
        got = Evaluator(rs, s).ev(settled(v.expr), {typ: (typ, i)} if typ else {}, el)
        if not same(got, truth):
            return {"residual": v.expr, "residual then": got, "full": truth}
    return None


# ---------------------------------------------------------------- fuzzing: what validate accepts, run must survive

def mutate(r: random.Random, expr, preds: list[str]):
    """One random change somewhere in a rule: the kinds of mistakes a model writing rules makes."""
    nodes = []

    def collect(x, parent, key):
        nodes.append((x, parent, key))
        if isinstance(x, dict):
            for k, v in x.items():
                collect(v, x, k)
        elif isinstance(x, list):
            for j, v in enumerate(x):
                collect(v, x, j)
    root = {"r": expr}
    collect(expr, root, "r")
    x, parent, key = r.choice(nodes)
    choices = [
        lambda: {"fact": r.choice(preds)},                                  # a fact of another type or meaning
        lambda: {"fact": "x." + r.choice(["width", "nope", ""])},             # unknown variable
        lambda: r.choice(["12 mm", "3 m2", "not-permitted", "", 7, True, None, [], {}]),
        lambda: {r.choice(["lt", "eq", "all", "any", "not", "in", "max", "mul", "div", "ceil", "cases", "frob"]): x},
        lambda: {r.choice(["lt", "ge", "mul", "div"]): [x, r.choice(["0 mm", 0, "x", True, "2 m2"])]},
        lambda: {"cases": [{"when": x, "then": 1}]},                          # no cite, no else
        lambda: {"term": r.choice(["nope", "t"])},
        lambda: {"lookup": "nope", "key": x, "column": "c"},
    ]
    new = r.choice(choices)()
    parent[key] = new
    return root["r"]


def fuzz(cases: int, seed: int, report) -> tuple[int, int]:
    """Mutate real norms; whenever validate reports no error, run must complete on random evidence.
    Returns (accepted by validate, crashes)."""
    import copy
    from normir.evidence import load_evidence, run
    from normir.model import validate
    r = random.Random(seed)
    base = [load(p.parent) for p in sorted(ROOT.glob("packs/*/package.yaml"))]
    accepted = crashes = 0
    for n in range(cases):
        rs = r.choice(base)
        norms = [k for k in rs.elements if k[0] == "norm"]
        key = r.choice(norms)
        el = rs.elements[key]
        preds = [k[1] for k in rs.elements if k[0] == "predicate"]
        data = copy.deepcopy(el.data)
        for _ in range(r.randint(1, 3)):
            data["require"] = mutate(r, data["require"], preds)
        els = dict(rs.elements)
        els[key] = Element(el.kind, el.name, data, el.package)
        mrs = Ruleset(rs.chain, els, list(rs.errors))
        try:
            errors, _ = validate(mrs)
        except Exception as e:  # noqa: BLE001 - the validator itself must not crash on a bad rule
            crashes += 1
            report("fuzz: validate crashed", n, data["require"], None, None, repr(e))
            continue
        if any(key[1] in e for e in errors):
            continue
        accepted += 1
        typ = next(iter((data.get("for") or {}).values()), None)
        pv = {p: d.data for (k, p), d in rs.elements.items() if k == "predicate"}
        facts = {p.split(".", 1)[1]: draw(r, d.get("type"), d.get("values")) for p, d in pv.items() if p.startswith(rs.subject + ".") and r.random() < 0.7}
        doc = {"facts": facts, "elements": []}
        if typ:
            doc["elements"].append({"type": typ, "id": "e1", "facts": {p.split(".", 1)[1]: draw(r, d.get("type"), d.get("values"))
                                                                       for p, d in pv.items() if p.startswith(typ + ".") and r.random() < 0.7}})
        try:
            rows = [x for x in run(mrs, load_evidence(doc), {"norms": [key[1]]})]
            bad = [x for x in rows if x["verdict"] not in ("pass", "fail", "uncertain", "unknown", "not_applicable")]
            if bad:
                raise AssertionError(f"verdict {bad[0]['verdict']!r}")
        except Exception as e:  # noqa: BLE001
            crashes += 1
            report("fuzz: run crashed on a pack validate accepted", n, data["require"], facts, None, repr(e))
    return accepted, crashes


def tie_pairs() -> list[tuple[str, str]]:
    """Equal lengths written in two units, exact by construction: n mm = n/1000 m, k in = 25.4k mm = k/12 ft."""
    pairs = [(f"{n} mm", f"{n / 1000!r} m") for n in range(1, 5001)]
    pairs += [(f"{k} in", f"{k * 254 // 10}.{k * 254 % 10} mm") for k in range(1, 601)]
    pairs += [(f"{12 * k} in", f"{k} ft") for k in range(1, 101)]
    return pairs


def ties(report) -> tuple[int, int]:
    """Every comparison between two equal lengths, in both orders, against the reference."""
    bad = n = 0
    for a, b in tie_pairs():
        norms = {f"{op}{x}": {"cite": CITE, "require": {op: list(p)}}
                 for op in ("eq", "ne", "lt", "le", "gt", "ge") for x, p in (("ab", (a, b)), ("ba", (b, a)))}
        rs = ruleset(norms)
        for name in norms:
            n += 1
            cx = meaning(rs, name, {}, None)
            if cx:
                bad += 1
                report("tie", n, norms[name]["require"], {}, None, cx)
    return n, bad


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--packs", action="store_true")
    ap.add_argument("--per-norm", type=int, default=20)
    ap.add_argument("--fuzz", type=int, default=0, help="mutated real norms to try")
    a = ap.parse_args()
    shown = []

    def report(kind, n, rule, s, i, cx):
        if len(shown) < 5:
            shown.append((kind, n, rule, s, i, cx))

    f1 = generated(a.cases, a.seed, report)
    print(f"generated rules: {a.cases} cases ({errored[0]} resting on a part that cannot be evaluated), {f1} counterexamples")
    total = f1
    tn, tb = ties(report)
    print(f"unit ties: {tn} comparisons of equal lengths in different units, {tb} wrong")
    total += tb
    if a.packs:
        f2, norms = packs(a.seed, a.per_norm, report)
        print(f"pack norms: {norms} norms x {a.per_norm} assignments, {f2} norms with a counterexample")
        total += f2
    if a.fuzz:
        acc, crashes = fuzz(a.fuzz, a.seed, report)
        print(f"fuzzed norms: {a.fuzz} mutated, {acc} accepted by validate, {crashes} crashes")
        total += crashes
    for kind, n, rule, s, i, cx in shown:
        print(f"\n[{kind} #{n}]\n rule: {rule}\n subject: {s}\n instance: {i}\n {cx}")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
