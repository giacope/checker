"""Partial evaluation of terms and norms over whatever facts are known.

Unknown facts do not make the evaluator guess. They leave a residual: the part
of the rule that still depends on them, with every branch the known facts
already ruled out recorded separately.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from .model import Element, Ruleset, amendment_status, walk
from .quantity import Quantity, div, mul

OPS = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "lt": lambda a, b: a < b,
    "le": lambda a, b: a <= b,
    "gt": lambda a, b: a > b,
    "ge": lambda a, b: a >= b,
}
# What a norm evaluates to when its `applies` condition is false: the requirement is about something the subject
# does not have or is not (a dwelling-only provision on a clinic, a security-question rule where there are none).
NOT_APPLICABLE = "not_applicable"
SYMBOLS = {"eq": "is", "ne": "is not", "lt": "<", "le": "≤", "gt": ">", "ge": "≥"}


@dataclass
class Residual:
    expr: dict


def literal(v: Any) -> Any:
    if isinstance(v, str):
        q = Quantity.parse(v)
        return q if q is not None else v
    return v


def invalid(el: Element, message: str) -> dict:
    """A part of a rule that cannot be evaluated on these values (a length compared with "not-permitted", a
    division by zero). It stays undetermined like an open fact: the rule is still decided when the rest decides
    it whatever this part is, and is otherwise reported with the message."""
    return {"invalid": f"{el.name}: {message}"}


def attempt(el: Element, fn) -> Any:
    try:
        return fn()
    except (TypeError, ValueError, ZeroDivisionError, ArithmeticError) as e:
        return Residual(invalid(el, str(e)))


def lift(v: Any) -> dict:
    return v.expr if isinstance(v, Residual) else {"value": v}


def _row_values(v: Any) -> list | None:
    """Every value an open `cases` can still take, when its rows are exhaustive and their values known."""
    if not isinstance(v, Residual) or "cases" not in v.expr:
        return [v] if not isinstance(v, Residual) else None
    rows = v.expr["cases"]
    if not rows or "else" not in rows[-1]:
        return None  # no row may match: the value itself is undetermined
    out = []
    for row in rows:
        val = row.get("then", row.get("else"))
        if not (isinstance(val, dict) and set(val) == {"value"}):
            return None
        out.append(val["value"])
    return out


def _by_rows(op: str, a: Any, b: Any) -> bool | None:
    """A comparison with an open table value is decided when it comes out the same for every row the open
    conditions still allow: 2 m is wider than every row of a width table, whichever row applies."""
    xs, ys = _row_values(a), _row_values(b)
    if xs is None or ys is None:
        return None
    try:
        got = {OPS[op](x, y) for x in xs for y in ys}
    except TypeError:
        return None
    return got.pop() if len(got) == 1 else None


class Evaluator:
    def __init__(self, rs: Ruleset, building: dict | None = None):
        # `building` holds facts about the subject as a whole, whatever the pack's subject is.
        self.rs = rs
        self.building = {k: literal(v) for k, v in (building or {}).items()}
        self.used: list[tuple[Element, dict]] = []
        self.ruled_out: list[tuple[Element, dict]] = []
        self.read: set[str] = set()

    # ------------------------------------------------------------ public API

    def term(self, name: str, instance: dict | None = None) -> Any:
        el = self.rs.get("term", name)
        return self._element(el, self._scope(el, instance), el.data["value"])

    def norm(self, name: str, instance: dict | None = None, none: bool = False) -> Any:
        """True, False, NOT_APPLICABLE, or a residual. With `none`, the norm's `when_none` ({applies, require} over
        the subject): what it requires when no element of its `for` type was found."""
        el = self.rs.get("norm", name)
        spec = el.data["when_none"] if none else el.data
        body = spec["require"]
        if "applies" in spec:
            body = {"applicable": [spec["applies"], body]}
        return self._element(el, {} if none else self._scope(el, instance), body)

    # ------------------------------------------------------------ internals

    def _scope(self, el: Element, instance: dict | None) -> dict:
        f = el.data.get("for") or {}
        return {var: (typ, instance) for var, typ in f.items()}

    def _cite(self, el: Element, extra: dict | None = None, bucket: list | None = None) -> None:
        cite = {**el.data["cite"], **(extra or {})}
        target = self.used if bucket is None else bucket
        if (el, cite) not in target:
            target.append((el, cite))

    def _element(self, el: Element, scope: dict, expr: Any) -> Any:
        self._cite(el)
        return self.ev(expr, scope, el)

    def fact(self, path: str, scope: dict) -> Any:
        root, _, attr = path.partition(".")
        if root == self.rs.subject:
            key, source = f"{root}.{attr}", self.building
        else:
            typ, inst = scope[root]
            key, source = f"{typ}.{attr}", inst or {}
        self.read.add(key)
        if attr in source and source[attr] is not None:
            return literal(source[attr])
        return Residual({"fact": key})

    def ev(self, e: Any, scope: dict, el: Element) -> Any:
        if e is None or isinstance(e, (bool, int, float)):
            return e
        if isinstance(e, str):
            return literal(e)
        if isinstance(e, list):
            return [self.ev(x, scope, el) for x in e]
        if "value" in e and len(e) == 1:
            return e["value"]
        if "fact" in e:
            return self.fact(e["fact"], scope)
        if "term" in e:
            target = self.rs.get("term", e["term"])
            f = target.data.get("for") or {}
            inner = {var: scope[e["of"]] for var in f} if f else {}
            return self._element(target, inner, target.data["value"])
        if "lookup" in e:
            return self._lookup(e, scope, el)
        if "cases" in e:
            return self._cases(e["cases"], scope, el)
        (op, args), = e.items()
        if op == "applicable":  # a norm's applies condition and requirement, as built by norm()
            a = self.ev(args[0], scope, el)
            if not isinstance(a, (bool, Residual)):
                a = Residual(invalid(el, f"'applies' needs true/false, got {a!r}"))
            if a is False:
                return NOT_APPLICABLE
            r = self.ev(args[1], scope, el)
            if a is True:
                return r
            # Open applicability stays open even when the requirement holds: filling it in still changes the value
            # (to not_applicable). evidence.check counts that residual as met, since every completion is.
            return Residual({"applicable": [a.expr, lift(r)]})
        if op in ("all", "any"):
            stop = op == "any"  # value that decides the whole expression
            rest = []
            for a in args:
                v = self.ev(a, scope, el)
                if isinstance(v, Residual):
                    rest.append(v.expr)
                elif v is stop:
                    return stop
                elif not isinstance(v, bool):
                    rest.append(invalid(el, f"'{op}' needs true/false, got {v!r}"))
            if not rest:
                return not stop
            return Residual(rest[0] if len(rest) == 1 else {op: rest})
        if op == "not":
            v = self.ev(args, scope, el)
            if isinstance(v, Residual):
                return Residual({"not": v.expr})
            return not v if isinstance(v, bool) else Residual(invalid(el, f"'not' needs true/false, got {v!r}"))
        if op in OPS:
            a, b = (self.ev(x, scope, el) for x in args)
            if isinstance(a, Residual) or isinstance(b, Residual):
                decided = _by_rows(op, a, b)
                return Residual({op: [lift(a), lift(b)]}) if decided is None else decided
            return attempt(el, lambda: OPS[op](a, b))
        if op == "in":
            a = self.ev(args[0], scope, el)
            options = [literal(x) for x in args[1]]
            return Residual({"in": [a.expr, args[1]]}) if isinstance(a, Residual) else a in options
        if op in ("max", "min"):
            vals = [self.ev(x, scope, el) for x in args]
            known = [v for v in vals if not isinstance(v, Residual)]
            open_ = [v.expr for v in vals if isinstance(v, Residual)]
            fold = attempt(el, lambda: (max if op == "max" else min)(known)) if known else None
            if isinstance(fold, Residual):
                return fold
            if not open_:
                return fold
            items = ([{"value": fold}] if known else []) + open_
            return Residual(items[0] if len(items) == 1 else {op: items})
        if op in ("mul", "div"):
            a, b = (self.ev(x, scope, el) for x in args)
            if isinstance(a, Residual) or isinstance(b, Residual):
                return Residual({op: [lift(a), lift(b)]})
            return attempt(el, lambda: mul(a, b) if op == "mul" else div(a, b))
        if op == "ceil":
            v = self.ev(args, scope, el)
            return Residual({"ceil": v.expr}) if isinstance(v, Residual) else attempt(el, lambda: math.ceil(round(v, 9)))
        raise ValueError(f"{el.name}: unknown operator '{op}'")

    def _cases(self, rows: list, scope: dict, el: Element) -> Any:
        remaining = []
        for row in rows:
            cite = row["cite"]
            if "else" in row:
                v = self.ev(row["else"], scope, el)
                if not remaining:
                    self._cite(el, cite)
                    return v
                remaining.append({"else": lift(v), "cite": cite})
                break
            w = self.ev(row["when"], scope, el)
            if not isinstance(w, (bool, Residual)):
                w = Residual(invalid(el, f"a cases condition needs true/false, got {w!r}"))
            if w is False:
                self._cite(el, cite, self.ruled_out)
                continue
            v = self.ev(row["then"], scope, el)
            if w is True:
                if not remaining:
                    self._cite(el, cite)
                    return v
                remaining.append({"else": lift(v), "cite": cite})
                break
            remaining.append({"when": w.expr, "then": lift(v), "cite": cite})
        for row in remaining:
            self._cite(el, row["cite"])
        return Residual({"cases": remaining})

    def _lookup(self, e: dict, scope: dict, el: Element) -> Any:
        table = self.rs.get("table", e["lookup"])
        key = self.ev(e["key"], scope, el)
        self._cite(table)
        if isinstance(key, Residual):
            return Residual({"lookup": e["lookup"], "key": key.expr, "column": e["column"]})
        row = next((r for r in table.data["rows"] if r["key"] == key), None)
        if row is None:
            return Residual({"unlisted": e["lookup"], "key": key})
        self._cite(table, {"row": row["row"]})
        if "see" in row:
            return Residual({"see": row["see"], "row": row["row"]})
        return literal(row[e["column"]])


# -------------------------------------------------------------------- answers


def met_if_applicable(expr: Any) -> bool:
    """A residual open only on whether the norm applies, whose requirement holds: met wherever it applies."""
    return isinstance(expr, dict) and "applicable" in expr and expr["applicable"][1] == {"value": True}


def facts_in(expr: Any) -> list[str]:
    return sorted({n["fact"] for n in walk(expr) if "fact" in n})


def describe(expr: Any, rs: Ruleset) -> str:
    def label(key: str) -> str:
        return rs.get("predicate", key).data.get("label", key) if rs.has("predicate", key) else key

    def d(x: Any) -> str:
        if not isinstance(x, dict):
            return "yes" if x is True else "no" if x is False else str(x)
        if "value" in x and len(x) == 1:
            return d(x["value"])
        if "fact" in x:
            return label(x["fact"])
        if "all" in x:
            return " and ".join(d(a) for a in x["all"])
        if "any" in x:
            return "(" + " or ".join(d(a) for a in x["any"]) + ")"
        if "not" in x:
            return f"not ({d(x['not'])})"
        if "in" in x:
            return f"{d(x['in'][0])} is one of {', '.join(map(str, x['in'][1]))}"
        for op, sym in SYMBOLS.items():
            if op in x:
                a, b = x[op]
                if op == "eq" and b == {"value": True}:
                    return d(a)
                return f"{d(a)} {sym} {d(b)}"
        if "max" in x:
            return "the larger of " + " and ".join(f"[{d(a)}]" for a in x["max"])
        if "min" in x:
            return "the smaller of " + " and ".join(f"[{d(a)}]" for a in x["min"])
        if "mul" in x:
            return f"{d(x['mul'][0])} × {d(x['mul'][1])}"
        if "div" in x:
            return f"{d(x['div'][0])} ÷ {d(x['div'][1])}"
        if "ceil" in x:
            return f"{d(x['ceil'])}, rounded up"
        if "cases" in x:
            parts = [f"{d(r['then'])} if {d(r['when'])}" if "when" in r else f"otherwise {d(r['else'])}" for r in x["cases"]]
            return "; ".join(parts)
        if "lookup" in x:
            return f"the {x['column']} for {d(x['key'])} in Table {x['lookup'].lstrip('T')}"
        if "see" in x:
            return f"set by §{x['see']} ({x['row']})"
        if "applicable" in x:
            a, r = x["applicable"]
            return f"if it applies ({d(a)}): {d(r)}"
        if "invalid" in x:
            return f"[cannot be evaluated: {x['invalid']}]"
        if "unlisted" in x:
            return f"not listed in Table {x['unlisted'].lstrip('T')}; the building official assigns the nearest listed function"
        return str(x)

    return d(expr)


def _citation(rs: Ruleset, el: Element, cite: dict) -> dict:
    out = {k: v for k, v in cite.items() if k in ("section", "table", "row", "url", "note")}
    out["element"] = f"{el.package}/{el.kind}/{el.name}"
    out["status"] = el.data.get("status", "draft")
    out["amendment"] = amendment_status(rs, el, cite.get("section"), cite.get("table"))
    return out


def ask(rs: Ruleset, term: str, building: dict | None = None, instance: dict | None = None) -> dict:
    """Answer a research question: evaluate a term on whatever facts are known."""
    ev = Evaluator(rs, building)
    v = ev.term(term, instance)
    el = rs.get("term", term)
    residual = v.expr if isinstance(v, Residual) else None
    notes = []
    for key in sorted(ev.read):
        pred = rs.get("predicate", key)
        deleted = {}
        for section in pred.data.get("refers_to", []):
            status = amendment_status(rs, None, section)
            if status.startswith("Deleted"):
                deleted.setdefault(status, []).append(f"§{section}")
        for status, sections in deleted.items():
            notes.append(f"'{pred.data.get('label', key)}' refers to {', '.join(sections)}. {status}.")
    defers = []
    for used, _ in ev.used:
        for s in used.data.get("defers_to", []):
            if s not in defers:
                defers.append(s)
    return {
        "term": term,
        "title": el.data.get("title", term),
        "determined": residual is None,
        "value": None if residual is not None else v,
        "residual": residual,
        "answer": describe(residual if residual is not None else {"value": v}, rs),
        "open_facts": facts_in(residual) if residual is not None else [],
        "ruled_out": [_citation(rs, e, c) for e, c in ev.ruled_out],
        "citations": [_citation(rs, e, c) for e, c in ev.used],
        "not_formalized": defers,
        "notes": notes,
    }
