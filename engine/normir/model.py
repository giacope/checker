"""Loading, merging, and validating rule packages (Norm IR v0)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import yaml

from .quantity import Quantity

KINDS = {"predicates": "predicate", "tables": "table", "terms": "term", "norms": "norm"}
COMPARISONS = {"eq", "ne", "lt", "le", "gt", "ge"}
STATUSES = {"draft", "reviewed"}


@dataclass
class Element:
    kind: str
    name: str
    data: dict
    package: str


@dataclass
class Package:
    name: str
    meta: dict
    path: Path
    elements: dict[tuple[str, str], Element] = field(default_factory=dict)


@dataclass
class Ruleset:
    """A package resolved together with the packages it extends, base first."""

    chain: list[Package]
    elements: dict[tuple[str, str], Element]
    errors: list[str]

    @property
    def top(self) -> Package:
        return self.chain[-1]

    def get(self, kind: str, name: str) -> Element:
        return self.elements[(kind, name)]

    def has(self, kind: str, name: str) -> bool:
        return (kind, name) in self.elements

    @property
    def subject(self) -> str:
        """Root name for facts about the thing checked as a whole: 'building', 'system', ..."""
        return self.chain[0].meta.get("subject", "building")

    def overlays(self) -> list[Package]:
        return [p for p in self.chain if p.meta.get("adoption")]


def _read_package(path: Path) -> tuple[Package, list[str]]:
    errors: list[str] = []
    meta = yaml.safe_load((path / "package.yaml").read_text())
    pkg = Package(name=meta["package"], meta=meta, path=path)
    for file in sorted(path.glob("*.yaml")):
        if file.name == "package.yaml":
            continue
        doc = yaml.safe_load(file.read_text()) or {}
        for section, items in doc.items():
            if section not in KINDS:
                errors.append(f"{file.name}: unknown section '{section}'")
                continue
            for item in items:
                key = (KINDS[section], item["name"])
                if key in pkg.elements:
                    errors.append(f"{pkg.name}: {key[0]} '{key[1]}' is defined twice")
                pkg.elements[key] = Element(KINDS[section], item["name"], item, pkg.name)
    return pkg, errors


def load(path: str | Path) -> Ruleset:
    path = Path(path).resolve()
    pkg, errors = _read_package(path)
    base_name = pkg.meta.get("extends")
    if not base_name:
        return Ruleset([pkg], dict(pkg.elements), errors)
    base = load(path.parent / base_name)
    errors = base.errors + errors
    merged = dict(base.elements)
    replaced = {(p["kind"], p["name"]) for p in pkg.meta.get("patches", []) if p["op"] == "replace"}
    for key in replaced:
        if key not in merged:
            errors.append(f"{pkg.name}: patch replaces {key[0]} '{key[1]}', which {base_name} does not define")
        if key not in pkg.elements:
            errors.append(f"{pkg.name}: patch replaces {key[0]} '{key[1]}' but gives no replacement")
    for key, el in pkg.elements.items():
        if key in merged and key not in replaced:
            errors.append(f"{pkg.name}: {key[0]} '{key[1]}' already exists in {base_name}; add a replace patch")
        merged[key] = el
    return Ruleset(base.chain + [pkg], merged, errors)


# ---------------------------------------------------------------- amendments


def _section_matches(entry: str, section: str | None, table: str | None) -> bool:
    if entry.startswith("Table "):
        return table == entry[len("Table "):]
    if not section:
        return False
    if entry.startswith("Chapter "):
        head = section.split(".")[0]
        return head.isdigit() and int(head) // 100 == int(entry.split()[1])
    if entry.endswith("+"):
        stem = entry[:-1]
        return section == stem or section.startswith(stem + ".")
    return section == entry


def amendment_status(rs: Ruleset, el: Element | None, section: str | None, table: str | None = None) -> str:
    """How the adopting jurisdictions changed a cited provision."""
    notes = []
    for overlay in rs.overlays():
        instrument = overlay.meta["adoption"]["instrument"]
        if el is not None and el.package == overlay.name:
            notes.append(f"Replaced by {instrument}")
            continue
        deleted = [e for e in overlay.meta.get("deleted", []) if _section_matches(e, section, table)]
        if not deleted:
            notes.append(f"Not amended: not among the provisions {instrument} deletes")
            continue
        substitutes = [
            e for e in overlay.elements.values()
            if e.kind != "predicate" and _section_matches(deleted[0], e.data["cite"].get("section"), e.data["cite"].get("table"))
        ]
        if substitutes:
            notes.append(f"Deleted and replaced by {instrument} ({deleted[0]}); this pack uses the substitute")
            continue
        text = f"Deleted by {instrument} ({deleted[0]})"
        for r in overlay.meta.get("redirects", []):
            if r["from"] == deleted[0]:
                text += f"; see {r['to']}"
        notes.append(text)
    return "; ".join(notes) if notes else "Model code as published"


# ---------------------------------------------------------------- validation


def walk(expr: Any) -> Iterator[dict]:
    if isinstance(expr, dict):
        yield expr
        for v in expr.values():
            yield from walk(v)
    elif isinstance(expr, list):
        for v in expr:
            yield from walk(v)


def _has_key(obj: Any, key: str) -> bool:
    return any(key in node for node in walk(obj))


def validate(rs: Ruleset) -> tuple[list[str], list[str]]:
    errors = list(rs.errors)
    warnings: list[str] = []
    preds = {name: el for (kind, name), el in rs.elements.items() if kind == "predicate"}

    def fact_key(path: str, scope: dict[str, str], where: str) -> str | None:
        root, _, attr = path.partition(".")
        key = f"{rs.subject}.{attr}" if root == rs.subject else f"{scope[root]}.{attr}" if root in scope else None
        if key is None:
            errors.append(f"{where}: fact '{path}' uses unknown variable '{root}'")
        elif key not in preds:
            errors.append(f"{where}: fact '{path}' resolves to undeclared predicate '{key}'")
            key = None
        return key

    def enum_of(arg: Any, scope: dict[str, str], where: str) -> list | None:
        if isinstance(arg, dict) and "fact" in arg:
            key = fact_key(arg["fact"], scope, where)
            return preds[key].data.get("values") if key else None
        return None

    def check_symbol(values: list | None, lit: Any, where: str) -> None:
        if values is not None and isinstance(lit, str) and Quantity.parse(lit) is None and lit not in values:
            errors.append(f"{where}: '{lit}' is not a value of the compared fact ({', '.join(map(str, values))})")

    def check_expr(expr: Any, scope: dict[str, str], where: str) -> None:
        for node in walk(expr):
            if "fact" in node:
                fact_key(node["fact"], scope, where)
            if "term" in node:
                if not rs.has("term", node["term"]):
                    errors.append(f"{where}: unknown term '{node['term']}'")
                    continue
                target_for = rs.get("term", node["term"]).data.get("for") or {}
                of = node.get("of")
                if target_for and (of not in scope or scope[of] != next(iter(target_for.values()))):
                    errors.append(f"{where}: term '{node['term']}' needs 'of' bound to a {next(iter(target_for.values()))}")
                if not target_for and of:
                    errors.append(f"{where}: term '{node['term']}' is subject-level and takes no 'of'")
            if "lookup" in node:
                if not rs.has("table", node["lookup"]):
                    errors.append(f"{where}: unknown table '{node['lookup']}'")
                elif node.get("column") not in rs.get("table", node["lookup"]).data["columns"]:
                    errors.append(f"{where}: table '{node['lookup']}' has no column '{node.get('column')}'")
            for op in COMPARISONS & node.keys():
                a, b = node[op]
                check_symbol(enum_of(a, scope, where), b, where)
            if "in" in node:
                values = enum_of(node["in"][0], scope, where)
                for lit in node["in"][1]:
                    check_symbol(values, lit, where)
            if "cases" in node:
                for row in node["cases"]:
                    if "cite" not in row:
                        errors.append(f"{where}: every cases row needs a 'cite' with the table row or clause it comes from")
                if "else" not in node["cases"][-1]:
                    warnings.append(f"{where}: cases has no 'else' row; unmatched inputs stay unknown")

    for (kind, name), el in sorted(rs.elements.items()):
        where = f"{el.package}: {kind} '{name}'"
        d = el.data
        if d.get("status", "draft") not in STATUSES:
            errors.append(f"{where}: status must be one of {sorted(STATUSES)}")
        if kind != "predicate":
            cite = d.get("cite") or {}
            url = str(cite.get("url") or "")
            # A customer's own document has no public URL: it is cited by `at` (file and lines), with at most a
            # path in the app that shows it.
            customer = bool(cite.get("at")) and (not url or (url.startswith("/") and not url.startswith("//")))
            if not cite.get("section") or not (url.startswith("https://") or customer):
                errors.append(f"{where}: needs cite.section and an https cite.url (or cite.at for a customer document)")
        scope = dict(d.get("for") or {})
        if kind == "term":
            check_expr(d["value"], scope, where)
        if kind == "norm":
            check_expr(d["require"], scope, where)
        if kind == "table":
            key_pred = preds.get(d["key"])
            if key_pred is None or key_pred.data.get("type") != "enum":
                errors.append(f"{where}: key '{d['key']}' must be a declared enum predicate")
            seen = set()
            for row in d["rows"]:
                if row["key"] in seen:
                    errors.append(f"{where}: row key '{row['key']}' appears twice")
                seen.add(row["key"])
                if key_pred and row["key"] not in key_pred.data.get("values", []):
                    errors.append(f"{where}: row key '{row['key']}' is not a value of {d['key']}")
                if "row" not in row:
                    errors.append(f"{where}: row '{row['key']}' needs its 'row' label as printed")
            if key_pred:
                missing = [v for v in key_pred.data["values"] if v not in seen]
                if missing:
                    warnings.append(f"{where}: no row for {', '.join(missing)}; lookups fall back to the building official")

    for pkg in rs.chain:
        if pkg.meta.get("text_policy") == "link-only" and any(_has_key(el.data, "quote") for el in pkg.elements.values()):
            errors.append(f"{pkg.name}: text_policy is link-only, so elements may not store 'quote' text")

    # term cycles
    graph = {name: {n["term"] for n in walk(el.data["value"]) if "term" in n}
             for (kind, name), el in rs.elements.items() if kind == "term"}
    state: dict[str, int] = {}

    def visit(n: str, path: list[str]) -> None:
        state[n] = 1
        for m in graph.get(n, ()):
            if state.get(m) == 1:
                errors.append(f"term cycle: {' -> '.join(path + [n, m])}")
            elif m in graph and not state.get(m):
                visit(m, path + [n])
        state[n] = 2

    for n in graph:
        if not state.get(n):
            visit(n, [])
    return errors, warnings
