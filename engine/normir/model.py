"""Loading, merging, and validating rule packages (Norm IR v0)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import yaml

from .quantity import DIMENSIONS, Quantity

KINDS = {"predicates": "predicate", "tables": "table", "terms": "term", "norms": "norm"}
COMPARISONS = {"eq", "ne", "lt", "le", "gt", "ge"}
STATUSES = {"draft", "reviewed"}
MAX_EXTENDS = 16  # packages in one extends chain


# ---------------------------------------------------------------- YAML from files nobody vouches for

MAX_YAML_DEPTH = 100           # nesting levels, aliases expanded: the packs reach 22, evidence documents 7
MAX_YAML_ALIAS_NODES = 10_000  # nodes that aliases may add by repeating an anchored part (no pack uses one)


class YAMLInputError(ValueError):
    """Bytes that are not the YAML they should be: not UTF-8, not valid YAML (or a tag other than YAML's own),
    nested deeper than MAX_YAML_DEPTH, or aliases that repeat more than MAX_YAML_ALIAS_NODES nodes or refer to a
    node that contains them. The message says which, and where."""


def _yaml_children(node: yaml.Node) -> list:
    if isinstance(node, yaml.MappingNode):
        return [x for pair in node.value for x in pair]
    return list(node.value) if isinstance(node, yaml.SequenceNode) else []


def _check_expansion(root: yaml.Node | None) -> None:
    """Refuse a document whose aliases, expanded, nest deeper than MAX_YAML_DEPTH, add more than
    MAX_YAML_ALIAS_NODES nodes, or never end (an alias inside the node it names). Linear in the composed nodes:
    an anchored part is measured once however often it is repeated."""
    if root is None:
        return
    done: dict[int, tuple[int, int]] = {}  # id(node) -> (nodes, levels) once expanded
    open_: set[int] = set()
    stack: list[tuple[yaml.Node, bool]] = [(root, False)]
    while stack:
        node, measured = stack.pop()
        key = id(node)
        if measured:
            kids = [done[id(k)] for k in _yaml_children(node)]
            done[key] = (1 + sum(k[0] for k in kids), 1 + max((k[1] for k in kids), default=0))
            open_.discard(key)
            continue
        if key in done:
            continue
        if key in open_:
            raise YAMLInputError(f"an alias at line {node.start_mark.line + 1} refers to a node that contains it")
        open_.add(key)
        stack.append((node, True))
        stack.extend((k, False) for k in _yaml_children(node))
    nodes, levels = done[id(root)]
    if levels > MAX_YAML_DEPTH:
        raise YAMLInputError(f"aliases nest the document deeper than {MAX_YAML_DEPTH} levels")
    if nodes - len(done) > MAX_YAML_ALIAS_NODES:
        raise YAMLInputError(f"aliases repeat {nodes - len(done)} nodes, more than {MAX_YAML_ALIAS_NODES}")


class _BoundedLoader(yaml.SafeLoader):
    """SafeLoader that stops at MAX_YAML_DEPTH levels while composing (the composer recurses, so it must stop
    before the stack runs out) and checks every document's aliases before anything is built from it."""

    _depth = 0

    def compose_node(self, parent, index):
        self._depth += 1
        try:
            if self._depth > MAX_YAML_DEPTH:
                raise YAMLInputError(f"nested deeper than {MAX_YAML_DEPTH} levels at line {self.peek_event().start_mark.line + 1}")
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def compose_document(self):
        node = super().compose_document()
        _check_expansion(node)
        return node


def read_yaml(data: bytes | str, compose: bool = False) -> Any:
    """Read YAML (or JSON) from an untrusted file: UTF-8 only, YAML's own tags only, nesting and aliases bounded.
    Returns the data of the file's one document, or with `compose` the node graph of every document (for
    readers that keep line numbers). Raises YAMLInputError."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError as e:
            line = e.object.count(b"\n", 0, e.start) + 1
            raise YAMLInputError(f"not UTF-8 text: byte 0x{e.object[e.start]:02x} at line {line}") from None
    loader = None
    try:
        loader = _BoundedLoader(data)  # the reader refuses control characters here
        if compose:
            docs = []
            while loader.check_node():
                docs.append(loader.get_node())
            return docs
        return loader.get_single_data()
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        what = " ".join(str(getattr(e, "problem", None) or e).split())
        raise YAMLInputError(f"not valid YAML: {what}" + (f" at line {mark.line + 1}" if mark else "")) from None
    finally:
        if loader is not None:
            loader.dispose()


def _what(v: Any) -> str:
    """What a value is, in the words of an error message."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true/false"
    if isinstance(v, (int, float)):
        return "a number"
    if isinstance(v, str):
        return "text"
    return {dict: "a mapping", list: "a list"}.get(type(v), type(v).__name__)


class PackError(ValueError):
    """A package that cannot be read at all: its package.yaml is missing, unreadable, or names no package, or
    its `extends` chain loops, runs past MAX_EXTENDS, or names something other than a sibling package directory.
    What a readable package gets wrong (a malformed file, item, patch, or field) is in `Ruleset.errors`."""


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
        """Root name for facts about the thing checked as a whole: 'building', 'system', ... (the base package's
        `subject`; validate() reports a package that declares none)."""
        return self.chain[0].meta.get("subject") or "subject"

    def overlays(self) -> list[Package]:
        return [p for p in self.chain if p.meta.get("adoption")]


def _meta_errors(meta: dict, name: str) -> list[str]:
    """What is malformed in package.yaml's fields; each malformed field is removed from `meta`, so the loader and
    validate() only ever see fields of the right shape."""
    errors: list[str] = []

    def drop(key: str, msg: str) -> None:
        errors.append(f"{name}: package.yaml '{key}' {msg}")
        meta.pop(key, None)

    text = lambda v: isinstance(v, str) and bool(v)  # noqa: E731
    for key in ("extends", "subject", "text_policy"):
        if key in meta and meta[key] is not None and not text(meta[key]):
            drop(key, f"takes a name, got {_what(meta[key])}")
    patches = meta.get("patches")
    if patches is not None:
        if not isinstance(patches, list):
            drop("patches", f"takes a list of {{op, kind, name}}, got {_what(patches)}")
        else:
            bad = [i for i, p in enumerate(patches) if not isinstance(p, dict) or not all(text(p.get(k)) for k in ("op", "kind", "name"))]
            for i in bad:
                errors.append(f"{name}: package.yaml patches[{i}] needs 'op', 'kind' and 'name' (text)")
            meta["patches"] = [p for i, p in enumerate(patches) if i not in bad]
    adoption = meta.get("adoption")
    if adoption and not (isinstance(adoption, dict) and text(adoption.get("instrument"))):
        drop("adoption", "needs 'instrument' (the adopting law's name)")
    deleted = meta.get("deleted")
    if deleted is not None and not (isinstance(deleted, list) and all(
            text(d) and (not d.startswith("Chapter ") or d[len("Chapter "):].isdigit()) for d in deleted)):
        drop("deleted", "takes a list of sections ('1011.2', '103+', 'Table 1004.5', 'Chapter 9')")
    redirects = meta.get("redirects")
    if redirects is not None and not (isinstance(redirects, list) and all(
            isinstance(r, dict) and text(r.get("from")) and text(r.get("to")) for r in redirects)):
        drop("redirects", "takes a list of {from, to}")
    return errors


def _read_package(path: Path) -> tuple[Package, list[str]]:
    errors: list[str] = []
    try:
        data = (path / "package.yaml").read_bytes()
    except OSError as e:
        raise PackError(f"{path.name}: no readable package.yaml ({e.strerror or e})") from None
    try:
        meta = read_yaml(data)
    except YAMLInputError as e:
        raise PackError(f"{path.name}/package.yaml: {e}") from None
    if not isinstance(meta, dict):
        got = "empty" if meta is None else _what(meta)
        raise PackError(f"{path.name}/package.yaml: is {got}, not a mapping with the package's name under 'package'")
    if not isinstance(meta.get("package"), str) or not meta["package"]:
        got = "missing" if meta.get("package") is None else _what(meta["package"])
        raise PackError(f"{path.name}/package.yaml: 'package' takes the package's name, got {got}")
    errors += _meta_errors(meta, meta["package"])
    pkg = Package(name=meta["package"], meta=meta, path=path)
    for file in sorted(path.glob("*.yaml")):
        if file.name == "package.yaml":
            continue
        try:
            doc = read_yaml(file.read_bytes())
        except OSError as e:
            errors.append(f"{file.name}: cannot be read ({e.strerror or e})")
            continue
        except YAMLInputError as e:
            errors.append(f"{file.name}: {e}")
            continue
        if doc is None:
            continue
        if not isinstance(doc, dict):
            errors.append(f"{file.name}: maps sections ({', '.join(KINDS)}) to lists of items, got {_what(doc)}")
            continue
        for section, items in doc.items():
            if section not in KINDS:
                errors.append(f"{file.name}: unknown section '{section}'")
                continue
            if not isinstance(items, list):
                if items is not None:
                    errors.append(f"{file.name}: {section} takes a list of items, got {_what(items)}")
                continue
            for i, item in enumerate(items):
                if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"]:
                    errors.append(f"{file.name}: {section}[{i}] needs a 'name' (text)"
                                  + ("" if isinstance(item, dict) else f"; it is {_what(item)}, not a mapping"))
                    continue
                key = (KINDS[section], item["name"])
                if key in pkg.elements:
                    errors.append(f"{pkg.name}: {key[0]} '{key[1]}' is defined twice")
                pkg.elements[key] = Element(KINDS[section], item["name"], item, pkg.name)
    return pkg, errors


def load(path: str | Path) -> Ruleset:
    """A package and the packages it extends. Raises PackError for a package that cannot be read at all;
    everything else it finds wrong is in `errors` (see validate())."""
    return _load(Path(path).resolve(), ())


def _load(path: Path, below: tuple[Path, ...]) -> Ruleset:
    if path in below:
        raise PackError(f"extends loops: {' -> '.join(p.name for p in (*below, path))}")
    if len(below) >= MAX_EXTENDS:
        raise PackError(f"{below[0].name}: extends more than {MAX_EXTENDS} packages deep")
    pkg, errors = _read_package(path)
    base_name = pkg.meta.get("extends")
    if not base_name:
        return Ruleset([pkg], dict(pkg.elements), errors)
    if base_name in (".", "..") or "/" in base_name or "\\" in base_name:
        raise PackError(f"{pkg.name}: extends '{base_name}', which is not the name of a package next to it")
    base = _load((path.parent / base_name).resolve(), (*below, path))
    errors = base.errors + errors
    merged = dict(base.elements)
    replaced = {(p["kind"], p["name"]) for p in pkg.meta.get("patches") or [] if p["op"] == "replace"}
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


# ---------------------------------------------------------------- expression grammar and types

ORDERING = {"lt", "le", "gt", "ge"}
PRED_TYPE = {"bool": "bool", "number": "number", "enum": "symbol", **{d: d for d in DIMENSIONS}}


def shape_errors(expr: Any, where: str) -> list[str]:
    """Every way `expr` departs from the Norm IR expression grammar. Rules that pass can be walked and
    evaluated without structural surprises; this runs before any other check so none of them crash."""
    out: list[str] = []

    def bad(msg: str) -> None:
        out.append(f"{where}: {msg}")

    def go(e: Any) -> None:
        if e is None or isinstance(e, (bool, int, float, str)):
            return
        if isinstance(e, list):
            bad(f"a list is only allowed as an operator's arguments: {str(e)[:60]}")
            return
        if not isinstance(e, dict) or not e:
            bad(f"not an expression: {str(e)[:60]}")
            return
        keys = set(e)
        if keys == {"value"}:
            if isinstance(e["value"], (dict, list)):
                bad("'value' takes a literal")
            return
        if keys == {"fact"}:
            if not isinstance(e["fact"], str) or e["fact"].count(".") != 1 or not all(e["fact"].split(".")):
                bad(f"'fact' takes a name like var.attr, got {str(e['fact'])[:60]}")
            return
        if "term" in keys:
            if not keys <= {"term", "of"} or not isinstance(e["term"], str) or not isinstance(e.get("of", ""), str):
                bad("'term' takes a term name and optionally 'of' (a variable name)")
            return
        if "lookup" in keys:
            if keys != {"lookup", "key", "column"} or not isinstance(e["lookup"], str) or not isinstance(e["column"], str):
                bad("'lookup' takes a table name, a 'key' expression and a 'column' name")
                return
            go(e["key"])
            return
        if "cases" in keys:
            rows = e["cases"]
            if keys != {"cases"} or not isinstance(rows, list) or not rows:
                bad("'cases' takes a non-empty list of rows")
                return
            for j, row in enumerate(rows):
                if not isinstance(row, dict) or not ({"when", "then"} <= set(row) or "else" in row) or ("else" in row and j != len(rows) - 1) \
                        or not set(row) <= {"when", "then", "else", "cite"}:
                    bad("each cases row has 'when' and 'then', and only the last may be 'else'")
                    return
                cite = row.get("cite", {})
                if not isinstance(cite, dict) or any(not isinstance(v, (str, int, float)) for v in cite.values()):
                    bad("a cases row's 'cite' maps names to text")
                    return
                for k in ("when", "then", "else"):
                    if k in row:
                        go(row[k])
            return
        if len(keys) != 1:
            bad(f"an operator node has one key, got {sorted(map(str, keys))[:5]}")
            return
        (op, args), = e.items()
        if op in ("all", "any", "max", "min"):
            if not isinstance(args, list) or not args:
                bad(f"'{op}' takes a non-empty list")
                return
            for a in args:
                go(a)
        elif op in ("not", "ceil"):
            go(args)
        elif op in COMPARISONS or op in ("mul", "div"):
            if not isinstance(args, list) or len(args) != 2:
                bad(f"'{op}' takes exactly two arguments")
                return
            for a in args:
                go(a)
        elif op == "in":
            if not isinstance(args, list) or len(args) != 2 or not isinstance(args[1], list) or not args[1] \
                    or any(isinstance(x, (dict, list)) for x in args[1]):
                bad("'in' takes an expression and a non-empty list of literals")
                return
            go(args[0])
        else:
            bad(f"unknown operator '{op}'")

    go(expr)
    return out


def _literal_type(v: Any) -> str:
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        q = Quantity.parse(v)
        return "symbol" if q is None else q.dim
    return "none"


def type_errors(rs: "Ruleset", expr: Any, scope: dict[str, str], where: str, boolean: bool = False) -> list[str]:
    """Combinations that fail on every input: true/false operators over non-booleans, ordering or arithmetic
    over values that can never be compared or combined. Types are sets of what a value may be (a table cell
    may be a length or "not-permitted"), so only a combination that fails for every member is an error."""
    out: list[str] = []
    seen_terms: set[str] = set()

    def pred_type(path: str, sc: dict) -> set[str]:
        root, _, attr = path.partition(".")
        key = f"{rs.subject}.{attr}" if root == rs.subject else f"{sc.get(root)}.{attr}"
        if not rs.has("predicate", key):
            return {"any"}
        return {PRED_TYPE.get(rs.get("predicate", key).data.get("type"), "any")}

    def t(e: Any, sc: dict) -> set[str]:
        if not isinstance(e, dict):
            return {_literal_type(e)}
        if set(e) == {"value"}:
            return {_literal_type(e["value"])}
        if "fact" in e:
            return pred_type(e["fact"], sc)
        if "term" in e:
            if not rs.has("term", e["term"]) or e["term"] in seen_terms:
                return {"any"}
            seen_terms.add(e["term"])
            target = rs.get("term", e["term"]).data
            var = next(iter(target.get("for") or {}), None)
            inner = {var: sc.get(e.get("of"))} if var else {}
            got = t(target.get("value"), inner)
            seen_terms.discard(e["term"])
            return got
        if "lookup" in e:
            if not rs.has("table", e["lookup"]):
                return {"any"}
            cells = [r.get(e["column"]) for r in rs.get("table", e["lookup"]).data.get("rows", []) if e["column"] in r]
            return {_literal_type(c) for c in cells} or {"any"}
        if "cases" in e:
            got: set[str] = set()
            for row in e["cases"]:
                if "when" in row:
                    need(row["when"], sc, "a cases condition")
                got |= t(row.get("then", row.get("else")), sc)
            return got
        (op, args), = e.items()
        if op in ("all", "any"):
            for a in args:
                need(a, sc, f"'{op}'")
            return {"bool"}
        if op == "not":
            need(args, sc, "'not'")
            return {"bool"}
        if op in COMPARISONS:
            a, b = t(args[0], sc), t(args[1], sc)
            if op in ORDERING and "any" not in a | b:
                ordered = {"number", *DIMENSIONS}
                if not any(x == y and x in ordered for x in a for y in b):
                    out.append(f"{where}: '{op}' compares {'/'.join(sorted(a))} with {'/'.join(sorted(b))}, which never have an order")
            return {"bool"}
        if op == "in":
            t(args[0], sc)
            return {"bool"}
        if op in ("max", "min"):
            return set().union(*(t(a, sc) for a in args))
        if op == "ceil":
            t(args, sc)
            return {"number"}
        a, b = t(args[0], sc), t(args[1], sc)
        if "any" in a | b:
            return {"any"}
        qty = set(DIMENSIONS)
        results: set[str] = set()
        for x in a:
            for y in b:
                if op == "mul" and {x, y} <= qty | {"number"} and not (x in qty and y in qty):
                    results.add(x if x in qty else y)
                if op == "div" and x in qty | {"number"} and y in qty | {"number"} and not (x == "number" and y in qty) \
                        and not (x in qty and y in qty and x != y):
                    results.add("number" if x == y or x == "number" else x)
        if not results:
            out.append(f"{where}: '{op}' of {'/'.join(sorted(a))} and {'/'.join(sorted(b))} is never defined")
            return {"any"}
        return results

    def need(e: Any, sc: dict, what: str) -> None:
        got = t(e, sc)
        if "any" not in got and "bool" not in got:
            out.append(f"{where}: {what} needs true/false, got {'/'.join(sorted(got))}")

    if boolean:
        need(expr, scope, "the requirement")
    else:
        t(expr, scope)
    return out


def _has_key(obj: Any, key: str) -> bool:
    return any(key in node for node in walk(obj))


def _expr_nodes(expr: Any) -> Iterator[dict]:
    """The nodes of an expression that passed shape_errors, in walk() order, without the cases rows' `cite`
    (whose values are text, so they hold no operators)."""
    stack = [expr]
    while stack:
        e = stack.pop()
        if isinstance(e, list):
            stack.extend(reversed(e))
        elif isinstance(e, dict):
            yield e
            stack.extend(reversed([v for k, v in e.items() if k != "cite"]))


def _scalar(v: Any) -> bool:
    return isinstance(v, (str, int, float, bool))


def _element_errors(el: Element) -> list[str]:
    """How an element departs from the shape of its kind: the fields that validate() and the evaluator read,
    and the grammar of every expression it holds. validate() checks nothing more of an element that has any, and
    treats references to it as already reported, so no later check meets a malformed element."""
    where = f"{el.package}: {el.kind} '{el.name}'"
    d = el.data
    out: list[str] = []
    scope = d.get("for") or {}
    if not isinstance(scope, dict) or len(scope) > 1 or not all(isinstance(k, str) and isinstance(v, str) for k, v in scope.items()):
        out.append(f"{where}: 'for' binds one variable to a type name")
    if el.kind == "predicate":
        if "type" in d and not isinstance(d["type"], str):
            out.append(f"{where}: 'type' takes a type name ({', '.join(PRED_TYPE)}), got {_what(d['type'])}")
        if "values" in d and not (isinstance(d["values"], list) and all(_scalar(v) for v in d["values"])):
            out.append(f"{where}: 'values' takes a list of values, got {_what(d['values'])}")
        vocab = d.get("vocab")
        if vocab is not None and not (isinstance(vocab, str) and vocab.count(".") == 1 and all(vocab.split("."))):
            out.append(f"{where}: 'vocab' takes a vocabulary attribute like Type.attr, got {str(vocab)[:60]}")
    if el.kind in ("term", "norm"):
        body = "value" if el.kind == "term" else "require"
        out += shape_errors(d[body], where) if body in d else [f"{where}: needs '{body}'"]
    if el.kind == "norm":
        # applies: when the norm is about the subject or element at all; when_none: what it requires of the
        # subject when no element of its `for` type was found (otherwise that is not applicable).
        if "applies" in d:
            out += shape_errors(d["applies"], f"{where} applies")
        if "when_none" in d:
            wn = d["when_none"]
            if not scope:
                out.append(f"{where}: 'when_none' needs 'for'")
            elif not isinstance(wn, dict) or "require" not in wn or not set(wn) <= {"applies", "require"}:
                out.append(f"{where}: 'when_none' takes 'require' and optionally 'applies'")
            else:
                for k in ("applies", "require"):
                    if k in wn:
                        out += shape_errors(wn[k], f"{where} when_none {k}")
    if el.kind == "table":
        if not isinstance(d.get("key"), str):
            out.append(f"{where}: 'key' takes the name of an enum predicate, got {_what(d.get('key'))}")
        if not (isinstance(d.get("columns"), list) and all(isinstance(c, str) for c in d["columns"])):
            out.append(f"{where}: 'columns' takes a list of column names")
        rows = d.get("rows")
        if not isinstance(rows, list):
            out.append(f"{where}: 'rows' takes a list of rows, got {_what(rows)}")
        else:
            out += [f"{where}: rows[{i}] needs a 'key' (a value of the key predicate)"
                    for i, row in enumerate(rows) if not isinstance(row, dict) or not _scalar(row.get("key"))]
    return out


def validate(rs: Ruleset) -> tuple[list[str], list[str]]:
    errors = list(rs.errors)
    warnings: list[str] = []
    if not rs.chain[0].meta.get("subject"):
        errors.append("package declares no subject (the root name of facts about the whole thing checked: building, system, ...)")
    broken: set[tuple[str, str]] = set()  # elements with shape errors, reported once, checked no further
    for key, el in sorted(rs.elements.items(), key=lambda kv: kv[0]):
        shape = _element_errors(el)
        if shape:
            broken.add(key)
            errors += shape
    ok = Ruleset(rs.chain, {k: el for k, el in rs.elements.items() if k not in broken}, [])
    preds = {name: el for (kind, name), el in ok.elements.items() if kind == "predicate"}

    def fact_key(path: str, scope: dict[str, str], where: str) -> str | None:
        root, _, attr = path.partition(".")
        key = f"{rs.subject}.{attr}" if root == rs.subject else f"{scope[root]}.{attr}" if root in scope else None
        if key is None:
            errors.append(f"{where}: fact '{path}' uses unknown variable '{root}'")
        elif key not in preds:
            if ("predicate", key) not in broken:
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
        for node in _expr_nodes(expr):
            if "fact" in node:
                fact_key(node["fact"], scope, where)
            if "term" in node:
                if not ok.has("term", node["term"]):
                    if ("term", node["term"]) not in broken:
                        errors.append(f"{where}: unknown term '{node['term']}'")
                    continue
                target_for = ok.get("term", node["term"]).data.get("for") or {}
                of = node.get("of")
                if target_for and (of not in scope or scope[of] != next(iter(target_for.values()))):
                    errors.append(f"{where}: term '{node['term']}' needs 'of' bound to a {next(iter(target_for.values()))}")
                if not target_for and of:
                    errors.append(f"{where}: term '{node['term']}' is subject-level and takes no 'of'")
            if "lookup" in node:
                if not ok.has("table", node["lookup"]):
                    if ("table", node["lookup"]) not in broken:
                        errors.append(f"{where}: unknown table '{node['lookup']}'")
                elif node.get("column") not in ok.get("table", node["lookup"]).data["columns"]:
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

    for (kind, name), el in sorted(rs.elements.items(), key=lambda kv: kv[0]):
        where = f"{el.package}: {kind} '{name}'"
        d = el.data
        status = d.get("status", "draft")
        if not isinstance(status, str) or status not in STATUSES:
            errors.append(f"{where}: status must be one of {sorted(STATUSES)}")
        if kind != "predicate":
            cite = d.get("cite") if isinstance(d.get("cite"), dict) else {}
            url = str(cite.get("url") or "")
            # A customer's own document has no public URL: it is cited by `at` (file and lines), with at most a
            # path in the app that shows it.
            customer = bool(cite.get("at")) and (not url or (url.startswith("/") and not url.startswith("//")))
            if not cite.get("section") or not isinstance(cite["section"], str) or not (url.startswith("https://") or customer):
                errors.append(f"{where}: needs cite.section and an https cite.url (or cite.at for a customer document)")
        if (kind, name) in broken:
            continue
        scope = dict(d.get("for") or {})
        if kind in ("term", "norm"):
            body = d["value" if kind == "term" else "require"]
            check_expr(body, scope, where)
            errors += type_errors(ok, body, scope, where, boolean=kind == "norm")
        if kind == "norm":
            parts = [("applies", d["applies"], scope)] if "applies" in d else []
            if "when_none" in d:
                parts += [(f"when_none {k}", d["when_none"][k], {}) for k in ("applies", "require") if k in d["when_none"]]
            for field, expr, sc in parts:
                check_expr(expr, sc, f"{where} {field}")
                errors += type_errors(ok, expr, sc, f"{where} {field}", boolean=True)
        if kind == "table":
            key_pred = preds.get(d["key"])
            if key_pred is None or key_pred.data.get("type") != "enum":
                errors.append(f"{where}: key '{d['key']}' must be a declared enum predicate")
            values = (key_pred.data.get("values") or []) if key_pred else []
            seen = set()
            for row in d["rows"]:
                if row["key"] in seen:
                    errors.append(f"{where}: row key '{row['key']}' appears twice")
                seen.add(row["key"])
                if key_pred and row["key"] not in values:
                    errors.append(f"{where}: row key '{row['key']}' is not a value of {d['key']}")
                if "row" not in row:
                    errors.append(f"{where}: row '{row['key']}' needs its 'row' label as printed")
            missing = [v for v in values if v not in seen]
            if missing:
                warnings.append(f"{where}: no row for {', '.join(map(str, missing))}; lookups fall back to the authority having jurisdiction")

    for pkg in rs.chain:
        if pkg.meta.get("text_policy") == "link-only" and any(_has_key(el.data, "quote") for el in pkg.elements.values()):
            errors.append(f"{pkg.name}: text_policy is link-only, so elements may not store 'quote' text")

    # term cycles
    graph = {name: {n["term"] for n in walk(el.data.get("value")) if isinstance(n.get("term"), str)}
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
