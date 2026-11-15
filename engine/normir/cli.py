"""normir validate | ask | status"""

from __future__ import annotations

import argparse
import json
import sys

import yaml

from .evaluate import ask
from .model import amendment_status, load, validate
from .quantity import Quantity


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="normir")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate", help="check a package and everything it extends")
    v.add_argument("package")

    a = sub.add_parser("ask", help="evaluate a term on a project profile")
    a.add_argument("package")
    a.add_argument("term")
    a.add_argument("--profile", help="YAML file with a 'building' map of known facts")
    a.add_argument("--set", action="append", default=[], metavar="FACT=VALUE",
                   help="override a building fact, e.g. --set sprinkler_system=none")
    a.add_argument("--json", action="store_true")

    s = sub.add_parser("status", help="how the adopting jurisdiction changed a section")
    s.add_argument("package")
    s.add_argument("section")
    s.add_argument("--table", action="store_true", help="the section is a table number")

    args = p.parse_args(argv)
    rs = load(args.package)

    if args.cmd == "validate":
        errors, warnings = validate(rs)
        counts = {}
        for kind, _ in rs.elements:
            counts[kind] = counts.get(kind, 0) + 1
        print(" → ".join(f"{pkg.name}@{pkg.meta['version']}" for pkg in rs.chain))
        print(", ".join(f"{n} {k}s" for k, n in sorted(counts.items())))
        for w in warnings:
            print(f"warning: {w}")
        for e in errors:
            print(f"error: {e}")
        print("valid" if not errors else f"{len(errors)} errors")
        return 1 if errors else 0

    if args.cmd == "status":
        section = None if args.table else args.section
        table = args.section if args.table else None
        print(amendment_status(rs, None, section, table))
        return 0

    building = {}
    if args.profile:
        building = (yaml.safe_load(open(args.profile)) or {}).get("building", {})
    for item in args.set:
        k, _, val = item.partition("=")
        building[k] = yaml.safe_load(val)
    result = ask(rs, args.term, building)
    if args.json:
        print(json.dumps(result, indent=2, default=lambda o: str(o) if isinstance(o, Quantity) else repr(o)))
        return 0
    print(f"{result['title']}")
    print(f"  {result['answer']}")
    if result["open_facts"]:
        print(f"  open facts: {', '.join(result['open_facts'])}")
    for c in result["ruled_out"]:
        print(f"  ruled out by the profile: {c.get('row') or c['section']}")
    print("  sources:")
    for c in result["citations"]:
        where = f"§{c['section']}" + (f", Table {c['table']}" if c.get("table") else "")
        row = f" — {c['row']}" if c.get("row") else ""
        print(f"    {where}{row} [{c['status']}]")
        print(f"      {c['url']}")
        print(f"      {c['amendment']}")
    for s in result["not_formalized"]:
        print(f"  not formalized yet, may modify this answer: §{s}")
    for n in result["notes"]:
        print(f"  note: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
