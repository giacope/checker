"""Reference answers from the kernel for a benchmark file, run N times.

uv run python bench/kernel.py bench/austin.yaml [--runs 10]
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import yaml

from normir import Quantity, ask, load
from normir.quantity import UNITS

ROOT = Path(__file__).resolve().parents[1]


def answer(rs, ref: dict, unit: str) -> dict:
    a = ask(rs, ref["term"], ref.get("building", {}), ref.get("instance"))
    v = a["value"]
    if isinstance(v, Quantity) and unit in UNITS:
        v = Quantity(v.base, v.dim, unit)  # report in the unit the question asks for
    if isinstance(v, bool):
        v = int(v)  # yes/no questions are answered 1 or 0
    return {
        "value": str(v) if a["determined"] else None,
        "open_facts": a["open_facts"],
        "citations": sorted({c["section"] + (f" Table {c['table']}" if c.get("table") else "") for c in a["citations"] if c.get("section")}),
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("bench")
    p.add_argument("--runs", type=int, default=10)
    args = p.parse_args()
    spec = yaml.safe_load(open(args.bench))
    runs = []
    for _ in range(args.runs):
        rs = load(ROOT / spec["pack"])  # reload each run so nothing is cached between runs
        runs.append({q["id"]: answer(rs, q["ref"], q["unit"]) for q in spec["questions"]})
    digests = {hashlib.sha256(json.dumps(r, sort_keys=True).encode()).hexdigest()[:12] for r in runs}
    out = {"bench": args.bench, "runs": args.runs, "distinct_outputs": len(digests), "answers": runs[0]}
    dest = ROOT / "bench" / "results" / f"kernel-{Path(args.bench).stem}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    for qid, a in out["answers"].items():
        print(f"{qid:4} {a['value'] or 'open: ' + ', '.join(a['open_facts']):>12}  {', '.join(a['citations'])}")
    print(f"{args.runs} runs, {len(digests)} distinct output(s) -> {dest.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
