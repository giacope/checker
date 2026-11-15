"""Check the NIBS clinic under four rule sets through the shared evidence pipeline.

uv run --with ifcopenshell python -m bench.clinic.check <Clinic_A_20110906.ifc>

  IFC model  --adapters.ifc-->  evidence (source "ifc")      \
  drawings   --reader------->  evidence (source "drawings")  --> reconcile --> run(pack, profile) --> verdicts
  profiles.yaml: each jurisdiction's classifications          /

The same pipeline checks code: adapters.code_static and a model reader emit
evidence in vocab/code.yaml terms instead (bench/code_check.py).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from adapters.ifc import extract
from normir import load
from normir.evidence import conflicts, load_evidence, run, summarize

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).parent


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("ifc")
    args = p.parse_args()
    ifc_doc = extract(args.ifc)
    (ROOT / "bench" / "results" / "clinic-ifc.evidence.yaml").write_text(yaml.safe_dump(ifc_doc, allow_unicode=True, sort_keys=False, width=120))
    ev = load_evidence(ifc_doc, HERE / "drawings.evidence.yaml")
    profiles = yaml.safe_load((HERE / "profiles.yaml").read_text())
    report = {"ifc": Path(args.ifc).name, "conflicts": conflicts(ev), "packs": {}}
    for pack, profile in profiles.items():
        rows = run(load(ROOT / "packs" / pack), ev, profile)
        report["packs"][pack] = {"summary": summarize(rows), "rows": rows}
        for r in rows:
            if r["type"] == "Door" and r["verdict"] == "pass":
                continue
            deciding = {k: [v["value"] for v in vs] for k, vs in r["deciding"].items()}
            print(f"{pack:14} {r['norm']:9} {str(r['element'])[:24]:24} {r['verdict']:10}" + (f" decided by {deciding}" if deciding else "") + (f" open {r['open']}" if r["open"] else ""))
        doors = [r for r in rows if r["type"] == "Door"]
        if doors:
            print(f"{pack:14} {'404.2.3':9} {len(doors)} doors: " + ", ".join(f"{k} {v}" for k, v in sorted({x['verdict']: sum(1 for y in doors if y['verdict'] == x['verdict']) for x in doors}.items())))
    # A conflict matters when some verdict turns on it.
    deciding = {(r["element"], k) for pk in report["packs"].values() for r in pk["rows"] for k in r["deciding"]}
    vocab_of = {"people_served": "occupant_load", "riser": "riser_height", "tread": "tread_depth", "exit_access_travel_distance": "travel_distance"}
    deciding |= {(e, vocab_of.get(k, k)) for e, k in deciding}
    for c in report["conflicts"]:
        c["decides_a_verdict"] = (c["element"], c["fact"]) in deciding
        print(f"conflict {c['element'][:24]:24} {c['fact']:14} {[v['value'] for v in c['values']]}  {'DECIDES A VERDICT' if c['decides_a_verdict'] else 'no verdict depends on it'}")
    dest = ROOT / "bench" / "results" / "clinic-check.json"
    dest.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n")
    print(f"-> {dest.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
