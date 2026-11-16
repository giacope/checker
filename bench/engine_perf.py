"""Engine timing: `run` on the largest real evidence (the NIBS clinic) and on scaled synthetic evidence.

uv run python bench/engine_perf.py [--repeats 5]

Real: every building pack with its clinic profile (bench/clinic/profiles.yaml) on bench/results/clinic-ifc.evidence.yaml
and the drawings evidence. Synthetic: the IBC door, stair and corridor norms on N elements of each type whose facts
come from two sources that disagree, so each check enumerates value sets. Prints the median of the repeats.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

import yaml

from normir import load
from normir.evidence import load_evidence, run

ROOT = Path(__file__).resolve().parents[1]


def timed(fn, repeats):
    xs = []
    for _ in range(repeats):
        t = time.perf_counter()
        n = fn()
        xs.append(time.perf_counter() - t)
    return statistics.median(xs), n


def synthetic(n: int) -> dict:
    els = []
    for i in range(n):
        els.append({"type": "Door", "id": f"door:{i}", "facts": {"clear_width": [{"value": f"{800 + i % 40} mm", "source": "a"}, {"value": f"{805 + i % 40} mm", "source": "b"}],
                                                              "height": "2100 mm", "is_external": i % 3 == 0}})
        els.append({"type": "Stair", "id": f"stair:{i}", "facts": {"headroom": "2100 mm", "rise": [{"value": "3.2 m", "source": "a"}, {"value": "3.9 m", "source": "b"}],
                                                                "handrail_height": "900 mm", "riser_height": "175 mm", "risers": 18}})
        els.append({"type": "Corridor", "id": f"corr:{i}", "facts": {"dead_end_length": f"{5 + i % 3} m", "clear_width": "1.2 m"}})
    return {"subject": {"kind": "building", "id": "synthetic"}, "sources": [{"id": "a"}, {"id": "b"}], "elements": els}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=5)
    a = ap.parse_args()
    out = {}
    docs = (ROOT / "bench/results/clinic-ifc.evidence.yaml", ROOT / "bench/clinic/drawings.evidence.yaml")
    ev = load_evidence(*docs)
    profiles = yaml.safe_load((ROOT / "bench/clinic/profiles.yaml").read_text())
    packs = {p: load(ROOT / "packs" / p) for p in profiles}
    med, rows = timed(lambda: sum(len(run(packs[p], ev, dict(prof))) for p, prof in profiles.items()), a.repeats)
    out["clinic"] = {"rows": rows, "median_s": round(med, 3), "rows_per_s": round(rows / med)}
    print(f"clinic: {rows} rows over {len(profiles)} packs, median {med:.3f} s ({rows / med:.0f} rows/s)")
    ibc = load(ROOT / "packs/ibc-2024")
    prof = {"building": {"occupancy_group": "B", "sprinkler_system": "nfpa13"}}
    for n in (100, 1000):
        sev = load_evidence(synthetic(n))
        med, rows = timed(lambda: len(run(ibc, sev, dict(prof))), a.repeats)
        out[f"synthetic_{n}"] = {"elements": 3 * n, "rows": rows, "median_s": round(med, 3), "rows_per_s": round(rows / med)}
        print(f"synthetic {3 * n} elements: {rows} rows, median {med:.3f} s ({rows / med:.0f} rows/s)")
    print(json.dumps(out))


if __name__ == "__main__":
    main()
