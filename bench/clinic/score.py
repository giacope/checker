"""Compare models' per-element clinic verdicts with the kernel's.

uv run python bench/clinic/score.py bench/results/*/clinic.json

The kernel's verdicts come from bench/results/clinic-check.json (run check.py first).
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKS = {  # prompt check -> (pack, norm)
    "C1": ("austin-2024", "1011.2"), "C2": ("austin-2024", "1011.5.2"), "C3": ("austin-2024", "1017.2"),
    "C4": ("jp-bsa-egress", "令23条1項"), "C5": ("uk-adb-v2", "ADB2 2.7"), "C6": ("uk-adb-v2", "ADB2 3.10"),
}


def norm_el(e: str) -> str:
    e = str(e).strip()
    low = e.lower()
    if "first" in low or low in ("1f", "level 1", "floor 1"):
        return "First Floor"
    if "second" in low or low in ("2f", "level 2", "floor 2"):
        return "Second Floor"
    m = re.search(r"[0-9A-Za-z_$]{22}", e)
    return m.group(0) if m else e


def norm_v(v: str) -> str:
    v = str(v).lower().strip()
    return {"compliant": "pass", "complies": "pass", "non-compliant": "fail", "unknown": "uncertain"}.get(v, v)


def main() -> None:
    k = json.loads((ROOT / "bench" / "results" / "clinic-check.json").read_text())
    ref = {}
    for c, (pack, norm) in CHECKS.items():
        for r in k["packs"][pack]["rows"]:
            if r["norm"] == norm:
                ref[(c, str(r["element"]))] = r["verdict"]
    ref_doors = {r["element"]: r["verdict"] for r in k["packs"]["ada-2010"]["rows"] if r["verdict"] != "pass"}
    report = {"reference": {f"{a} {b}": v for (a, b), v in ref.items()}, "reference_doors": ref_doors, "models": {}}
    print(f"{'model':18} {'run':>3} {'agree':>7} {'doors J':>8} {'width conflict':>15} {'tread conflict':>15}")
    for path in sys.argv[1:]:
        data = json.loads(Path(path).read_text())
        runs = [r for r in data["runs"] if r]
        per_item: dict[tuple, list] = {key: [] for key in ref}
        rows = []
        for i, run in enumerate(runs, 1):
            got = {}
            for v in run.get("verdicts", []):
                got[(v.get("check"), norm_el(v.get("element", "")))] = norm_v(v.get("verdict"))
            for key in ref:
                per_item[key].append(got.get(key, "missing"))
            agree = sum(got.get(key) == val for key, val in ref.items())
            doors = {norm_el(d.get("guid", "")) for d in run.get("doors_not_certain", [])}
            inter = len(doors & set(ref_doors))
            jacc = inter / len(doors | set(ref_doors)) if doors | set(ref_doors) else 1.0
            text = json.dumps(run.get("conflicts_found", [])) + json.dumps(run.get("verdicts", []))
            width = bool(re.search(r"1\s?000", text) and re.search(r"1\s?210", text))
            tread = bool(re.search(r"\b279\b", text) and re.search(r"\b280\b", text))
            rows.append({"run": i, "agree": agree, "items": len(ref), "doors_listed": len(doors), "doors_overlap": inter,
                         "doors_jaccard": round(jacc, 2), "found_width_conflict": width, "found_tread_conflict": tread})
            print(f"{data['model']:18} {i:>3} {agree:>3}/{len(ref):<3} {jacc:>8.2f} {str(width):>15} {str(tread):>15}")
        stable = sum(len(set(v)) == 1 for v in per_item.values())
        report["models"][data["model"]] = {
            "runs": rows,
            "items_stable_across_runs": f"{stable}/{len(ref)}",
            "per_item": {f"{a} {b}": {"kernel": ref[(a, b)], "model": dict(Counter(v))} for (a, b), v in per_item.items()},
        }
        print(f"{data['model']:18} items with the same verdict in every run: {stable}/{len(ref)}")
    dest = ROOT / "bench" / "results" / "score-clinic.json"
    dest.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(f"-> {dest.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
