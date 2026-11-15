"""Score direct model answers against the kernel for one benchmark.

uv run python bench/score.py bench/austin.yaml bench/results/*/austin.json

Each results file is {"model": ..., "runs": [[{"id", "answer", "unit", "citations", "confidence"}, ...], ...]}.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def number(v):
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    m = re.match(r"^\s*(-?\d+(?:\.\d+)?)", str(v))
    return float(m.group(1)) if m else str(v)


def same(a, b) -> bool:
    if isinstance(a, float) and isinstance(b, float):
        return abs(a - b) < 1e-3
    return a == b


def main() -> None:
    bench = Path(sys.argv[1])
    kernel = json.loads((ROOT / "bench" / "results" / f"kernel-{bench.stem}.json").read_text())["answers"]
    ref = {qid: number(a["value"]) for qid, a in kernel.items()}
    report = {"bench": bench.stem, "reference": ref, "models": {}}
    for path in sys.argv[2:]:
        data = json.loads(Path(path).read_text())
        runs = [{a["id"]: a for a in run} for run in data["runs"] if run]
        per_q = {}
        for qid, r in ref.items():
            answers = [number(run.get(qid, {}).get("answer")) for run in runs]
            counts = Counter(json.dumps(a) for a in answers)
            correct = sum(same(a, r) for a in answers)
            conf = [c for c in (run.get(qid, {}).get("confidence") for run in runs) if isinstance(c, (int, float))]
            per_q[qid] = {
                "reference": r,
                "answers": dict(counts),
                "correct": correct,
                "runs": len(answers),
                "distinct": len(counts),
                "majority_correct": same(json.loads(counts.most_common(1)[0][0]), r) if counts else False,
                "mean_confidence": round(sum(conf) / len(conf), 2) if conf else None,
            }
        n = sum(q["runs"] for q in per_q.values())
        report["models"][data["model"]] = {
            "runs": len(runs),
            "accuracy": round(sum(q["correct"] for q in per_q.values()) / max(1, n), 3),
            "all_runs_agree": sum(q["distinct"] == 1 for q in per_q.values()),
            "all_runs_correct": sum(q["correct"] == q["runs"] for q in per_q.values()),
            "majority_correct": sum(q["majority_correct"] for q in per_q.values()),
            "fully_correct_runs": sum(all(same(number(run.get(qid, {}).get("answer")), r) for qid, r in ref.items()) for run in runs),
            "questions": per_q,
        }
    report["models"]["kernel"] = {"runs": json.loads((ROOT / "bench" / "results" / f"kernel-{bench.stem}.json").read_text())["runs"], "distinct_outputs": 1}
    dest = ROOT / "bench" / "results" / f"score-{bench.stem}.json"
    dest.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(f"{'model':24} {'acc':>6} {'agree':>6} {'allok':>6} {'major':>6} {'perfect runs':>13}")
    nq = len(ref)
    for m, s in report["models"].items():
        if m == "kernel":
            continue
        print(f"{m:24} {s['accuracy']:>6} {s['all_runs_agree']:>3}/{nq:<2} {s['all_runs_correct']:>3}/{nq:<2} {s['majority_correct']:>3}/{nq:<2} {s['fully_correct_runs']:>6}/{s['runs']}")
    print(f"-> {dest.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
