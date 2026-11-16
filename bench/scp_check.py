"""Customer-regulation benchmark: a compiled regulation's verdicts on one repository, graded against blind labels.

uv run python bench/scp_check.py [<compiled pack dir> <scan.json> [<labels.yaml>]]

Defaults to bench/scp-railsgoat/: the pack adapters.regulation compiled from the OWASP Secure Coding Practices
Quick Reference Guide v2.0 (CC BY-SA 3.0, its clauses are quoted), and the evidence documents app.scan stored for
OWASP/railsgoat at f5951f1 with the Codex model. Labels (bench/scp-railsgoat-truth.yaml) were made by reading the
repository blind to the system's output: fail, pass, undecidable (the repository cannot settle it) or
not_applicable. Reports how often a decisive verdict is right, how many labelled failures the system finds, and
splits the system's failures by what they rest on: cited code, or no matching code in what was searched.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.scan import SOURCES  # noqa: E402
from normir import load  # noqa: E402
from normir.evidence import load_evidence, prefer_sources, run, summarize  # noqa: E402

SYSTEM = {"pass": "pass", "fail": "fail", "unknown": "open", "uncertain": "open", "not_applicable": "not_applicable"}


def grade(pack: Path, scan: Path, truth: Path) -> dict:
    rs = load(pack)
    docs = json.loads(scan.read_text())["docs"]
    ev = prefer_sources(load_evidence(*docs), SOURCES, narrow=True)
    verdicts = {n: SYSTEM[s["verdict"]] for n, s in summarize(run(rs, ev)).items()}
    labels = yaml.safe_load(truth.read_text())["labels"]
    basis = {}  # norm -> what the model's answer rests on, for assessed checks
    for (kind, name), el in rs.elements.items():
        fact = (el.data.get("require") or {}).get("fact") if kind == "norm" and isinstance(el.data.get("require"), dict) else None
        f = ev.facts.get(fact.rpartition(".")[2]) if fact else None
        if f and f.observations:
            basis[name] = f.observations[0].get("basis") or ("evidence" if f.observations[0].get("at") else "?")
    rows = [{"check": c, "truth": lab["truth"], "confidence": lab.get("confidence"), "system": verdicts.get(c, "not_applicable"),
             "basis": basis.get(c)} for c, lab in sorted(labels.items(), key=lambda kv: [int(x) for x in kv[0][1:].split("-")])]
    confusion = Counter((r["system"], r["truth"]) for r in rows)
    out = {"checks": len(rows), "confusion": {f"{s} vs {t}": n for (s, t), n in sorted(confusion.items())}}
    for v in ("fail", "pass"):
        said = [r for r in rows if r["system"] == v]
        out[f"{v}_precision"] = round(sum(r["truth"] == v for r in said) / len(said), 3) if said else None
        out[f"{v}_said"] = len(said)
        truth_v = [r for r in rows if r["truth"] == v]
        out[f"{v}_recall"] = round(sum(r["system"] == v for r in truth_v) / len(truth_v), 3) if truth_v else None
    for b in ("evidence", "absence"):
        said = [r for r in rows if r["system"] == "fail" and r["basis"] == b]
        out[f"fail_on_{b}"] = {"said": len(said), "right": sum(r["truth"] == "fail" for r in said)}
    out["wrong_pass"] = [r["check"] for r in rows if r["system"] == "pass" and r["truth"] == "fail"]
    out["wrong_fail"] = [r["check"] for r in rows if r["system"] == "fail" and r["truth"] == "pass"]
    out["decisive_on_undecidable"] = [f"{r['check']}:{r['system']}" for r in rows if r["truth"] == "undecidable" and r["system"] in ("pass", "fail")]
    out["rows"] = rows
    return out


def main() -> None:
    here = ROOT / "bench" / "scp-railsgoat"
    pack, scan = (Path(sys.argv[1]), Path(sys.argv[2])) if len(sys.argv) > 2 else (here / "pack", here / "scan.json")
    truth = Path(sys.argv[3]) if len(sys.argv) > 3 else ROOT / "bench" / "scp-railsgoat-truth.yaml"
    out = grade(pack, scan, truth)
    for k, v in out.items():
        if k != "rows":
            print(f"{k:24} {v}")
    dest = ROOT / "bench" / "results" / "score-scp-railsgoat.json"
    dest.write_text(json.dumps(out, indent=1) + "\n")
    print(f"-> {dest.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
