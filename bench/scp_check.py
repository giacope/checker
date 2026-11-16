"""Customer-regulation benchmark: a compiled regulation's verdicts on real repositories, graded against blind labels.

uv run python bench/scp_check.py [<repo>[:<scan.json>] ...]   # default: every bench/scp/<repo>.scan.json with labels

bench/scp/regulation.json is what adapters.regulation compiled from the OWASP Secure Coding Practices Quick
Reference Guide v2.0 (CC BY-SA 3.0; its clauses are quoted). The pack is built from it with the current
build_pack. bench/scp/<repo>.scan.json holds the evidence documents app.scan.collect produced for the pinned
checkout (bench/scp_scan.py). bench/scp/<repo>.truth.yaml labels every computed and assessed check, made by
reading the repository blind to the system's output: fail, pass, undecidable (the repository cannot settle it) or
not_applicable. Where a second labeller's file exists (<repo>.truth.b.yaml) the labellers' agreement is reported,
and the system is also graded on the checks both labellers agree on.

Reports per repository: precision and recall of fail and pass, how often "doesn't apply" is right, the system's
failures split by what they rest on (cited code, or nothing found where it searched), and its wrong passes.
"""

from __future__ import annotations

import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapters.regulation import build_pack, upgrade  # noqa: E402
from app.scan import SOURCES, VOCAB  # noqa: E402
from normir import load  # noqa: E402
from normir.evaluate import facts_in  # noqa: E402
from normir.evidence import load_evidence, prefer_sources, run, summarize  # noqa: E402

HERE = ROOT / "bench" / "scp"
SYSTEM = {"pass": "pass", "fail": "fail", "unknown": "open", "uncertain": "open", "not_applicable": "not_applicable"}


def verdicts(rs, docs: list[dict]) -> tuple[dict[str, str], dict[str, str]]:
    """norm -> the system's verdict, and norm -> what the reviewer's answer rests on (evidence or absence)."""
    ev = prefer_sources(load_evidence(*(upgrade(d) for d in docs)), SOURCES, narrow=True)
    got = {n: SYSTEM[s["verdict"]] for n, s in summarize(run(rs, ev)).items()}
    basis = {}
    for (kind, name), el in rs.elements.items():
        if kind != "norm":
            continue
        for f in facts_in([el.data.get("require"), el.data.get("when_none")]):
            obs = ev.facts[f.rpartition(".")[2]].observations if f.rpartition(".")[2] in ev.facts else []
            if f.rpartition(".")[2].startswith("req_") and obs:
                basis[name] = "absence" if all(o.get("basis") == "absence" for o in obs) else "evidence"
    return {n: got.get(n, "not_applicable") for (k, n) in rs.elements if k == "norm"}, basis


def score(got: dict[str, str], basis: dict[str, str], labels: dict[str, dict]) -> dict:
    rows = [{"check": c, "truth": lab["truth"], "system": got.get(c, "not_applicable"), "basis": basis.get(c)} for c, lab in labels.items()]
    out = {"checks": len(rows), "confusion": {f"{s} vs {t}": n for (s, t), n in sorted(Counter((r["system"], r["truth"]) for r in rows).items())}}
    for v in ("fail", "pass", "not_applicable"):
        said = [r for r in rows if r["system"] == v]
        truth_v = [r for r in rows if r["truth"] == v]
        out[v] = {"said": len(said), "right": sum(r["truth"] == v for r in said), "labelled": len(truth_v),
                  "found": sum(r["system"] == v for r in truth_v)}
        out[v]["precision"] = round(out[v]["right"] / len(said), 3) if said else None
        out[v]["recall"] = round(out[v]["found"] / len(truth_v), 3) if truth_v else None
    for b in ("evidence", "absence"):
        said = [r for r in rows if r["system"] == "fail" and r["basis"] == b]
        out[f"fail_on_{b}"] = {"said": len(said), "right": sum(r["truth"] == "fail" for r in said),
                               "contradicts_a_labelled_pass": sum(r["truth"] == "pass" for r in said)}
    out["decisive"] = sum(r["system"] in ("pass", "fail") for r in rows)
    out["decisive_right"] = sum(r["system"] == r["truth"] for r in rows if r["system"] in ("pass", "fail"))
    out["open"] = sum(r["system"] == "open" for r in rows)
    out["wrong_pass"] = [r["check"] for r in rows if r["system"] == "pass" and r["truth"] == "fail"]
    out["wrong_fail"] = [r["check"] for r in rows if r["system"] == "fail" and r["truth"] == "pass"]
    return out


def agreement(a: dict[str, dict], b: dict[str, dict]) -> dict:
    keys = sorted(set(a) & set(b))
    same = sum(a[k]["truth"] == b[k]["truth"] for k in keys)
    pa, pb = Counter(a[k]["truth"] for k in keys), Counter(b[k]["truth"] for k in keys)
    chance = sum(pa[v] * pb[v] for v in pa) / len(keys) ** 2
    return {"checks": len(keys), "agree": same, "kappa": round((same / len(keys) - chance) / (1 - chance), 3),
            "pairs": {f"{x} / {y}": n for (x, y), n in sorted(Counter((a[k]["truth"], b[k]["truth"]) for k in keys).items()) if x != y}}


def main() -> None:
    reg = json.loads((HERE / "regulation.json").read_text())
    voc = yaml.safe_load((ROOT / "vocab" / f"{reg['domain']}.yaml").read_text()) if reg.get("domain") != "code" else VOCAB
    names = sys.argv[1:] or sorted(p.name.split(".")[0] for p in HERE.glob("*.truth.yaml"))
    report = {}
    with tempfile.TemporaryDirectory() as d:
        rs = load(build_pack(reg, voc, Path(d) / "pack"))
        for arg in names:
            name, _, path = arg.partition(":")
            scan = Path(path) if path else HERE / f"{name}.scan.json"
            if not scan.is_file():
                print(f"{name}: no {scan.name}, skipped")
                continue
            got, basis = verdicts(rs, json.loads(scan.read_text())["docs"])
            labels = yaml.safe_load((HERE / f"{name}.truth.yaml").read_text())["labels"]
            r = {"labels": score(got, basis, labels)}
            second = HERE / f"{name}.truth.b.yaml"
            if second.is_file():
                lb = yaml.safe_load(second.read_text())["labels"]
                r["labellers"] = agreement(labels, lb)
                r["second_labels"] = score(got, basis, lb)
                r["both_agree"] = score(got, basis, {k: v for k, v in labels.items() if lb.get(k, {}).get("truth") == v["truth"]})
            report[name] = r
            s = r["labels"]
            print(f"\n{name}: {s['checks']} checks, {s['decisive']} decided ({s['decisive_right']} right), {s['open']} open")
            for v in ("fail", "pass", "not_applicable"):
                print(f"  {v:15} said {s[v]['said']:3}  precision {s[v]['precision']}  recall {s[v]['recall']}")
            print(f"  fails citing code {s['fail_on_evidence']}  fails on nothing found {s['fail_on_absence']}")
            print(f"  wrong passes {s['wrong_pass']}  wrong fails {s['wrong_fail']}")
            if "labellers" in r:
                print(f"  labellers agree on {r['labellers']['agree']} of {r['labellers']['checks']} (kappa {r['labellers']['kappa']}); "
                      f"on those, fail precision {r['both_agree']['fail']['precision']}, pass precision {r['both_agree']['pass']['precision']}")
    dest = ROOT / "bench" / "results" / ("score-scp.json" if not any(":" in a for a in names) else "score-scp-custom.json")
    dest.write_text(json.dumps(report, indent=1) + "\n")
    print(f"\n-> {dest.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
