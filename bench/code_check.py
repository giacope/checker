"""Code benchmark: compare four ways of answering C1-C12 with the truth labels.

uv run python bench/code_check.py bench/results/*/code.json

  kernel-static   the packs on bench/evidence/<repo>.static.yaml (adapters.code_static)
  kernel-oracle   the packs on the facts in the truth file: isolates pack error from extraction error
  kernel+<model>  the packs on static facts reconciled with one model run's reported facts (all values pooled)
  kernel+pref     the same, with source precedence: static wins on measured facts, the model on judged ones
  kernel+narrow  kernel+pref, and where static sites disagree a model value among theirs narrows the fact
  kernel+reader-first  precedence to the model reader on every fact; static facts fill what the reader left out
  direct <model>  the model's own verdicts

Each check maps to the norms that encode it (CHECKS). A check fails when any of its
norms fails on any element, then uncertain, then unknown, else pass; not_applicable
when the repository has no element of the check's type. The kernel's "unknown"
(a fact no source gave) is scored as "uncertain": both mean the evidence does not
decide the check. Failing locators are compared for element checks only, file and
line within LINE_TOLERANCE.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import yaml

from normir import load
from normir.evidence import LINE_TOLERANCE, CODE_LOCATOR, load_evidence, prefer_sources, rank_by_kind, run

ROOT = Path(__file__).resolve().parents[1]
REPOS = ["juice-shop", "NodeGoat", "pygoat", "full-stack-fastapi-template"]
CHECKS = {  # check -> (pack, norms)
    "C1": ("owasp-asvs-5", ["V11.4.2"]),
    "C2": ("owasp-asvs-5", ["V1.2.4"]),
    "C3": ("owasp-asvs-5", ["V3.3.1", "V3.3.2", "V3.3.4"]),
    "C4": ("owasp-asvs-5", ["V9.1.1", "V9.1.2"]),
    "C5": ("owasp-asvs-5", ["V13.3.1"]),
    "C6": ("owasp-asvs-5", ["V16.2.5"]),
    "C7": ("nist-800-63b-4", ["3.1.1.2 minimum length"]),
    "C8": ("nist-800-63b-4", ["3.1.1.2 no composition rules"]),
    "C9": ("nist-800-63b-4", ["3.1.1.2 blocklist"]),
    "C10": ("nist-800-63b-4", ["3.1.1.2 rate limiting"]),
    "C11": ("gdpr", ["art17_erasure_path"]),
    "C12": ("gdpr", ["chapter5_transfer_basis"]),
}
ELEMENT_CHECKS = {"C1", "C2", "C3", "C4", "C5", "C6", "C12"}
PACKS = {p: load(ROOT / "packs" / p) for p, _ in CHECKS.values()}
VOCAB = yaml.safe_load((ROOT / "vocab" / "code.yaml").read_text())
PREFER = rank_by_kind(VOCAB, {"measured": ["static", "llm"], "judged": ["llm", "static"], "given": ["llm", "static"]})
READER_FIRST = rank_by_kind(VOCAB, {k: ["llm", "static"] for k in ("measured", "judged", "given")})


def _norm_v(v) -> str:
    v = str(v).lower().strip().replace("-", "_").replace(" ", "_")
    return {"unknown": "uncertain", "n/a": "not_applicable", "na": "not_applicable"}.get(v, v)


def kernel(*docs, prefer=None, narrow=False) -> dict[str, dict]:
    ev = load_evidence(*docs)
    if prefer is not None:
        ev = prefer_sources(ev, prefer, narrow=narrow)
    rows = {p: run(rs, ev) for p, rs in PACKS.items()}
    out = {}
    for c, (pack, norms) in CHECKS.items():
        rs = [r for r in rows[pack] if r["norm"] in norms]
        seen = Counter(r["verdict"] for r in rs)
        v = next((x for x in ("fail", "uncertain", "unknown") if x in seen), "pass" if rs else "not_applicable")
        failing = sorted({(r.get("at") or [r["element"]])[0] for r in rs if r["verdict"] == "fail"})
        open_ = sorted({f for r in rs if r["verdict"] in ("unknown", "uncertain") for f in (r["open"] or list(r["deciding"]))})
        out[c] = {"verdict": _norm_v(v), "failing": failing, "open": open_}
    return out


def _observations(value, at, source):
    vals = value if isinstance(value, list) else [value]
    return [{"value": x, "source": source, **({"at": at} if at else {})} for x in vals if x is not None]


def model_doc(repo: str, reply: dict, source: str) -> dict:
    """A model's reported facts as an evidence document."""
    facts: dict[str, list] = {}
    for k, v in (reply.get("system") or {}).items():
        facts.setdefault(k, []).extend(_observations(v, None, source))
    elements = []
    for i, e in enumerate(reply.get("elements") or []):
        f = {k: _observations(v, e.get("at"), source) for k, v in (e.get("facts") or {}).items()}
        f = {k: v for k, v in f.items() if v}
        if e.get("type") == "system":
            for k, v in f.items():
                facts.setdefault(k, []).extend(v)
            continue
        elements.append({"type": e["type"], "id": f"{source}:{e['type']}@{e.get('at') or i}", "at": e.get("at") or f"{source}:{i}", "facts": f})
    return {"subject": {"kind": "system", "id": repo}, "sources": [{"id": source, "kind": "model_reading"}], "facts": facts, "elements": elements}


def truth_doc(t: dict) -> dict:
    facts = {k: _observations(v.get("value"), (v.get("at") or [None])[0], "truth") for k, v in (t.get("system") or {}).items()}
    elements = [{"type": e["type"], "id": f"truth:{e['type']}@{e['at']}", "at": e["at"],
                 "facts": {k: v for k, v in ((k, _observations(x, e["at"], "truth")) for k, x in (e.get("facts") or {}).items()) if v}}
                for e in t.get("elements") or []]
    return {"subject": {"kind": "system", "id": t["repo"]}, "sources": [{"id": "truth", "kind": "label"}], "facts": {k: v for k, v in facts.items() if v}, "elements": elements}


def _match(a: str, b: str) -> bool:
    ma, mb = CODE_LOCATOR.match(str(a).strip()), CODE_LOCATOR.match(str(b).strip())
    if not (ma and mb):
        return str(a).strip() == str(b).strip()
    pa, pb = ma["path"].lstrip("./"), mb["path"].lstrip("./")
    return (pa == pb or pa.endswith("/" + pb) or pb.endswith("/" + pa)) and abs(int(ma["line"]) - int(mb["line"])) <= LINE_TOLERANCE


def locator_pr(found: list[str], truth: list[str]) -> tuple[int, int, int]:
    """(true positives among found, len(found), truth locators recovered)."""
    tp = sum(1 for f in found if any(_match(f, t) for t in truth))
    rec = sum(1 for t in truth if any(_match(f, t) for f in found))
    return tp, len(found), rec


def score(answers: dict[str, dict], truth: dict) -> dict:
    per = {}
    for c in CHECKS:
        a, t = answers.get(c, {}), truth["verdicts"][c]
        tv, av = _norm_v(t["verdict"]), _norm_v(a.get("verdict", "missing"))
        row = {"verdict": av, "truth": tv, "agree": av == tv}
        if c in ELEMENT_CHECKS and tv == "fail" and av == "fail":
            row["locators"] = locator_pr(a.get("failing") or [], t.get("failing") or [])
        per[c] = row
    return per


def main() -> None:
    truths = {r: yaml.safe_load((ROOT / "bench" / "code-truth" / f"{r}.yaml").read_text()) for r in REPOS}
    results: dict[str, dict[str, list[dict]]] = {}  # method -> repo -> [scored run]
    for r in REPOS:
        static = ROOT / "bench" / "evidence" / f"{r}.static.yaml"
        results.setdefault("kernel-static", {})[r] = [score(kernel(static), truths[r])]
        results.setdefault("kernel-oracle", {})[r] = [score(kernel(truth_doc(truths[r])), truths[r])]
    for path in sys.argv[1:]:
        data = json.loads(Path(path).read_text())
        m = data["model"]
        for run_ in data["runs"]:
            reply, r = run_["reply"], run_["repo"]
            direct = {v["check"]: v for v in reply.get("verdicts") or []}
            results.setdefault(f"direct {m}", {}).setdefault(r, []).append(score(direct, truths[r]))
            static, mdoc = ROOT / "bench" / "evidence" / f"{r}.static.yaml", model_doc(r, reply, f"llm:{m}#{run_['run']}")
            results.setdefault(f"kernel+ {m}", {}).setdefault(r, []).append(score(kernel(static, mdoc), truths[r]))
            results.setdefault(f"kernel+pref {m}", {}).setdefault(r, []).append(score(kernel(static, mdoc, prefer=PREFER), truths[r]))
            results.setdefault(f"kernel+narrow {m}", {}).setdefault(r, []).append(score(kernel(static, mdoc, prefer=PREFER, narrow=True), truths[r]))
            results.setdefault(f"kernel+reader-first {m}", {}).setdefault(r, []).append(score(kernel(static, mdoc, prefer=READER_FIRST), truths[r]))
            results.setdefault(f"kernel-model-only {m}", {}).setdefault(r, []).append(score(kernel(model_doc(r, reply, f"llm:{m}")), truths[r]))

    print(f"{'method':34} " + " ".join(f"{r[:10]:>10}" for r in REPOS) + f" {'all':>7} {'stable':>7} {'loc P':>6} {'loc R':>6}")
    summary = {}
    for method, by_repo in results.items():
        cells, tot, n, stable, pairs = [], 0, 0, 0, 0
        tp = found = rec = tl = 0
        for r in REPOS:
            runs = by_repo.get(r, [])
            agree = sum(row["agree"] for run_ in runs for row in run_.values())
            cells.append(f"{agree / len(runs):>10.1f}" if runs else f"{'-':>10}")
            tot += agree
            n += len(runs) * len(CHECKS)
            for c in CHECKS:
                pairs += 1
                stable += len({run_[c]["verdict"] for run_ in runs}) <= 1
                for run_ in runs:
                    if "locators" in run_[c]:
                        a, b, cr = run_[c]["locators"]
                        tp, found, rec = tp + a, found + b, rec + cr
                        tl += len(truths[r]["verdicts"][c].get("failing") or [])
        summary[method] = {"agree": tot, "of": n, "stable_pairs": stable, "pairs": pairs,
                           "locator_precision": tp / found if found else None, "locator_recall": rec / tl if tl else None,
                           "per_repo": {r: [{c: row for c, row in run_.items()} for run_ in by_repo.get(r, [])] for r in REPOS}}
        p = f"{tp / found:>6.2f}" if found else f"{'-':>6}"
        rc = f"{rec / tl:>6.2f}" if tl else f"{'-':>6}"
        print(f"{method:34} " + " ".join(cells) + f" {tot / n * 100:>6.1f}% {stable:>3}/{pairs:<3} {p} {rc}")
    print("\nper check (mean agreement over repos and runs):")
    print(f"{'method':34} " + " ".join(f"{c:>4}" for c in CHECKS))
    for method, by_repo in results.items():
        line = []
        for c in CHECKS:
            xs = [run_[c]["agree"] for r in REPOS for run_ in by_repo.get(r, [])]
            line.append(f"{sum(xs) / len(xs):>4.2f}" if xs else f"{'-':>4}")
        print(f"{method:34} " + " ".join(line))
    print("\ndisagreements with truth (method repo check: answer vs truth):")
    for method, by_repo in results.items():
        for r in REPOS:
            for c in CHECKS:
                got = Counter(run_[c]["verdict"] for run_ in by_repo.get(r, []) if not run_[c]["agree"])
                if got:
                    print(f"  {method:34} {r[:12]:12} {c:4} {dict(got)} vs {truths[r]['verdicts'][c]['verdict']}")
    dest = ROOT / "bench" / "results" / "score-code.json"
    dest.write_text(json.dumps(summary, indent=1, ensure_ascii=False) + "\n")
    print(f"-> {dest.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
