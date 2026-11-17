"""Turn an evaluation into a report: one entry per requirement, with its citation, verdict, the code behind it,
what would settle an open verdict, remediation guidance, and an honest statement of what was not checked."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import yaml

from normir.evidence import conflicts
from normir.model import walk

ROOT = Path(__file__).resolve().parents[1]
ASVS_INVENTORY = yaml.safe_load((Path(__file__).parent / "asvs-inventory.yaml").read_text())
ORDER = {"fail": 0, "uncertain": 1, "unknown": 2, "pass": 3, "not_applicable": 4}
VERDICT_LABEL = {"fail": "Fails", "uncertain": "Uncertain", "unknown": "Needs input", "pass": "Passes", "not_applicable": "Not applicable"}
TYPE_LABEL = {"PasswordStore": "password storage", "Query": "database query", "Cookie": "cookie", "TokenVerification": "token check",
              "Secret": "secret in source", "LogStatement": "log statement", "Transfer": "data transfer", "Dependency": "dependency",
              "CommandExecution": "OS command", "HtmlOutput": "unescaped HTML output", "MassAssignment": "mass assignment",
              "Deserialization": "deserialization"}


def _guidance(rs) -> dict[str, str]:
    """Guidance per norm: a `guidance:` key on the norm, or packs/<pack>/guidance.yaml keyed by norm name."""
    out = {}
    for pkg in rs.chain:
        g = pkg.path / "guidance.yaml"
        if g.is_file():
            out.update({str(k): str(v) for k, v in (yaml.safe_load(g.read_text()) or {}).items()})
    for (kind, name), el in rs.elements.items():
        if kind == "norm" and el.data.get("guidance"):
            out[name] = str(el.data["guidance"]).strip()
    return out


def _predicate(rs, name: str) -> dict:
    return rs.get("predicate", name).data if rs.has("predicate", name) else {}


def link(repo: dict, at: str) -> str | None:
    # Dependency elements are located as "lockfile#L<n>" (the engine merges "path:line" neighbours).
    path, _, line = str(at).rpartition("#L" if "#L" in str(at) else ":")
    m = re.fullmatch(r"(\d+)(?:-(\d+))?", line)
    if not path or not m or not repo.get("commit"):
        return None
    return f"{repo['url']}/blob/{repo['commit']}/{path}#L{m[1]}" + (f"-L{m[2]}" if m[2] else "")


def _verdict(rows: list[dict]) -> str:
    if not rows:
        return "not_applicable"
    seen = {r["verdict"] for r in rows}
    return next((v for v in ("fail", "uncertain", "unknown", "pass") if v in seen), "not_applicable")


def _question_key(element: str, attr: str) -> str:
    return f"{element}::{attr}"


def _facts_of(ev, element_id: str) -> dict:
    e = next((x for x in ev.elements if x.id == element_id), None)
    if e is None:
        return {}
    return {k: [str(v) for v in f.values()] for k, f in e.facts.items()}


def _notes(ev, require) -> list[dict]:
    out = []
    for attr in dict.fromkeys(n["fact"].rpartition(".")[2] for n in walk(require or {}) if "fact" in n):
        f = ev.facts.get(attr)
        for o in (f.observations if f else []):
            if o.get("note") and not any(x["note"] == o["note"] for x in out):
                out.append({"note": str(o["note"])[:500], "source": o.get("source"), "value": o.get("value")})
    return out[:3]


def source_limits(docs: list[dict]) -> list[str]:
    """What each source did not read or could not settle, in words: a verdict resting on it is only as complete."""
    return [f"{s.get('id')}: {line}" for d in docs for s in d.get("sources", []) for line in _limits(s)]


def _limits(src: dict) -> list[str]:
    out = []
    if src.get("failed_batches"):
        out.append(f"{src['failed_batches']} of {src.get('batches')} reading calls failed: what those files hold was not "
                   "read, so requirements about it can show as not applicable")
    if src.get("files_not_sent"):
        out.append(f"{src['files_not_sent']} files were not read by the model: its budget ran out")
    if src.get("failed"):
        out.append(f"{len(src['failed'])} requirements stay open because their model call failed")
    if src.get("kind") == "model_assessment" and src.get("not_sent"):
        out.append(f"{len(src['not_sent'])} requirements were never sent to the model: the run's budget ran out")
    if (src.get("second_look") or {}).get("skipped"):
        out.append(f"{src['second_look']['skipped']} requirements the model left open got no second look: the run's budget ran out")
    if src.get("excluded_code"):
        ex = src["excluded_code"]
        names = ", ".join(f"{k}/ ({n})" for k, n in list(ex.items())[:5]) + (" …" if len(ex) > 5 else "")
        out.append(f"{sum(ex.values())} Python, Ruby or Elixir files were not analysed because their folders are named like "
                   f"build output, assets or translations: {names}. A requirement about code kept there can show as not "
                   "applicable; move the code or check those folders by hand")
    if src.get("requirement_chars"):
        out.append(f"each requirement was shown at most {src['requirement_chars']:,} characters, best matches first, "
                   "so that every requirement fits the run's budget")
    return out


def _asvs_id(norm: str) -> str | None:
    m = re.match(r"V?(\d+\.\d+\.\d+)", norm)
    return m.group(1) if m else None


def build(scan_data: dict, evaluation: dict, asvs_level: int = 2, answers: dict | None = None) -> dict:
    repo = scan_data["repo"]
    answers = answers or {}
    snips = scan_data.get("snippets", {})
    standards, questions = sections(evaluation, lambda a: {"at": a, "url": link(repo, a), "snippet": snips.get(a)},
                                    coverage=lambda sid, names: asvs_coverage(names, asvs_level) if sid == "asvs" else None)
    ev = evaluation["evidence"]
    for (target, attr), v in _answer_items(answers):
        q = questions.get(_question_key(target, attr))
        if q is not None:
            q["answer"] = v
    answered = [q for q in _answered_questions(answers, questions)]
    return {
        "repo": repo, "languages": scan_data.get("languages", {}),
        "notes": source_limits(scan_data["docs"]) + scan_data.get("notes", []),
        "seconds": scan_data.get("seconds"), "asvs_level": asvs_level,
        "sources": [{k: v for k, v in s.items() if k not in {"not_sent"}} for d in scan_data["docs"] for s in d.get("sources", [])],
        "standards": standards,
        "questions": sorted((q for q in questions.values() if q["answer"] is None), key=lambda q: (q["element"] != "_subject", q["attr"])),
        "answered": answered,
        "dependencies": dependencies(ev, repo, scan_data.get("advisories", {})),
        "conflicts": [c for c in conflicts(ev)][:200],
        "totals": dict(Counter(e["verdict"] for s in standards for e in s["entries"])),
    }


def sections(evaluation: dict, locate, coverage=lambda sid, names: None, by_type: bool = False) -> tuple[list[dict], dict]:
    """One section per standard, one entry per norm, and the questions that would settle open verdicts.

    `locate(at)` turns a locator into what the report shows for it (a link, a snippet, a sheet crop).
    With `by_type`, a question about an element attribute is asked once per element type ("every Door"),
    the way a building profile answers it, instead of once per element."""
    ev = evaluation["evidence"]
    standards, questions = [], {}
    for sid, res in evaluation["results"].items():
        rs, rows = res["rs"], res["rows"]
        guidance = _guidance(rs)
        norm_names = res["norms"] or [n for (k, n) in rs.elements if k == "norm"]
        by_norm: dict[str, list] = {}
        for r in rows:
            by_norm.setdefault(r["norm"], []).append(r)
        entries = []
        for name in norm_names:
            el = rs.get("norm", name).data
            nrows = by_norm.get(name, [])
            verdict = _verdict(nrows)
            cite = el.get("cite", {})
            interp = el.get("interpretation") or {}
            findings, passes = [], []
            for r in sorted(nrows, key=lambda r: (ORDER[r["verdict"]], str(r.get("at")))):
                if r["verdict"] == "pass" and r.get("type"):   # listed with what it was read from: the record of what was checked
                    passes.append({"element": r["element"], "type": r["type"], "at": [locate(a) for a in (r.get("at") or [])[:1]],
                                   "facts": _facts_of(ev, r["element"])})
                    continue
                ats = r.get("at") or []
                f = {"element": r["element"], "type": r.get("type"), "verdict": r["verdict"],
                     "at": [locate(a) for a in ats[:3]], "more_at": max(0, len(ats) - 3),
                     "facts": _facts_of(ev, r["element"]) if r.get("type") else {},
                     "seen_by": r.get("seen_by", []),
                     "deciding": r.get("deciding") or {}, "open": r.get("open") or [],
                     "open_labels": [_predicate(rs, o).get("label") or o for o in r.get("open") or []],
                     # a system-level verdict: the reasons the sources gave for the facts it reads (a model's judgement)
                     "notes": [] if r.get("type") else _notes(ev, el.get("require"))}
                findings.append(f)
                for fact in f["open"] + list(f["deciding"]):
                    root, _, attr = fact.rpartition(".") if "." in fact else ("system", "", fact)
                    subject_level = root == rs.subject or not r.get("type")
                    pred = _predicate(rs, fact if "." in fact else f"{rs.subject}.{fact}")
                    attr = (pred.get("vocab") or fact).split(".")[-1]
                    # A classification (given or judged) is answered once per type; a measurement is about one element.
                    typed = by_type and pred.get("kind") in ("given", "judged")
                    target = "_subject" if subject_level else (r["type"] if typed else r["element"])
                    key = _question_key(target, attr)
                    q = questions.setdefault(key, {
                        "key": key, "element": target, "attr": attr, "type": r.get("type") if not subject_level else None,
                        "scope": "subject" if subject_level else ("type" if typed else "element"), "elements": [],
                        "label": pred.get("label", attr), "value_type": pred.get("type", "bool"), "values": pred.get("values"),
                        "value_labels": pred.get("value_labels") or {},
                        "at": [a["at"] for a in f["at"]] if not subject_level else [],
                        "candidates": [d["value"] for d in f["deciding"].get(fact, [])] if fact in f["deciding"] else [],
                        "decides": [], "answer": None})
                    section = cite.get("section") or name
                    short = res.get("short") or STANDARD_SHORT.get(sid, sid)
                    tag = section if section.startswith(short) else f"{short} {section}"
                    if tag not in q["decides"]:
                        q["decides"].append(tag)
                    if not subject_level and r["element"] not in q["elements"]:
                        q["elements"].append(r["element"])
            counts = Counter(r["verdict"] for r in nrows)
            # what a reviewer's answer to a customer check rests on: cited text, or nothing found where it searched
            answered = [o for n in walk([el.get("require"), el.get("when_none")]) if "fact" in n
                        and n["fact"].rpartition(".")[2].startswith("req_")
                        for o in (ev.facts[n["fact"].rpartition(".")[2]].observations if n["fact"].rpartition(".")[2] in ev.facts else [])]
            rests_on = ("absence" if answered and all(o.get("basis") == "absence" for o in answered)
                        else "evidence" if answered else None)
            entries.append({
                "rests_on": rests_on,
                "na_reason": [{"note": str(o.get("note") or "")[:300], "source": o.get("source"),
                               "at": [locate(o["at"])] if o.get("at") else []} for o in answered][:3] if verdict == "not_applicable" else [],
                "norm": name, "title": el.get("title", name), "section": cite.get("section") or name, "url": cite.get("url"),
                "quote": (cite.get("quote") or el.get("quote") or "").strip() or None, "level": el.get("level"),
                "interpretation": (interp.get("note") or "").strip() if isinstance(interp, dict) else str(interp),
                "settled": interp.get("settled") if isinstance(interp, dict) else None,
                "defers_to": el.get("defers_to") or [], "guidance": guidance.get(name),
                "verdict": verdict, "counts": dict(counts), "checked": len(nrows), "findings": findings, "passes": passes,
                "for_type": next(iter((el.get("for") or {}).values()), None),
            })
        entries.sort(key=lambda e: (ORDER[e["verdict"]], e["section"]))
        meta = rs.top.meta
        lic = meta.get("licence") or {}
        not_formalized = [x for p in rs.chain for x in (p.meta.get("not_formalized") or [])]
        standards.append({"id": sid, "label": res["label"], "title": meta.get("title"), "pack": res["pack"],
                          "version": meta.get("version"), "text_policy": meta.get("text_policy", "public"),
                          "attribution": lic.get("attribution") or lic.get("notice"), "entries": entries,
                          "summary": dict(Counter(e["verdict"] for e in entries)), "not_formalized": not_formalized,
                          "coverage": coverage(sid, norm_names)})
    return standards, questions


STANDARD_SHORT = {"asvs": "ASVS", "nist": "NIST", "gdpr": "GDPR", "uk-gdpr": "UK GDPR", "appi": "APPI"}


def _answer_items(answers: dict):
    for k, v in (answers.get("subject") or {}).items():
        yield ("_subject", k), v
    for e, facts in (answers.get("elements") or {}).items():
        for k, v in facts.items():
            yield (e, k), v


VOCAB_LABELS = {(t, a): spec.get("label", a) for t, td in yaml.safe_load((ROOT / "vocab" / "code.yaml").read_text())["types"].items()
                for a, spec in (td.get("attrs") or {}).items()}


def _answered_questions(answers: dict, questions: dict) -> list[dict]:
    def label(e, a):
        type_ = "system" if e == "_subject" else e.split("@", 1)[0]
        return (questions.get(_question_key(e, a)) or {}).get("label") or VOCAB_LABELS.get((type_, a), a)
    return [{"element": e, "attr": a, "value": v, "label": label(e, a)} for (e, a), v in _answer_items(answers)]


def asvs_coverage(norm_names: list[str], level: int) -> dict:
    checked = {_asvs_id(n) for n in norm_names} - {None}
    chapters = []
    total = 0
    for cid, ch in ASVS_INVENTORY["chapters"].items():
        reqs = {r: lv for r, lv in ch["requirements"].items() if lv <= level}
        total += len(reqs)
        done = sorted((r for r in reqs if r in checked), key=lambda r: [int(x) for x in r.split(".")])
        chapters.append({"chapter": cid, "title": ch["title"], "requirements": len(reqs), "checked": done,
                         "manual": len(reqs) - len(done)})
    return {"level": level, "total": total, "checked": len(checked), "chapters": chapters,
            "source": ASVS_INVENTORY["source"]}


def dependencies(ev, repo: dict, advisories: dict) -> dict:
    deps = [e for e in ev.elements if e.type == "Dependency"]
    rows = []
    for e in deps:
        f = {k: (x.values()[0] if x.values() else None) for k, x in e.facts.items()}
        if not f.get("vulnerable"):
            continue
        ids = [i.strip() for i in str(f.get("advisories") or "").split(",") if i.strip()]
        advs, seen = [], set()
        for i in ids:  # a GHSA id and its CVE alias resolve to one OSV record: list it once
            d = advisories.get(i) or {}
            rid = d.get("id", i)
            if rid in seen:
                continue
            seen.add(rid)
            fixed = d.get("fixed")
            if isinstance(fixed, dict):  # {"npm/form-data": [versions]}: only this package's fixes
                fixed = fixed.get(f"{f.get('ecosystem')}/{f.get('name')}") or []
            advs.append({**d, "id": rid, "fixed": ", ".join(map(str, fixed[:4])) if isinstance(fixed, list) else fixed})
        rows.append({"name": f.get("name"), "version": f.get("version"), "ecosystem": f.get("ecosystem"),
                     "severity": f.get("max_severity"), "fix_available": f.get("fix_available"),
                     "at": [{"at": a, "url": link(repo, a)} for a in e.at[:1]], "advisories": advs})
    sev = {"critical": 0, "high": 1, "moderate": 2, "low": 3, "unknown": 4, "none": 5}
    rows.sort(key=lambda r: (sev.get(str(r["severity"]), 4), str(r["name"])))
    return {"total": len(deps), "vulnerable": len(rows), "by_severity": dict(Counter(str(r["severity"]) for r in rows)), "rows": rows}


# ---------------------------------------------------------------- Markdown

def markdown(rep: dict) -> str:
    r = rep["repo"]
    out = [f"# Compliance report: {r['owner']}/{r['name']}", "",
           f"Repository: {r['url']} at commit `{(r.get('commit') or '?')[:12]}`" + (f" (branch {r['branch']})" if r.get("branch") else ""),
           f"Languages: {', '.join(f'{k} ({v})' for k, v in rep['languages'].items()) or 'none recognised'}", ""]
    t = rep["totals"]
    out += ["## Summary", "", "| Standard | Fails | Uncertain | Needs input | Passes | Not applicable |", "|---|---|---|---|---|---|"]
    for s in rep["standards"]:
        c = s["summary"]
        out.append(f"| {s['label']} | {c.get('fail', 0)} | {c.get('uncertain', 0)} | {c.get('unknown', 0)} | {c.get('pass', 0)} | {c.get('not_applicable', 0)} |")
    out.append("")
    out.append(f"{t.get('fail', 0)} requirements fail, {t.get('uncertain', 0) + t.get('unknown', 0)} cannot be decided from the code alone, "
               f"and {t.get('pass', 0)} pass. Verdicts are produced by rule packs from facts extracted from the code; each finding cites the code it rests on.")
    if rep["notes"]:
        out += ["", "**Limits of this scan:**", ""] + [f"- {n}" for n in rep["notes"]]
    for s in rep["standards"]:
        out += ["", f"## {s['label']}", ""]
        if s.get("attribution"):
            out += [f"_{s['attribution'].strip()}_", ""]
        for e in s["entries"]:
            if e["verdict"] == "not_applicable":
                continue
            lvl = f" (L{e['level']})" if e.get("level") else ""
            tag = " (nothing found in the code searched)" if e.get("rests_on") == "absence" and e["verdict"] == "fail" else ""
            out += [f"### {VERDICT_LABEL[e['verdict']]}{tag}: {e['section']}{lvl} {e['title']}", ""]
            if e.get("url"):
                out.append(f"Source: {e['url']}")
            if e.get("quote"):
                out += ["", "> " + " ".join(e["quote"].split())]
            out.append("")
            for f in e["findings"][:25]:
                where = ", ".join(f"[{a['at']}]({a['url']})" if a.get("url") else a["at"] for a in f["at"]) or "the application as a whole"
                facts = "; ".join(f"{k}={'/'.join(v)}" for k, v in f["facts"].items()) if f["facts"] else ""
                line = f"- **{VERDICT_LABEL[f['verdict']]}** {TYPE_LABEL.get(f['type'] or '', f['type'] or 'system')} at {where}"
                if facts:
                    line += f" ({facts})"
                if f["deciding"]:
                    line += ". Sources disagree on " + ", ".join(
                        f"{k}: " + " vs ".join(f"{d['value']} ({', '.join(d['sources'][:2])})" for d in vs) for k, vs in f["deciding"].items())
                if f["open"]:
                    line += ". Open: " + ", ".join(f["open"])
                out.append(line)
            if len(e["findings"]) > 25:
                out.append(f"- … and {len(e['findings']) - 25} more")
            if e["verdict"] == "pass":
                out.append(f"Checked {e['checked']} {'place' if e['checked'] == 1 else 'places'}; all pass.")
            if e.get("interpretation"):
                out += ["", f"How it is checked: {' '.join(e['interpretation'].split())}"]
            if e.get("guidance") and e["verdict"] != "pass":
                out += ["", f"What to do: {e['guidance']}"]
            out.append("")
        na = [e for e in s["entries"] if e["verdict"] == "not_applicable"]
        for e in (e for e in na if e.get("na_reason")):
            w = e["na_reason"][0]
            out.append(f"- Judged not to apply: {e['section']} {e['title'].rstrip('.')}. {w['note']} ({w['source']}"
                       + (", nothing found in the code searched" if e.get("rests_on") == "absence" else "")
                       + "".join(f"; {a['at']}" for a in w["at"]) + ")")
        plain = [e for e in na if not e.get("na_reason")]
        if plain:
            out += ["", "Not applicable (nothing in the code is subject to them): " + ", ".join(e["section"] for e in plain), ""]
        if s.get("coverage"):
            c = s["coverage"]
            out += [f"Coverage: {c['checked']} of the {c['total']} ASVS 5.0 requirements at level {c['level']} are checked automatically; "
                    f"the rest need manual review.", ""]
        if s.get("not_formalized"):
            out += ["Not checked by this pack:", ""] + [f"- {x}" for x in s["not_formalized"]] + [""]
    d = rep["dependencies"]
    if d["total"]:
        out += ["## Vulnerable dependencies", "", f"{d['vulnerable']} of {d['total']} locked packages have published advisories.", ""]
        for row in d["rows"][:100]:
            advs = ", ".join(a["id"] for a in row["advisories"])
            fixed = "fix available" if row.get("fix_available") else "no fixed release"
            out.append(f"- {row['name']} {row['version']} ({row['ecosystem']}): {row['severity']}, {fixed}. {advs}")
    if rep["questions"]:
        out += ["", "## Questions that would settle open verdicts", ""]
        for q in rep["questions"]:
            where = f" ({', '.join(q['at'])})" if q["at"] else ""
            out.append(f"- {q['label']}{where}: decides {', '.join(q['decides'])}")
    out += ["", "## How this report was made", ""]
    for s in rep["sources"]:
        bits = [f"{k}: {v}" for k, v in s.items() if k in {"adapter", "adapter_version", "model", "files_analysed", "files_sent", "lockfiles"} and v]
        out.append(f"- {s.get('id')}: " + "; ".join(map(str, bits)))
    out += ["", "Facts come from deterministic static analysis and, where configured, a language model reading the code. "
            "Where they disagree, static analysis decides measured facts unless it only found nothing, the model decides "
            "judged ones, and the disagreement is listed. Rule packs are drafts "
            "written from the published texts; their interpretations are stated with each requirement. This is an "
            "automated assessment, not legal advice or a certification."]
    return "\n".join(out) + "\n"
