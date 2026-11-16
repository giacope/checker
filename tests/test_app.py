"""The web app end to end with the clone replaced by a local synthetic repository (no network)."""

import importlib
import json
import shutil
import sys
import time
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import adapters.research  # noqa: F401 - loaded before the compiler fixture stands in for adapters.regulation
from adapters.code_static import analyse

REPO = {
    "server/routes.js": """\
const express = require("express");
const crypto = require("crypto");
const app = express();
app.post("/login", (req, res) => {
  db.query("SELECT * FROM users WHERE email = '" + req.body.email + "'");
  const h = crypto.createHash("md5").update(req.body.password).digest("hex");
});
const SESSION_SECRET = "s3cr3t-signing-key-value";
""",
}


@pytest.fixture
def client(tmp_path, monkeypatch):
    src = tmp_path / "src"
    for rel, text in REPO.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(text)
    monkeypatch.setenv("NORMIR_DATA", str(tmp_path / "data"))
    import app.main as main
    import app.regulations as regs
    import app.scan as scan_mod
    importlib.reload(regs)
    main = importlib.reload(main)
    calls = []

    def fake_scan(url, work, branch=None, progress=lambda m: None, **kw):
        calls.append(kw)
        if kw.get("keep"):
            scan_mod.keep_source(src, kw["keep"])
        progress("Static analysis")
        docs = [analyse(src, "acme/shop")]
        return {"repo": {"url": "https://github.com/acme/shop", "owner": "acme", "name": "shop", "branch": None, "commit": "a" * 40},
                "languages": {"JavaScript": 1}, "docs": docs, "snippets": scan_mod.snippets(src, docs), "advisories": {},
                "notes": [], "seconds": 0.1}
    monkeypatch.setattr(main, "scan", fake_scan)
    c = TestClient(main.app)
    c.scan_calls = calls
    return c


def wait(client, sid):
    for _ in range(100):
        st = client.get(f"/scans/{sid}/status").json()
        if st.get("state") in ("done", "error"):
            return st
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def test_scan_report_answers_and_exports(client):
    r = client.post("/scans", data={"url": "https://github.com/acme/shop", "standards": ["asvs", "nist"], "asvs_level": "2"},
                    follow_redirects=False)
    assert r.status_code == 303
    sid = r.headers["location"].rsplit("/", 1)[1]
    assert wait(client, sid)["state"] == "done"
    rep = client.get(f"/scans/{sid}/report.json").json()
    entries = {e["norm"]: e for s in rep["standards"] for e in s["entries"]}
    # injection: fails, cites the requirement and the line, with a link pinned to the commit and the code around it
    inj = entries["V1.2.4"]
    assert inj["verdict"] == "fail" and inj["url"].startswith("https://github.com/OWASP/ASVS/blob/v5.0.0_release/")
    at = inj["findings"][0]["at"][0]
    assert at["at"] == "server/routes.js:5"
    assert at["url"] == "https://github.com/acme/shop/blob/" + "a" * 40 + "/server/routes.js#L5"
    assert [5, '  db.query("SELECT * FROM users WHERE email = \'" + req.body.email + "\'");'] in at["snippet"]["lines"]
    assert entries["V11.4.2"]["verdict"] == "fail"
    # the literal secret's value is never shown
    secret = entries["V13.3.1"]
    assert secret["verdict"] == "unknown"
    shown = json.dumps(secret["findings"], ensure_ascii=False)
    assert "s3cr3t-signing-key-value" not in shown and "•••" in shown
    # the open fact is asked, and answering it decides the requirement
    q = next(q for q in rep["questions"] if q["attr"] == "test_or_example")
    assert "V13.3.1" in " ".join(q["decides"])
    client.post(f"/scans/{sid}/answers", data={q["key"]: "false"})
    rep2 = client.get(f"/scans/{sid}/report.json").json()
    assert next(e for s in rep2["standards"] for e in s["entries"] if e["norm"] == "V13.3.1")["verdict"] == "fail"
    assert [a["value"] for a in rep2["answered"]] == [False]
    # an L2-only scan includes L2 norms; coverage counts the inventory
    assert rep["standards"][0]["coverage"]["total"] > 200
    md = client.get(f"/scans/{sid}/report.md").text
    assert "### Fails: ASVS 5.0 V1.2.4" in md and "server/routes.js#L5" in md
    assert "s3cr3t-signing-key-value" not in client.get(f"/scans/{sid}").text


def test_level_1_drops_level_2_norms(client):
    r = client.post("/scans", data={"url": "https://github.com/acme/shop", "standards": ["asvs"], "asvs_level": "1"}, follow_redirects=False)
    sid = r.headers["location"].rsplit("/", 1)[1]
    wait(client, sid)
    norms = {e["norm"] for s in client.get(f"/scans/{sid}/report.json").json()["standards"] for e in s["entries"]}
    assert "V1.2.4" in norms and "V11.4.2" not in norms  # 11.4.2 is L2


@pytest.mark.parametrize("url", ["https://gitlab.com/a/b", "file:///etc", "https://github.com/a", "https://github.com/a/b/../c"])
def test_only_github_repository_urls(client, url):
    assert client.post("/scans", data={"url": url}, follow_redirects=False).status_code == 400


def test_unknown_or_malformed_scan_ids(client):
    assert client.get("/scans/../../etc").status_code == 404
    assert client.get("/scans/aaaaaaaaaaaa").status_code == 404


class RegulationError(Exception):
    pass


@pytest.fixture
def compiler(monkeypatch):
    """A stand-in for adapters.regulation: two requirements, one compiled to an assessed check and one attested,
    and a pack built by copying the GDPR pack so the scan has real rules to run under the regulation's name."""
    m = types.ModuleType("adapters.regulation")
    m.RegulationError = RegulationError
    m.read = lambda path, rel: types.SimpleNamespace(file=rel, sha256="0" * 64, kind="md", pages=1,
                                                     lines=Path(path).read_text().splitlines())
    m.clauses = lambda docs, progress=None, **kw: [
        {"id": "c1", "ref": "1", "title": "Purpose", "text": "This standard applies to all services.", "requirement": False},
        {"id": "c2", "ref": "2.1", "text": "Passwords must be hashed with a slow, salted hash.", "requirement": True},
        {"id": "c3", "ref": "2.2", "text": "Each service must have a named security owner.", "requirement": True}]
    m.uncovered = lambda docs, cl: [{"file": "acme.md", "lines": [7, 8], "at": "acme.md#L7-L8",
                                     "text": "Annex B\nKeys are rotated every 90 days."}]
    m.compile_checks = lambda cl, vocab, progress=None, **kw: ([
        {"id": "2.1", "clause": "c2", "kind": "assessed", "enabled": True, "summary": "Passwords are stored with a slow salted hash.",
         "search": ["password", "hash"]},
        {"id": "2.2", "clause": "c3", "kind": "attested", "enabled": True, "summary": "A security owner is named.",
         "question": "Does the service have a named security owner?"}], {"clauses": 3})
    m.build_pack = lambda reg, vocab, out: shutil.copytree(Path(__file__).parents[1] / "packs" / "gdpr", out, dirs_exist_ok=True)
    m.fact_attr = lambda rid, cid: f"req_{rid}_{cid.replace('.', '_')}"
    m.PACK_FORMAT = 2  # the copied pack declares none, so app.regulations rebuilds it before each use
    m.requirements = lambda reg: [{"attr": m.fact_attr(reg["id"], k["id"]), "summary": k["summary"], "search": k.get("search"),
                                   "clause": next(c["text"] for c in reg["clauses"] if c["id"] == k["clause"])}
                                  for k in reg["checks"] if k.get("enabled") and k["kind"] == "assessed"]
    import adapters
    monkeypatch.setitem(sys.modules, "adapters.regulation", m)
    monkeypatch.setattr(adapters, "regulation", m, raising=False)
    return m


def wait_reg(client, rid):
    for _ in range(100):
        st = client.get(f"/regulations/{rid}/status").json()
        if st.get("state") in ("done", "error"):
            return st
        time.sleep(0.05)
    raise AssertionError("compiling did not finish")


def test_customer_regulation_upload_review_and_scan(client, compiler):
    r = client.post("/regulations", data={"name": "Acme standard", "domain": "code"},
                    files=[("files", ("acme.md", b"# Acme\n2.1 Passwords must be hashed.\n", "text/markdown"))], follow_redirects=False)
    assert r.status_code == 303
    rid = r.headers["location"].rsplit("/", 1)[1]
    assert wait_reg(client, rid)["state"] == "done"
    page = client.get(f"/regulations/{rid}").text
    assert 'id="c2"' in page and "Passwords must be hashed with a slow, salted hash." in page
    assert 'name="kind::2.1"' in page and "Does the service have a named security owner?" in page
    assert "2 lines are in no clause." in page and "acme.md lines 7–8" in page and "Keys are rotated every 90 days." in page
    # a regulation that is not ready is refused, not swapped for the default standards
    r = client.post("/scans", data={"url": "https://github.com/acme/shop", "standards": ["reg:r000000nope"]}, follow_redirects=False)
    assert r.status_code == 400 and "reg:r000000nope" in r.text
    # the index offers it for scans; scanning with it hands the assessed check to the model assessor
    assert f'value="reg:{rid}"' in client.get("/").text
    r = client.post("/scans", data={"url": "https://github.com/acme/shop", "standards": [f"reg:{rid}"]}, follow_redirects=False)
    sid = r.headers["location"].rsplit("/", 1)[1]
    assert wait(client, sid)["state"] == "done"
    assert [q["attr"] for q in client.scan_calls[-1]["requirements"]] == [f"req_{rid}_2_1"]
    assert "Passwords must be hashed" in client.scan_calls[-1]["requirements"][0]["clause"]
    rep = client.get(f"/scans/{sid}/report.json").json()
    assert [(s["id"], s["label"], s["pack"]) for s in rep["standards"]] == [(f"reg:{rid}", "Acme standard", f"regulations/{rid}")]
    # switching the assessed check off (its checkbox absent) and making the other one assessed changes what is assessed
    client.post(f"/regulations/{rid}/checks", data={"seen::2.1": "1", "kind::2.1": "assessed", "seen::2.2": "1",
                                                     "enabled::2.2": "on", "kind::2.2": "assessed"})
    import app.regulations as regs
    reg = regs.load_reg(rid)
    k = {c["id"]: c for c in reg["checks"]}
    assert k["2.1"]["enabled"] is False and k["2.2"]["kind"] == "assessed" and k["2.2"]["search"]
    assert [q["attr"] for q in regs.assessed([rid])] == [f"req_{rid}_2_2"]


def test_regulation_upload_rejects_unreadable_files(client, compiler):
    r = client.post("/regulations", data={"domain": "code"}, files=[("files", ("a.exe", b"MZ", "application/octet-stream"))])
    assert r.status_code == 400
    assert client.get("/regulations/rzzzzzzzzzz").status_code == 404
    assert client.get("/regulations/../../etc").status_code == 404


def test_regulation_compile_error_is_shown(client, compiler, monkeypatch):
    def fail(*a, **kw):
        raise RegulationError("No requirements were found in the documents.")
    monkeypatch.setattr(compiler, "clauses", fail)
    r = client.post("/regulations", data={"domain": "code"}, files=[("files", ("a.txt", b"hello", "text/plain"))], follow_redirects=False)
    rid = r.headers["location"].rsplit("/", 1)[1]
    st = wait_reg(client, rid)
    assert st == {**st, "state": "error", "error": "No requirements were found in the documents."}
    assert "No requirements were found" in client.get(f"/regulations/{rid}").text


def test_model_citations_with_line_ranges_get_code_and_links(tmp_path):
    from app.report import link
    from app.scan import snippets
    (tmp_path / "a.rb").write_text("\n".join(f"line {i}" for i in range(1, 21)))
    docs = [{"facts": {"req_x": [{"value": False, "at": "a.rb:5-7"}]}, "elements": []}]
    s = snippets(tmp_path, docs)["a.rb:5-7"]
    assert (s["line"], s["end"]) == (5, 7) and [n for n, _ in s["lines"]] == list(range(3, 10))
    repo = {"url": "https://github.com/a/b", "commit": "c" * 40}
    assert link(repo, "a.rb:5-7") == "https://github.com/a/b/blob/" + "c" * 40 + "/a.rb#L5-L7"
    assert link(repo, "a.rb:5").endswith("/a.rb#L5")


def test_report_separates_doesnt_apply_and_nothing_found(tmp_path, monkeypatch):
    """A compiled regulation through the app's own evaluate and report: an answer that the check doesn't apply is its
    own verdict with its reason, and a failure resting on nothing found is labelled as such."""
    import app.regulations as regs
    from adapters.regulation import build_pack, fact_attr
    from app import report
    from app.scan import evaluate
    rid = "rtestna0001"
    clauses = [{"id": f"c{i}", "ref": f"{i}.1", "file": "std.md", "at": f"std.md#L{i}-L{i}", "text": t}
               for i, t in enumerate(["Uploads are scanned for malware.", "Logins are rate limited.", "Errors hide traces."], 1)]
    checks = [{"id": f"k{i}-1", "clause": f"c{i}", "kind": "assessed", "enabled": True, "summary": c["text"], "why": "", "search": ["x"]}
              for i, c in enumerate(clauses, 1)]
    reg = {"id": rid, "name": "Acme", "domain": "code", "clauses": clauses, "checks": checks}
    monkeypatch.setattr(regs, "ready", lambda r, domain: {"name": "Acme"})
    monkeypatch.setattr(regs, "pack_dir", lambda r: build_pack(reg, regs.vocab("code"), tmp_path / "pack"))
    src = {"id": "llm:m", "kind": "model_assessment", "not_sent": ["req_a", "req_b"], "failed": ["req_c"], "requirement_chars": 9000,
           "second_look": {"asked": 4, "answered": 1, "skipped": 3}}
    doc = {"subject": {"kind": "system", "id": "shop"}, "sources": [src], "facts": {
        fact_attr(rid, "k1-1"): [{"value": "not_applicable", "basis": "absence", "note": "nothing is uploaded", "source": "llm:m"}],
        fact_attr(rid, "k2-1"): [{"value": "not_met", "basis": "absence", "note": "searched 4 excerpts: no throttle", "source": "llm:m"}],
        fact_attr(rid, "k3-1"): [{"value": "met", "basis": "evidence", "at": "app/errors.rb:3", "note": "generic page", "source": "llm:m"}]}}
    scan_data = {"repo": {"url": "https://github.com/a/shop", "owner": "a", "name": "shop", "commit": "c" * 40}, "docs": [doc]}
    rep = report.build(scan_data, evaluate([doc], [f"reg:{rid}"]))
    e = {x["norm"]: x for x in rep["standards"][0]["entries"]}
    assert (e["k1-1"]["verdict"], e["k2-1"]["verdict"], e["k3-1"]["verdict"]) == ("not_applicable", "fail", "pass")
    assert e["k1-1"]["na_reason"][0]["note"] == "nothing is uploaded" and e["k2-1"]["rests_on"] == "absence"
    assert e["k3-1"]["rests_on"] == "evidence" and rep["totals"] == {"not_applicable": 1, "fail": 1, "pass": 1}
    md = report.markdown(rep)
    assert "### Fails (nothing found in the code searched): 2.1" in md
    # what the model was never shown or could not answer is a stated limit, not a silent gap
    assert rep["notes"] == ["llm:m: 1 requirements stay open because their model call failed",
                            "llm:m: 2 requirements were never sent to the model: the run's budget ran out",
                            "llm:m: 3 requirements the model left open got no second look: the run's budget ran out",
                            "llm:m: each requirement was shown at most 9,000 characters, best matches first, so that every "
                            "requirement fits the run's budget"]
    assert "- llm:m: 2 requirements were never sent to the model" in md
    assert "Judged not to apply: 1.1 Uploads are scanned for malware. nothing is uploaded (llm:m, nothing found in the code searched)" in md


def test_questions_about_a_scan_with_its_regulation(client, compiler, monkeypatch):
    """Ask from the scan page: the code kept from the scan and the regulation are read together, the page shows
    the answer with each citation's own text, and the form rejects what it cannot answer."""
    research = adapters.research
    r = client.post("/regulations", data={"name": "Acme standard", "domain": "code"},
                    files=[("files", ("acme.md", b"2.1 Passwords must be hashed.\n", "text/markdown"))], follow_redirects=False)
    rid = r.headers["location"].rsplit("/", 1)[1]
    assert wait_reg(client, rid)["state"] == "done"
    sid = client.post("/scans", data={"url": "https://github.com/acme/shop", "standards": [f"reg:{rid}"]},
                      follow_redirects=False).headers["location"].rsplit("/", 1)[1]
    assert wait(client, sid)["state"] == "done"
    page = client.get(f"/scans/{sid}").text
    assert 'action="/ask"' in page and f'name="regulations" value="{rid}" checked' in page

    seen = []

    def complete(pname, model, key, system, user, client_):
        seen.append(user)
        return json.dumps({"status": "answered", "answer": "No: MD5, against 2.1.", "claims": [
            {"text": "Passwords are hashed with MD5.", "at": ["A|server/routes.js:6"]},
            {"text": "2.1 requires a slow salted hash.", "at": ["R1|c2"]},
            {"text": "An invented line.", "at": ["A|server/routes.js:60"]}]})
    monkeypatch.setattr(research, "complete", complete)
    monkeypatch.setattr(research, "provider_from_env", lambda: ("anthropic", "test-model", "k"))
    r = client.post("/ask", data={"question": "Does password hashing meet the standard?", "mode": "quick", "artifact_kind": "scan",
                                  "artifact_id": sid, "regulations": [rid]}, follow_redirects=False)
    assert r.status_code == 303
    qid = r.headers["location"].rsplit("/", 1)[1]
    for _ in range(100):
        got = client.get(f"/questions/{qid}/answer.json").json()
        if got["status"].get("state") in ("done", "error"):
            break
        time.sleep(0.05)
    assert got["status"]["state"] == "done", got["status"]
    assert "[A] server/routes.js" in seen[0] and "[R1] clause c2" in seen[0]
    a = got["answer"]
    assert [c["at"] for c in a["sections"][0]["claims"]] == [["A|server/routes.js:6"], ["R1|c2"]]
    html = client.get(f"/questions/{qid}").text
    assert "No: MD5, against 2.1." in html and "An invented line." not in html
    assert 'href="https://github.com/acme/shop/blob/' + "a" * 40 + '/server/routes.js#L6"' in html
    assert 'createHash(&#34;md5&#34;)' in html                       # the cited line itself, from the kept source
    assert f'href="/regulations/{rid}#c2"' in html and "Passwords must be hashed with a slow, salted hash." in html
    assert f'/questions/{qid}' in client.get(f"/scans/{sid}").text  # listed under "asked before"
    # what it cannot answer
    assert client.post("/ask", data={"question": "hi there", "artifact_kind": "scan", "artifact_id": "zzzzzzzzzzzz"}).status_code == 400
    assert client.post("/ask", data={"question": "hi there", "regulations": ["rzzzzzzzzzz"]}).status_code == 400
    assert client.post("/ask", data={"question": "hi there", "mode": "forever", "regulations": [rid]}).status_code == 400
    assert client.post("/ask", data={"question": "hi there"}).status_code == 400
    assert client.get("/questions/../../etc").status_code == 404
