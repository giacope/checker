"""The documents side of the web app: a regulation compiled for documents, a document set read by the real reader,
and a model (mocked) whose answers must cite lines it was shown to count."""

import importlib
import json
import re
import time
import types

import pytest
from fastapi.testclient import TestClient

PLAN = ("# Harbour Café food safety plan\n\nOwner: J. Doe\n\n## Hazards\n\nRaw chicken is a biological hazard.\n\n"
        "## Critical limits\n\nChicken is cooked to a core temperature of 75 °C, checked with a probe thermometer.\n\n"
        "## Records\n\nCooking temperatures are written in the kitchen log each service.\n")
CORE = "Chicken is cooked to a core temperature of 75 °C, checked with a probe thermometer."


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("NORMIR_DATA", str(tmp_path / "data"))
    import app.main as main
    import app.questions as qs
    import app.regulations as regs
    importlib.reload(regs)
    importlib.reload(qs)
    main = importlib.reload(main)
    monkeypatch.setattr(main, "ISOLATE", False)   # the fakes below live in this process
    return TestClient(main.app)


def compile_hygiene(client, monkeypatch) -> str:
    """A documents regulation with the compiling model replaced: an assessed and an attested check."""
    import adapters.regulation as R
    monkeypatch.setattr(R, "read", lambda path, rel: types.SimpleNamespace(file=rel, sha256="0" * 64, kind="md", pages=1,
                                                                            lines=path.read_text().splitlines()))
    monkeypatch.setattr(R, "clauses", lambda docs, progress=None, **kw: [
        {"id": "c1", "file": "reg.md", "ref": "5(2)(c)", "title": "Critical limits",
         "text": "Establish critical limits at critical control points.", "requirement": True, "at": "reg.md#L1-L1"},
        {"id": "c2", "file": "reg.md", "ref": "5(4)", "title": "Review", "text": "Review the procedures when anything changes.",
         "requirement": True, "at": "reg.md#L2-L2"}])
    monkeypatch.setattr(R, "uncovered", lambda docs, cl: [])
    monkeypatch.setattr(R, "compile_checks", lambda cl, vocab, progress=None, **kw: ([
        {"id": "k1-1", "clause": "c1", "kind": "assessed", "enabled": True, "summary": "Critical limits are set for each hazard.",
         "search": ["critical limit", "temperature"]},
        {"id": "k2-1", "clause": "c2", "kind": "attested", "enabled": True, "summary": "Procedures are reviewed after changes.",
         "question": "Are the procedures reviewed whenever the business changes?"}], {"checks": 2}))
    r = client.post("/regulations", data={"name": "Hygiene Art 5", "domain": "documents"},
                    files=[("files", ("reg.md", b"5(2)(c)\n5(4)\n", "text/markdown"))], follow_redirects=False)
    rid = r.headers["location"].rsplit("/", 1)[1]
    for _ in range(100):
        if client.get(f"/regulations/{rid}/status").json().get("state") in ("done", "error"):
            break
        time.sleep(0.05)
    assert client.get(f"/regulations/{rid}/status").json()["state"] == "done"
    return rid


def model(monkeypatch, at):
    """A model that answers every requirement met, citing `at`; returns the prompts it was sent."""
    import adapters.assess as assess_mod
    import adapters.code_llm as llm
    calls = []

    def complete(pname, name, key, system, user, client):
        calls.append(user)
        asked = re.search(r"Answer these requirements: (.*)$", user).group(1).split(", ")
        return json.dumps({"answers": [{"attr": a, "value": "met", "basis": "evidence", "note": "75 °C core limit.", "at": at}
                                       for a in asked]})
    monkeypatch.setattr(assess_mod, "complete", complete)
    provider = ("anthropic", "test-model", "k")
    monkeypatch.setattr(llm, "provider_from_env", lambda: provider)
    monkeypatch.setattr(assess_mod, "provider_from_env", lambda: provider)
    return calls


def upload(client, rid, files):
    r = client.post("/documents", data={"name": "Harbour Café", "codes": [f"reg:{rid}"]},
                    files=[("files", f) for f in files], follow_redirects=False)
    assert r.status_code == 303, r.text
    did = r.headers["location"].rsplit("/", 1)[1]
    for _ in range(100):
        st = client.get(f"/documents/{did}/status").json()
        if st.get("state") in ("done", "error"):
            return did, st
        time.sleep(0.05)
    raise AssertionError("the documents did not finish")


def test_documents_are_assessed_with_cited_lines_and_attested_checks_are_asked(client, monkeypatch):
    rid = compile_hygiene(client, monkeypatch)
    assert f'value="reg:{rid}"' in client.get("/documents").text
    assert f'value="reg:{rid}"' not in client.get("/buildings").text and f'value="reg:{rid}"' not in client.get("/code").text
    # line 6 of the plan is the core temperature; L99 does not exist and other.md is not a file of the set
    calls = model(monkeypatch, ["plan.md#L6", "plan.md#L99", "other.md#L1"])
    did, st = upload(client, rid, [("plan.md", PLAN.encode(), "text/markdown"), ("empty.txt", b"\n", "text/plain")])
    assert st["state"] == "done"
    assert len(calls) == 1 and "Establish critical limits at critical control points." in calls[0] and CORE in calls[0]
    rep = client.get(f"/documents/{did}/report.json").json()
    assert [f["file"] for f in rep["files"]] == ["plan.md"]
    assert any("empty.txt" in n and "skipped" in n for n in rep["notes"])
    entries = {e["norm"]: e for e in rep["standards"][0]["entries"]}
    lim = entries["k1-1"]
    assert lim["verdict"] == "pass" and lim["section"] == "5(2)(c)" and lim["url"] == f"/regulations/{rid}#c1"
    m = lim["assessment"]
    assert m["value"] == "met" and m["source"] == "llm:test-model" and [a["at"] for a in m["at"]] == ["plan.md#L6"]
    snip = m["at"][0]["snippet"]
    assert m["at"][0]["label"] == "plan.md L6" and (snip["line"], snip["end"]) == (6, 6) and [6, CORE] in snip["lines"]
    src = next(s for s in rep["sources"] if s["id"] == "llm:test-model")
    assert src["rejected_locators"] == {"locator does not exist": 2}
    # the attested check is a question; answering it decides the requirement
    assert entries["k2-1"]["verdict"] == "unknown"
    q = next(q for q in rep["questions"] if q["attr"] == f"req_{rid}_k2_1")
    assert q["label"] == "Are the procedures reviewed whenever the business changes?"
    html = client.get(f"/documents/{did}").text
    assert "<b>Model assessment:</b> Yes, met" in html and CORE in html and q["key"] in html
    v = next(x for x in (q["values"] or [True]) if x in ("met", True))
    client.post(f"/documents/{did}/answers", data={q["key"]: "true" if v is True else v})
    rep = client.get(f"/documents/{did}/report.json").json()
    assert {e["norm"]: e["verdict"] for e in rep["standards"][0]["entries"]}["k2-1"] == "pass"
    assert [a["attr"] for a in rep["answered"]] == [f"req_{rid}_k2_1"] and not rep["questions"]
    # questions read the same documents
    from app import questions as qs
    c = qs.corpus_of({"artifact": {"kind": "documents", "id": did}})
    assert [h for h, _ in c.search(["probe thermometer"], 10_000)] == ["plan.md#L1-L8"]
    r = client.post("/ask", data={"question": "What is the core temperature?", "artifact_kind": "documents", "artifact_id": did},
                    follow_redirects=False)
    assert r.status_code == 303


def test_without_a_model_the_assessed_checks_stay_open(client, monkeypatch):
    import adapters.code_llm as llm
    rid = compile_hygiene(client, monkeypatch)
    monkeypatch.setattr(llm, "provider_from_env", lambda: None)
    did, st = upload(client, rid, [("plan.md", PLAN.encode(), "text/markdown")])
    assert st["state"] == "done"
    rep = client.get(f"/documents/{did}/report.json").json()
    assert any("judged by a model, and none is configured" in n for n in rep["notes"])
    lim = next(e for e in rep["standards"][0]["entries"] if e["norm"] == "k1-1")
    assert lim["verdict"] == "unknown" and lim["assessment"] is None
    assert {q["attr"] for q in rep["questions"]} == {f"req_{rid}_k1_1", f"req_{rid}_k2_1"}


def test_an_upload_needs_a_documents_regulation_and_readable_files(client, monkeypatch):
    r = client.post("/documents", data={"name": "x", "codes": []}, files=[("files", ("a.md", b"text", "text/markdown"))])
    assert r.status_code == 400
    rid = compile_hygiene(client, monkeypatch)
    r = client.post("/documents", data={"codes": [f"reg:{rid}"]}, files=[("files", ("a.exe", b"MZ", "application/octet-stream"))])
    assert r.status_code == 400 and "a.exe" in r.text
    _, st = upload(client, rid, [("empty.txt", b" \n", "text/plain")])
    assert st["state"] == "error" and "None of the uploaded files could be read" in st["error"]


def test_uploaded_folders_are_kept_so_files_of_one_name_stay_apart(client, monkeypatch):
    import adapters.code_llm as llm
    rid = compile_hygiene(client, monkeypatch)
    monkeypatch.setattr(llm, "provider_from_env", lambda: None)
    did, st = upload(client, rid, [("site-a/plan.md", b"Cook to 75 \xc2\xb0C.\n", "text/markdown"),
                                   ("site-b/plan.md", b"Chill below 5 \xc2\xb0C.\n", "text/markdown"),
                                   ("site-b/plan.md", b"Second copy.\n", "text/markdown"),
                                   ("../../etc/plan.md", b"Outside.\n", "text/markdown")])
    assert st["state"] == "done", st
    rep = client.get(f"/documents/{did}/report.json").json()
    assert sorted(f["file"] for f in rep["files"]) == [
        "etc/plan.md", "site-a/plan.md", "site-b/plan-1.md", "site-b/plan.md"]
