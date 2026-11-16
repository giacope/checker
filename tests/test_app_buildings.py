"""The building-drawings side of the web app, with the adapters replaced by a fixed evidence document.

The adapters have their own tests; these check what the app adds: uploads and zips, the report's sheet
citations, questions asked once per element type, answers re-evaluating the codes, and the exports."""

import importlib
import io
import json
import re
import time
import types
import zipfile

import pytest
from fastapi.testclient import TestClient

from app import buildings

SHEET = "plans/A11-1.pdf#page=1&bbox=100,200,180,214"
PROCESS = buildings.process   # the real one, before the client fixture replaces it


def evidence(files_dir, name, progress=lambda m: None):
    progress("Reading")
    doc = {
        "subject": {"kind": "building", "id": name},
        "sources": [{"id": "drawings", "kind": "drawings", "adapter": "test"}],
        "facts": {"stated_occupancy_classification": [{"value": "BUSINESS", "at": "plans/A11-1.pdf#page=1&bbox=10,10,90,20"}],
                  "sprinkler_system": [{"value": "nfpa13", "at": "plans/A11-1.pdf#page=1&bbox=10,30,90,40"}]},
        "elements": [
            {"type": "Stair", "id": "stair:1", "at": [SHEET],
             "facts": {"riser_height": [{"value": "190 mm", "at": SHEET}], "tread_depth": [{"value": "279 mm", "at": SHEET}],
                       "width": [{"value": "1210 mm", "at": SHEET}]}},
            {"type": "Stair", "id": "stair:2", "at": ["ifc:2abc"],
             "facts": {"riser_height": [{"value": "176 mm", "at": "ifc:2abc"}], "tread_depth": [{"value": "280 mm", "at": "ifc:2abc"}],
                       "width": [{"value": "1210 mm", "at": "ifc:2abc"}]}},
        ],
    }
    return {"docs": [doc], "sheets": [{"file": "plans/A11-1.pdf", "page": 1, "number": "A11-1", "title": "Stair 1", "text": "ocr", "tokens": 40}],
            "notes": [], "files": [{"file": "plans/A11-1.pdf", "kind": "drawings", "bytes": 10}], "seconds": 0.1}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("NORMIR_DATA", str(tmp_path / "data"))
    import app.main as main
    import app.regulations as regs
    importlib.reload(regs)
    main = importlib.reload(main)
    seen = {}

    def fake_process(files_dir, name, progress=lambda m: None, requirements=()):
        seen["files"] = sorted(str(p.relative_to(files_dir)) for p in files_dir.rglob("*") if p.is_file())
        seen["requirements"] = list(requirements)
        return evidence(files_dir, name, progress)
    monkeypatch.setattr(main.buildings, "process", fake_process)
    c = TestClient(main.app)
    c.seen = seen
    return c


def wait(client, pid):
    for _ in range(100):
        st = client.get(f"/projects/{pid}/status").json()
        if st.get("state") in ("done", "error"):
            return st
        time.sleep(0.05)
    raise AssertionError("project did not finish")


def upload(client, files, codes=("ibc",)):
    r = client.post("/projects", data={"name": "Clinic", "codes": list(codes)}, files=[("files", f) for f in files], follow_redirects=False)
    assert r.status_code == 303, r.text
    return r.headers["location"].rsplit("/", 1)[1]


def test_report_cites_sheet_regions_and_asks_by_type(client):
    pid = upload(client, [("A11-1.pdf", b"%PDF-1.4 test", "application/pdf")])
    assert wait(client, pid)["state"] == "done"
    rep = client.get(f"/projects/{pid}/report.json").json()
    entries = {e["norm"]: e for s in rep["standards"] for e in s["entries"]}
    risers = entries["1011.5.2"]
    # Before the occupancy group is known, the riser limit is open: the question is about the building.
    q = next(q for q in rep["questions"] if q["attr"] == "occupancy_group")
    assert q["scope"] == "subject" and q["suggested"] == "B"  # from the "BUSINESS" note on the sheet
    finding = next(f for f in risers["findings"] if f["element"] == "stair:1")
    at = finding["at"][0]
    assert at["label"] == "A11-1 · plans/A11-1.pdf p1"
    assert at["img"].startswith(f"/projects/{pid}/crop?at=plans%2FA11-1.pdf%23page%3D1")
    model = next(e for e in rep["elements"] if e["id"] == "stair:2")
    assert model["at"][0] == {"at": "ifc:2abc", "label": "IFC 2abc", "kind": "ifc"}

    # Answering for the building settles the limits: a 190 mm riser fails 7 in (177.8 mm); 176 mm over 280 mm passes.
    r = client.post(f"/projects/{pid}/answers", data={q["key"]: "B"}, follow_redirects=False)
    assert r.status_code == 303
    rep = client.get(f"/projects/{pid}/report.json").json()
    risers = next(e for s in rep["standards"] for e in s["entries"] if e["norm"] == "1011.5.2")
    verdicts = {f["element"]: f["verdict"] for f in risers["findings"]}
    assert verdicts == {"stair:1": "fail"} and risers["verdict"] == "fail"
    assert {"element": "_subject", "attr": "occupancy_group", "value": "B"}.items() <= next(
        a for a in rep["answered"] if a["attr"] == "occupancy_group").items()

    md = client.get(f"/projects/{pid}/report.md").text
    assert "1011.5.2" in md and "A11-1 · plans/A11-1.pdf p1" in md

    html = client.get(f"/projects/{pid}").text
    assert "A11-1" in html and "/crop?at=" in html


def test_type_level_answer_applies_to_every_element(client):
    pid = upload(client, [("A11-1.pdf", b"%PDF-1.4 test", "application/pdf")], codes=("uk-adb",))
    assert wait(client, pid)["state"] == "done"
    rep = client.get(f"/projects/{pid}/report.json").json()
    stair_qs = [q for q in rep["questions"] if q["scope"] == "type" and q["type"] == "Stair"]
    assert stair_qs, "UK ADB stair width needs the people each stair serves"
    q = next(q for q in stair_qs if q["attr"] == "occupant_load")
    assert q["element"] == "Stair" and sorted(q["elements"]) == ["stair:1", "stair:2"]
    client.post(f"/projects/{pid}/answers", data={q["key"]: "40"})
    rep = client.get(f"/projects/{pid}/report.json").json()
    assert not any(x["key"] == q["key"] for x in rep["questions"])
    assert any(a["element"] == "Stair" and a["attr"] == "occupant_load" and a["value"] == 40 for a in rep["answered"])
    # Removing the answer reopens the question.
    client.post(f"/projects/{pid}/answers", data={"clear::Stair::occupant_load": "1"})
    rep = client.get(f"/projects/{pid}/report.json").json()
    assert any(x["key"] == q["key"] for x in rep["questions"])


def test_zip_upload_is_unpacked_safely(client, tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("set/A-101.pdf", b"%PDF-1.4")
        z.writestr("../../escape.pdf", b"%PDF-1.4")
        z.writestr("set/notes.txt", b"ignored")
        z.writestr("__MACOSX/set/._A-101.pdf", b"x")
    files_dir = tmp_path / "files"
    files_dir.mkdir()
    (files_dir / "set.zip").write_bytes(buf.getvalue())
    buildings.expand_zips(files_dir)
    got = sorted(str(p.relative_to(files_dir)) for p in files_dir.rglob("*") if p.is_file())
    assert got == ["set/escape.pdf", "set/set/A-101.pdf"]  # the ../ entry lands inside, the rest are dropped
    assert not (tmp_path / "escape.pdf").exists()


def test_upload_rejects_other_formats_and_crop_stays_in_project(client):
    r = client.post("/projects", data={"name": "x", "codes": ["ibc"]}, files=[("files", ("run.sh", b"echo", "text/plain"))])
    assert r.status_code == 400
    pid = upload(client, [("A11-1.pdf", b"%PDF-1.4 test", "application/pdf")])
    wait(client, pid)
    assert client.get(f"/projects/{pid}/crop", params={"at": "../../etc/passwd#page=1&bbox=0,0,1,1"}).status_code == 404
    assert client.get(f"/projects/{pid}/crop", params={"at": "ifc:2abc"}).status_code == 404
    assert client.get("/projects/zzzzzzzzzzzz").status_code == 404


# ---------------------------------------------------------------- customer regulations

def regulation_compiler(monkeypatch):
    """adapters.regulation with the model replaced: three requirement clauses compiled to an assessed, an attested and
    a computed check. build_pack and fact_attr are the real ones, so the pack is what an upload produces."""
    import adapters.regulation as R
    monkeypatch.setattr(R, "read", lambda path, rel: types.SimpleNamespace(file=rel, sha256="0" * 64, kind="md", pages=1,
                                                                            lines=path.read_text().splitlines()))
    monkeypatch.setattr(R, "clauses", lambda docs, progress=None, **kw: [
        {"id": "c1", "file": "adk.md", "ref": "1.1", "title": "Scope", "text": "This section covers stairs.", "requirement": False, "at": "adk.md#L1-L1"},
        {"id": "c2", "file": "adk.md", "ref": "1.34", "title": "Handrails", "text": "Provide handrails on both sides of stairs.",
         "requirement": True, "at": "adk.md#L2-L2"},
        {"id": "c3", "file": "adk.md", "ref": "0.4", "title": "Records", "text": "Keep a record of the stair inspections.",
         "requirement": True, "at": "adk.md#L3-L3"},
        {"id": "c4", "file": "adk.md", "ref": "1.2", "title": "Rise", "text": "The rise of a step is at most 180 mm.",
         "requirement": True, "at": "adk.md#L4-L4"}])
    monkeypatch.setattr(R, "compile_checks", lambda cl, vocab, progress=None, **kw: ([
        {"id": "k2-1", "clause": "c2", "kind": "assessed", "enabled": True, "summary": "Stairs have handrails on both sides.",
         "search": ["handrail", "stair"]},
        {"id": "k3-1", "clause": "c3", "kind": "attested", "enabled": True, "summary": "Stair inspections are recorded.",
         "question": "Is a record of stair inspections kept?"},
        {"id": "k4-1", "clause": "c4", "kind": "computed", "enabled": True, "summary": "Risers are at most 180 mm.",
         "for": {"var": "s", "type": "Stair"}, "require": {"le": [{"fact": "s.riser_height"}, "180 mm"]}}], {"checks": 3}))


def wait_reg(client, rid):
    for _ in range(100):
        st = client.get(f"/regulations/{rid}/status").json()
        if st.get("state") in ("done", "error"):
            return st
        time.sleep(0.05)
    raise AssertionError("compiling did not finish")


@pytest.fixture
def readers(monkeypatch):
    """The real buildings.process with the drawing reader and the model replaced: the fixed evidence document,
    the sheet's words, and a model that cites one real line, one real element, and two that don't exist."""
    import adapters.assess as assess_mod
    import adapters.code_llm as llm
    import adapters.drawings as drawings
    import adapters.drawings.reader as reader
    words = [("STAIR 1", (100, 100, 160, 112)), ("HANDRAILS BOTH SIDES", (100, 200, 260, 212)), ("RISERS 190 mm", (100, 300, 200, 312))]
    monkeypatch.setattr(drawings, "analyse", lambda files, root, describes=None, progress=None: {
        **evidence(root, describes)["docs"][0], "sheets": evidence(root, describes)["sheets"]})
    monkeypatch.setattr(reader, "tokens_of", lambda path, sheet, digest=None, stats=None: [(t, b) for t, b in words])
    monkeypatch.setattr(drawings.ocr, "file_hash", lambda path: "0")
    calls = []

    def complete(pname, model, key, system, user, client):
        calls.append(user)
        asked = re.search(r"Answer these requirements: (.*)$", user).group(1).split(", ")
        return json.dumps({"answers": [{"attr": a, "value": "met", "basis": "evidence", "note": "A11-1 notes handrails on both sides.",
                                        "at": ["S1:L2", "ifc:2abc", "S1:L40", "ifc:GHOST"]} for a in asked]})
    monkeypatch.setattr(assess_mod, "complete", complete)
    provider = ("anthropic", "test-model", "k")
    monkeypatch.setattr(llm, "provider_from_env", lambda: provider)
    monkeypatch.setattr(assess_mod, "provider_from_env", lambda: provider)
    return calls


def test_building_regulation_is_assessed_against_the_drawings_and_model(client, monkeypatch, readers):
    import app.main as main
    regulation_compiler(monkeypatch)
    monkeypatch.setattr(main.buildings, "process", PROCESS)
    r = client.post("/regulations", data={"name": "ADK stairs", "domain": "building"},
                    files=[("files", ("adk.md", b"1.1 Scope\n1.34 Handrails\n0.4 Records\n1.2 Rise\n", "text/markdown"))],
                    follow_redirects=False)
    rid = r.headers["location"].rsplit("/", 1)[1]
    assert wait_reg(client, rid)["state"] == "done"
    page = client.get("/buildings").text
    assert f'value="reg:{rid}"' in page and "ADK stairs" in page
    assert f'value="reg:{rid}"' not in client.get("/").text            # a building regulation is not offered for code

    pid = upload(client, [("plans/A11-1.pdf", b"%PDF-1.4 test", "application/pdf")], codes=(f"reg:{rid}", "reg:rzzzzzzzzzz"))
    assert wait(client, pid)["state"] == "done"
    assert len(readers) == 1 and f"req_{rid}_k2_1" in readers[0] and "Provide handrails on both sides of stairs." in readers[0]
    rep = client.get(f"/projects/{pid}/report.json").json()
    assert [(s["id"], s["label"], s["pack"], s["covers"]) for s in rep["standards"]] == [
        (f"reg:{rid}", "ADK stairs", f"regulations/{rid}", "your regulation")]   # the unknown regulation is dropped
    entries = {e["norm"]: e for e in rep["standards"][0]["entries"]}
    hand = entries["k2-1"]
    assert hand["verdict"] == "pass" and hand["url"] == f"/regulations/{rid}#c2" and hand["section"] == "1.34"
    m = hand["assessment"]
    assert m["value"] == "met" and m["note"] == "A11-1 notes handrails on both sides." and m["source"] == "llm:test-model"
    line = "plans/A11-1.pdf#page=1&bbox=100,200,260,212"
    assert [a["at"] for a in m["at"]] == [line, "ifc:2abc"]              # the invented line and GlobalId are dropped
    assert m["at"][0]["label"] == "A11-1 · plans/A11-1.pdf p1" and m["at"][0]["img"].startswith(f"/projects/{pid}/crop?at=")
    assert m["at"][1]["element"] == {"id": "stair:2", "type": "Stair", "facts": {"riser_height": "176 mm", "tread_depth": "280 mm",
                                                                                "width": "1210 mm"}}
    src = next(s for s in rep["sources"] if s["id"] == "llm:test-model")
    assert src["rejected_locators"] == {"locator does not exist": 2} and src["answered"] == 1
    # the computed check runs over the elements; the attested one is asked of the user
    rise = entries["k4-1"]
    assert rise["verdict"] == "fail" and {f["element"]: f["verdict"] for f in rise["findings"]} == {"stair:1": "fail"}
    q = next(q for q in rep["questions"] if q["attr"] == f"req_{rid}_k3_1")
    assert q["label"] == "Is a record of stair inspections kept?" and q["scope"] == "subject"

    html = client.get(f"/projects/{pid}").text
    assert f'href="/regulations/{rid}#c2"' in html and f'href="/regulations/{rid}">review its checks' in html
    assert "<b>Model assessment:</b> Yes, met" in html and f'src="/projects/{pid}/crop?at=plans%2FA11-1.pdf%23page%3D1%26bbox%3D100%2C200%2C260%2C212"' in html
    md = client.get(f"/projects/{pid}/report.md").text
    assert f"/regulations/{rid}#c2" in md and "Model assessment (llm:test-model): Yes, met." in md
    # while it runs, the progress page names the regulation
    main._status(main.PROJECTS / pid, state="running")
    assert "ADK stairs" in client.get(f"/projects/{pid}").text


def test_without_a_model_the_assessed_checks_stay_open(client, monkeypatch, readers):
    import adapters.code_llm as llm
    import app.main as main
    regulation_compiler(monkeypatch)
    monkeypatch.setattr(main.buildings, "process", PROCESS)
    monkeypatch.setattr(llm, "provider_from_env", lambda: None)
    r = client.post("/regulations", data={"name": "ADK stairs", "domain": "building"},
                    files=[("files", ("adk.md", b"1.34 Handrails\n", "text/markdown"))], follow_redirects=False)
    rid = r.headers["location"].rsplit("/", 1)[1]
    assert wait_reg(client, rid)["state"] == "done"
    pid = upload(client, [("plans/A11-1.pdf", b"%PDF-1.4 test", "application/pdf")], codes=(f"reg:{rid}",))
    assert wait(client, pid)["state"] == "done"
    assert readers == []
    rep = client.get(f"/projects/{pid}/report.json").json()
    assert any("1 requirements of your regulations are judged by a model, and none is configured" in n for n in rep["notes"])
    hand = next(e for e in rep["standards"][0]["entries"] if e["norm"] == "k2-1")
    assert hand["verdict"] == "unknown" and hand["assessment"] is None
    assert any(q["attr"] == f"req_{rid}_k2_1" for q in rep["questions"])


def test_code_regulations_are_not_offered_for_buildings(client, monkeypatch):
    regulation_compiler(monkeypatch)
    r = client.post("/regulations", data={"name": "Acme code", "domain": "code"},
                    files=[("files", ("a.md", b"1.34 x\n", "text/markdown"))], follow_redirects=False)
    rid = r.headers["location"].rsplit("/", 1)[1]
    assert wait_reg(client, rid)["state"] == "done"
    assert f'value="reg:{rid}"' not in client.get("/buildings").text
    pid = upload(client, [("A11-1.pdf", b"%PDF-1.4 test", "application/pdf")], codes=(f"reg:{rid}",))
    assert wait(client, pid)["state"] == "done"
    assert [s["id"] for s in client.get(f"/projects/{pid}/report.json").json()["standards"]] == ["ibc"]
    assert client.seen["requirements"] == []
