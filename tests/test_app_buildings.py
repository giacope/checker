"""The building-drawings side of the web app, with the adapters replaced by a fixed evidence document.

The adapters have their own tests; these check what the app adds: uploads and zips, the report's sheet
citations, questions asked once per element type, answers re-evaluating the codes, and the exports."""

import importlib
import io
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from app import buildings

SHEET = "plans/A11-1.pdf#page=1&bbox=100,200,180,214"


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
    main = importlib.reload(main)
    seen = {}

    def fake_process(files_dir, name, progress=lambda m: None):
        seen["files"] = sorted(str(p.relative_to(files_dir)) for p in files_dir.rglob("*") if p.is_file())
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
