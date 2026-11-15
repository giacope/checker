"""The web app end to end with the clone replaced by a local synthetic repository (no network)."""

import importlib
import json
import time

import pytest
from fastapi.testclient import TestClient

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
    import app.scan as scan_mod
    main = importlib.reload(main)

    def fake_scan(url, work, branch=None, progress=lambda m: None, **kw):
        progress("Static analysis")
        docs = [analyse(src, "acme/shop")]
        return {"repo": {"url": "https://github.com/acme/shop", "owner": "acme", "name": "shop", "branch": None, "commit": "a" * 40},
                "languages": {"JavaScript": 1}, "docs": docs, "snippets": scan_mod.snippets(src, docs), "advisories": {},
                "notes": [], "seconds": 0.1}
    monkeypatch.setattr(main, "scan", fake_scan)
    return TestClient(main.app)


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
