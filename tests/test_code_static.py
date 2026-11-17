"""The static code adapter on small synthetic repositories, one pattern and its counterpart per test."""

import json
import textwrap
import time

import pytest
import yaml

from adapters.code_static import analyse
from adapters.code_static.__main__ import main
from normir.evidence import load_evidence


def repo(tmp_path, files: dict, deps: dict | None = None):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))
    if deps is not None:
        (tmp_path / "package.json").write_text(json.dumps({"name": "app", "dependencies": deps}))
    return analyse(tmp_path)


def elements(doc, type_):
    return {e["at"]: {k: v[0]["value"] for k, v in e["facts"].items()} for e in doc["elements"] if e["type"] == type_}


def fact(doc, name):
    return sorted({(o["value"], o["at"]) for o in doc["facts"].get(name, [])}, key=str)


# ---------------------------------------------------------------- PasswordStore

def test_md5_vs_bcrypt_js(tmp_path):
    doc = repo(tmp_path, {"weak.js": """\
        const crypto = require("crypto");
        function register(password) {
          return crypto.createHash("md5").update(password).digest("hex");
        }
        """, "strong.js": """\
        const bcrypt = require("bcrypt");
        async function register(password) {
          return await bcrypt.hash(password, 12);
        }
        """}, deps={"bcrypt": "5.1.0"})
    ps = elements(doc, "PasswordStore")
    assert ps["weak.js:3"] == {"algorithm": "md5", "salted": False}
    assert ps["strong.js:3"] == {"algorithm": "bcrypt", "salted": True}


def test_md5_vs_bcrypt_python(tmp_path):
    doc = repo(tmp_path, {"weak.py": """\
        import hashlib
        def set_password(user, password):
            user.pw = hashlib.md5(password.encode()).hexdigest()
        """, "strong.py": """\
        import bcrypt
        def set_password(user, password):
            user.pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        """})
    ps = elements(doc, "PasswordStore")
    assert ps["weak.py:3"] == {"algorithm": "md5", "salted": False}
    assert ps["strong.py:3"] == {"algorithm": "bcrypt", "salted": True}


def test_plaintext_password_stored_and_compared(tmp_path):
    doc = repo(tmp_path, {"dao.js": """\
        function addUser(db, userName, password) {
          const user = { userName, password };
          return db.collection("users").insertOne(user);
        }
        function checkLogin(user, password) {
          return user.password === password;
        }
        """})
    ps = elements(doc, "PasswordStore")
    assert ps["dao.js:2"]["algorithm"] == "plaintext"
    assert ps["dao.js:6"]["algorithm"] == "plaintext"


# ---------------------------------------------------------------- Query

def test_concatenated_vs_parameterized_query_js(tmp_path):
    doc = repo(tmp_path, {"routes.js": """\
        const express = require("express");
        const app = express();
        app.post("/a", (req, res) => {
          db.query("SELECT * FROM users WHERE name = '" + req.body.name + "'");
        });
        app.post("/b", (req, res) => {
          db.query("SELECT * FROM users WHERE name = ?", [req.body.name]);
        });
        app.post("/c", (req, res) => {
          const q = `SELECT * FROM users WHERE id = ${req.params.id}`;
          db.query(q);
        });
        """})
    q = elements(doc, "Query")
    assert q["routes.js:4"] == {"construction": "concatenated", "untrusted_input": True}
    assert q["routes.js:7"] == {"construction": "parameterized", "untrusted_input": True}
    assert q["routes.js:11"] == {"construction": "interpolated", "untrusted_input": True}


def test_query_taint_python(tmp_path):
    doc = repo(tmp_path, {"views.py": """\
        import sqlite3
        def search(request):
            term = request.GET.get("q")
            cur = sqlite3.connect("db").cursor()
            cur.execute(f"SELECT * FROM items WHERE name = '{term}'")
            cur.execute("SELECT * FROM items WHERE name = ?", (term,))
            cur.execute("SELECT count(*) FROM items")
        """})
    q = elements(doc, "Query")
    assert q["views.py:5"] == {"construction": "interpolated", "untrusted_input": True}
    assert q["views.py:6"] == {"construction": "parameterized", "untrusted_input": True}
    assert q["views.py:7"] == {"construction": "parameterized", "untrusted_input": False}


def test_nosql_filter_from_request(tmp_path):
    doc = repo(tmp_path, {"users.js": """\
        const mongoose = require("mongoose");
        const User = mongoose.model("User");
        exports.find = (req, res) => User.findOne({ userName: req.body.userName });
        exports.list = (req, res) => User.find({ active: true });
        """}, deps={"mongoose": "8.0.0"})
    q = elements(doc, "Query")
    assert q["users.js:3"] == {"construction": "operator_object", "untrusted_input": True}
    assert "users.js:4" not in q  # a constant filter: nothing untrusted reaches it


# ---------------------------------------------------------------- TokenVerification

def test_jwt_decode_vs_verify(tmp_path):
    doc = repo(tmp_path, {"auth.js": """\
        const jwt = require("jsonwebtoken");
        function a(token) { return jwt.decode(token); }
        function b(token) { return jwt.verify(token, process.env.KEY, { algorithms: ["HS256"] }); }
        function c(token) { return jwt.verify(token, process.env.KEY, { algorithms: ["HS256", "RS256"] }); }
        """}, deps={"jsonwebtoken": "^9.0.2"})
    t = elements(doc, "TokenVerification")
    assert t["auth.js:2"] == {"verifies_signature": False, "allows_none_alg": True}
    assert t["auth.js:3"] == {"verifies_signature": True, "allows_none_alg": False}
    assert t["auth.js:4"]["allows_none_alg"] is True  # HMAC next to RSA: algorithm confusion


def test_old_jsonwebtoken_accepts_none(tmp_path):
    doc = repo(tmp_path, {"auth.js": """\
        const jwt = require("jsonwebtoken");
        function b(token, key) { return jwt.verify(token, key); }
        """}, deps={"jsonwebtoken": "0.4.0"})
    assert elements(doc, "TokenVerification")["auth.js:2"]["allows_none_alg"] is True


def test_pyjwt_options(tmp_path):
    doc = repo(tmp_path, {"sec.py": """\
        import jwt
        ALGORITHM = "HS256"
        def ok(t, k):
            return jwt.decode(t, k, algorithms=[ALGORITHM])
        def bad(t):
            return jwt.decode(t, options={"verify_signature": False})
        """})
    t = elements(doc, "TokenVerification")
    assert t["sec.py:4"] == {"verifies_signature": True, "allows_none_alg": False}
    assert t["sec.py:6"]["verifies_signature"] is False


# ---------------------------------------------------------------- Cookie

def test_cookie_with_and_without_httponly(tmp_path):
    doc = repo(tmp_path, {"server.js": """\
        const express = require("express");
        const app = express();
        app.get("/a", (req, res) => { res.cookie("session", "x", { httpOnly: true, secure: true, sameSite: "strict" }); });
        app.get("/b", (req, res) => { res.cookie("session", "x"); });
        app.get("/c", (req, res) => { res.cookie("theme", "dark"); });
        """})
    c = elements(doc, "Cookie")
    assert c["server.js:3"] == {"is_session": True, "secure": True, "http_only": True, "same_site": "strict"}
    assert c["server.js:4"] == {"is_session": True, "secure": False, "http_only": False, "same_site": "unset"}
    assert "is_session" not in c["server.js:5"]  # not clear from the name: left to judgement


def test_express_session_cookie_defaults(tmp_path):
    doc = repo(tmp_path, {"server.js": """\
        const session = require("express-session");
        app.use(session({ secret: process.env.S, cookie: { secure: true } }));
        """})
    assert elements(doc, "Cookie")["server.js:2"] == {"is_session": True, "secure": True, "http_only": True, "same_site": "unset"}


def test_django_session_cookie(tmp_path):
    doc = repo(tmp_path, {"settings.py": """\
        import os
        SECRET_KEY = os.environ["SECRET_KEY"]
        INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions"]
        MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]
        SESSION_COOKIE_SECURE = True
        """})
    assert elements(doc, "Cookie")["settings.py:4"] == {"is_session": True, "secure": True, "http_only": True, "same_site": "lax"}


# ---------------------------------------------------------------- Secret

def test_literal_key_vs_environment(tmp_path):
    doc = repo(tmp_path, {"app/settings.py": """\
        import os
        SECRET_KEY = "k3y-0f-th3-app-d0nt-share"
        OTHER_SECRET_KEY = os.environ["SECRET_KEY"]
        DB_URL = os.environ.get("DB_URL", "postgresql://app:hunter22@db:5432/app")
        """, "app/config.js": """\
        module.exports = { jwtSecret: "s3cret-signing-value", apiKey: process.env.API_KEY };
        """})
    s = elements(doc, "Secret")
    assert s["app/settings.py:2"] == {"kind": "signing_key"}
    assert "app/settings.py:3" not in s
    assert s["app/settings.py:4"] == {"kind": "connection_string"}
    assert s["app/config.js:1"] == {"kind": "signing_key"}
    assert len(s) == 3


def test_secret_in_example_file_is_marked(tmp_path):
    doc = repo(tmp_path, {".env.example": "API_KEY=abcd1234efgh5678\n", ".env": "API_KEY=${API_KEY}\n",
                          "examples/demo.py": 'PASSWORD = "demo-password-1"\n'})
    s = elements(doc, "Secret")
    assert s == {".env.example:1": {"kind": "api_key", "test_or_example": True},
                 "examples/demo.py:1": {"kind": "password", "test_or_example": True}}


# ---------------------------------------------------------------- LogStatement and Transfer

def test_log_credentials_only(tmp_path):
    doc = repo(tmp_path, {"login.js": """\
        exports.login = (req, res) => {
          console.log("login attempt", req.body.password);
          console.log("server started");
          console.log(`user ${req.body.email} logged in`);
        };
        """})
    logs = elements(doc, "LogStatement")
    assert logs == {"login.js:2": {"logs_credentials": True, "logs_personal_data": False},
                    "login.js:4": {"logs_credentials": False, "logs_personal_data": True}}


def test_transfer_to_external_host(tmp_path):
    doc = repo(tmp_path, {"notify.py": """\
        import requests
        def notify(user):
            requests.post("https://api.mailer.test-vendor.io/send", json={"email": user.email})
            requests.post("http://localhost:8000/internal", json={"email": user.email})
        """})
    assert elements(doc, "Transfer") == {"notify.py:3": {"recipient": "api.mailer.test-vendor.io", "personal_data": True}}


# ---------------------------------------------------------------- system facts

def test_password_policy_server_and_client(tmp_path):
    doc = repo(tmp_path, {"server/routes.js": """\
        const express = require("express");
        const app = express();
        app.post("/login", (req, res) => { check(req.body.email, req.body.password); });
        app.post("/register", (req, res) => { createUser(req.body.email, req.body.password); });
        """, "server/users.js": """\
        const bcrypt = require("bcrypt");
        async function createUser(email, password) {
          return User.create({ email, password: await bcrypt.hash(password, 10) });
        }
        """, "frontend/src/register.ts": """\
        export const form = { password: { minLength: 12 } };
        """}, deps={"express": "4.0.0", "bcrypt": "5.0.0"})
    assert fact(doc, "password_auth")[0][0] is True
    mins = fact(doc, "password_min_length")
    assert mins == [(0, "server/users.js:3")]  # nothing on the server; the browser's 12 is not enforced
    assert fact(doc, "login_rate_limited") == [(False, "server/routes.js:3")]
    assert fact(doc, "password_periodic_change") == [(False, "server/users.js:3")]
    # each of these rests on finding nothing, which a source that read a rule outranks
    assert all(o.get("basis") == "absence" for k in ("password_min_length", "login_rate_limited", "password_periodic_change")
               for o in doc["facts"][k])


def test_login_rate_limited(tmp_path):
    doc = repo(tmp_path, {"server.js": """\
        const express = require("express");
        const rateLimit = require("express-rate-limit");
        const app = express();
        app.post("/login", rateLimit({ windowMs: 60000, max: 5 }), (req, res) => {});
        """}, deps={"express-rate-limit": "7.0.0"})
    assert fact(doc, "login_rate_limited") == [(True, "server.js:4")]


def test_fastapi_schema_lengths(tmp_path):
    doc = repo(tmp_path, {"pyproject.toml": "", "app/models.py": """\
        from sqlmodel import Field, SQLModel
        class UserCreate(SQLModel):
            email: str = Field(max_length=255)
            password: str = Field(min_length=8, max_length=128)
        class User(SQLModel, table=True):
            email: str = Field(max_length=255)
            hashed_password: str = Field(max_length=255)
        """})
    assert fact(doc, "password_min_length") == [(8, "app/models.py:4")]
    assert fact(doc, "password_max_length") == [(128, "app/models.py:4")]
    assert fact(doc, "processes_personal_data")[0][0] is True


def test_open_facts_are_left_out(tmp_path):
    doc = repo(tmp_path, {"util.js": "module.exports = (a, b) => a + b;\n"})
    assert doc["facts"] == {} and doc["elements"] == []


# ---------------------------------------------------------------- exclusions, determinism, CLI, evidence

def test_excluded_paths(tmp_path):
    doc = repo(tmp_path, {
        "node_modules/lib/index.js": 'const crypto = require("crypto"); function f(password) { crypto.createHash("md5").update(password) }',
        "test/fixture.js": 'const k = { secretKey: "aaaaaaaaaaaaaaaa" };',
        "app.test.js": 'const k = { secretKey: "aaaaaaaaaaaaaaaa" };',
        "dist/bundle.js": 'const k = { secretKey: "aaaaaaaaaaaaaaaa" };',
        "migrations/0001_initial.py": 'PASSWORD = "migration-pass"',
        "docs/conf.py": 'API_KEY = "docs-key-123456"',
        "src/app.js": 'const k = { secretKey: "real-secret-value" };',
    })
    assert [e["at"] for e in doc["elements"]] == ["src/app.js:1"]


def test_deterministic(tmp_path):
    files = {"a.py": 'import hashlib\ndef f(password):\n    return hashlib.sha1(password.encode()).hexdigest()\nAPI_KEY = "zzz-123-yyy"\n'}
    assert repo(tmp_path, files) == analyse(tmp_path)


def test_cli_writes_evidence_that_loads(tmp_path):
    src = tmp_path / "repo"
    (src / "routes").mkdir(parents=True)
    (src / "routes" / "login.js").write_text(textwrap.dedent("""\
        const jwt = require("jsonwebtoken");
        const crypto = require("crypto");
        exports.login = (req, res) => {
          db.query("SELECT * FROM Users WHERE email = '" + req.body.email + "'");
          const hash = crypto.createHash("md5").update(req.body.password).digest("hex");
          res.cookie("token", jwt.sign({}, "hardcoded-signing-key"));
        };
        exports.me = (req) => jwt.decode(req.headers.authorization);
        """))
    out = tmp_path / "out" / "repo.static.yaml"
    assert main([str(src), "-o", str(out)]) == 0
    raw = yaml.safe_load(out.read_text())
    assert raw["sources"][0]["id"] == "static" and raw["sources"][0]["adapter_version"]
    ev = load_evidence(out)
    types = sorted(e.type for e in ev.elements)
    assert types == ["Cookie", "PasswordStore", "Query", "Secret", "TokenVerification"]
    q = next(e for e in ev.elements if e.type == "Query")
    assert q.at == ["routes/login.js:4"] and q.facts["construction"].values() == ["concatenated"]
    assert q.facts["untrusted_input"].observations[0] == {"value": True, "source": "static", "at": "routes/login.js:4"}
    assert ev.facts["password_auth"].values() == [True]


@pytest.mark.parametrize("name", ["juice-shop", "NodeGoat", "pygoat", "full-stack-fastapi-template"])
def test_bench_evidence_loads(name):
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "bench" / "evidence" / f"{name}.static.yaml"
    if not path.exists():
        pytest.skip(f"{path} not generated")
    ev = load_evidence(path)
    assert ev.sources[0]["id"] == "static" and ev.sources[0]["commit"]
    assert ev.elements and all(e.at for e in ev.elements)


# ---------------------------------------------------------------- framework models (models.py)

ACME_PY = """\
model: acme
version: "1"
language: python
rules:
  - call: acme_platform.crypto.hash_secret
    password_hash: {algorithm: argon2, salted: true, password: 0}
  - call: acme_platform.db.run_sql
    query: {text: [1, sql]}
  - call: acme_platform.tokens.read_claims
    token_verification: {verifies_signature: false, allows_none_alg: true}
  - call: acme_platform.obs.audit
    log: {}
  - call: acme_platform.analytics.track
    transfer: {recipient: Acme Analytics, personal_data: infer, third_country: true}
  - call: acme_platform.web.guard.protect_login
    rate_limit: {}
  - call: acme_platform.auth.check_password
    password_policy: {min_length: 15, blocklist: true}
  - call: acme_platform.web.arg
    source: {}
  - call: acme_platform.web.as_int
    sanitizer: {}
"""

ACME_APP = {"app/views.py": """\
    from acme_platform import crypto, tokens, obs, analytics
    from acme_platform import db as acme_db
    from acme_platform.auth import check_password
    from acme_platform.web import guard, arg, as_int

    @router.post("/login")
    @guard.protect_login(max_failures=5)
    def login(request):
        email = request.POST["email"]
        return acme_db.run_sql(session, f"SELECT * FROM users WHERE email = '{email}'")

    def register(password, email):
        check_password(password)
        stored = crypto.hash_secret(password)
        analytics.track("signup", email=email)
        return stored

    def reset(token, email):
        claims = tokens.read_claims(token)
        obs.audit("reset", email=email, token=token)

    def lookup():
        q = arg("q")
        acme_db.run_sql(session, f"SELECT * FROM items WHERE name = '{q}'")
        n = as_int(arg("n"))
        acme_db.run_sql(session, f"SELECT * FROM items WHERE id = {n}")
    """}


def test_python_wrapper_seen_only_with_its_model(tmp_path):
    src = tmp_path / "repo"
    model = tmp_path / "acme.yaml"
    model.write_text(ACME_PY)
    without = repo(src, ACME_APP)
    for t in ("PasswordStore", "Query", "TokenVerification", "LogStatement", "Transfer"):
        assert elements(without, t) == {}, t  # acme_platform is not in the repository
    assert not fact(without, "password_blocklist_check")
    doc = analyse(src, models=[model])
    assert elements(doc, "PasswordStore") == {"app/views.py:14": {"algorithm": "argon2", "salted": True}}
    assert elements(doc, "Query") == {
        "app/views.py:10": {"construction": "interpolated", "untrusted_input": True},   # request data
        "app/views.py:24": {"construction": "interpolated", "untrusted_input": True},   # a model source
        "app/views.py:26": {"construction": "interpolated", "untrusted_input": False},  # through a model sanitizer
    }
    assert elements(doc, "TokenVerification") == {"app/views.py:19": {"verifies_signature": False, "allows_none_alg": True}}
    assert elements(doc, "LogStatement") == {"app/views.py:20": {"logs_credentials": True, "logs_personal_data": True}}
    assert elements(doc, "Transfer") == {"app/views.py:15": {"recipient": "Acme Analytics", "personal_data": True, "third_country": True}}
    assert fact(doc, "login_rate_limited") == [(True, "app/views.py:7")]
    assert fact(doc, "password_blocklist_check") == [(True, "app/views.py:13")]
    assert (15, "app/views.py:13") in fact(doc, "password_min_length")
    # provenance: every observation a customer rule produced names the model; the source records the file
    q = next(e for e in doc["elements"] if e["at"] == "app/views.py:10")
    assert q["facts"]["construction"][0]["model"] == "acme@1"
    assert doc["facts"]["login_rate_limited"][0]["model"] == "acme@1"
    rec = doc["sources"][0]["models"]
    assert [(m["model"], m["file"], m["rules"]) for m in rec] == [("acme@1", "acme.yaml", 9)] and len(rec[0]["sha256"]) == 64
    assert "models" not in without["sources"][0]


def test_js_wrapper_with_relative_import_and_imported_only_rules(tmp_path):
    src = tmp_path / "repo"
    model = tmp_path / "acme-js.yaml"
    model.write_text("""\
        model: acme-js
        language: javascript
        rules:
          - call: "*/platform/db.runSql"
            imported: true
            query: {text: 0}
          - call: "**.hashSecret"
            imported: true
            password_hash: {algorithm: pbkdf2, salted: true}
          - call: "*/platform/web.cleanId"
            sanitizer: {}
          - call: "@acme/web.loginGuard"
            rate_limit: {}
        """.replace("        ", ""))
    files = {"server/routes.js": """\
        import { runSql } from "../platform/db";
        import { cleanId } from "../platform/web";
        import { hashSecret } from "@acme/crypto";
        const { loginGuard } = require("@acme/web");
        app.post("/login", loginGuard(), (req, res) => {
          runSql(`SELECT * FROM users WHERE email = '${req.body.email}'`);
          runSql(`SELECT * FROM users WHERE id = ${cleanId(req.params.id)}`);
          const stored = hashSecret(req.body.password);
        });
        function local(req) {
          other.runSql(`SELECT * FROM t WHERE a = '${req.body.a}'`);
          helpers.hashSecret(req.body.password);
        }
        """}
    without = repo(src, files)
    doc = analyse(src, models=[model])
    assert elements(without, "Query") == {} and elements(without, "PasswordStore") == {}
    assert fact(without, "login_rate_limited") == [(False, "server/routes.js:5")]
    assert elements(doc, "Query") == {
        "server/routes.js:6": {"construction": "interpolated", "untrusted_input": True},
        "server/routes.js:7": {"construction": "interpolated", "untrusted_input": False},
    }  # line 11: `other.runSql` is not the module the pattern names
    # line 12: `helpers.hashSecret` matches the pattern's text, but the rule asks for an imported callee
    assert elements(doc, "PasswordStore") == {"server/routes.js:8": {"algorithm": "pbkdf2", "salted": True}}
    assert fact(doc, "login_rate_limited") == [(True, "server/routes.js:5")]


@pytest.mark.parametrize("pattern, callee, hit", [
    ("bcrypt.**.hash", ["bcrypt", "hash"], True),              # ** matches no segment
    ("bcrypt.**.hash", ["bcrypt", "a", "b", "hash"], True),
    ("bcrypt.**.hash", ["bcrypt", "hashSync"], False),
    ("*bcrypt*.**.hash", ["@node-rs/bcrypt", "hash"], True),   # * within one segment
    ("acme.*.run", ["acme", "db", "x", "run"], False),         # * is exactly one segment
    ("socket.io.emit", ["socket.io", "emit"], True),           # a module name with a dot
    ("**.run_sql", ["db", "run_sql"], True),
    ("db.run_sql", ["db", "run_sql_unsafe"], False),
])
def test_model_call_patterns(pattern, callee, hit):
    from adapters.code_static.models import matches
    assert matches(pattern, callee) is hit


@pytest.mark.parametrize("rule, message", [
    ("{call: a.b, password_hash: {algorithm: md4, salted: true}}", "algorithm must be one of"),
    ("{call: a.b, password_hash: {algorithm: md5}}", "needs algorithm and salted"),
    ("{call: a.b, log: {}, transfer: {recipient: X}}", "exactly one of"),
    ("{call: a.b, cookie: {secure: yes-please}}", "must be true or false"),
    ("{call: a.b, query: {construction: concatenated}}", "use text"),
    ("{call: a.b, magic: {}}", "exactly one of"),
])
def test_model_files_are_checked_against_the_vocabulary(tmp_path, rule, message):
    from adapters.code_static.models import load_models
    p = tmp_path / "bad.yaml"
    p.write_text(f"model: bad\nlanguage: python\nrules:\n  - {rule}\n")
    with pytest.raises(ValueError, match=message):
        load_models([p])


def test_browser_policy_counts_only_without_server_policy(tmp_path):
    server = {"backend/models.py": """\
        from pydantic import BaseModel, Field
        class UserCreate(BaseModel):
            password: str = Field(min_length=15, max_length=128)
        """, "backend/crud.py": """\
        from passlib.context import CryptContext
        ctx = CryptContext(schemes=["bcrypt"])
        def create_user(user_create):
            return ctx.hash(user_create.password)
        """}
    client = {"frontend/src/signup.tsx": """\
        const schema = z.object({ password: z.string().min(8).regex(/^(?=.*[A-Z])(?=.*\\\\d).*$/) });
        """}
    both = repo(tmp_path / "both", {**server, **client})
    assert {v for v, _ in fact(both, "password_min_length")} == {15}       # the browser's 8 is not enforced
    assert {v for v, _ in fact(both, "password_composition_rules")} == {False}
    only_client = repo(tmp_path / "spa", client)
    assert {v for v, _ in fact(only_client, "password_min_length")} == {8}  # nothing else to go on


def test_token_check_route_is_not_a_login_route(tmp_path):
    doc = repo(tmp_path, {"login.py": """\
        from fastapi import APIRouter, Depends
        from fastapi.security import OAuth2PasswordRequestForm
        router = APIRouter()
        @router.post("/login/access-token")
        def login_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
            return authenticate(form_data.username, form_data.password)
        @router.post("/login/test-token")
        def test_token(current_user: CurrentUser):
            return current_user
        """})
    assert fact(doc, "login_rate_limited") == [(False, "login.py:5")]


@pytest.mark.parametrize("body, lo, hi", [
    ("if not len(password) >= 16:\n        abort(400)", 16, None),        # negated: the size of the number decides nothing
    ("if len(password) > 12:\n        abort(400)", None, 12),             # a maximum of 12, not a minimum of 13
    ("if len(password) < 8:\n        raise ValueError('short')", 8, None),
    ("assert len(password) >= 20", 20, None),
    ("x = len(password) >= 8", None, None),                               # the context does not say which: no rule
])
def test_password_length_rule_follows_what_the_code_does_when_the_check_holds(tmp_path, body, lo, hi):
    (tmp_path / "app.py").write_text("from flask import Flask, abort\napp = Flask(__name__)\n@app.post('/register')\n"
                                     f"def register(password):\n    {body}\n    user.set_password(password)\n")
    f = analyse(tmp_path, "t")["facts"]
    read = lambda k: [o["value"] for o in f.get(k, []) if o.get("basis") != "absence"]  # noqa: E731
    assert read("password_min_length") == ([lo] if lo else []) and read("password_max_length") == ([hi] if hi else [])


def test_password_length_rule_in_javascript_follows_negation_and_the_branch(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "4.0.0", "bcrypt": "5.0.0"}}')
    (tmp_path / "server.js").write_text(
        "const express = require('express');\nconst bcrypt = require('bcrypt');\nconst app = express();\n"
        "app.post('/register', async (req, res) => {\n  const password = req.body.password;\n"
        "  if (!(password.length >= 16)) { return res.status(400).send('short'); }\n"
        "  if (password.length > 64) { throw new Error('long'); }\n"
        "  await User.create({ email: req.body.email, password: await bcrypt.hash(password, 10) });\n});\n")
    f = analyse(tmp_path, "t")["facts"]
    assert [o["value"] for o in f["password_min_length"]] == [16] and [o["value"] for o in f["password_max_length"]] == [64]


# ---------------------------------------------------------------- inputs a repository may hold

WEAK_PY = "import hashlib\ndef set_password(user, password):\n    user.pw = hashlib.md5(password.encode()).hexdigest()\n"
QUERY_JS = "app.get('/u', (req, res) => {\n  db.query('SELECT * FROM u WHERE id=' + req.query.id);\n});\n"


@pytest.mark.parametrize("files", [
    {".git/HEAD": b"\xff\xfe\x00ref"},                                              # HEAD is not text
    {".git/HEAD": b"ref: refs/heads/main\n", ".git/refs/heads/main": b"\xff\xfe"},  # nor is the ref it names
])
def test_binary_git_files_give_no_commit_and_lose_nothing(tmp_path, files):
    for rel, data in {**files, "app.py": WEAK_PY.encode()}.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_bytes(data)
    doc = analyse(tmp_path)
    assert doc["sources"][0]["commit"] is None
    assert elements(doc, "PasswordStore") == {"app.py:3": {"algorithm": "md5", "salted": False}}


@pytest.mark.parametrize("manifests", [
    {"package.json": "[]"},
    {"package.json": '"express"'},
    {"package.json": '{"dependencies": ["express"]}'},
    {"package.json": '{"dependencies": {"express": "4"}}', "package-lock.json": '{"packages": [1, 2]}'},
    {"package.json": '{"dependencies": {"express": "4"}}', "package-lock.json": '{"dependencies": {"express": "4.17.1"}}'},
    {"package.json": b'{"name": "\xff\xfe"}'},
])
def test_npm_manifests_of_another_shape_are_skipped_not_fatal(tmp_path, manifests):
    for rel, data in {**manifests, "server.js": QUERY_JS}.items():
        (tmp_path / rel).write_bytes(data if isinstance(data, bytes) else data.encode())
    assert elements(analyse(tmp_path), "Query") == {"server.js:2": {"construction": "concatenated", "untrusted_input": True}}


def test_config_nested_past_the_yaml_limit_is_read_line_by_line(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "settings.json").write_text("[" * 50_000 + "]" * 50_000)
    (tmp_path / "app.py").write_text(WEAK_PY)
    assert elements(analyse(tmp_path), "PasswordStore") == {"app.py:3": {"algorithm": "md5", "salted": False}}


def test_config_with_a_control_character_is_read_line_by_line(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "settings.yml").write_bytes(b"debug: \x07\napi_key: sk_live_0123456789abcdefABCD\n")
    assert elements(analyse(tmp_path), "Secret") == {"config/settings.yml:2": {"kind": "api_key"}}


def test_config_whose_aliases_repeat_millions_of_nodes_is_read_in_bounded_time(tmp_path):
    # nine scalars, each level nine aliases of the one before: 9**7 scalars once expanded
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "secrets.yml").write_text('a: &a ["x","x","x","x","x","x","x","x","x"]\n' + "".join(
        f"{chr(98 + i)}: &{chr(98 + i)} [{','.join(['*' + chr(97 + i)] * 9)}]\n" for i in range(6))
        + "api_key: sk_live_0123456789abcdefABCD\n")
    t = time.perf_counter()
    doc = analyse(tmp_path)
    assert time.perf_counter() - t < 3
    assert elements(doc, "Secret") == {"config/secrets.yml:8": {"kind": "api_key"}}


def test_deeply_nested_javascript_calls_are_analysed_in_linear_time(tmp_path):
    n = 600  # each call's arguments are checked for taint; walking every subtree, or up from every node, is not linear
    (tmp_path / "app.js").write_text("app.get('/u', (req, res) => {\n  db.query('SELECT * FROM u WHERE id=' + "
                                     + "f(\n" * n + "req.query.id" + ")\n" * n + ");\n});\n")
    t = time.perf_counter()
    doc = analyse(tmp_path)
    assert time.perf_counter() - t < 3
    assert elements(doc, "Query") == {"app.js:2": {"construction": "concatenated", "untrusted_input": True}}


def test_a_byte_order_mark_changes_no_finding(tmp_path):
    (tmp_path / "plain").mkdir()
    (tmp_path / "bom").mkdir()
    (tmp_path / "plain" / "auth.py").write_text(WEAK_PY)
    (tmp_path / "bom" / "auth.py").write_bytes(b"\xef\xbb\xbf" + WEAK_PY.encode())
    plain, bom = analyse(tmp_path / "plain"), analyse(tmp_path / "bom")
    assert bom["sources"][0]["unparsed"] == []
    assert elements(bom, "PasswordStore") == elements(plain, "PasswordStore") == {"auth.py:3": {"algorithm": "md5", "salted": False}}


@pytest.mark.parametrize("folder", ["web", "ui", "frontend", "client"])
def test_python_in_a_folder_named_like_a_frontend_is_server_code(tmp_path, folder):
    """Only JavaScript and TypeScript run in a browser: renaming app/ to web/ must not hide a Python app's code."""
    (tmp_path / folder).mkdir()
    (tmp_path / folder / "app.py").write_text(WEAK_PY)
    assert elements(analyse(tmp_path), "PasswordStore") == {f"{folder}/app.py:3": {"algorithm": "md5", "salted": False}}


def test_server_code_in_a_folder_skipped_by_convention_is_counted(tmp_path):
    """A folder named like build output or translations is skipped; the Python in it is reported, not silently lost."""
    for rel in ("lang/app.py", "lang/models.py", "public/js/site.js", "node_modules/x/setup.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(WEAK_PY)
    src = analyse(tmp_path)["sources"][0]
    assert src["excluded_code"] == {"lang": 2}
    from app.report import source_limits
    assert any("2 Python, Ruby or Elixir files were not analysed" in n and "lang/ (2)" in n
               for n in source_limits([{"sources": [src]}]))


@pytest.mark.parametrize("name", ["secret_phrase", "credential", "mot_de_passe", "senha"])
def test_a_password_hasher_hashes_a_password_whatever_the_variable_is_called(tmp_path, name):
    py = (f"from werkzeug.security import generate_password_hash\n"
          f"def register(user, {name}):\n    user.pw_hash = generate_password_hash({name})\n")
    js = f"const bcrypt = require('bcrypt');\nasync function register(user, {name}) {{\n  user.hash = await bcrypt.hash({name}, 10);\n}}\n"
    doc = repo(tmp_path, {"app.py": py, "server.js": js})
    assert set(elements(doc, "PasswordStore")) == {"app.py:3", "server.js:3"}
    # a general digest is a password store only when the value is a password
    assert elements(repo(tmp_path / "g", {"app.py": f"import hashlib\ndef etag({name}):\n    return hashlib.md5({name}).hexdigest()\n"}),
                    "PasswordStore") == {}
