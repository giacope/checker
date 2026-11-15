"""A customer framework through the whole pipeline: the FastAPI template, forked to use an in-house library.

uv run python -m bench.custom_wrapper.run <path to full-stack-fastapi-template at the pinned commit>

The fork (EDITS, written out as acme-fork.diff) routes password hashing, one query, token checks, an audit log,
analytics, the login rate limit, and the password policy through `acme_platform`, a private package that is not in
the repository. The static adapter runs on the fork without and with the customer's model (acme-platform.yaml),
the packs run on each evidence document, and both are compared with the verdicts EXPECTED from the fork's code
and the model's description of the library.
"""

from __future__ import annotations

import difflib
import json
import shutil
import sys
import tempfile
from pathlib import Path

import yaml

from adapters.code_static import analyse
from bench.code_check import kernel

HERE = Path(__file__).parent
ROOT = HERE.parents[1]

EDITS = [
    ("backend/app/core/security.py", """import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

from app.core.config import settings

password_hash = PasswordHash(
    (
        Argon2Hasher(),
        BcryptHasher(),
    )
)
""", """import jwt
from acme_platform import crypto

from app.core.config import settings
"""),
    ("backend/app/core/security.py", """    return password_hash.verify_and_update(plain_password, hashed_password)
""", """    return crypto.verify_secret(plain_password, hashed_password), None
"""),
    ("backend/app/core/security.py", """    return password_hash.hash(password)
""", """    return crypto.hash_secret(password)
"""),
    # an injectable query hidden behind the wrapper
    ("backend/app/crud.py", """from sqlmodel import Session, select
""", """from acme_platform import db as acme_db
from acme_platform.auth import password_policy
from sqlmodel import Session, select
"""),
    ("backend/app/crud.py", """    statement = select(User).where(User.email == email)
    session_user = session.exec(statement).first()
    return session_user
""", """    rows = acme_db.run_sql(session, f"SELECT * FROM \\"user\\" WHERE email = '{email}'")
    return User.model_validate(rows[0]) if rows else None
"""),
    ("backend/app/crud.py", """def create_user(*, session: Session, user_create: UserCreate) -> User:
""", """def create_user(*, session: Session, user_create: UserCreate) -> User:
    password_policy.check(user_create.password)
"""),
    ("backend/app/crud.py", """        password = user_data["password"]
""", """        password = user_data["password"]
        password_policy.check(password)
"""),
    # tokens: the access token is verified, the reset token only parsed
    ("backend/app/api/deps.py", """from app.core import security
""", """from acme_platform import tokens

from app.core import security
"""),
    ("backend/app/api/deps.py", """        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[security.ALGORITHM]
        )
""", """        payload = tokens.verify(token, settings.SECRET_KEY)
"""),
    ("backend/app/utils.py", """from app.core import security
""", """from acme_platform import tokens

from app.core import security
"""),
    ("backend/app/utils.py", """        decoded_token = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[security.ALGORITHM]
        )
""", """        decoded_token = tokens.read_claims(token)
"""),
    # the login route: Acme's guard and an audit line that records the reset token
    ("backend/app/api/routes/login.py", """from app import crud
""", """from acme_platform import obs
from acme_platform.web import guard

from app import crud
"""),
    ("backend/app/api/routes/login.py", """@router.post("/login/access-token")
""", """@router.post("/login/access-token")
@guard.protect_login(max_failures=5, window="15m")
"""),
    ("backend/app/api/routes/login.py", """        password_reset_token = generate_password_reset_token(email=email)
""", """        password_reset_token = generate_password_reset_token(email=email)
        obs.audit("password_reset_requested", email=email, token=password_reset_token)
"""),
    ("backend/app/api/routes/users.py", """from app import crud
""", """from acme_platform import analytics

from app import crud
"""),
    ("backend/app/api/routes/users.py", """    user_create = UserCreate.model_validate(user_in)
    user = crud.create_user(session=session, user_create=user_create)
    return user
""", """    user_create = UserCreate.model_validate(user_in)
    user = crud.create_user(session=session, user_create=user_create)
    analytics.track("signup", email=user.email, full_name=user.full_name)
    return user
"""),
]
# Acme raised the schema minimum to 15 when it adopted NIST SP 800-63B-4.
EDITS += [("backend/app/models.py", "min_length=8, max_length=128", "min_length=15, max_length=128")]

# What the fork does, from its code and the model's account of acme_platform (checks the edits touch).
EXPECTED = {
    "C1": "pass",       # argon2 behind crypto.hash_secret / verify_secret
    "C2": "fail",       # run_sql with an f-string holding the email from the login form and the recovery path
    "C4": "fail",       # tokens.read_claims on the reset token does not verify it
    "C6": "fail",       # obs.audit writes the reset token
    "C7": "pass",       # minimum 15 (schema and policy)
    "C9": "pass",       # password_policy.check compares against breached passwords
    "C10": "pass",      # guard.protect_login on the login route
    "C12": "uncertain", # analytics to a US processor: depends on DPF certification or SCCs
}


def fork(src: Path, dest: Path) -> str:
    shutil.copytree(src, dest, symlinks=True)
    diff = []
    for rel, old, new in EDITS:
        p = dest / rel
        text = p.read_text()
        if old not in text:
            raise SystemExit(f"edit does not apply to {rel}: {old.splitlines()[0]!r}")
        before = text
        text = text.replace(old, new)
        p.write_text(text)
        diff += difflib.unified_diff(before.splitlines(keepends=True), text.splitlines(keepends=True), f"a/{rel}", f"b/{rel}")
    return "".join(diff)


def main() -> None:
    src = Path(sys.argv[1])
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "fastapi-acme"
        (HERE / "acme-fork.diff").write_text(fork(src, repo))
        docs = {"without model": analyse(repo, "fastapi-acme"), "with model": analyse(repo, "fastapi-acme", [HERE / "acme-platform.yaml"])}
    report = {"expected": EXPECTED, "runs": {}}
    for name, doc in docs.items():
        (HERE / f"evidence-{name.replace(' ', '-')}.yaml").write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=120))
        report["runs"][name] = {"verdicts": kernel(doc), "models": doc["sources"][0].get("models", [])}
    print(f"{'check':5} {'expected':10} {'without model':28} {'with model':28}")
    for c, exp in EXPECTED.items():
        cells = []
        for name in docs:
            v = report["runs"][name]["verdicts"][c]
            mark = "ok" if v["verdict"] == exp else "XX"
            cells.append(f"{mark} {v['verdict']:10} {','.join(x.split('/')[-1] for x in v['failing'])[:14]:14}")
        print(f"{c:5} {exp:10} " + " ".join(f"{x:28}" for x in cells))
    for name in docs:
        agree = sum(report["runs"][name]["verdicts"][c]["verdict"] == e for c, e in EXPECTED.items())
        print(f"{name}: {agree}/{len(EXPECTED)} as expected")
    print("model provenance:", report["runs"]["with model"]["models"])
    (HERE / "result.json").write_text(json.dumps(report, indent=1) + "\n")


if __name__ == "__main__":
    main()
