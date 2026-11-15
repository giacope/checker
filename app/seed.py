"""Create the example building projects from app/seeds.yaml, through the same pipeline as an upload.

    uv run python -m app.seed                 # every seed not yet processed
    uv run python -m app.seed --only clinic   # one seed
    uv run python -m app.seed --refresh       # process again, replacing the earlier project

Files come from their publishers (verified against the manifest's sha256) or from a local copy under
NORMIR_SEED_INPUTS that has the same hash. Nothing is precomputed: the adapters read the files.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import zipfile
from pathlib import Path

import httpx
import yaml

HERE = Path(__file__).parent
MANIFEST = HERE / "seeds.yaml"
CACHE = Path(os.environ.get("NORMIR_SEED_CACHE", Path.home() / ".cache" / "normir" / "seeds"))
INPUTS = Path(os.environ.get("NORMIR_SEED_INPUTS", HERE.parent / ".amp" / "in" / "orb-backup" / "inputs"))


class SeedError(Exception):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(spec: dict, log=print) -> Path:
    """The publisher's file, verified: a local copy with the right hash, the cache, or a download."""
    want = spec["sha256"]
    if spec.get("local"):
        local = INPUTS / spec["local"]
        if local.is_file() and _sha256(local) == want:
            return local
    cached = CACHE / want
    if cached.is_file():
        return cached
    CACHE.mkdir(parents=True, exist_ok=True)
    log(f"Downloading {spec['url']}")
    tmp = CACHE / f".{want}.part"
    with httpx.stream("GET", spec["url"], follow_redirects=True, timeout=120) as r:
        r.raise_for_status()
        with open(tmp, "wb") as f:
            for chunk in r.iter_bytes(1 << 20):
                f.write(chunk)
    got = _sha256(tmp)
    if got != want:
        tmp.unlink()
        raise SeedError(f"{spec['url']}: sha256 {got} does not match the manifest ({want}); the publisher changed the file.")
    tmp.replace(cached)
    return cached


def place(spec: dict, files_dir: Path, log=print) -> str:
    """Copy one manifest file (or one zip member) into a project's files folder; returns its name there."""
    src = fetch(spec, log)
    if spec.get("member"):
        name = Path(spec["member"]).name
        with zipfile.ZipFile(src) as zf, zf.open(spec["member"]) as m, open(files_dir / name, "wb") as out:
            shutil.copyfileobj(m, out, 1 << 20)
    else:
        name = spec.get("name") or Path(spec["url"].split("?")[0]).name
        shutil.copyfile(src, files_dir / name)
    return name


def seed(key: str, spec: dict, refresh: bool = False, log=print) -> str | None:
    from . import main
    existing = [p for p in main._projects(seeded=True, limit=1000) if p.get("seed") == key]
    if existing and not refresh and existing[0]["state"] == "done":
        log(f"{key}: already processed as project {existing[0]['id']}")
        return existing[0]["id"]
    for p in existing:
        shutil.rmtree(main.PROJECTS / p["id"], ignore_errors=True)
    pid, d = main.new_project(spec["name"], spec["codes"], seed=key)
    req = main._read(d, "request.json")
    req.update(source=spec.get("source"), licence=" ".join(str(spec.get("licence", "")).split()))
    main._write(d, "request.json", req)
    for f in spec["files"]:
        log(f"{key}: {place(f, d / 'files', log)}")
    log(f"{key}: processing as project {pid}")
    main.run_project(pid)
    st = main._read(d, "status.json", {})
    log(f"{key}: {st.get('state')} {st.get('error') or ''} ({st.get('seconds', '?')} s)")
    return pid


def seed_all(only: list[str] | None = None, refresh: bool = False, log=print) -> list[str]:
    manifest = yaml.safe_load(MANIFEST.read_text())
    out = []
    for key, spec in manifest.items():
        if only and key not in only:
            continue
        try:
            out.append(seed(key, spec, refresh, log))
        except (SeedError, httpx.HTTPError, OSError, zipfile.BadZipFile) as e:
            log(f"{key}: not seeded: {e}")
    return out


def main_cli() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--only", action="append")
    p.add_argument("--refresh", action="store_true")
    a = p.parse_args()
    seed_all(a.only, a.refresh, log=lambda m: print(m, file=sys.stderr, flush=True))


if __name__ == "__main__":
    main_cli()
