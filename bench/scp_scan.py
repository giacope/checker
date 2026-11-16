"""Scan a pinned checkout against the compiled OWASP Secure Coding Practices regulation, as the app does.

uv run python bench/scp_scan.py <checkout> <owner/name> <out.json>

Runs app.scan.collect (static adapters, dependency check, the model reader, then the model assessor on the
regulation's requirements, adapters.regulation.requirements) and writes {repo, docs, notes}. bench/scp_check.py
grades the result. Needs a model provider (the Codex sign-in); assessed answers are cached under NORMIR_DATA.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapters.code_static import git_commit  # noqa: E402
from adapters.regulation import requirements  # noqa: E402
from app.scan import collect  # noqa: E402


def main() -> None:
    root, name, out = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    reg = json.loads((ROOT / "bench" / "scp" / "regulation.json").read_text())
    started = time.time()
    docs, notes = collect(root, name, requirements=requirements(reg), progress=lambda m: print(m, flush=True))
    owner, repo = name.split("/", 1)
    out.write_text(json.dumps({"repo": {"url": f"https://github.com/{name}", "owner": owner, "name": repo, "commit": git_commit(root)},
                               "docs": docs, "notes": notes, "seconds": round(time.time() - started, 1)}, ensure_ascii=False) + "\n")
    print(f"-> {out} in {time.time() - started:.0f} s")


if __name__ == "__main__":
    main()
