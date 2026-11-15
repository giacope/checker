"""uv run python -m adapters.code_elixir <repo-path> -o <out.yaml>"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from . import analyse


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m adapters.code_elixir", description=__doc__)
    ap.add_argument("repo", help="path to the Elixir repository to analyse (read only; nothing in it is executed)")
    ap.add_argument("-o", "--out", help="evidence YAML to write (default: stdout)")
    ap.add_argument("--name", help="subject id (default: the repository directory name)")
    ap.add_argument("--models", action="append", default=[], metavar="PATH",
                    help="framework model file or directory (YAML, language: elixir; see adapters/code_static/models.py); repeatable")
    a = ap.parse_args(argv)
    if not Path(a.repo).is_dir():
        ap.error(f"not a directory: {a.repo}")
    doc = analyse(a.repo, a.name, a.models)
    text = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=120)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
