"""uv run python -m adapters.code_llm <repo-path> -o <out.yaml>   (needs ANTHROPIC_API_KEY or OPENAI_API_KEY)"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from . import ReaderError, analyse


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m adapters.code_llm", description=__doc__)
    ap.add_argument("repo", help="path to the repository to read (nothing in it is executed)")
    ap.add_argument("-o", "--out", help="evidence YAML to write (default: stdout)")
    ap.add_argument("--name", help="subject id (default: the repository directory name)")
    a = ap.parse_args(argv)
    if not Path(a.repo).is_dir():
        ap.error(f"not a directory: {a.repo}")
    try:
        doc = analyse(a.repo, a.name, progress=lambda m: print(m, file=sys.stderr))
    except ReaderError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    text = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=120)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
