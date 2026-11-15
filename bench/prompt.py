"""Render the prompt a model answering directly receives for a benchmark file.

uv run python bench/prompt.py bench/austin.yaml > bench/prompts/austin.md
"""

import re
import sys

import yaml

spec = yaml.safe_load(open(sys.argv[1]))
lines = [spec["preamble"].strip(), ""]
if spec.get("inputs"):
    lines += ["Project inputs (download them if you need them):", ""]
    lines += [f"- {i['what']}: {i['url']}" for i in spec["inputs"]]
    lines.append("")
lines += [
    "Research the official sources on the web as you see fit. Do not look for or read any local files.",
    "",
    "Questions:",
    "",
]
for q in spec["questions"]:
    lines.append(f"{q['id']}. {' '.join(q['ask'].split())} [unit: {q['unit']}]")
lines += [
    "",
    "Reply with only a JSON array, one object per question, in this form:",
    '[{"id": "<question id>", "answer": <number or null>, "unit": "<unit>", "citations": ["<section or table numbers you relied on>"], "confidence": <0 to 1>}, ...]',
    "`answer` is a number in the requested unit, or null if you cannot determine it.",
]
# Folded YAML puts spaces between Japanese sentences; drop them.
CJK = "\u3000-\u30ff\u3300-\u33ff\u4e00-\u9fff\uff00-\uffef"
print(re.sub(f"(?<=[{CJK}]) (?=[{CJK}])", "", "\n".join(lines)))
