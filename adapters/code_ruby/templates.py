"""Templates (ERB, HAML, Slim), Rails YAML configuration, and key files.

The Ruby inside a template is parsed with the same grammar as application code: for ERB, the code of every tag is
laid over blank text at its original line and column (so locators stay exact and tags share locals), with `;` where
each tag closes; HAML and Slim code is parsed one line at a time. Unescaped output tags (`<%== %>`, HAML `!=`, Slim
`==`) are recorded so the analyser can report what they write.
"""

from __future__ import annotations

import re

import yaml

from adapters.code_static.common import Collector, literal_secret_kind, plausible_secret_value, secret_kind_for_name
from adapters.code_static.config import scan_config, scan_key_file
from adapters.code_static.files import SourceFile

from .rb import RbFile

ERB_TAG = re.compile(r"<%(?!%)(?P<kind>==|=|-|#)?(?P<code>.*?)-?%>", re.S)
HAML_CODE = re.compile(r"^(?P<lead>\s*(?:[%.#][\w\-.#%:]*(?:\{[^}]*\}|\([^)]*\)|\[[^\]]*\])*)?\s*)(?P<op>!=|&=|=|~|-)(?!=)\s?(?P<code>.*)$")
SLIM_CODE = re.compile(r"^(?P<lead>\s*(?:[a-z][\w\-:]*|[.#][\w\-]+)*(?:\[[^\]]*\]|\([^)]*\)|\{[^}]*\})*\s*)(?P<op>==|=|-)(?P<code>(?!=).*)$")
TEST_SECTIONS = {"development", "test", "dev", "testing", "ci", "local", "example", "sample", "demo"}


class TemplateRuby(RbFile):
    """Ruby from a template; `unescaped` holds byte ranges of code written without HTML escaping."""

    def __init__(self, sf, src, tree, line_offset=0, unescaped=()):
        super().__init__(sf, src, tree, line_offset)
        self.unescaped = list(unescaped)


def template_ruby(sf: SourceFile, text: str, parser) -> list[RbFile]:
    low = sf.rel.lower()
    if low.endswith(".erb"):
        return [_erb(sf, text, parser)]
    if low.endswith((".haml", ".slim")):
        return _per_line(sf, text, parser, HAML_CODE if low.endswith(".haml") else SLIM_CODE,
                         {"!="} if low.endswith(".haml") else {"=="})
    return []


def _erb(sf: SourceFile, text: str, parser) -> RbFile:
    shadow = [c if c == "\n" else " " for c in text]
    regions = []
    for m in ERB_TAG.finditer(text):
        kind = m.group("kind") or ""
        if kind == "#":
            continue
        s, e = m.start("code"), m.end("code")
        for i in range(s, e):
            shadow[i] = text[i]
        close = text.rfind("%>", s, m.end())
        if close >= 0:
            shadow[close if text[close - 1] != "-" else close - 1] = ";"
        if kind == "==":
            regions.append((s, e))
    src = "".join(shadow)
    data = src.encode("utf-8")
    offsets = []
    for s, e in regions:
        offsets.append((len(src[:s].encode("utf-8")), len(src[:e].encode("utf-8"))))
    return TemplateRuby(sf, src, parser.parse(data), 0, offsets)


def _per_line(sf: SourceFile, text: str, parser, pattern, unescaped_ops: set[str]) -> list[RbFile]:
    out = []
    for i, ln in enumerate(text.splitlines()):
        m = pattern.match(ln)
        if not m or not m.group("code").strip():
            continue
        code = m.group("code")
        src = " " * len(m.group("lead") + m.group("op")) + code
        tree = parser.parse(src.encode("utf-8"))
        if tree.root_node.has_error:
            tree = parser.parse((src + "\nend").encode("utf-8"))
        start = len(src[: len(src) - len(code)].encode("utf-8"))
        regions = [(start, len(src.encode("utf-8")))] if m.group("op") in unescaped_ops else []
        out.append(TemplateRuby(sf, src, tree, i, regions))
    return out


# ------------------------------------------------------------------ configuration

def _erb_blank(text: str) -> str:
    """Rails YAML is ERB first: `<%= ... %>` becomes a same-length placeholder, `<% ... %>` blank space."""
    def sub(m):
        s = m.group(0)
        if s.startswith("<%=") and "\n" not in s:
            return "x" * len(s)  # an ERB value: never a literal secret
        return re.sub(r"[^\n]", " ", s)
    return re.sub(r"<%.*?%>", sub, text, flags=re.S)


def scan_config_file(sf: SourceFile, text: str, out: Collector):
    low = sf.rel.rsplit("/", 1)[-1].lower()
    if not low.endswith((".yml", ".yaml")):
        scan_config(sf, text, out)
        return
    try:
        docs = list(yaml.compose_all(_erb_blank(text), Loader=yaml.SafeLoader))
    except yaml.YAMLError:
        scan_config(sf, text, out)
        return
    for d in docs:
        if d is not None:
            _walk(d, sf, out, "", sf.example)


def _walk(node, sf: SourceFile, out: Collector, key: str, test: bool, depth: int = 0):
    if isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            name = str(k.value) if isinstance(k, yaml.ScalarNode) else ""
            _walk(v, sf, out, name, test or (depth == 0 and name.lower() in TEST_SECTIONS), depth + 1)
    elif isinstance(node, yaml.SequenceNode):
        for v in node.value:
            _walk(v, sf, out, key, test, depth + 1)
    elif isinstance(node, yaml.ScalarNode) and isinstance(node.value, str):
        value = node.value.strip()
        kind = literal_secret_kind(value) or secret_kind_for_name(key)
        if kind and plausible_secret_value(value, kind):
            out.element("Secret", f"{sf.rel}:{node.start_mark.line + 1}", kind=kind, test_or_example=True if test else None)


def scan_key(sf: SourceFile, text: str, out: Collector):
    """config/master.key (or config/credentials/<env>.key) committed: the key that decrypts the credentials file."""
    m = re.search(r"(^|/)config/(master|credentials/(?P<env>[\w\-]+))\.key$", sf.rel)
    if m and re.fullmatch(r"\s*[0-9a-fA-F]{32,128}\s*", text):
        env = (m.group("env") or "").lower()
        out.element("Secret", f"{sf.rel}:1", kind="private_key",
                    test_or_example=True if sf.example or env in {"development", "test"} else None)
        return
    scan_key_file(sf, text, out)
