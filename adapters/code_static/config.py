"""Configuration files, key files, and templates: secrets, client-side password rules, embedded trackers."""

from __future__ import annotations

import json
import re

import yaml
from normir.model import YAMLInputError, read_yaml

from .common import (Collector, TRACKER_HOSTS, analyse_password_regex, literal_secret_kind, plausible_secret_value,
                     secret_kind_for_name)
from .files import SourceFile

ENV_LINE = re.compile(r"^\s*(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)\s*[=:]\s*(?P<value>.*?)\s*$")
INPUT_TAG = re.compile(r"<input\b[^>]*>", re.I | re.S)
SCRIPT_SRC = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"'](?P<src>[^\"']+)[\"']", re.I)


def _secret(out: Collector, sf: SourceFile, line: int, key: str, value: str):
    value = value.strip().strip("\"'")
    kind = literal_secret_kind(value) or secret_kind_for_name(key)
    if kind and plausible_secret_value(value, kind):
        out.element("Secret", f"{sf.rel}:{line}", kind=kind, test_or_example=True if sf.example else None)


def _yaml_walk(node, out: Collector, sf: SourceFile, key: str = ""):
    if isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            name = k.value if isinstance(k, yaml.ScalarNode) else ""
            _yaml_walk(v, out, sf, str(name))
    elif isinstance(node, yaml.SequenceNode):
        for v in node.value:
            _yaml_walk(v, out, sf, key)
    elif isinstance(node, yaml.ScalarNode) and isinstance(node.value, str):
        _secret(out, sf, node.start_mark.line + 1, key, node.value)


def scan_config(sf: SourceFile, text: str, out: Collector):
    low = sf.rel.rsplit("/", 1)[-1].lower()
    if low.endswith((".yml", ".yaml", ".json")):
        try:
            docs = read_yaml(text, compose=True)  # bounded: deep nesting or alias bombs are not configuration
        except YAMLInputError:
            docs = None
        if docs is not None:
            for d in docs:
                if d is not None:
                    _yaml_walk(d, out, sf)
            return
        if low.endswith(".json"):
            try:
                json.loads(text)
            except (ValueError, RecursionError):
                return
    # .env, .ini, .properties, .toml, .conf, and JSON that YAML cannot read: one key per line
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("#", ";", "//", "[")):
            continue
        m = ENV_LINE.match(line)
        if m:
            _secret(out, sf, i, m["key"], m["value"].split(" #")[0])
        else:
            for lit in re.findall(r"[\"']([^\"']{8,})[\"']", line):
                kind = literal_secret_kind(lit)
                if kind:
                    out.element("Secret", f"{sf.rel}:{i}", kind=kind, test_or_example=True if sf.example else None)


def scan_key_file(sf: SourceFile, text: str, out: Collector):
    for i, line in enumerate(text.splitlines(), 1):
        if re.search(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----", line):
            out.element("Secret", f"{sf.rel}:{i}", kind="private_key", test_or_example=True if sf.example else None)


def _attr(tag: str, name: str) -> str | None:
    m = re.search(r"[\s\[]" + name + r"\]?\s*=\s*[\"']([^\"']*)[\"']", tag, re.I)
    return m.group(1) if m else None


def scan_template(sf: SourceFile, text: str, out: Collector):
    """Password inputs with length or pattern rules (enforced in the browser), and third-party scripts."""
    starts = [0]
    for m in re.finditer("\n", text):
        starts.append(m.end())

    def line_of(pos: int) -> int:
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    for m in INPUT_TAG.finditer(text):
        tag = m.group(0)
        typ = (_attr(tag, "type") or "").lower()
        ident = " ".join(filter(None, (_attr(tag, "name"), _attr(tag, "id"), _attr(tag, "formControlName"))))
        if typ != "password" and not re.search(r"pass", ident, re.I):
            continue
        if re.search(r"confirm|repeat|verify|current|old", ident, re.I):
            continue
        at = f"{sf.rel}:{line_of(m.start())}"
        mn, mx, pat = _attr(tag, "minlength"), _attr(tag, "maxlength"), _attr(tag, "pattern")
        if mn and mn.isdigit():
            out.signal("pw_min", at, int(mn), side="client")
            out.signal("pw_validation", at, side="client")
        if mx and mx.isdigit():
            out.signal("pw_max", at, int(mx), side="client")
            out.signal("pw_validation", at, side="client")
        if pat:
            r = analyse_password_regex(pat)
            if "min" in r:
                out.signal("pw_min", at, r["min"], side="client")
            if "max" in r:
                out.signal("pw_max", at, r["max"], side="client")
            if r.get("composition"):
                out.signal("pw_composition", at, side="client")
            out.signal("pw_validation", at, side="client")
    for m in SCRIPT_SRC.finditer(text):
        src = m.group("src")
        for host, name in TRACKER_HOSTS.items():
            if re.search(r"(^|//|\.)" + re.escape(host) + r"(/|$)", src):
                out.element("Transfer", f"{sf.rel}:{line_of(m.start())}", recipient=name)
