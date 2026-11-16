"""The model reader with the provider mocked: locators and values are verified, system facts are settled."""

import json

import httpx
import pytest

from adapters.code_llm import ReaderError, analyse, parse_json, provider_from_env
from normir.evidence import load_evidence

APP = {
    "app/controllers/sessions_controller.rb": "class SessionsController < ApplicationController\n"
                                              "  def create\n"
                                              "    User.where(\"email = '#{params[:email]}'\").first\n"
                                              "  end\n"
                                              "end\n",
    "config/environments/production.rb": "Rails.application.configure do\n  config.force_ssl = true\nend\n",
}


def fake(replies):
    """A transport answering Anthropic-style calls from a list, recording the prompts it was sent."""
    sent = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        sent.append(body)
        text = replies[min(len(sent), len(replies)) - 1]
        return httpx.Response(200, json={"content": [{"type": "text", "text": text}]})
    return httpx.MockTransport(handler), sent


def write(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp_path


def test_reader_verifies_locators_and_values(tmp_path):
    root = write(tmp_path / "repo", APP)
    read = json.dumps({"elements": [
        {"type": "Query", "at": "app/controllers/sessions_controller.rb:3", "facts": {"construction": "interpolated", "untrusted_input": True}},
        {"type": "Query", "at": "app/controllers/sessions_controller.rb:99", "facts": {"construction": "orm"}},   # no such line
        {"type": "Query", "at": "app/models/ghost.rb:1", "facts": {"construction": "orm"}},                      # no such file
        {"type": "Cookie", "at": "config/environments/production.rb:2", "facts": {"same_site": "sometimes"}},    # bad value only
        {"type": "Rocket", "at": "config/environments/production.rb:2", "facts": {}},                           # unknown type
    ], "system": [{"fact": "tls_enforced", "value": True, "at": ["config/environments/production.rb:2"]}]})
    settled = "```json\n" + json.dumps({"system": [
        {"fact": "tls_enforced", "value": True, "at": ["config/environments/production.rb:2"]},
        {"fact": "hsts_max_age", "value": "two years"},   # not a number
    ]}) + "\n```"
    transport, sent = fake([read, settled])
    doc = analyse(root, "demo", provider=("anthropic", "test-model", "k"), transport=transport, workers=1)
    assert [(e["type"], e["at"]) for e in doc["elements"]] == [("Query", "app/controllers/sessions_controller.rb:3")]
    assert doc["facts"] == {"tls_enforced": [{"value": True, "at": "config/environments/production.rb:2", "source": "llm:test-model"}]}
    src = doc["sources"][0]
    assert src["dropped"] == {"locator does not exist": 2, "fact outside the vocabulary": 2, "unknown element type": 1}
    assert src["files_sent"] == 2 and src["batches"] == 1
    # the repository text reaches the model with line numbers, and the settle call sees the cited line
    assert "    3      User.where" in sent[0]["messages"][0]["content"]
    assert "config.force_ssl = true" in sent[1]["messages"][0]["content"]
    ev = load_evidence(doc)
    assert ev.elements[0].facts["construction"].values() == ["interpolated"]


def test_every_failed_call_is_an_error(tmp_path):
    root = write(tmp_path / "repo", APP)
    transport = httpx.MockTransport(lambda r: httpx.Response(401, json={"error": "bad key"}))
    with pytest.raises(ReaderError, match="401"):
        analyse(root, provider=("anthropic", "m", "k"), transport=transport, workers=1)


def test_no_provider_is_an_error(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "no-codex"))
    with pytest.raises(ReaderError, match="no model provider"):
        analyse(write(tmp_path / "repo", APP))


FAKE_CODEX = """#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
stdin = sys.stdin.read()
log = os.environ["FAKE_CODEX_LOG"]
calls = json.load(open(log)) if os.path.exists(log) else []
calls.append({"args": args, "cwd": os.getcwd(), "stdin": stdin})
json.dump(calls, open(log, "w"))
replies = json.load(open(os.environ["FAKE_CODEX_REPLIES"]))
open(args[args.index("-o") + 1], "w").write(replies[min(len(calls), len(replies)) - 1])
"""


def test_codex_cli_reader_on_its_own_sign_in(tmp_path, monkeypatch):
    """Without API keys, a signed-in Codex CLI is the provider: each call is a `codex exec` in an empty directory
    with a read-only sandbox and nothing saved, the instructions and source text on stdin, the reply read from -o."""
    root = write(tmp_path / "repo", APP)
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "codex").write_text(FAKE_CODEX)
    (bin_ / "codex").chmod(0o755)
    home = tmp_path / "codex-home"
    home.mkdir()
    (home / "auth.json").write_text("{}")
    read = json.dumps({"elements": [{"type": "Query", "at": "app/controllers/sessions_controller.rb:3",
                                     "facts": {"construction": "interpolated"}}],
                       "system": [{"fact": "tls_enforced", "value": True, "at": ["config/environments/production.rb:2"]}]})
    settled = json.dumps({"system": [{"fact": "tls_enforced", "value": True, "at": ["config/environments/production.rb:2"]}]})
    (tmp_path / "replies.json").write_text(json.dumps([read, settled]))
    for k, v in {"PATH": f"{bin_}:{__import__('os').environ['PATH']}", "CODEX_HOME": str(home),
                 "FAKE_CODEX_LOG": str(tmp_path / "calls.json"), "FAKE_CODEX_REPLIES": str(tmp_path / "replies.json")}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("NORMIR_LLM_PROVIDER", "codex")   # chosen over a key that is also set
    monkeypatch.delenv("NORMIR_LLM_MODEL", raising=False)
    assert provider_from_env() == ("codex", "gpt-6.1-sol", "")
    doc = analyse(root, "demo", workers=1)
    assert [(e["type"], e["at"]) for e in doc["elements"]] == [("Query", "app/controllers/sessions_controller.rb:3")]
    assert doc["facts"]["tls_enforced"][0]["source"] == "llm:gpt-6.1-sol"
    calls = json.loads((tmp_path / "calls.json").read_text())
    assert len(calls) == 2
    for c in calls:
        a = c["args"]
        assert a[0] == "exec" and a[-1] == "-" and "--ephemeral" in a and "--ignore-user-config" in a
        assert a[a.index("--sandbox") + 1] == "read-only" and a[a.index("-m") + 1] == "gpt-6.1-sol"
        assert a[a.index("-C") + 1] == c["cwd"] and str(root) not in c["cwd"]   # an empty directory, not the repository
    assert "    3      User.where" in calls[0]["stdin"] and calls[0]["stdin"].startswith("You are used as a reader only")
    monkeypatch.delenv("NORMIR_LLM_PROVIDER")
    assert provider_from_env()[0] == "openai"   # a key wins when no provider is named
    monkeypatch.delenv("OPENAI_API_KEY")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert provider_from_env()[0] == "codex"    # the sign-in alone is enough


def test_parse_json_takes_fenced_or_bare_objects():
    assert parse_json('Here:\n```json\n{"a": 1}\n```\nDone') == {"a": 1}
    assert parse_json('prefix {"a": {"b": 2}} suffix') == {"a": {"b": 2}}
    with pytest.raises(ReaderError):
        parse_json("no json here")
