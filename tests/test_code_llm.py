"""The model reader with the provider mocked: locators and values are verified, system facts are settled."""

import json

import httpx
import pytest

from adapters.code_llm import ReaderError, analyse, parse_json
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
    with pytest.raises(ReaderError, match="no model provider"):
        analyse(write(tmp_path / "repo", APP))


def test_parse_json_takes_fenced_or_bare_objects():
    assert parse_json('Here:\n```json\n{"a": 1}\n```\nDone') == {"a": 1}
    assert parse_json('prefix {"a": {"b": 2}} suffix') == {"a": {"b": 2}}
    with pytest.raises(ReaderError):
        parse_json("no json here")
