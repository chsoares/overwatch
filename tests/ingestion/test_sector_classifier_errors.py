import types

import pytest

from scripts import sector_classifier as sc


class _Resp:
    def __init__(self, status):
        self.status_code = status
    def raise_for_status(self):
        if self.status_code >= 400:
            raise AssertionError("raise_for_status should not be reached for handled codes")
    def json(self):
        return {"choices": [{"message": {"content": "ok"}}]}


def _client(monkeypatch, status):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test")
    client = sc.OpenRouterClient()
    monkeypatch.setattr(sc.requests, "post", lambda *a, **k: _Resp(status))
    monkeypatch.setattr(sc, "sleep", lambda *_: None)
    return client


def test_404_model_not_found_is_systemic(monkeypatch):
    client = _client(monkeypatch, 404)
    with pytest.raises(sc.SystemicClassifierError):
        client.call_api("prompt")


def test_401_invalid_key_is_systemic(monkeypatch):
    client = _client(monkeypatch, 401)
    with pytest.raises(sc.SystemicClassifierError):
        client.call_api("prompt")


def test_model_defaults_to_available_gemini(monkeypatch):
    monkeypatch.delenv("OPENROUTER_MODEL", raising=False)
    monkeypatch.setenv("OPENROUTER_API_KEY", "test")
    assert sc.OpenRouterClient().model == "google/gemini-2.5-flash-lite"
