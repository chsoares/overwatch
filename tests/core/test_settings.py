from pathlib import Path

from core import settings


def test_paths_point_into_repo():
    assert settings.DATA_DIR.is_absolute()
    assert (settings.DATA_DIR.parent / "Home.py").exists()
    assert settings.RESOURCES_DIR.name == "resources"


def test_env_defaults(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert settings.nvd_api_key() is None
    assert settings.openrouter_api_key() is None
    assert settings.classifier_enabled() is False


def test_classifier_enabled_with_key(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "x")
    assert settings.classifier_enabled() is True
