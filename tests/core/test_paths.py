from pathlib import Path

from core import paths


def test_base_dir_is_repo_root():
    assert (paths.BASE_DIR / "Home.py").exists()


def test_expected_dirs_are_absolute():
    for value in (paths.DATA_DIR, paths.RESOURCES_DIR, paths.LOGS_DIR, paths.PAGES_DIR):
        assert isinstance(value, Path)
        assert value.is_absolute()


def test_configure_locale_returns_str_or_none():
    result = paths.configure_locale()
    assert result is None or isinstance(result, str)
