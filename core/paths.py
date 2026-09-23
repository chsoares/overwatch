"""Filesystem constants and locale setup for the application and ingestion."""

import locale
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RESOURCES_DIR = BASE_DIR / "resources"
LOGS_DIR = BASE_DIR / "logs"
PAGES_DIR = BASE_DIR / "pages"

_LOCALES = ("pt_BR.UTF-8", "Portuguese_Brazil.1252")


def configure_locale():
    """Set the primary available pt-BR locale. Returns the name used or None."""
    for name in _LOCALES:
        try:
            locale.setlocale(locale.LC_ALL, name)
            return name
        except locale.Error:
            continue
    return None
