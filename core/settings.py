"""Runtime settings for ingestion, backed by core.paths and environment variables.

Replaces the former config.yaml. No YAML file is read.
"""

import os

from core.paths import BASE_DIR, DATA_DIR, LOGS_DIR, RESOURCES_DIR

DEFAULT_OPENROUTER_MODEL = "google/gemini-2.5-flash-lite"

__all__ = [
    "BASE_DIR", "DATA_DIR", "LOGS_DIR", "RESOURCES_DIR",
    "nvd_api_key", "openrouter_api_key", "openrouter_base_url",
    "openrouter_model", "classifier_enabled",
]


def nvd_api_key():
    return os.getenv("NVD_API_KEY") or None


def openrouter_api_key():
    return os.getenv("OPENROUTER_API_KEY") or None


def openrouter_base_url():
    return os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")


def openrouter_model():
    return os.getenv("OPENROUTER_MODEL", DEFAULT_OPENROUTER_MODEL)


def classifier_enabled():
    """True only when an OpenRouter key is configured (classification is optional)."""
    return bool(openrouter_api_key())
