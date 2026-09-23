import importlib

import pytest

from core.paths import BASE_DIR

SCRIPTS = [
    "scripts.ransom_dataset",
    "scripts.vuln_dataset",
    "scripts.mailsec",
    "scripts.mailsec_dnssec",
    "scripts.mailsec_tester",
    "scripts.sector_classifier",
    "scripts.web_extractor",
]


@pytest.mark.parametrize("name", SCRIPTS)
def test_script_imports(name):
    importlib.import_module(name)


def test_no_load_config_references():
    for path in (BASE_DIR / "scripts").glob("*.py"):
        assert "load_config" not in path.read_text(encoding="utf-8"), path
