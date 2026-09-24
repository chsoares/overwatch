import json
from pathlib import Path

import pandas as pd

from scripts.ransom_dataset import FALLBACK_SECTOR, RansomIngestor

REPO_ROOT = Path(__file__).resolve().parents[2]
SECTORS_FILE = REPO_ROOT / "resources" / "sectors.json"
MAPPING_FILE = REPO_ROOT / "resources" / "sectors_mapping.json"
DATASET_FILE = REPO_ROOT / "data" / "ransom_dataset.csv"

PREVIOUSLY_LEAKING_LABELS = [
    "Professional Services",
    "Retail & E-Commerce",
    "Government & Defense",
    "Other",
    "Transportation",
    "Hospitality",
    "Energy & Utilities",
    "Healtcare",
    "Manufacturer",
    "Food and Agriculture",
    "Automotive Industry",
    "Sports",
]


def _load_canonical_sectors():
    with open(SECTORS_FILE, "r", encoding="utf-8") as f:
        return set(json.load(f).keys())


def _bare_ingestor(mapping=None, canonical=None):
    ingestor = RansomIngestor.__new__(RansomIngestor)
    if mapping is None:
        with open(MAPPING_FILE, "r", encoding="utf-8") as f:
            mapping = json.load(f)
    ingestor.sectors_mapping = mapping
    ingestor.canonical_sectors = (
        canonical if canonical is not None else _load_canonical_sectors()
    )
    return ingestor


def test_map_sector_never_leaks_off_taxonomy_values():
    canonical = _load_canonical_sectors()
    ingestor = _bare_ingestor(canonical=canonical)

    for label in PREVIOUSLY_LEAKING_LABELS:
        mapped = ingestor._map_sector(label)
        assert mapped in canonical, f"{label!r} mapeou para {mapped!r} (fora da taxonomia)"


def test_map_sector_unknown_label_uses_canonical_fallback():
    canonical = _load_canonical_sectors()
    ingestor = _bare_ingestor(canonical=canonical)

    mapped = ingestor._map_sector("Quantum Widgets Inc.")

    assert mapped in canonical
    assert mapped != "Quantum Widgets Inc."
    assert mapped == FALLBACK_SECTOR


def test_map_sector_off_taxonomy_mapping_target_uses_fallback():
    ingestor = _bare_ingestor(
        mapping={"Ghost Source": "Ghost Sector"},
        canonical={"Financial Services"},
    )

    assert ingestor._map_sector("Ghost Source") == FALLBACK_SECTOR


def test_map_sector_not_found_behavior_unchanged():
    ingestor = _bare_ingestor()

    assert ingestor._map_sector("Not Found") == "Not Found"
    assert ingestor._map_sector("") == "Not Found"
    assert ingestor._map_sector(None) == "Not Found"


def test_dataset_activity_classified_is_within_canonical_taxonomy():
    canonical = _load_canonical_sectors()
    df = pd.read_csv(DATASET_FILE)
    values = set(df["activity_classified"].dropna().unique())
    off_taxonomy = values - canonical - {"Not Found"}

    assert not off_taxonomy, f"Valores fora da taxonomia no dataset: {sorted(off_taxonomy)}"
