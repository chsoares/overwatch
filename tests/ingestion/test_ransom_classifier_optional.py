import pandas as pd

import scripts.ransom_dataset as ransom_dataset
from scripts.ransom_dataset import RansomIngestor

COLUMNS = [
    "post_title",
    "country",
    "website",
    "group_name",
    "activity",
    "activity_classified",
    "used_fallback",
    "published",
    "discovered",
    "screenshot",
    "post_url",
]


class _NullExtractor:
    def extract_content(self, url):
        return None


class _FakeExtractor:
    def __init__(self, content="ACME is a bank"):
        self.content = content

    def extract_content(self, url):
        return self.content


class _RecordingExtractor:
    def __init__(self):
        self.calls = []

    def extract_content(self, url):
        self.calls.append(url)
        return "ACME is a bank"


class _FakeApiClient:
    def __init__(self):
        self.total_cost = 0.0


class _FakeClassifier:
    def __init__(self, sectors_file):
        self.sectors_file = sectors_file
        self.api_client = _FakeApiClient()

    def classify_content(self, content, company_name=None):
        return "Financial Services"


def _bare_ingestor(extractor=None):
    ingestor = RansomIngestor.__new__(RansomIngestor)
    ingestor.classifier = None
    ingestor.extractor = extractor if extractor is not None else _NullExtractor()
    ingestor.sectors_mapping = {"Finance": "Financial Services"}
    ingestor.canonical_sectors = {"Financial Services"}
    ingestor.columns = list(COLUMNS)
    ingestor.classification_start_time = None
    ingestor.classification_total_time = 0.0
    ingestor.classification_total_cost = 0.0
    return ingestor


def test_init_enables_classifier_when_key_present(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setattr(ransom_dataset, "SectorClassifier", _FakeClassifier)

    ingestor = RansomIngestor()

    assert ingestor.classifier is not None
    assert isinstance(ingestor.classifier, _FakeClassifier)


def test_classify_sectors_uses_classifier_when_present():
    ingestor = _bare_ingestor(extractor=_FakeExtractor("ACME is a bank"))
    ingestor.classifier = _FakeClassifier(None)
    df = pd.DataFrame(
        [
            {
                "post_title": "ACME",
                "website": "acme.com",
                "activity": "Finance",
                "activity_classified": "",
                "used_fallback": False,
            }
        ]
    )

    result = ingestor.classify_sectors(df)

    assert result.loc[0, "activity_classified"] == "Financial Services"
    assert bool(result.loc[0, "used_fallback"]) is False


def test_classify_sectors_uses_fallback_without_classifier():
    ingestor = _bare_ingestor()
    df = pd.DataFrame(
        [
            {
                "post_title": "ACME",
                "website": "",
                "activity": "Finance",
                "activity_classified": "",
                "used_fallback": False,
            }
        ]
    )

    result = ingestor.classify_sectors(df)

    assert result.loc[0, "activity_classified"] == "Financial Services"
    assert bool(result.loc[0, "used_fallback"]) is True


def test_classify_sector_skips_extraction_when_classifier_disabled():
    extractor = _RecordingExtractor()
    ingestor = _bare_ingestor(extractor=extractor)

    classification, used_fallback = ingestor._classify_sector(
        pd.Series(
            {
                "post_title": "ACME",
                "website": "acme.com",
                "activity": "Finance",
            }
        )
    )

    assert classification == "Financial Services"
    assert used_fallback is True
    assert extractor.calls == []
