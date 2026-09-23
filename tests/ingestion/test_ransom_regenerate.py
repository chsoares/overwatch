import pandas as pd

from tests.ingestion.test_ransom_classifier_optional import _bare_ingestor


def test_finalize_regenerated_data_adds_classification_columns():
    ingestor = _bare_ingestor()
    raw = pd.DataFrame(
        [
            {
                "post_title": "ACME",
                "country": "BR",
                "website": "",
                "group_name": "lockbit",
                "activity": "Finance",
                "published": "2023-05-01",
                "discovered": "2023-05-02",
                "screenshot": "",
                "post_url": "",
            }
        ]
    )

    result = ingestor._finalize_regenerated_data(raw)

    assert list(result.columns) == ingestor.columns
    assert result.loc[0, "activity_classified"] == "Financial Services"
    assert bool(result.loc[0, "used_fallback"]) is True
