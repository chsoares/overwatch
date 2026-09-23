import pandas as pd
import pytest

from scripts.ransom_dataset import RansomIngestor

BASE_COLUMNS = [
    "post_title",
    "country",
    "website",
    "group_name",
    "activity",
    "published",
    "discovered",
    "screenshot",
    "post_url",
]

API_V2_COLUMN_MAPPING = {
    "victim": "post_title",
    "country": "country",
    "domain": "website",
    "group": "group_name",
    "activity": "activity",
    "attackdate": "published",
    "discovered": "discovered",
    "screenshot": "screenshot",
    "claim_url": "post_url",
}


def _bare_date_ingestor():
    ingestor = RansomIngestor.__new__(RansomIngestor)
    ingestor.base_columns = list(BASE_COLUMNS)
    ingestor.columns = list(BASE_COLUMNS)
    ingestor.valid_iso2_codes = {"BR", "US"}
    ingestor.api_v2_column_mapping = dict(API_V2_COLUMN_MAPPING)
    return ingestor


def _api_v2_frame():
    """DataFrame with the exact shape returned by api.ransomware.live v2."""
    return pd.DataFrame(
        [
            {
                "victim": "Old Co",
                "country": "BR",
                "domain": "old.com",
                "group": "lockbit",
                "activity": "Finance",
                "attackdate": "2022-05-01T10:00:00.000000+00:00",
                "discovered": "2022-05-02T10:00:00.000000+00:00",
                "screenshot": "",
                "claim_url": "",
            },
            {
                "victim": "New Co",
                "country": "US",
                "domain": "new.com",
                "group": "lockbit",
                "activity": "Finance",
                "attackdate": "2024-05-01T10:00:00.000000+00:00",
                "discovered": "2024-05-02T10:00:00.000000+00:00",
                "screenshot": "",
                "claim_url": "",
            },
            {
                "victim": "Null Date Co",
                "country": "US",
                "domain": "nulldate.com",
                "group": "lockbit",
                "activity": "Finance",
                "attackdate": "",
                "discovered": None,
                "screenshot": "",
                "claim_url": "",
            },
        ]
    )


def test_to_naive_utc_drops_offset_and_keeps_naive():
    ingestor = _bare_date_ingestor()

    aware = ingestor._to_naive_utc(
        pd.Series(["2026-02-28T21:02:36.060651+00:00"])
    )
    naive = ingestor._to_naive_utc(pd.Series(["2024-05-01T10:00:00"]))

    assert aware.dt.tz is None
    assert naive.dt.tz is None
    assert aware.dt.strftime("%Y-%m-%d %H:%M:%S").tolist() == [
        "2026-02-28 21:02:36"
    ]
    assert naive.dt.strftime("%Y-%m-%d %H:%M:%S").tolist() == [
        "2024-05-01 10:00:00"
    ]


def test_process_victims_data_returns_naive_datetimes_without_raising():
    ingestor = _bare_date_ingestor()
    raw = ingestor._transform_api_v2_response(_api_v2_frame())

    result = ingestor.process_victims_data(raw)

    assert result["published"].dt.tz is None
    assert result["discovered"].dt.tz is None


def test_process_victims_data_applies_2023_cutoff():
    ingestor = _bare_date_ingestor()
    raw = ingestor._transform_api_v2_response(_api_v2_frame())

    result = ingestor.process_victims_data(raw)

    titles = set(result["post_title"])
    assert "New Co" in titles
    assert "Old Co" not in titles


def test_process_victims_data_drops_null_dates_without_raising():
    ingestor = _bare_date_ingestor()
    raw = ingestor._transform_api_v2_response(_api_v2_frame())

    result = ingestor.process_victims_data(raw)

    assert "Null Date Co" not in set(result["post_title"])
    assert result["published"].notna().all()
    assert result["discovered"].notna().all()
