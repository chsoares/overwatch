import pandas as pd

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


def test_parse_api_datetime_handles_mixed_object_column():
    """Reproduce the exact mixed object column produced by pd.read_json.

    Some elements are already Timestamps, others are ISO strings with an
    offset, and some are None/empty. The old code fed this straight to
    pd.to_datetime without a format, which inferred the format from the
    first element and coerced the rest to NaT.
    """
    mixed = pd.Series(
        [
            pd.Timestamp("2026-09-11 00:00:00"),
            "2026-03-31T19:18:14.446162+00:00",
            "2026-09-23T11:30:00+00:00",
            None,
            "",
        ],
        dtype=object,
    )
    ingestor = _bare_date_ingestor()

    parsed = ingestor._parse_api_datetime(mixed)

    # Only None/empty are NaT; every valid element must parse.
    assert parsed.isna().sum() == 2
    assert parsed.iloc[0] == pd.Timestamp("2026-09-11 00:00:00", tz="UTC")
    assert parsed.iloc[1] == pd.Timestamp("2026-03-31 19:18:14.446162", tz="UTC")
    assert parsed.iloc[2] == pd.Timestamp("2026-09-23 11:30:00", tz="UTC")


def test_parse_api_datetime_roundtrips_both_shapes():
    ingestor = _bare_date_ingestor()

    parsed = ingestor._parse_api_datetime(
        pd.Series(
            [
                "2026-09-11 00:00:00.000000",
                "2026-03-31T19:18:14.446162+00:00",
            ],
            dtype=object,
        )
    )

    naive = parsed.dt.tz_localize(None)
    assert naive.tolist() == [
        pd.Timestamp("2026-09-11 00:00:00"),
        pd.Timestamp("2026-03-31 19:18:14.446162"),
    ]


def test_to_naive_utc_parses_mixed_formats():
    ingestor = _bare_date_ingestor()

    result = ingestor._to_naive_utc(
        pd.Series(
            [
                "2026-09-11 00:00:00.000000",
                "2026-03-31T19:18:14.446162+00:00",
                "2026-09-23T11:30:00+00:00",
            ],
            dtype=object,
        )
    )

    assert str(result.dtype) == "datetime64[ns]"
    assert result.notna().all()


def test_process_victims_data_keeps_rows_with_mixed_date_formats():
    ingestor = _bare_date_ingestor()
    raw = ingestor._transform_api_v2_response(
        pd.DataFrame(
            [
                {
                    "victim": "Space Micro",
                    "country": "BR",
                    "domain": "space.com",
                    "group": "lockbit",
                    "activity": "Finance",
                    "attackdate": "2026-09-11 00:00:00.000000",
                    "discovered": "2026-09-11 00:00:00.000000",
                    "screenshot": "",
                    "claim_url": "",
                },
                {
                    "victim": "T Offset Micro",
                    "country": "US",
                    "domain": "offsetmicro.com",
                    "group": "lockbit",
                    "activity": "Finance",
                    "attackdate": "2026-03-31T19:18:14.446162+00:00",
                    "discovered": "2026-03-31T19:18:14.446162+00:00",
                    "screenshot": "",
                    "claim_url": "",
                },
                {
                    "victim": "T Offset No Micro",
                    "country": "US",
                    "domain": "offsetnano.com",
                    "group": "lockbit",
                    "activity": "Finance",
                    "attackdate": "2026-09-23T11:30:00+00:00",
                    "discovered": "2026-09-23T11:30:00+00:00",
                    "screenshot": "",
                    "claim_url": "",
                },
            ]
        )
    )

    result = ingestor.process_victims_data(raw)

    assert len(result) == 3
    assert str(result["published"].dtype) == "datetime64[ns]"
    assert str(result["discovered"].dtype) == "datetime64[ns]"
    assert result["published"].dt.tz is None
    assert result["discovered"].dt.tz is None
