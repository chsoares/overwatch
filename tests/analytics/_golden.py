"""Golden-fixture comparison helpers for the overwatch analytics port.

Fixtures under ``tests/golden/`` are a **frozen oracle** captured on
**2026-09-22** from the legacy analyzers (``scripts/ransom_analyzer.py`` and
``scripts/vuln_analyzer.py``) with ``period.type=annual``, ``period.year=2024``,
``country.iso2=BR``, reading ``data/ransom_dataset.csv`` and
``data/vuln_dataset.csv``. They are used to verify that the pure functions in
``core/analytics`` reproduce the legacy aggregation numbers.

Those analyzers have since been deleted (``refactor: remove legacy analyzers``),
so the goldens **cannot be regenerated** from the current repository without
restoring that tooling. The matching inputs live in ``tests/fixtures/`` (see
``tests/fixtures/README.md``); the two form a paired oracle. Do not edit the
captured CSVs, and do not regenerate them casually.
"""

import warnings
from pathlib import Path

import pandas as pd
import pandas.testing as pdt

GOLDEN = Path(__file__).resolve().parent.parent / "golden"


def load_golden(name):
    return pd.read_csv(GOLDEN / name)


def _is_string_like(series):
    return pd.api.types.is_object_dtype(series) or isinstance(
        series.dtype, pd.StringDtype
    )


def _normalize(series):
    """Coerce a column into a comparable representation.

    Datetime-like values become ``datetime64``, fully-numeric values become
    numeric (so tolerance applies), and everything else compares as strings.
    Each side is normalized independently with the same rules, so a faithful
    port is not penalized for CSV round-trip dtype loss.
    """
    if pd.api.types.is_datetime64_any_dtype(series):
        return pd.to_datetime(series, errors="coerce")

    non_null = series.notna()
    if not non_null.any():
        return _as_string(series)

    if _is_string_like(series):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            parsed_dates = pd.to_datetime(series, errors="coerce", format="mixed")
        if parsed_dates[non_null].notna().sum() == non_null.sum():
            return parsed_dates

    numeric = pd.to_numeric(series, errors="coerce")
    if numeric[non_null].notna().sum() == non_null.sum():
        return numeric

    return _as_string(series)


def _as_string(series):
    """Render a column as strings with all missing values collapsed to ``""``.

    ``astype(str)`` would turn ``None``/``pd.NA`` into ``"None"``/``"<NA>"``
    while a blank CSV cell reads back as ``"nan"``. Normalizing every missing
    value to the same sentinel makes both renderings compare equal.
    """
    return series.where(series.notna(), "").astype(str)


def _normalize_frame(df):
    return pd.DataFrame({col: _normalize(df[col]) for col in df.columns})


def assert_matches_golden(result, name, sort_by=None):
    expected = load_golden(name)
    got = result.copy()

    assert not expected.empty, f"golden fixture '{name}' is empty"

    missing = set(expected.columns) - set(got.columns)
    unexpected = set(got.columns) - set(expected.columns)
    assert set(got.columns) == set(expected.columns), (
        f"column mismatch for '{name}': missing={missing}, unexpected={unexpected}"
    )

    expected = expected[got.columns]

    if sort_by is None:
        sort_by = list(got.columns)

    got = _normalize_frame(got)
    expected = _normalize_frame(expected)

    got = got.sort_values(by=sort_by, kind="stable").reset_index(drop=True)
    expected = expected.sort_values(by=sort_by, kind="stable").reset_index(drop=True)

    pdt.assert_frame_equal(got, expected, check_dtype=False, atol=1e-6, rtol=1e-6)
