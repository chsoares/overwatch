"""Golden tests for the pure ransom-analytics port.

The fixtures under ``tests/golden/`` were captured from the legacy
``scripts/ransom_analyzer.py``. The un-prefixed fixtures use
``period.type=annual``, ``year=2024``; the ``monthly_`` / ``custom_`` prefixed
ones use ``monthly: year=2024, month=3`` and
``custom: 2024-03-01..2024-06-15``. All were captured with
``country.iso2=BR`` and ``vendor.name=all``.
"""

from datetime import date
import re
from pathlib import Path

import pandas as pd
import pytest

from core.analytics import ransom
from core.analytics.common import (
    MONTH_ABBR_NUM,
    EmptyPeriodError,
    filter_periods,
)
from tests.analytics._datasets import RANSOM_CSV
from tests.analytics._golden import assert_matches_golden

PERIOD = {"type": "annual", "start": date(2024, 1, 1), "end": date(2024, 12, 31)}
NONANNUAL_PERIODS = {
    "monthly": {"type": "monthly", "start": date(2024, 3, 1), "end": date(2024, 3, 31)},
    "custom": {"type": "custom", "start": date(2024, 3, 1), "end": date(2024, 6, 15)},
}
EMPTY_PERIOD = {"type": "annual", "start": date(1990, 1, 1), "end": date(1990, 12, 31)}


@pytest.fixture(scope="module")
def df():
    return ransom.load_dataset(RANSOM_CSV)


# ---------------------------------------------------------------------------
# Annual goldens (captured first)
# ---------------------------------------------------------------------------


def test_historical_series_matches_golden(df):
    assert_matches_golden(ransom.historical_series(df, PERIOD), "dash_historical_series.csv")


def test_overview_matches_golden(df):
    assert_matches_golden(ransom.overview(df, PERIOD), "ransom_overview.csv")


def test_monthly_attacks_matches_golden(df):
    assert_matches_golden(ransom.monthly_attacks(df, PERIOD), "dash_monthly_attacks.csv")


def test_daily_heatmap_matches_golden(df):
    assert_matches_golden(ransom.daily_heatmap(df, PERIOD), "dash_daily_heatmap.csv")


def test_top_groups_matches_golden(df):
    assert_matches_golden(ransom.top_groups(df, PERIOD, iso2=None), "dash_top_groups.csv")


def test_top_groups_br_matches_golden(df):
    assert_matches_golden(ransom.top_groups(df, PERIOD, iso2="BR"), "dash_top_groups_br.csv")


def test_monthly_group_activity_matches_golden(df):
    assert_matches_golden(
        ransom.monthly_group_activity(df, PERIOD), "dash_monthly_group_activity.csv"
    )


def test_monthly_active_groups_matches_golden(df):
    assert_matches_golden(
        ransom.monthly_active_groups(df, PERIOD), "dash_monthly_active_groups.csv"
    )


def test_countries_matches_golden(df):
    assert_matches_golden(ransom.countries(df, PERIOD), "dash_countries.csv")


def test_world_sectors_matches_golden(df):
    assert_matches_golden(ransom.world_sectors(df, PERIOD), "dash_world_sectors.csv")


def test_country_sectors_matches_golden(df):
    assert_matches_golden(
        ransom.country_sectors(df, PERIOD, "BR"), "dash_country_sectors.csv"
    )


def test_victims_table_matches_golden(df):
    assert_matches_golden(ransom.victims_table(df, PERIOD, "BR"), "tbl_vitimas.csv")


# ---------------------------------------------------------------------------
# Monthly / custom goldens
# ---------------------------------------------------------------------------

CASES = [
    pytest.param(
        lambda df, p: ransom.historical_series(df, p),
        "dash_historical_series.csv",
        id="historical_series",
    ),
    pytest.param(lambda df, p: ransom.overview(df, p), "ransom_overview.csv", id="overview"),
    pytest.param(
        lambda df, p: ransom.monthly_attacks(df, p),
        "dash_monthly_attacks.csv",
        id="monthly_attacks",
    ),
    pytest.param(
        lambda df, p: ransom.daily_heatmap(df, p), "dash_daily_heatmap.csv", id="daily_heatmap"
    ),
    pytest.param(
        lambda df, p: ransom.top_groups(df, p, iso2=None), "dash_top_groups.csv", id="top_groups"
    ),
    pytest.param(
        lambda df, p: ransom.top_groups(df, p, iso2="BR"),
        "dash_top_groups_br.csv",
        id="top_groups_br",
    ),
    pytest.param(
        lambda df, p: ransom.monthly_group_activity(df, p),
        "dash_monthly_group_activity.csv",
        id="monthly_group_activity",
    ),
    pytest.param(
        lambda df, p: ransom.monthly_active_groups(df, p),
        "dash_monthly_active_groups.csv",
        id="monthly_active_groups",
    ),
    pytest.param(lambda df, p: ransom.countries(df, p), "dash_countries.csv", id="countries"),
    pytest.param(
        lambda df, p: ransom.world_sectors(df, p), "dash_world_sectors.csv", id="world_sectors"
    ),
    pytest.param(
        lambda df, p: ransom.country_sectors(df, p, "BR"),
        "dash_country_sectors.csv",
        id="country_sectors",
    ),
    pytest.param(
        lambda df, p: ransom.victims_table(df, p, "BR"), "tbl_vitimas.csv", id="victims_table"
    ),
]


@pytest.mark.parametrize("period_name,prefix", [("monthly", "monthly_"), ("custom", "custom_")])
@pytest.mark.parametrize("call,golden", CASES)
def test_nonannual_matches_golden(df, period_name, prefix, call, golden):
    assert_matches_golden(call(df, NONANNUAL_PERIODS[period_name]), f"{prefix}{golden}")


# ---------------------------------------------------------------------------
# Ranking order (the column-sorted golden helper would hide a regression here)
# ---------------------------------------------------------------------------

ORDER_CASES = [
    pytest.param(
        lambda df, p: ransom.top_groups(df, p, iso2=None), "counts", id="top_groups"
    ),
    pytest.param(
        lambda df, p: ransom.top_groups(df, p, iso2="BR"), "counts", id="top_groups_br"
    ),
    pytest.param(ransom.countries, "counts", id="countries"),
    pytest.param(ransom.world_sectors, "attacks", id="world_sectors"),
    pytest.param(
        lambda df, p: ransom.country_sectors(df, p, "BR"), "attacks", id="country_sectors"
    ),
]


@pytest.mark.parametrize("period_name", ["annual", "monthly", "custom"])
@pytest.mark.parametrize("call,column", ORDER_CASES)
def test_ranked_outputs_are_sorted_descending(df, period_name, call, column):
    period = PERIOD if period_name == "annual" else NONANNUAL_PERIODS[period_name]
    result = call(df, period)
    assert result[column].is_monotonic_decreasing


# ---------------------------------------------------------------------------
# Date ordering for the time-series outputs
# ---------------------------------------------------------------------------

DATE_ORDER_CASES = [
    pytest.param(lambda df, p: ransom.historical_series(df, p), id="historical_series"),
    pytest.param(lambda df, p: ransom.monthly_attacks(df, p), id="monthly_attacks"),
    pytest.param(lambda df, p: ransom.daily_heatmap(df, p), id="daily_heatmap"),
    pytest.param(
        lambda df, p: ransom.monthly_group_activity(df, p), id="monthly_group_activity"
    ),
    pytest.param(
        lambda df, p: ransom.monthly_active_groups(df, p), id="monthly_active_groups"
    ),
]


@pytest.mark.parametrize("period_name", ["annual", "monthly", "custom"])
@pytest.mark.parametrize("call", DATE_ORDER_CASES)
def test_date_outputs_are_chronological(df, period_name, call):
    period = PERIOD if period_name == "annual" else NONANNUAL_PERIODS[period_name]
    result = call(df, period)
    assert result["date"].is_monotonic_increasing


def _announcement_key(value):
    day, month, year = value.split()
    return (int(year), MONTH_ABBR_NUM[month.rstrip(".").title()], int(day))


@pytest.mark.parametrize("period_name", ["annual", "monthly", "custom"])
def test_victims_table_follows_announcement_order(df, period_name):
    period = PERIOD if period_name == "annual" else NONANNUAL_PERIODS[period_name]
    result = ransom.victims_table(df, period, "BR")
    keys = result["Data do anúncio"].map(_announcement_key)
    assert keys.is_monotonic_increasing


# ---------------------------------------------------------------------------
# Empty periods raise a clear error; missing countries keep empty frames
# ---------------------------------------------------------------------------

EMPTY_CASES = [
    pytest.param(lambda df: ransom.historical_series(df, EMPTY_PERIOD), id="historical_series"),
    pytest.param(lambda df: ransom.overview(df, EMPTY_PERIOD), id="overview"),
    pytest.param(lambda df: ransom.monthly_attacks(df, EMPTY_PERIOD), id="monthly_attacks"),
    pytest.param(lambda df: ransom.daily_heatmap(df, EMPTY_PERIOD), id="daily_heatmap"),
    pytest.param(lambda df: ransom.top_groups(df, EMPTY_PERIOD), id="top_groups"),
    pytest.param(
        lambda df: ransom.monthly_group_activity(df, EMPTY_PERIOD), id="monthly_group_activity"
    ),
    pytest.param(
        lambda df: ransom.monthly_active_groups(df, EMPTY_PERIOD), id="monthly_active_groups"
    ),
    pytest.param(lambda df: ransom.countries(df, EMPTY_PERIOD), id="countries"),
    pytest.param(lambda df: ransom.world_sectors(df, EMPTY_PERIOD), id="world_sectors"),
    pytest.param(
        lambda df: ransom.country_sectors(df, EMPTY_PERIOD, "BR"), id="country_sectors"
    ),
    pytest.param(lambda df: ransom.victims_table(df, EMPTY_PERIOD, "BR"), id="victims_table"),
]


@pytest.mark.parametrize("call", EMPTY_CASES)
def test_empty_period_raises_empty_period_error(df, call):
    assert issubclass(EmptyPeriodError, ValueError)
    with pytest.raises(EmptyPeriodError, match="No data for period"):
        call(df)


def test_top_groups_missing_country_returns_empty_frame(df):
    result = ransom.top_groups(df, PERIOD, iso2="ZZ")
    assert result.empty
    assert list(result.columns) == ["group_name", "counts", "proportion"]


def test_victims_table_missing_country_returns_empty_frame(df):
    result = ransom.victims_table(df, PERIOD, "ZZ")
    assert result.empty
    assert list(result.columns) == ["Vítima", "Setor", "Grupo", "Data do anúncio"]


def test_country_sectors_missing_country_returns_empty_frame(df):
    result = ransom.country_sectors(df, PERIOD, "ZZ")
    assert result.empty
    assert list(result.columns) == ["sector", "attacks", "proportion"]


# ---------------------------------------------------------------------------
# Locale regression guards
# ---------------------------------------------------------------------------


def test_ransom_source_has_no_locale_month_parsing():
    source = Path(ransom.__file__).read_text(encoding="utf-8")
    assert not re.search(r"strptime\s*\([^)]*%[bB]", source), (
        "ransom.py must not parse month names with locale-sensitive strptime"
    )


_LOCALE_CASES = [
    pytest.param(
        "monthly_group_activity",
        "monthly_dash_monthly_group_activity.csv",
        id="monthly_group_activity",
    ),
    pytest.param(
        "monthly_active_groups",
        "monthly_dash_monthly_active_groups.csv",
        id="monthly_active_groups",
    ),
]

_NON_ENGLISH_LOCALES = ("pt_BR.UTF-8", "de_DE.UTF-8", "fr_FR.UTF-8", "es_ES.UTF-8")


@pytest.mark.parametrize("call_name,golden", _LOCALE_CASES)
def test_group_month_functions_under_nonenglish_locale(df, call_name, golden):
    import locale as _locale

    previous = _locale.setlocale(_locale.LC_TIME)
    chosen = None
    for name in _NON_ENGLISH_LOCALES:
        try:
            _locale.setlocale(_locale.LC_TIME, name)
            chosen = name
            break
        except _locale.Error:
            continue
    if chosen is None:
        _locale.setlocale(_locale.LC_TIME, previous or "C")
        pytest.skip("no non-English locale available on this machine")
    try:
        call = getattr(ransom, call_name)
        assert_matches_golden(call(df, NONANNUAL_PERIODS["monthly"]), golden)
    finally:
        _locale.setlocale(_locale.LC_TIME, previous or "C")


# ---------------------------------------------------------------------------
# Injectable wall clock
# ---------------------------------------------------------------------------


def test_historical_series_accepts_frozen_today(df):
    result = ransom.historical_series(df, PERIOD, today=pd.Timestamp("2024-12-31"))
    assert_matches_golden(result, "dash_historical_series.csv")


def test_historical_series_today_can_truncate_plot(df):
    full = ransom.historical_series(df, PERIOD, today=pd.Timestamp("2024-12-31"))
    truncated = ransom.historical_series(df, PERIOD, today=pd.Timestamp("2024-06-30"))
    assert truncated["date"].is_monotonic_increasing
    assert len(truncated) < len(full)


# ---------------------------------------------------------------------------
# Default dataset path (production behavior unchanged)
# ---------------------------------------------------------------------------


def test_load_dataset_defaults_to_live_data_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(ransom, "DATA_DIR", tmp_path)
    (tmp_path / "ransom_dataset.csv").write_text(
        "published,discovered\n2024-01-01,2024-01-02\n"
    )
    df = ransom.load_dataset()
    assert len(df) == 1
    assert pd.api.types.is_datetime64_any_dtype(df["published"])
    assert pd.api.types.is_datetime64_any_dtype(df["discovered"])


# ---------------------------------------------------------------------------
# Custom periods longer than 12 months
# (regression: calendar months from different years must stay distinct)
# ---------------------------------------------------------------------------

LONG_CUSTOM_PERIOD = {
    "type": "custom",
    "start": date(2023, 1, 1),
    "end": date(2024, 12, 31),
}
SINGLE_DAY_CUSTOM_PERIOD = {
    "type": "custom",
    "start": date(2024, 3, 1),
    "end": date(2024, 3, 1),
}


def test_monthly_attacks_long_custom_period_keeps_months_distinct(df):
    current, _, _ = filter_periods(df, LONG_CUSTOM_PERIOD)
    result = ransom.monthly_attacks(df, LONG_CUSTOM_PERIOD)

    assert result["date"].is_unique
    assert result["date"].nunique() == 24
    assert result["date"].dt.year.nunique() == 2
    assert result["world_attacks"].sum() == len(current)
    assert result["country_attacks"].sum() == len(current[current["country"] == "BR"])


def test_monthly_group_activity_long_custom_period_has_unique_date_group_pairs(df):
    result = ransom.monthly_group_activity(df, LONG_CUSTOM_PERIOD)

    pairs = result[["date", "group_name"]].drop_duplicates()
    assert len(pairs) == len(result)
    assert result["date"].dt.year.nunique() == 2


def test_monthly_active_groups_long_custom_period_keeps_months_distinct(df):
    result = ransom.monthly_active_groups(df, LONG_CUSTOM_PERIOD)

    assert result["date"].is_unique
    assert result["date"].nunique() == 24
    assert result["date"].dt.year.nunique() == 2


# ---------------------------------------------------------------------------
# Single-day custom periods (regression: delta_days == 0 division)
# ---------------------------------------------------------------------------


def test_single_day_custom_period_returns_valid_overview(df):
    current, _, _ = filter_periods(df, SINGLE_DAY_CUSTOM_PERIOD)
    result = ransom.overview(df, SINGLE_DAY_CUSTOM_PERIOD)

    assert not result.empty
    world = result.set_index("Métrica")["Mundo"]
    assert world["Ataques no período"] == str(len(current))
    assert world["Média de ataques por período"] == f"{len(current):.1f}"


def test_single_day_custom_period_other_slices_do_not_crash(df):
    assert not ransom.monthly_attacks(df, SINGLE_DAY_CUSTOM_PERIOD).empty
    assert not ransom.monthly_group_activity(df, SINGLE_DAY_CUSTOM_PERIOD).empty
    assert not ransom.monthly_active_groups(df, SINGLE_DAY_CUSTOM_PERIOD).empty
    assert not ransom.daily_heatmap(df, SINGLE_DAY_CUSTOM_PERIOD).empty
