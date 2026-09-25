from datetime import date

import pandas as pd

from core.analytics import ransom
from core.analytics.common import iso_frame
from tests.analytics._datasets import RANSOM_CSV

PERIOD = {"type": "annual", "start": date(2024, 1, 1), "end": date(2024, 12, 31)}
GROUP = "qilin"


def _rows(df, year=2024):
    mask = (df["group_name"] == GROUP) & (df["published"].dt.year == year)
    return df[mask]


def _rows_all(df, year):
    return df[df["published"].dt.year == year]


def _axis_months(world):
    return set(zip(world["date"].dt.year, world["date"].dt.month))


def test_group_overview_metrics():
    df = ransom.load_dataset(RANSOM_CSV)
    current = df[df["published"].dt.year == 2024]
    group = _rows(df, 2024)
    previous = _rows(df, 2023)

    result = ransom.group_overview(df, PERIOD, GROUP)

    assert result["Ataques"] == len(group)
    assert result["Ataques_anterior"] == len(previous)
    assert result["% do mundo"] == len(group) / len(current)
    assert result["Países"] == group["country"].nunique()
    valid_sectors = group[group["activity_classified"] != "Not Found"]
    assert result["Setores"] == valid_sectors["activity_classified"].nunique()
    assert result["Setores"] == len(ransom.group_sectors(df, PERIOD, GROUP))
    assert result["has_previous"] is True

    all_time = df[df["group_name"] == GROUP]
    assert result["Primeira atividade"] == all_time["published"].min()
    assert result["Última atividade"] == all_time["published"].max()


def test_group_overview_first_last_are_all_time_not_period_bound():
    df = ransom.load_dataset(RANSOM_CSV)
    monthly = {"type": "monthly", "start": date(2024, 1, 1), "end": date(2024, 1, 31)}

    result = ransom.group_overview(df, monthly, GROUP)

    all_time = df[df["group_name"] == GROUP]
    period_start = pd.Timestamp("2024-01-01")
    assert result["Primeira atividade"] == all_time["published"].min()
    assert result["Última atividade"] == all_time["published"].max()
    assert result["Primeira atividade"] < period_start
    assert result["Última atividade"] > pd.Timestamp("2024-01-31 23:59:59")


def test_group_overview_previous_metrics_for_all_first_row_metrics():
    df = ransom.load_dataset(RANSOM_CSV)
    previous = _rows(df, 2023)

    result = ransom.group_overview(df, PERIOD, GROUP)

    assert set(
        ["Ataques_anterior", "% do mundo_anterior", "Países_anterior", "Setores_anterior"]
    ).issubset(result)
    assert result["Ataques_anterior"] == len(previous)
    valid_previous_sectors = previous[
        previous["activity_classified"] != "Not Found"
    ]["activity_classified"]
    assert result["Países_anterior"] == previous["country"].nunique()
    assert result["Setores_anterior"] == valid_previous_sectors.nunique()
    assert isinstance(result["Países_anterior"], int)
    assert isinstance(result["Setores_anterior"], int)
    assert result["Países_anterior"] >= 0
    assert result["Setores_anterior"] >= 0
    assert 0.0 <= result["% do mundo_anterior"] <= 1.0
    assert result["% do mundo_anterior"] == len(previous) / len(_rows_all(df, 2023))


def test_group_overview_empty_group_is_zero_but_period_valid():
    df = ransom.load_dataset(RANSOM_CSV)
    result = ransom.group_overview(df, PERIOD, "does-not-exist")
    assert result["Ataques"] == 0
    assert result["% do mundo"] == 0.0
    assert result["has_previous"] is True


def test_group_overview_total_period_has_no_previous():
    df = ransom.load_dataset(RANSOM_CSV)
    total_period = {"type": "total", "start": date(2024, 1, 1), "end": date(2024, 12, 31)}
    result = ransom.group_overview(df, total_period, GROUP)
    assert result["has_previous"] is False


def test_group_monthly_axis_matches_world_and_sums_to_group():
    df = ransom.load_dataset(RANSOM_CSV)
    monthly = ransom.monthly_attacks(df, PERIOD, "BR")

    result = ransom.group_monthly(df, PERIOD, GROUP)

    assert list(result.columns) == ["date", "world_attacks", "group_attacks"]
    assert len(result) == len(monthly)
    assert list(result["date"]) == list(monthly["date"])
    assert list(result["world_attacks"]) == list(monthly["world_attacks"])
    assert result["group_attacks"].sum() == len(_rows(df, 2024))


def test_group_countries_only_group_and_sums():
    df = ransom.load_dataset(RANSOM_CSV)
    group = _rows(df, 2024)

    result = ransom.group_countries(df, PERIOD, GROUP)

    assert list(result.columns) == ["country", "ISO3", "ISO2", "counts", "proportion"]
    assert set(result["ISO2"]).issubset(set(group["country"].dropna()))
    in_iso = group["country"].dropna()
    in_iso = in_iso[in_iso.isin(iso_frame()["ISO2"])]
    assert result["counts"].sum() == len(in_iso)
    assert (result["counts"] > 0).all()


def test_group_sectors_only_group_and_sums():
    df = ransom.load_dataset(RANSOM_CSV)
    group = _rows(df, 2024)

    result = ransom.group_sectors(df, PERIOD, GROUP)

    assert list(result.columns) == ["sector", "attacks", "proportion"]
    expected = len(group[group["activity_classified"] != "Not Found"])
    assert result["attacks"].sum() == expected
    assert (result["attacks"] > 0).all()


def test_group_sectors_empty_group_returns_empty():
    df = ransom.load_dataset(RANSOM_CSV)
    result = ransom.group_sectors(df, PERIOD, "does-not-exist")
    assert result.empty
    assert list(result.columns) == ["sector", "attacks", "proportion"]


def test_distinct_countries_by_month_rows_and_non_negative():
    df = ransom.load_dataset(RANSOM_CSV)
    group = _rows(df, 2024)

    result = ransom.distinct_countries_by_month(df, PERIOD, GROUP)

    assert list(result.columns) == ["date", "distinct_countries"]
    present = group["published"].dt.strftime("%Y-%m").nunique()
    assert len(result) == present
    assert (result["distinct_countries"] > 0).all()
    assert result["date"].is_monotonic_increasing


def test_distinct_sectors_by_month_rows_and_non_negative():
    df = ransom.load_dataset(RANSOM_CSV)
    group = _rows(df, 2024)
    valid = group[group["activity_classified"] != "Not Found"]

    result = ransom.distinct_sectors_by_month(df, PERIOD, GROUP)

    assert list(result.columns) == ["date", "distinct_sectors"]
    present = valid["published"].dt.strftime("%Y-%m").nunique()
    assert len(result) == present
    assert (result["distinct_sectors"] > 0).all()
    assert result["date"].is_monotonic_increasing


def test_distinct_by_month_empty_group_returns_empty():
    df = ransom.load_dataset(RANSOM_CSV)
    countries = ransom.distinct_countries_by_month(df, PERIOD, "does-not-exist")
    sectors = ransom.distinct_sectors_by_month(df, PERIOD, "does-not-exist")
    assert countries.empty and list(countries.columns) == ["date", "distinct_countries"]
    assert sectors.empty and list(sectors.columns) == ["date", "distinct_sectors"]


def test_group_historical_series_world_matches_and_group_sums():
    df = ransom.load_dataset(RANSOM_CSV)
    world = ransom.historical_series(df, PERIOD, iso2=None)

    result = ransom.group_historical_series(df, PERIOD, GROUP)

    assert list(result.columns) == ["date", "world_attacks", "group_attacks"]
    assert list(result["date"]) == list(world["date"])
    assert list(result["world_attacks"]) == list(world["world_attacks"])

    axis = _axis_months(world)
    group = df[df["group_name"] == GROUP]
    on_axis = group[
        [ (year, month) in axis for year, month in
          zip(group["published"].dt.year, group["published"].dt.month) ]
    ]
    assert result["group_attacks"].sum() == len(on_axis)
    assert result["group_attacks"].dtype.kind in "iu"
