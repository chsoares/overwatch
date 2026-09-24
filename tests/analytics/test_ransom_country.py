from datetime import date

from core.analytics import ransom
from tests.analytics._datasets import RANSOM_CSV

PERIOD = {"type": "annual", "start": date(2024, 1, 1), "end": date(2024, 12, 31)}


def test_group_activity_country_matches_prefiltered_input():
    df = ransom.load_dataset(RANSOM_CSV)
    assert (
        ransom.monthly_group_activity(df[df["country"] == "BR"], PERIOD)
        .reset_index(drop=True)
        .equals(
            ransom.monthly_group_activity(df, PERIOD, iso2="BR").reset_index(
                drop=True
            )
        )
    )


def test_group_activity_country_exact_attacks():
    df = ransom.load_dataset(RANSOM_CSV)
    br = ransom.monthly_group_activity(df, PERIOD, iso2="BR")
    world = ransom.monthly_group_activity(df, PERIOD)
    assert br["attacks"].sum() == 78.0
    assert br["attacks"].sum() < world["attacks"].sum()
    assert set(br.columns) == {"date", "group_name", "attacks"}


def test_group_activity_missing_country_returns_empty():
    df = ransom.load_dataset(RANSOM_CSV)
    empty = ransom.monthly_group_activity(df, PERIOD, iso2="ZZ")
    assert empty.empty
    assert list(empty.columns) == ["date", "group_name", "attacks"]


def test_active_groups_country_matches_prefiltered_input():
    df = ransom.load_dataset(RANSOM_CSV)
    assert (
        ransom.monthly_active_groups(df[df["country"] == "BR"], PERIOD)
        .reset_index(drop=True)
        .equals(
            ransom.monthly_active_groups(df, PERIOD, iso2="BR").reset_index(
                drop=True
            )
        )
    )


def test_active_groups_country_exact_values():
    df = ransom.load_dataset(RANSOM_CSV)
    br = ransom.monthly_active_groups(df, PERIOD, iso2="BR")
    world = ransom.monthly_active_groups(df, PERIOD)
    assert br["active_groups"].sum() == 71
    assert br["active_groups"].sum() < world["active_groups"].sum()
    assert list(br.columns) == ["date", "active_groups"]


def test_active_groups_missing_country_returns_empty():
    df = ransom.load_dataset(RANSOM_CSV)
    empty = ransom.monthly_active_groups(df, PERIOD, iso2="ZZ")
    assert empty.empty
    assert list(empty.columns) == ["date", "active_groups"]


def test_daily_heatmap_country_matches_prefiltered_input():
    df = ransom.load_dataset(RANSOM_CSV)
    assert (
        ransom.daily_heatmap(df[df["country"] == "BR"], PERIOD)
        .reset_index(drop=True)
        .equals(
            ransom.daily_heatmap(df, PERIOD, iso2="BR").reset_index(drop=True)
        )
    )


def test_daily_heatmap_country_exact_values():
    df = ransom.load_dataset(RANSOM_CSV)
    br = ransom.daily_heatmap(df, PERIOD, iso2="BR")
    world = ransom.daily_heatmap(df, PERIOD)
    assert br["count"].sum() == 114.0
    assert br["count"].sum() < world["count"].sum()
    assert list(br.columns) == ["date", "day", "week", "count"]


def test_daily_heatmap_missing_country_returns_empty():
    df = ransom.load_dataset(RANSOM_CSV)
    empty = ransom.daily_heatmap(df, PERIOD, iso2="ZZ")
    assert empty.empty
    assert list(empty.columns) == ["date", "day", "week", "count"]
