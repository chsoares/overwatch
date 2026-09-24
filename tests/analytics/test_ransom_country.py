import pandas as pd
from datetime import date

from core.analytics import ransom
from tests.analytics._datasets import RANSOM_CSV

PERIOD = {"type": "annual", "start": date(2024, 1, 1), "end": date(2024, 12, 31)}


def test_group_activity_world_unchanged_with_default():
    df = ransom.load_dataset(RANSOM_CSV)
    assert ransom.monthly_group_activity(df, PERIOD).equals(
        ransom.monthly_group_activity(df, PERIOD, iso2=None)
    )


def test_group_activity_country_sums_only_that_country():
    df = ransom.load_dataset(RANSOM_CSV)
    world = ransom.monthly_group_activity(df, PERIOD)
    br = ransom.monthly_group_activity(df, PERIOD, iso2="BR")
    assert br["attacks"].sum() <= world["attacks"].sum()
    assert set(br.columns) == {"date", "group_name", "attacks"}


def test_active_groups_world_unchanged_with_default():
    df = ransom.load_dataset(RANSOM_CSV)
    assert ransom.monthly_active_groups(df, PERIOD).equals(
        ransom.monthly_active_groups(df, PERIOD, iso2=None)
    )


def test_active_groups_country_has_fewer_or_equal():
    df = ransom.load_dataset(RANSOM_CSV)
    world = ransom.monthly_active_groups(df, PERIOD)
    br = ransom.monthly_active_groups(df, PERIOD, iso2="BR")
    assert br["active_groups"].sum() <= world["active_groups"].sum()
    assert list(br.columns) == ["date", "active_groups"]


def test_daily_heatmap_world_unchanged_with_default():
    df = ransom.load_dataset(RANSOM_CSV)
    assert ransom.daily_heatmap(df, PERIOD).equals(
        ransom.daily_heatmap(df, PERIOD, iso2=None)
    )


def test_daily_heatmap_country_sums_less_or_equal():
    df = ransom.load_dataset(RANSOM_CSV)
    world = ransom.daily_heatmap(df, PERIOD)
    br = ransom.daily_heatmap(df, PERIOD, iso2="BR")
    assert br["count"].sum() <= world["count"].sum()
    assert list(br.columns) == ["date", "day", "week", "count"]
