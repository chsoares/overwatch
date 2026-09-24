from datetime import date

import pandas as pd

from core.analytics import ransom
from core.analytics.common import normalize_iso2, selection_label
from tests.analytics._datasets import RANSOM_CSV

PERIOD = {"type": "annual", "start": date(2024, 1, 1), "end": date(2024, 12, 31)}


def test_normalize_iso2_scalar_to_list():
    assert normalize_iso2("BR") == ["BR"]


def test_normalize_iso2_list_passthrough():
    assert normalize_iso2(["BR", "US"]) == ["BR", "US"]


def test_normalize_iso2_none_and_empty():
    assert normalize_iso2(None) == []
    assert normalize_iso2([]) == []
    assert normalize_iso2("") == []


def test_selection_label_single():
    assert selection_label(["BR"], lambda c: "Brasil") == "Brasil"


def test_selection_label_multiple():
    assert selection_label(["BR", "US"], lambda c: "x") == "países selecionados"


def test_scalar_and_single_list_equivalent():
    df = ransom.load_dataset(RANSOM_CSV)
    for fn in (ransom.overview, ransom.monthly_attacks, ransom.historical_series):
        assert fn(df, PERIOD, "BR").equals(fn(df, PERIOD, ["BR"]))


def test_overview_sum_two_countries():
    df = ransom.load_dataset(RANSOM_CSV)
    br = ransom.overview(df, PERIOD, "BR")
    us = ransom.overview(df, PERIOD, "US")
    both = ransom.overview(df, PERIOD, ["BR", "US"])

    def sel_col(frame):
        return [c for c in frame.columns if c not in ("Métrica", "Mundo")][0]

    def attacks(frame):
        return int(frame.loc[frame["Métrica"] == "Ataques no período", sel_col(frame)].iloc[0])

    assert attacks(both) == attacks(br) + attacks(us)


def test_monthly_attacks_single_list_equals_scalar():
    df = ransom.load_dataset(RANSOM_CSV)
    assert ransom.monthly_attacks(df, PERIOD, "BR").equals(
        ransom.monthly_attacks(df, PERIOD, ["BR"])
    )


def test_top_groups_none_still_world():
    df = ransom.load_dataset(RANSOM_CSV)
    assert ransom.top_groups(df, PERIOD, None).equals(ransom.top_groups(df, PERIOD, iso2=None))


def test_country_sectors_accepts_list():
    df = ransom.load_dataset(RANSOM_CSV)
    one = ransom.country_sectors(df, PERIOD, "BR")
    lst = ransom.country_sectors(df, PERIOD, ["BR"])
    assert one.equals(lst)


def test_victims_table_list_union():
    df = ransom.load_dataset(RANSOM_CSV)
    both = ransom.victims_table(df, PERIOD, ["BR", "US"])
    assert set(both.columns) == {"Vítima", "Setor", "Grupo", "Data do anúncio"}
    assert len(both) >= len(ransom.victims_table(df, PERIOD, "BR"))


def test_monthly_attacks_by_country_columns_and_total():
    df = ransom.load_dataset(RANSOM_CSV)
    result = ransom.monthly_attacks_by_country(df, PERIOD, ["BR", "US"])
    assert list(result.columns) == ["date", "BR", "US"]
    expected_br = len(df[(df["country"] == "BR") & (df["published"].dt.year == 2024)])
    assert result["BR"].sum() == expected_br


def test_monthly_attacks_by_country_matches_monthly_attacks():
    df = ransom.load_dataset(RANSOM_CSV)
    result = ransom.monthly_attacks_by_country(df, PERIOD, ["BR", "US"])
    combined = ransom.monthly_attacks(df, PERIOD, ["BR", "US"])
    per_month = (result["BR"] + result["US"]).reset_index(drop=True)
    assert per_month.equals(combined["country_attacks"].reset_index(drop=True))


def test_countries_selected_only_selected_and_total():
    df = ransom.load_dataset(RANSOM_CSV)
    result = ransom.countries_selected(df, PERIOD, ["BR", "US"])
    assert set(result["ISO2"]).issubset({"BR", "US"})
    period_rows = df[
        (df["country"].isin(["BR", "US"])) & (df["published"].dt.year == 2024)
    ]
    assert result["counts"].sum() == len(period_rows)


def test_historical_series_multi_columns_and_world():
    df = ransom.load_dataset(RANSOM_CSV)
    result = ransom.historical_series_multi(df, PERIOD, ["BR", "US"])
    assert {"world_attacks", "selection_attacks", "BR", "US"}.issubset(result.columns)
    world = ransom.historical_series(df, PERIOD, iso2=None)
    assert result["world_attacks"].reset_index(drop=True).equals(
        world["world_attacks"].reset_index(drop=True)
    )


def test_historical_series_multi_selection_is_sum():
    df = ransom.load_dataset(RANSOM_CSV)
    result = ransom.historical_series_multi(df, PERIOD, ["BR", "US"])
    assert (result["selection_attacks"] == result["BR"] + result["US"]).all()


def test_historical_series_multi_empty_selection_is_zero():
    df = ransom.load_dataset(RANSOM_CSV)
    result = ransom.historical_series_multi(df, PERIOD, [])
    assert result["selection_attacks"].sum() == 0
    assert "BR" not in result.columns
    assert len(result) == len(result["date"])


def test_historical_series_multi_missing_country_is_zero():
    df = ransom.load_dataset(RANSOM_CSV)
    result = ransom.historical_series_multi(df, PERIOD, ["ZZ"])
    assert result["selection_attacks"].sum() == 0
