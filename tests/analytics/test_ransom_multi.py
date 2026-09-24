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
