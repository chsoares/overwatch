"""Regression guards for the spurious trailing zero month in monthly charts.

``monthly_axis_end`` used to return the first day of the *next* month, so
``month_axis`` could emit a 13th all-zero month whenever the window's earliest
row landed exactly on midnight. ``historical_series`` had the same problem when
its ``plot_end_date`` was clamped to a mid-month ``today``. These tests pin the
axis to the selected/current month on the frozen fixture.
"""

from datetime import date

import pandas as pd
import pytest

from core.analytics import ransom
from tests.analytics._datasets import RANSOM_CSV


@pytest.fixture(scope="module")
def df():
    return ransom.load_dataset(RANSOM_CSV)


def _monthly(year, month):
    return {
        "type": "monthly",
        "start": date(year, month, 1),
        "end": date(year, month, 28),
    }


# 2024-02 is a past month whose frozen-fixture 12-month window starts on a
# midnight timestamp (2023-03-01 00:00:00), which is what used to leak the
# extra month. 2026-04 reproduces the live report (the whole selected month is
# empty in the frozen fixture, so it must still be the last axis month).
PAST_PERIODS = [
    pytest.param(2024, 2, id="2024-02-has-data"),
    pytest.param(2026, 4, id="2026-04-selected-empty"),
]


@pytest.mark.parametrize("year,month", PAST_PERIODS)
def test_monthly_attacks_past_period_ends_at_selected_month(df, year, month):
    result = ransom.monthly_attacks(df, _monthly(year, month))

    assert len(result) == 12
    assert result["date"].is_unique
    last = result["date"].iloc[-1]
    assert (last.year, last.month) == (year, month)
    assert not (result["date"] > last).any()


def test_monthly_attacks_past_period_has_no_trailing_zero_month(df):
    result = ransom.monthly_attacks(df, _monthly(2024, 2))

    # The selected month has attacks; the buggy extra March row was all zero.
    assert result["world_attacks"].iloc[-1] > 0
    assert result["date"].iloc[-1] == pd.Timestamp("2024-02-01", tz=None)


def test_monthly_group_activity_past_period_ends_at_selected_month(df):
    result = ransom.monthly_group_activity(df, _monthly(2024, 2))

    months = result["date"].dt.to_period("M").nunique()
    assert months == 12
    assert result["date"].max() == pd.Timestamp("2024-02-01")


def test_monthly_active_groups_still_ends_at_selected_month(df):
    result = ransom.monthly_active_groups(df, _monthly(2024, 2))

    assert result["date"].dt.to_period("M").nunique() == 12
    assert result["date"].max() == pd.Timestamp("2024-02-01")


@pytest.mark.parametrize(
    "today,year,month",
    [
        pytest.param(pd.Timestamp("2024-02-15 23:00:00"), 2024, 2, id="feb-2024"),
        pytest.param(pd.Timestamp("2024-07-10 12:00:00"), 2024, 7, id="jul-2024"),
    ],
)
def test_historical_series_current_month_has_no_future_month(df, today, year, month):
    result = ransom.historical_series(df, _monthly(year, month), today=today)

    assert result["date"].is_unique
    last = result["date"].iloc[-1]
    assert (last.year, last.month) == (year, month)
    assert not (result["date"] > last).any()
