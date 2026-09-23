"""Regression guards for the version-independent monthly axis.

``month_axis`` used to delegate to ``pd.date_range(freq="MS")``, whose
inclusive-end handling changed between pandas 2.3 and 3.x when a boundary
carries a time-of-day. The legacy goldens were captured on pandas 2.3.3, so
``month_axis`` now reproduces those semantics explicitly. These tests pin the
boundary cases that used to differ so a future pandas bump cannot silently
regress them.
"""

import pandas as pd
import pytest

from core.analytics.common import month_axis

TS = pd.Timestamp


def _starts(start, end):
    return list(month_axis(start, end)["published"])


def test_columns_and_labels():
    frame = month_axis(TS("2024-01-01 08:00"), TS("2024-03-31 23:59"), include_year=True)
    assert list(frame.columns) == ["published", "month", "sigla", "year"]
    assert frame["month"].tolist() == ["January", "February", "March"]
    assert frame["sigla"].tolist() == ["Jan", "Feb", "Mar"]
    assert frame["year"].tolist() == [2024, 2024, 2024]


def test_year_column_is_omitted_by_default():
    frame = month_axis(TS("2024-01-01"), TS("2024-03-01"))
    assert list(frame.columns) == ["published", "month", "sigla"]


def test_end_on_month_end_midnight_is_rolled_back():
    # end day != 1 -> rolled back to the month start (00:00), which is earlier
    # than the generated month start (08:00), so the final month is excluded.
    assert _starts(TS("2023-01-01 08:00"), TS("2024-04-30 00:00"))[-1] == TS(
        "2024-03-01 08:00"
    )


def test_end_on_month_start_with_earlier_time_is_excluded():
    assert _starts(TS("2023-01-01 08:00"), TS("2024-04-01 00:00"))[-1] == TS(
        "2024-03-01 08:00"
    )


def test_end_on_month_start_with_later_time_is_included():
    assert _starts(TS("2023-01-01 08:00"), TS("2024-04-01 23:59"))[-1] == TS(
        "2024-04-01 08:00"
    )


def test_start_not_on_month_start_rolls_forward_without_touching_end():
    # start day != 1 -> start rolls forward to the next month start and end is
    # left untouched (mirrors pandas 2's if/elif), so March 15 still admits Mar.
    assert _starts(TS("2023-01-05 08:00"), TS("2023-03-15 00:00")) == [
        TS("2023-02-01 08:00"),
        TS("2023-03-01 08:00"),
    ]


def test_time_of_day_and_microseconds_are_preserved():
    start = TS("2023-01-01 08:56:31.106810")
    starts = _starts(start, TS("2023-03-01 23:59"))
    assert starts == [
        TS("2023-01-01 08:56:31.106810"),
        TS("2023-02-01 08:56:31.106810"),
        TS("2023-03-01 08:56:31.106810"),
    ]


def test_annual_2024_spans_jan_2023_to_dec_2024():
    starts = _starts(TS("2023-01-01 08:56:31"), TS("2025-01-31 00:00"))
    assert len(starts) == 24
    assert starts[0] == TS("2023-01-01 08:56:31")
    assert starts[-1] == TS("2024-12-01 08:56:31")


@pytest.mark.parametrize("end", ["2025-01-31 00:00", "2025-01-15 00:00", "2025-01-01 00:00"])
def test_january_2025_boundary_never_leaks_into_annual_2024(end):
    starts = _starts(TS("2023-01-01 08:56:31"), TS(end))
    assert len(starts) == 24
    assert starts[-1].year == 2024
