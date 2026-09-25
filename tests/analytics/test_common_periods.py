from datetime import date

from core.analytics.common import filter_periods


def test_filter_periods_total_returns_all_rows_and_empty_previous():
    import pandas as pd
    dates = pd.to_datetime(["2023-01-01", "2024-06-01", "2026-09-01"])
    df = pd.DataFrame({"published": dates})
    period = {"type": "total", "start": date(2023, 1, 1), "end": date(2026, 9, 25)}
    current, previous, monthly = filter_periods(df, period)
    assert len(current) == 3
    assert previous.empty
    assert len(monthly) == 3


def test_filter_periods_total_ignores_period_bounds_and_keeps_all_rows():
    import pandas as pd
    dates = pd.to_datetime(["2022-05-01", "2023-01-01", "2024-06-01", "2026-09-01"])
    df = pd.DataFrame({"published": dates})
    period = {"type": "total", "start": date(2023, 1, 1), "end": date(2024, 12, 31)}
    current, previous, monthly = filter_periods(df, period)
    assert len(current) == 4
    assert previous.empty
    assert len(monthly) == 4
