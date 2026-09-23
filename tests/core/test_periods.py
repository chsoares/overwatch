from datetime import date

import pytest

from core import periods


def test_normalize_period_monthly():
    result = periods.normalize_period({"type": "monthly", "year": 2024, "month": 3})
    assert result == {"type": "monthly", "start": date(2024, 3, 1), "end": date(2024, 3, 31)}


def test_normalize_period_annual():
    result = periods.normalize_period({"type": "annual", "year": 2023})
    assert result == {"type": "annual", "start": date(2023, 1, 1), "end": date(2023, 12, 31)}


def test_normalize_period_custom():
    result = periods.normalize_period(
        {
            "type": "custom",
            "custom": {"start_date": date(2024, 1, 5), "end_date": date(2024, 2, 10)},
        }
    )
    assert result == {"type": "custom", "start": date(2024, 1, 5), "end": date(2024, 2, 10)}


def test_normalize_period_monthly_leap_year():
    result = periods.normalize_period({"type": "monthly", "year": 2024, "month": 2})
    assert result == {"type": "monthly", "start": date(2024, 2, 1), "end": date(2024, 2, 29)}


def test_normalize_period_invalid_month():
    with pytest.raises(ValueError):
        periods.normalize_period({"type": "monthly", "year": 2024, "month": 13})
