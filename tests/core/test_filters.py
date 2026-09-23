from core import filters, periods


def test_filters_reexports_period_helpers():
    assert filters.normalize_period is periods.normalize_period
    assert filters.PERIOD_TYPES is periods.PERIOD_TYPES
