"""Shared pure helpers for the analytics ports (no Streamlit, no locale, no I/O writes).

Period-slice contract:

* A period that selects no rows at all raises :class:`EmptyPeriodError` (a
  ``ValueError`` subclass) from :func:`require_data`.
* A non-empty period with no rows for a given country is *not* an error: the
  country-scoped aggregations return a correctly-columned empty frame.
"""

import json
from datetime import datetime, time
from functools import lru_cache

import pandas as pd

from core.paths import RESOURCES_DIR

MONTH_NAMES = (
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)

MONTH_ABBR = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)

MONTH_NUM = {name: number for number, name in enumerate(MONTH_NAMES, start=1)}
MONTH_ABBR_NUM = {abbr: number for number, abbr in enumerate(MONTH_ABBR, start=1)}


class EmptyPeriodError(ValueError):
    """Raised when a normalized period selects no rows from the dataset."""


def month_name(month):
    """Fixed English month name (locale-independent)."""
    return MONTH_NAMES[month - 1]


def month_abbr(month):
    """Fixed English month abbreviation (locale-independent)."""
    return MONTH_ABBR[month - 1]


def month_number(label):
    """Resolve an English month label (full name or abbreviation) to 1..12."""
    if label in MONTH_NUM:
        return MONTH_NUM[label]
    return MONTH_ABBR_NUM[label]


def month_to_timestamp(year, label):
    """First day of the month from a numeric ``year`` and English month label.

    Builds the timestamp from the numeric month so parsing never depends on the
    process locale (unlike ``strptime('%B')`` / ``strptime('%b')``).
    """
    return pd.Timestamp(int(year), month_number(label), 1)


def filter_periods(df, period, date_col="published"):
    """Slice ``df`` into (current, previous, monthly) like the legacy filter.

    ``period`` is a normalized period dict as returned by
    :func:`core.periods.normalize_period`. ``date_col`` names the parsed
    datetime column to slice on (the ransom dataset uses ``published``; the
    vulnerability dataset uses ``dateAdded``).
    """
    dates = df[date_col]
    kind = period["type"]

    if kind == "annual":
        year = period["start"].year
        current = df[dates.dt.year == year]
        previous = df[dates.dt.year == year - 1]
        return current, previous, current.copy()

    if kind == "monthly":
        year, month = period["start"].year, period["start"].month
        current_start = pd.Timestamp(f"{year}-{month:02d}-01")
        current_end = (current_start + pd.offsets.MonthEnd()).replace(
            hour=23, minute=59, second=59
        )
        current = df[(dates >= current_start) & (dates <= current_end)]

        previous_start = current_start - pd.offsets.MonthBegin()
        previous_end = (previous_start + pd.offsets.MonthEnd()).replace(
            hour=23, minute=59, second=59
        )
        previous = df[(dates >= previous_start) & (dates <= previous_end)]

        start = current_start - pd.DateOffset(months=11)
        monthly = df[(dates >= start) & (dates <= current_end)].copy()
        return current, previous, monthly

    start_date = pd.Timestamp(datetime.combine(period["start"], time.min))
    end_date = pd.Timestamp(datetime.combine(period["end"], time.max))
    current = df[(dates >= start_date) & (dates <= end_date)]

    delta = end_date - start_date
    previous_end = start_date - pd.Timedelta(days=1)
    previous_start = previous_end - delta
    previous = df[(dates >= previous_start) & (dates <= previous_end)]
    return current, previous, current.copy()


def require_data(current, period):
    """Return ``current`` or raise :class:`EmptyPeriodError` when it is empty."""
    if current.empty:
        raise EmptyPeriodError(f"No data for period: {period}")
    return current


def monthly_axis_end(end, period):
    """Legacy end-date adjustment for the monthly month axis."""
    kind = period["type"]
    if kind == "monthly":
        year, month = period["start"].year, period["start"].month
        return pd.Timestamp(f"{year}-{month:02d}-01") + pd.DateOffset(months=1)
    if kind == "custom":
        return end
    return end + pd.DateOffset(months=1)


def _add_months(timestamp, months):
    """Shift ``timestamp`` by ``months``, pinning the day to the first.

    Pure year/month arithmetic (no ``DateOffset``) so the result never depends
    on the pandas version. Time-of-day and sub-second precision are preserved.
    """
    total = timestamp.year * 12 + (timestamp.month - 1) + months
    year, month = divmod(total, 12)
    return timestamp.replace(year=year, month=month + 1, day=1)


def _month_start_sequence(start, end):
    """Month-start timestamps equivalent to ``date_range(freq="MS")`` on pandas 2.

    pandas 2.3 and pandas 3.x disagree on inclusive-end handling for an
    anchored ``MS`` range whose boundaries carry a time-of-day (the goldens
    were captured on 2.3.3). The legacy semantics are reproduced explicitly:

    * if ``start`` is not a month start, roll it *forward* to the next month
      start and leave ``end`` untouched (this mirrors pandas 2's ``if``/``elif``
      in ``_generate_range``);
    * otherwise, if ``end`` is not a month start, roll it *back* to its month
      start;
    * emit month starts while ``cur <= end``.

    ``MonthBegin.is_on_offset`` only inspects the day-of-month, so the
    time-of-day is never a factor in the roll decisions -- only in the final
    comparison.
    """
    start = pd.Timestamp(start)
    end = pd.Timestamp(end)

    if start.day != 1:
        start = _add_months(start, 1)
    elif end.day != 1:
        end = end.replace(day=1)

    months = []
    current = start
    while current <= end:
        months.append(current)
        current = _add_months(current, 1)
    return months


def month_axis(start, end, include_year=False):
    """Build the legacy ``all_months`` frame from a monthly date range."""
    index = pd.DatetimeIndex(_month_start_sequence(start, end))
    data = {
        "published": index,
        "month": index.month.map(month_name),
        "sigla": index.month.map(month_abbr),
    }
    if include_year:
        data["year"] = index.year
    return pd.DataFrame(data)


@lru_cache(maxsize=1)
def _iso_frame():
    iso = pd.read_json(RESOURCES_DIR / "iso.json")
    return iso.rename(columns={"nome": "country"})


def iso_frame():
    """ISO country table with the legacy ``nome`` -> ``country`` rename.

    Returns a copy so callers can never mutate the cached frame.
    """
    return _iso_frame().copy()


def country_name(iso2):
    """Return the localized name for an ISO2 code (falls back to the code)."""
    iso = _iso_frame()
    match = iso[iso["ISO2"] == iso2]
    if match.empty:
        return iso2
    return match.iloc[0]["country"]


@lru_cache(maxsize=1)
def _sectors():
    with open(RESOURCES_DIR / "sectors.json", "r", encoding="utf-8") as f:
        return json.load(f)


def translate_sector(sector):
    """Translate an English sector name to Portuguese (identity fallback)."""
    return _sectors().get(sector, sector)


def has_country_data(data, iso2):
    """Legacy ``_validate_country_data``: does ``data`` hold rows for ``iso2``?"""
    if data.empty:
        return False
    return bool(len(data[data["country"] == iso2]))
