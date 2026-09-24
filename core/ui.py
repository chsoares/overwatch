"""Display and formatting helpers shared by the content pages (no Streamlit)."""

import re

import pandas as pd

from core.periods import MONTHS_PT

MONTHS_ABBR = (
    "jan", "fev", "mar", "abr", "mai", "jun",
    "jul", "ago", "set", "out", "nov", "dez",
)

_EN_TO_PT_ABBR = {
    "Jan": "jan", "Feb": "fev", "Mar": "mar", "Apr": "abr",
    "May": "mai", "Jun": "jun", "Jul": "jul", "Aug": "ago",
    "Sep": "set", "Oct": "out", "Nov": "nov", "Dec": "dez",
}

_MONTH_TOKEN_RE = re.compile(r"\b([A-Za-z]{3})\b")


def _translate_month_token(match):
    token = match.group(1)
    return _EN_TO_PT_ABBR.get(token) or _EN_TO_PT_ABBR.get(token.capitalize(), token)


def _localize_victim_date(value):
    if not isinstance(value, str):
        return value
    return _MONTH_TOKEN_RE.sub(_translate_month_token, value)


def localize_victim_dates(series):
    """Translate English month abbrs from analytics into Portuguese.

    ``victims_table`` emits labels like ``"01 Sep. 2026"`` (English, sometimes
    lowercased). Analytics stays locale-independent; the presentation layer
    rewrites the month token for display. Accepts a single string or a Series.
    """
    if isinstance(series, str):
        return _localize_victim_date(series)
    return series.map(_localize_victim_date)


def month_labels(dates, capitalize=False):
    """Format dates as ``<abbr>. <yy>`` labels, optionally capitalized."""
    labels = []
    for value in pd.to_datetime(dates):
        abbr = MONTHS_ABBR[value.month - 1]
        if capitalize:
            abbr = abbr.capitalize()
        labels.append(f"{abbr}. {value.year % 100:02d}")
    return labels


def period_caption(period):
    """Human-readable caption for a normalized period dict."""
    if period["type"] == "monthly":
        start = period["start"]
        return f"{MONTHS_PT[start.month - 1]} de {start.year}"
    if period["type"] == "annual":
        return str(period["start"].year)
    return f"{period['start'].strftime('%d/%m/%Y')} a {period['end'].strftime('%d/%m/%Y')}"


def as_int(value):
    """Coerce a metric to ``int``, falling back to ``0`` when not numeric."""
    try:
        return int(float(value))
    except (TypeError, ValueError, OverflowError):
        return 0


def as_float(value):
    """Coerce a metric to ``float``, tolerating a trailing ``%`` and NaN."""
    try:
        return float(str(value).rstrip("%"))
    except (TypeError, ValueError):
        return float("nan")


def format_delta(current, previous, mode, has_previous=True):
    """Format the variation between two values.

    Returns ``None`` when there is no previous baseline to compare against:
    either the caller reports no previous period, or ``previous`` is missing
    (``None``/NaN). This keeps count, CVSS and EPSS metrics consistent.
    """
    if not has_previous:
        return None
    if previous is None or pd.isna(previous):
        return None
    delta = current - previous
    if mode == "Percentual":
        if previous == 0:
            return "+∞%" if current > 0 else "0%"
        return f"{delta / previous * 100:+.1f}%"
    if delta == 0:
        return "0"
    return f"{delta:+g}"


def delta_color(value):
    """Streamlit ``delta_color`` for a formatted delta (off when neutral)."""
    if value is None:
        return "off"
    return "off" if as_float(value) == 0 else "normal"
