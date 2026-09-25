"""Pure period helpers (no Streamlit, no I/O)."""

import calendar
from datetime import date

PERIOD_TYPES = {"Anual": "annual", "Mensal": "monthly", "Customizado": "custom", "Total": "total"}

MONTHS_PT = (
    "Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho",
    "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro",
)


def normalize_period(period):
    """Return {'type', 'start', 'end'} for a period dict produced by the widgets."""
    kind = period["type"]
    if kind == "monthly":
        year, month = period["year"], period["month"]
        if not 1 <= month <= 12:
            raise ValueError(f"month out of range: {month}")
        last_day = calendar.monthrange(year, month)[1]
        return {"type": kind, "start": date(year, month, 1), "end": date(year, month, last_day)}
    if kind == "annual":
        return {"type": kind, "start": date(period["year"], 1, 1), "end": date(period["year"], 12, 31)}
    if kind == "total":
        return {"type": kind, "start": period["data_min"], "end": period["data_max"]}
    custom = period["custom"]
    return {"type": kind, "start": custom["start_date"], "end": custom["end_date"]}
