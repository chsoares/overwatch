"""Sidebar widgets and period normalization shared by the content pages."""

import json

import streamlit as st

from core.paths import RESOURCES_DIR
from core.periods import MONTHS_PT, PERIOD_TYPES, normalize_period


@st.cache_data(show_spinner=False)
def _load_countries():
    path = RESOURCES_DIR / "iso.json"
    if not path.exists():
        raise FileNotFoundError(f"Resource not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def period_widget(key, min_date, max_date, default=None):
    """Render the period controls and return a period dict."""
    default = default or {}
    default_type = default.get("type", "monthly")
    default_year = default.get("year", max_date.year)
    default_month = default.get("month", max_date.month)
    default_custom = default.get("custom") or {}
    custom_start = default_custom.get("start_date", min_date)
    custom_end = default_custom.get("end_date", max_date)
    custom_start = min(max(custom_start, min_date), max_date)
    custom_end = min(max(custom_end, min_date), max_date)

    names = list(PERIOD_TYPES.keys())
    current = next((pt for pt, en in PERIOD_TYPES.items() if en == default_type), "Mensal")
    selected_pt = st.sidebar.selectbox("Tipo de Período", names, index=names.index(current), key=f"{key}_type")
    kind = PERIOD_TYPES[selected_pt]
    if kind == "total":
        return {"type": kind, "data_min": min_date, "data_max": max_date}
    period = {"type": kind, "year": default_year, "month": default_month,
              "custom": {"start_date": custom_start, "end_date": custom_end}}
    if kind in ("annual", "monthly"):
        period["year"] = st.sidebar.number_input("Ano", min_value=min_date.year,
                                                 max_value=max_date.year,
                                                 value=period["year"], key=f"{key}_year")
    if kind == "monthly":
        selected = st.sidebar.selectbox("Mês", MONTHS_PT, index=period["month"] - 1, key=f"{key}_month")
        period["month"] = MONTHS_PT.index(selected) + 1
    if kind == "custom":
        period["custom"]["start_date"] = st.sidebar.date_input("Data Inicial", min_value=min_date,
                                                               max_value=max_date,
                                                               value=period["custom"]["start_date"],
                                                               format="DD/MM/YYYY", key=f"{key}_start")
        period["custom"]["end_date"] = st.sidebar.date_input("Data Final", min_value=min_date,
                                                             max_value=max_date,
                                                             value=period["custom"]["end_date"],
                                                             format="DD/MM/YYYY", key=f"{key}_end")
    return period


def country_widget(key, default="BR"):
    """Render the country selector and return a list of ISO2 codes."""
    countries = _load_countries()
    options = {f"{c['nome']} ({c['ISO2'].strip()})": c["ISO2"].strip() for c in countries}
    labels = list(options.keys())
    default_labels = [label for label in labels if options[label] == default] or [
        label for label in labels if options[label] == "BR"
    ]
    chosen = st.sidebar.multiselect(
        "Países", labels, default=default_labels[:1], key=f"{key}_country"
    )
    if not chosen:
        st.sidebar.warning("Nenhum país selecionado; usando Brasil.")
        chosen = default_labels[:1]
    return [options[label] for label in chosen]


def group_widget(key, groups, default=None):
    """Render the group selector (single group) and return one group name."""
    options = sorted(g for g in groups if g)
    if not options:
        return ""
    index = options.index(default) if default in options else 0
    return st.sidebar.selectbox("Grupo", options, index=index, key=f"{key}_group")


def vendor_widget(key, vendors, default="all"):
    """Render the vendor selector and return the chosen vendor (or 'all')."""
    options = ["all"] + sorted(v for v in vendors if v)
    index = options.index(default) if default in options else 0
    return st.sidebar.selectbox("Fornecedor", options, index=index, key=f"{key}_vendor")
