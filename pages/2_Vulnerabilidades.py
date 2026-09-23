#!/usr/bin/env python3
"""Vulnerability dashboard page backed by the live analytics layer."""

import plotly.graph_objects as go
import streamlit as st

from core.analytics import vuln
from core.analytics.common import EmptyPeriodError
from core.charts import horizontal_bar, line_with_mean
from core.dataset import ALL_COLUMNS, filter_dataset
from core.filters import normalize_period, period_widget, vendor_widget
from core.paths import RESOURCES_DIR
from core.styles import apply_app_styles
from core.ui import (
    as_float,
    as_int,
    delta_color,
    format_delta,
    month_labels,
    period_caption,
)

_RISK_COLORS = {
    "Baixo": "green",
    "Médio": "darkorange",
    "Alto": "firebrick",
    "Crítico": "indigo",
}

st.set_page_config(
    page_title="overwatch / vulnerabilidades",
    layout="centered",
)
st.logo(str(RESOURCES_DIR / "logo_text.png"), icon_image=str(RESOURCES_DIR / "logo_icon.png"))
apply_app_styles()


@st.cache_data(ttl=3600, show_spinner="Carregando dataset...")
def load_dataset():
    """Load and cache the vulnerability dataset for the whole session."""
    return vuln.load_dataset()


def metric_value(table, name):
    match = table.loc[table["Métrica"] == name, "Valor"]
    return match.iloc[0] if not match.empty else None


def has_previous_period(previous):
    """Whether ``overview_previous`` holds a non-empty previous slice."""
    return as_int(metric_value(previous, "Número de CVEs")) > 0


def risk_chart(risk):
    fig = go.Figure()
    for _, row in risk.iterrows():
        if row["Proporção"] > 0:
            fig.add_trace(
                go.Bar(
                    x=[row["Proporção"]],
                    y=[""],
                    name=row["Risco"],
                    orientation="h",
                    marker=dict(color=_RISK_COLORS[row["Risco"]]),
                    text=f"{row['Risco']}<br>({row['Proporção'] * 100:.1f}%)",
                    textposition="inside",
                    insidetextanchor="middle",
                    width=0.5,
                    showlegend=False,
                    hovertemplate=(
                        f"{row['Risco']}: {row['Proporção'] * 100:.1f}%<extra></extra>"
                    ),
                )
            )
    fig.update_layout(
        barmode="stack",
        height=100,
        margin=dict(l=0, r=0, t=0, b=0),
        plot_bgcolor="white",
        yaxis=dict(showticklabels=False, showgrid=False),
        xaxis=dict(showticklabels=False, showgrid=False, range=[0, 1]),
        uniformtext=dict(mode="hide", minsize=10),
    )
    return fig


def scatter_chart(scatter, flag_col, positive, negative, legend_title, flag_label):
    fig = go.Figure()
    for x0, x1, y0, y1, color, opacity in (
        (0, 0.5, 0, 50, "green", 0.25),
        (0.5, 1, 0, 50, "orange", 0.25),
        (0, 0.5, 50, 100, "orange", 0.25),
        (0.5, 1, 50, 100, "red", 0.25),
        (0.9, 1, 90, 100, "indigo", 0.5),
    ):
        fig.add_hrect(
            x0=x0, x1=x1, y0=y0, y1=y1,
            fillcolor=color, opacity=opacity, line_width=0, layer="below",
        )
    fig.update_layout(
        showlegend=True,
        legend=dict(
            title=dict(text=legend_title, font=dict(size=14)),
            yanchor="top",
            y=0.99,
            xanchor="left",
            x=0.01,
            bgcolor="rgba(255, 255, 255, 0.8)",
        ),
        plot_bgcolor="white",
        margin=dict(l=0, r=50, t=0, b=0),
        height=700,
        xaxis=dict(
            title="CVSS",
            range=[0, 10],
            dtick=1,
            gridcolor="white",
            showgrid=True,
            rangemode="tozero",
            automargin=True,
        ),
        yaxis=dict(
            title="EPSS",
            range=[0, 100],
            dtick=10,
            ticksuffix="%",
            gridcolor="white",
            rangemode="tozero",
            automargin=True,
        ),
    )
    for wanted, name, color, symbol, size in (
        (positive, "Sim", "firebrick", "x", 12),
        (negative, "Não", "orange", "circle", 8),
    ):
        subset = scatter[scatter[flag_col] == wanted]
        fig.add_trace(
            go.Scatter(
                x=subset["cvss"],
                y=subset["epss"],
                mode="markers",
                name=name,
                marker=dict(
                    color=color, symbol=symbol, size=size,
                    line=dict(width=1, color=color),
                ),
                customdata=subset["cveID"],
                hovertemplate=(
                    "<b>%{customdata}</b><br>CVSS: %{x:.1f}<br>EPSS: %{y:.1f}%<br>"
                    f"{flag_label}: {name}<extra></extra>"
                ),
                cliponaxis=False,
            )
        )
    return fig


def render_overview(current, previous):
    st.subheader("Visão geral")
    st.caption(
        "Métricas de vulnerabilidades adicionadas à KEV durante o período "
        "e variação em relação ao período anterior"
    )

    mode = st.segmented_control(
        "Variação", ["Absoluta", "Percentual"], default="Absoluta"
    ) or "Absoluta"
    has_previous = has_previous_period(previous)

    total = as_int(metric_value(current, "Número de CVEs"))
    critical = as_int(metric_value(current, "CVEs de risco crítico"))
    exploits = as_int(metric_value(current, "CVEs com exploits públicos disponíveis"))
    ransom = as_int(metric_value(current, "CVEs associadas a campanhas de ransomware"))
    cvss = as_float(metric_value(current, "CVSS médio"))
    epss = as_float(metric_value(current, "EPSS médio"))

    prev_total = as_int(metric_value(previous, "Número de CVEs"))
    prev_critical = as_int(metric_value(previous, "CVEs de risco crítico"))
    prev_exploits = as_int(
        metric_value(previous, "CVEs com exploits públicos disponíveis")
    )
    prev_ransom = as_int(
        metric_value(previous, "CVEs associadas a campanhas de ransomware")
    )
    prev_cvss = as_float(metric_value(previous, "CVSS médio"))
    prev_epss = as_float(metric_value(previous, "EPSS médio"))

    metrics = (
        (
            "Total de CVEs",
            str(total),
            format_delta(total, prev_total, mode, has_previous),
            None,
        ),
        (
            "Risco crítico",
            str(critical),
            format_delta(critical, prev_critical, mode, has_previous),
            "CVEs com risco estimado de nível crítico",
        ),
        (
            "Exploit público",
            str(exploits),
            format_delta(exploits, prev_exploits, mode, has_previous),
            "CVEs com código de exploração publicamente disponível",
        ),
        (
            "Ransomware",
            str(ransom),
            format_delta(ransom, prev_ransom, mode, has_previous),
            "CVEs com uso conhecido em campanhas de ransomware",
        ),
        (
            "CVSS médio",
            f"{cvss:.1f}",
            format_delta(cvss, prev_cvss, mode, has_previous),
            None,
        ),
        (
            "EPSS médio",
            f"{epss:.1f}%",
            format_delta(epss, prev_epss, mode, has_previous),
            None,
        ),
    )
    for column, (label, value, delta, help_text) in zip(st.columns(6), metrics):
        with column:
            st.metric(
                label,
                value,
                delta,
                delta_color=delta_color(delta),
                help=help_text,
                border=True,
            )


dataset = load_dataset()

min_date = dataset["dateAdded"].min().date()
max_date = dataset["dateAdded"].max().date()

st.sidebar.caption("Configurações")
st.sidebar.subheader("Período")
period = normalize_period(period_widget("vuln", min_date, max_date))
st.sidebar.subheader("Fornecedor")
vendor = vendor_widget("vuln", dataset["vendorProject"].unique())
data = dataset if vendor == "all" else dataset[dataset["vendorProject"] == vendor]

try:
    overview = vuln.overview(data, period)
    previous = vuln.overview_previous(data, period)
    monthly = vuln.monthly_vulns(data, period)
    risk = vuln.risk_bars(data, period)
    exploit = vuln.exploit_scatter(data, period)
    ransom = vuln.ransom_scatter(data, period)
    vendors = vuln.vendor_breakdown(dataset, period)
except EmptyPeriodError:
    st.warning(
        "Não há dados para o período selecionado. "
        "Ajuste os filtros na barra lateral e tente novamente."
    )
    st.stop()

st.title("overwatch / vulnerabilidades")
st.caption(f"_Período analisado:_ {period_caption(period)}")
if vendor != "all":
    st.caption(f"_Fornecedor:_ {vendor}")

tab_dashboard, tab_dataset = st.tabs(["Dashboard", "Dataset"])

with tab_dashboard:
    render_overview(overview, previous)

    st.write("")
    st.subheader("Vulnerabilidades mensais")
    st.caption(
        "Distribuição das vulnerabilidades adicionadas à KEV nos últimos meses"
    )
    with st.container(border=True):
        st.plotly_chart(
            line_with_mean(
                month_labels(monthly["date"], capitalize=True),
                monthly["vulnerabilities"],
                "Vulnerabilidades",
                "firebrick",
                mean=monthly["vulnerabilities"].mean(),
                hover="Vulnerabilidades: %{y}<extra></extra>",
                height=300,
            )
        )

    st.write("")
    st.subheader("Risco estimado")
    st.caption(
        "Distribuição das vulnerabilidades do período por nível de risco estimado"
    )
    with st.container(border=True):
        st.plotly_chart(risk_chart(risk))

    st.write("")
    st.subheader("Vulnerabilidades com exploit público")
    st.caption(
        "Vulnerabilidades do período com código de exploração publicamente "
        "disponível por CVSS e EPSS"
    )
    with st.container(border=True):
        st.plotly_chart(
            scatter_chart(
                exploit, "exploit", "Yes", "No", "Exploit público", "Exploit"
            )
        )

    st.write("")
    st.subheader("Vulnerabilidades exploradas em campanhas de ransomware")
    st.caption(
        "Vulnerabilidades do período com uso conhecido por campanhas de "
        "ransomware por CVSS e EPSS"
    )
    with st.container(border=True):
        st.plotly_chart(
            scatter_chart(
                ransom,
                "ransomCampaign",
                "Known",
                "Unknown",
                "Campanha ransomware",
                "Ransomware",
            )
        )

    st.write("")
    st.subheader("Vulnerabilidades por fornecedor")
    st.caption(
        "Fornecedores de tecnologia com maior número de vulnerabilidades "
        "adicionadas à KEV no período (todos os fornecedores, independente do "
        "filtro da barra lateral)"
    )
    with st.container(border=True):
        st.plotly_chart(
            horizontal_bar(vendors, "CVEs", "Empresa", "teal", hover_label="CVEs")
        )
    st.dataframe(vendors, hide_index=True)

with tab_dataset:
    st.subheader("Dataset")
    st.caption("Dados brutos carregados de `data/vuln_dataset.csv`")

    col1, col2 = st.columns([0.3, 0.7])
    with col1:
        column = st.selectbox(
            "Coluna",
            [ALL_COLUMNS] + list(data.columns),
            key="vuln_dataset_column",
        )
    with col2:
        query = st.text_input("Termo de busca", key="vuln_dataset_query")

    filtered = filter_dataset(data, column, query)
    st.caption(f"{len(filtered)} registros encontrados")
    st.dataframe(filtered, hide_index=True)
    st.download_button(
        "📥 Baixar CSV",
        filtered.to_csv(index=False).encode("utf-8-sig"),
        file_name="vuln_dataset.csv",
        mime="text/csv",
    )
