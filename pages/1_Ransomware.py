#!/usr/bin/env python3
"""Ransomware dashboard page backed by the live analytics layer."""

from datetime import date

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from plotly.subplots import make_subplots

from core.analytics import ransom
from core.analytics.common import EmptyPeriodError, country_name
from core.charts import horizontal_bar, line_with_mean
from core.dataset import ALL_COLUMNS, filter_dataset
from core.filters import country_widget, normalize_period, period_widget
from core.paths import RESOURCES_DIR
from core.styles import apply_app_styles
from core.ui import (
    MONTHS_ABBR,
    delta_color,
    format_delta,
    localize_victim_dates,
    month_labels,
    period_caption,
)

_WEEKDAYS = ["Seg", "Ter", "Qua", "Qui", "Sex", "Sáb", "Dom"]
_WEEKDAYS_FULL = (
    "Segunda-feira", "Terça-feira", "Quarta-feira", "Quinta-feira",
    "Sexta-feira", "Sábado", "Domingo",
)
_HEATMAP_COLORSCALE = [
    [0.0, "rgb(255, 255, 255)"],
    [0.1, "rgb(235, 245, 235)"],
    [0.2, "rgb(200, 230, 200)"],
    [0.4, "rgb(150, 200, 150)"],
    [0.6, "rgb(100, 170, 100)"],
    [0.8, "rgb(50, 140, 50)"],
    [0.95, "rgb(25, 100, 25)"],
    [1.0, "rgb(0, 60, 0)"],
]
_HEATMAP_COLORSCALE_COUNTRY = [
    [0.0, "rgb(255, 255, 255)"],
    [0.1, "rgb(235, 238, 250)"],
    [0.2, "rgb(205, 215, 245)"],
    [0.4, "rgb(160, 180, 235)"],
    [0.6, "rgb(110, 140, 220)"],
    [0.8, "rgb(65, 105, 225)"],
    [0.95, "rgb(72, 61, 139)"],
    [1.0, "rgb(45, 35, 95)"],
]
_COLORWAY_COUNTRY = [
    "#1F77B4", "#FF7F0E", "#2CA02C", "#D62728", "#9467BD",
    "#8C564B", "#E377C2", "#7F7F7F", "#BCBD22", "#17BECF",
]

st.set_page_config(
    page_title="overwatch / ransomware",
    layout="centered",
)
st.logo(str(RESOURCES_DIR / "logo_text.png"), icon_image=str(RESOURCES_DIR / "logo_icon.png"))
apply_app_styles()


@st.cache_data(ttl=3600, show_spinner="Carregando dataset...")
def load_dataset():
    """Load and cache the ransomware dataset for the whole session."""
    return ransom.load_dataset()


def period_is_current(period, today):
    if period["type"] == "monthly":
        start = period["start"]
        return (start.year, start.month) == (today.year, today.month)
    if period["type"] == "annual":
        return period["start"].year == today.year
    return period["end"] >= today


def group_activity_chart(activity, colorway=None):
    activity = activity.copy()
    activity["month_label"] = month_labels(activity["date"])
    fig = go.Figure()
    for group in activity["group_name"].unique():
        group_data = activity[activity["group_name"] == group]
        fig.add_trace(
            go.Scatter(
                x=group_data["month_label"],
                y=group_data["attacks"],
                name=group,
                mode="lines+markers",
                line=dict(width=2, shape="linear"),
                marker=dict(size=6),
                hovertemplate="<b>%{x}</b><br>Grupo: " + group
                + "<br>Incidentes: %{y}<extra></extra>",
            )
        )
    fig.update_layout(
        showlegend=True,
        legend=dict(orientation="v", yanchor="middle", y=0.5, xanchor="left", x=1.02),
        margin=dict(l=0, r=100, t=30, b=0),
        plot_bgcolor="white",
        xaxis=dict(showgrid=False, showspikes=False, type="category"),
        yaxis=dict(
            showspikes=False,
            showgrid=True,
            gridcolor="lightgray",
            gridwidth=0.5,
            rangemode="tozero",
        ),
    )
    if colorway is not None:
        fig.update_layout(colorway=colorway)
    return fig


def choropleth_chart(countries):
    data = countries.copy()
    data["log_counts"] = np.log1p(data["counts"])
    text = data["country"] + "<br>Incidentes: " + data["counts"].astype(str)
    fig = go.Figure(
        go.Choropleth(
            locations=data["ISO3"],
            z=data["log_counts"],
            text=text,
            colorscale="reds",
            marker_line_color="darkgray",
            marker_line_width=1,
            showscale=False,
            hovertemplate="%{text}<extra></extra>",
        )
    )
    fig.update_layout(
        geo=dict(
            showframe=False,
            showcoastlines=True,
            coastlinecolor="darkgray",
            coastlinewidth=1.25,
            projection_type="equirectangular",
        ),
        margin=dict(t=0, b=0, l=0, r=0),
        height=400,
    )
    return fig


def heatmap_bounds(period):
    start = period["start"]
    if period["type"] == "monthly":
        end = pd.Timestamp(f"{start.year}-{start.month:02d}-01") + pd.offsets.MonthEnd()
        return (end - pd.DateOffset(months=11)).replace(day=1), end
    if period["type"] == "annual":
        return pd.Timestamp(f"{start.year}-01-01"), pd.Timestamp(f"{start.year}-12-31")
    return pd.Timestamp(start), pd.Timestamp(period["end"])


def daily_heatmap_chart(heatmap, period, colorscale=None):
    heatmap = heatmap.copy()
    heatmap["date"] = pd.to_datetime(heatmap["date"])
    heatmap["date_formatted"] = heatmap["date"].dt.strftime("%d/%m/%Y")
    heatmap["weekday_full"] = heatmap["day"].map(dict(enumerate(_WEEKDAYS_FULL)))

    matrix = heatmap.pivot(index="day", columns="week", values="count")
    date_matrix = heatmap.pivot(index="day", columns="week", values="date_formatted")
    weekday_matrix = heatmap.pivot(index="day", columns="week", values="weekday_full")

    start, end = heatmap_bounds(period)
    week_dates = heatmap.groupby("week")["date"].first()
    x_labels = []
    current = None
    for week in matrix.columns:
        week_date = week_dates[week]
        if start <= week_date <= end:
            abbr = MONTHS_ABBR[week_date.month - 1]
            if abbr != current:
                x_labels.append(abbr)
                current = abbr
            else:
                x_labels.append("")
        else:
            x_labels.append("")

    values = matrix.values.flatten()
    nonzero = values[values > 0]
    zmax = np.percentile(nonzero, 90) * 2.5 if nonzero.size else 1

    fig = go.Figure(
        data=go.Heatmap(
            z=matrix.values,
            x=matrix.columns,
            y=_WEEKDAYS,
            customdata=np.dstack((date_matrix, weekday_matrix)),
            colorscale=_HEATMAP_COLORSCALE if colorscale is None else colorscale,
            zauto=False,
            zmin=0,
            zmax=zmax,
            showscale=False,
            hoverongaps=False,
            xgap=2,
            ygap=2,
            hovertemplate="<b>%{customdata[1]}</b><br>Data: %{customdata[0]}"
            "<br>Incidentes: %{z}<extra></extra>",
        )
    )
    fig.update_layout(
        margin=dict(t=0, b=0, l=0, r=0),
        height=150,
        plot_bgcolor="white",
        xaxis=dict(
            showgrid=False,
            showspikes=False,
            showline=False,
            zeroline=False,
            ticktext=x_labels,
            tickvals=list(matrix.columns),
            tickmode="array",
            tickangle=0,
        ),
        yaxis=dict(
            showgrid=False,
            showspikes=False,
            showline=False,
            zeroline=False,
            autorange="reversed",
        ),
    )
    return fig


def historical_series_chart(series, name):
    labels = month_labels(series["date"])
    fig = make_subplots(specs=[[{"secondary_y": True}]])
    fig.add_trace(
        go.Scatter(
            x=labels,
            y=series["world_attacks"],
            name="Mundo",
            line=dict(color="firebrick", width=3),
            mode="lines+markers",
        ),
        secondary_y=False,
    )
    fig.add_trace(
        go.Scatter(
            x=labels,
            y=series["country_attacks"],
            name=name,
            line=dict(color="green", width=3),
            mode="lines+markers",
        ),
        secondary_y=True,
    )

    world_max = series["world_attacks"].max()
    country_max = series["country_attacks"].max()
    y1_max = world_max * 1.1
    if country_max == 0:
        y2_max = 5
    else:
        world_scale = y1_max / world_max if world_max else 1
        ratio = 6 if country_max < world_max * 0.1 else 2
        y2_max = country_max * ratio * world_scale

    fig.update_layout(
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
        margin=dict(l=0, r=0, t=30, b=0),
        hovermode="x unified",
        plot_bgcolor="white",
    )
    fig.update_xaxes(showgrid=False, type="category")
    fig.update_yaxes(
        title_text="Incidentes Mundiais",
        secondary_y=False,
        showgrid=True,
        gridcolor="lightgray",
        gridwidth=0.5,
        title_font=dict(color="firebrick"),
        range=[0, y1_max],
    )
    fig.update_yaxes(
        title_text=f"Incidentes em {name}",
        secondary_y=True,
        showgrid=False,
        title_font=dict(color="green"),
        range=[0, y2_max],
    )
    return fig


def render_overview(overview, world_groups, name):
    st.subheader("Visão geral")
    st.caption("Métricas de ataques no período e variação em relação ao período anterior")

    def metric(metric_name, column):
        return int(overview.loc[overview["Métrica"] == metric_name, column].iloc[0])

    world_current = metric("Ataques no período", "Mundo")
    world_previous = metric("Ataques no período anterior", "Mundo")
    country_current = metric("Ataques no período", name)
    country_previous = metric("Ataques no período anterior", name)
    groups_current = metric("Grupos ativos", "Mundo")
    groups_previous = metric("Grupos ativos anterior", "Mundo")

    mode = st.segmented_control(
        "Variação", ["Absoluta", "Percentual"], default="Absoluta"
    ) or "Absoluta"

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        delta = format_delta(world_current, world_previous, mode)
        st.metric("Ataques no mundo", str(world_current), delta,
                  delta_color=delta_color(delta), border=True)
    with col2:
        delta = format_delta(country_current, country_previous, mode)
        st.metric(f"Ataques em {name}", str(country_current), delta,
                  delta_color=delta_color(delta), border=True)
    with col3:
        delta = format_delta(groups_current, groups_previous, mode)
        st.metric("Grupos ativos", str(groups_current), delta,
                  delta_color=delta_color(delta), border=True)
    with col4:
        if world_groups.empty:
            st.metric("Grupo mais ativo", "—", "Sem dados", delta_color="off", border=True)
        else:
            top = world_groups.sort_values("counts", ascending=False).iloc[0]
            st.metric("Grupo mais ativo", top["group_name"],
                      f"{int(top['counts'])} ataques", delta_color="off", border=True)


def render_victims(victims, name):
    st.subheader(f"Vítimas em {name}")
    st.caption(
        f"Ataques a instituições anunciadas pelos grupos de ransomware no período"
    )
    if victims.empty:
        st.info("Sem dados para o período")
        return
    display = victims.copy()
    display["Data do anúncio"] = localize_victim_dates(display["Data do anúncio"])
    st.dataframe(display, hide_index=True)


def render_monthly_attacks(monthly, name):
    st.subheader("Ataques mensais")
    st.caption(
        "Evolução do número de ataques ransomware anunciados ao longo dos últimos meses"
    )
    labels = month_labels(monthly["date"])
    col1, col2 = st.columns(2, border=True)
    with col1:
        st.write("###### No mundo")
        st.plotly_chart(
            line_with_mean(labels, monthly["world_attacks"], "Mundial", "firebrick",
                           hover="Incidentes: %{y}<extra></extra>",
                           mean=monthly["world_attacks"].mean()),
        )
    with col2:
        st.write(f"###### Em {name}")
        if monthly["country_attacks"].sum() > 0:
            st.plotly_chart(
                line_with_mean(labels, monthly["country_attacks"], name, "green",
                               hover="Incidentes: %{y}<extra></extra>",
                               mean=monthly["country_attacks"].mean()),
                )
        else:
            st.info("Sem dados para o período")


def render_groups(world_groups, country_groups, name):
    st.subheader("Grupos mais ativos")
    st.caption("Grupos com maior número de ataques anunciados durante o período")
    col1, col2 = st.columns(2, border=True)
    with col1:
        st.write("###### No mundo")
        if world_groups.empty:
            st.info("Sem dados para o período")
        else:
            st.plotly_chart(
                horizontal_bar(world_groups, "counts", "group_name", "darkslateblue",
                               hover_label="Incidentes"),
                )
    with col2:
        st.write(f"###### Em {name}")
        if country_groups.empty:
            st.info("Sem dados para o período")
        else:
            st.plotly_chart(
                horizontal_bar(country_groups, "counts", "group_name", "orange",
                               hover_label="Incidentes"),
                )


def render_group_activity(world, country, name):
    st.subheader("Evolução das atividades dos grupos")
    st.caption(
        "Evolução do número de ataques anunciados pelos grupos mais ativos "
        "no período ao longo dos últimos meses"
    )
    with st.container(border=True):
        st.write("###### No mundo")
        if world.empty:
            st.info("Sem dados para o período")
        else:
            st.plotly_chart(group_activity_chart(world))
    with st.container(border=True):
        st.write(f"###### Em {name}")
        if country.empty:
            st.info("Sem dados para o período")
        else:
            st.plotly_chart(
                group_activity_chart(country, colorway=_COLORWAY_COUNTRY)
            )


def render_active_groups(world, country, name):
    st.subheader("Grupos em atividade")
    st.caption(
        "Evolução do número de grupos distintos em atividade "
        "ao longo dos últimos meses"
    )
    col1, col2 = st.columns(2, border=True)
    with col1:
        st.write("###### No mundo")
        _plot_active_groups(world)
    with col2:
        st.write(f"###### Em {name}")
        _plot_active_groups(country, color="darkorange", mean_color="orange")


def _plot_active_groups(active, color="rebeccapurple", mean_color="plum"):
    if active.empty or active["active_groups"].sum() == 0:
        st.info("Sem dados para o período")
        return
    mean_active = active["active_groups"].mean()
    labels = month_labels(active["date"])
    st.plotly_chart(
        line_with_mean(labels, active["active_groups"], "Grupos ativos",
                       color, mean=mean_active, mean_color=mean_color,
                       hover="Grupos: %{y}<extra></extra>",
                       y_range=[0, mean_active * 1.6], height=300),
    )


def render_countries(countries):
    st.subheader("Países mais afetados")
    st.caption(
        "Países com maior número de vítimas de ransomware anunciadas durante o período"
    )
    with st.container(border=True):
        st.plotly_chart(
            horizontal_bar(countries, "counts", "country", "midnightblue",
                           hover_label="Incidentes"),
        )


def render_geography(countries):
    st.subheader("Distribuição geográfica dos ataques")
    st.caption(
        "Todos os países com pelo menos um ataque anunciado durante o período, "
        "em escala logarítmica"
    )
    with st.container(border=True):
        st.plotly_chart(choropleth_chart(countries))


def render_sectors(world_sectors, country_sectors, name):
    st.subheader("Setores mais atacados")
    st.caption(
        "Setores econômicos com maior número de vítimas anunciadas durante o período"
    )
    col1, col2 = st.columns(2, border=True)
    with col1:
        st.write("###### No mundo")
        if world_sectors.empty:
            st.info("Sem dados para o período")
        else:
            st.plotly_chart(
                horizontal_bar(world_sectors, "attacks", "sector", "orangered",
                               hover_label="Incidentes"),
                )
    with col2:
        st.write(f"###### Em {name}")
        if country_sectors.empty:
            st.info("Sem dados para o período")
        else:
            st.plotly_chart(
                horizontal_bar(country_sectors, "attacks", "sector", "royalblue",
                               hover_label="Incidentes"),
                )


def render_daily_heatmap(world, country, period, name):
    st.subheader("Distribuição diária dos ataques")
    st.caption(
        "Quantidade de ataques por dia da semana ao longo dos últimos meses"
    )
    with st.container(border=True):
        st.write("###### No mundo")
        if world.empty:
            st.info("Sem dados para o período")
        else:
            st.plotly_chart(daily_heatmap_chart(world, period))
    with st.container(border=True):
        st.write(f"###### Em {name}")
        if country.empty:
            st.info("Sem dados para o período")
        else:
            st.plotly_chart(
                daily_heatmap_chart(
                    country, period, colorscale=_HEATMAP_COLORSCALE_COUNTRY
                )
            )


def render_historical_series(series, name):
    st.subheader("Série histórica")
    st.caption(
        f"Evolução do número de ataques ransomware no mundo e em {name} "
        "desde o início da coleta de dados"
    )
    with st.container(border=True):
        st.plotly_chart(historical_series_chart(series, name))


data = load_dataset()

min_date = data["published"].min().date()
max_date = data["published"].max().date()

st.sidebar.caption("Configurações")
st.sidebar.subheader("Período")
period = normalize_period(period_widget("ransom", min_date, max_date))
st.sidebar.subheader("País")
iso2 = country_widget("ransom", default="BR")
name = country_name(iso2)

try:
    overview = ransom.overview(data, period, iso2)
    monthly = ransom.monthly_attacks(data, period, iso2)
    historical = ransom.historical_series(data, period, iso2)
    world_groups = ransom.top_groups(data, period, iso2=None)
    country_groups = ransom.top_groups(data, period, iso2=iso2)
    group_activity = ransom.monthly_group_activity(data, period)
    group_activity_country = ransom.monthly_group_activity(data, period, iso2=iso2)
    active_groups = ransom.monthly_active_groups(data, period)
    active_groups_country = ransom.monthly_active_groups(data, period, iso2=iso2)
    countries = ransom.countries(data, period)
    world_sectors = ransom.world_sectors(data, period)
    country_sectors = ransom.country_sectors(data, period, iso2)
    victims = ransom.victims_table(data, period, iso2)
    heatmap = ransom.daily_heatmap(data, period)
    heatmap_country = ransom.daily_heatmap(data, period, iso2=iso2)
except EmptyPeriodError:
    st.warning(
        "Não há dados para o período selecionado. "
        "Ajuste os filtros na barra lateral e tente novamente."
    )
    st.stop()

st.title("overwatch / ransomware")
st.caption(f"_Período analisado:_ {period_caption(period)}")
if period_is_current(period, date.today()):
    st.warning("O período selecionado é o atual. Os dados podem estar incompletos.")

tab_dashboard, tab_dataset = st.tabs(["Dashboard", "Dataset"])

with tab_dashboard:
    render_overview(overview, world_groups, name)

    st.write("")
    render_victims(victims, name)

    st.write("")
    render_monthly_attacks(monthly, name)

    st.write("")
    render_groups(world_groups, country_groups, name)

    st.write("")
    render_group_activity(group_activity, group_activity_country, name)

    st.write("")
    render_active_groups(active_groups, active_groups_country, name)

    st.write("")
    render_countries(countries)

    st.write("")
    render_geography(countries)

    st.write("")
    render_sectors(world_sectors, country_sectors, name)

    st.write("")
    render_daily_heatmap(heatmap, heatmap_country, period, name)

    st.write("")
    render_historical_series(historical, name)

with tab_dataset:
    st.subheader("Dataset")
    st.caption("Dados brutos carregados de `data/ransom_dataset.csv`")

    col1, col2 = st.columns([0.3, 0.7])
    with col1:
        column = st.selectbox(
            "Coluna",
            [ALL_COLUMNS] + list(data.columns),
            key="ransom_dataset_column",
        )
    with col2:
        query = st.text_input("Termo de busca", key="ransom_dataset_query")

    filtered = filter_dataset(data, column, query)
    st.caption(f"{len(filtered)} registros encontrados")
    st.dataframe(filtered, hide_index=True)
    st.download_button(
        "📥 Baixar CSV",
        filtered.to_csv(index=False).encode("utf-8-sig"),
        file_name="ransom_dataset.csv",
        mime="text/csv",
    )
