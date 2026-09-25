#!/usr/bin/env python3
"""Ransomware dashboard page backed by the live analytics layer."""

from datetime import date

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from plotly.subplots import make_subplots

from core.analytics import ransom
from core.analytics.common import (
    EmptyPeriodError,
    country_name,
    filter_periods,
    month_abbr,
    selection_label,
    translate_sector,
)
from core.charts import horizontal_bar, line_with_mean
from core.dataset import ALL_COLUMNS, filter_dataset
from core.filters import (
    country_widget,
    group_widget,
    normalize_period,
    period_widget,
)
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
_COLOR_WORLD = "firebrick"
_COLOR_SELECTION = "green"
_COLORWAY_HISTORY_COUNTRY = [
    "darkslateblue", "darkorange", "teal", "rebeccapurple", "royalblue",
    "midnightblue", "darkcyan", "slategray", "sienna", "orchid",
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
                line=dict(width=3, shape="linear"),
                marker=dict(size=7),
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


def country_series_chart(series, name_fn):
    series = series.copy()
    series["month_label"] = month_labels(series["date"])
    fig = go.Figure()
    for code in series.columns:
        if code in ("date", "month_label"):
            continue
        label = name_fn(code)
        fig.add_trace(
            go.Scatter(
                x=series["month_label"],
                y=series[code],
                name=label,
                mode="lines+markers",
                line=dict(width=3, shape="linear"),
                marker=dict(size=7),
                hovertemplate="<b>%{x}</b><br>" + label
                + "<br>Incidentes: %{y}<extra></extra>",
            )
        )
    fig.update_layout(
        showlegend=True,
        colorway=_COLORWAY_COUNTRY,
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
    return fig


def choropleth_chart(countries, colorscale="reds"):
    data = countries.copy()
    data["log_counts"] = np.log1p(data["counts"])
    text = data["country"] + "<br>Incidentes: " + data["counts"].astype(str)
    fig = go.Figure(
        go.Choropleth(
            locations=data["ISO3"],
            z=data["log_counts"],
            text=text,
            colorscale=colorscale,
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


def historical_series_multi_chart(series, name_fn):
    labels = month_labels(series["date"])
    codes = [
        column
        for column in series.columns
        if column not in ("date", "world_attacks", "selection_attacks")
    ]
    fig = make_subplots(specs=[[{"secondary_y": True}]])
    fig.add_trace(
        go.Scatter(
            x=labels,
            y=series["world_attacks"],
            name="Mundo",
            line=dict(color=_COLOR_WORLD, width=3),
            mode="lines+markers",
        ),
        secondary_y=False,
    )
    fig.add_trace(
        go.Scatter(
            x=labels,
            y=series["selection_attacks"],
            name="países selecionados",
            line=dict(color=_COLOR_SELECTION, width=3),
            mode="lines+markers",
        ),
        secondary_y=True,
    )
    for index, code in enumerate(codes):
        label = name_fn(code)
        fig.add_trace(
            go.Scatter(
                x=labels,
                y=series[code],
                name=label,
                line=dict(
                    color=_COLORWAY_HISTORY_COUNTRY[
                        index % len(_COLORWAY_HISTORY_COUNTRY)
                    ],
                    width=3,
                    dash="dash",
                ),
                mode="lines+markers",
                hovertemplate="<b>%{x}</b><br>" + label
                + "<br>Incidentes: %{y}<extra></extra>",
            ),
            secondary_y=True,
        )

    world_max = series["world_attacks"].max()
    right_columns = ["selection_attacks"] + codes
    right_max = series[right_columns].to_numpy().max()
    y1_max = world_max * 1.1 if world_max else 5
    y2_max = right_max * 1.1 if right_max else 5

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
        title_font=dict(color=_COLOR_WORLD),
        range=[0, y1_max],
    )
    fig.update_yaxes(
        title_text="Incidentes nos países selecionados",
        secondary_y=True,
        showgrid=False,
        title_font=dict(color=_COLOR_SELECTION),
        range=[0, y2_max],
    )
    return fig


def has_previous_period(overview):
    """Whether ``overview`` holds a non-empty previous period.

    The overview reports ``Ataques no período anterior`` as ``len(previous)``,
    so a positive value means a real baseline exists. Period type ``total``
    slices an empty previous by design; gating the deltas on this keeps
    ``format_delta`` from inventing ``+N`` / ``+∞%`` against a zero baseline.
    """
    previous = overview.loc[
        overview["Métrica"] == "Ataques no período anterior", "Mundo"
    ].iloc[0]
    return int(previous) > 0


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
    has_previous = has_previous_period(overview)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        delta = format_delta(world_current, world_previous, mode, has_previous)
        st.metric("Ataques no mundo", str(world_current), delta,
                  delta_color=delta_color(delta), border=True)
    with col2:
        delta = format_delta(country_current, country_previous, mode, has_previous)
        st.metric(f"Ataques em {name}", str(country_current), delta,
                  delta_color=delta_color(delta), border=True)
    with col3:
        delta = format_delta(groups_current, groups_previous, mode, has_previous)
        st.metric("Grupos ativos", str(groups_current), delta,
                  delta_color=delta_color(delta), border=True)
    with col4:
        if world_groups.empty:
            st.metric("Grupo mais ativo", "—", "Sem dados", delta_color="off", border=True)
        else:
            top = world_groups.sort_values("counts", ascending=False).iloc[0]
            st.metric("Grupo mais ativo", top["group_name"],
                      f"{int(top['counts'])} ataques", delta_color="off", border=True)


def victims_with_country(data, period, victims, iso_list):
    """Attach the source country to a ``victims_table`` frame for several countries.

    ``victims_table`` preserves the source frame index, so the country is
    resolved by label against the same period slice.
    """
    if len(iso_list) < 2 or victims.empty:
        return victims
    current, _, _ = filter_periods(data, period)
    if not current.index.is_unique or not victims.index.isin(current.index).all():
        return victims
    display = victims.copy()
    display.insert(1, "País", current.loc[display.index, "country"].map(country_name))
    return display


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


def render_monthly_attacks(monthly, name, by_country=None):
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
    if by_country is not None:
        with st.container(border=True):
            st.write("###### Por país selecionado")
            st.plotly_chart(country_series_chart(by_country, country_name))


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


def render_countries(countries, selected=None):
    st.subheader("Países mais afetados")
    st.caption(
        "Países com maior número de vítimas de ransomware anunciadas durante o período"
    )
    if selected is None:
        with st.container(border=True):
            st.plotly_chart(
                horizontal_bar(countries, "counts", "country", "midnightblue",
                               hover_label="Incidentes"),
            )
        return
    col1, col2 = st.columns(2, border=True)
    with col1:
        st.write("###### No mundo")
        if countries.empty:
            st.info("Sem dados para o período")
        else:
            st.plotly_chart(
                horizontal_bar(countries, "counts", "country", "midnightblue",
                               hover_label="Incidentes"),
            )
    with col2:
        st.write("###### Nos países selecionados")
        if selected.empty:
            st.info("Sem dados para o período")
        else:
            st.plotly_chart(
                horizontal_bar(selected, "counts", "country", "teal",
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


def render_historical_series(series, name, multi_series=None):
    st.subheader("Série histórica")
    st.caption(
        f"Evolução do número de ataques ransomware no mundo e em {name} "
        "desde o início da coleta de dados"
    )
    with st.container(border=True):
        if multi_series is not None:
            st.plotly_chart(historical_series_multi_chart(multi_series, country_name))
        else:
            st.plotly_chart(historical_series_chart(series, name))


def _format_activity(value):
    if value is None or pd.isna(value):
        return "—"
    return pd.Timestamp(value).strftime("%d/%m/%Y")


def group_victims(data, period, group):
    """Group-filtered victim listing with a ``País`` column.

    Mirrors ``ransom.victims_table`` presentation (sector translation and
    lowercased ``dd Mmm. yyyy`` dates) while adding the source country and
    restricting the rows to one attacker group. Kept page-local so the
    analytics layer stays untouched.
    """
    columns = ["Vítima", "País", "Setor", "Grupo", "Data"]
    current, _, _ = filter_periods(data, period)
    subset = current[current["group_name"] == group]
    if subset.empty:
        return pd.DataFrame(columns=columns)
    subset = subset.copy()
    subset["activity_classified"] = subset["activity_classified"].apply(
        lambda x: translate_sector(x) if x != "Not Found" else "Não Encontrado"
    )
    victims = subset.sort_values("published")[
        ["post_title", "country", "activity_classified", "group_name", "published"]
    ].copy()
    published = victims["published"]
    victims["published"] = (
        published.dt.day.astype(str).str.zfill(2)
        + " "
        + published.dt.month.map(month_abbr)
        + ". "
        + published.dt.year.astype(str)
    ).str.replace(" 0", " ").str.lower()
    victims["country"] = victims["country"].map(country_name).fillna("—")
    victims["group_name"] = victims["group_name"].str.title()
    victims.columns = columns
    return victims


def render_group_metrics(overview, group):
    st.subheader("Métricas")
    st.caption(
        f"Indicadores de {group} no período e participação no total anunciado"
    )
    has_previous = overview["has_previous"]
    attacks = int(overview["Ataques"])
    previous = int(overview["Ataques_anterior"])
    attacks_delta = format_delta(attacks, previous, "Absoluta", has_previous)

    pct = float(overview["% do mundo"]) * 100
    pct_previous = float(overview["% do mundo_anterior"]) * 100
    if has_previous:
        pct_delta = f"{pct - pct_previous:+.1f}"
    else:
        pct_delta = None

    countries = int(overview["Países"])
    countries_previous = int(overview["Países_anterior"])
    countries_delta = format_delta(countries, countries_previous, "Absoluta", has_previous)

    sectors = int(overview["Setores"])
    sectors_previous = int(overview["Setores_anterior"])
    sectors_delta = format_delta(sectors, sectors_previous, "Absoluta", has_previous)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Ataques", str(attacks), attacks_delta,
                  delta_color=delta_color(attacks_delta), border=True)
    with col2:
        st.metric("% do mundo", f"{pct:.1f}%", pct_delta,
                  delta_color=delta_color(pct_delta), border=True)
    with col3:
        st.metric("Países", str(countries), countries_delta,
                  delta_color=delta_color(countries_delta), border=True)
    with col4:
        st.metric("Setores", str(sectors), sectors_delta,
                  delta_color=delta_color(sectors_delta), border=True)

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Primeira atividade",
                  _format_activity(overview["Primeira atividade"]), border=True)
    with col2:
        st.metric("Última atividade",
                  _format_activity(overview["Última atividade"]), border=True)


def render_group_victims(victims, group):
    st.subheader("Vítimas")
    st.caption(f"Ataques a instituições anunciadas por {group} no período")
    if victims.empty:
        st.info("Sem dados para o período")
        return
    display = victims.copy()
    display["Data"] = localize_victim_dates(display["Data"])
    st.dataframe(display, hide_index=True)


def render_group_monthly(monthly, group):
    st.subheader("Ataques mensais")
    st.caption(
        "Evolução do número de ataques ransomware anunciados ao longo dos últimos meses"
    )
    labels = month_labels(monthly["date"])
    col1, col2 = st.columns(2, border=True)
    with col1:
        st.write(f"###### {group}")
        if monthly["group_attacks"].sum() > 0:
            st.plotly_chart(
                line_with_mean(labels, monthly["group_attacks"], group, "green",
                               hover="Incidentes: %{y}<extra></extra>",
                               mean=monthly["group_attacks"].mean()),
            )
        else:
            st.info("Sem dados para o período")
    with col2:
        st.write("###### Todos os grupos")
        st.plotly_chart(
            line_with_mean(labels, monthly["world_attacks"], "Todos os grupos",
                           _COLOR_WORLD,
                           hover="Incidentes: %{y}<extra></extra>",
                           mean=monthly["world_attacks"].mean()),
        )


def render_group_countries(world_countries, group_countries, distinct, group):
    st.subheader("Países mais afetados")
    st.caption(
        "Países com maior número de vítimas de ransomware anunciadas durante o período"
    )
    col1, col2 = st.columns(2, border=True)
    with col1:
        st.write(f"###### {group}")
        if group_countries.empty:
            st.info("Sem dados para o período")
        else:
            st.plotly_chart(
                horizontal_bar(group_countries, "counts", "country", "teal",
                               hover_label="Incidentes"),
            )
    with col2:
        st.write("###### Todos os grupos")
        if world_countries.empty:
            st.info("Sem dados para o período")
        else:
            st.plotly_chart(
                horizontal_bar(world_countries, "counts", "country", "midnightblue",
                               hover_label="Incidentes"),
            )
    with st.container(border=True):
        st.write("###### Países distintos atacados por mês")
        if distinct.empty:
            st.info("Sem dados para o período")
        else:
            labels = month_labels(distinct["date"])
            mean_distinct = distinct["distinct_countries"].mean()
            st.plotly_chart(
                line_with_mean(labels, distinct["distinct_countries"],
                               "Países distintos", "royalblue",
                               mean=mean_distinct, mean_color="lightskyblue",
                               hover="Países: %{y}<extra></extra>",
                               y_range=[0, mean_distinct * 1.6 if mean_distinct else 5],
                               height=300),
            )


def render_group_geography(world_countries, group_countries, group):
    st.subheader("Distribuição geográfica dos ataques")
    st.caption(
        "Todos os países com pelo menos um ataque anunciado durante o período, "
        "em escala logarítmica"
    )
    col1, col2 = st.columns(2, border=True)
    with col1:
        st.write(f"###### {group}")
        if group_countries.empty:
            st.info("Sem dados para o período")
        else:
            st.plotly_chart(choropleth_chart(group_countries, colorscale="blues"))
    with col2:
        st.write("###### Todos os grupos")
        st.plotly_chart(choropleth_chart(world_countries))


def render_group_sectors(world_sectors, group_sectors, distinct, group):
    st.subheader("Setores mais atacados")
    st.caption(
        "Setores econômicos com maior número de vítimas anunciadas durante o período"
    )
    col1, col2 = st.columns(2, border=True)
    with col1:
        st.write(f"###### {group}")
        if group_sectors.empty:
            st.info("Sem dados para o período")
        else:
            st.plotly_chart(
                horizontal_bar(group_sectors, "attacks", "sector", "royalblue",
                               hover_label="Incidentes"),
            )
    with col2:
        st.write("###### Todos os grupos")
        if world_sectors.empty:
            st.info("Sem dados para o período")
        else:
            st.plotly_chart(
                horizontal_bar(world_sectors, "attacks", "sector", "orangered",
                               hover_label="Incidentes"),
            )
    with st.container(border=True):
        st.write("###### Setores distintos atacados por mês")
        if distinct.empty:
            st.info("Sem dados para o período")
        else:
            labels = month_labels(distinct["date"])
            mean_distinct = distinct["distinct_sectors"].mean()
            st.plotly_chart(
                line_with_mean(labels, distinct["distinct_sectors"],
                               "Setores distintos", "darkorange",
                               mean=mean_distinct, mean_color="navajowhite",
                               hover="Setores: %{y}<extra></extra>",
                               y_range=[0, mean_distinct * 1.6 if mean_distinct else 5],
                               height=300),
            )


def render_group_daily_heatmap(world, period):
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


def group_historical_chart(series, group):
    labels = month_labels(series["date"])
    fig = make_subplots(specs=[[{"secondary_y": True}]])
    fig.add_trace(
        go.Scatter(
            x=labels,
            y=series["world_attacks"],
            name="Todos os grupos",
            line=dict(color=_COLOR_WORLD, width=3),
            mode="lines+markers",
        ),
        secondary_y=False,
    )
    fig.add_trace(
        go.Scatter(
            x=labels,
            y=series["group_attacks"],
            name=group,
            line=dict(color="green", width=3),
            mode="lines+markers",
        ),
        secondary_y=True,
    )

    world_max = series["world_attacks"].max()
    group_max = series["group_attacks"].max()
    y1_max = world_max * 1.1 if world_max else 5
    if group_max == 0:
        y2_max = 5
    else:
        world_scale = y1_max / world_max if world_max else 1
        ratio = 6 if group_max < world_max * 0.1 else 2
        y2_max = group_max * ratio * world_scale

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
        title_font=dict(color=_COLOR_WORLD),
        range=[0, y1_max],
    )
    fig.update_yaxes(
        title_text=f"Incidentes em {group}",
        secondary_y=True,
        showgrid=False,
        title_font=dict(color="green"),
        range=[0, y2_max],
    )
    return fig


def render_group_historical(series, group):
    st.subheader("Série histórica")
    st.caption(
        f"Evolução do número de ataques ransomware no mundo e por {group} "
        "desde o início da coleta de dados"
    )
    with st.container(border=True):
        st.plotly_chart(group_historical_chart(series, group))


data = load_dataset()

min_date = data["published"].min().date()
max_date = data["published"].max().date()

st.sidebar.caption("Configurações")
st.sidebar.subheader("Tipo de análise")
analysis_type = st.sidebar.selectbox(
    "Tipo de análise", ["Geográfica", "Atacante"], key="ransom_analysis"
)
st.sidebar.subheader("Período")
period = normalize_period(period_widget("ransom", min_date, max_date))

if analysis_type == "Atacante":
    default_group = data["group_name"].value_counts().idxmax()
    st.sidebar.subheader("Grupo")
    group = group_widget(
        "ransom", data["group_name"].dropna().unique(), default=default_group
    )
else:
    st.sidebar.subheader("País")
    iso_list = country_widget("ransom", default="BR")
    name = selection_label(iso_list, country_name)
    multi_country = len(iso_list) >= 2

try:
    if analysis_type == "Atacante":
        group_metrics = ransom.group_overview(data, period, group)
        group_monthly_data = ransom.group_monthly(data, period, group)
        group_countries_data = ransom.group_countries(data, period, group)
        group_sectors_data = ransom.group_sectors(data, period, group)
        distinct_countries_data = ransom.distinct_countries_by_month(data, period, group)
        distinct_sectors_data = ransom.distinct_sectors_by_month(data, period, group)
        group_historical_data = ransom.group_historical_series(data, period, group)
        group_victims_data = group_victims(data, period, group)
        world_countries = ransom.countries(data, period)
        world_sectors = ransom.world_sectors(data, period)
        heatmap = ransom.daily_heatmap(data, period)
    else:
        overview = ransom.overview(data, period, iso_list)
        monthly = ransom.monthly_attacks(data, period, iso_list)
        historical = ransom.historical_series(data, period, iso_list)
        world_groups = ransom.top_groups(data, period, iso2=None)
        country_groups = ransom.top_groups(data, period, iso2=iso_list)
        group_activity = ransom.monthly_group_activity(data, period)
        group_activity_country = ransom.monthly_group_activity(data, period, iso2=iso_list)
        active_groups = ransom.monthly_active_groups(data, period)
        active_groups_country = ransom.monthly_active_groups(data, period, iso2=iso_list)
        countries = ransom.countries(data, period)
        world_sectors = ransom.world_sectors(data, period)
        country_sectors = ransom.country_sectors(data, period, iso_list)
        victims = ransom.victims_table(data, period, iso_list)
        heatmap = ransom.daily_heatmap(data, period)
        heatmap_country = ransom.daily_heatmap(data, period, iso2=iso_list)
        if multi_country:
            monthly_by_country = ransom.monthly_attacks_by_country(data, period, iso_list)
            countries_selected_frame = ransom.countries_selected(data, period, iso_list)
            historical_multi = ransom.historical_series_multi(data, period, iso_list)
            victims_display = victims_with_country(data, period, victims, iso_list)
        else:
            monthly_by_country = None
            countries_selected_frame = None
            historical_multi = None
            victims_display = victims
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
    if analysis_type == "Atacante":
        render_group_metrics(group_metrics, group)

        st.write("")
        render_group_victims(group_victims_data, group)

        st.write("")
        render_group_monthly(group_monthly_data, group)

        st.write("")
        render_group_countries(
            world_countries, group_countries_data, distinct_countries_data, group
        )

        st.write("")
        render_group_geography(world_countries, group_countries_data, group)

        st.write("")
        render_group_sectors(
            world_sectors, group_sectors_data, distinct_sectors_data, group
        )

        st.write("")
        render_group_daily_heatmap(heatmap, period)

        st.write("")
        render_group_historical(group_historical_data, group)
    else:
        render_overview(overview, world_groups, name)

        st.write("")
        render_victims(victims_display, name)

        st.write("")
        render_monthly_attacks(monthly, name, by_country=monthly_by_country)

        st.write("")
        render_groups(world_groups, country_groups, name)

        st.write("")
        render_group_activity(group_activity, group_activity_country, name)

        st.write("")
        render_active_groups(active_groups, active_groups_country, name)

        st.write("")
        render_countries(countries, selected=countries_selected_frame)

        st.write("")
        render_geography(countries)

        st.write("")
        render_sectors(world_sectors, country_sectors, name)

        st.write("")
        render_daily_heatmap(heatmap, heatmap_country, period, name)

        st.write("")
        render_historical_series(historical, name, multi_series=historical_multi)

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
