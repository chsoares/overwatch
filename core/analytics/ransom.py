"""Pure ransom-aggregation ports of the legacy ``RansomAnalyzer``.

Every function takes an already-loaded DataFrame (see :func:`load_dataset`)
plus a normalized period dict and returns a DataFrame. No plotting, no file
writes, no config, no Streamlit.

Month labels emitted here are deterministic **English** names/abbreviations
(the golden oracle was captured in English). Localization for display belongs
to the presentation layer (``pages/``); this layer never calls ``locale``.
"""

from datetime import datetime, time

import pandas as pd

from core.analytics.common import (
    country_name,
    filter_periods,
    has_country_data,
    iso_frame,
    month_abbr,
    month_axis,
    month_name,
    month_to_timestamp,
    monthly_axis_end,
    normalize_iso2,
    require_data,
    selection_label,
    translate_sector,
)
from core.paths import DATA_DIR

TOP_N = 10


def load_dataset(path=None):
    """Load ``data/ransom_dataset.csv`` with parsed dates (legacy ``load_data``).

    ``path`` optionally overrides the source CSV.
    """
    if path is None:
        path = DATA_DIR / "ransom_dataset.csv"
    df = pd.read_csv(path)
    df["published"] = pd.to_datetime(df["published"], format="mixed")
    df["discovered"] = pd.to_datetime(df["discovered"], format="mixed")
    return df


def historical_series(df, period, iso2="BR", today=None):
    """Legacy ``analyze_series`` dashboard slice.

    ``today`` defaults to ``pd.Timestamp.today()`` and exists so tests can
    freeze the wall-clock cutoff; the default behavior is unchanged.
    """
    iso_list = normalize_iso2(iso2) or ["BR"]
    kind = period["type"]
    year, month = period["start"].year, period["start"].month

    plot_start_date = pd.Timestamp("2023-01-01")
    if kind == "annual":
        plot_end_date = pd.Timestamp(f"{year}-12-31")
    elif kind == "monthly":
        plot_end_date = (
            pd.Timestamp(f"{year}-{month:02d}-01") + pd.offsets.MonthEnd()
        )
    else:
        plot_end_date = pd.Timestamp(datetime.combine(period["end"], time.max))

    if today is None:
        today = pd.Timestamp.today()
    if plot_end_date > today:
        plot_end_date = today

    series_data = require_data(
        df[(df["published"] >= plot_start_date) & (df["published"] <= plot_end_date)].copy(),
        period,
    )
    series_data["year"] = series_data["published"].dt.year
    series_data["month"] = series_data["published"].dt.month.map(month_name)
    series_data["sigla"] = series_data["published"].dt.month.map(month_abbr)

    if kind == "custom":
        series_end = plot_end_date
    else:
        # Land inside the month holding ``plot_end_date`` so the axis never
        # appends a future zero month when ``plot_end_date`` was clamped to a
        # mid-month ``today`` (inheriting the start's time-of-day otherwise
        # admitted the next month-start boundary).
        series_end = (plot_end_date + pd.offsets.MonthEnd(0)).replace(
            hour=23, minute=59, second=59, microsecond=999999
        )
    all_months = month_axis(
        series_data["published"].min(), series_end, include_year=True
    )

    monthly_counts = (
        series_data.groupby(["year", "month", "sigla"]).size().reset_index(name="counts")
    )
    monthly_counts = all_months.merge(
        monthly_counts, how="left", on=["year", "month", "sigla"]
    ).fillna(0)

    series_data_br = series_data[series_data["country"].isin(iso_list)].copy()
    monthly_counts_br = (
        series_data_br.groupby(["year", "month", "sigla"])
        .size()
        .reset_index(name="counts")
    )
    monthly_counts_br = all_months.merge(
        monthly_counts_br, how="left", on=["year", "month", "sigla"]
    ).fillna(0)

    monthly_counts["month_order"] = monthly_counts["published"].dt.month
    monthly_counts = monthly_counts.sort_values(["year", "month_order"])
    monthly_counts_br["month_order"] = monthly_counts_br["published"].dt.month
    monthly_counts_br = monthly_counts_br.sort_values(["year", "month_order"])

    return pd.DataFrame(
        {
            "date": monthly_counts["published"],
            "world_attacks": monthly_counts["counts"],
            "country_attacks": monthly_counts_br["counts"],
            "month_label": monthly_counts["sigla"]
            + " "
            + monthly_counts["year"].astype(str),
        }
    )


def historical_series_multi(df, period, iso_list, today=None):
    """World series + selection-summed series + one series per selected country.

    Columns: ``date``, ``world_attacks``, ``selection_attacks``, then one column
    per ISO2 code (in the order given).
    """
    codes = normalize_iso2(iso_list)
    world = historical_series(df, period, iso2=None, today=today)
    result = pd.DataFrame({
        "date": world["date"],
        "world_attacks": world["world_attacks"],
    })
    if codes:
        selection = historical_series(df, period, iso2=codes, today=today)
        result["selection_attacks"] = selection["country_attacks"]
    else:
        result["selection_attacks"] = pd.Series(0, index=result.index)
    for code in codes:
        single = historical_series(df, period, iso2=[code], today=today)
        result[code] = single["country_attacks"]
    return result


def overview(df, period, iso2="BR"):
    """Legacy ``analyze_overview`` comparison table."""
    current, previous, _ = filter_periods(df, period)
    require_data(current, period)
    iso_list = normalize_iso2(iso2) or ["BR"]
    name = selection_label(iso_list, country_name)

    has_current_country = has_country_data(current, iso_list)
    has_previous_country = has_country_data(previous, iso_list)

    metrics = {
        "Ataques no período": len(current),
        "Ataques no período anterior": len(previous),
    }
    metrics["Delta de ataques"] = metrics["Ataques no período"] - metrics[
        "Ataques no período anterior"
    ]

    metrics_br = {}
    if has_current_country or has_previous_country:
        current_br = current[current["country"].isin(iso_list)]
        previous_br = previous[previous["country"].isin(iso_list)]
        metrics_br["Ataques no período"] = len(current_br)
        metrics_br["Ataques no período anterior"] = len(previous_br)
    else:
        current_br = pd.DataFrame()
        previous_br = pd.DataFrame()
        metrics_br["Ataques no período"] = 0
        metrics_br["Ataques no período anterior"] = 0
    metrics_br["Delta de ataques"] = (
        metrics_br["Ataques no período"] - metrics_br["Ataques no período anterior"]
    )

    kind = period["type"]
    year, month = period["start"].year, period["start"].month
    if kind == "annual":
        metrics["Média de ataques"] = len(current) / 12
        metrics["Média anterior"] = len(previous) / 12
        metrics_br["Média de ataques"] = len(current_br) / 12
        metrics_br["Média anterior"] = len(previous_br) / 12
    elif kind == "monthly":
        days_current = pd.Timestamp(f"{year}-{month}").days_in_month
        previous_date = pd.Timestamp(f"{year}-{month:02d}-01") - pd.offsets.MonthBegin()
        days_previous = previous_date.days_in_month
        metrics["Média de ataques"] = len(current) / days_current
        metrics["Média anterior"] = len(previous) / days_previous
        metrics_br["Média de ataques"] = len(current_br) / days_current
        metrics_br["Média anterior"] = len(previous_br) / days_previous
    else:
        start_date = pd.Timestamp(datetime.combine(period["start"], time.min))
        end_date = pd.Timestamp(datetime.combine(period["end"], time.max))
        delta_days = max((end_date - start_date).days, 1)
        if delta_days > 31:
            months_current = (
                (end_date.year - start_date.year) * 12
                + end_date.month
                - start_date.month
                + 1
            )
            metrics["Média de ataques"] = len(current) / months_current
            metrics["Média anterior"] = len(previous) / months_current
            metrics_br["Média de ataques"] = len(current_br) / months_current
            metrics_br["Média anterior"] = len(previous_br) / months_current
        else:
            metrics["Média de ataques"] = len(current) / delta_days
            metrics["Média anterior"] = len(previous) / delta_days
            metrics_br["Média de ataques"] = len(current_br) / delta_days
            metrics_br["Média anterior"] = len(previous_br) / delta_days

    metrics["Delta de média"] = metrics["Média de ataques"] - metrics["Média anterior"]
    metrics_br["Delta de média"] = (
        metrics_br["Média de ataques"] - metrics_br["Média anterior"]
    )

    metrics["Grupos ativos"] = current["group_name"].nunique()
    metrics["Grupos ativos anterior"] = previous["group_name"].nunique()
    metrics["Delta de grupos"] = (
        metrics["Grupos ativos"] - metrics["Grupos ativos anterior"]
    )
    if has_current_country:
        metrics_br["Grupos ativos"] = current_br["group_name"].nunique()
        metrics_br["Grupos ativos anterior"] = previous_br["group_name"].nunique()
    else:
        metrics_br["Grupos ativos"] = 0
        metrics_br["Grupos ativos anterior"] = 0
    metrics_br["Delta de grupos"] = (
        metrics_br["Grupos ativos"] - metrics_br["Grupos ativos anterior"]
    )

    return pd.DataFrame(
        {
            "Métrica": [
                "Ataques no período",
                "Ataques no período anterior",
                "Delta de ataques",
                "Média de ataques por período",
                "Média anterior por período",
                "Delta de média",
                "Grupos ativos",
                "Grupos ativos anterior",
                "Delta de grupos",
            ],
            "Mundo": [
                f"{metrics['Ataques no período']}",
                f"{metrics['Ataques no período anterior']}",
                f"{metrics['Delta de ataques']:+}",
                f"{metrics['Média de ataques']:.1f}",
                f"{metrics['Média anterior']:.1f}",
                f"{metrics['Delta de média']:+.1f}",
                f"{metrics['Grupos ativos']}",
                f"{metrics['Grupos ativos anterior']}",
                f"{metrics['Delta de grupos']:+}",
            ],
            name: [
                f"{metrics_br['Ataques no período']}",
                f"{metrics_br['Ataques no período anterior']}",
                f"{metrics_br['Delta de ataques']:+}",
                f"{metrics_br['Média de ataques']:.1f}",
                f"{metrics_br['Média anterior']:.1f}",
                f"{metrics_br['Delta de média']:+.1f}",
                f"{metrics_br['Grupos ativos']}",
                f"{metrics_br['Grupos ativos anterior']}",
                f"{metrics_br['Delta de grupos']:+}",
            ],
        }
    )


def monthly_attacks(df, period, iso2="BR"):
    """Legacy ``analyze_monthly`` dashboard slice."""
    _, _, monthly_data = filter_periods(df, period)
    require_data(monthly_data, period)
    iso_list = normalize_iso2(iso2) or ["BR"]

    monthly_data = monthly_data.sort_values("published").copy()
    monthly_data["year"] = monthly_data["published"].dt.year
    monthly_data["month"] = monthly_data["published"].dt.month.map(month_name)
    monthly_data["sigla"] = monthly_data["published"].dt.month.map(month_abbr)

    all_months = month_axis(
        monthly_data["published"].min(),
        monthly_axis_end(monthly_data["published"].max(), period),
        include_year=True,
    )

    monthly_counts = (
        monthly_data.groupby(["year", "month", "sigla"])
        .size()
        .reset_index(name="counts")
    )
    monthly_counts = (
        all_months[["year", "month", "sigla"]]
        .merge(monthly_counts, how="left", on=["year", "month", "sigla"])
        .fillna(0)
    )

    monthly_data_br = monthly_data[monthly_data["country"].isin(iso_list)]
    monthly_counts_br = (
        monthly_data_br.groupby(["year", "month", "sigla"])
        .size()
        .reset_index(name="counts")
    )
    monthly_counts_br = (
        all_months[["year", "month", "sigla"]]
        .merge(monthly_counts_br, how="left", on=["year", "month", "sigla"])
        .fillna(0)
    )

    return pd.DataFrame(
        {
            "date": all_months["published"],
            "world_attacks": monthly_counts["counts"],
            "country_attacks": monthly_counts_br["counts"],
            "month_label": monthly_counts["sigla"]
            + " "
            + all_months["published"].dt.year.astype(str),
        }
    )


def monthly_attacks_by_country(df, period, iso_list):
    """Monthly attack counts, one column per selected country.

    Returns a DataFrame with ``date`` plus one column per ISO2 code (in the
    order given), each holding that country's monthly counts over the same
    month axis as ``monthly_attacks``.
    """
    _, _, monthly_data = filter_periods(df, period)
    require_data(monthly_data, period)
    codes = normalize_iso2(iso_list)
    monthly_data = monthly_data.copy()
    monthly_data["year"] = monthly_data["published"].dt.year
    monthly_data["month"] = monthly_data["published"].dt.month.map(month_name)
    monthly_data["sigla"] = monthly_data["published"].dt.month.map(month_abbr)
    all_months = month_axis(
        monthly_data["published"].min(),
        monthly_axis_end(monthly_data["published"].max(), period),
        include_year=True,
    )
    result = {"date": all_months["published"]}
    for code in codes:
        subset = monthly_data[monthly_data["country"] == code]
        counts = subset.groupby(["year", "month", "sigla"]).size().reset_index(name=code)
        merged = all_months[["year", "month", "sigla"]].merge(
            counts, how="left", on=["year", "month", "sigla"]
        ).fillna(0)
        result[code] = merged[code]
    return pd.DataFrame(result)


def daily_heatmap(df, period, iso2=None):
    """Legacy ``analyze_daily`` dashboard slice (global or per country)."""
    kind = period["type"]
    year, month = period["start"].year, period["start"].month

    if kind == "annual":
        start = pd.Timestamp(f"{year}-01-01")
        end = pd.Timestamp(f"{year}-12-31")
    elif kind == "monthly":
        end = (
            pd.Timestamp(f"{year}-{month:02d}-01") + pd.offsets.MonthEnd()
        )
        start = (
            end - pd.DateOffset(months=12) + pd.DateOffset(months=1)
        ).replace(day=1)
    else:
        start = pd.Timestamp(datetime.combine(period["start"], time.min))
        end = pd.Timestamp(datetime.combine(period["end"], time.max))

    selected = require_data(
        df[(df["published"] >= start) & (df["published"] <= end)], period
    )
    iso_list = normalize_iso2(iso2)
    if iso_list:
        selected = selected[selected["country"].isin(iso_list)]
    if selected.empty:
        return pd.DataFrame(columns=["date", "day", "week", "count"])
    daily_counts = (
        selected["published"]
        .dt.floor("d")
        .value_counts()
        .rename_axis("date")
        .reset_index(name="count")
    )
    daily_counts["date"] = pd.to_datetime(daily_counts["date"])

    start_weekday = start.weekday()
    if start_weekday > 0:
        start_adjusted = start - pd.Timedelta(days=start_weekday)
    else:
        start_adjusted = start

    all_dates = pd.date_range(start=start_adjusted, end=end)
    heatmap_data = pd.DataFrame({"date": all_dates})
    heatmap_data = heatmap_data.merge(daily_counts, on="date", how="left").fillna(0)

    heatmap_data["day"] = heatmap_data["date"].dt.weekday
    heatmap_data["week"] = (heatmap_data["date"] - start_adjusted).dt.days // 7

    dashboard_data = heatmap_data.copy()
    dashboard_data["date"] = dashboard_data["date"].dt.strftime("%Y-%m-%d")
    return dashboard_data[["date", "day", "week", "count"]]


def _top_groups_frame(data):
    groups_count = data["group_name"].str.title().value_counts().reset_index()
    groups_count.columns = ["group_name", "counts"]
    groups_count["proportion"] = (
        groups_count["counts"] / groups_count["counts"].sum()
    ).round(3)
    return groups_count


def top_groups(df, period, iso2=None):
    """Legacy ``analyze_groups`` top-groups ranking (global or per country)."""
    current, _, _ = filter_periods(df, period)
    require_data(current, period)
    iso_list = normalize_iso2(iso2)
    if iso_list:
        current = current[current["country"].isin(iso_list)]
    if current.empty:
        return pd.DataFrame(columns=["group_name", "counts", "proportion"])
    return _top_groups_frame(current)


def monthly_group_activity(df, period, iso2=None):
    """Legacy ``analyze_groups`` monthly activity of the top groups (global or per country)."""
    current, _, monthly_data = filter_periods(df, period)
    kind = period["type"]
    year, month = period["start"].year, period["start"].month
    require_data(monthly_data, period)
    iso_list = normalize_iso2(iso2)
    if iso_list:
        current = current[current["country"].isin(iso_list)]
        monthly_data = monthly_data[monthly_data["country"].isin(iso_list)]
    if monthly_data.empty:
        return pd.DataFrame(columns=["date", "group_name", "attacks"])

    monthly_data = monthly_data.copy()
    monthly_data["year"] = monthly_data["published"].dt.year
    monthly_data["month"] = monthly_data["published"].dt.month.map(month_name)
    monthly_data["sigla"] = monthly_data["published"].dt.month.map(month_abbr)
    monthly_data["group_name"] = monthly_data["group_name"].str.title()

    all_months = month_axis(
        monthly_data["published"].min(),
        monthly_axis_end(monthly_data["published"].max(), period),
        include_year=True,
    )

    if kind == "monthly":
        last_month_data = monthly_data[
            (monthly_data["published"].dt.year == year)
            & (monthly_data["published"].dt.month == month)
        ]
        groups_count_period = last_month_data["group_name"].str.title().value_counts()
    else:
        groups_count_period = current["group_name"].str.title().value_counts()
    top = groups_count_period.head(TOP_N).index

    month_group_combinations = pd.DataFrame(
        [
            (month_year, name, sigla, group)
            for month_year, name, sigla in all_months[["year", "month", "sigla"]].values
            for group in top
        ],
        columns=["year", "month", "sigla", "group_name"],
    )

    monthly_group_counts = (
        monthly_data[monthly_data["group_name"].isin(top)]
        .groupby(["year", "month", "sigla", "group_name"])
        .size()
        .reset_index(name="counts")
    )
    monthly_group_counts = (
        month_group_combinations.merge(
            monthly_group_counts,
            how="left",
            on=["year", "month", "sigla", "group_name"],
        ).fillna(0)
    )
    monthly_group_counts["group_order"] = monthly_group_counts["group_name"].map(
        {name: i for i, name in enumerate(top)}
    )

    dashboard_data = monthly_group_counts.copy()
    dashboard_data["date"] = dashboard_data.apply(
        lambda row: month_to_timestamp(row["year"], row["month"]),
        axis=1,
    )
    dashboard_data = dashboard_data.rename(columns={"counts": "attacks"})
    return dashboard_data[["date", "group_name", "attacks"]]


def monthly_active_groups(df, period, iso2=None):
    """Legacy ``analyze_groups`` unique active groups per month (global or per country)."""
    _, _, monthly_data = filter_periods(df, period)
    require_data(monthly_data, period)
    iso_list = normalize_iso2(iso2)
    if iso_list:
        monthly_data = monthly_data[monthly_data["country"].isin(iso_list)]
    if monthly_data.empty:
        return pd.DataFrame(columns=["date", "active_groups"])
    monthly_data = monthly_data.copy()
    monthly_data["year"] = monthly_data["published"].dt.year
    monthly_data["sigla"] = monthly_data["published"].dt.month.map(month_abbr)

    active_monthly = monthly_data[["published", "group_name", "year", "sigla"]].copy()
    active_counts = (
        active_monthly.groupby(["year", "sigla"])["group_name"]
        .nunique()
        .reset_index(name="counts")
    )
    month_order = (
        monthly_data.groupby(["year", "sigla"])["published"].min().sort_values().index
    )
    active_counts = (
        active_counts.set_index(["year", "sigla"]).reindex(month_order).reset_index()
    )

    dashboard_data = active_counts.copy()
    dashboard_data["date"] = dashboard_data.apply(
        lambda row: month_to_timestamp(row["year"], row["sigla"]),
        axis=1,
    )
    dashboard_data = dashboard_data.rename(columns={"counts": "active_groups"})
    return dashboard_data[["date", "active_groups"]]


def countries(df, period):
    """Legacy ``analyze_countries`` attacks per country."""
    current, _, _ = filter_periods(df, period)
    require_data(current, period)
    country_counts = current["country"].value_counts().reset_index()
    country_counts.columns = ["ISO2", "counts"]
    country_counts = country_counts.merge(iso_frame(), how="left", on="ISO2").dropna()[
        ["country", "ISO3", "ISO2", "counts"]
    ]
    total_attacks = len(current)
    country_counts["proportion"] = (
        country_counts["counts"] / total_attacks
    ).round(3)
    return country_counts


def countries_selected(df, period, iso_list):
    """Attack counts for the selected countries only (ranking among them)."""
    current, _, _ = filter_periods(df, period)
    require_data(current, period)
    codes = normalize_iso2(iso_list)
    subset = current[current["country"].isin(codes)]
    country_counts = subset["country"].value_counts().reset_index()
    country_counts.columns = ["ISO2", "counts"]
    country_counts = country_counts.merge(
        iso_frame(), how="left", on="ISO2"
    ).dropna()[["country", "ISO3", "ISO2", "counts"]]
    total_attacks = len(subset)
    country_counts["proportion"] = (
        (country_counts["counts"] / total_attacks).round(3) if total_attacks > 0 else 0
    )
    return country_counts


def _translated(data):
    data = data.copy()
    data["activity_classified_pt"] = data["activity_classified"].apply(
        lambda x: translate_sector(x) if x != "Not Found" else x
    )
    return data


def world_sectors(df, period):
    """Legacy ``analyze_sectors`` global sector ranking."""
    current, _, _ = filter_periods(df, period)
    require_data(current, period)
    data = _translated(current)

    world_sectors = (
        data[data["activity_classified"] != "Not Found"]["activity_classified_pt"]
        .value_counts()
        .reset_index()
    )
    world_sectors.columns = ["sector", "attacks"]
    total_attacks = len(data[data["activity_classified"] != "Not Found"])
    world_sectors["proportion"] = (
        (world_sectors["attacks"] / total_attacks).round(3)
        if total_attacks > 0
        else 0
    )
    return world_sectors


def country_sectors(df, period, iso2):
    """Legacy ``analyze_sectors`` sector ranking for ``iso2``."""
    current, _, _ = filter_periods(df, period)
    require_data(current, period)
    data = _translated(current)

    country_mask = (data["country"].isin(normalize_iso2(iso2))) & (
        data["activity_classified"] != "Not Found"
    )
    country_sectors = data[country_mask]["activity_classified_pt"].value_counts().reset_index()
    country_sectors.columns = ["sector", "attacks"]
    total_attacks = len(data[country_mask])
    country_sectors["proportion"] = (
        (country_sectors["attacks"] / total_attacks).round(3)
        if total_attacks > 0
        else 0
    )
    return country_sectors


def group_overview(df, period, group):
    """Metrics for one group plus its share of the world total."""
    current, previous, _ = filter_periods(df, period)
    require_data(current, period)
    g = current[current["group_name"] == group]
    world_total = len(current)
    attacks = len(g)
    pct = (attacks / world_total) if world_total else 0.0
    n_countries = g["country"].nunique()
    sectors = g[g["activity_classified"] != "Not Found"][
        "activity_classified"
    ].nunique()
    first = g["published"].min() if not g.empty else pd.NaT
    last = g["published"].max() if not g.empty else pd.NaT
    prev_attacks = (
        int((previous["group_name"] == group).sum()) if not previous.empty else 0
    )
    return {
        "Ataques": attacks,
        "Ataques_anterior": prev_attacks,
        "% do mundo": pct,
        "Países": n_countries,
        "Setores": sectors,
        "Primeira atividade": first,
        "Última atividade": last,
        "has_previous": not previous.empty,
    }


def group_monthly(df, period, group):
    """Monthly attacks for one group. Columns: date, world_attacks, group_attacks."""
    _, _, monthly_data = filter_periods(df, period)
    require_data(monthly_data, period)
    monthly_data = monthly_data.copy()
    monthly_data["year"] = monthly_data["published"].dt.year
    monthly_data["month"] = monthly_data["published"].dt.month.map(month_name)
    monthly_data["sigla"] = monthly_data["published"].dt.month.map(month_abbr)
    all_months = month_axis(
        monthly_data["published"].min(),
        monthly_axis_end(monthly_data["published"].max(), period),
        include_year=True,
    )
    world = (
        monthly_data.groupby(["year", "month", "sigla"]).size().reset_index(name="world_attacks")
    )
    world = all_months[["year", "month", "sigla"]].merge(
        world, how="left", on=["year", "month", "sigla"]
    ).fillna(0)
    grp = monthly_data[monthly_data["group_name"] == group]
    grp = (
        grp.groupby(["year", "month", "sigla"]).size().reset_index(name="group_attacks")
    )
    grp = all_months[["year", "month", "sigla"]].merge(
        grp, how="left", on=["year", "month", "sigla"]
    ).fillna(0)
    return pd.DataFrame(
        {
            "date": all_months["published"],
            "world_attacks": world["world_attacks"],
            "group_attacks": grp["group_attacks"],
        }
    )


def group_countries(df, period, group):
    """Per-country attack counts for one group (shape of ``countries``)."""
    current, _, _ = filter_periods(df, period)
    require_data(current, period)
    g = current[current["group_name"] == group]
    counts = g["country"].value_counts().reset_index()
    counts.columns = ["ISO2", "counts"]
    counts = counts.merge(iso_frame(), how="left", on="ISO2").dropna()[
        ["country", "ISO3", "ISO2", "counts"]
    ]
    total = len(g)
    counts["proportion"] = (counts["counts"] / total).round(3) if total else 0
    return counts


def group_sectors(df, period, group):
    """Per-sector counts for one group (shape of ``world_sectors``)."""
    current, _, _ = filter_periods(df, period)
    require_data(current, period)
    data = _translated(current)
    g = data[(data["group_name"] == group) & (data["activity_classified"] != "Not Found")]
    sectors = g["activity_classified_pt"].value_counts().reset_index()
    sectors.columns = ["sector", "attacks"]
    total = len(g)
    sectors["proportion"] = (sectors["attacks"] / total).round(3) if total else 0
    return sectors


def distinct_countries_by_month(df, period, group):
    """Distinct countries attacked per month by one group."""
    _, _, monthly_data = filter_periods(df, period)
    require_data(monthly_data, period)
    monthly_data = monthly_data.copy()
    monthly_data["year"] = monthly_data["published"].dt.year
    monthly_data["sigla"] = monthly_data["published"].dt.month.map(month_abbr)
    g = monthly_data[monthly_data["group_name"] == group]
    if g.empty:
        return pd.DataFrame(columns=["date", "distinct_countries"])
    counts = (
        g.groupby(["year", "sigla"])["country"]
        .nunique()
        .reset_index(name="distinct_countries")
    )
    counts["date"] = counts.apply(
        lambda r: month_to_timestamp(r["year"], r["sigla"]), axis=1
    )
    return counts[["date", "distinct_countries"]].sort_values("date").reset_index(drop=True)


def distinct_sectors_by_month(df, period, group):
    """Distinct sectors attacked per month by one group."""
    _, _, monthly_data = filter_periods(df, period)
    require_data(monthly_data, period)
    monthly_data = monthly_data.copy()
    monthly_data["year"] = monthly_data["published"].dt.year
    monthly_data["sigla"] = monthly_data["published"].dt.month.map(month_abbr)
    g = monthly_data[
        (monthly_data["group_name"] == group)
        & (monthly_data["activity_classified"] != "Not Found")
    ]
    if g.empty:
        return pd.DataFrame(columns=["date", "distinct_sectors"])
    counts = (
        g.groupby(["year", "sigla"])["activity_classified"]
        .nunique()
        .reset_index(name="distinct_sectors")
    )
    counts["date"] = counts.apply(
        lambda r: month_to_timestamp(r["year"], r["sigla"]), axis=1
    )
    return counts[["date", "distinct_sectors"]].sort_values("date").reset_index(drop=True)


def group_historical_series(df, period, group, today=None):
    """World series + one-group series. Columns: date, world_attacks, group_attacks."""
    world = historical_series(df, period, iso2=None, today=today)
    dates = world["date"]
    labels = pd.to_datetime(dates)
    year = labels.dt.year
    sigla = labels.dt.month.map(month_abbr)
    gm = df[df["group_name"] == group].copy()
    gm["year"] = gm["published"].dt.year
    gm["sigla"] = gm["published"].dt.month.map(month_abbr)
    counts = gm.groupby(["year", "sigla"]).size().reset_index(name="group_attacks")
    merged = (
        pd.DataFrame({"year": year, "sigla": sigla})
        .merge(counts, how="left", on=["year", "sigla"])
        .fillna(0)
    )
    return pd.DataFrame(
        {
            "date": dates,
            "world_attacks": world["world_attacks"],
            "group_attacks": merged["group_attacks"].astype(int),
        }
    )


def victims_table(df, period, iso2):
    """Legacy ``analyze_victims`` victim listing for ``iso2``."""
    current, _, _ = filter_periods(df, period)
    require_data(current, period)
    iso_list = normalize_iso2(iso2)
    if not has_country_data(current, iso_list):
        return pd.DataFrame(columns=["Vítima", "Setor", "Grupo", "Data do anúncio"])

    data = current.copy()
    data["activity_classified"] = data["activity_classified"].apply(
        lambda x: translate_sector(x) if x != "Not Found" else "Não Encontrado"
    )
    victims = data[data["country"].isin(iso_list)][
        ["post_title", "activity_classified", "group_name", "published"]
    ].copy()
    victims = victims.sort_values("published")
    published = victims["published"]
    victims["published"] = (
        published.dt.day.astype(str).str.zfill(2)
        + " "
        + published.dt.month.map(month_abbr)
        + ". "
        + published.dt.year.astype(str)
    ).str.replace(" 0", " ").str.lower()
    victims.columns = ["Vítima", "Setor", "Grupo", "Data do anúncio"]
    victims["Grupo"] = victims["Grupo"].str.title()
    return victims
