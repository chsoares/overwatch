"""Pure vulnerability-analytics ports of the legacy ``VulnAnalyzer``.

Every function takes an already-loaded DataFrame (see :func:`load_dataset`)
plus a normalized period dict and returns a DataFrame. No plotting, no file
writes, no config, no Streamlit.

Month labels emitted here are deterministic **English** abbreviations built
from the numeric month (the golden oracle was captured in English). Display
localization belongs to the presentation layer (``pages/``); this layer never
calls ``locale`` or ``strftime``.
"""

import pandas as pd

from core.analytics.common import (
    filter_periods,
    month_abbr,
    month_name,
    require_data,
)
from core.paths import DATA_DIR

RISK_TRANSLATIONS = {
    "High": "Alto",
    "Medium": "Médio",
    "Low": "Baixo",
    "Critical": "Crítico",
}

RISK_ORDER = ["Baixo", "Médio", "Alto", "Crítico"]


def load_dataset(path=None):
    """Load ``data/vuln_dataset.csv`` with parsed dates (legacy ``load_data``).

    ``path`` optionally overrides the source CSV.
    """
    if path is None:
        path = DATA_DIR / "vuln_dataset.csv"
    df = pd.read_csv(path)
    df["dateAdded"] = pd.to_datetime(df["dateAdded"], format="mixed")
    return df


def _overview_table(data):
    """Build the legacy overview/previous table for a data slice."""
    overview_table = pd.DataFrame(
        {
            "Número de CVEs": [len(data)],
            "CVEs de risco crítico": [(data["risk"] == "Critical").sum()],
            "CVEs com exploits públicos disponíveis": [(data["exploit"] == "Yes").sum()],
            "CVEs associadas a campanhas de ransomware": [
                (data["ransomCampaign"] == "Known").sum()
            ],
            "CVSS médio": [data["cvss"].mean()],
            "EPSS médio": [data["epss"].mean()],
        }
    )

    overview_table = overview_table.T.rename(columns={0: "Valor"})
    overview_table.index.name = "Métrica"
    overview_table = overview_table.reset_index()

    # Cast to object up front so the formatted-string assignments below stay
    # dtype-safe: assigning a str into a float column is deprecated in pandas
    # 2.3 and would otherwise emit a FutureWarning (and eventually raise).
    overview_table["Valor"] = overview_table["Valor"].astype(object)

    cvss_mask = overview_table["Métrica"] == "CVSS médio"
    overview_table.loc[cvss_mask, "Valor"] = (
        f"{overview_table.loc[cvss_mask, 'Valor'].iloc[0]:.1f}"
    )
    epss_mask = overview_table["Métrica"] == "EPSS médio"
    # An empty slice formats as the literal legacy parity strings "nan"/"nan%".
    overview_table.loc[epss_mask, "Valor"] = (
        f"{float(overview_table.loc[epss_mask, 'Valor'].iloc[0]) * 100:.1f}%"
    )
    return overview_table


def overview(df, period):
    """Legacy ``analyze_overview`` current-period table.

    The current slice drives the empty-period gate: :func:`require_data` raises
    :class:`~core.analytics.common.EmptyPeriodError` when the period has no rows.
    """
    current, _, _ = filter_periods(df, period, date_col="dateAdded")
    require_data(current, period)
    return _overview_table(current)


def overview_previous(df, period):
    """Legacy ``analyze_overview`` previous-period table.

    The **current** slice drives the empty-period gate, mirroring
    :func:`overview` and ``core.analytics.ransom.overview``: previous-only
    access is intentionally unsupported, so a period whose current slice is
    empty raises even when its previous slice holds rows.

    A non-empty current period with an empty previous slice yields the legacy
    parity values ``"0.0"`` for the counts and ``"nan"`` / ``"nan%"`` for the
    CVSS/EPSS means (see :func:`_overview_table`).
    """
    current, previous, _ = filter_periods(df, period, date_col="dateAdded")
    require_data(current, period)
    return _overview_table(previous)


def risk_bars(df, period):
    """Legacy ``analyze_risk`` stacked-bar dashboard slice.

    The legacy ``analyze_risk`` builds a wider intermediate frame carrying
    ``Quantidade``/``Exploit``/``Ransomware`` before exporting only
    ``Risco``/``Proporção``. This port skips the unused columns; only the
    proportions (zero-filled for absent severity levels) are reproduced.
    """
    current, _, _ = filter_periods(df, period, date_col="dateAdded")
    require_data(current, period)

    risk_counts = current["risk"].value_counts()
    risk_counts.index = risk_counts.index.map(RISK_TRANSLATIONS)

    proportions = risk_counts / risk_counts.sum()
    proportions = proportions.reindex(RISK_ORDER)

    return pd.DataFrame(
        {
            "Risco": proportions.index,
            "Proporção": proportions.fillna(0),
        }
    )


def exploit_scatter(df, period):
    """Legacy ``analyze_exploits`` scatter dashboard slice."""
    current, _, _ = filter_periods(df, period, date_col="dateAdded")
    require_data(current, period)

    scatter_exploit = current[["cveID", "cvss", "epss", "exploit"]].copy()
    scatter_exploit["epss"] = scatter_exploit["epss"] * 100
    return scatter_exploit.sort_values(by="exploit", ascending=False)


def ransom_scatter(df, period):
    """Legacy ``analyze_ransomware`` scatter dashboard slice."""
    current, _, _ = filter_periods(df, period, date_col="dateAdded")
    require_data(current, period)

    scatter_ransom = current[["cveID", "cvss", "epss", "ransomCampaign"]].copy()
    scatter_ransom["epss"] = scatter_ransom["epss"] * 100
    return scatter_ransom.sort_values(by="ransomCampaign", ascending=False)


def vendor_breakdown(df, period):
    """Legacy ``analyze_vendors`` dashboard/export slice.

    Groups the current period by ``vendorProject`` and returns one row per
    vendor with CVE counts, mean CVSS/EPSS and exploit/ransomware counts,
    sorted by CVE count (descending).
    """
    current, _, _ = filter_periods(df, period, date_col="dateAdded")
    require_data(current, period)

    grouped = (
        current.groupby("vendorProject")
        .agg(
            CVEs=("cveID", "count"),
            **{"CVSS Médio": ("cvss", "mean"), "EPSS Médio": ("epss", "mean")},
            Exploit=("exploit", lambda values: (values == "Yes").sum()),
            Ransomware=("ransomCampaign", lambda values: (values == "Known").sum()),
        )
        .reset_index()
        .rename(columns={"vendorProject": "Empresa"})
        .sort_values("CVEs", ascending=False)
        .reset_index(drop=True)
    )
    return grouped[
        ["Empresa", "CVEs", "CVSS Médio", "EPSS Médio", "Exploit", "Ransomware"]
    ]


def monthly_vulns(df, period):
    """Legacy ``analyze_monthly`` monthly-distribution dashboard slice."""
    _, _, monthly_data = filter_periods(df, period, date_col="dateAdded")
    require_data(monthly_data, period)

    kind = period["type"]
    year, month = period["start"].year, period["start"].month

    if kind == "annual":
        start_date = pd.Timestamp(f"{year}-01-01")
        end_date = pd.Timestamp(f"{year}-12-31")
    elif kind == "monthly":
        end_date = pd.Timestamp(f"{year}-{month:02d}-01") + pd.offsets.MonthEnd()
        start_date = (end_date - pd.DateOffset(months=11)).replace(day=1)
    else:
        start_date = monthly_data["dateAdded"].min().replace(day=1)
        end_date = (
            monthly_data["dateAdded"].max().replace(day=1) + pd.offsets.MonthEnd()
        )

    date_range = pd.date_range(start=start_date, end=end_date, freq="ME")
    all_months = pd.DataFrame(
        {
            "dateAdded": date_range,
            "month": date_range.month.map(month_name),
            "sigla": date_range.month.map(month_abbr),
            "year": date_range.year,
        }
    )

    data = monthly_data.copy()
    data["month"] = data["dateAdded"].dt.month.map(month_name)
    data["sigla"] = data["dateAdded"].dt.month.map(month_abbr)
    data["year"] = data["dateAdded"].dt.year

    monthly_counts = (
        data.groupby(["month", "sigla", "year"])
        .agg(counts=("dateAdded", "size"), first_date=("dateAdded", "min"))
        .reset_index()
    )
    monthly_counts = (
        all_months[["month", "sigla", "year"]]
        .merge(monthly_counts, how="left", on=["month", "sigla", "year"])
        .fillna(0)
    )

    return pd.DataFrame(
        {
            "date": all_months["dateAdded"],
            "vulnerabilities": monthly_counts["counts"],
            "month_label": monthly_counts["sigla"]
            + " "
            + monthly_counts["year"].astype(str),
        }
    )
