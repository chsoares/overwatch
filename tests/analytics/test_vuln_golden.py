"""Golden tests for the pure vulnerability-analytics port.

The fixtures under ``tests/golden/`` were captured from the legacy
``scripts/vuln_analyzer.py`` with ``vendor.name=all``, reading
``data/vuln_dataset.csv``:

* un-prefixed fixtures: ``period.type=annual``, ``year=2024``; the legacy
  annual period is exactly ``2024-01-01..2024-12-31`` (rows selected by
  ``dateAdded.dt.year == 2024``), which is what ``PERIOD`` below encodes.
* ``monthly_`` fixtures: ``type=monthly, year=2024, month=6``.
* ``custom_`` fixtures: ``type=custom, 2023-11-01..2024-03-31`` (cross-year on
  purpose, to guard duplicate-month-name merges).
"""

from datetime import date
import re
from pathlib import Path

import pandas as pd
import pytest

from core.analytics import vuln
from core.analytics.common import EmptyPeriodError
from tests.analytics._datasets import VULN_CSV
from tests.analytics._golden import assert_matches_golden

PERIOD = {"type": "annual", "start": date(2024, 1, 1), "end": date(2024, 12, 31)}
NONANNUAL_PERIODS = {
    "monthly": {"type": "monthly", "start": date(2024, 6, 1), "end": date(2024, 6, 30)},
    "custom": {"type": "custom", "start": date(2023, 11, 1), "end": date(2024, 3, 31)},
}
EMPTY_PERIOD = {"type": "annual", "start": date(1990, 1, 1), "end": date(1990, 12, 31)}


@pytest.fixture(scope="module")
def df():
    return vuln.load_dataset(VULN_CSV)


# ---------------------------------------------------------------------------
# Golden tests (one per exported function)
# ---------------------------------------------------------------------------


def test_overview_matches_golden(df):
    assert_matches_golden(vuln.overview(df, PERIOD), "vuln_overview.csv")


def test_overview_previous_matches_golden(df):
    assert_matches_golden(
        vuln.overview_previous(df, PERIOD), "vuln_overview_previous.csv"
    )


def test_risk_bars_matches_golden(df):
    assert_matches_golden(vuln.risk_bars(df, PERIOD), "dash_risk_bars.csv")


def test_exploit_scatter_matches_golden(df):
    assert_matches_golden(vuln.exploit_scatter(df, PERIOD), "dash_exploit_scatter.csv")


def test_monthly_vulns_matches_golden(df):
    assert_matches_golden(vuln.monthly_vulns(df, PERIOD), "dash_monthly_vulns.csv")


def test_ransom_scatter_matches_golden(df):
    assert_matches_golden(vuln.ransom_scatter(df, PERIOD), "dash_ransom_scatter.csv")


# ---------------------------------------------------------------------------
# Monthly / custom goldens
# ---------------------------------------------------------------------------

CASES = [
    pytest.param(lambda df, p: vuln.overview(df, p), "vuln_overview.csv", id="overview"),
    pytest.param(
        lambda df, p: vuln.overview_previous(df, p),
        "vuln_overview_previous.csv",
        id="overview_previous",
    ),
    pytest.param(
        lambda df, p: vuln.risk_bars(df, p), "dash_risk_bars.csv", id="risk_bars"
    ),
    pytest.param(
        lambda df, p: vuln.exploit_scatter(df, p),
        "dash_exploit_scatter.csv",
        id="exploit_scatter",
    ),
    pytest.param(
        lambda df, p: vuln.monthly_vulns(df, p),
        "dash_monthly_vulns.csv",
        id="monthly_vulns",
    ),
    pytest.param(
        lambda df, p: vuln.ransom_scatter(df, p),
        "dash_ransom_scatter.csv",
        id="ransom_scatter",
    ),
]


@pytest.mark.parametrize(
    "period_name,prefix", [("monthly", "monthly_"), ("custom", "custom_")]
)
@pytest.mark.parametrize("call,golden", CASES)
def test_nonannual_matches_golden(df, period_name, prefix, call, golden):
    assert_matches_golden(call(df, NONANNUAL_PERIODS[period_name]), f"{prefix}{golden}")


# ---------------------------------------------------------------------------
# Ordering assertions (the column-sorted golden helper hides ordering)
# ---------------------------------------------------------------------------


def test_monthly_vulns_is_chronological(df):
    result = vuln.monthly_vulns(df, PERIOD)
    assert result["date"].is_monotonic_increasing
    assert len(result) == 12


def test_exploit_scatter_groups_public_exploits_first(df):
    result = vuln.exploit_scatter(df, PERIOD)
    assert result["exploit"].is_monotonic_decreasing


def test_ransom_scatter_groups_unknown_first(df):
    result = vuln.ransom_scatter(df, PERIOD)
    assert result["ransomCampaign"].is_monotonic_decreasing


def test_risk_bars_follow_legacy_severity_order(df):
    result = vuln.risk_bars(df, PERIOD)
    assert list(result["Risco"]) == ["Baixo", "Médio", "Alto", "Crítico"]


def test_overview_rows_follow_legacy_order(df):
    result = vuln.overview(df, PERIOD)
    assert list(result["Métrica"]) == [
        "Número de CVEs",
        "CVEs de risco crítico",
        "CVEs com exploits públicos disponíveis",
        "CVEs associadas a campanhas de ransomware",
        "CVSS médio",
        "EPSS médio",
    ]


@pytest.mark.parametrize("period_name", ["monthly", "custom"])
def test_monthly_vulns_nonannual_is_chronological(df, period_name):
    result = vuln.monthly_vulns(df, NONANNUAL_PERIODS[period_name])
    assert result["date"].is_monotonic_increasing


@pytest.mark.parametrize("period_name", ["monthly", "custom"])
def test_scatter_nonannual_keeps_grouping_order(df, period_name):
    period = NONANNUAL_PERIODS[period_name]
    assert vuln.exploit_scatter(df, period)["exploit"].is_monotonic_decreasing
    assert vuln.ransom_scatter(df, period)["ransomCampaign"].is_monotonic_decreasing


def test_overview_previous_with_empty_previous_slice_yields_legacy_nan(df):
    # 2021 is the earliest year in the dataset, so its previous slice (2020) is
    # empty even though the current slice is not. The legacy analyzer renders
    # the zero counts and NaN means verbatim; this asserts that parity.
    period = {"type": "annual", "start": date(2021, 1, 1), "end": date(2021, 12, 31)}
    result = vuln.overview_previous(df, period)
    values = {row["Métrica"]: f"{row['Valor']}" for _, row in result.iterrows()}
    assert values["Número de CVEs"] == "0.0"
    assert values["CVSS médio"] == "nan"
    assert values["EPSS médio"] == "nan%"


# ---------------------------------------------------------------------------
# Empty periods raise a clear error
# ---------------------------------------------------------------------------


EMPTY_CASES = [
    pytest.param(lambda df: vuln.overview(df, EMPTY_PERIOD), id="overview"),
    pytest.param(
        lambda df: vuln.overview_previous(df, EMPTY_PERIOD), id="overview_previous"
    ),
    pytest.param(lambda df: vuln.risk_bars(df, EMPTY_PERIOD), id="risk_bars"),
    pytest.param(
        lambda df: vuln.exploit_scatter(df, EMPTY_PERIOD), id="exploit_scatter"
    ),
    pytest.param(lambda df: vuln.monthly_vulns(df, EMPTY_PERIOD), id="monthly_vulns"),
    pytest.param(
        lambda df: vuln.ransom_scatter(df, EMPTY_PERIOD), id="ransom_scatter"
    ),
]


@pytest.mark.parametrize("call", EMPTY_CASES)
def test_empty_period_raises_empty_period_error(df, call):
    assert issubclass(EmptyPeriodError, ValueError)
    with pytest.raises(EmptyPeriodError, match="No data for period"):
        call(df)


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------


def test_load_dataset_parses_date_added(df):
    assert pd.api.types.is_datetime64_any_dtype(df["dateAdded"])
    assert {"cveID", "cvss", "epss", "risk", "exploit", "ransomCampaign"} <= set(
        df.columns
    )


def test_load_dataset_defaults_to_live_data_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(vuln, "DATA_DIR", tmp_path)
    (tmp_path / "vuln_dataset.csv").write_text("dateAdded\n2024-01-01\n")
    df = vuln.load_dataset()
    assert len(df) == 1
    assert pd.api.types.is_datetime64_any_dtype(df["dateAdded"])


# ---------------------------------------------------------------------------
# Locale regression guard
# ---------------------------------------------------------------------------


def test_vuln_source_has_no_locale_dependency():
    source = Path(vuln.__file__).read_text(encoding="utf-8")
    assert "import locale" not in source
    assert not re.search(r"strptime\s*\([^)]*%[bB]", source), (
        "vuln.py must not parse month names with locale-sensitive strptime"
    )
    assert "strftime(" not in source, "vuln.py must build dates from numeric month/year"
    assert "strptime(" not in source


# ---------------------------------------------------------------------------
# Vendor breakdown (crafted frame; no legacy golden exists for this table)
# ---------------------------------------------------------------------------

VENDOR_COLUMNS = [
    "Empresa",
    "CVEs",
    "CVSS Médio",
    "EPSS Médio",
    "Exploit",
    "Ransomware",
]


def _vendor_frame():
    return pd.DataFrame(
        {
            "cveID": ["CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"],
            "dateAdded": pd.to_datetime(
                ["2024-01-05", "2024-02-10", "2024-03-01", "2024-04-15", "2024-05-20"]
            ),
            "vendorProject": ["Acme", "Acme", "Beta", "Beta", "Beta"],
            "cvss": [9.0, 7.0, 5.0, 6.0, 4.0],
            "epss": [0.9, 0.5, 0.1, 0.3, 0.2],
            "exploit": ["Yes", "No", "Yes", "No", "No"],
            "ransomCampaign": ["Known", "Unknown", "Known", "Known", "Unknown"],
        }
    )


def test_vendor_breakdown_groups_and_sorts_by_cve_count():
    result = vuln.vendor_breakdown(_vendor_frame(), PERIOD)

    assert list(result.columns) == VENDOR_COLUMNS
    assert list(result["Empresa"]) == ["Beta", "Acme"]
    assert list(result["CVEs"]) == [3, 2]
    assert list(result["Exploit"]) == [1, 1]
    assert list(result["Ransomware"]) == [2, 1]
    assert result["CVSS Médio"].tolist() == pytest.approx([5.0, 8.0])
    assert result["EPSS Médio"].tolist() == pytest.approx([0.2, 0.7])


def test_vendor_breakdown_totals_match_period_rows(df):
    result = vuln.vendor_breakdown(df, PERIOD)

    dates = df["dateAdded"]
    in_period = df[
        (dates >= pd.Timestamp("2024-01-01")) & (dates <= pd.Timestamp("2024-12-31"))
    ]
    assert list(result.columns) == VENDOR_COLUMNS
    assert result["CVEs"].sum() == len(in_period)
    assert result["CVEs"].is_monotonic_decreasing


def test_vendor_breakdown_empty_period_raises(df):
    with pytest.raises(EmptyPeriodError, match="No data for period"):
        vuln.vendor_breakdown(df, EMPTY_PERIOD)
