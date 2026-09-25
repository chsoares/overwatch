"""Smoke tests for the Streamlit landing and content pages.

Every page is exercised end-to-end with ``AppTest`` and must fail loudly: a
rendering exception or missing branding is a test failure, not a skip.
"""

import json
import py_compile
import re
from datetime import date, datetime
from pathlib import Path

import pandas as pd
import pytest

from core.analytics import mailsec, ransom, vuln
from core.analytics.common import EmptyPeriodError
from tests.analytics._datasets import FIXTURES_DIR, MAILSEC_CSV, RANSOM_CSV, VULN_CSV

HOME = Path(__file__).resolve().parent.parent / "Home.py"
PAGE = Path(__file__).resolve().parent.parent / "pages" / "1_Ransomware.py"
VULN_PAGE = Path(__file__).resolve().parent.parent / "pages" / "2_Vulnerabilidades.py"
EMAIL_PAGE = Path(__file__).resolve().parent.parent / "pages" / "3_Email Seguro.py"
EMPTY_PERIOD = {"type": "annual", "start": date(1990, 1, 1), "end": date(1990, 12, 31)}
VULN_EMPTY_PREVIOUS = {"type": "annual", "start": date(2021, 1, 1), "end": date(2021, 12, 31)}
VULN_WITH_PREVIOUS = {"type": "annual", "start": date(2024, 1, 1), "end": date(2024, 12, 31)}

_HOME_LEGACY_REFERENCES = (
    "sys.path",
    "setup_logger",
    "logger_config",
    "find_project_root",
    "get_environment_prefix",
    "markdown_insert",
    "home_style",
)

_LEGACY_REFERENCES = (
    "config[",
    "run_analysis",
    "report_variables",
    "Executar Análise",
    "export/",
    "output/",
    "subprocess",
    "markdown_insert",
    "get_environment_prefix",
)

_VULN_LEGACY_REFERENCES = _LEGACY_REFERENCES + (
    "load_config",
    "save_config",
    "create_export_zip",
    "vuln_report_executed",
    "Relatório",
)

_EMAIL_LEGACY_REFERENCES = (
    "config[",
    "load_config",
    "get_environment_prefix",
    "find_project_root",
    "report_style",
    "logs/",
    "mailsec.log",
    "Executar",
)

_PAGES = (HOME, PAGE, VULN_PAGE, EMAIL_PAGE)

_MONTH_LABEL_RE = re.compile(r"^([A-Za-z]{3})\. \d{2}$")
_PT_MONTH_ABBRS = {
    "jan", "fev", "mar", "abr", "mai", "jun",
    "jul", "ago", "set", "out", "nov", "dez",
}


def _plotly_month_labels(app):
    """Collect ``<abbr>. <yy>`` x labels from every rendered Plotly chart."""
    labels = []
    for chart in app.get("plotly_chart"):
        spec = json.loads(chart.proto.spec)
        for trace in spec.get("data", []):
            for value in trace.get("x") or []:
                match = _MONTH_LABEL_RE.match(str(value))
                if match:
                    labels.append(match.group(1))
    return labels


def _assert_month_labels_lowercase_pt(app):
    labels = _plotly_month_labels(app)
    assert labels, "expected at least one month label in the rendered charts"
    for abbr in labels:
        assert abbr == abbr.lower(), f"capitalized month label: {abbr}"
        assert abbr in _PT_MONTH_ABBRS, f"non-portuguese month label: {abbr}"


@pytest.fixture(autouse=True)
def frozen_datasets(monkeypatch):
    """Redirect every dataset read to the frozen snapshots in ``tests/fixtures``.

    A daily ingestion job rewrites ``data/*.csv``, so these smoke tests must not
    read it. The analytics modules bind ``DATA_DIR`` into their own namespace at
    import time, and the email page imports ``core.paths.DATA_DIR`` for its
    existence guard, so all of them are patched. ``st.cache_data`` keys on the
    function rather than the resolved path, so a dataset cached by an earlier
    run would otherwise leak through; clear it on both sides of each test.
    """
    import core.paths
    import streamlit as st

    monkeypatch.setattr(core.paths, "DATA_DIR", FIXTURES_DIR)
    for module in (ransom, vuln, mailsec):
        monkeypatch.setattr(module, "DATA_DIR", FIXTURES_DIR)

    st.cache_data.clear()
    yield
    st.cache_data.clear()


def test_pages_carry_overwatch_branding():
    for page in _PAGES:
        source = page.read_text(encoding="utf-8")
        assert "overwatch" in source, f"{page.name} is missing the overwatch brand"
        assert "copic" not in source, f"{page.name} still references the old brand"


def test_home_page_compiles():
    py_compile.compile(str(HOME), doraise=True)


def test_home_page_has_no_legacy_references():
    source = HOME.read_text(encoding="utf-8")
    for pattern in _HOME_LEGACY_REFERENCES:
        assert pattern not in source, f"legacy reference still present: {pattern}"


def test_home_page_runs_without_exception():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

    app = AppTest.from_file(str(HOME), default_timeout=120)
    app.run()

    assert not app.exception, [error.value for error in app.exception]
    markdown = "\n".join(item.value for item in app.markdown)
    assert "ransomware" in markdown


def test_ransomware_page_compiles():
    py_compile.compile(str(PAGE), doraise=True)


def test_page_has_no_legacy_pipeline_references():
    source = PAGE.read_text(encoding="utf-8")
    for pattern in _LEGACY_REFERENCES:
        assert pattern not in source, f"legacy reference still present: {pattern}"


def test_ransomware_page_runs_without_exception():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

    app = AppTest.from_file(str(PAGE), default_timeout=120)
    app.run()

    assert not app.exception, [error.value for error in app.exception]
    assert [tab.label for tab in app.tabs] == ["Dashboard", "Dataset"]
    assert any("overwatch / ransomware" in title.value for title in app.title)
    _assert_month_labels_lowercase_pt(app)


def test_ransomware_page_has_world_and_country_panels():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = AppTest.from_file(str(PAGE), default_timeout=120)
    app.run()
    assert not app.exception, [e.value for e in app.exception]
    markdown = "\n".join(m.value for m in app.markdown)
    assert "No mundo" in markdown
    assert "Em Brasil" in markdown


def test_ransomware_country_selector_is_multiselect_defaulting_to_brazil():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = AppTest.from_file(str(PAGE), default_timeout=120)
    app.run()

    assert not app.exception, [e.value for e in app.exception]
    selectors = [widget for widget in app.sidebar.multiselect if widget.label == "Países"]
    assert selectors, "country multiselect not found"
    assert selectors[0].value == ["Brasil (BR)"]


def test_multi_country_analytics_feed_the_page():
    """The multi-only visuals consume the list-based analytics directly."""
    df = ransom.load_dataset(RANSOM_CSV)
    period = {"type": "annual", "start": date(2024, 1, 1), "end": date(2024, 12, 31)}
    iso_list = ["BR", "US"]

    by_country = ransom.monthly_attacks_by_country(df, period, iso_list)
    assert set(iso_list).issubset(by_country.columns)

    selected = ransom.countries_selected(df, period, iso_list)
    assert set(selected["ISO2"]).issubset(set(iso_list))

    multi = ransom.historical_series_multi(df, period, iso_list)
    assert {"world_attacks", "selection_attacks"}.issubset(multi.columns)
    assert set(iso_list).issubset(multi.columns)

    source = PAGE.read_text(encoding="utf-8")
    assert "iso2=iso_list" in source
    assert "selection_label(iso_list, country_name)" in source


def test_ransomware_victims_country_column_only_for_multi_selection():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ransomware_page", PAGE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    df = ransom.load_dataset(RANSOM_CSV)
    period = {"type": "annual", "start": date(2024, 1, 1), "end": date(2024, 12, 31)}
    iso_list = ["BR", "US"]

    victims = ransom.victims_table(df, period, iso_list)
    display = module.victims_with_country(df, period, victims, iso_list)
    assert "País" in display.columns
    assert len(display) == len(victims)
    assert set(display["País"]).issubset({"Brasil", "Estados Unidos"})

    single = module.victims_with_country(
        df, period, ransom.victims_table(df, period, "BR"), ["BR"]
    )
    assert "País" not in single.columns


def test_filter_dataset_treats_query_as_literal_text():
    """Metacharacter queries must not reach the regex engine.

    ``str.contains`` defaults to ``regex=True``; a literal search must pass
    ``regex=False`` or inputs like ``(`` raise ``re.PatternError``. The page
    script is loaded as a module (Streamlit tolerates bare execution) so the
    real ``filter_dataset`` implementation is exercised, not a copy.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("ransomware_page", PAGE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    df = ransom.load_dataset(RANSOM_CSV).head(200)

    for column in ("Todas as colunas", "post_title"):
        for query in ["(", "[", "*", "C++", "??"]:
            result = module.filter_dataset(df, column, query)
            assert len(result) <= len(df)

    sample = df["post_title"].dropna().astype(str).iloc[0]
    literal = module.filter_dataset(df, "post_title", sample)
    assert sample in set(literal["post_title"])


def test_empty_period_analytics_raise_for_the_page_guard():
    """The page wraps its analytics calls in ``except EmptyPeriodError``.

    A period with no rows must make every dashboard aggregation raise so the
    guard (warning + ``st.stop``) is what the user sees instead of a traceback.
    Note: ``AppTest`` cannot re-render this page after a sidebar interaction
    that changes the period type (its dependent selectboxes trip a harness
    ``ValueError``), so this covers the analytics contract directly.
    """
    df = ransom.load_dataset(RANSOM_CSV)

    calls = {
        "overview": lambda: ransom.overview(df, EMPTY_PERIOD, "BR"),
        "monthly_attacks": lambda: ransom.monthly_attacks(df, EMPTY_PERIOD, "BR"),
        "historical_series": lambda: ransom.historical_series(df, EMPTY_PERIOD, "BR"),
        "top_groups": lambda: ransom.top_groups(df, EMPTY_PERIOD, "BR"),
        "monthly_group_activity": lambda: ransom.monthly_group_activity(df, EMPTY_PERIOD),
        "monthly_active_groups": lambda: ransom.monthly_active_groups(df, EMPTY_PERIOD),
        "countries": lambda: ransom.countries(df, EMPTY_PERIOD),
        "world_sectors": lambda: ransom.world_sectors(df, EMPTY_PERIOD),
        "country_sectors": lambda: ransom.country_sectors(df, EMPTY_PERIOD, "BR"),
        "victims_table": lambda: ransom.victims_table(df, EMPTY_PERIOD, "BR"),
        "daily_heatmap": lambda: ransom.daily_heatmap(df, EMPTY_PERIOD),
    }
    for name, call in calls.items():
        with pytest.raises(EmptyPeriodError):
            call()

    source = PAGE.read_text(encoding="utf-8")
    assert "except EmptyPeriodError" in source
    assert "st.stop()" in source


def test_ransomware_delta_hidden_when_previous_period_is_empty():
    """A missing previous slice must hide every ransom delta.

    Under period type ``total`` the previous slice is empty by design, so the
    overview reports zero for every previous metric and the page must pass
    ``has_previous=False`` to ``format_delta`` instead of rendering ``+N`` or
    ``+∞%`` against a bogus zero baseline.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("ransomware_page", PAGE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    df = ransom.load_dataset(RANSOM_CSV)
    total = {
        "type": "total",
        "start": df["published"].min().date(),
        "end": df["published"].max().date(),
    }
    assert module.has_previous_period(ransom.overview(df, total, "BR")) is False
    assert module.format_delta(18672, 0, "Absoluta", has_previous=False) is None
    assert module.format_delta(18672, 0, "Percentual", has_previous=False) is None

    monthly = {
        "type": "monthly",
        "start": date(2026, 1, 1),
        "end": date(2026, 1, 31),
    }
    assert module.has_previous_period(ransom.overview(df, monthly, "BR")) is True


def test_vulnerability_page_compiles():
    py_compile.compile(str(VULN_PAGE), doraise=True)


def test_vulnerability_page_has_no_legacy_pipeline_references():
    source = VULN_PAGE.read_text(encoding="utf-8")
    for pattern in _VULN_LEGACY_REFERENCES:
        assert pattern not in source, f"legacy reference still present: {pattern}"


def test_vulnerability_page_runs_without_exception():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

    app = AppTest.from_file(str(VULN_PAGE), default_timeout=120)
    app.run()

    assert not app.exception, [error.value for error in app.exception]
    assert [tab.label for tab in app.tabs] == ["Dashboard", "Dataset"]
    assert any("overwatch / vulnerabilidades" in title.value for title in app.title)
    _assert_month_labels_lowercase_pt(app)


def test_vulnerability_filter_dataset_treats_query_as_literal_text():
    """Metacharacter queries must not reach the regex engine.

    ``str.contains`` defaults to ``regex=True``; the page's literal search must
    pass ``regex=False`` or inputs like ``(`` raise ``re.PatternError``. The page
    script is loaded as a module so the real ``filter_dataset`` is exercised.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("vulnerability_page", VULN_PAGE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    df = vuln.load_dataset(VULN_CSV).head(200)

    for column in ("Todas as colunas", "vendorProject", "product"):
        for query in ["(", "[", "*", "C++", "??"]:
            result = module.filter_dataset(df, column, query)
            assert len(result) <= len(df)

    sample = df["vendorProject"].dropna().astype(str).iloc[0]
    literal = module.filter_dataset(df, "vendorProject", sample)
    assert sample in set(literal["vendorProject"])

    source = VULN_PAGE.read_text(encoding="utf-8")
    assert "except EmptyPeriodError" in source
    assert "st.stop()" in source


def test_vulnerability_delta_hidden_when_previous_period_is_empty():
    """A missing previous slice must hide deltas for every metric.

    Count metrics previously fell back to ``0`` and rendered ``+N`` against a
    zero baseline while CVSS/EPSS rendered nothing. ``has_previous_period`` is
    derived once from ``overview_previous`` and gates the delta formatter.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("vulnerability_page", VULN_PAGE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    df = vuln.load_dataset(VULN_CSV)

    empty_previous = vuln.overview_previous(df, VULN_EMPTY_PREVIOUS)
    assert module.has_previous_period(empty_previous) is False
    assert module.format_delta(5, 0, "Absoluta", has_previous=False) is None
    assert module.format_delta(5, 0, "Percentual", has_previous=False) is None

    populated_previous = vuln.overview_previous(df, VULN_WITH_PREVIOUS)
    assert module.has_previous_period(populated_previous) is True
    assert module.format_delta(5, 2, "Absoluta", has_previous=True) == "+3"
    assert module.format_delta(5, 0, "Absoluta", has_previous=True) == "+5"


def test_email_page_compiles():
    py_compile.compile(str(EMAIL_PAGE), doraise=True)


def test_email_page_has_no_legacy_references():
    source = EMAIL_PAGE.read_text(encoding="utf-8")
    for pattern in _EMAIL_LEGACY_REFERENCES:
        assert pattern not in source, f"legacy reference still present: {pattern}"


def test_email_page_runs_without_exception():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

    app = AppTest.from_file(str(EMAIL_PAGE), default_timeout=120)
    app.run()

    assert not app.exception, [error.value for error in app.exception]
    assert [tab.label for tab in app.tabs] == ["Dashboard", "Dataset"]
    assert any("overwatch / email seguro" in title.value for title in app.title)

    subheaders = [item.value for item in app.subheader]
    for expected in (
        "Visão geral",
        "Status de segurança",
        "Análise por protocolo",
        "Aderência por protocolo",
        "Domínios",
    ):
        assert expected in subheaders, f"missing subheader: {expected}"


def test_email_filter_dataset_treats_query_as_literal_text():
    """Metacharacter queries must not reach the regex engine.

    The page adopts ``core.dataset.filter_dataset`` (``regex=False``). The page
    script is loaded as a module so the real function is exercised, not a copy.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("email_page", EMAIL_PAGE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    df = mailsec.load_dataset(MAILSEC_CSV).head(200)

    for column in ("Todas as colunas", "domain"):
        for query in ["(", "[", "*", "C++", "??"]:
            result = module.filter_dataset(df, column, query)
            assert len(result) <= len(df)

    sample = df["domain"].dropna().astype(str).iloc[0]
    literal = module.filter_dataset(df, "domain", sample)
    assert sample in set(literal["domain"])

    source = EMAIL_PAGE.read_text(encoding="utf-8")
    assert "st.warning" in source
    assert "st.stop()" in source


def test_email_page_dataset_last_update_reads_mtime(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("email_page", EMAIL_PAGE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.dataset_last_update(tmp_path / "missing.csv") is None

    csv = tmp_path / "mailsec_dataset.csv"
    csv.write_text("domain,MX_found\nabc.gov.br,True\n")
    stamp = module.dataset_last_update(csv)
    assert isinstance(stamp, datetime)
    assert stamp.year >= 2000


def test_email_page_dataset_last_update_survives_bad_timestamp(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("email_page", EMAIL_PAGE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    csv = tmp_path / "mailsec_dataset.csv"
    csv.write_text("domain,MX_found\nabc.gov.br,True\n")

    class _OutOfRangeDateTime:
        @staticmethod
        def fromtimestamp(_):
            raise OverflowError("timestamp out of range")

    module.datetime = _OutOfRangeDateTime
    assert module.dataset_last_update(csv) is None


def test_email_adherence_chart_renders_analytics_percentages():
    """Protocol adherence is a share of domains that handle mail, not all rows.

    The chart consumes ``mailsec.protocol_adherence`` directly, so its x/y come
    from the MX-denominated analytics rather than a page-local denominator.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("email_page", EMAIL_PAGE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    adherence = pd.DataFrame(
        {
            "protocol": ["SPF válido", "SPF seguro", "DKIM", "DNSSEC"],
            "count": [20, 10, 5, 4],
            "percent": [50.0, 25.0, 12.5, 10.0],
        }
    )
    trace = module.adherence_chart(adherence).data[0]

    assert list(trace.x) == ["SPF válido", "SPF seguro", "DKIM", "DNSSEC"]
    assert list(trace.y) == [50.0, 25.0, 12.5, 10.0]


def test_email_status_emoji_is_mapped_per_protocol():
    """The same status code must render differently across protocols.

    ``valid`` means "found" (✅) for DKIM but "valid, not secure" (⚠️) for
    SPF/DMARC. A single shared map rendered every valid DKIM as "not found".
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("email_page", EMAIL_PAGE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.status_emoji("spf", "safe") == "✅"
    assert module.status_emoji("spf", "valid") == "⚠️"
    assert module.status_emoji("spf", "invalid") == "❌"
    assert module.status_emoji("dmarc", "safe") == "✅"
    assert module.status_emoji("dmarc", "valid") == "⚠️"
    assert module.status_emoji("dmarc", "invalid") == "❌"
    assert module.status_emoji("dkim", "valid") == "✅"
    assert module.status_emoji("dkim", "not_found") == "⚠️"
    assert module.status_emoji("dnssec", "signed") == "✅"
    assert module.status_emoji("dnssec", "not_signed") == "❌"

    assert module.status_emoji("dkim", "valid") != module.status_emoji("spf", "valid")


def test_email_status_table_maps_each_column_with_its_own_protocol():
    """The per-domain table must use each column's protocol mapping."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("email_page", EMAIL_PAGE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    status = pd.DataFrame(
        {
            "domain": ["valid-dkim.gov.br", "valid-spf.gov.br"],
            "SPF_status": ["invalid", "valid"],
            "DMARC_status": ["invalid", "invalid"],
            "DKIM_status": ["valid", "not_found"],
            "DNSSEC_status": ["signed", "not_signed"],
        }
    )
    display = module.emoji_status_table(status)

    assert list(display.columns) == [
        "domain",
        "SPF_status",
        "DMARC_status",
        "DKIM_status",
        "DNSSEC_status",
    ]
    assert list(
        display.loc[0, ["SPF_status", "DMARC_status", "DKIM_status", "DNSSEC_status"]]
    ) == ["❌", "❌", "✅", "✅"]
    assert list(
        display.loc[1, ["SPF_status", "DMARC_status", "DKIM_status", "DNSSEC_status"]]
    ) == ["⚠️", "❌", "⚠️", "❌"]
