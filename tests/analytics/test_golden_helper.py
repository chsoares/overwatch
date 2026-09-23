import numpy as np
import pandas as pd
import pytest

from tests.analytics import _golden


@pytest.fixture
def golden_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(_golden, "GOLDEN", tmp_path)
    return tmp_path


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return path


def test_datetime_result_matches_string_golden(golden_dir):
    _write(
        golden_dir / "series.csv",
        "date,value\n2024-01-01 00:00:00,10\n2024-02-01 00:00:00,20\n",
    )
    result = pd.DataFrame(
        {
            "date": pd.to_datetime(["2024-02-01", "2024-01-01"]),
            "value": [20, 10],
        }
    )
    _golden.assert_matches_golden(result, "series.csv", sort_by=["date"])


def test_numeric_result_matches_plus_string_golden(golden_dir):
    _write(
        golden_dir / "overview.csv",
        "metric,delta\nattacks,+186\nmean,+48.7\n",
    )
    result = pd.DataFrame({"metric": ["attacks", "mean"], "delta": [186, 48.7]})
    _golden.assert_matches_golden(result, "overview.csv")


def test_formatted_percent_strings_compare_exactly(golden_dir):
    _write(golden_dir / "vuln.csv", "metric,value\nepss,61.4%\n")

    ok = pd.DataFrame({"metric": ["epss"], "value": ["61.4%"]})
    _golden.assert_matches_golden(ok, "vuln.csv")

    bad = pd.DataFrame({"metric": ["epss"], "value": ["61.5%"]})
    with pytest.raises(AssertionError):
        _golden.assert_matches_golden(bad, "vuln.csv")


def test_missing_string_matches_blank_golden(golden_dir):
    _write(golden_dir / "blank.csv", "name,note\nalpha,hello\nbeta,\n")

    none_result = pd.DataFrame({"name": ["beta", "alpha"], "note": [None, "hello"]})
    _golden.assert_matches_golden(none_result, "blank.csv")

    na_result = pd.DataFrame({"name": ["beta", "alpha"], "note": [pd.NA, "hello"]})
    _golden.assert_matches_golden(na_result, "blank.csv")

    nan_result = pd.DataFrame({"name": ["beta", "alpha"], "note": [np.nan, "hello"]})
    _golden.assert_matches_golden(nan_result, "blank.csv")


def test_missing_or_extra_column_raises(golden_dir):
    _write(golden_dir / "tbl.csv", "a,b\n1,2\n")

    missing = pd.DataFrame({"a": [1]})
    with pytest.raises(AssertionError):
        _golden.assert_matches_golden(missing, "tbl.csv")

    extra = pd.DataFrame({"a": [1], "b": [2], "c": [3]})
    with pytest.raises(AssertionError):
        _golden.assert_matches_golden(extra, "tbl.csv")
