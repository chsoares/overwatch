import math
from datetime import date

import numpy as np
import pandas as pd

from core import dataset, ui


def test_filter_dataset_returns_input_for_empty_query():
    df = pd.DataFrame({"name": ["Alpha", "Beta"]})
    assert dataset.filter_dataset(df, "name", "") is df


def test_filter_dataset_treats_query_as_literal_text():
    df = pd.DataFrame({"name": ["foo(bar)", "plain", "C++", "a[b]"]})
    assert list(dataset.filter_dataset(df, "name", "C++")["name"]) == ["C++"]


def test_filter_dataset_accepts_regex_metacharacters():
    df = pd.DataFrame({"name": ["foo(bar)", "plain", "a[b]"]})
    for query in ("(", "[", "*", "??"):
        dataset.filter_dataset(df, "name", query)  # must not raise


def test_filter_dataset_does_not_mutate_input():
    original = pd.DataFrame({"a": ["x", "y"], "b": ["z", "target"]})
    df = original.copy()
    dataset.filter_dataset(df, dataset.ALL_COLUMNS, "target")
    assert df.equals(original)


def test_filter_dataset_searches_all_columns():
    df = pd.DataFrame({"a": ["x", "y"], "b": ["z", "target"]})
    assert list(dataset.filter_dataset(df, dataset.ALL_COLUMNS, "target").index) == [1]


def test_format_delta_hidden_without_previous():
    assert ui.format_delta(5, 0, "Absoluta", has_previous=False) is None
    assert ui.format_delta(5, 0, "Percentual", has_previous=False) is None


def test_format_delta_hidden_when_previous_missing():
    assert ui.format_delta(5, None, "Absoluta") is None
    assert ui.format_delta(5, float("nan"), "Absoluta") is None
    assert ui.format_delta(5, np.float32("nan"), "Absoluta") is None
    assert ui.format_delta(5, pd.NA, "Absoluta") is None
    assert ui.format_delta(5, float("nan"), "Percentual") is None


def test_format_delta_absolute():
    assert ui.format_delta(5, 2, "Absoluta") == "+3"
    assert ui.format_delta(5, 5, "Absoluta") == "0"
    assert ui.format_delta(2, 5, "Absoluta") == "-3"


def test_format_delta_percentual():
    assert ui.format_delta(150, 100, "Percentual") == "+50.0%"
    assert ui.format_delta(100, 100, "Percentual") == "+0.0%"
    assert ui.format_delta(5, 0, "Percentual") == "+∞%"
    assert ui.format_delta(0, 0, "Percentual") == "0%"


def test_as_int_edge_cases():
    assert ui.as_int("42") == 42
    assert ui.as_int("3.9") == 3
    assert ui.as_int(7) == 7
    assert ui.as_int(None) == 0
    assert ui.as_int("abc") == 0
    assert ui.as_int(float("nan")) == 0
    assert ui.as_int(float("inf")) == 0
    assert ui.as_int("inf") == 0


def test_as_float_edge_cases():
    assert ui.as_float("12.5%") == 12.5
    assert ui.as_float(3) == 3.0
    assert math.isnan(ui.as_float(""))
    assert math.isnan(ui.as_float(None))
    assert math.isnan(ui.as_float("abc"))


def test_month_labels():
    labels = ui.month_labels(pd.to_datetime(["2024-01-15", "2024-02-01"]))
    assert labels == ["jan. 24", "fev. 24"]
    assert ui.month_labels(pd.to_datetime(["2024-03-01"]), capitalize=True) == ["Mar. 24"]


def test_period_caption():
    assert ui.period_caption({"type": "monthly", "start": date(2024, 3, 1)}) == "Março de 2024"
    assert ui.period_caption({"type": "annual", "start": date(2024, 1, 1)}) == "2024"
    custom = ui.period_caption(
        {"type": "custom", "start": date(2024, 1, 5), "end": date(2024, 2, 10)}
    )
    assert custom == "05/01/2024 a 10/02/2024"


def test_delta_color():
    assert ui.delta_color(None) == "off"
    assert ui.delta_color("0") == "off"
    assert ui.delta_color("0%") == "off"
    assert ui.delta_color("+0.0%") == "off"
    assert ui.delta_color("+3") == "normal"
    assert ui.delta_color("-3") == "normal"
    assert ui.delta_color("+∞%") == "normal"
