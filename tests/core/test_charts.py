import pandas as pd

from core import charts


def _frame(n=12):
    return pd.DataFrame(
        {
            "value": list(range(1, n + 1)),
            "label": [f"L{i}" for i in range(1, n + 1)],
        }
    )


def test_horizontal_bar_uses_top_n_in_ascending_order():
    fig = charts.horizontal_bar(
        _frame(), "value", "label", "blue", hover_label="Incidentes", n=5
    )
    assert len(fig.data) == 1
    trace = fig.data[0]
    assert trace.orientation == "h"
    assert list(trace.y) == ["L8", "L9", "L10", "L11", "L12"]
    assert list(trace.x) == [8, 9, 10, 11, 12]


def test_horizontal_bar_defaults_to_top_ten():
    fig = charts.horizontal_bar(
        _frame(), "value", "label", "blue", hover_label="Incidentes"
    )
    assert len(fig.data) == 1
    assert list(fig.data[0].y) == [f"L{i}" for i in range(3, 13)]


def test_horizontal_bar_hover_template_uses_label():
    fig = charts.horizontal_bar(_frame(), "value", "label", "blue", hover_label="CVEs")
    assert "CVEs: %{x}" in fig.data[0].hovertemplate


def test_line_with_mean_adds_mean_trace():
    fig = charts.line_with_mean(
        [1, 2, 3],
        [1, 2, 3],
        "Série",
        "green",
        hover="Incidentes: %{y}<extra></extra>",
        mean=2.0,
    )
    assert len(fig.data) == 2
    mean_trace, series_trace = fig.data
    assert mean_trace.name == "Média"
    assert list(mean_trace.y) == [2.0, 2.0, 2.0]
    assert series_trace.name == "Série"
    assert list(series_trace.y) == [1, 2, 3]


def test_line_with_mean_omits_mean_trace_when_none():
    fig = charts.line_with_mean(
        [1, 2, 3],
        [1, 2, 3],
        "Série",
        "green",
        hover="Incidentes: %{y}<extra></extra>",
    )
    assert len(fig.data) == 1
    assert fig.data[0].name == "Série"
