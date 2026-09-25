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


def test_mean_line_range_headroom_around_mean():
    import pandas as pd
    from core.charts import mean_line_range
    # serie plana: mean dita o teto (respiro)
    flat = pd.Series([18, 20, 22, 20])
    assert mean_line_range(flat) == [0, max(flat.mean()*1.6, flat.max()*1.1, 5)]


def test_mean_line_range_never_clips_peak():
    import pandas as pd
    from core.charts import mean_line_range
    # outlier: teto >= maximo*1.1 (nunca corta o pico)
    spiky = pd.Series([5, 5, 30, 5, 24, 28, 17, 13])
    top = mean_line_range(spiky)[1]
    assert top >= spiky.max() * 1.1 - 1e-9
    assert mean_line_range(spiky) == [0, max(spiky.mean()*1.6, spiky.max()*1.1, 5)]


def test_mean_line_range_empty_falls_back_to_floor():
    import pandas as pd
    from core.charts import mean_line_range
    assert mean_line_range(pd.Series([], dtype=float)) == [0, 5]
    assert mean_line_range(pd.Series([float("nan")])) == [0, 5]
