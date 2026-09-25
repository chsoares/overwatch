"""Reusable Plotly figure builders shared by the content pages."""

import plotly.graph_objects as go


def mean_line_range(values, floor=5):
    """Y-axis upper bound for a mean-line chart that never clips the peak.

    Uses ``mean * 1.6`` when the series is flat enough (headroom around the
    mean), but falls back to ``max * 1.1`` when a peak would exceed that, so the
    highest point is always visible with a little slack. Empty/all-NaN series
    fall back to ``floor``.
    """
    series = values.dropna()
    if series.empty:
        return [0, floor]
    peak = float(series.max())
    mean = float(series.mean())
    return [0, max(mean * 1.6, peak * 1.1, floor)]


def horizontal_bar(data, value_col, label_col, color, hover_label, height=400, n=10):
    """Horizontal bar chart of the top ``n`` rows by ``value_col`` (ascending).

    ``hover_label`` names the value in the hover tooltip, keeping the module
    free of page-specific wording.
    """
    data = data.sort_values(value_col, ascending=True).tail(n)
    fig = go.Figure(
        go.Bar(
            x=data[value_col],
            y=data[label_col],
            orientation="h",
            marker_color=color,
            text=data[value_col],
            textposition="auto",
            hovertemplate=f"<b>%{{y}}</b><br>{hover_label}: %{{x}}<extra></extra>",
        )
    )
    fig.update_layout(
        showlegend=False,
        xaxis_title=None,
        yaxis_title=None,
        xaxis=dict(showgrid=True),
        yaxis=dict(showgrid=False),
        plot_bgcolor="white",
        margin=dict(t=0, b=0, l=0, r=0),
        height=height,
    )
    return fig


def line_with_mean(x, y, name, color, hover, mean=None, mean_color="goldenrod",
                   y_range=None, height=400):
    """Line+markers series with an optional dashed mean reference line.

    ``hover`` is the series hovertemplate, supplied by the caller so the module
    stays free of page-specific wording.
    """
    fig = go.Figure()
    if mean is not None:
        fig.add_trace(
            go.Scatter(
                x=x,
                y=[mean] * len(x),
                name="Média",
                mode="lines",
                line=dict(color=mean_color, width=2, dash="dash"),
                hovertemplate="Média: %{y:.1f}<extra></extra>",
            )
        )
    fig.add_trace(
        go.Scatter(
            x=x,
            y=y,
            name=name,
            mode="lines+markers",
            line=dict(color=color, width=4),
            marker=dict(color=color, size=8),
            hovertemplate=hover,
        )
    )
    yaxis = dict(
        showspikes=False,
        showgrid=True,
        gridcolor="lightgray",
        gridwidth=0.5,
        rangemode="tozero",
    )
    if y_range is not None:
        yaxis["range"] = y_range
    fig.update_layout(
        showlegend=False,
        height=height,
        margin=dict(l=0, r=0, t=30, b=0),
        hovermode="x unified",
        plot_bgcolor="white",
        xaxis=dict(showgrid=False, showspikes=False, type="category"),
        yaxis=yaxis,
    )
    return fig
