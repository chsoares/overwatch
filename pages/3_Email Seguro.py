#!/usr/bin/env python3
"""Email-security dashboard page backed by the live analytics layer."""

from datetime import datetime

import plotly.graph_objects as go
import streamlit as st

from core.analytics import mailsec
from core.dataset import ALL_COLUMNS, filter_dataset
from core.paths import DATA_DIR, RESOURCES_DIR
from core.styles import apply_app_styles

_DATASET = DATA_DIR / "mailsec_dataset.csv"

_PROTOCOL_TITLES = {
    "spf": "SPF",
    "dmarc": "DMARC",
    "dkim": "DKIM",
    "dnssec": "DNSSEC",
}

_SUNBURST_COLORS = {
    "spf": [
        "#6c757d",
        "royalblue",
        "slategrey",
        "yellowgreen",
        "darkred",
        "darkgreen",
        "orange",
    ],
    "dmarc": [
        "#6c757d",
        "royalblue",
        "slategrey",
        "yellowgreen",
        "darkred",
        "darkgreen",
        "orange",
    ],
    "dkim": ["#6c757d", "royalblue", "slategrey", "darkgreen", "orange"],
    "dnssec": ["#6c757d", "royalblue", "slategrey", "darkgreen", "darkred"],
}

_SUNBURST_TEMPLATES = {
    "spf": [
        "%{label}",
        "📧 %{value:,}",
        "%{value:,}",
        "👍 %{value:,}",
        "❌ %{value:,}",
        "✅ %{value:,}",
        "⚠️ %{value:,}",
    ],
    "dmarc": [
        "%{label}",
        "📧 %{value:,}",
        "%{value:,}",
        "👍 %{value:,}",
        "❌ %{value:,}",
        "✅ %{value:,}",
        "⚠️ %{value:,}",
    ],
    "dkim": [
        "%{label}",
        "📧 %{value:,}",
        "%{value:,}",
        "✅ %{value:,}",
        "⚠️ %{value:,}",
    ],
    "dnssec": [
        "%{label}",
        "📧 %{value:,}",
        "%{value:,}",
        "✅ %{value:,}",
        "❌ %{value:,}",
    ],
}

_STATUS_EMOJI = {
    "spf": {"safe": "✅", "valid": "⚠️", "invalid": "❌"},
    "dmarc": {"safe": "✅", "valid": "⚠️", "invalid": "❌"},
    "dkim": {"valid": "✅", "not_found": "⚠️"},
    "dnssec": {"signed": "✅", "not_signed": "❌"},
}

_STATUS_COLUMNS = ("SPF_status", "DMARC_status", "DKIM_status", "DNSSEC_status")


def status_emoji(protocol, code):
    """Emoji for a per-protocol status code.

    The same code carries different meaning per protocol: ``valid`` is ✅ for
    DKIM (a record was found) but ⚠️ for SPF/DMARC (valid yet not secure), so
    the mapping is keyed by protocol instead of shared across all four.
    """
    return _STATUS_EMOJI[protocol][code]


def emoji_status_table(status):
    """Map a ``status_by_domain`` frame to its per-protocol emoji display.

    Each ``*_status`` column is mapped with its own protocol's dictionary
    (derived from the column prefix), so DKIM ``valid`` renders ✅ while SPF
    ``valid`` renders ⚠️.
    """
    display = status[["domain", *_STATUS_COLUMNS]].copy()
    for column in _STATUS_COLUMNS:
        protocol = column.split("_")[0].lower()
        display[column] = display[column].map(
            lambda code, protocol=protocol: status_emoji(protocol, code)
        )
    return display

st.set_page_config(
    page_title="overwatch / email seguro",
    layout="centered",
)
st.logo(str(RESOURCES_DIR / "logo_text.png"), icon_image=str(RESOURCES_DIR / "logo_icon.png"))
apply_app_styles()


@st.cache_data(ttl=3600, show_spinner="Carregando dataset...")
def load_dataset():
    """Load and cache the email-security dataset for the whole session."""
    return mailsec.load_dataset()


def dataset_last_update(path):
    """Return the dataset file's mtime, or ``None`` when it is unreadable."""
    try:
        return datetime.fromtimestamp(path.stat().st_mtime)
    except (OSError, OverflowError, ValueError):
        return None


def render_overview(counts):
    st.subheader("Visão geral")
    st.caption("Métricas de segurança de e-mail em domínios .gov.br")

    base = (
        ("Domínios .gov.br", counts["domains"]),
        ("Com e-mail", counts["with_email"]),
        ("SPF seguro", counts["spf_secure"]),
        ("DMARC seguro", counts["dmarc_secure"]),
        ("DKIM válido", counts["dkim_valid"]),
        ("DNSSEC assinado", counts["dnssec_signed"]),
    )
    for column, (label, value) in zip(st.columns(6), base):
        with column:
            st.metric(label, f"{value:,}", delta_color="off", border=True)


def render_status(counts, critical):
    st.subheader("Status de segurança")
    st.caption("Domínios com MX e adesão ao conjunto de protocolos de segurança")

    status = (
        (
            "Domínios seguros",
            counts["secure_domains"],
            "Domínios com MX, SPF seguro, DMARC seguro, DKIM válido e DNSSEC assinado",
        ),
        (
            "Domínios vulneráveis",
            counts["vulnerable_domains"],
            "Domínios com MX, mas sem todos os protocolos de segurança adequados",
        ),
        (
            "Domínios críticos",
            counts["critical_domains"],
            "Domínios com MX, mas sem SPF, DMARC, DKIM e DNSSEC",
        ),
    )
    for column, (label, value, help_text) in zip(st.columns(3), status):
        with column:
            st.metric(
                label, f"{value:,}", delta_color="off", help=help_text, border=True
            )

    if not critical.empty:
        st.caption(
            "Lista de domínios críticos (com MX, mas sem SPF, DMARC, DKIM e DNSSEC)"
        )
        st.dataframe(
            critical,
            column_config={
                "domain": st.column_config.TextColumn(
                    "Domínio", help="Domínio .gov.br", width="medium"
                )
            },
            hide_index=True,
            use_container_width=True,
        )


def sunburst_chart(dataset, protocol):
    """Plotly sunburst for one protocol, styled from the analytics hierarchy."""
    data = mailsec.protocol_sunburst(dataset, protocol)
    fig = go.Figure(
        go.Sunburst(
            ids=data["ids"],
            labels=data["labels"],
            parents=data["parents"],
            values=data["values"],
            branchvalues="total",
            marker=dict(colors=_SUNBURST_COLORS[protocol]),
            textinfo="label+text",
            texttemplate=_SUNBURST_TEMPLATES[protocol],
            hovertemplate="<b>%{label}</b><br>Valor: %{value:,} "
            "(%{percentParent:.0%})<extra></extra>",
        )
    )
    fig.update_layout(margin=dict(t=0, b=0, l=0, r=0), height=400)
    return fig


def render_protocols(dataset):
    st.subheader("Análise por protocolo")
    st.caption("Distribuição dos domínios por status de cada protocolo de segurança")

    for left, right in (("spf", "dmarc"), ("dkim", "dnssec")):
        left_col, right_col = st.columns(2, border=True)
        for column, protocol in ((left_col, left), (right_col, right)):
            with column:
                st.write(f"###### {_PROTOCOL_TITLES[protocol]}")
                st.plotly_chart(sunburst_chart(dataset, protocol))


def adherence_chart(adherence):
    """Vertical bar of protocol adherence over domains with MX."""
    labels = list(adherence["protocol"])
    rates = list(adherence["percent"])
    fig = go.Figure(
        go.Bar(
            x=labels,
            y=rates,
            marker_color="royalblue",
            text=[f"{rate:.1f}%" for rate in rates],
            textposition="auto",
            hovertemplate="<b>%{x}</b><br>Aderência: %{y:.1f}%<extra></extra>",
        )
    )
    fig.update_layout(
        showlegend=False,
        xaxis_title=None,
        yaxis_title="Aderência (%)",
        xaxis=dict(showgrid=False),
        yaxis=dict(showgrid=True, gridcolor="lightgray", gridwidth=0.5, range=[0, 100]),
        plot_bgcolor="white",
        margin=dict(t=0, b=0, l=0, r=0),
        height=250,
    )
    return fig


def render_adherence(adherence):
    st.subheader("Aderência por protocolo")
    st.caption(
        "Percentual de domínios com cada configuração de segurança "
        "(apenas domínios com MX)"
    )

    table = adherence.rename(
        columns={
            "protocol": "Protocolo",
            "count": "Quantidade",
            "percent": "Percentual",
        }
    )
    table["Percentual"] = table["Percentual"].map(lambda value: f"{value:.1f}%")

    chart_col, table_col = st.columns(2, border=True)
    with chart_col:
        st.plotly_chart(adherence_chart(adherence), use_container_width=True)
    with table_col:
        st.dataframe(
            table,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Protocolo": st.column_config.TextColumn(
                    "Protocolo", width="medium"
                ),
                "Quantidade": st.column_config.NumberColumn(
                    "Quantidade", format="%d", width="small"
                ),
                "Percentual": st.column_config.TextColumn(
                    "Percentual", width="small"
                ),
            },
        )


def render_domains(dataset):
    st.subheader("Domínios")
    st.caption("Status de segurança de e-mail por domínio (apenas domínios com MX)")

    mx = dataset[dataset["MX_found"].fillna(False).astype(bool)]
    if mx.empty:
        st.info("Sem domínios com e-mail no dataset.")
        return

    status = mailsec.status_by_domain(mx)
    search = st.text_input("🔍 Filtrar por domínio", key="domain_search")
    if search:
        status = status[
            status["domain"].str.contains(search, case=False, na=False, regex=False)
        ]

    display = emoji_status_table(status)

    st.dataframe(
        display,
        use_container_width=True,
        hide_index=True,
        column_config={
            "domain": st.column_config.TextColumn("Domínio", width="large"),
            "SPF_status": st.column_config.TextColumn(
                "SPF",
                width="small",
                help="✅: Válido e seguro\n⚠️: Válido mas não seguro\n❌: Inválido",
            ),
            "DMARC_status": st.column_config.TextColumn(
                "DMARC",
                width="small",
                help="✅: Válido e seguro\n⚠️: Válido mas não seguro\n❌: Inválido",
            ),
            "DKIM_status": st.column_config.TextColumn(
                "DKIM",
                width="small",
                help="✅: Válido\n⚠️: Não encontrado",
            ),
            "DNSSEC_status": st.column_config.TextColumn(
                "DNSSEC",
                width="small",
                help="✅: Assinado\n❌: Não assinado",
            ),
        },
    )

    st.caption(
        """
        - ✅: Configuração segura (SPF/DMARC/DKIM/DNSSEC)
        - ⚠️: Configuração válida mas não segura (SPF/DMARC) ou não encontrada (DKIM)
        - ❌: Configuração inválida ou inexistente (SPF/DMARC/DNSSEC)
        """
    )

    st.info(
        """
        _Nota sobre DKIM:_

        A verificação de DKIM depende de se conhecer o nome do selector utilizado
        pelo domínio. Um resultado negativo não significa necessariamente que o
        domínio não possui DKIM, mas que o DKIM não foi encontrado a partir dos
        selectors comuns testados.

        _Selectors testados_:
        Nome do domínio (sem .gov.br), selector1, selector2, default, google, mail,
        dkim, s1, s2, k1, k2
        """
    )


if not _DATASET.exists():
    st.warning(
        "Dataset de segurança de e-mail não encontrado em "
        "`data/mailsec_dataset.csv`."
    )
    st.stop()

dataset = load_dataset()

if dataset.empty:
    st.warning("O dataset de segurança de e-mail está vazio.")
    st.stop()

overview = mailsec.overview(dataset)
critical = mailsec.critical_domains(dataset)
adherence = mailsec.protocol_adherence(dataset)

st.title("overwatch / email seguro")
last_update = dataset_last_update(_DATASET)
if last_update is not None:
    st.caption(f"_Última atualização:_ {last_update.strftime('%d/%m/%Y %H:%M')}")

tab_dashboard, tab_dataset = st.tabs(["Dashboard", "Dataset"])

with tab_dashboard:
    render_overview(overview)

    st.write("")
    render_status(overview, critical)

    st.write("")
    render_protocols(dataset)

    st.write("")
    render_adherence(adherence)

    st.write("")
    render_domains(dataset)

with tab_dataset:
    st.subheader("Dataset")
    st.caption("Dados brutos carregados de `data/mailsec_dataset.csv`")

    col1, col2 = st.columns([0.3, 0.7])
    with col1:
        column = st.selectbox(
            "Coluna",
            [ALL_COLUMNS] + list(dataset.columns),
            key="mailsec_dataset_column",
        )
    with col2:
        query = st.text_input("Termo de busca", key="mailsec_dataset_query")

    filtered = filter_dataset(dataset, column, query)
    st.caption(f"{len(filtered)} registros encontrados")
    st.dataframe(filtered, hide_index=True)
    st.download_button(
        "📥 Baixar CSV",
        filtered.to_csv(index=False).encode("utf-8-sig"),
        file_name="mailsec_dataset.csv",
        mime="text/csv",
    )
