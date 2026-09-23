"""Pure aggregations for the email-security dataset.

Every function takes an already-loaded DataFrame (see :func:`load_dataset`).
No plotting, no file writes, no config, no Streamlit.
"""

import pandas as pd

from core.paths import DATA_DIR

_DTYPES = {
    "domain": "string",
    "MX_found": "boolean",
    "SPF": "string",
    "SPF_valid": "boolean",
    "SPF_secure": "boolean",
    "DMARC": "string",
    "DMARC_valid": "boolean",
    "DMARC_secure": "boolean",
    "DKIM": "string",
    "DKIM_valid": "boolean",
    "DNSSEC_signed": "boolean",
}

_COUNT_COLUMNS = {
    "with_email": "MX_found",
    "spf_secure": "SPF_secure",
    "dmarc_secure": "DMARC_secure",
    "dkim_valid": "DKIM_valid",
    "dnssec_signed": "DNSSEC_signed",
}

_SECURE_COLUMNS = (
    "MX_found",
    "SPF_secure",
    "DMARC_secure",
    "DKIM_valid",
    "DNSSEC_signed",
)

_CRITICAL_COLUMNS = (
    "MX_found",
    "SPF_valid",
    "DMARC_valid",
    "DKIM_valid",
    "DNSSEC_signed",
)


def load_dataset(path=None):
    """Load ``data/mailsec_dataset.csv`` with the page's pinned dtypes.

    ``path`` optionally overrides the source CSV.
    """
    if path is None:
        path = DATA_DIR / "mailsec_dataset.csv"
    return pd.read_csv(path, dtype=_DTYPES)


def _flags(df, column):
    """Boolean mask for ``column``; missing columns and nulls count as False."""
    if column not in df.columns:
        return pd.Series(False, index=df.index, dtype=bool)
    return df[column].fillna(False).astype(bool)


def overview(df):
    """Reproduce the page's "Visão geral" metrics as integer counts.

    Keys:

    * ``domains`` — total rows (domains in the dataset).
    * ``with_email`` — domains with a mail exchanger (``MX_found``).
    * ``spf_secure`` / ``dmarc_secure`` — domains with a secure SPF/DMARC policy.
    * ``dkim_valid`` — domains with a valid DKIM selector.
    * ``dnssec_signed`` — domains signed with DNSSEC.
    * ``secure_domains`` — with MX and *all* of SPF secure, DMARC secure, DKIM
      valid and DNSSEC signed.
    * ``vulnerable_domains`` — with MX but not fully secure (``with_email``
      minus ``secure_domains``).
    * ``critical_domains`` — with MX but no SPF, DMARC, DKIM or DNSSEC. A null
      flag is not treated as explicitly missing, so (as on the page) a null in
      any of those columns excludes the row from this count.
    """
    counts = {"domains": int(len(df))}
    for key, column in _COUNT_COLUMNS.items():
        counts[key] = int(_flags(df, column).sum())

    mx = _flags(df, "MX_found")
    secure = mx
    for column in _SECURE_COLUMNS[1:]:
        secure = secure & _flags(df, column)
    counts["secure_domains"] = int(secure.sum())
    counts["vulnerable_domains"] = counts["with_email"] - counts["secure_domains"]

    if all(column in df.columns for column in _CRITICAL_COLUMNS):
        critical = mx
        for column in _CRITICAL_COLUMNS[1:]:
            critical = critical & (df[column] == False)  # noqa: E712
        counts["critical_domains"] = int(critical.sum())
    else:
        counts["critical_domains"] = 0

    return counts


def critical_domains(df):
    """Domains with MX but no SPF, DMARC, DKIM or DNSSEC, sorted by domain.

    Null flags are not treated as explicitly missing (matching
    :func:`overview`), so a null in any of the four columns excludes the row.
    """
    critical = _flags(df, "MX_found")
    for column in ("SPF_valid", "DMARC_valid", "DKIM_valid", "DNSSEC_signed"):
        if column in df.columns:
            critical &= df[column].eq(False).fillna(False).astype(bool)
        else:
            critical &= False
    return (
        df.loc[critical, ["domain"]]
        .sort_values("domain")
        .reset_index(drop=True)
    )


def protocol_sunburst(df, protocol):
    """Hierarchy for the per-protocol sunburst, without any Plotly types.

    Returns a dict with ``ids``, ``labels``, ``values`` and ``parents`` ready to
    feed ``plotly.graph_objects.Sunburst`` with ``branchvalues="total"``. The
    shape mirrors the legacy charts: ``Total`` → ``Com MX``/``Sem MX`` →
    valid/invalid → secure/not-secure (SPF and DMARC); DKIM and DNSSEC branch
    straight from ``Com MX``.
    """
    key = str(protocol).lower()
    if key not in ("spf", "dmarc", "dkim", "dnssec"):
        raise ValueError(f"unknown protocol: {protocol!r}")

    mx = _flags(df, "MX_found")
    mx_total = int(len(df))
    mx_true = int(mx.sum())
    mx_false = mx_total - mx_true
    df_mx = df[mx]

    if key in ("spf", "dmarc"):
        prefix = "SPF" if key == "spf" else "DMARC"
        valid_column = f"{prefix}_valid"
        secure_column = f"{prefix}_secure"
        valid = _flags(df_mx, valid_column)
        valid_true = int(valid.sum())
        valid_false = mx_true - valid_true
        secure_true = int((valid & _flags(df_mx, secure_column)).sum())
        secure_false = valid_true - secure_true
        return {
            "ids": [
                "Total",
                "MX=True",
                "MX=False",
                f"{prefix}_valid=True",
                f"{prefix}_valid=False",
                f"{prefix}_secure=True",
                f"{prefix}_secure=False",
            ],
            "labels": [
                "Total",
                "Com MX",
                "Sem MX",
                f"{prefix} válido",
                f"{prefix} inválido",
                f"{prefix} seguro",
                f"{prefix} não seguro",
            ],
            "parents": [
                "",
                "Total",
                "Total",
                "MX=True",
                "MX=True",
                f"{prefix}_valid=True",
                f"{prefix}_valid=True",
            ],
            "values": [
                mx_total,
                mx_true,
                mx_false,
                valid_true,
                valid_false,
                secure_true,
                secure_false,
            ],
        }

    column = "DKIM_valid" if key == "dkim" else "DNSSEC_signed"
    node = "DKIM" if key == "dkim" else "DNSSEC"
    label = "DKIM válido" if key == "dkim" else "DNSSEC válido"
    missing = "DKIM não encontrado" if key == "dkim" else "DNSSEC não encontrado"
    valid_true = int(_flags(df_mx, column).sum())
    return {
        "ids": [
            "Total",
            "MX=True",
            "MX=False",
            f"{node}_valid=True",
            f"{node}_valid=False",
        ],
        "labels": ["Total", "Com MX", "Sem MX", label, missing],
        "parents": ["", "Total", "Total", "MX=True", "MX=True"],
        "values": [mx_total, mx_true, mx_false, valid_true, mx_true - valid_true],
    }


_ADHERENCE = (
    ("SPF válido", "SPF_valid"),
    ("SPF seguro", "SPF_secure"),
    ("DMARC válido", "DMARC_valid"),
    ("DMARC seguro", "DMARC_secure"),
    ("DKIM", "DKIM_valid"),
    ("DNSSEC", "DNSSEC_signed"),
)


def protocol_adherence(df):
    """Count and share of MX domains meeting each configuration.

    The denominator is the number of domains with MX (the legacy chart's
    ``df_mx`` slice), not every dataset row.
    """
    mx = _flags(df, "MX_found")
    base = int(mx.sum())
    rows = []
    for label, column in _ADHERENCE:
        count = int((mx & _flags(df, column)).sum())
        rows.append(
            {
                "protocol": label,
                "count": count,
                "percent": count / base * 100 if base else 0.0,
            }
        )
    return pd.DataFrame(rows, columns=["protocol", "count", "percent"])


def _two_way_status(df, column, true_code, false_code):
    """Boolean flag mapped to ``true_code`` / ``false_code`` (nulls false)."""
    flag = _flags(df, column)
    status = pd.Series(false_code, index=df.index, dtype="string")
    status[flag] = true_code
    return status


def _protocol_status(df, valid_column, secure_column, valid_code, safe_code):
    """Three-way SPF/DMARC status: secure, valid-only or invalid.

    A missing or null flag counts as not satisfied, matching :func:`_flags`.
    """
    valid = _flags(df, valid_column)
    secure = _flags(df, secure_column)
    status = pd.Series("invalid", index=df.index, dtype="string")
    status[valid] = valid_code
    status[valid & secure] = safe_code
    return status


def status_by_domain(df):
    """Per-domain status code for each protocol, following the legacy rules.

    Codes are presentation-free: ``safe`` / ``valid`` / ``invalid`` for
    SPF and DMARC, ``valid`` / ``not_found`` for DKIM and ``signed`` /
    ``not_signed`` for DNSSEC. The page maps them to emoji and colors.
    """
    return pd.DataFrame(
        {
            "domain": df["domain"],
            "SPF_status": _protocol_status(
                df, "SPF_valid", "SPF_secure", "valid", "safe"
            ),
            "DMARC_status": _protocol_status(
                df, "DMARC_valid", "DMARC_secure", "valid", "safe"
            ),
            "DKIM_status": _two_way_status(df, "DKIM_valid", "valid", "not_found"),
            "DNSSEC_status": _two_way_status(
                df, "DNSSEC_signed", "signed", "not_signed"
            ),
        },
        index=df.index,
    )


def filter_domain(df, query):
    """Case-insensitive substring filter on ``domain`` only.

    This is intentionally narrower than the Dataset tab's cross-column search
    (``pages/3_Email Seguro.py``): it matches the ``domain`` column alone, so it
    must not be reused as a general dataset filter.
    """
    if not query:
        return df
    return df[df["domain"].str.contains(query, case=False, na=False, regex=False)]
