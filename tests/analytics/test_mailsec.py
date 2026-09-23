"""Behavior tests for the pure mail-security analytics port."""

import pandas as pd
import pytest

from core.analytics import mailsec
from tests.analytics._datasets import MAILSEC_CSV

_FLAGS = [
    "MX_found",
    "SPF_valid",
    "SPF_secure",
    "DMARC_valid",
    "DMARC_secure",
    "DKIM_valid",
    "DNSSEC_signed",
]


def _frame():
    """Crafted frame covering secure, vulnerable, critical, no-MX and null rows."""
    df = pd.DataFrame(
        {
            "domain": [
                "alpha.gov.br",
                "beta.gov.br",
                "gamma.gov.br",
                "delta.gov.br",
                "epsilon.gov.br",
            ],
            "MX_found": [True, True, True, False, pd.NA],
            "SPF_valid": [True, True, False, True, pd.NA],
            "SPF_secure": [True, False, False, False, pd.NA],
            "DMARC_valid": [True, False, False, True, pd.NA],
            "DMARC_secure": [True, False, False, False, pd.NA],
            "DKIM_valid": [True, False, False, False, pd.NA],
            "DNSSEC_signed": [True, False, False, False, pd.NA],
        }
    )
    return df.astype({column: "boolean" for column in _FLAGS})


def test_overview_reproduces_page_overview_numbers():
    assert mailsec.overview(_frame()) == {
        "domains": 5,
        "with_email": 3,
        "spf_secure": 1,
        "dmarc_secure": 1,
        "dkim_valid": 1,
        "dnssec_signed": 1,
        "secure_domains": 1,
        "vulnerable_domains": 2,
        "critical_domains": 1,
    }


def test_overview_empty_returns_zeros():
    assert mailsec.overview(_frame().iloc[0:0]) == {
        "domains": 0,
        "with_email": 0,
        "spf_secure": 0,
        "dmarc_secure": 0,
        "dkim_valid": 0,
        "dnssec_signed": 0,
        "secure_domains": 0,
        "vulnerable_domains": 0,
        "critical_domains": 0,
    }


def test_overview_missing_columns_fall_back_to_zero():
    df = pd.DataFrame(
        {"domain": ["a.gov.br", "b.gov.br"], "MX_found": [True, False]}
    ).astype({"MX_found": "boolean"})
    assert mailsec.overview(df) == {
        "domains": 2,
        "with_email": 1,
        "spf_secure": 0,
        "dmarc_secure": 0,
        "dkim_valid": 0,
        "dnssec_signed": 0,
        "secure_domains": 0,
        "vulnerable_domains": 1,
        "critical_domains": 0,
    }


def test_overview_null_flags_are_not_counted():
    counts = mailsec.overview(_frame())
    assert counts["with_email"] == 3
    assert counts["spf_secure"] == 1
    assert counts["secure_domains"] == 1


def test_overview_matches_frozen_dataset_snapshot():
    # Captured from the frozen snapshot at tests/fixtures/mailsec_dataset.csv.
    # Pins the six base metrics plus the three derived metrics.
    assert mailsec.overview(mailsec.load_dataset(MAILSEC_CSV)) == {
        "domains": 1276,
        "with_email": 551,
        "spf_secure": 471,
        "dmarc_secure": 210,
        "dkim_valid": 325,
        "dnssec_signed": 168,
        "secure_domains": 82,
        "vulnerable_domains": 469,
        "critical_domains": 45,
    }


def test_overview_critical_excludes_null_flags():
    columns = ["MX_found", "SPF_valid", "DMARC_valid", "DKIM_valid", "DNSSEC_signed"]
    df = pd.DataFrame(
        {
            "domain": ["null-spf.gov.br", "all-invalid.gov.br"],
            "MX_found": [True, True],
            "SPF_valid": [pd.NA, False],
            "DMARC_valid": [False, False],
            "DKIM_valid": [False, False],
            "DNSSEC_signed": [False, False],
        }
    ).astype({column: "boolean" for column in columns})
    assert mailsec.overview(df)["critical_domains"] == 1


def test_filter_domain_empty_query_returns_all_without_mutating():
    df = _frame()
    before = df.copy(deep=True)
    result = mailsec.filter_domain(df, "")
    pd.testing.assert_frame_equal(result, df)
    pd.testing.assert_frame_equal(df, before)


def test_filter_domain_matches_case_insensitively_and_substring():
    df = _frame()
    assert list(mailsec.filter_domain(df, "GAMMA")["domain"]) == ["gamma.gov.br"]
    assert len(mailsec.filter_domain(df, "gov")) == 5


def test_filter_domain_skips_null_domains():
    df = pd.DataFrame({"domain": ["admin.gov.br", pd.NA, "Saude.gov.br"]}).astype(
        {"domain": "string"}
    )
    result = mailsec.filter_domain(df, "gov")
    assert len(result) == 2
    assert list(mailsec.filter_domain(df, "SAUDE")["domain"]) == ["Saude.gov.br"]


def test_filter_domain_treats_query_as_literal_text():
    df = pd.DataFrame(
        {"domain": ["a.gov.br", "weird(x).gov.br", "axgov.br"]}
    ).astype({"domain": "string"})
    assert list(mailsec.filter_domain(df, "(x)")["domain"]) == ["weird(x).gov.br"]
    assert list(mailsec.filter_domain(df, "a.gov")["domain"]) == ["a.gov.br"]


def test_load_dataset_uses_page_dtype_contract():
    df = mailsec.load_dataset(MAILSEC_CSV)
    for column in ("domain", "SPF", "DMARC", "DKIM"):
        assert str(df[column].dtype) == "string", column
    for column in _FLAGS:
        assert str(df[column].dtype) == "boolean", column


def test_load_dataset_defaults_to_live_data_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(mailsec, "DATA_DIR", tmp_path)
    (tmp_path / "mailsec_dataset.csv").write_text("domain,MX_found\nx,True\n")
    df = mailsec.load_dataset()
    assert list(df["domain"]) == ["x"]


def test_status_by_domain_applies_original_rules():
    result = mailsec.status_by_domain(_frame())
    assert list(result.columns) == [
        "domain",
        "SPF_status",
        "DMARC_status",
        "DKIM_status",
        "DNSSEC_status",
    ]
    assert list(result["domain"]) == [
        "alpha.gov.br",
        "beta.gov.br",
        "gamma.gov.br",
        "delta.gov.br",
        "epsilon.gov.br",
    ]
    assert list(result["SPF_status"]) == [
        "safe",
        "valid",
        "invalid",
        "valid",
        "invalid",
    ]
    assert list(result["DMARC_status"]) == [
        "safe",
        "invalid",
        "invalid",
        "valid",
        "invalid",
    ]
    assert list(result["DKIM_status"]) == [
        "valid",
        "not_found",
        "not_found",
        "not_found",
        "not_found",
    ]
    assert list(result["DNSSEC_status"]) == [
        "signed",
        "not_signed",
        "not_signed",
        "not_signed",
        "not_signed",
    ]


def test_status_by_domain_treats_null_flags_as_unsatisfied():
    columns = ["SPF_valid", "SPF_secure", "DMARC_valid", "DMARC_secure",
               "DKIM_valid", "DNSSEC_signed"]
    df = pd.DataFrame(
        {
            "domain": ["null.gov.br"],
            "SPF_valid": [pd.NA],
            "SPF_secure": [pd.NA],
            "DMARC_valid": [pd.NA],
            "DMARC_secure": [pd.NA],
            "DKIM_valid": [pd.NA],
            "DNSSEC_signed": [pd.NA],
        }
    ).astype({column: "boolean" for column in columns})
    result = mailsec.status_by_domain(df).iloc[0]
    assert result["SPF_status"] == "invalid"
    assert result["DMARC_status"] == "invalid"
    assert result["DKIM_status"] == "not_found"
    assert result["DNSSEC_status"] == "not_signed"


def test_status_by_domain_does_not_mutate_input():
    df = _frame()
    before = df.copy(deep=True)
    mailsec.status_by_domain(df)
    pd.testing.assert_frame_equal(df, before)


def _adherence_frame():
    """Four domains: three with MX (two valid, one secure) plus one non-MX."""
    df = pd.DataFrame(
        {
            "domain": ["a.gov.br", "b.gov.br", "c.gov.br", "d.gov.br"],
            "MX_found": [True, True, True, False],
            "SPF_valid": [True, True, False, True],
            "SPF_secure": [True, False, False, True],
            "DMARC_valid": [True, True, False, True],
            "DMARC_secure": [True, False, False, True],
            "DKIM_valid": [True, False, False, True],
            "DNSSEC_signed": [True, False, False, True],
        }
    )
    return df.astype({column: "boolean" for column in _FLAGS})


def test_protocol_adherence_uses_mx_denominator():
    result = mailsec.protocol_adherence(_adherence_frame())
    assert list(result["protocol"]) == [
        "SPF válido",
        "SPF seguro",
        "DMARC válido",
        "DMARC seguro",
        "DKIM",
        "DNSSEC",
    ]
    assert list(result["count"]) == [2, 1, 2, 1, 1, 1]
    for percent, expected in zip(result["percent"], [200 / 3, 100 / 3, 200 / 3, 100 / 3, 100 / 3, 100 / 3]):
        assert percent == pytest.approx(expected)


def test_protocol_adherence_without_mx_is_zero():
    df = _adherence_frame()
    df["MX_found"] = pd.Series([False, False, False, False], dtype="boolean")
    result = mailsec.protocol_adherence(df)
    assert list(result["count"]) == [0, 0, 0, 0, 0, 0]
    assert list(result["percent"]) == [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]


def test_protocol_adherence_matches_frozen_dataset_snapshot():
    result = mailsec.protocol_adherence(mailsec.load_dataset(MAILSEC_CSV))
    assert list(result["count"]) == [491, 471, 344, 210, 325, 168]
    expected = [c / 551 * 100 for c in [491, 471, 344, 210, 325, 168]]
    for percent, want in zip(result["percent"], expected):
        assert percent == pytest.approx(want)


def test_protocol_sunburst_spf_structure():
    sunburst = mailsec.protocol_sunburst(_frame(), "spf")
    assert sunburst["ids"] == [
        "Total",
        "MX=True",
        "MX=False",
        "SPF_valid=True",
        "SPF_valid=False",
        "SPF_secure=True",
        "SPF_secure=False",
    ]
    assert sunburst["labels"] == [
        "Total",
        "Com MX",
        "Sem MX",
        "SPF válido",
        "SPF inválido",
        "SPF seguro",
        "SPF não seguro",
    ]
    assert sunburst["parents"] == [
        "",
        "Total",
        "Total",
        "MX=True",
        "MX=True",
        "SPF_valid=True",
        "SPF_valid=True",
    ]
    assert sunburst["values"] == [5, 3, 2, 2, 1, 1, 1]


def test_protocol_sunburst_values_sum_to_parents_for_every_protocol():
    df = _frame()
    for protocol in ("spf", "dmarc", "dkim", "dnssec"):
        sunburst = mailsec.protocol_sunburst(df, protocol)
        ids = sunburst["ids"]
        parents = sunburst["parents"]
        values = sunburst["values"]
        assert values[0] == len(df)
        assert values[1] + values[2] == values[0]
        for node_id, parent, value in zip(ids, parents, values):
            if not parent:
                continue
            children = [
                child_value
                for child_value, child_parent in zip(values, parents)
                if child_parent == node_id
            ]
            if children:
                assert sum(children) == value, f"{protocol}:{node_id}"


def test_protocol_sunburst_dkim_and_dnssec_branches():
    df = _frame()
    dkim = mailsec.protocol_sunburst(df, "dkim")
    assert dkim["ids"] == [
        "Total",
        "MX=True",
        "MX=False",
        "DKIM_valid=True",
        "DKIM_valid=False",
    ]
    assert dkim["labels"][-2:] == ["DKIM válido", "DKIM não encontrado"]
    assert dkim["values"] == [5, 3, 2, 1, 2]

    dnssec = mailsec.protocol_sunburst(df, "dnssec")
    assert dnssec["ids"] == [
        "Total",
        "MX=True",
        "MX=False",
        "DNSSEC_valid=True",
        "DNSSEC_valid=False",
    ]
    assert dnssec["labels"][-2:] == ["DNSSEC válido", "DNSSEC não encontrado"]
    assert dnssec["values"] == [5, 3, 2, 1, 2]


def test_protocol_sunburst_rejects_unknown_protocol():
    with pytest.raises(ValueError):
        mailsec.protocol_sunburst(_frame(), "tls")


def test_critical_domains_selects_mx_without_any_protocol():
    result = mailsec.critical_domains(_frame())
    assert list(result.columns) == ["domain"]
    assert list(result["domain"]) == ["gamma.gov.br"]


def test_critical_domains_excludes_non_mx_and_null_flags():
    columns = ["MX_found", "SPF_valid", "DMARC_valid", "DKIM_valid", "DNSSEC_signed"]
    df = pd.DataFrame(
        {
            "domain": [
                "nomx.gov.br",
                "null-spf.gov.br",
                "critical.gov.br",
                "invalid.gov.br",
            ],
            "MX_found": [False, True, True, True],
            "SPF_valid": [False, pd.NA, False, False],
            "DMARC_valid": [False, False, False, True],
            "DKIM_valid": [False, False, False, False],
            "DNSSEC_signed": [False, False, False, False],
        }
    ).astype({column: "boolean" for column in columns})
    assert list(mailsec.critical_domains(df)["domain"]) == ["critical.gov.br"]


def test_critical_domains_matches_overview_count_on_frozen_snapshot():
    df = mailsec.load_dataset(MAILSEC_CSV)
    result = mailsec.critical_domains(df)
    assert len(result) == mailsec.overview(df)["critical_domains"] == 45
    assert list(result["domain"])[:5] == [
        "abrasil.gov.br",
        "acre.gov.br",
        "aeroshopping.gov.br",
        "bancodonordeste.gov.br",
        "biodiversidade.gov.br",
    ]
    assert list(result["domain"])[-3:] == [
        "sintegra.gov.br",
        "trt.gov.br",
        "vidadacrianca.gov.br",
    ]
