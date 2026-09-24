from core.analytics.common import normalize_iso2, selection_label


def test_normalize_iso2_scalar_to_list():
    assert normalize_iso2("BR") == ["BR"]


def test_normalize_iso2_list_passthrough():
    assert normalize_iso2(["BR", "US"]) == ["BR", "US"]


def test_normalize_iso2_none_and_empty():
    assert normalize_iso2(None) == []
    assert normalize_iso2([]) == []
    assert normalize_iso2("") == []


def test_selection_label_single():
    assert selection_label(["BR"], lambda c: "Brasil") == "Brasil"


def test_selection_label_multiple():
    assert selection_label(["BR", "US"], lambda c: "x") == "países selecionados"
