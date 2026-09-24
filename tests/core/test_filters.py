from types import SimpleNamespace

from core import filters, periods


class _FakeSidebar:
    def __init__(self, value):
        self.value = value
        self.warnings = []

    def multiselect(self, label, options, default=None, key=None):
        return self.value

    def warning(self, message):
        self.warnings.append(message)


def test_filters_reexports_period_helpers():
    assert filters.normalize_period is periods.normalize_period
    assert filters.PERIOD_TYPES is periods.PERIOD_TYPES


def test_country_widget_returns_list(monkeypatch):
    sidebar = _FakeSidebar(["Brasil (BR)", "Estados Unidos (US)"])
    monkeypatch.setattr(filters, "st", SimpleNamespace(sidebar=sidebar))
    assert filters.country_widget("test") == ["BR", "US"]
    assert sidebar.warnings == []


def test_country_widget_empty_selection_falls_back_to_br_and_warns(monkeypatch):
    sidebar = _FakeSidebar([])
    monkeypatch.setattr(filters, "st", SimpleNamespace(sidebar=sidebar))
    assert filters.country_widget("test") == ["BR"]
    assert sidebar.warnings == ["Nenhum país selecionado; usando Brasil."]
