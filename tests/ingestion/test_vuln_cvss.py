import logging

import requests

import scripts.vuln_dataset as vuln_dataset
from scripts.vuln_dataset import VulnIngestor


class _FakeCVE:
    def __init__(self, score, severity="CRITICAL", version="V31"):
        self.score = [version, score, severity]


def _http_404():
    response = requests.Response()
    response.status_code = 404
    return requests.exceptions.HTTPError("404 Client Error", response=response)


def _bare_ingestor(nvd_key="test-key", key_invalid=False):
    ingestor = VulnIngestor.__new__(VulnIngestor)
    ingestor.logger = logging.getLogger("test.vuln.cvss")
    ingestor.nvd_key = nvd_key
    ingestor._nvd_key_invalid = key_invalid
    return ingestor


def _patch(monkeypatch, fake_search):
    monkeypatch.setattr(vuln_dataset.nvdlib, "searchCVE", fake_search)
    sleeps = []
    monkeypatch.setattr(vuln_dataset, "sleep", lambda seconds: sleeps.append(seconds))
    return sleeps


def test_check_cvss_with_key_returns_score(monkeypatch):
    calls = []

    def fake_search(**kwargs):
        calls.append(kwargs)
        return [_FakeCVE(9.8)]

    _patch(monkeypatch, fake_search)
    ingestor = _bare_ingestor(nvd_key="valid-key")

    assert ingestor.check_cvss("CVE-2021-44228") == 9.8
    assert len(calls) == 1
    assert calls[0]["key"] == "valid-key"
    assert calls[0]["delay"] == 1


def test_check_cvss_invalid_key_falls_back_keyless_and_flags(monkeypatch):
    calls = []

    def fake_search(**kwargs):
        calls.append(kwargs)
        if kwargs.get("key") is not None:
            raise _http_404()
        return [_FakeCVE(9.8)]

    sleeps = _patch(monkeypatch, fake_search)
    ingestor = _bare_ingestor(nvd_key="bad-key")

    assert ingestor.check_cvss("CVE-2021-44228") == 9.8
    assert ingestor._nvd_key_invalid is True
    assert len(calls) == 2
    assert calls[0]["key"] == "bad-key"
    assert calls[1].get("key") is None
    assert "delay" not in calls[1]
    assert sleeps == []


def test_check_cvss_skips_key_once_marked_invalid(monkeypatch):
    calls = []

    def fake_search(**kwargs):
        calls.append(kwargs)
        return [_FakeCVE(7.5)]

    sleeps = _patch(monkeypatch, fake_search)
    ingestor = _bare_ingestor(nvd_key="bad-key", key_invalid=True)

    assert ingestor.check_cvss("CVE-2021-44228") == 7.5
    assert len(calls) == 1
    assert calls[0].get("key") is None
    assert sleeps == []


def test_check_cvss_keyless_404_does_not_retry(monkeypatch):
    calls = []

    def fake_search(**kwargs):
        calls.append(kwargs)
        raise _http_404()

    sleeps = _patch(monkeypatch, fake_search)
    ingestor = _bare_ingestor(nvd_key=None)

    assert ingestor.check_cvss("CVE-2021-44228") is None
    assert len(calls) == 1
    assert sleeps == []


def test_check_cvss_transient_error_retries_then_succeeds(monkeypatch):
    calls = []

    def fake_search(**kwargs):
        calls.append(kwargs)
        if len(calls) < 3:
            raise requests.exceptions.Timeout("boom")
        return [_FakeCVE(5.0)]

    sleeps = _patch(monkeypatch, fake_search)
    ingestor = _bare_ingestor(nvd_key="valid-key")

    assert ingestor.check_cvss("CVE-2021-44228") == 5.0
    assert len(calls) == 3
    assert sleeps == [3]


def test_check_cvss_keyless_empty_result_returns_none(monkeypatch):
    calls = []

    def fake_search(**kwargs):
        calls.append(kwargs)
        return []

    sleeps = _patch(monkeypatch, fake_search)
    ingestor = _bare_ingestor(nvd_key=None)

    assert ingestor.check_cvss("CVE-2020-0000") is None
    assert len(calls) == 1
    assert sleeps == []
