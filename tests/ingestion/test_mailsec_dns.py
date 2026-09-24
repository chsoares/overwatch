import types

import dns.resolver

import scripts.mailsec  # noqa: F401  (import installs the default resolver)
import scripts.mailsec_dnssec

DNS_SERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


def test_mailsec_installs_explicit_default_resolver():
    resolver = dns.resolver.default_resolver

    assert resolver is not None
    assert resolver.nameservers == DNS_SERVERS
    assert resolver.timeout == 3.0
    assert resolver.lifetime == 5.0


def test_mailsec_dnssec_exposes_dnskey_server_constant():
    assert scripts.mailsec_dnssec.DNSKEY_SERVER == "8.8.8.8"


def test_check_dnssec_uses_configured_dnskey_server(monkeypatch):
    captured = {}

    def fake_udp(request, server, timeout=2):
        captured["server"] = server
        captured["timeout"] = timeout
        return types.SimpleNamespace(answer=[])

    monkeypatch.setattr(
        scripts.mailsec_dnssec.dns.message, "make_query", lambda *a, **k: "request"
    )
    monkeypatch.setattr(scripts.mailsec_dnssec.dns.query, "udp", fake_udp)

    result = scripts.mailsec_dnssec.check_dnssec("example.gov.br")

    assert result is False
    assert captured["server"] == scripts.mailsec_dnssec.DNSKEY_SERVER
    assert captured["timeout"] == 2
