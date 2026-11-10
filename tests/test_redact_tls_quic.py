# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.redact -- levée de l'exclusion --redact avec --tls/--quic/
--client-group (issue #1155).

Couvre les deux helpers partages par les CLI, l'API et la GUI :
- redact_diagnostic_events : les evenements des pipelines independants
  TLS/QUIC passent par la MEME table de pseudonymes que les paquets ;
- redact_client_group : les adresses --client-group sont traduites AVANT
  usage, avec la table du run (coherence avec les paquets rediges).
"""

from conftest import make_pkt

from netcross_core.quic_diagnostics import QuicEvent
from netcross_core.redact import (
    AddressRedactor,
    redact_client_group,
    redact_diagnostic_events,
    redact_packets,
)
from netcross_core.tls_diagnostics import TlsEvent


def _tls_event(src="10.0.0.1", dst="93.184.216.34", sni="www.example.com"):
    return TlsEvent(
        point="LAN",
        ts=1000.0,
        src=src,
        sport=1234,
        dst=dst,
        dport=443,
        record_type="handshake",
        handshake_type="client_hello",
        sni=sni,
    )


def _quic_event(src="10.0.0.1", dst="93.184.216.34"):
    return QuicEvent(
        point="LAN",
        ts=1000.0,
        src=src,
        dst=dst,
        sport=1234,
        dport=443,
        dcid=b"\x01" * 8,
        decryptable=True,
        sni="www.example.com",
    )


# -- redact_diagnostic_events ------------------------------------------------


def test_redact_diagnostic_events_redige_adresses_et_sni():
    redactor = AddressRedactor()
    ev = _tls_event()
    redact_diagnostic_events([ev], redactor)
    assert ev.src != "10.0.0.1"
    assert ev.dst != "93.184.216.34"
    assert ev.sni != "www.example.com"
    assert ev.sni.endswith(".example.invalid")


def test_redact_diagnostic_events_meme_table_que_les_paquets():
    """Une adresse vue dans un paquet ET dans un evenement garde le meme
    pseudonyme (criteres d'acceptation de #1155)."""
    redactor = redact_packets([make_pkt(point="LAN", src="10.0.0.1", dst="93.184.216.34", dport=443, ts=1000.0)])
    ev = _tls_event()
    redact_diagnostic_events([ev], redactor)
    mapping = redactor.mapping
    assert ev.src == mapping["10.0.0.1"]
    assert ev.dst == mapping["93.184.216.34"]


def test_redact_diagnostic_events_quic():
    redactor = AddressRedactor()
    ev = _quic_event()
    redact_diagnostic_events([ev], redactor)
    assert ev.src != "10.0.0.1"
    assert ev.dst != "93.184.216.34"
    assert ev.sni.endswith(".example.invalid")


def test_redact_diagnostic_events_portee_adresses_seules_garde_le_sni():
    """--redact-scope adresses : les evenements TLS/QUIC ne redigent que
    les adresses, le SNI reste en clair (meme portee que les paquets)."""
    redactor = AddressRedactor(scope="adresses")
    ev = _tls_event()
    redact_diagnostic_events([ev], redactor)
    assert ev.src != "10.0.0.1"
    assert ev.sni == "www.example.com"


def test_redact_diagnostic_events_sans_sni():
    redactor = AddressRedactor()
    ev = _tls_event()
    ev.sni = None
    redact_diagnostic_events([ev], redactor)
    assert ev.sni is None


# -- redact_client_group -----------------------------------------------------


def test_redact_client_group_traduit_les_adresses():
    redactor = AddressRedactor()
    translated = redact_client_group({"PosteA": {"10.0.0.5", "10.0.0.6"}, "PosteB": {"10.0.0.12"}}, redactor)
    assert set(translated) == {"PosteA", "PosteB"}
    for ips in translated.values():
        for ip in ips:
            assert ip not in ("10.0.0.5", "10.0.0.6", "10.0.0.12")


def test_redact_client_group_meme_table_que_les_paquets():
    """Un groupe dont une IP apparait dans les captures garde la
    correspondance du run : la comparaison client vs client retrouve
    les paquets rediges."""
    redactor = redact_packets([make_pkt(point="LAN", src="10.0.0.5", dst="10.0.0.6", dport=80, ts=1000.0)])
    translated = redact_client_group({"PosteA": {"10.0.0.5"}, "PosteB": {"10.0.0.6"}}, redactor)
    mapping = redactor.mapping
    assert translated["PosteA"] == {mapping["10.0.0.5"]}
    assert translated["PosteB"] == {mapping["10.0.0.6"]}
