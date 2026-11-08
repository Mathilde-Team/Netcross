# SPDX-License-Identifier: GPL-3.0-or-later
"""
tests/test_application -- tests du modèle transactionnel applicatif
(Job 23, §6.9/§6.10).
"""

from __future__ import annotations

import pytest

from netcross_core.application import (
    ApplicationTransaction,
    TransactionClassification,
    TransactionThresholds,
    build_dns_transactions,
    build_http_transactions,
    classify_transaction,
)
from tests.conftest import make_pkt

# --- Helpers ----------------------------------------------------------------


def _http_request(ts=1.0, point="A", src="10.0.0.1", dst="10.0.0.2", sport=50000, dport=80, method="GET", uri="/"):
    return make_pkt(
        proto="TCP",
        point=point,
        ts=ts,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        http_is_request=True,
        http_method=method,
        http_uri=uri,
    )


def _http_response(
    ts=1.5, point="A", src="10.0.0.2", dst="10.0.0.1", sport=80, dport=50000, status=200, response_time_ms=None
):
    return make_pkt(
        proto="TCP",
        point=point,
        ts=ts,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        http_is_response=True,
        http_status_code=status,
        http_response_time_ms=response_time_ms,
    )


def _dns_query(
    ts=1.0, point="A", src="10.0.0.1", dst="10.0.0.2", sport=50000, dport=53, txn_id=1234, name="example.com"
):
    return make_pkt(
        proto="UDP",
        point=point,
        ts=ts,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        dns_txn_id=txn_id,
        dns_is_response=False,
        dns_qry_name=name,
    )


def _dns_response(
    ts=1.1, point="A", src="10.0.0.2", dst="10.0.0.1", sport=53, dport=50000, txn_id=1234, rcode=0, name="example.com"
):
    return make_pkt(
        proto="UDP",
        point=point,
        ts=ts,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        dns_txn_id=txn_id,
        dns_is_response=True,
        dns_qry_name=name,
        dns_rcode=rcode,
    )


# --- HTTP pairing -----------------------------------------------------------


def test_http_requete_reponse_appariee():
    pkts = [_http_request(ts=1.0), _http_response(ts=1.5, status=200)]
    txns = build_http_transactions(pkts)
    assert len(txns) == 1
    assert txns[0].protocol == "HTTP"
    assert txns[0].total_time_ms == 500.0
    assert txns[0].request_summary == "GET /"
    assert txns[0].response_summary == "200"


def test_http_sans_reponse_missing():
    pkts = [_http_request(ts=1.0)]
    txns = build_http_transactions(pkts)
    assert len(txns) == 1
    assert txns[0].response_ts is None
    assert txns[0].total_time_ms is None


def test_http_fifo_multiples_requetes():
    """Deux requêtes sur le même flux, deux réponses dans l'ordre."""
    pkts = [
        _http_request(ts=1.0, uri="/page1"),
        _http_request(ts=1.1, uri="/page2"),
        _http_response(ts=1.5, status=200),
        _http_response(ts=1.6, status=301),
    ]
    txns = build_http_transactions(pkts)
    assert len(txns) == 2
    assert txns[0].request_summary == "GET /page1"
    assert txns[1].request_summary == "GET /page2"


def test_http_non_tcp_ignore():
    pkts = [
        make_pkt(proto="UDP", http_is_request=True, http_method="GET", http_uri="/"),
    ]
    txns = build_http_transactions(pkts)
    assert len(txns) == 0


# --- DNS pairing ------------------------------------------------------------


def test_dns_query_response_appariee():
    pkts = [_dns_query(ts=1.0, name="example.com"), _dns_response(ts=1.05, name="example.com")]
    txns = build_dns_transactions(pkts)
    assert len(txns) == 1
    assert txns[0].protocol == "DNS"
    assert txns[0].total_time_ms == pytest.approx(50.0)
    assert txns[0].request_summary == "example.com"


def test_dns_sans_reponse_missing():
    pkts = [_dns_query(ts=1.0)]
    txns = build_dns_transactions(pkts)
    assert len(txns) == 1
    assert txns[0].response_ts is None


def test_dns_meme_txn_id_clients_differents_non_confondu():
    """Deux clients différents avec le même txn_id ne doivent pas être
    confondus."""
    pkts = [
        _dns_query(ts=1.0, src="10.0.0.1", sport=50000, txn_id=1234),
        _dns_query(ts=1.1, src="10.0.0.3", sport=50001, txn_id=1234),
        _dns_response(ts=1.2, src="10.0.0.2", dst="10.0.0.1", sport=53, dport=50000, txn_id=1234),
        _dns_response(ts=1.3, src="10.0.0.2", dst="10.0.0.3", sport=53, dport=50001, txn_id=1234),
    ]
    txns = build_dns_transactions(pkts)
    assert len(txns) == 2
    assert txns[0].client == "10.0.0.1"
    assert txns[1].client == "10.0.0.3"


def test_dns_fifo_ids_reutilises():
    """Même txn_id réutilisé séquentiellement -> FIFO correct."""
    pkts = [
        _dns_query(ts=1.0, txn_id=100, name="a.com"),
        _dns_response(ts=1.1, txn_id=100, name="a.com"),
        _dns_query(ts=2.0, txn_id=100, name="b.com"),
        _dns_response(ts=2.1, txn_id=100, name="b.com"),
    ]
    txns = build_dns_transactions(pkts)
    assert len(txns) == 2
    assert txns[0].request_summary == "a.com"
    assert txns[1].request_summary == "b.com"


def test_dns_non_udp_tcp_ignore():
    pkts = [
        make_pkt(proto="ICMP", dns_txn_id=1234, dns_is_response=False),
    ]
    txns = build_dns_transactions(pkts)
    assert len(txns) == 0


# --- Classification ---------------------------------------------------------


def test_classify_normal():
    txn = ApplicationTransaction(
        protocol="HTTP",
        point="A",
        client="c",
        server="s",
        request_ts=1.0,
        response_ts=1.1,
        total_time_ms=100.0,
    )
    assert classify_transaction(txn) == TransactionClassification.NORMAL


def test_classify_missing_response():
    txn = ApplicationTransaction(
        protocol="HTTP",
        point="A",
        client="c",
        server="s",
        request_ts=1.0,
        response_ts=None,
        total_time_ms=None,
    )
    assert classify_transaction(txn) == TransactionClassification.MISSING_RESPONSE


def test_classify_network_slow():
    txn = ApplicationTransaction(
        protocol="HTTP",
        point="A",
        client="c",
        server="s",
        request_ts=1.0,
        response_ts=2.0,
        total_time_ms=1000.0,
        network_signals=["retransmission", "lost_segment"],
    )
    assert classify_transaction(txn) == TransactionClassification.NETWORK_SLOW


def test_classify_server_slow():
    """server_time_ms mesuré et >= 60% du total -> server_slow."""
    txn = ApplicationTransaction(
        protocol="HTTP",
        point="A",
        client="c",
        server="s",
        request_ts=1.0,
        response_ts=2.0,
        total_time_ms=1000.0,
        server_time_ms=800.0,
    )
    assert classify_transaction(txn) == TransactionClassification.SERVER_SLOW


def test_classify_application_slow():
    """Lenteur sans signal réseau ni split serveur -> application_slow."""
    txn = ApplicationTransaction(
        protocol="HTTP",
        point="A",
        client="c",
        server="s",
        request_ts=1.0,
        response_ts=2.0,
        total_time_ms=1000.0,
    )
    assert classify_transaction(txn) == TransactionClassification.APPLICATION_SLOW


def test_classify_dns_normal_sous_seuil():
    txn = ApplicationTransaction(
        protocol="DNS",
        point="A",
        client="c",
        server="s",
        request_ts=1.0,
        response_ts=1.1,
        total_time_ms=100.0,
    )
    # 100ms < seuil DNS 200ms -> normal
    assert classify_transaction(txn) == TransactionClassification.NORMAL


def test_classify_dns_slow_au_dela_seuil():
    txn = ApplicationTransaction(
        protocol="DNS",
        point="A",
        client="c",
        server="s",
        request_ts=1.0,
        response_ts=1.3,
        total_time_ms=300.0,
    )
    # 300ms > seuil DNS 200ms -> application_slow (pas de signal réseau)
    assert classify_transaction(txn) == TransactionClassification.APPLICATION_SLOW


def test_classify_seuils_personnalisables():
    thresholds = TransactionThresholds(http_slow_ms=100.0)
    txn = ApplicationTransaction(
        protocol="HTTP",
        point="A",
        client="c",
        server="s",
        request_ts=1.0,
        response_ts=1.15,
        total_time_ms=150.0,
    )
    # 150ms > seuil personnalisé 100ms -> application_slow
    assert classify_transaction(txn, thresholds) == TransactionClassification.APPLICATION_SLOW


def test_classify_server_slow_non_dominant_reste_application():
    """server_time_ms présent mais < 60% du total -> application_slow."""
    txn = ApplicationTransaction(
        protocol="HTTP",
        point="A",
        client="c",
        server="s",
        request_ts=1.0,
        response_ts=2.0,
        total_time_ms=1000.0,
        server_time_ms=400.0,  # 40% < 60%
    )
    assert classify_transaction(txn) == TransactionClassification.APPLICATION_SLOW


def test_classify_network_slow_prioritaire_sur_server():
    """Si signaux réseau ET server_time dominant, network_slow gagne."""
    txn = ApplicationTransaction(
        protocol="HTTP",
        point="A",
        client="c",
        server="s",
        request_ts=1.0,
        response_ts=2.0,
        total_time_ms=1000.0,
        server_time_ms=800.0,
        network_signals=["retransmission"],
    )
    assert classify_transaction(txn) == TransactionClassification.NETWORK_SLOW


# --- Intégration dans Report ------------------------------------------------


def test_report_application_transactions_peuple():
    from netcross_core.analysis import analyse
    from netcross_core.correlate import correlate

    pkts = [
        _http_request(ts=1.0),
        _http_response(ts=1.6, status=200, response_time_ms=400.0),
        _dns_query(ts=2.0, name="test.com"),
        _dns_response(ts=2.3, name="test.com"),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A"], all_packets=pkts)
    assert len(r.application_transactions) == 2
    protocols = {t["protocol"] for t in r.application_transactions}
    assert "HTTP" in protocols
    assert "DNS" in protocols


def test_report_classification_missing_response_integree():
    from netcross_core.analysis import analyse
    from netcross_core.correlate import correlate

    pkts = [
        _http_request(ts=1.0),
        # pas de réponse
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A"], all_packets=pkts)
    assert len(r.application_transactions) == 1
    assert r.application_transactions[0]["classification"] == "missing_response"


def test_report_network_slow_avec_signaux_tcp():
    from netcross_core.analysis import analyse
    from netcross_core.correlate import correlate

    pkts = [
        _http_request(ts=1.0),
        _http_response(ts=2.0, status=200),  # 1000ms > seuil HTTP 500ms
        # un paquet TCP avec retransmission sur le même flux
        make_pkt(
            proto="TCP",
            point="A",
            ts=1.5,
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=50000,
            dport=80,
            is_retransmission=True,
        ),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A"], all_packets=pkts)
    http_txns = [t for t in r.application_transactions if t["protocol"] == "HTTP"]
    assert len(http_txns) == 1
    assert http_txns[0]["classification"] == "network_slow"
    assert "retransmission" in http_txns[0]["network_signals"]
