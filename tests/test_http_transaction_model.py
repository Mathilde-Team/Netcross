"""Modèle de transaction HTTP commun et adaptateur HTTP/1.x (issue #1051).

Non-régression : build_http_transactions passe désormais par HttpTransaction ;
ses résultats doivent être strictement identiques à l'implémentation
précédente, recopiée ci-dessous comme référence (_reference_build).
"""

from __future__ import annotations

import random
import shutil
from collections import defaultdict, deque
from pathlib import Path

import pytest

from netcross_core.application import (
    ApplicationTransaction,
    HttpConnection,
    HttpTransaction,
    build_http_transactions,
    http1_transactions,
)
from netcross_core.application.models import HTTP_1X, HTTP_2, HTTP_3, _split_target
from tests.conftest import make_pkt

# --- référence : build_http_transactions avant #1051 (copie conforme) --------


def _reference_build(packets, network_signals=None):
    if network_signals is None:
        network_signals = {}
    pending = defaultdict(deque)
    transactions = []
    for pkt in packets:
        if pkt.proto != "TCP":
            continue
        if pkt.http_is_request:
            pending[(pkt.src, pkt.dst, pkt.sport, pkt.dport)].append(pkt)
        elif pkt.http_is_response:
            queue = pending.get((pkt.dst, pkt.src, pkt.dport, pkt.sport))
            if queue and queue[0].ts <= pkt.ts:
                req = queue.popleft()
                transactions.append(_reference_pair(req, pkt, network_signals))
    for key, queue in pending.items():
        for req in queue:
            client, server, _sport, _dport = key
            transactions.append(
                ApplicationTransaction(
                    protocol="HTTP",
                    point=req.point,
                    client=client,
                    server=server,
                    request_ts=req.ts,
                    response_ts=None,
                    total_time_ms=None,
                    request_summary=f"{req.http_method or 'GET'} {req.http_uri or '/'}",
                    response_summary="",
                    network_signals=list(network_signals.get(key, [])),
                )
            )
    transactions.sort(key=lambda t: t.request_ts or 0.0)
    return transactions


def _reference_pair(request, response, network_signals):
    total_ms = (response.ts - request.ts) * 1000.0 if response.ts and request.ts else None
    signals = network_signals.get((request.src, request.dst, request.sport, request.dport), [])
    return ApplicationTransaction(
        protocol="HTTP",
        point=request.point,
        client=request.src,
        server=request.dst,
        request_ts=request.ts,
        response_ts=response.ts,
        total_time_ms=total_ms,
        server_time_ms=response.http_response_time_ms,
        request_summary=f"{request.http_method or 'GET'} {request.http_uri or '/'}",
        response_summary=str(response.http_status_code or ""),
        network_signals=list(signals),
    )


def _dicts(transactions):
    return [t.to_dict() for t in transactions]


# --- jeux d'exemples -------------------------------------------------------------


def _req(ts, uri="/", method="GET", src="10.0.0.1", dst="10.0.0.2", sport=50000, dport=80, point="A", proto="TCP"):
    return make_pkt(
        proto=proto,
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


def _rep(ts, status=200, src="10.0.0.2", dst="10.0.0.1", sport=80, dport=50000, point="A", rt=None):
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
        http_response_time_ms=rt,
    )


EXEMPLES = {
    "simple": [_req(1.0), _rep(1.5, rt=480.0)],
    "sans_reponse": [_req(1.0)],
    "fifo_pipeline": [_req(1.0, "/p1"), _req(1.1, "/p2"), _rep(1.5), _rep(1.6, 301)],
    "reponse_avant_requete": [_rep(0.5), _req(1.0)],
    "reponse_orpheline": [_rep(2.0)],
    "non_tcp": [_req(1.0, proto="UDP"), _rep(1.5)],
    "horodatage_nul": [_req(0.0), _rep(0.2)],
    "methode_et_uri_absentes": [_req(1.0, uri=None, method=None), _rep(1.2, status=None)],
    "uri_absolue": [_req(1.0, "https://tls13.test/netcross-secret?x=1"), _rep(1.1)],
    "deux_flux_deux_points": [
        _req(1.0, "/a"),
        _req(1.05, "/b", sport=50001, point="B"),
        _rep(1.2, dport=50001, point="B", status=404),
        _req(1.3, "/c"),
        _rep(1.4, status=500),
    ],
}

SIGNAUX = {("10.0.0.1", "10.0.0.2", 50000, 80): ["retransmission", "lost_segment"]}


@pytest.mark.parametrize("nom", sorted(EXEMPLES))
@pytest.mark.parametrize("signaux", [None, SIGNAUX])
def test_resultats_identiques_a_l_ancienne_implementation(nom, signaux):
    paquets = EXEMPLES[nom]
    assert _dicts(build_http_transactions(paquets, signaux)) == _dicts(_reference_build(paquets, signaux))


def _paquets_aleatoires(graine: int):
    alea = random.Random(graine)
    paquets = []
    for i in range(300):
        port = 50000 + alea.randrange(6)
        point = alea.choice("AB")
        ts = round(alea.uniform(0.0, 30.0), 3)
        if alea.random() < 0.55:
            uri = alea.choice(["/", "/api", None, "http://h.test/x", f"/r/{i}"])
            paquets.append(_req(ts, uri, alea.choice(["GET", "POST", None]), sport=port, point=point))
        else:
            rt = alea.choice([None, round(alea.uniform(1, 500), 2)])
            paquets.append(_rep(ts, alea.choice([200, 204, 301, 404, 500, None]), dport=port, point=point, rt=rt))
    paquets.sort(key=lambda p: p.ts)
    return paquets


@pytest.mark.parametrize("graine", range(5))
def test_resultats_identiques_sur_series_aleatoires(graine):
    paquets = _paquets_aleatoires(graine)
    signaux = {("10.0.0.1", "10.0.0.2", 50000 + k, 80): [f"s{k}"] for k in range(0, 6, 2)}
    attendu = _dicts(_reference_build(paquets, signaux))
    assert len(attendu) > 50
    assert _dicts(build_http_transactions(paquets, signaux)) == attendu


EXEMPLES_GUIDE = sorted((Path(__file__).parent.parent / "docs/guide/exemples").glob("*.pcap"))


@pytest.mark.skipif(shutil.which("tshark") is None or not EXEMPLES_GUIDE, reason="tshark ou exemples absents")
@pytest.mark.parametrize("capture", EXEMPLES_GUIDE, ids=lambda p: p.name)
def test_resultats_identiques_sur_les_captures_du_guide(capture):
    from netcross_core.parsing import parse_capture

    paquets = sorted(parse_capture(capture.stem, str(capture)), key=lambda p: p.ts)
    assert _dicts(build_http_transactions(paquets)) == _dicts(_reference_build(paquets))


# --- modèle ------------------------------------------------------------------------


def test_adaptateur_http1_champs_du_modele():
    txns = http1_transactions(EXEMPLES["simple"] + EXEMPLES["uri_absolue"])
    assert len(txns) == 2
    simple, absolue = txns
    assert simple.version == HTTP_1X
    assert simple.connection == HttpConnection("TCP", "10.0.0.1", "10.0.0.2", 50000, 80)
    assert simple.stream_id is None
    assert (simple.method, simple.target, simple.authority, simple.path, simple.status) == ("GET", "/", None, "/", 200)
    assert (simple.request_ts, simple.first_byte_ts, simple.end_ts) == (1.0, 1.5, 1.5)
    assert simple.ttfb_ms == pytest.approx(500.0)
    assert simple.total_ms == pytest.approx(500.0)
    assert simple.server_time_ms == 480.0
    assert simple.answered
    assert (absolue.authority, absolue.path) == ("tls13.test", "/netcross-secret?x=1")


def test_adaptateur_http1_ordre_non_trie():
    # réponses appariées d'abord, puis requêtes sans réponse
    txns = http1_transactions([_req(1.0, "/sans"), _req(2.0, "/servie", sport=50001), _rep(2.5, dport=50001)])
    assert [t.target for t in txns] == ["/servie", "/sans"]
    sans = txns[1]
    assert not sans.answered
    assert (sans.status, sans.first_byte_ts, sans.end_ts, sans.ttfb_ms, sans.total_ms) == (None,) * 5


@pytest.mark.parametrize(
    ("cible", "autorite", "chemin"),
    [
        (None, None, None),
        ("", None, ""),
        ("/a?b", None, "/a?b"),
        ("*", None, "*"),
        ("http://h.test", "h.test", "/"),
        ("https://h.test:8443/x/y?z", "h.test:8443", "/x/y?z"),
        ("https:///x", None, "/x"),
    ],
)
def test_autorite_et_chemin_derives_de_la_cible(cible, autorite, chemin):
    assert _split_target(cible) == (autorite, chemin)


def test_transaction_http2_sur_le_meme_modele():
    connexion = HttpConnection("TCP", "10.0.0.1", "10.0.0.2", 50000, 443)
    txn = HttpTransaction(
        version=HTTP_2,
        point="CLIENT",
        connection=connexion,
        stream_id=5,
        method="GET",
        target="/index.html",
        authority="exemple.test",
        path="/index.html",
        status=200,
        request_ts=10.0,
        first_byte_ts=10.02,
        end_ts=10.25,
    )
    assert txn.ttfb_ms == pytest.approx(20.0)
    assert txn.total_ms == pytest.approx(250.0)
    app = txn.to_application_transaction({connexion.key(): ["zero_window"]})
    assert app.to_dict() | {"total_time_ms": None} == {
        "protocol": "HTTP",
        "point": "CLIENT",
        "client": "10.0.0.1",
        "server": "10.0.0.2",
        "request_ts": 10.0,
        "response_ts": 10.25,
        "total_time_ms": None,
        "network_time_ms": None,
        "server_time_ms": None,
        "request_summary": "GET /index.html",
        "response_summary": "200",
        "network_signals": ["zero_window"],
        "classification": "normal",
    }
    assert app.total_time_ms == pytest.approx(250.0)


def test_transaction_http3_premier_octet_sans_fin():
    connexion = HttpConnection("UDP", "10.0.0.1", "10.0.0.2", 50000, 443)
    txn = HttpTransaction.from_target(HTTP_3, "P", connexion, "/flux", stream_id=0, request_ts=1.0, first_byte_ts=1.1)
    assert (txn.authority, txn.path) == (None, "/flux")
    assert txn.answered
    assert txn.ttfb_ms == pytest.approx(100.0)
    assert txn.total_ms is None
    assert txn.to_application_transaction().response_ts is None


def test_from_target_respecte_une_autorite_explicite():
    connexion = HttpConnection("TCP", "a", "b", 1, 2)
    txn = HttpTransaction.from_target(HTTP_2, "P", connexion, "/x", authority=":authority.test")
    assert (txn.authority, txn.path, txn.target) == (":authority.test", "/x", "/x")
