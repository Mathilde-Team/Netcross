# SPDX-License-Identifier: GPL-3.0-or-later
"""Anonymisation des champs nommes et option --redact-scope (issue #1153)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from conftest import make_pkt

import cross_capture_analyzer_cli as cli
from netcross_core.redact import (
    SCOPE_ADDRESSES,
    SCOPE_ALL,
    SCOPE_NAMES,
    AddressRedactor,
    redact_packets,
    redaction_map_csv,
    scope_label,
)
from netcross_core.security import findings as security_findings

REAL_NAMES = (
    "intranet.acme-secret.fr",
    "acme-secret.fr",
    "compta/salaires",
    "CN=intranet.acme-secret.fr",
    "Acme Secret Root CA",
    "a84b4c76e66710@pbx.acme-secret.fr",
    "Yealink SIP-T46S",
    "Asterisk PBX 18",
)
REAL_ADDRESSES = ("10.66.1.10", "10.66.1.20", "10.66.9.9")


def _named_packets(point="A", t0=100.0):
    c = {"src": "10.66.1.10", "dst": "10.66.1.20", "sport": 50000}
    s = {"src": "10.66.1.20", "dst": "10.66.1.10", "dport": 50000}
    return [
        make_pkt(
            point=point, ts=t0, frame_number=1, proto="UDP", dport=53, dns_qry_name="Intranet.ACME-secret.fr.", **c
        ),
        make_pkt(
            point=point,
            ts=t0 + 0.01,
            frame_number=2,
            dport=80,
            http_is_request=True,
            http_method="GET",
            http_uri="http://intranet.acme-secret.fr:8080/compta/salaires.xlsx?annee=2026",
            **c,
        ),
        make_pkt(
            point=point,
            ts=t0 + 0.02,
            frame_number=3,
            sport=443,
            tls_cert_san=("intranet.acme-secret.fr", "*.acme-secret.fr", "*.fr", ""),
            tls_cert_san_ip=("10.66.9.9",),
            tls_cert_subject="CN=intranet.acme-secret.fr",
            tls_cert_issuer="CN=Acme Secret Root CA",
            **s,
        ),
        make_pkt(
            point=point,
            ts=t0 + 0.03,
            frame_number=4,
            proto="UDP",
            dport=5060,
            sip_call_id="a84b4c76e66710@pbx.acme-secret.fr",
            sip_msg_type="INVITE",
            sip_user_agent="Yealink SIP-T46S",
            **c,
        ),
        make_pkt(
            point=point,
            ts=t0 + 0.04,
            frame_number=5,
            proto="UDP",
            sport=5060,
            sip_call_id="a84b4c76e66710@pbx.acme-secret.fr",
            sip_msg_type="200",
            sip_server="Asterisk PBX 18",
            **s,
        ),
    ]


# --- portee ---------------------------------------------------------------------


def test_portee_inconnue_refusee():
    with pytest.raises(ValueError, match="portée d'anonymisation inconnue"):
        AddressRedactor("partiel")


def test_portee_par_defaut_tout():
    assert AddressRedactor().scope == SCOPE_ALL
    assert redact_packets([]).scope == SCOPE_ALL


@pytest.mark.parametrize(
    ("scope", "text"),
    [(SCOPE_ADDRESSES, "adresses IP/MAC anonymisees"), (SCOPE_NAMES, "noms"), (SCOPE_ALL, "adresses IP/MAC et noms")],
)
def test_scope_label(scope, text):
    assert text in scope_label(scope)


def test_portee_adresses_laisse_les_noms():
    pkts = _named_packets()
    redact_packets(pkts, SCOPE_ADDRESSES)
    assert pkts[0].src.startswith("192.0.2.")
    assert pkts[0].dns_qry_name == "Intranet.ACME-secret.fr."
    assert pkts[2].tls_cert_san_ip == ("192.0.2.3",)
    assert pkts[3].sip_user_agent == "Yealink SIP-T46S"


def test_portee_noms_laisse_les_adresses():
    pkts = _named_packets()
    redactor = redact_packets(pkts, SCOPE_NAMES)
    assert pkts[0].src == "10.66.1.10"
    assert pkts[2].tls_cert_san_ip == ("10.66.9.9",)
    assert pkts[0].dns_qry_name.endswith(".example.invalid")
    assert len(redactor) == 0
    assert len(redactor.names) >= 1


# --- champs nommes ----------------------------------------------------------------


def test_champs_nommes_pseudonymises_et_stables():
    pkts = _named_packets()
    redactor = redact_packets(pkts)
    dns, http, tls, invite, ok = pkts
    assert dns.dns_qry_name == "host-1.domain-1.example.invalid"
    assert http.http_uri == "http://host-1.domain-1.example.invalid:8080/res-1"
    assert tls.tls_cert_san == ("host-1.domain-1.example.invalid", "*.host-2.example.invalid", "*.fr", "")
    assert tls.tls_cert_subject == "CN=dn-1"
    assert tls.tls_cert_issuer == "CN=dn-2"
    # meme dialogue SIP : meme Call-ID pseudonymise
    assert invite.sip_call_id == ok.sip_call_id == "call-1@example.invalid"
    assert invite.sip_user_agent == "agent-1"
    assert ok.sip_server == "agent-2"
    kinds = {kind for _real, _pseudo, kind in redactor.entries()}
    assert {"ipv4", "nom", "domaine", "dn", "call-id", "agent", "ressource"} <= kinds
    csv_text = redaction_map_csv(redactor.entries())
    assert "Yealink SIP-T46S,agent-1,agent" in csv_text


def test_auto_signe_conserve():
    pk = make_pkt(tls_cert_subject="CN=srv.acme.fr", tls_cert_issuer="CN=srv.acme.fr")
    redact_packets([pk])
    assert pk.tls_cert_subject == pk.tls_cert_issuer == "CN=dn-1"


def test_idempotence_deux_passes():
    pkts = _named_packets()
    redactor = AddressRedactor(SCOPE_NAMES)
    redactor.redact(pkts)
    first = [(p.dns_qry_name, p.http_uri, p.tls_cert_subject, p.sip_call_id) for p in pkts]
    redactor.redact(pkts)
    assert [(p.dns_qry_name, p.http_uri, p.tls_cert_subject, p.sip_call_id) for p in pkts] == first


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("/", "/"),
        ("*", "*"),
        ("", ""),
        ("/login?u=alice", "/res-1"),
        ("https://www.acme.fr/", "https://host-1.domain-1.example.invalid/"),
        ("https://www.acme.fr", "https://host-1.domain-1.example.invalid"),
        ("http://user:pw@www.acme.fr/x", "http://host-1.domain-1.example.invalid/res-1"),
        ("http://10.1.2.3:8080/x", "http://192.0.2.3:8080/res-1"),
        ("http://[2001:4860::8888]/x", "http://[2001:db8::1]/res-1"),
        ("www.acme.fr:443", "host-1.domain-1.example.invalid:443"),
        ("www.acme.fr", "host-1.domain-1.example.invalid"),
        ("10.1.2.3:443", "192.0.2.3:443"),
    ],
)
def test_formes_de_cible_http(uri, expected):
    pk = make_pkt(http_uri=uri)
    redact_packets([pk])
    assert pk.http_uri == expected


def test_san_adresse_ip_dans_les_noms():
    pk = make_pkt(tls_cert_san=("10.1.2.3",), tls_cert_san_ip=("pas-une-ip",))
    redact_packets([pk])
    assert pk.tls_cert_san == ("192.0.2.3",)
    assert pk.tls_cert_san_ip == ("pas-une-ip",)


def test_champs_absents_sans_effet():
    pk = make_pkt()
    redact_packets([pk])
    assert pk.dns_qry_name is None
    assert pk.http_uri is None
    assert pk.sip_call_id is None


# --- bout en bout : aucune valeur reelle dans les sorties -------------------------------


@pytest.fixture
def lance(monkeypatch):
    pkts = [*_named_packets("A", 100.0), *_named_packets("B", 100.005)]
    monkeypatch.setattr(
        cli, "parse_capture", lambda label, path, raise_on_error=False: [p for p in pkts if p.point == label]
    )
    monkeypatch.setattr(security_findings, "scan_capture_exploits", lambda label, path: [])

    def _run(*argv):
        args = ["cross_capture_analyzer_cli.py", "--capture", "A=a.pcap", "--capture", "B=b.pcap"]
        monkeypatch.setattr(sys, "argv", [*args, *map(str, argv)])
        try:
            cli.main()
        except SystemExit as exc:
            return exc.code
        return 0

    return _run


def _outputs(tmp_path: Path) -> dict[str, Path]:
    return {
        "--json-report": tmp_path / "r.json",
        "--md-report": tmp_path / "r.md",
        "--detail-csv": tmp_path / "d.csv",
        "--zeek-conn": tmp_path / "conn.log",
        "--prom-file": tmp_path / "m.prom",
        "--openmetrics-file": tmp_path / "m.om",
    }


def test_aucune_valeur_reelle_dans_les_sorties(lance, tmp_path, capsys):
    outputs = _outputs(tmp_path)
    argv = ["--redact", "--redact-map", tmp_path / "map.csv"]
    for option, path in outputs.items():
        argv += [option, path]
    assert lance(*argv) == 0
    stdout = capsys.readouterr().out
    assert "--redact-scope tout" in stdout
    texts = {"stdout": stdout} | {name: path.read_text(encoding="utf-8") for name, path in outputs.items()}
    real = [v.lower() for v in (*REAL_NAMES, *REAL_ADDRESSES)]
    for name, text in texts.items():
        lowered = text.lower()
        leaks = [v for v in real if v in lowered]
        assert not leaks, f"{name} contient {leaks}"
    # la table privee, elle, les contient toutes (sinon le test ne prouverait rien)
    private = (tmp_path / "map.csv").read_text(encoding="utf-8").lower()
    assert all(v in private for v in real)


def test_portee_adresses_laisse_fuiter_les_noms(lance, tmp_path, capsys):
    json_path = tmp_path / "r.json"
    assert lance("--redact", "--redact-scope", "adresses", "--json-report", json_path) == 0
    assert "--redact-scope adresses" in capsys.readouterr().out
    text = json_path.read_text(encoding="utf-8")
    assert "intranet.acme-secret.fr" in text
    assert "10.66.1.10" not in text


def test_temoin_sans_redact_les_valeurs_fuient(lance, tmp_path, capsys):
    # temoin : sans --redact, les memes sorties portent bien les valeurs reelles
    json_path = tmp_path / "r.json"
    assert lance("--json-report", json_path) == 0
    stdout = capsys.readouterr().out
    assert "Yealink SIP-T46S" in stdout
    assert "a84b4c76e66710@pbx.acme-secret.fr" in json_path.read_text(encoding="utf-8")


def test_redact_scope_sans_redact_refuse(lance, capsys):
    assert lance("--redact-scope", "noms") == 1
    assert "--redact-scope necessite --redact" in capsys.readouterr().err
