"""Tests de l'export Zeek conn.log (issue #1115, chantier #1003).

Relecture facon ``zeek-cut`` : un analyseur TSV qui suit les en-tetes
``#separator``/``#fields``/``#types`` comme le fait Zeek, et qui verifie que
chaque ligne a exactement les colonnes annoncees. Puis la variante JSON,
les etats TCP, les colonnes multi-points et ``--redact``.
"""

from __future__ import annotations

import json
import sys

import pytest
from conftest import make_pkt

import cross_capture_analyzer_cli as cli
from netcross_core.redact import redact_packets
from netcross_report import zeek_export as zk

# -- analyseur TSV « zeek-cut » ----------------------------------------------------------------


def lire_conn_log(texte: str) -> tuple[dict[str, str], list[str], list[str], list[dict[str, str]]]:
    """Relit un conn.log TSV comme zeek-cut : en-tetes, #fields, #types, lignes."""
    lignes = texte.splitlines()
    assert lignes[0] == "#separator \\x09"
    sep = "\t"
    entetes: dict[str, str] = {}
    fields: list[str] = []
    types: list[str] = []
    rows: list[dict[str, str]] = []
    for ligne in lignes[1:]:
        if ligne.startswith("#"):
            cle, _, valeur = ligne[1:].partition(sep)
            if cle == "fields":
                fields = valeur.split(sep)
            elif cle == "types":
                types = valeur.split(sep)
            else:
                entetes[cle] = valeur
            continue
        valeurs = ligne.split(sep)
        assert len(valeurs) == len(fields), f"colonnes : {len(valeurs)} au lieu de {len(fields)}"
        rows.append(dict(zip(fields, valeurs, strict=True)))
    return entetes, fields, types, rows


def _tcp(point, t0, client="10.0.0.1", serveur="10.0.0.2", fin=True, lag=0.0):
    c = {"src": client, "dst": serveur, "sport": 50000, "dport": 443, "point": point}
    s = {"src": serveur, "dst": client, "sport": 443, "dport": 50000, "point": point}
    pkts = [
        make_pkt(ts=t0 + lag, flags="SYN", seq=1, length=74, **c),
        make_pkt(ts=t0 + 0.020 + lag, flags="SYN,ACK", seq=9, ack=2, length=74, **s),
        make_pkt(ts=t0 + 0.021 + lag, flags="ACK", seq=2, length=66, **c),
        make_pkt(
            ts=t0 + 0.030 + lag,
            flags="PSH,ACK",
            seq=3,
            tcp_len=100,
            payload_hash="p1",
            length=166,
            tls_client_hello=True,
            **c,
        ),
        make_pkt(ts=t0 + 0.050 + lag, flags="PSH,ACK", seq=10, tcp_len=400, payload_hash="p2", length=466, **s),
    ]
    if fin:
        pkts += [
            make_pkt(ts=t0 + 0.060 + lag, flags="FIN,ACK", seq=103, length=66, **c),
            make_pkt(ts=t0 + 0.070 + lag, flags="FIN,ACK", seq=410, length=66, **s),
        ]
    return pkts


# -- en-tetes et colonnes ----------------------------------------------------------------------


def test_entetes_fields_types_conformes():
    texte = zk.to_tsv(zk.build_conn_records(_tcp("A", 1_700_000_000.0), ["A"]))
    entetes, fields, types, rows = lire_conn_log(texte)
    assert entetes["set_separator"] == ","
    assert entetes["empty_field"] == "(empty)"
    assert entetes["unset_field"] == "-"
    assert entetes["path"] == "conn"
    assert entetes["open"] == "2023-11-14-22-13-20"
    assert "close" in entetes
    standard = [n for n, _t in zk.ZEEK_STANDARD_FIELDS]
    # colonnes Zeek standard d'abord, dans l'ordre de Zeek, puis netcross_*
    assert fields[: len(standard)] == standard
    assert fields[:6] == ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"]
    assert all(f.startswith("netcross_") for f in fields[len(standard) :])
    assert len(types) == len(fields)
    assert dict(zip(fields, types, strict=True))["ts"] == "time"
    assert dict(zip(fields, types, strict=True))["id.orig_h"] == "addr"
    assert dict(zip(fields, types, strict=True))["netcross_points"] == "set[string]"
    assert texte.splitlines()[-1].startswith("#close\t")
    assert len(rows) == 1


def test_connexion_tcp_complete():
    (row,) = lire_conn_log(zk.to_tsv(zk.build_conn_records(_tcp("A", 100.0), ["A"])))[3]
    assert row["id.orig_h"] == "10.0.0.1" and row["id.orig_p"] == "50000"
    assert row["id.resp_h"] == "10.0.0.2" and row["id.resp_p"] == "443"
    assert row["proto"] == "tcp"
    assert row["service"] == "ssl"
    assert row["conn_state"] == "SF"
    assert row["history"] == "ShADdFf"
    assert row["orig_pkts"] == "4" and row["resp_pkts"] == "3"
    assert row["orig_bytes"] == "100" and row["resp_bytes"] == "400"
    assert row["orig_ip_bytes"] == str(74 + 66 + 166 + 66)
    assert row["duration"] == "0.070000"
    assert row["uid"].startswith("C") and len(row["uid"]) == 18
    # champs que Netcross ne sait pas calculer : non renseignes, pas inventes
    assert row["local_orig"] == "-" and row["missed_bytes"] == "-"
    assert row["tunnel_parents"] == "(empty)"
    # sans --order : pas de colonnes de segment
    assert row["netcross_point"] == "A"
    assert row["netcross_points"] == "A"
    assert row["netcross_segment"] == "-" and row["netcross_loss_segment"] == "-"


@pytest.mark.parametrize(
    ("pkts", "etat"),
    [
        ([make_pkt(flags="SYN", sport=1, dport=2)], "S0"),
        (
            [
                make_pkt(flags="SYN", sport=1, dport=2),
                make_pkt(ts=0.1, flags="RST,ACK", src="10.0.0.2", dst="10.0.0.1", sport=2, dport=1),
            ],
            "REJ",
        ),
        (
            [
                make_pkt(flags="SYN", sport=1, dport=2),
                make_pkt(ts=0.1, flags="SYN,ACK", src="10.0.0.2", dst="10.0.0.1", sport=2, dport=1),
            ],
            "S1",
        ),
        (
            [
                make_pkt(flags="SYN", sport=1, dport=2),
                make_pkt(ts=0.1, flags="SYN,ACK", src="10.0.0.2", dst="10.0.0.1", sport=2, dport=1),
                make_pkt(ts=0.2, flags="RST", sport=1, dport=2),
            ],
            "RSTO",
        ),
        (
            [
                make_pkt(flags="SYN", sport=1, dport=2),
                make_pkt(ts=0.1, flags="SYN,ACK", src="10.0.0.2", dst="10.0.0.1", sport=2, dport=1),
                make_pkt(ts=0.2, flags="RST", src="10.0.0.2", dst="10.0.0.1", sport=2, dport=1),
            ],
            "RSTR",
        ),
        (
            [
                make_pkt(flags="SYN", sport=1, dport=2),
                make_pkt(ts=0.1, flags="FIN", sport=1, dport=2),
            ],
            "SH",
        ),
        ([make_pkt(flags="ACK", sport=1, dport=2)], "OTH"),
        ([make_pkt(proto="UDP", sport=5353, dport=53)], "S0"),
        (
            [
                make_pkt(proto="UDP", sport=5353, dport=53, dns_qry_name="example.org"),
                make_pkt(ts=0.01, proto="UDP", src="10.0.0.2", dst="10.0.0.1", sport=53, dport=5353),
            ],
            "SF",
        ),
    ],
)
def test_etats_de_connexion(pkts, etat):
    (rec,) = zk.build_conn_records(pkts, ["A"])
    assert rec.conn_state == etat


@pytest.mark.parametrize(
    ("champs", "service"),
    [
        ({"http_is_request": True}, "http"),
        ({"sip_call_id": "abc@host"}, "sip"),
        ({"dhcp_msg_type": "1"}, "dhcp"),
        ({"ssh_hassh": "ec7378c1a92f5a8dde7e8b7a1ddf33d1"}, "ssh"),
        ({}, None),
    ],
)
def test_service_atteste_par_la_dissection(champs, service):
    (rec,) = zk.build_conn_records([make_pkt(**champs)], ["A"])
    assert rec.service == service


def test_historique_une_lettre_par_sens():
    c = {"sport": 1, "dport": 2}
    pkts = [
        make_pkt(ts=0.0, flags="ACK", tcp_len=10, payload_hash="a", **c),
        make_pkt(ts=0.1, flags="ACK", tcp_len=10, payload_hash="b", seq=2000, **c),
    ]
    (rec,) = zk.build_conn_records(pkts, ["A"])
    assert rec.history == "D"
    assert rec.orig_bytes == 20


def test_drapeaux_tshark_positionnels():
    # tcp.flags.str : 12 caracteres, les six derniers U A P R S F
    assert zk.tcp_flag_names("··········S·") == {"SYN"}
    assert zk.tcp_flag_names("·······A··S·") == {"ACK", "SYN"}
    assert zk.tcp_flag_names("....R..") == {"RST"}
    assert zk.tcp_flag_names("SYN,ACK") == {"SYN", "ACK"}
    assert zk.tcp_flag_names(None) == frozenset()


def test_icmp_type_et_code_dans_les_ports():
    pkts = [
        make_pkt(proto="ICMP", sport=None, dport=None, icmp_type=8, icmp_code=0),
        make_pkt(ts=0.01, proto="ICMP", src="10.0.0.2", dst="10.0.0.1", sport=None, dport=None, icmp_type=0),
    ]
    (rec,) = zk.build_conn_records(pkts, ["A"])
    assert (rec.proto, rec.orig_p, rec.resp_p) == ("icmp", 8, 0)
    assert rec.orig_pkts == 1 and rec.resp_pkts == 1


def test_arp_et_doublons_ignores():
    pkts = [make_pkt(proto="ARP", sport=None, dport=None), make_pkt(is_duplicate=True)]
    assert zk.build_conn_records(pkts, ["A"]) == []
    entetes, fields, _types, rows = lire_conn_log(zk.to_tsv([]))
    assert rows == [] and fields and entetes["open"] == "1970-01-01-00-00-00"


def test_echappement_tsv():
    rec = zk.build_conn_records(_tcp("LAN\tbis", 0.0), ["LAN\tbis"])[0]
    _e, _f, _t, (row,) = lire_conn_log(zk.to_tsv([rec]))
    assert row["netcross_point"] == "LAN\\x09bis"


def test_deterministe():
    a = zk.to_tsv(zk.build_conn_records(_tcp("A", 5.0), ["A"]))
    b = zk.to_tsv(zk.build_conn_records(_tcp("A", 5.0), ["A"]))
    assert a == b


# -- multi-points ------------------------------------------------------------------------------


def test_segments_latence_et_pertes_avec_order():
    amont = _tcp("LAN", 100.0)
    aval = _tcp("WAN", 100.0, lag=0.004)
    perdu = aval.pop(3)  # le ClientHello n'arrive pas au WAN
    assert perdu.payload_hash == "p1"
    recs = zk.build_conn_records(amont + aval, ["LAN", "WAN"], ["LAN", "WAN"])
    par_point = {r.point: r for r in recs}
    assert set(par_point) == {"LAN", "WAN"}
    lan, wan = par_point["LAN"], par_point["WAN"]
    assert lan.points_seen == ("LAN", "WAN") == wan.points_seen
    assert lan.segment is None and lan.segment_lost_pkts is None
    assert wan.segment == "LAN->WAN"
    assert wan.segment_lost_pkts == 1
    assert wan.segment_delay_ms == pytest.approx(4.0)
    assert lan.loss_segment == wan.loss_segment == "LAN->WAN"
    assert lan.uid != wan.uid
    _e, _f, _t, rows = lire_conn_log(zk.to_tsv(recs))
    row_wan = next(r for r in rows if r["netcross_point"] == "WAN")
    assert row_wan["netcross_points"] == "LAN,WAN"
    assert row_wan["netcross_segment_delay_ms"] == "4.000"
    assert row_wan["netcross_segment_lost_pkts"] == "1"


def test_sans_perte_pas_de_segment_de_perte():
    recs = zk.build_conn_records(_tcp("A", 0.0) + _tcp("B", 0.0, lag=0.001), ["A", "B"], ["A", "B"])
    assert all(r.loss_segment is None for r in recs)
    assert next(r for r in recs if r.point == "B").segment_lost_pkts == 0


# -- JSON --------------------------------------------------------------------------------------


def test_variante_json_une_ligne_par_flux():
    recs = zk.build_conn_records(_tcp("A", 100.0) + _tcp("B", 100.0, lag=0.002), ["A", "B"], ["A", "B"])
    texte = zk.to_json_lines(recs)
    lignes = texte.splitlines()
    assert len(lignes) == 2 and texte.endswith("\n")
    objets = [json.loads(ligne) for ligne in lignes]
    premier = objets[0]
    assert list(premier)[:6] == ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"]
    assert premier["ts"] == pytest.approx(100.0)
    assert premier["netcross_points"] == ["A", "B"]
    # champs non renseignes omis, comme LogAscii::use_json
    assert "local_orig" not in premier and "tunnel_parents" not in premier
    assert "netcross_segment" not in premier
    assert objets[1]["netcross_segment"] == "A->B"


def test_ecriture_et_format_inconnu(tmp_path):
    recs = zk.build_conn_records(_tcp("A", 0.0), ["A"])
    chemin = zk.write_zeek_conn(recs, tmp_path / "conn.log")
    assert lire_conn_log((tmp_path / "conn.log").read_text(encoding="utf-8"))[3]
    assert chemin.endswith("conn.log")
    zk.write_zeek_conn(recs, tmp_path / "conn.json", "json")
    assert json.loads((tmp_path / "conn.json").read_text(encoding="utf-8"))["proto"] == "tcp"
    with pytest.raises(ValueError, match="format Zeek inconnu"):
        zk.write_zeek_conn(recs, tmp_path / "x", "csv")


# -- --redact ----------------------------------------------------------------------------------


def test_redact_aucune_adresse_reelle():
    pkts = _tcp("A", 0.0, client="192.168.1.10", serveur="8.8.8.8")
    reel = zk.to_tsv(zk.build_conn_records(_tcp("A", 0.0, "192.168.1.10", "8.8.8.8"), ["A"]))
    redactor = redact_packets(pkts)
    assert len(redactor) >= 2
    texte = zk.to_tsv(zk.build_conn_records(pkts, ["A"]))
    assert "192.168.1.10" not in texte and "8.8.8.8" not in texte
    _e, _f, _t, (row,) = lire_conn_log(texte)
    assert row["id.orig_h"] == pkts[0].src
    # l'uid derive des valeurs pseudonymisees : different de celui de la capture reelle
    assert row["uid"] != lire_conn_log(reel)[3][0]["uid"]


# -- CLI ---------------------------------------------------------------------------------------


@pytest.fixture
def lance(monkeypatch):
    pkts = [
        *_tcp("A", 100.0, client="192.168.1.10", serveur="8.8.8.8"),
        *_tcp("B", 100.0, client="192.168.1.10", serveur="8.8.8.8", lag=0.003),
    ]

    monkeypatch.setattr(
        cli, "parse_capture", lambda label, path, raise_on_error=False: [p for p in pkts if p.point == label]
    )

    def _run(*argv):
        monkeypatch.setattr(
            sys,
            "argv",
            ["cross_capture_analyzer_cli.py", "--capture", "A=a.pcap", "--capture", "B=b.pcap", *map(str, argv)],
        )
        try:
            cli.main()
        except SystemExit as exc:
            return exc.code
        return 0

    return _run


def test_cli_zeek_conn_tsv_avec_redact(lance, tmp_path, capsys):
    sortie = tmp_path / "conn.log"
    assert lance("--order", "A,B", "--redact", "--zeek-conn", sortie) == 0
    assert "Journal Zeek conn.log (tsv, 2 ligne(s))" in capsys.readouterr().out
    texte = sortie.read_text(encoding="utf-8")
    assert "192.168.1.10" not in texte and "8.8.8.8" not in texte
    _e, _f, _t, rows = lire_conn_log(texte)
    assert {r["netcross_point"] for r in rows} == {"A", "B"}
    assert next(r for r in rows if r["netcross_point"] == "B")["netcross_segment"] == "A->B"


def test_cli_zeek_conn_json(lance, tmp_path):
    sortie = tmp_path / "conn.json"
    assert lance("--zeek-conn", sortie, "--zeek-format", "json") == 0
    objets = [json.loads(ligne) for ligne in sortie.read_text(encoding="utf-8").splitlines()]
    assert len(objets) == 2 and objets[0]["id.orig_h"] == "192.168.1.10"


def test_cli_zeek_conn_refuse_avec_merge(lance, tmp_path, capsys):
    code = lance("--merge", tmp_path / "m.pcapng", "--zeek-conn", tmp_path / "c.log")
    assert code not in (0, None)
    assert "--zeek-conn" in capsys.readouterr().err
