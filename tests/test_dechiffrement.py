# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #1043 : compteur de sessions TLS/QUIC déchiffrées par point."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import make_pkt

import cross_capture_analyzer_cli as cli
from netcross_core.dechiffrement import (
    compter_sessions,
    document_json,
    lignes,
    phrase,
    points_a_signaler,
)
from netcross_core.models import Report
from netcross_core.report_text import print_report
from netcross_report.json_report import build_json_report_document
from pcap_parser.protocols import _premier, extract_dechiffrement

sys.path.insert(0, str(Path(__file__).parent))
from tls13_keylog_capture import ecrire_capture_sessions  # noqa: E402

avec_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent")


# --- extraction des champs EK ---------------------------------------------------


def test_extraction_sans_tls_ni_quic():
    assert extract_dechiffrement({"ip": {}}) is None


def test_extraction_tls_dechiffre():
    layers = {"tls": {"tls_tls_stream": ["3", "3"], "tls_tls_record_sequence_number": "0"}}
    assert extract_dechiffrement(layers) == {
        "tls_stream": 3,
        "tls_dechiffre": True,
        "quic_connexion": None,
        "quic_dechiffre": False,
    }


def test_extraction_tls_chiffre():
    resultat = extract_dechiffrement({"tls": {"tls_tls_stream": "0", "tls_tls_record_content_type": "23"}})
    assert resultat["tls_stream"] == 0
    assert resultat["tls_dechiffre"] is False


@pytest.mark.parametrize(
    ("quic", "attendu"),
    [
        ({"quic_quic_connection_number": "1", "quic_quic_long_packet_type": "0"}, False),
        ({"quic_quic_connection_number": "1", "quic_quic_short": None, "quic_quic_frame_type": "11"}, True),
        # sans cle, tshark n'expose que la charge restante, sans signaler d'echec
        ({"quic_quic_connection_number": "1", "quic_quic_short": None, "quic_quic_remaining_payload": "e2:be"}, False),
        (
            {
                "quic_quic_connection_number": "1",
                "quic_quic_short": None,
                "quic_quic_frame_type": "1",
                "quic_quic_decryption_failed": "x",
            },
            False,
        ),
    ],
)
def test_extraction_quic(quic, attendu):
    resultat = extract_dechiffrement({"quic": quic})
    assert resultat["quic_connexion"] == 1
    assert resultat["quic_dechiffre"] is attendu
    assert resultat["tls_stream"] is None


def test_extraction_quic_coalesce():
    # deux paquets QUIC coalescés dans un datagramme : Initial puis 1-RTT
    layers = {"quic": [{"quic_quic_connection_number": "2"}, {"quic_quic_short": None, "quic_quic_frame_type": "29"}]}
    resultat = extract_dechiffrement(layers)
    assert resultat["quic_connexion"] == 2
    assert resultat["quic_dechiffre"] is True


@pytest.mark.parametrize(("valeur", "attendu"), [(["4", "5"], "4"), ([], None), ("7", "7"), (None, None)])
def test_premier(valeur, attendu):
    assert _premier(valeur) == attendu


# --- comptage -------------------------------------------------------------------


def _tls(point, stream, dechiffre, **autres):
    return make_pkt(point=point, tls_stream=stream, tls_dechiffre=dechiffre, **autres)


def test_comptage_partiel_tls():
    paquets = [
        _tls("CLIENT", 0, False),
        _tls("CLIENT", 0, True),
        _tls("CLIENT", 1, False),
        _tls("CLIENT", 2, True),
        _tls("SERVEUR", 0, False),
        make_pkt(point="CLIENT"),  # ni TLS ni QUIC
    ]
    assert compter_sessions(paquets) == {
        "CLIENT": {"tls": {"sessions": 3, "dechiffrees": 2}},
        "SERVEUR": {"tls": {"sessions": 1, "dechiffrees": 0}},
    }


def test_comptage_quic_et_repli_conversation():
    paquets = [
        make_pkt(point="P", quic_connexion=0, quic_dechiffre=True),
        make_pkt(point="P", quic_connexion=1),
        # sans identifiant : rattaché à la conversation, quel que soit le sens
        make_pkt(point="P", src="10.0.0.1", dst="10.0.0.2", sport=5, dport=443, tls_client_hello=True),
        make_pkt(point="P", src="10.0.0.2", dst="10.0.0.1", sport=443, dport=5, tls_dechiffre=True),
        make_pkt(point="P", src="10.0.0.3", dst="10.0.0.2", sport=None, dport=None, quic_dechiffre=True),
    ]
    assert compter_sessions(paquets) == {
        "P": {"tls": {"sessions": 1, "dechiffrees": 1}, "quic": {"sessions": 3, "dechiffrees": 2}},
    }


def test_comptage_vide():
    assert compter_sessions([]) == {}


# --- points signalés et mise en forme -------------------------------------------


def _rapport(**champs) -> Report:
    r = Report(points=["CLIENT", "MILIEU", "SERVEUR"], pairs=[])
    for nom, valeur in champs.items():
        setattr(r, nom, valeur)
    return r


def test_phrase_du_critere_d_acceptation():
    assert phrase("CLIENT", "tls", {"sessions": 50, "dechiffrees": 42}) == (
        "42/50 sessions TLS déchiffrées au point CLIENT"
    )


def test_points_signales():
    r = _rapport(
        dechiffrement={
            "SERVEUR": {"tls": {"sessions": 2, "dechiffrees": 1}},  # DSB ou autre : déchiffré
            "MILIEU": {"tls": {"sessions": 4, "dechiffrees": 0}},  # aucune clé : tu
            "CLIENT": {"quic": {"sessions": 3, "dechiffrees": 0}},  # clé fournie : 0/3 signalé
            "AUTRE": {"tls": {"sessions": 1, "dechiffrees": 0}},  # DSB : signalé
        },
        points_keylog=["CLIENT", "VIDE"],
        capture_infos=[{"label": "AUTRE", "decryption_secrets_blocks": 1}, {"label": "MILIEU"}],
    )
    assert points_a_signaler(r) == ["CLIENT", "SERVEUR", "AUTRE", "VIDE"]
    assert lignes(r) == [
        "0/3 sessions QUIC déchiffrées au point CLIENT",
        "1/2 sessions TLS déchiffrées au point SERVEUR",
        "0/1 sessions TLS déchiffrées au point AUTRE",
        "aucune session TLS ou QUIC au point VIDE",
    ]
    entrees = document_json(r)
    assert entrees[0] == {
        "point": "CLIENT",
        "keylog": True,
        "tls_sessions": 0,
        "tls_decrypted": 0,
        "quic_sessions": 3,
        "quic_decrypted": 0,
        "summary": ["0/3 sessions QUIC déchiffrées au point CLIENT"],
    }
    assert entrees[-1]["summary"] == []


def test_rien_a_signaler_sans_cle():
    r = _rapport(dechiffrement={"CLIENT": {"tls": {"sessions": 4, "dechiffrees": 0}}})
    assert lignes(r) == []
    assert "decryption" not in build_json_report_document(r)
    sortie = io.StringIO()
    with contextlib.redirect_stdout(sortie):
        print_report(r)
    assert "Dechiffrement TLS / QUIC" not in sortie.getvalue()


def test_sorties_texte_json_pdf(tmp_path):
    r = _rapport(dechiffrement={"CLIENT": {"tls": {"sessions": 50, "dechiffrees": 42}}}, points_keylog=["CLIENT"])
    phrase_attendue = "42/50 sessions TLS déchiffrées au point CLIENT"
    document = build_json_report_document(r)
    assert document["decryption"]["by_point"][0]["summary"] == [phrase_attendue]
    sortie = io.StringIO()
    with contextlib.redirect_stdout(sortie):
        print_report(r)
    assert phrase_attendue in sortie.getvalue()

    pytest.importorskip("reportlab")
    from netcross_report.pdf import generate_pdf

    chemin = tmp_path / "r.pdf"
    generate_pdf(r, str(chemin))
    if shutil.which("pdftotext") is None:
        pytest.skip("pdftotext non installe : contenu du PDF non verifiable")
    texte = subprocess.run(["pdftotext", str(chemin), "-"], capture_output=True, text=True, check=True).stdout
    assert phrase_attendue in texte


# --- bout en bout avec tshark : keylog couvrant une session sur deux -------------


@pytest.fixture(scope="module")
def deux_sessions(tmp_path_factory):
    pytest.importorskip("cryptography")
    return ecrire_capture_sessions(tmp_path_factory.mktemp("tls13-dechiffrement"), 2)


@avec_tshark
def test_compteur_exact_keylog_partiel(deux_sessions, tmp_path, monkeypatch):
    capture, keylogs = deux_sessions
    rapport = tmp_path / "rapport.json"
    argv = ["prog", "--capture", f"CLIENT={capture}", "--tls-keylog", f"CLIENT={keylogs[0]}"]
    monkeypatch.setattr(sys, "argv", [*argv, "--json-report", str(rapport)])
    with contextlib.redirect_stdout(io.StringIO()) as sortie, contextlib.suppress(SystemExit):
        cli.main()
    assert "1/2 sessions TLS déchiffrées au point CLIENT" in sortie.getvalue()
    entree = json.loads(rapport.read_text())["decryption"]["by_point"]
    assert entree == [
        {
            "point": "CLIENT",
            "keylog": True,
            "tls_sessions": 2,
            "tls_decrypted": 1,
            "quic_sessions": 0,
            "quic_decrypted": 0,
            "summary": ["1/2 sessions TLS déchiffrées au point CLIENT"],
        }
    ]


@avec_tshark
def test_compteur_keylog_complet_et_absent(deux_sessions, tmp_path):
    from netcross_core.parsing import parse_capture

    capture, keylogs = deux_sessions
    complet = tmp_path / "complet.txt"
    complet.write_text("".join(k.read_text() for k in keylogs))
    avec = parse_capture("CLIENT", str(capture), tls_keylog=str(complet))
    assert compter_sessions(avec) == {"CLIENT": {"tls": {"sessions": 2, "dechiffrees": 2}}}
    sans = parse_capture("CLIENT", str(capture))
    assert compter_sessions(sans) == {"CLIENT": {"tls": {"sessions": 2, "dechiffrees": 0}}}


# --- QUIC réel : tests/data/quic-1rtt.pcap (scripts/generer_capture_quic.py) ------

DONNEES = Path(__file__).parent / "data"


@avec_tshark
@pytest.mark.parametrize(("avec_cle", "attendu"), [(True, 1), (False, 0)])
def test_compteur_quic_reel(avec_cle, attendu):
    from netcross_core.parsing import parse_capture

    options = {"tls_keylog": str(DONNEES / "quic-1rtt-keys.txt")} if avec_cle else {}
    paquets = parse_capture("CLIENT", str(DONNEES / "quic-1rtt.pcap"), **options)
    assert compter_sessions(paquets) == {"CLIENT": {"quic": {"sessions": 1, "dechiffrees": attendu}}}, _vue_tshark(
        options
    )


def _vue_tshark(options: dict) -> str:
    """Champs QUIC vus par tshark, joints au message d'échec (diagnostic CI)."""
    args = ["tshark", "-n", "-r", str(DONNEES / "quic-1rtt.pcap")]
    if options:
        args += ["-o", f"tls.keylog_file:{options['tls_keylog']}"]
    champs = ["frame.number", "quic.short", "quic.frame_type", "quic.decryption_failed", "quic.connection.number"]
    for champ in champs:
        args += ["-e", champ]
    sortie = subprocess.run([*args, "-T", "fields"], capture_output=True, text=True, check=False)
    paquets = subprocess.run(["tshark", "-n", "-r", args[3], *args[4:6]], capture_output=True, text=True, check=False)
    return f"{sortie.stdout}\n{sortie.stderr}\n{paquets.stdout}"
