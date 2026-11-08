"""--tls-keylog (issue #1040) : spécifications, refus, transmission à tshark.

Les tests « réels » utilisent une vraie session TLS 1.3 générée en mémoire
(tests/tls13_keylog_capture.py) : sans fichier de clés tshark ne voit que des
enregistrements TLS, avec le fichier il décode la requête HTTP chiffrée.
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from netcross_core import tls_keylog as tk
from netcross_core.tls_keylog import (
    MESSAGE_REDACT,
    TlsKeylogError,
    fichier_du_point,
    options_lecture,
    options_lecture_parallele,
    resoudre_keylogs,
    resume_keylogs,
    verifier_compatibilite,
)
from pcap_parser.ek_source import tls_keylog_prefs

sys.path.insert(0, str(Path(__file__).parent))
from tls13_keylog_capture import URI, ecrire_capture  # noqa: E402

TSHARK = shutil.which("tshark")
avec_tshark = pytest.mark.skipif(TSHARK is None, reason="tshark absent")


@pytest.fixture(scope="module")
def session_tls13(tmp_path_factory):
    pytest.importorskip("cryptography")
    return ecrire_capture(tmp_path_factory.mktemp("tls13"))


@pytest.fixture
def cles(tmp_path):
    a, b = tmp_path / "a.keys", tmp_path / "b.keys"
    a.write_text("CLIENT_RANDOM 00 11\n")
    b.write_text("CLIENT_RANDOM 22 33\n")
    return str(a), str(b)


# --- spécifications ---------------------------------------------------------


def test_sans_option_aucun_fichier():
    assert resoudre_keylogs(None, ["P1"]) == {}
    assert resoudre_keylogs([], ["P1"]) == {}


def test_fichier_global_pour_tous_les_points(cles):
    assert resoudre_keylogs([cles[0]], ["P1", "P2", "P1"]) == {"P1": cles[0], "P2": cles[0]}


def test_fichier_par_point_prioritaire(cles):
    a, b = cles
    assert resoudre_keylogs([a, f"P2={b}"], ["P1", "P2"]) == {"P1": a, "P2": b}
    assert resoudre_keylogs([f"P2={b}"], ["P1", "P2"]) == {"P2": b}
    assert resoudre_keylogs([f" P2 = {b} "], ["P1", "P2"]) == {"P2": b}


def test_chemin_contenant_un_egal_reste_global(tmp_path):
    chemin = tmp_path / "cle=1.txt"
    chemin.write_text("x")
    assert resoudre_keylogs([str(chemin)], ["P1"]) == {"P1": str(chemin)}


@pytest.mark.parametrize(
    ("specs", "attendu"),
    [
        (["X={a}"], "point inconnu « X »"),
        (["{a}", "{b}"], "un seul fichier pour tous les points"),
        (["P1={a}", "P1={b}"], "plusieurs fichiers pour le point P1"),
        (["P1="], "chemin vide"),
        (["{a}.absent"], "fichier introuvable"),
    ],
)
def test_specifications_refusees(cles, specs, attendu):
    a, b = cles
    with pytest.raises(TlsKeylogError, match=attendu):
        resoudre_keylogs([s.format(a=a, b=b) for s in specs], ["P1", "P2"])


def test_point_inconnu_sans_point(cles):
    with pytest.raises(TlsKeylogError, match="points : aucun"):
        resoudre_keylogs([f"X={cles[0]}"], [])


def test_fichier_illisible(cles):
    with patch.object(tk.os, "access", return_value=False), pytest.raises(TlsKeylogError, match="illisible"):
        resoudre_keylogs([cles[0]], ["P1"])


def test_refus_avec_redact(cles):
    verifier_compatibilite(None, redact=True)
    verifier_compatibilite([cles[0]], redact=False)
    with pytest.raises(TlsKeylogError, match="--redact"):
        verifier_compatibilite([cles[0]], redact=True)
    assert "chantier #997" in MESSAGE_REDACT


def test_split_interfaces_herite_du_point(cles):
    keylogs = {"P1": cles[0]}
    assert fichier_du_point(keylogs, "P1:eth0") == cles[0]
    assert fichier_du_point(keylogs, "P2:eth0") is None
    assert fichier_du_point(keylogs, "P2") is None
    assert options_lecture(keylogs, "P1:eth1") == {"tls_keylog": cles[0]}
    assert options_lecture(keylogs, "P2") == {}
    captures = [("P1:eth0", "x"), ("P2", "y")]
    assert options_lecture_parallele(keylogs, captures) == {"tls_keylogs": {"P1:eth0": cles[0]}}
    assert options_lecture_parallele({}, captures) == {}
    assert options_lecture_parallele({"P3": cles[0]}, captures) == {}


def test_resume_sans_chemin(cles):
    assert resume_keylogs({"P2": cles[0], "P1": cles[1]}) == "P1, P2"
    assert resume_keylogs({}) == "aucun"


def test_preference_tshark():
    assert tls_keylog_prefs(None) == ()
    assert tls_keylog_prefs("") == ()
    assert tls_keylog_prefs("/k/keys.txt") == ("tls.keylog_file:/k/keys.txt",)


# --- transmission à tshark (appels simulés) ---------------------------------


def test_sans_fichier_appel_tshark_inchange():
    from pcap_parser import capture

    with patch.object(capture, "iter_ek_records", return_value=iter(())) as ek:
        capture._collect_packets([], "a.pcap", read_via_stdin=False)
        capture._collect_packets([], "a.pcap", read_via_stdin=True)
    assert ek.call_args_list[0].kwargs == {"path": "a.pcap"}
    assert ek.call_args_list[1].kwargs == {"path": "a.pcap", "read_via_stdin": True}


def test_avec_fichier_preference_transmise():
    from pcap_parser import capture

    with patch.object(capture, "iter_ek_records", return_value=iter(())) as ek:
        capture._collect_packets([], "a.pcap", read_via_stdin=False, tls_keylog="/k")
        capture._collect_packets([], "a.pcap", read_via_stdin=True, tls_keylog="/k")
    for appel in ek.call_args_list:
        assert appel.kwargs["extra_prefs"] == ("tls.keylog_file:/k",)
    assert ek.call_args_list[1].kwargs["read_via_stdin"] is True


def test_lecture_minutee_transmet_le_fichier():
    from netcross_core import parsing
    from pcap_parser import capture

    with patch.object(capture, "parse_capture", return_value=[]) as brut:
        capture._parse_capture_timed("P1", "a.pcap")
        capture._parse_capture_timed("P1", "a.pcap", "/k")
    assert brut.call_args_list[0].kwargs == {"raise_on_error": True}
    assert brut.call_args_list[1].kwargs == {"raise_on_error": True, "tls_keylog": "/k"}
    with patch.object(parsing, "parse_capture", return_value=[]) as coeur:
        parsing._parse_capture_timed("P1", "a.pcap")
        parsing._parse_capture_timed("P1", "a.pcap", "/k")
    assert coeur.call_args_list[0].kwargs == {"raise_on_error": True}
    assert coeur.call_args_list[1].kwargs == {"raise_on_error": True, "tls_keylog": "/k"}
    assert capture.keylog_task_args({"P1": "/k"}, "P1") == ("/k",)
    assert capture.keylog_task_args({"P1": "/k"}, "P2") == ()


def test_coeur_transmet_le_fichier():
    from netcross_core import parsing

    with patch.object(parsing.pcap_parser, "parse_capture", return_value=[]) as brut:
        parsing.parse_capture("P1", "a.pcap")
        parsing.parse_capture("P1", "a.pcap", tls_keylog="/k")
    assert brut.call_args_list[0].kwargs == {"raise_on_error": True}
    assert brut.call_args_list[1].kwargs == {"raise_on_error": True, "tls_keylog": "/k"}


# --- vraie capture TLS 1.3 ---------------------------------------------------


def _requetes(paquets):
    return [p for p in paquets if getattr(p, "http_method", None)]


@avec_tshark
def test_capture_reelle_sans_cle_comportement_inchange(session_tls13):
    import pcap_parser

    capture, _ = session_tls13
    paquets = pcap_parser.parse_capture(str(capture), raise_on_error=True)
    assert len(paquets) > 5
    assert _requetes(paquets) == []


@avec_tshark
def test_capture_reelle_dechiffree_avec_cle(session_tls13):
    import pcap_parser

    capture, cles = session_tls13
    paquets = pcap_parser.parse_capture(str(capture), raise_on_error=True, tls_keylog=str(cles))
    requetes = _requetes(paquets)
    assert [p.http_method for p in requetes] == ["GET"]
    assert requetes[0].http_uri.endswith(URI)
    assert any(p.http_status_code == 200 for p in paquets)


@avec_tshark
def test_capture_reelle_parallele_par_point(session_tls13):
    from netcross_core.parsing import parse_captures_parallel

    capture, cles = session_tls13
    paquets, stats = parse_captures_parallel(
        [("P1", str(capture)), ("P2", str(capture))], max_workers=2, tls_keylogs={"P2": str(cles)}
    )
    assert all(s["error"] is None for s in stats)
    assert {p.point for p in _requetes(paquets)} == {"P2"}


@avec_tshark
def test_capture_reelle_parallele_brut(session_tls13):
    from pcap_parser.capture import parse_captures_parallel

    capture, cles = session_tls13
    paquets, stats = parse_captures_parallel([("P1", str(capture))], max_workers=1, tls_keylogs={"P1": str(cles)})
    assert stats[0]["error"] is None
    assert len(_requetes(paquets)) == 1


def test_le_fichier_de_cles_contient_des_secrets_tls13(session_tls13):
    _, cles = session_tls13
    texte = cles.read_text()
    assert "CLIENT_HANDSHAKE_TRAFFIC_SECRET" in texte
    assert "SERVER_TRAFFIC_SECRET_0" in texte
    assert os.path.getsize(cles) > 0
    assert stat.S_ISREG(os.stat(cles).st_mode)
