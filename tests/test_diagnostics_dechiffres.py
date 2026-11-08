# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #1045 : certificat TLS 1.3, trames QUIC 1-RTT et signatures
d'exploits branchés sur le contenu déchiffré (fichier de clés)."""

from __future__ import annotations

import contextlib
import io
import json
import re
import shutil
import sys
from pathlib import Path

import pytest

import cross_capture_analyzer_cli as cli
from netcross_core.exploit_signatures import Detection, Signature
from netcross_core.quic_diagnostics import QuicEvent, _code_fermeture, constats_1rtt, diagnose_quic, parse_quic_capture
from netcross_core.security import findings as security_findings
from pcap_parser import TsharkError
from pcap_parser import decrypted as module_dechiffre
from pcap_parser.decrypted import parse_hex_dump, read_decrypted_tls
from pcap_parser.protocols import _couche_certificat, _quic_fermeture, extract_tls_certificate

sys.path.insert(0, str(Path(__file__).parent))
from tls13_keylog_capture import ecrire_capture  # noqa: E402

avec_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent")
DONNEES = Path(__file__).parent / "data"


@pytest.fixture
def quic(tmp_path):
    """Capture QUIC et clés copiées en répertoire temporaire (tshark confiné
    par AppArmor en CI, voir tests/test_dechiffrement.py)."""
    for nom in ("quic-1rtt.pcap", "quic-1rtt-keys.txt"):
        shutil.copy(DONNEES / nom, tmp_path / nom)
    return str(tmp_path / "quic-1rtt.pcap"), str(tmp_path / "quic-1rtt-keys.txt")


@pytest.fixture(scope="module")
def tls13(tmp_path_factory):
    pytest.importorskip("cryptography")
    return ecrire_capture(tmp_path_factory.mktemp("tls13-1045"))


# --- certificat dans une trame TLS 1.3 déchiffrée ---------------------------------


def test_couche_certificat_prend_l_occurrence_avec_dates():
    certificat = {"tls_tls_handshake_type": "11", "x509af_x509af_utcTime": ["260101000000Z"]}
    verify = {"tls_tls_handshake_type": "15"}
    assert _couche_certificat({"tls": [{"tls_tls_handshake_type": "8"}, certificat, verify]}) is certificat


def test_couche_certificat_repli_historique():
    assert _couche_certificat({"tls": [{"a": 1}, {"b": 2}]}) == {"b": 2}
    assert _couche_certificat({"ip": {}}) is None


@avec_tshark
def test_certificat_lisible_avec_la_cle_seulement(tls13):
    import pcap_parser

    capture, cles = tls13
    avec = [p for p in pcap_parser.parse_capture(str(capture), tls_keylog=str(cles)) if p.tls_cert_serial]
    sans = [p for p in pcap_parser.parse_capture(str(capture)) if p.tls_cert_serial]
    assert len(avec) == 1
    assert sans == []
    assert extract_tls_certificate({"ip": {}}) is None


# --- substitution de certificat multi-points (critère d'acceptation) ---------------


def _lance(argv, monkeypatch, rapport):
    monkeypatch.setattr(sys, "argv", ["prog", *argv, "--json-report", str(rapport)])
    with contextlib.redirect_stdout(io.StringIO()) as sortie, contextlib.suppress(SystemExit):
        cli.main()
    return sortie.getvalue(), json.loads(rapport.read_text())


@avec_tshark
def test_substitution_certificat_tls13_multi_points(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    lan, cles_lan = ecrire_capture(tmp_path / "lan")
    wan, cles_wan = ecrire_capture(tmp_path / "wan")  # autre certificat, même 5-uplet
    captures = ["--capture", f"LAN={lan}", "--capture", f"WAN={wan}", "--order", "LAN,WAN"]
    cles = ["--tls-keylog", f"LAN={cles_lan}", "--tls-keylog", f"WAN={cles_wan}"]

    sortie, document = _lance([*captures, *cles], monkeypatch, tmp_path / "avec.json")
    assert "LAN -> WAN : 1 connexion(s) presentent un certificat different" in sortie
    assert "interception/substitution TLS possible" in sortie
    assert '"rule_id": "tls_cert_mismatch"' in json.dumps(document)

    # sans les fichiers de clés, le certificat TLS 1.3 reste chiffré : rien à comparer
    sortie_sans, document_sans = _lance(captures, monkeypatch, tmp_path / "sans.json")
    assert "aucune anomalie de certificat detectee" in sortie_sans
    assert "tls_cert_mismatch" not in json.dumps(document_sans)


# --- contenu TLS déchiffré (vidage -x de tshark) -----------------------------------

VIDAGE = """\
       10

Packet (24 bytes):
0000  02 00 00 00 45 00 00 14 00 00 00 00 40 06 00 00   ....E.......@...
0010  0a 00 00 01 0a 00 00 02                           ........
Decrypted TLS (20 bytes):
0000  47 45 54 20 2f 6e 65 74 63 72 6f 73 73 2d 73 65   GET /netcross-se
0010  63 72 65 74                                       cret
Decrypted TLS (2 bytes):
0000  0d 0a                                             ..
       11

Reassembled TCP (3 bytes):
0000  41 42 43                                          ABC
"""


def test_parse_hex_dump_synthetique():
    assert parse_hex_dump(VIDAGE.splitlines(keepends=True)) == {10: b"GET /netcross-secret\r\n"}
    assert parse_hex_dump(["Decrypted TLS (1 bytes):", "0000  41   A"]) == {}


@avec_tshark
def test_read_decrypted_tls_reel(tls13):
    capture, cles = tls13
    clair = read_decrypted_tls(str(capture), str(cles))
    textes = b"".join(clair.values())
    assert b"GET /netcross-secret" in textes
    assert b"HTTP/1.1" in textes


def test_read_decrypted_tls_capture_absente(tmp_path):
    with pytest.raises(TsharkError, match="capture illisible"):
        read_decrypted_tls(str(tmp_path / "absente.pcap"), str(tmp_path / "k.txt"))


@avec_tshark
def test_read_decrypted_tls_echec_tshark(tmp_path):
    pas_une_capture = tmp_path / "faux.pcap"
    pas_une_capture.write_bytes(b"ceci n'est pas une capture")
    with pytest.raises(TsharkError, match="tshark a échoué"):
        read_decrypted_tls(str(pas_une_capture), str(tmp_path / "k.txt"))


# --- signatures d'exploits sur le contenu déchiffré --------------------------------

SIGNATURE = Signature(
    id="NC-TEST-1045",
    name="URI secrète",
    cves=("CVE-0000-1045",),
    severity="high",
    targets=("http_uri", "payload"),
    regex=re.compile("netcross-secret"),
)


@avec_tshark
def test_signature_appliquee_au_contenu_dechiffre(tls13):
    capture, cles = tls13
    sans = security_findings.scan_capture_exploits("CLIENT", str(capture), [SIGNATURE])
    assert sans == []
    avec = security_findings.scan_capture_exploits("CLIENT", str(capture), [SIGNATURE], tls_keylog=str(cles))
    assert avec
    assert all(d.decrypted for d in avec)
    constats = security_findings.exploit_findings(avec)
    assert any("contenu TLS déchiffré" in c["detail"] for c in constats)


@avec_tshark
def test_echec_lecture_dechiffree_journalise(tls13, monkeypatch):
    capture, cles = tls13

    def echoue(path, keylog):
        raise TsharkError("panne simulée")

    monkeypatch.setattr(module_dechiffre, "read_decrypted_tls", echoue)
    assert security_findings.scan_capture_exploits("CLIENT", str(capture), [SIGNATURE], tls_keylog=str(cles)) == []


def test_capture_vide_avec_cle(monkeypatch):
    monkeypatch.setattr(security_findings.pcap_parser, "parse_capture", lambda path, raise_on_error: [])
    assert security_findings.scan_capture_exploits("A", "x.pcap", [SIGNATURE], tls_keylog="k.txt") == []


def test_detection_par_defaut_non_dechiffree():
    d = Detection("S", "n", (), "low", "", "payload", 0.0, 1, "tcp", "a", 1, "b", 2, None)
    assert d.decrypted is False


# --- QUIC 1-RTT ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("couche", "attendu"),
    [
        ({"quic_quic_cc_error_code_app": "66", "quic_quic_cc_reason_phrase": "netcross"}, "applicatif 0x42 (netcross)"),
        ({"quic_quic_cc_error_code": "10"}, "transport 0xa"),
        ({"quic_quic_short": "x"}, None),
        ("pas un dict", None),
    ],
)
def test_quic_fermeture(couche, attendu):
    assert _quic_fermeture(couche) == attendu


@pytest.mark.parametrize(("texte", "code"), [("applicatif 0x42 (x)", 0x42), ("transport 0x0", 0), ("bizarre", None)])
def test_code_fermeture(texte, code):
    assert _code_fermeture(texte) == code


def _evt(**kw):
    base = {"point": "A", "ts": 0.0, "src": "10.0.0.1", "dst": "10.0.0.2", "sport": 1, "dport": 443, "dcid": b""}
    return QuicEvent(**{**base, "kind": "1rtt", **kw})


def test_constats_1rtt_synthetiques():
    evts = [
        _evt(decryptable=True, connexion=0, fermeture="transport 0x0"),
        _evt(decryptable=True, connexion=0, fermeture="transport 0x0"),
        _evt(point="B", decryptable=False, connexion=3),
    ]
    constats = constats_1rtt(evts)
    messages = [c.message for c in constats]
    assert messages[0].startswith("2/2 paquet(s) QUIC 1-RTT dechiffre(s) sur 1 connexion(s)")
    assert constats[1].severity == "info"  # fermeture normale (code 0), une seule fois
    assert "aucun des 1 paquet(s) QUIC 1-RTT dechiffre" in messages[2]
    assert len(constats) == 3


@avec_tshark
def test_quic_1rtt_reel_avec_cle(quic):
    pytest.importorskip("cryptography")
    evenements = parse_quic_capture("CLIENT", quic[0], tls_keylog=quic[1])
    courts = [e for e in evenements if e.kind == "1rtt"]
    assert courts
    assert all(e.decryptable for e in courts)
    assert any(e.fermeture == "applicatif 0x42 (netcross)" for e in courts)
    constats = diagnose_quic(evenements, ["CLIENT"])
    fermetures = [c for c in constats if "fermee" in c.message]
    assert fermetures
    assert fermetures[0].severity == "a_surveiller"
    assert "applicatif 0x42 (netcross)" in fermetures[0].message


@avec_tshark
def test_quic_sans_cle_inchange(quic):
    pytest.importorskip("cryptography")
    evenements = parse_quic_capture("CLIENT", quic[0])
    assert evenements
    assert all(e.kind == "initial" for e in evenements)
    assert not [c for c in diagnose_quic(evenements, []) if "1-RTT" in c.message]
