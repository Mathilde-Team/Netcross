# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #1143 : decapsulation 802.11 -> IP et dechiffrement WPA2-PSK.

Capture de reference synthetique (tests/wpa2_reference.py) : 4-way handshake
EAPOL (messages 1 et 2) puis deux trames de donnees CCMP portant de l'UDP
10.0.0.2:5000 -> 10.0.0.1:6000. Sans cle : aucun paquet IP et un
avertissement explicite. Avec la cle : les paquets IP sont extraits, tagues
802.11(dechiffre), et la phrase de passe ne fuit nulle part (argv de tshark,
journaux loguru, sorties, messages d'erreur).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import ClassVar

import pytest
from loguru import logger

import cross_capture_analyzer_cli as cli
from pcap_parser import ek_source
from pcap_parser.capture import parse_capture
from pcap_parser.ek_source import TsharkError, iter_ek_records
from pcap_parser.tunnels import TAG_80211_DECHIFFRE, detect_encapsulation
from pcap_parser.wifi_keys import (
    ENV_WIFI_KEYS,
    WLAN_DECRYPTION_PREFS,
    WifiKey,
    WifiKeysError,
    load_wifi_keys,
    parse_wifi_keys,
    wifi_keys_from_env,
    wlan_decryption,
)

sys.path.insert(0, str(Path(__file__).parent))
import wpa2_reference  # noqa: E402

avec_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent")
PSK = "ab" * 32


@pytest.fixture
def journal():
    """Tous les messages loguru (TRACE compris) dans un tampon."""
    tampon = io.StringIO()
    sink = logger.add(tampon, level=0, format="{level} {message} {extra} {exception}")
    yield tampon
    logger.remove(sink)


@pytest.fixture
def fichier_cles(tmp_path, monkeypatch):
    """Fichier de cles de la capture de reference ; NETCROSS_WIFI_KEYS est
    restaure a la fin du test, meme si la CLI l'a modifie."""
    monkeypatch.setenv(ENV_WIFI_KEYS, "")
    chemin = tmp_path / "cles.txt"
    chemin.write_text(f"# reseau de test\n\nwpa-pwd:{wpa2_reference.PHRASE}:{wpa2_reference.SSID}\n", encoding="utf-8")
    return chemin


# -- capture de reference --------------------------------------------------


def test_capture_versionnee_identique_au_generateur():
    assert wpa2_reference.WPA2_PCAP.read_bytes() == wpa2_reference.wpa2_bytes()


# -- fichier de cles -------------------------------------------------------


def test_parse_phrase_avec_deux_points_et_psk():
    cles = parse_wifi_keys(f"wpa-pwd:{wpa2_reference.PHRASE}:{wpa2_reference.SSID}\n# x\nWPA-PSK:{PSK.upper()}\n")
    assert cles[0] == WifiKey("wpa-pwd", wpa2_reference.PHRASE, wpa2_reference.SSID)
    assert cles[1] == WifiKey("wpa-psk", PSK)
    assert wpa2_reference.PHRASE not in repr(cles)
    assert cles[0].uat_line() == '"wpa-pwd","exemple%3Anetcross-wpa2:NetcrossLab"'
    assert cles[1].uat_line() == f'"wpa-psk","{PSK}"'


@pytest.mark.parametrize(
    ("texte", "attendu"),
    [
        ("wep:0102030405", "type de clé"),
        ("sans-separateur", "type de clé"),
        ("wpa-psk:1234", "64 chiffres"),
        ("wpa-pwd:phrasesanssid", "wpa-pwd:PHRASE:SSID"),
        ("wpa-pwd:phrasesecrete:", "wpa-pwd:PHRASE:SSID"),
        ("wpa-pwd:court:Lab", "8 à 63"),
        ("wpa-pwd:phrasesecrete:" + "S" * 33, "32 octets"),
        ("# rien\n\n", "aucune clé"),
    ],
)
def test_parse_erreurs_sans_secret(texte, attendu):
    with pytest.raises(WifiKeysError) as exc:
        parse_wifi_keys(texte)
    assert attendu in str(exc.value)
    for secret in ("phrasesanssid", "phrasesecrete", "0102030405"):
        assert secret not in str(exc.value)


def test_load_fichier_illisible(tmp_path):
    with pytest.raises(WifiKeysError, match="illisible"):
        load_wifi_keys(str(tmp_path / "absent.txt"))
    binaire = tmp_path / "binaire.txt"
    binaire.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(WifiKeysError, match="UnicodeDecodeError"):
        load_wifi_keys(str(binaire))


def test_wifi_keys_from_env(fichier_cles):
    assert wifi_keys_from_env({}) == ()
    assert wifi_keys_from_env({ENV_WIFI_KEYS: ""}) == ()
    assert len(wifi_keys_from_env({ENV_WIFI_KEYS: str(fichier_cles)})) == 1
    os.environ[ENV_WIFI_KEYS] = str(fichier_cles)
    assert len(wifi_keys_from_env()) == 1


def test_contexte_sans_cle_vide():
    with wlan_decryption(()) as (env, prefs):
        assert (env, prefs) == ({}, ())


def test_contexte_permissions_et_suppression(fichier_cles):
    cles = load_wifi_keys(str(fichier_cles))
    with pytest.raises(RuntimeError), wlan_decryption(cles) as (env, prefs):
        dossier = Path(env["WIRESHARK_CONFIG_DIR"])
        assert prefs == WLAN_DECRYPTION_PREFS
        assert stat.S_IMODE(dossier.stat().st_mode) == 0o700
        uat = dossier / "80211_keys"
        assert stat.S_IMODE(uat.stat().st_mode) == 0o600
        assert uat.read_text() == cles[0].uat_line() + "\n"
        raise RuntimeError("erreur pendant la lecture")
    assert not dossier.exists()


# -- integration ek_source (tshark simule) ---------------------------------


class _FauxPopen:
    """tshark simule : rejoue ``lignes`` et memorise argv/kwargs."""

    lignes: ClassVar[list] = []
    appels: ClassVar[list] = []

    def __init__(self, args, **kwargs):
        _FauxPopen.appels.append((list(args), kwargs))
        self.stdout = io.StringIO("".join(json.dumps(x) + "\n" for x in _FauxPopen.lignes))
        self.stderr = io.StringIO("")
        self.returncode = 0
        self.pid = 1

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0


def _record(**layers):
    return {"timestamp": "1700000000000", "layers": {"frame": {"frame_frame_number": "1"}, **layers}}


PROTEGEE = {"wlan_wlan_fc_type": "2", "wlan_wlan_fc_protected": True}


@pytest.fixture
def faux_tshark(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tshark")
    monkeypatch.setattr(subprocess, "Popen", _FauxPopen)
    monkeypatch.setenv(ENV_WIFI_KEYS, "")
    _FauxPopen.appels = []
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")
    return capture


def test_sans_cle_appel_inchange_et_avertissement(faux_tshark, journal):
    _FauxPopen.lignes = [
        _record(wlan=PROTEGEE),
        _record(wlan=[{}, PROTEGEE]),
        _record(wlan={"wlan_wlan_fc_type": "0", "wlan_wlan_fc_protected": True}),
        _record(wlan=PROTEGEE, ipv6={}),
        _record(eth={}),
    ]
    assert len(list(iter_ek_records(path=str(faux_tshark)))) == 5
    args, kwargs = _FauxPopen.appels[0]
    assert "env" not in kwargs
    assert not any("wlan.enable_decryption" in a for a in args)
    assert "2 trame(s) de données 802.11 chiffrée(s) non déchiffrée(s) : aucune clé Wi-Fi fournie" in journal.getvalue()


@pytest.mark.parametrize(
    ("eapol", "raison"),
    [(False, "4-way handshake EAPOL absent"), (True, "clé ne correspondant pas au réseau")],
)
def test_avec_cle_raisons_du_repli(faux_tshark, fichier_cles, journal, eapol, raison):
    os.environ[ENV_WIFI_KEYS] = str(fichier_cles)
    _FauxPopen.lignes = [_record(wlan=PROTEGEE, **({"eapol": {}} if eapol else {})), _record(wlan=PROTEGEE)]
    list(iter_ek_records(path=str(faux_tshark)))
    args, kwargs = _FauxPopen.appels[0]
    assert "wlan.enable_decryption:TRUE" in args
    assert not Path(kwargs["env"]["WIRESHARK_CONFIG_DIR"]).exists()
    assert raison in journal.getvalue()
    assert wpa2_reference.PHRASE not in " ".join(args) + journal.getvalue()


def test_aucun_avertissement_sans_trame_chiffree(faux_tshark, journal):
    _FauxPopen.lignes = [_record(wlan=PROTEGEE, ip={}), _record(eth={})]
    list(iter_ek_records(path=str(faux_tshark)))
    assert "non déchiffrée" not in journal.getvalue()


def test_fichier_env_invalide_leve_tsharkerror(faux_tshark, tmp_path):
    mauvais = tmp_path / "mauvais.txt"
    mauvais.write_text("wpa-pwd:court:Lab\n", encoding="utf-8")
    os.environ[ENV_WIFI_KEYS] = str(mauvais)
    with pytest.raises(TsharkError, match="8 à 63"):
        list(iter_ek_records(path=str(faux_tshark)))
    assert _FauxPopen.appels == []


def test_tag_encapsulation():
    assert detect_encapsulation({"wlan": PROTEGEE, "ip": {}}) == (TAG_80211_DECHIFFRE,)
    assert detect_encapsulation({"wlan": [{"wlan_wlan_fc_protected": "1"}], "ipv6": {}}) == (TAG_80211_DECHIFFRE,)
    assert detect_encapsulation({"wlan": {"wlan_wlan_fc_protected": False}, "ip": {}}) == ()
    assert detect_encapsulation({"wlan": PROTEGEE}) == ()
    assert detect_encapsulation({"ip": {}}) == ()
    assert TAG_80211_DECHIFFRE not in detect_encapsulation({"wlan": PROTEGEE, "ip": {}, "capwap_data": {}})


# -- vrai tshark -----------------------------------------------------------


@avec_tshark
def test_dechiffrement_reel(fichier_cles, journal, monkeypatch):
    capture = str(wpa2_reference.WPA2_PCAP)
    assert parse_capture(capture) == []
    assert "aucune clé Wi-Fi fournie" in journal.getvalue()

    vus = []
    vrai_popen = subprocess.Popen

    def espion(args, **kwargs):
        vus.append(list(args))
        return vrai_popen(args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", espion)
    monkeypatch.setattr(ek_source.subprocess, "Popen", espion)
    os.environ[ENV_WIFI_KEYS] = str(fichier_cles)
    paquets = parse_capture(capture)
    flux = [(p.proto, p.src, p.dst, p.sport, p.dport) for p in paquets]
    assert flux == [("UDP", "10.0.0.2", "10.0.0.1", 5000, 6000)] * 2
    assert [p.payload for p in paquets] == [b"netcross-wifi-1", b"netcross-wifi-2"]
    assert all(p.encap_tags == (TAG_80211_DECHIFFRE,) for p in paquets)
    assert paquets[0].radio is not None and paquets[0].radio.channel == 6
    assert vus and all(wpa2_reference.PHRASE not in " ".join(a) for a in vus)
    assert wpa2_reference.PHRASE not in journal.getvalue()


def _lancer_cli(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["prog", *[str(a) for a in argv]])
    with (
        contextlib.redirect_stdout(io.StringIO()) as sortie,
        contextlib.redirect_stderr(io.StringIO()) as erreurs,
    ):
        code = 0
        try:
            cli.main()
        except SystemExit as exc:
            code = exc.code or 0
    return code, sortie.getvalue(), erreurs.getvalue()


@avec_tshark
def test_cli_wifi_keys_sans_fuite(fichier_cles, journal, monkeypatch, tmp_path):
    rapport = tmp_path / "rapport.json"
    code, sortie, erreurs = _lancer_cli(
        monkeypatch,
        "--capture",
        f"WIFI={wpa2_reference.WPA2_PCAP}",
        "--wifi-keys",
        fichier_cles,
        "--json-report",
        rapport,
    )
    assert code == 0, erreurs
    assert os.environ[ENV_WIFI_KEYS] == str(fichier_cles)
    assert "1 cle(s) Wi-Fi transmise(s)" in erreurs
    contenu = rapport.read_text(encoding="utf-8")
    assert "10.0.0.2" in contenu
    for texte in (contenu, sortie, erreurs, journal.getvalue()):
        assert wpa2_reference.PHRASE not in texte


def test_cli_wifi_keys_invalide(fichier_cles, monkeypatch, tmp_path):
    mauvais = tmp_path / "mauvais.txt"
    mauvais.write_text("wpa-pwd:phrasesecrete\n", encoding="utf-8")
    code, _, erreurs = _lancer_cli(monkeypatch, "--capture", "A=x.pcap", "--wifi-keys", mauvais)
    assert code == 1
    assert "--wifi-keys : ligne 1" in erreurs
    assert "phrasesecrete" not in erreurs
    assert os.environ[ENV_WIFI_KEYS] == ""
