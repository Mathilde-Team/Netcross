# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #1066 : client TWAMP-Light (RFC 5357 annexe I), avec un réflecteur
local sur la boucle locale et sans réflecteur."""

from __future__ import annotations

import socket
import struct
import threading
import time

import pytest

from netcross_core.active import twamp
from netcross_core.active.planner import PARIS_TRACEROUTE, TWAMP_LIGHT, FiveTuple, ProposedMeasurement
from netcross_core.active.twamp import (
    Reponse,
    ResultatTwamp,
    Sonde,
    TwampError,
    cible_de_proposition,
    construire_reponse,
    construire_sonde,
    depuis_ntp,
    lire_reponse,
    mesurer,
    vers_ntp,
)

RAPIDE = {"intervalle": 0.1, "timeout": 0.3}


class Reflecteur(threading.Thread):
    """Réflecteur TWAMP-Light de test sur 127.0.0.1 (port libre).

    ``perdre`` : séquences client auxquelles il ne répond pas ;
    ``parasites`` : envoie d'abord un paquet trop court et une réponse à une
    séquence inconnue, puis la vraie réponse en double."""

    def __init__(self, *, perdre=(), parasites=False, delai=0.0):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self.perdre, self.parasites, self.delai = set(perdre), parasites, delai
        self.recues: list[bytes] = []
        self.arret = threading.Event()

    def run(self):
        sequence = 0
        while not self.arret.is_set():
            try:
                sonde, client = self.sock.recvfrom(2048)
            except TimeoutError:
                continue
            reception = time.time()
            self.recues.append(sonde)
            seq_client = struct.unpack_from("!I", sonde)[0]
            if seq_client in self.perdre:
                continue
            time.sleep(self.delai)
            reponse = construire_reponse(sonde, sequence, reception, time.time(), ttl=64)
            sequence += 1
            if self.parasites:
                self.sock.sendto(b"court", client)
                inconnue = construire_reponse(struct.pack("!IQH", 999, 0, 1), 0, reception, reception)
                self.sock.sendto(inconnue, client)
                self.sock.sendto(reponse, client)
            self.sock.sendto(reponse, client)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.arret.set()
        self.join()
        self.sock.close()


# --- formats ----------------------------------------------------------------------


def test_ntp_aller_retour():
    instant = 1_762_600_000.25
    assert vers_ntp(instant) >> 32 == 1_762_600_000 + 2_208_988_800
    assert depuis_ntp(vers_ntp(instant)) == pytest.approx(instant, abs=1e-9)


def test_sonde_et_reponse():
    sonde = construire_sonde(7, 100.5)
    assert len(sonde) == 41
    assert struct.unpack_from("!IQH", sonde) == (7, vers_ntp(100.5), twamp.ERREUR_PAR_DEFAUT)
    assert len(construire_sonde(1, 0.0, taille=200)) == 200
    reponse = lire_reponse(construire_reponse(sonde, 3, 101.0, 101.25, ttl=60))
    assert reponse == Reponse(3, pytest.approx(101.25), pytest.approx(101.0), 7, pytest.approx(100.5), 60)
    assert len(construire_reponse(construire_sonde(1, 0.0, taille=200), 0, 0.0, 0.0)) == 200


def test_paquets_trop_courts():
    with pytest.raises(TwampError, match="réponse TWAMP trop courte"):
        lire_reponse(b"\x00" * 40)
    with pytest.raises(TwampError, match="sonde TWAMP trop courte"):
        construire_reponse(b"\x00" * 13, 0, 0.0, 0.0)


def test_delais_d_une_sonde():
    reponse = Reponse(0, emission=10.003, reception=10.002, sequence_client=0, emission_client=10.0, ttl_client=62)
    sonde = Sonde(0, envoi=10.0, retour_recu=10.006, reponse=reponse)
    assert not sonde.perdue
    assert sonde.aller_retour == pytest.approx(0.005)  # 6 ms moins 1 ms de traitement
    assert sonde.aller == pytest.approx(0.002)
    assert sonde.retour == pytest.approx(0.003)
    perdue = Sonde(1, envoi=11.0)
    assert perdue.perdue
    assert (perdue.aller_retour, perdue.aller, perdue.retour) == (None, None, None)


def test_statistiques_vides():
    resultat = ResultatTwamp("h", 862, "t", False, "m")
    assert resultat.statistiques()["taux_pertes"] is None
    assert resultat.statistiques()["gigue_ms"] is None


# --- avec un réflecteur local ------------------------------------------------------


def test_mesure_avec_reflecteur_local():
    with Reflecteur(delai=0.002) as reflecteur:
        resultat = mesurer("127.0.0.1", reflecteur.port, nombre=4, **RAPIDE)
    assert resultat.reflecteur_present
    assert (resultat.envoyees, resultat.recues) == (4, 4)
    stats = resultat.statistiques()
    assert stats["pertes"] == 0
    assert stats["taux_pertes"] == 0
    assert 0 <= stats["aller_retour_min_ms"] <= stats["aller_retour_moyen_ms"] <= stats["aller_retour_max_ms"] < 100
    assert stats["gigue_ms"] is not None
    assert all(len(p) == 41 for p in reflecteur.recues)
    assert resultat.message.startswith(f"réflecteur TWAMP-Light 127.0.0.1:{reflecteur.port} : 4/4 réponse(s)")
    document = resultat.to_dict()
    assert document["type"] == TWAMP_LIGHT
    assert document["sondes"][0]["ttl_recu"] == 64
    assert document["statistiques"]["recues"] == 4


def test_pertes_et_paquets_parasites():
    with Reflecteur(perdre={1, 3}, parasites=True) as reflecteur:
        resultat = mesurer("127.0.0.1", reflecteur.port, nombre=5, **RAPIDE)
    assert [s.perdue for s in resultat.sondes] == [False, True, False, True, False]
    stats = resultat.statistiques()
    assert (stats["envoyees"], stats["recues"], stats["pertes"]) == (5, 3, 2)
    assert stats["taux_pertes"] == pytest.approx(0.4)
    assert resultat.to_dict()["sondes"][1] == {"sequence": 1, "perdue": True, "aller_retour_ms": None, "ttl_recu": None}


def test_debit_limite_a_dix_sondes_par_seconde():
    with Reflecteur() as reflecteur:
        debut = time.monotonic()
        mesurer("127.0.0.1", reflecteur.port, nombre=4, **RAPIDE)
        duree = time.monotonic() - debut
        envois = len(reflecteur.recues)
    assert envois == 4
    assert duree >= 0.3  # 4 sondes à 10/s : au moins 3 intervalles


def test_mesure_journalisee(caplog_loguru):
    with Reflecteur() as reflecteur:
        mesurer("127.0.0.1", reflecteur.port, nombre=2, **RAPIDE)
    lignes = [m for m in caplog_loguru if m.startswith("TWAMP-Light ")]
    assert lignes
    assert f"cible 127.0.0.1:{reflecteur.port}, 2 sonde(s) envoyée(s), 2 reçue(s)" in lignes[-1]
    assert lignes[-1].split()[1].endswith("+00:00")  # horodatage ISO UTC


@pytest.fixture
def caplog_loguru():
    from loguru import logger

    messages: list[str] = []
    sink = logger.add(lambda m: messages.append(m.record["message"]), level="INFO")
    yield messages
    logger.remove(sink)


# --- sans réflecteur : indiqué, jamais une exception --------------------------------


def test_sans_reflecteur_aucune_reponse():
    muet = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    muet.bind(("127.0.0.1", 0))
    with muet:
        resultat = mesurer("127.0.0.1", muet.getsockname()[1], nombre=2, intervalle=0.1, timeout=0.2)
    assert not resultat.reflecteur_present
    assert resultat.envoyees == 2
    assert "aucun réflecteur TWAMP-Light ne répond" in resultat.message
    assert "(2 sonde(s), aucune réponse en 0.2 s)" in resultat.message


def test_sans_reflecteur_port_ferme():
    libre = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    libre.bind(("127.0.0.1", 0))
    port = libre.getsockname()[1]
    libre.close()
    resultat = mesurer("127.0.0.1", port, nombre=3, **RAPIDE)
    assert not resultat.reflecteur_present
    assert resultat.message.endswith("port fermé (ICMP port inaccessible)")


def test_sans_reflecteur_nom_inconnu():
    resultat = mesurer("reflecteur.invalid", nombre=1, **RAPIDE)
    assert not resultat.reflecteur_present
    assert resultat.envoyees == 0
    assert resultat.message.startswith("cible injoignable : reflecteur.invalid:862")


def test_emission_impossible(monkeypatch):
    class Prise:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def send(self, data):
            raise OSError(101, "Network is unreachable")

    monkeypatch.setattr(twamp, "_ouvrir", lambda cible, port: Prise())
    resultat = mesurer("192.0.2.1", nombre=2, **RAPIDE)
    assert not resultat.reflecteur_present
    assert "émission impossible" in resultat.message


def test_reception_finale_en_echec(monkeypatch):
    appels = []

    def attendre(sock, sondes, limite, horloge):
        appels.append(limite)
        if len(appels) > 1:
            raise OSError(100, "Network is down")

    monkeypatch.setattr(twamp, "_attendre", attendre)
    with Reflecteur() as reflecteur:
        resultat = mesurer("127.0.0.1", reflecteur.port, nombre=1, **RAPIDE)
    assert "émission impossible (" in resultat.message
    assert len(appels) == 2


def test_connect_en_echec(monkeypatch):
    class Prise:
        closed = False

        def __init__(self, *args):
            pass

        def connect(self, adresse):
            raise OSError(99, "Cannot assign requested address")

        def close(self):
            Prise.closed = True

    monkeypatch.setattr(twamp.socket, "socket", Prise)
    resultat = mesurer("127.0.0.1", nombre=1, **RAPIDE)
    assert not resultat.reflecteur_present
    assert "Cannot assign requested address" in resultat.message
    assert Prise.closed


def test_pause_entre_sondes():
    pauses: list[float] = []
    horloge = iter([0.0, 0.0, 0.0, 0.05, 0.05, 0.1, 0.1, 0.12, 0.2, 0.2, 0.3, 0.6, 0.6])
    muet = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    muet.bind(("127.0.0.1", 0))
    with muet:
        mesurer(
            "127.0.0.1",
            muet.getsockname()[1],
            nombre=2,
            intervalle=0.1,
            timeout=0.3,
            horloge=lambda: next(horloge, 10.0),
            attente=pauses.append,
        )
    assert pauses
    assert all(p > 0 for p in pauses)


# --- garde-fous ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"nombre": 0}, "nombre de sondes hors bornes"),
        ({"nombre": twamp.SONDES_MAX + 1}, "nombre de sondes hors bornes"),
        ({"intervalle": 0.05}, "au plus 10 sondes/s"),
        ({"timeout": 0}, "timeout invalide"),
        ({"port": 0}, "port invalide"),
    ],
)
def test_parametres_refuses(options, message):
    with pytest.raises(TwampError, match=message):
        mesurer("127.0.0.1", **options)


# --- lien avec le planificateur (#1063) -------------------------------------------------


def _proposition(kind=TWAMP_LIGHT, port=862):
    flux = FiveTuple("UDP", "10.0.0.1", 40000, "10.0.0.9", 53)
    return ProposedMeasurement(kind, flux, "udp", port, "pertes")


def test_cible_de_proposition():
    assert cible_de_proposition(_proposition()) == ("10.0.0.9", 862)
    assert cible_de_proposition(_proposition(port=None), "192.0.2.5") == ("192.0.2.5", 862)
    with pytest.raises(TwampError, match="pas twamp_light"):
        cible_de_proposition(_proposition(kind=PARIS_TRACEROUTE))
