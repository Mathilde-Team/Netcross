# SPDX-License-Identifier: GPL-3.0-or-later
"""Pertes de capture déclarées et état d'horloge de la sonde (#1103).

Trois niveaux :

- ``lire_pertes_capture`` : somme des ISB pcapng (ifdrop/osdrop) —
  « la sonde a perdu », distinct des pertes réseau estimées ;
- ``lire_etat_horloge`` : horloge ANNONCÉE (chrony puis
  systemd-timesyncd, ``unknown`` en dernier recours, jamais inventée) ;
- l'acheminement jusqu'au rapport : ``extraire_fenetre`` (lire_horloge
  injectable) puis la CLI ``--sonde-meta POINT=JSON`` (testée dans
  test_cli_report_sondes.py).

Les commandes externes (chronyc, timedatectl) sont remplacées par des
stubs ; les tests pcapng réels (tshark/editcap/capinfos) sont sautés si
l'outil est absent du PATH, comme le reste du dépôt.
"""

from __future__ import annotations

import argparse
import ctypes.util
import json
import shutil
import struct

import pytest
from pcap_builders import epb, frame, idb, shb, write_bytes, write_pcap

from netcross_probe.etat import (
    EtatHorloge,
    PertesCapture,
    _lire_chrony,
    _lire_timesyncd,
    lire_etat_horloge,
    lire_pertes_capture,
)
from netcross_probe.fenetres import extraire_fenetre

LIBPCAP = ctypes.util.find_library("pcap")
TSHARK = shutil.which("tshark")
EDITCAP = shutil.which("editcap")
CAPINFOS = shutil.which("capinfos")

T0 = 1_791_000_000.0  # epoch arbitraire, seconde entière


def _isb(ifrecv=None, ifdrop=None, osdrop=None, interface=0):
    """Bloc ISB pcapng : interface_id + timestamp + options ifrecv/ifdrop/osdrop."""
    body = struct.pack("<I", interface) + struct.pack("<Q", 0)
    for code, valeur in [(4, ifrecv), (5, ifdrop), (7, osdrop)]:
        if valeur is not None:
            body += struct.pack("<HH", code, 8) + struct.pack("<Q", valeur)
    body += struct.pack("<HH", 0, 0)
    return struct.pack("<II", 0x00000005, 12 + len(body)) + body + struct.pack("<I", 12 + len(body))


def _pcapng_avec_isb(chemin, *, ifrecv, ifdrop, osdrop):
    write_bytes(
        chemin,
        shb(),
        idb(),
        epb(frame(0), ts_us=int(T0 * 1_000_000)),
        _isb(ifrecv=ifrecv, ifdrop=ifdrop, osdrop=osdrop),
    )


CHRONY_SORTIE = """Reference ID    : C0A80001 (192.168.0.1)
Stratum         : 3
Ref time (UTC)  : Tue Nov 10 01:00:00 2026
System time     : 0.000000005 seconds fast of NTP time
Last offset     : +0.000123456 seconds
RMS offset      : 0.000234567 seconds
Frequency       : 1.234 ppm slow
Residual freq   : +0.001 ppm
Skew            : 0.012 ppm
Root delay      : 0.012345678 seconds
Root dispersion : 0.023456789 seconds
Update interval : 64.4 seconds
Leap status     : Normal
"""

TIMESYNCD_SORTIE = """Server=no
NTPMessages Received=42
NTPMessages Sent=42
NTPMessageErrors=0
Offset=+0.05
Frequency=3.3ppm
PacketJitter=0.1ms
RootDistance=0.123456
ServerName=ntp.example.com
ServerAddress=192.168.0.1
"""


def _lancer_chrony(nom, arguments):
    if nom == "chronyc" and arguments == ["-n", "tracking"]:
        return CHRONY_SORTIE
    return None


def _lancer_timesyncd(nom, arguments):
    if nom == "timedatectl" and arguments == ["show-timesync"]:
        return TIMESYNCD_SORTIE
    if nom == "timedatectl" and arguments == ["show", "-p", "NTPSynchronized", "--value"]:
        return "yes\n"
    return None


# -- PertesCapture : miroir du schéma CaptureLoss du contrat v1 ------------------------------


def test_pertes_capture_vers_dict():
    pertes = PertesCapture(packets_received=1000, ifdrop=5, osdrop=2)
    assert pertes.packets_dropped == 7  # ifdrop + osdrop
    assert pertes.vers_dict() == {
        "packets_received": 1000,
        "packets_dropped": 7,
        "ifdrop": 5,
        "osdrop": 2,
    }


def test_etat_horloge_vers_dict():
    horloge = EtatHorloge(
        source="chrony",
        synchronized=True,
        offset_ms=0.123,
        dispersion_ms=0.234,
        reference="192.168.0.1",
        measured_at=1_791_000_000.0,
    )
    assert horloge.vers_dict() == {
        "source": "chrony",
        "synchronized": True,
        "offset_ms": 0.123,
        "dispersion_ms": 0.234,
        "reference": "192.168.0.1",
        "measured_at": 1_791_000_000.0,
    }


# -- lire_pertes_capture : somme des ISB -----------------------------------------------------


def test_lire_pertes_capture_somme_les_isb(tmp_path):
    """Deux fichiers pcapng avec ISB : les compteurs se somment, la
    fenêtre declare l'ensemble (le critère d'acceptation : les pertes
    déclarées dans l'ISB remontent jusqu'au rapport)."""
    _pcapng_avec_isb(tmp_path / "a.pcapng", ifrecv=1000, ifdrop=5, osdrop=2)
    _pcapng_avec_isb(tmp_path / "b.pcapng", ifrecv=500, ifdrop=1, osdrop=0)
    pertes = lire_pertes_capture([str(tmp_path / "a.pcapng"), str(tmp_path / "b.pcapng")])
    assert pertes is not None
    assert pertes.packets_received == 1500
    assert pertes.ifdrop == 6
    assert pertes.osdrop == 2
    assert pertes.packets_dropped == 8


def test_lire_pertes_capture_sans_isb_retourne_none(tmp_path):
    """Un pcap classique n'a pas d'ISB : None (pas 0) -- sans statistique,
    la sonde ne déclare rien, elle n'annonce pas zéro perte."""
    write_pcap(tmp_path / "classique.pcap", [(int(T0 * 1_000_000), frame(0))])
    assert lire_pertes_capture([str(tmp_path / "classique.pcap")]) is None


def test_lire_pertes_capture_fichier_inconnu_retourne_none():
    assert lire_pertes_capture(["/chemin/absent.pcapng"]) is None


def test_lire_pertes_capture_mixte_ne_compte_que_les_isb(tmp_path):
    _pcapng_avec_isb(tmp_path / "avec.pcapng", ifrecv=100, ifdrop=3, osdrop=1)
    write_pcap(tmp_path / "sans.pcap", [(int(T0 * 1_000_000), frame(0))])
    pertes = lire_pertes_capture([str(tmp_path / "sans.pcap"), str(tmp_path / "avec.pcapng")])
    assert pertes is not None
    assert pertes.packets_received == 100
    assert pertes.packets_dropped == 4


# -- lire_etat_horloge : chrony, timesyncd, unknown -------------------------------------------


def test_lire_chrony_parse_la_sortie_tracking():
    etat = _lire_chrony(_lancer_chrony)
    assert etat is not None
    assert etat.source == "chrony"
    assert etat.synchronized is True  # « Leap status : Normal »
    assert etat.offset_ms == pytest.approx(0.123456)  # « +0.000123456 seconds »
    assert etat.dispersion_ms == pytest.approx(0.234567)  # RMS offset
    assert etat.reference == "192.168.0.1"  # adresse lisible, pas l'ID hexa


def test_lire_chrony_non_synchronise():
    sortie = CHRONY_SORTIE.replace("Leap status     : Normal", "Leap status     : Not synchronised")
    etat = _lire_chrony(lambda nom, arguments: sortie if arguments == ["-n", "tracking"] else None)
    assert etat is not None
    assert etat.synchronized is False


def test_lire_timesyncd_parse_les_proprietes():
    etat = _lire_timesyncd(_lancer_timesyncd)
    assert etat is not None
    assert etat.source == "systemd-timesyncd"
    assert etat.synchronized is True  # NTPSynchronized=yes
    assert etat.offset_ms == pytest.approx(50.0)  # Offset=+0.05 s
    assert etat.dispersion_ms == pytest.approx(123.456)  # RootDistance
    assert etat.reference == "ntp.example.com"


def test_lire_etat_horloge_chrony_prioritaire():
    etat = lire_etat_horloge(_lancer_chrony)  # timesyncd aussi servi -> chrony gagne
    assert etat.source == "chrony"


def test_lire_etat_horloge_repli_timesyncd():
    etat = lire_etat_horloge(_lancer_timesyncd)  # chronyc absent
    assert etat.source == "systemd-timesyncd"


def test_lire_etat_horloge_unknown_ne_ment_jamais():
    """Ni chronyc ni timedatectl : source ``unknown``, aucune valeur
    inventée -- l'état réel (PTP, ntpd) n'est pas deviné."""
    etat = lire_etat_horloge(lambda nom, arguments: None)
    assert etat.source == "unknown"
    assert etat.synchronized is False
    assert etat.offset_ms is None
    assert etat.dispersion_ms is None
    assert etat.reference is None
    assert etat.measured_at > 0


def test_lire_etat_horloge_chrony_en_echec_replie_timesyncd():
    """chronyc présent mais code de sortie non nul : repli timesyncd."""
    etat = lire_etat_horloge(_lancer_timesyncd)
    assert etat.source == "systemd-timesyncd"


# -- extraire_fenetre : les métadonnées suivent la fenêtre -----------------------------------


requis_reels = pytest.mark.skipif(
    TSHARK is None or EDITCAP is None or CAPINFOS is None or LIBPCAP is None,
    reason="tshark/editcap/capinfos ou libpcap absent du PATH",
)


@requis_reels
def test_fenetre_porte_pertes_declarees_et_horloge(tmp_path):
    """Le JSON de la fenêtre (contrat v1 : Window.capture_loss/clock)
    porte les pertes déclarées par les ISB du tampon et l'horloge lue au
    moment de l'extraction (injectée : pas d'appel chronyc dans un test)."""
    horloge_annoncee = EtatHorloge(
        source="chrony",
        synchronized=True,
        offset_ms=0.5,
        dispersion_ms=1.0,
        reference="192.168.0.1",
        measured_at=1_791_000_012.0,
    )
    write_bytes(
        tmp_path / "probe_00001_20261109120000.pcapng",
        shb(),
        idb(),
        epb(frame(0), ts_us=int((T0 + 1) * 1_000_000)),
        epb(frame(1), ts_us=int((T0 + 2) * 1_000_000)),
        _isb(ifrecv=100, ifdrop=3, osdrop=1),
    )
    resultat = extraire_fenetre(
        str(tmp_path),
        T0,
        T0 + 3,
        dossier_sortie=str(tmp_path / "sorties"),
        lire_horloge=lambda: horloge_annoncee,
    )
    assert resultat.pertes is not None
    assert resultat.pertes.vers_dict() == {
        "packets_received": 100,
        "packets_dropped": 4,
        "ifdrop": 3,
        "osdrop": 1,
    }
    assert resultat.horloge is horloge_annoncee


@requis_reels
def test_fenetre_sans_isb_declare_rien(tmp_path):
    """Tampon sans ISB (pcap classique) : pertes None, pas 0."""
    write_pcap(
        tmp_path / "probe_00001_20261109120000.pcap",
        [(int((T0 + 1) * 1_000_000), frame(0)), (int((T0 + 2) * 1_000_000), frame(1))],
    )
    resultat = extraire_fenetre(
        str(tmp_path),
        T0,
        T0 + 3,
        dossier_sortie=str(tmp_path / "sorties"),
        lire_horloge=lambda: EtatHorloge(
            source="unknown", synchronized=False, offset_ms=None, dispersion_ms=None, reference=None, measured_at=0.0
        ),
    )
    assert resultat.pertes is None
    assert resultat.horloge.source == "unknown"


# -- sérialisation JSON de la sortie CLI fenetre --------------------------------------------


def test_json_fenetre_contient_capture_loss_et_clock(monkeypatch, capsys):
    """Le JSON imprimé par ``netcross_probe fenetre`` expose les clés du
    contrat v1 : Window.capture_loss et Window.clock (extraction réelle
    remplacée par un stub -- la sérialisation est le sujet du test)."""
    from netcross_probe.__main__ import _commande_fenetre

    pertes = PertesCapture(packets_received=100, ifdrop=3, osdrop=1)
    horloge = EtatHorloge(
        source="chrony", synchronized=True, offset_ms=0.5, dispersion_ms=1.0, reference="r", measured_at=1.0
    )

    class _Resultat:
        identifiant = "abc"
        demande = (0.0, 1.0)
        couvert = (0.0, 1.0)
        nb_paquets = 2
        octets = 100
        sha256 = "0" * 64
        chemin = "/tmp/x.pcapng"

    _Resultat.pertes = pertes
    _Resultat.horloge = horloge

    monkeypatch.setattr(
        "netcross_probe.__main__.extraire_fenetre_depuis_args",
        lambda args: _Resultat,
    )
    code = _commande_fenetre(argparse.Namespace())
    assert code == 0
    document = json.loads(capsys.readouterr().out)
    assert document["capture_loss"]["packets_dropped"] == 4
    assert document["clock"]["source"] == "chrony"
    assert document["clock"]["synchronized"] is True
