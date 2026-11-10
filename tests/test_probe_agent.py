# SPDX-License-Identifier: GPL-3.0-or-later
"""Sonde ``netcross-probe`` (issue #1099) : tampon circulaire + fenêtre [t1, t2] filtrée BPF.

Trois niveaux :

- filtrage BPF par libpcap (``netcross_probe.bpf``) : vrai pcap-filter en
  relecture, ce que tshark refuse (-f interdit avec -r) et dumpcap
  n'applique pas sur un tube ;
- extraction de fenêtre (``netcross_probe.fenetres``) : sélection du
  tampon, découpe editcap, fusion mergecap, filtre, pcapng, SHA-256 ;
- agent et CLI (``netcross_probe.agent``, ``__main__``) : registre de
  fenêtres avec expiration, codes de retour de la sous-commande ``fenetre``.

Les tests « réels » (libpcap, tshark, editcap, capinfos) sont sautés si
l'outil est absent du PATH, comme le reste du dépôt.
"""

from __future__ import annotations

import ctypes.util
import json
import os
import shutil
import struct
import subprocess

import pytest
from pcap_builders import read_pcap, write_pcap

from netcross_probe import (
    AgentCapture,
    AgentProbe,
    FiltreBpfInvalideError,
    ReglagesCapture,
    extraire_fenetre,
    valider_filtre,
)
from netcross_probe.bpf import LibpcapIndisponibleError, filtrer_capture
from netcross_probe.fenetres import FenetreInvalideError, FenetreTropGrandeError, FenetreVideError

LIBPCAP = ctypes.util.find_library("pcap")
TSHARK = shutil.which("tshark")
EDITCAP = shutil.which("editcap")
CAPINFOS = shutil.which("capinfos")

T0 = 1_791_000_000.0  # epoch arbitraire, seconde entière


def _trame(proto: int, sport: int, dport: int) -> bytes:
    """Trame Ethernet/IPv4 minimale mais décodable (TCP si proto=6, UDP si proto=17)."""
    if proto == 17:  # UDP : longueur 8 + charge 4, checksum 0
        segment = struct.pack("!HHHH", sport, dport, 8 + 4, 0) + b"\x00\x00\x00\x01"
    else:  # TCP : en-tête de 20 octets, drapeaux ACK
        segment = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, 0x10, 65535, 0, 0)
    total = 20 + len(segment)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        1,
        0,
        64,
        proto,
        0,
        b"\x0a\x00\x00\x01",
        b"\x0a\x00\x00\x02",
    )
    return b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + ip + segment


def _paquets_tampon():
    """10 paquets de T0 à T0+9 : UDP sur les rangs pairs, TCP sur les impairs."""
    return [(int((T0 + i) * 1_000_000), _trame(17 if i % 2 == 0 else 6, 40000, 443)) for i in range(10)]


def _ecrire_tampon(tmp_path, fichiers_paquets, prefixe="probe"):
    """Écrit un faux tampon circulaire : un fichier pcap par rotation, nommage tshark."""
    chemins = []
    for index, paquets in enumerate(fichiers_paquets, start=1):
        chemin = tmp_path / f"{prefixe}_{index:05d}_20261109120000.pcap"
        write_pcap(chemin, paquets)
        chemins.append(str(chemin))
    return chemins


# -- bpf : libpcap en relecture ---------------------------------------------------------------


@pytest.mark.skipif(LIBPCAP is None, reason="libpcap absente")
def test_valider_filtre_accepte_et_refuse():
    valider_filtre("tcp port 443")
    valider_filtre("udp and host 10.0.0.1")
    with pytest.raises(FiltreBpfInvalideError):
        valider_filtre("port")  # expression incomplète


@pytest.mark.skipif(LIBPCAP is None, reason="libpcap absente")
def test_filtrer_capture_applique_le_vrai_bpf(tmp_path):
    source = tmp_path / "source.pcap"
    write_pcap(source, _paquets_tampon())
    sortie = tmp_path / "filtre.pcap"
    retenus = filtrer_capture(str(source), str(sortie), "udp")
    _entete, paquets = read_pcap(sortie)
    assert retenus == 5  # les 5 paquets UDP (rangs pairs)
    assert len(paquets) == 5
    assert all(p[2][14 + 9] == 17 for p in paquets)  # champ protocole IP == UDP


@pytest.mark.skipif(LIBPCAP is None, reason="libpcap absente")
def test_filtrer_capture_aucun_paquet_et_filtre_invalide(tmp_path):
    source = tmp_path / "source.pcap"
    write_pcap(source, _paquets_tampon())
    vide = tmp_path / "vide.pcap"
    assert filtrer_capture(str(source), str(vide), "icmp") == 0
    _entete, paquets = read_pcap(vide)  # pcap valide, juste vide
    assert paquets == []
    with pytest.raises(FiltreBpfInvalideError):
        filtrer_capture(str(source), str(tmp_path / "x.pcap"), "port")


# -- fenêtres : extraction complète (tshark/editcap/capinfos réels) ---------------------------

requis_reels = pytest.mark.skipif(
    TSHARK is None or EDITCAP is None or CAPINFOS is None or LIBPCAP is None,
    reason="tshark/editcap/capinfos ou libpcap absent du PATH",
)


@requis_reels
def test_fenetre_end_to_end_sans_filtre(tmp_path):
    _ecrire_tampon(tmp_path, [_paquets_tampon()])
    resultat = extraire_fenetre(str(tmp_path), T0 + 3, T0 + 6, dossier_sortie=str(tmp_path / "sorties"))
    # bornes incluses : T0+3, T0+4, T0+5, T0+6
    assert resultat.nb_paquets == 4
    assert resultat.couvert == pytest.approx((T0 + 3, T0 + 6))
    assert resultat.demande == (T0 + 3, T0 + 6)
    assert len(resultat.sha256) == 64
    assert resultat.octets > 0
    with open(resultat.chemin, "rb") as fichier:
        assert fichier.read(4) == b"\x0a\x0d\x0d\x0a"  # magie pcapng
    assert not any(nom.startswith(".atelier") for nom in os.listdir(tmp_path / "sorties"))


@requis_reels
def test_fenetre_avec_filtre_bpf(tmp_path):
    _ecrire_tampon(tmp_path, [_paquets_tampon()])
    resultat = extraire_fenetre(str(tmp_path), T0, T0 + 9, filtre_bpf="udp", dossier_sortie=str(tmp_path / "sorties"))
    assert resultat.nb_paquets == 5
    assert resultat.couvert == pytest.approx((T0, T0 + 8))  # premier et dernier UDP


@requis_reels
def test_fenetre_bpf_sans_aucun_paquet_couvert_none(tmp_path):
    _ecrire_tampon(tmp_path, [_paquets_tampon()])
    resultat = extraire_fenetre(str(tmp_path), T0, T0 + 9, filtre_bpf="icmp", dossier_sortie=str(tmp_path / "sorties"))
    assert resultat.nb_paquets == 0
    assert resultat.couvert is None


@requis_reels
def test_fenetre_sur_plusieurs_fichiers_du_tampon(tmp_path):
    _ecrire_tampon(tmp_path, [_paquets_tampon()[:5], _paquets_tampon()[5:]])
    resultat = extraire_fenetre(str(tmp_path), T0 + 2, T0 + 7, dossier_sortie=str(tmp_path / "sorties"))
    assert resultat.nb_paquets == 6  # T0+2 .. T0+7 à cheval sur les deux rotations
    assert resultat.couvert == pytest.approx((T0 + 2, T0 + 7))


@requis_reels
def test_fenetre_hors_tampon_leve_vide(tmp_path):
    _ecrire_tampon(tmp_path, [_paquets_tampon()])
    with pytest.raises(FenetreVideError):
        extraire_fenetre(str(tmp_path), T0 + 100, T0 + 200, dossier_sortie=str(tmp_path / "sorties"))


def test_fenetre_inversee_leve_invalide(tmp_path):
    with pytest.raises(FenetreInvalideError):
        extraire_fenetre(str(tmp_path), T0 + 5, T0 + 2, dossier_sortie=str(tmp_path / "sorties"))


@requis_reels
def test_fenetre_bpf_invalide_leve_invalide(tmp_path):
    _ecrire_tampon(tmp_path, [_paquets_tampon()])
    with pytest.raises(FiltreBpfInvalideError):
        extraire_fenetre(str(tmp_path), T0, T0 + 9, filtre_bpf="port", dossier_sortie=str(tmp_path / "sorties"))


@requis_reels
def test_fenetre_trop_grande_refusee_et_supprimee(tmp_path):
    _ecrire_tampon(tmp_path, [_paquets_tampon()])
    sorties = tmp_path / "sorties"
    with pytest.raises(FenetreTropGrandeError):
        extraire_fenetre(str(tmp_path), T0, T0 + 9, dossier_sortie=str(sorties), max_octets=10)
    assert list(sorties.iterdir()) == []


# -- AgentCapture : enregistreur habillé (unitaire, enregistreur factice) ----------------------


class _FauxProcessus:
    def __init__(self):
        self.pid = 4242
        self._vivant = True

    def poll(self):
        return None if self._vivant else 0


def test_agent_capture_demarre_arrete_inventaire(tmp_path, monkeypatch):
    demarrages = []
    arrets = []
    monkeypatch.setattr(
        "netcross_probe.capture.start_ring_recorder",
        lambda *args, **kwargs: (demarrages.append((args, kwargs)), _FauxProcessus())[1],
    )
    monkeypatch.setattr(
        "netcross_probe.capture.stop_ring_recorder",
        lambda proc: (arrets.append(proc), "")[1],
    )
    monkeypatch.setattr(
        "netcross_probe.capture.ring_inventory",
        lambda dossier, prefix: [],
    )
    agent = AgentCapture(ReglagesCapture(interface="eth0", dossier=str(tmp_path)))
    assert not agent.en_cours
    agent.demarrer()
    assert agent.en_cours
    assert demarrages[0][1]["prefix"] == "probe"
    with pytest.raises(RuntimeError):
        agent.demarrer()  # déjà en cours
    assert agent.arreter() == ""
    assert arrets and not agent.en_cours
    assert agent.inventaire() == []


def test_agent_capture_arreter_sans_demarrer(tmp_path):
    agent = AgentCapture(ReglagesCapture(interface="eth0", dossier=str(tmp_path)))
    assert agent.arreter() == ""


# -- AgentProbe : registre de fenêtres avec expiration (unitaire) ------------------------------


def _faux_resultat(identifiant="abc123"):
    from netcross_probe.fenetres import FenetreResultat

    return FenetreResultat(
        identifiant=identifiant,
        demande=(1.0, 2.0),
        couvert=(1.0, 2.0),
        nb_paquets=3,
        octets=100,
        sha256="0" * 64,
        chemin="/tmp/x.pcapng",
    )


def test_agent_probe_registre_fenetres(tmp_path, monkeypatch):
    monkeypatch.setattr("netcross_probe.agent.extraire_fenetre", lambda *a, **k: _faux_resultat("f1"))
    agent = AgentProbe(
        ReglagesCapture(interface="eth0", dossier=str(tmp_path)),
        dossier_fenetres=str(tmp_path),
        expiration_fenetres=3600.0,
    )
    resultat = agent.extraire(1.0, 2.0, filtre_bpf="udp")
    assert resultat.identifiant == "f1"
    assert agent.fenetre("f1") is resultat
    assert agent.liberer("f1") is True
    assert agent.fenetre("f1") is None
    assert agent.liberer("f1") is False


def test_agent_probe_fenetre_expiree(tmp_path, monkeypatch):
    monkeypatch.setattr("netcross_probe.agent.extraire_fenetre", lambda *a, **k: _faux_resultat("f2"))
    agent = AgentProbe(
        ReglagesCapture(interface="eth0", dossier=str(tmp_path)),
        dossier_fenetres=str(tmp_path),
        expiration_fenetres=-1.0,  # déjà expirée à la naissance
    )
    agent.extraire(1.0, 2.0)
    assert agent.fenetre("f2") is None  # expirée -> plus visible
    assert agent.liberer("f2") is False


# -- CLI (python3 -m netcross_probe) -----------------------------------------------------------


@requis_reels
def test_cli_fenetre_imprime_la_description_json(tmp_path, capsys):
    from netcross_probe.__main__ import main

    _ecrire_tampon(tmp_path, [_paquets_tampon()])
    code = main(
        [
            "fenetre",
            "--dossier",
            str(tmp_path),
            "--debut",
            str(T0 + 3),
            "--fin",
            str(T0 + 6),
            "--sortie",
            str(tmp_path / "sorties"),
        ]
    )
    assert code == 0
    description = json.loads(capsys.readouterr().out)
    assert description["packet_count"] == 4
    assert description["requested"] == {"start": T0 + 3, "end": T0 + 6}
    assert len(description["sha256"]) == 64
    assert description["covered"] is not None


@requis_reels
def test_cli_fenetre_codes_de_retour(tmp_path, capsys):
    from netcross_probe.__main__ import main

    _ecrire_tampon(tmp_path, [_paquets_tampon()])
    sortie = str(tmp_path / "sorties")
    # fenêtre hors tampon -> 2
    assert (
        main(
            ["fenetre", "--dossier", str(tmp_path), "--debut", "9999999999", "--fin", "9999999999", "--sortie", sortie]
        )
        == 2
    )
    # filtre BPF invalide -> 3
    assert (
        main(
            [
                "fenetre",
                "--dossier",
                str(tmp_path),
                "--debut",
                str(T0),
                "--fin",
                str(T0 + 9),
                "--filtre-bpf",
                "port",
                "--sortie",
                sortie,
            ]
        )
        == 3
    )
    # trop grande -> 4
    assert (
        main(
            [
                "fenetre",
                "--dossier",
                str(tmp_path),
                "--debut",
                str(T0),
                "--fin",
                str(T0 + 9),
                "--max-octets",
                "10",
                "--sortie",
                sortie,
            ]
        )
        == 4
    )
    capsys.readouterr()


def test_cli_capture_arret_propre(tmp_path, monkeypatch, capsys):
    from netcross_probe.__main__ import _commande_capture, construire_parseur

    demarrages = []
    arrets = []
    monkeypatch.setattr(
        "netcross_probe.capture.start_ring_recorder",
        lambda *args, **kwargs: (demarrages.append(1), _FauxProcessus())[1],
    )
    monkeypatch.setattr(
        "netcross_probe.capture.stop_ring_recorder",
        lambda proc: (arrets.append(1), "")[1],
    )
    args = construire_parseur().parse_args(["capture", "--interface", "eth0", "--dossier", str(tmp_path)])
    # patienter injecté : premier cycle -> arrêt demandé immédiatement
    code = _commande_capture(args, patienter=lambda duree: False)
    assert code == 0
    assert demarrages and arrets
    assert "capture arrêtée" in capsys.readouterr().out


def test_cli_capture_enregistreur_mort(tmp_path, monkeypatch, capsys):
    from netcross_probe.__main__ import _commande_capture, construire_parseur

    class _ToujoursMort(_FauxProcessus):
        def __init__(self):
            super().__init__()
            self._vivant = False

    monkeypatch.setattr(
        "netcross_probe.capture.start_ring_recorder",
        lambda *args, **kwargs: _ToujoursMort(),
    )
    monkeypatch.setattr(
        "netcross_probe.capture.stop_ring_recorder",
        lambda proc: "",
    )
    args = construire_parseur().parse_args(["capture", "--interface", "eth0", "--dossier", str(tmp_path)])
    code = _commande_capture(args, patienter=lambda duree: False)
    assert code == 1
    assert "s'est arrêté" in capsys.readouterr().err


def test_cli_fenetre_imprimable_sans_outils(tmp_path, capsys, monkeypatch):
    """Le cablage argparse -> moteur est couvert même sans tshark (moteur factice)."""
    from netcross_probe.__main__ import main

    monkeypatch.setattr(
        "netcross_probe.__main__.extraire_fenetre_depuis_args",
        lambda args: _faux_resultat("cli1"),
    )
    code = main(
        [
            "fenetre",
            "--dossier",
            str(tmp_path),
            "--debut",
            "1",
            "--fin",
            "2",
            "--sortie",
            str(tmp_path),
        ]
    )
    assert code == 0
    description = json.loads(capsys.readouterr().out)
    assert description["window_id"] == "cli1"


# -- compléments de couverture : branches d'erreur et aiguillage -------------------------------


def test_main_aiguille_la_sous_commande_capture(tmp_path, monkeypatch):
    from netcross_probe.__main__ import main

    appels = []
    monkeypatch.setattr(
        "netcross_probe.__main__._commande_capture",
        lambda args, patienter=None: (appels.append(args.commande), 0)[1],
    )
    assert main(["capture", "--interface", "eth0", "--dossier", str(tmp_path)]) == 0
    assert appels == ["capture"]


def test_patienter_par_defaut_renvoie_vrai():
    from netcross_probe.__main__ import _patienter_par_defaut

    assert _patienter_par_defaut(0) is True


def test_boucle_attente_sans_outils(tmp_path, monkeypatch):
    """_boucle_attente : arrêt demandé par patienter, puis enregistreur mort."""
    from netcross_probe.__main__ import _boucle_attente
    from netcross_probe.agent import AgentProbe
    from netcross_probe.capture import AgentCapture

    vivant = _FauxProcessus()
    agent = AgentProbe.__new__(AgentProbe)
    agent.capture = AgentCapture.__new__(AgentCapture)
    agent.capture._processus = vivant
    assert _boucle_attente(agent, patienter=lambda duree: False) is True
    vivant._vivant = False
    assert _boucle_attente(agent, patienter=lambda duree: False) is False


def test_libpcap_absente_leve_erreur_specifique(monkeypatch):
    monkeypatch.setattr("ctypes.util.find_library", lambda nom: None)
    with pytest.raises(LibpcapIndisponibleError):
        valider_filtre("tcp")
    with pytest.raises(LibpcapIndisponibleError):
        filtrer_capture("/inexistant.pcap", "/tmp/x.pcap", "tcp")


def test_filtrer_capture_fichier_illisible(tmp_path):
    with pytest.raises(OSError):
        filtrer_capture(str(tmp_path / "absent.pcap"), str(tmp_path / "x.pcap"), "tcp")


def test_outils_wireshark_absents(tmp_path, monkeypatch):
    """Fusion refusée si mergecap est absent du PATH."""
    from netcross_probe.fenetres import _fusionner

    _ecrire_tampon(tmp_path, [_paquets_tampon()[:5], _paquets_tampon()[5:]])
    monkeypatch.setattr("netcross_probe.fenetres.shutil.which", lambda nom: None)
    with pytest.raises(RuntimeError, match="mergecap"):
        _fusionner(
            [str(tmp_path / "probe_00001_20261109120000.pcap"), str(tmp_path / "probe_00002_20261109120000.pcap")],
            str(tmp_path / "sorties" / "fusion.pcapng"),
        )


def test_erreur_mergecap_et_editcap(tmp_path, monkeypatch):
    """Échecs des sous-processus : mergecap et editcap signalent leur stderr."""
    from netcross_probe.fenetres import _convertir_pcapng, _fusionner

    _ecrire_tampon(tmp_path, [_paquets_tampon()[:5], _paquets_tampon()[5:]])
    echec = subprocess.CompletedProcess([], returncode=1, stderr="boom")
    monkeypatch.setattr("netcross_probe.fenetres.subprocess.run", lambda *a, **k: echec)
    with pytest.raises(RuntimeError, match="mergecap"):
        _fusionner(
            [str(tmp_path / "probe_00001_20261109120000.pcap"), str(tmp_path / "probe_00002_20261109120000.pcap")],
            str(tmp_path / "fusion.pcapng"),
        )
    with pytest.raises(RuntimeError, match="editcap"):
        _convertir_pcapng(str(tmp_path / "x.pcap"), str(tmp_path / "x.pcapng"))
