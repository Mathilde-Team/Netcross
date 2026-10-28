# SPDX-License-Identifier: GPL-3.0-or-later
"""
Job 38/issue #158 -- metadonnees de capture : pcap_parser.capinfos_source.
read_capture_info et pcap_parser.capfile.read_structure.

Quatre familles de tests, meme discipline que test_capinfos_source.py :

- fonctions PURES sur des fixtures de sortie reelle de capinfos 4.2.2
  (`capinfos -T -S -K`, colonnes separees par des TAB) ;
- cadrage binaire (read_structure) sur des fichiers pcap/pcapng fabriques
  octet par octet dans tmp_path -- y compris des Interface Statistics Blocks,
  que capinfos n'affiche pas et qu'aucun outil du projet ne fabrique ;
- orchestration du sous-processus via monkeypatch ;
- integration avec un VRAI capinfos, sautee s'il est absent.
"""

import gzip
import shutil
import struct
import subprocess

import pytest

from pcap_parser import CaptureInfo, read_capture_info
from pcap_parser.capfile import (
    FORMAT_NSECPCAP,
    FORMAT_PCAP,
    FORMAT_PCAPNG,
    CaptureStructure,
    InterfaceRecord,
    read_structure,
)
from pcap_parser.capinfos_source import _build_capture_info, _parse_table_report

# -- fixtures : sortie reelle de `capinfos -T -S -K` (4.2.2) ---------------

_COLONNES = [
    "File name",
    "File type",
    "File encapsulation",
    "File time precision",
    "Packet size limit",
    "Packet size limit min (inferred)",
    "Packet size limit max (inferred)",
    "Number of packets",
    "File size (bytes)",
    "Data size (bytes)",
    "Capture duration (seconds)",
    "Start time",
    "End time",
    "Data byte rate (bytes/sec)",
    "Data bit rate (bits/sec)",
    "Average packet size (bytes)",
    "Average packet rate (packets/sec)",
    "SHA256",
    "SHA1",
    "Strict time order",
    "Capture hardware",
    "Capture oper-sys",
    "Capture application",
]


def _table(*valeurs: str) -> str:
    assert len(valeurs) == len(_COLONNES)
    return "\t".join(_COLONNES) + "\n" + "\t".join(valeurs) + "\n"


# pcap classique de 5 paquets de 60 octets : limite de capture dans l'en-tete
# du fichier, aucun materiel/application (colonnes finales VIDES).
_TABLE_PCAP = _table(
    "a.pcap", "pcap", "ether", "microseconds", "65535", "n/a", "n/a", "5", "404", "300",
    "4.004000", "1700000000.000000", "1700000004.004000", "74.93", "599.40", "60.00", "1.25",
    "c9e7d8f0ef9d838a6db22bebc57a1a33c056b3a965dbf4d5329d38290a02f56e",
    "eeee8f8bfc845deb77cde49d264cf5c58004ea27",
    "True", "", "", "",
)  # fmt: skip

# pcapng ecrit par un outil qui renseigne materiel/OS/application ; pas de
# limite au niveau du fichier ("(not set)" : elle est portee par l'interface).
_TABLE_PCAPNG = _table(
    "drops.pcapng", "pcapng", "ether", "microseconds", "(not set)", "n/a", "n/a", "4", "536", "240",
    "3.000000", "1700000000.000000", "1700000003.000000", "80.00", "640.00", "60.00", "1.33",
    "7ed36d920cebd5424aca0e9ce20d34b2c6c1b2af93c6e7021258aa1e89ccf6aa",
    "94aa85e56b458b9062abd5da0e368d5f86cae66a",
    "True", "x86-hw", "linux", "test-app 1.0",
)  # fmt: skip

# Capture vide (en-tete seul) : duree et dates "n/a".
_TABLE_VIDE = _table(
    "empty.pcap", "pcap", "ether", "microseconds", "96", "n/a", "n/a", "0", "24", "0",
    "n/a", "n/a", "n/a", "0.00", "0.00", "0.00", "0.00",
    "e6e921a5f8b60a91e54000028fff8b2e467771814f752355a25dc336a56b0f95",
    "49cb6765f1ee732209a3fe659556323087a9dc1d",
    "True", "", "", "",
)  # fmt: skip


# -- fabrication de fichiers pcap / pcapng ----------------------------------

_TRAME = bytes.fromhex("ffffffffffff0011223344550800") + bytes(46)  # 60 octets


def _pcap(
    endian: str = "<", magic: int = 0xA1B2C3D4, snaplen: int = 65535, linktype: int = 1, paquets: int = 3
) -> bytes:
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype)
    for i in range(paquets):
        out += struct.pack(endian + "IIII", 1700000000 + i, i * 1000, len(_TRAME), len(_TRAME)) + _TRAME
    return out


def _opt(endian: str, code: int, valeur: bytes) -> bytes:
    return struct.pack(endian + "HH", code, len(valeur)) + valeur + bytes(-len(valeur) % 4)


def _bloc(endian: str, type_bloc: int, corps: bytes) -> bytes:
    total = 12 + len(corps)
    return struct.pack(endian + "II", type_bloc, total) + corps + struct.pack(endian + "I", total)


def _shb(endian: str = "<") -> bytes:
    return _bloc(endian, 0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1) + _opt(endian, 0, b""))


def _idb(endian: str = "<", linktype: int = 1, snaplen: int = 65535, nom: str | None = None) -> bytes:
    options = (_opt(endian, 2, nom.encode()) if nom else b"") + struct.pack(endian + "HH", 0, 0)
    return _bloc(endian, 1, struct.pack(endian + "HHI", linktype, 0, snaplen) + options)


def _epb(endian: str = "<", interface: int = 0, i: int = 0) -> bytes:
    ts = (1700000000 + i) * 1_000_000
    corps = struct.pack(endian + "IIIII", interface, ts >> 32, ts & 0xFFFFFFFF, len(_TRAME), len(_TRAME))
    return _bloc(endian, 6, corps + _TRAME + bytes(-len(_TRAME) % 4))


def _isb(endian: str = "<", interface: int = 0, recus=None, perdus_interface=None, perdus_os=None) -> bytes:
    options = b""
    for code, valeur in ((4, recus), (5, perdus_interface), (7, perdus_os)):
        if valeur is not None:
            options += _opt(endian, code, struct.pack(endian + "Q", valeur))
    corps = struct.pack(endian + "III", interface, 0, 0) + options + struct.pack(endian + "HH", 0, 0)
    return _bloc(endian, 5, corps)


def _ecrire(tmp_path, nom: str, contenu: bytes) -> str:
    chemin = tmp_path / nom
    chemin.write_bytes(contenu)
    return str(chemin)


# -- _parse_table_report ------------------------------------------------------


def test_parse_table_report_pcap_classique():
    fields = _parse_table_report(_TABLE_PCAP)
    assert fields is not None
    assert fields["File type"] == "pcap"
    assert fields["Number of packets"] == "5"
    assert fields["Capture application"] == ""  # colonne finale vide conservee


def test_parse_table_report_texte_libre_avec_virgule_ne_decale_pas_les_colonnes():
    # Raison du choix du separateur TAB (et non `-m`/`-Q`) : un materiel ou une
    # application contenant des virgules ou des guillemets ne doit rien decaler.
    table = _TABLE_PCAPNG.replace("x86-hw", 'Intel(R) Core(TM), "8 cores"').replace("test-app 1.0", "outil, v1")
    fields = _parse_table_report(table)
    assert fields is not None
    assert fields["Capture hardware"] == 'Intel(R) Core(TM), "8 cores"'
    assert fields["Capture application"] == "outil, v1"


@pytest.mark.parametrize(
    "sortie",
    [
        "",  # capinfos en echec : rien sur stdout
        "\n\n",
        "\t".join(_COLONNES) + "\n",  # en-tete seul
        "\t".join(_COLONNES) + "\n" + "a.pcap\tpcap\n",  # ligne plus courte que l'en-tete
    ],
)
def test_parse_table_report_forme_inattendue_donne_none(sortie):
    assert _parse_table_report(sortie) is None


# -- _build_capture_info -------------------------------------------------------


def _structure(*interfaces: InterfaceRecord, version: str = "1.0", fmt: str = FORMAT_PCAPNG) -> CaptureStructure:
    return CaptureStructure(fmt, version, tuple(interfaces))


def test_build_capture_info_pcap_classique():
    fields = _parse_table_report(_TABLE_PCAP)
    info = _build_capture_info(
        "a.pcap", fields, _structure(InterfaceRecord(0, 1, 65535), version="2.4", fmt=FORMAT_PCAP)
    )
    assert info.file_type == "pcap"
    assert info.version == "2.4"
    assert info.encapsulation == "ether"
    assert info.timestamp_precision == "microseconds"
    assert info.snaplen == 65535
    assert info.packet_count == 5
    assert info.byte_count == 300
    assert info.file_size == 404
    assert info.duration_seconds == pytest.approx(4.004)
    assert info.start_time == 1700000000.0
    assert info.end_time == pytest.approx(1700000004.004)
    assert info.strict_time_order is True
    assert (info.hardware, info.operating_system, info.application) == (None, None, None)  # "" -> None


def test_build_capture_info_pcapng_metadonnees_de_l_outil():
    fields = _parse_table_report(_TABLE_PCAPNG)
    info = _build_capture_info("drops.pcapng", fields, _structure(InterfaceRecord(0, 1, 65535, "eth0")))
    assert info.hardware == "x86-hw"
    assert info.operating_system == "linux"
    assert info.application == "test-app 1.0"
    assert [i.name for i in info.interfaces] == ["eth0"]


def test_build_capture_info_snaplen_pcapng_vient_des_interfaces():
    # "(not set)" au niveau du fichier : la limite est celle des interfaces,
    # la plus grande si plusieurs ; snaplen 0 (= sans limite) ne compte pas.
    fields = _parse_table_report(_TABLE_PCAPNG)
    info = _build_capture_info(
        "x", fields, _structure(InterfaceRecord(0, 1, 96), InterfaceRecord(1, 1, 1500), InterfaceRecord(2, 1, 0))
    )
    assert info.snaplen == 1500
    assert _build_capture_info("x", fields, _structure(InterfaceRecord(0, 1, 0))).snaplen is None
    assert _build_capture_info("x", fields, None).snaplen is None


def test_build_capture_info_capture_vide():
    info = _build_capture_info("empty.pcap", _parse_table_report(_TABLE_VIDE), None)
    assert info.packet_count == 0
    assert info.byte_count == 0
    assert info.snaplen == 96
    assert info.duration_seconds is None  # "n/a", pas 0.0
    assert info.start_time is None
    assert info.end_time is None


def test_build_capture_info_sans_cadrage_binaire():
    info = _build_capture_info("a.pcap", _parse_table_report(_TABLE_PCAP), None)
    assert info.version is None
    assert info.interfaces == ()
    assert info.has_drops is None


# -- CaptureInfo.dropped_* / has_drops --------------------------------------


def _info(*interfaces: InterfaceRecord) -> CaptureInfo:
    return CaptureInfo(path="x", interfaces=interfaces)


def test_has_drops_none_sans_statistiques():
    # Aucune statistique (pcap classique, pcapng sans ISB) : ABSENCE
    # D'INFORMATION -- surtout pas False, qui se lirait "aucune perte".
    info = _info(InterfaceRecord(0, 1, 65535))
    assert info.has_drops is None
    assert info.dropped_by_interface is None
    assert info.dropped_by_os is None
    assert _info().has_drops is None


def test_has_drops_false_si_statistiques_a_zero():
    info = _info(InterfaceRecord(0, 1, 65535, received=10, dropped_by_interface=0, dropped_by_os=0))
    assert info.has_drops is False
    assert info.dropped_by_interface == 0


def test_has_drops_true_perte_interface_ou_os():
    assert _info(InterfaceRecord(0, 1, 65535, dropped_by_interface=3)).has_drops is True
    assert _info(InterfaceRecord(0, 1, 65535, dropped_by_interface=0, dropped_by_os=2)).has_drops is True


def test_dropped_somme_sur_les_interfaces():
    info = _info(
        InterfaceRecord(0, 1, 65535, dropped_by_interface=3, dropped_by_os=1),
        InterfaceRecord(1, 1, 65535, dropped_by_interface=4),
        InterfaceRecord(2, 1, 65535),  # sans ISB : ignoree, pas comptee comme 0
    )
    assert info.dropped_by_interface == 7
    assert info.dropped_by_os == 1


# -- read_structure : pcap ------------------------------------------------


@pytest.mark.parametrize("endian", ["<", ">"])
def test_read_structure_pcap_les_deux_endianness(tmp_path, endian):
    structure = read_structure(_ecrire(tmp_path, "a.pcap", _pcap(endian, snaplen=1500, linktype=113)))
    assert structure == CaptureStructure(FORMAT_PCAP, "2.4", (InterfaceRecord(0, 113, 1500),))


def test_read_structure_pcap_nanoseconde(tmp_path):
    structure = read_structure(_ecrire(tmp_path, "n.pcap", _pcap("<", magic=0xA1B23C4D)))
    assert structure is not None
    assert structure.fmt == FORMAT_NSECPCAP


def test_read_structure_pcap_sans_statistiques(tmp_path):
    structure = read_structure(_ecrire(tmp_path, "a.pcap", _pcap()))
    interface = structure.interfaces[0]
    assert (interface.received, interface.dropped_by_interface, interface.dropped_by_os) == (None, None, None)


@pytest.mark.parametrize("contenu", [b"", b"pas une capture du tout" * 5, b"\xd4\xc3\xb2\xa1\x02\x00"])
def test_read_structure_format_inconnu_ou_tronque_donne_none(tmp_path, contenu):
    assert read_structure(_ecrire(tmp_path, "x.bin", contenu)) is None


def test_read_structure_fichier_compresse_donne_none(tmp_path):
    assert read_structure(_ecrire(tmp_path, "a.pcap.gz", gzip.compress(_pcap()))) is None


def test_read_structure_fichier_introuvable_leve_oserror(tmp_path):
    with pytest.raises(OSError):
        read_structure(str(tmp_path / "absent.pcap"))


# -- read_structure : pcapng et Interface Statistics Blocks ----------------


@pytest.mark.parametrize("endian", ["<", ">"])
def test_read_structure_pcapng_interfaces_et_compteurs(tmp_path, endian):
    contenu = (
        _shb(endian)
        + _idb(endian, linktype=1, snaplen=65535, nom="eth0")
        + _idb(endian, linktype=113, snaplen=0)
        + _epb(endian, 0)
        + _isb(endian, 0, recus=10, perdus_interface=3, perdus_os=1)
    )
    structure = read_structure(_ecrire(tmp_path, "a.pcapng", contenu))
    assert structure.fmt == FORMAT_PCAPNG
    assert structure.version == "1.0"
    eth0, cooked = structure.interfaces
    assert (eth0.name, eth0.linktype, eth0.snaplen) == ("eth0", 1, 65535)
    assert (eth0.received, eth0.dropped_by_interface, eth0.dropped_by_os) == (10, 3, 1)
    assert (cooked.name, cooked.linktype, cooked.snaplen) == (None, 113, 0)
    assert cooked.dropped_by_interface is None  # pas d'ISB pour elle : inconnu, pas 0


def test_read_structure_pcapng_sans_isb(tmp_path):
    structure = read_structure(_ecrire(tmp_path, "a.pcapng", _shb() + _idb() + _epb()))
    assert structure.interfaces[0].dropped_by_interface is None


def test_read_structure_le_dernier_isb_donne_les_totaux(tmp_path):
    # Compteurs cumulatifs : un ISB periodique en milieu de fichier puis un ISB
    # final -- seul le dernier compte, et un ISB qui omet une option ne
    # remet pas l'ancienne valeur a None.
    contenu = (
        _shb()
        + _idb()
        + _isb(interface=0, recus=5, perdus_interface=1, perdus_os=2)
        + _epb()
        + _isb(interface=0, recus=9, perdus_interface=4)
    )
    interface = read_structure(_ecrire(tmp_path, "a.pcapng", contenu)).interfaces[0]
    assert (interface.received, interface.dropped_by_interface, interface.dropped_by_os) == (9, 4, 2)


def test_read_structure_isb_d_une_interface_inconnue_est_ignore(tmp_path):
    contenu = _shb() + _idb() + _isb(interface=7, recus=1, perdus_interface=99)
    interface = read_structure(_ecrire(tmp_path, "a.pcapng", contenu)).interfaces[0]
    assert interface.dropped_by_interface is None


def test_read_structure_les_interface_id_repartent_a_zero_a_chaque_section(tmp_path):
    contenu = (
        _shb()
        + _idb(nom="a")
        + _isb(interface=0, perdus_interface=1)
        + _shb()
        + _idb(nom="b")
        + _isb(interface=0, perdus_interface=8)
    )
    premiere, seconde = read_structure(_ecrire(tmp_path, "a.pcapng", contenu)).interfaces
    assert (premiere.name, premiere.dropped_by_interface) == ("a", 1)
    assert (seconde.name, seconde.dropped_by_interface) == ("b", 8)


def test_read_structure_pcapng_tronque_garde_ce_qui_precede(tmp_path):
    complet = _shb() + _idb(nom="eth0") + _isb(perdus_interface=2) + _epb()
    interface = read_structure(_ecrire(tmp_path, "a.pcapng", complet[:-10])).interfaces[0]  # coupe dans l'EPB
    assert (interface.name, interface.dropped_by_interface) == ("eth0", 2)


def test_read_structure_pcapng_bloc_corrompu_garde_ce_qui_precede(tmp_path):
    corrompu = struct.pack("<II", 6, 3)  # longueur de bloc aberrante (< 12, non multiple de 4)
    interface = read_structure(_ecrire(tmp_path, "a.pcapng", _shb() + _idb(nom="eth0") + corrompu)).interfaces[0]
    assert interface.name == "eth0"


def test_read_structure_pcapng_option_de_longueur_aberrante(tmp_path):
    # Option annoncant 200 octets dans un bloc qui n'en contient que 8 : ignoree,
    # sans exception ni valeur inventee.
    corps = struct.pack("<III", 0, 0, 0) + struct.pack("<HH", 5, 200) + bytes(8)
    interface = read_structure(_ecrire(tmp_path, "a.pcapng", _shb() + _idb() + _bloc("<", 5, corps))).interfaces[0]
    assert interface.dropped_by_interface is None


# -- read_capture_info : orchestration (sous-processus simule) -----------


class _Proc:
    def __init__(self, stdout: str = "", returncode: int = 0):
        self.stdout = stdout
        self.returncode = returncode


def _simuler(monkeypatch, stdout: str = "", returncode: int = 0):
    """capinfos present, sortie imposee ; renvoie la liste des appels."""
    appels = []
    monkeypatch.setattr("shutil.which", lambda nom: "/usr/bin/capinfos")

    def faux_run(cmd, **kwargs):
        appels.append((cmd, kwargs))
        return _Proc(stdout, returncode)

    monkeypatch.setattr(subprocess, "run", faux_run)
    return appels


def test_read_capture_info_capinfos_absent_donne_none(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda nom: None)
    assert read_capture_info(_ecrire(tmp_path, "a.pcap", _pcap())) is None


def test_read_capture_info_appelle_capinfos_en_table_tab_sans_commentaire(monkeypatch, tmp_path):
    chemin = _ecrire(tmp_path, "a.pcap", _pcap())
    appels = _simuler(monkeypatch, _TABLE_PCAP)
    read_capture_info(chemin)
    ((cmd, kwargs),) = appels
    assert cmd == ["/usr/bin/capinfos", "-T", "-S", "-K", chemin]
    assert kwargs["timeout"] > 0
    assert kwargs["errors"] == "replace"  # texte libre non UTF-8 ne doit pas lever


def test_read_capture_info_chemin_nominal(monkeypatch, tmp_path):
    chemin = _ecrire(tmp_path, "d.pcapng", _shb() + _idb(nom="eth0") + _epb() + _isb(recus=4, perdus_interface=3))
    _simuler(monkeypatch, _TABLE_PCAPNG)
    info = read_capture_info(chemin)
    assert info.path == chemin
    assert info.file_type == "pcapng"
    assert info.version == "1.0"
    assert info.packet_count == 4
    assert info.snaplen == 65535
    assert info.dropped_by_interface == 3
    assert info.has_drops is True


@pytest.mark.parametrize("erreur", [OSError("exec format error"), subprocess.TimeoutExpired("capinfos", 30)])
def test_read_capture_info_echec_du_sous_processus_donne_none(monkeypatch, tmp_path, erreur):
    monkeypatch.setattr("shutil.which", lambda nom: "/usr/bin/capinfos")

    def leve(*args, **kwargs):
        raise erreur

    monkeypatch.setattr(subprocess, "run", leve)
    assert read_capture_info(_ecrire(tmp_path, "a.pcap", _pcap())) is None


def test_read_capture_info_capinfos_en_erreur_donne_none(monkeypatch, tmp_path):
    # Fichier illisible : code 2, rien sur stdout (verifie sur capinfos 4.2.2).
    _simuler(monkeypatch, "", returncode=2)
    assert read_capture_info(_ecrire(tmp_path, "x.bin", b"garbage")) is None


def test_read_capture_info_cadrage_illisible_garde_les_champs_de_capinfos(monkeypatch, tmp_path):
    # Fichier compresse : capinfos sait le lire, pas read_structure -- on rend
    # ce que capinfos a dit, sans interfaces, plutot que rien.
    chemin = _ecrire(tmp_path, "a.pcap.gz", gzip.compress(_pcap()))
    _simuler(monkeypatch, _TABLE_PCAP)
    info = read_capture_info(chemin)
    assert info.packet_count == 5
    assert info.interfaces == ()
    assert info.has_drops is None


def test_read_capture_info_erreur_de_lecture_du_cadrage_ne_leve_pas(monkeypatch, tmp_path):
    _simuler(monkeypatch, _TABLE_PCAP)
    info = read_capture_info(str(tmp_path / "introuvable.pcap"))  # capinfos simule "content", le fichier n'existe pas
    assert info is not None
    assert info.interfaces == ()


# -- integration : vrai capinfos --------------------------------------------

_capinfos_reel = pytest.mark.skipif(shutil.which("capinfos") is None, reason="capinfos absent de cet environnement")


@_capinfos_reel
def test_capinfos_reel_pcap_classique(tmp_path):
    info = read_capture_info(_ecrire(tmp_path, "a.pcap", _pcap(paquets=5)))
    assert info is not None
    assert info.file_type == "pcap"
    assert info.version == "2.4"
    assert info.encapsulation == "ether"
    assert info.snaplen == 65535
    assert info.packet_count == 5
    assert info.byte_count == 5 * 60
    assert info.duration_seconds == pytest.approx(4.004)
    assert info.start_time == 1700000000.0  # epoque, pas heure locale
    assert info.has_drops is None


@_capinfos_reel
def test_capinfos_reel_pcapng_avec_pertes(tmp_path):
    contenu = _shb() + _idb(nom="eth0") + b"".join(_epb(i=i) for i in range(4)) + _isb(recus=10, perdus_interface=3)
    info = read_capture_info(_ecrire(tmp_path, "d.pcapng", contenu))
    assert info.file_type == "pcapng"
    assert info.version == "1.0"
    assert info.packet_count == 4
    assert info.snaplen == 65535
    assert info.interfaces[0].name == "eth0"
    assert info.has_drops is True
    assert info.dropped_by_interface == 3


@_capinfos_reel
def test_capinfos_reel_pcapng_sans_perte(tmp_path):
    contenu = _shb() + _idb() + _epb() + _isb(recus=1, perdus_interface=0, perdus_os=0)
    assert read_capture_info(_ecrire(tmp_path, "z.pcapng", contenu)).has_drops is False


@_capinfos_reel
def test_capinfos_reel_capture_vide(tmp_path):
    info = read_capture_info(_ecrire(tmp_path, "e.pcap", _pcap(paquets=0)))
    assert info.packet_count == 0
    assert info.duration_seconds is None


@_capinfos_reel
def test_capinfos_reel_fichier_compresse(tmp_path):
    info = read_capture_info(_ecrire(tmp_path, "a.pcap.gz", gzip.compress(_pcap(paquets=2))))
    assert info is not None
    assert info.packet_count == 2
    assert info.interfaces == ()


@_capinfos_reel
def test_capinfos_reel_fichier_non_capture_donne_none(tmp_path):
    assert read_capture_info(_ecrire(tmp_path, "x.bin", b"pas une capture" * 10)) is None
    assert read_capture_info(str(tmp_path / "absent.pcap")) is None
