# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests d'intégration du Job 38/issue #158 : metadonnees de capture dans le
Report (champ capture_infos), affichage dans print_report, et fonction
pcap_parser.capinfos_source.read_capture_infos.
"""

from __future__ import annotations

from unittest.mock import patch

from netcross_core.models import Report
from netcross_core.parsing import read_capture_infos
from netcross_core.report_text import print_report

# -- read_capture_infos ----------------------------------------------------


def test_read_capture_infos_renvoie_une_liste_vide_sans_captures():
    assert read_capture_infos([]) == []


def test_read_capture_infos_filtre_les_none(monkeypatch, tmp_path):
    """Une capture dont read_capture_info renvoie None (capinfos absent,
    fichier illisible) ne produit aucune entree, comme read_capture_comments."""
    path = str(tmp_path / "absent.pcap")
    with patch("pcap_parser.capinfos_source.read_capture_info", return_value=None):
        infos = read_capture_infos([("POINT_A", path)])
    assert infos == []


def test_read_capture_infos_formate_les_metadonnees_avec_le_label(monkeypatch, tmp_path):
    """Le label du point de capture est attache a chaque entree, comme
    read_capture_comments -- pcap_parser.capinfos_source.read_capture_info
    ne connait volontairement aucun concept de label."""
    from pcap_parser.capfile import InterfaceRecord
    from pcap_parser.capinfos_source import CaptureInfo

    path = str(tmp_path / "capture.pcapng")
    mock_info = CaptureInfo(
        path=path,
        file_type="pcapng",
        version="1.0",
        encapsulation="Ethernet",
        snaplen=65535,
        packet_count=42,
        byte_count=4096,
        duration_seconds=10.5,
        hardware="TestHardware",
        interfaces=(
            InterfaceRecord(
                index=0,
                linktype=1,
                snaplen=65535,
                name="eth0",
                received=42,
                dropped_by_interface=2,
                dropped_by_os=0,
            ),
        ),
    )
    with patch("pcap_parser.capinfos_source.read_capture_info", return_value=mock_info):
        infos = read_capture_infos([("POINT_A", path)])

    assert len(infos) == 1
    info = infos[0]
    assert info["label"] == "POINT_A"
    assert info["path"] == path
    assert info["file_type"] == "pcapng"
    assert info["version"] == "1.0"
    # Assertion manquante jusqu'a l'issue #263 : la cle etait bien produite
    # par read_capture_infos, mais rien ne le verifiait et personne ne
    # l'affichait -- le champ traversait tout le pipeline sans usage.
    assert info["encapsulation"] == "Ethernet"
    assert info["snaplen"] == 65535
    assert info["packet_count"] == 42
    assert info["byte_count"] == 4096
    assert info["duration_seconds"] == 10.5
    assert info["hardware"] == "TestHardware"
    assert info["dropped_by_interface"] == 2
    assert info["dropped_by_os"] == 0
    assert len(info["interfaces"]) == 1
    iface = info["interfaces"][0]
    assert iface["index"] == 0
    assert iface["name"] == "eth0"
    assert iface["received"] == 42
    assert iface["dropped_by_interface"] == 2


def test_read_capture_infos_plusieurs_captures(monkeypatch, tmp_path):
    from pcap_parser.capinfos_source import CaptureInfo

    path_a = str(tmp_path / "a.pcap")
    path_b = str(tmp_path / "b.pcapng")
    with patch(
        "pcap_parser.capinfos_source.read_capture_info",
        side_effect=[
            CaptureInfo(path=path_a, file_type="pcap", version="2.4", packet_count=10),
            None,  # capinfos absent pour b
            CaptureInfo(path=path_b, file_type="pcapng", version="1.0", packet_count=20),
        ],
    ):
        infos = read_capture_infos([("A", path_a), ("B", path_b), ("C", str(tmp_path / "c.pcap"))])
    assert len(infos) == 2
    assert infos[0]["label"] == "A"
    assert infos[0]["file_type"] == "pcap"
    assert infos[1]["label"] == "C"
    assert infos[1]["file_type"] == "pcapng"


# -- Report.capture_infos --------------------------------------------------


def test_report_capture_infos_vide_par_defaut():
    r = Report()
    assert r.capture_infos == []


def test_report_capture_infos_assignable():
    r = Report()
    r.capture_infos = [{"label": "A", "file_type": "pcap"}]
    assert r.capture_infos == [{"label": "A", "file_type": "pcap"}]


# -- print_report : section metadonnees de capture -------------------------


def test_print_report_sans_capture_infos_n_affiche_pas_la_section(capsys):
    """La section metadonnees doit etre absente si capture_infos est vide,
    comme la section commentaires pcapng : la sortie historique reste
    inchangee."""
    r = Report(points=["A"])
    print_report(r)
    out = capsys.readouterr().out
    assert "Metadonnees de capture" not in out


def test_print_report_avec_capture_infos_affiche_la_section(capsys):
    r = Report(points=["A"])
    r.capture_infos = [
        {
            "label": "POINT_A",
            "file_type": "pcapng",
            "version": "1.0",
            "encapsulation": "ether",
            "snaplen": 65535,
            "packet_count": 42,
            "byte_count": 4096,
            "duration_seconds": 10.5,
            "hardware": "TestHW",
            "operating_system": "Linux",
            "application": "dumpcap",
            "dropped_by_interface": 2,
            "dropped_by_os": 0,
            "interfaces": [
                {
                    "index": 0,
                    "linktype": 1,
                    "snaplen": 65535,
                    "name": "eth0",
                    "received": 42,
                    "dropped_by_interface": 2,
                    "dropped_by_os": 0,
                },
            ],
        },
    ]
    print_report(r)
    out = capsys.readouterr().out
    assert "Metadonnees de capture" in out
    assert "POINT_A" in out
    assert "pcapng" in out
    # Issue #263 : ce test verifiait chaque autre champ de la section mais
    # pas l'encapsulation -- coherent avec le fait qu'elle n'etait pas
    # affichee. L'assertion manquante etait le signal.
    assert "encapsulation ether" in out
    assert "1.0" in out
    assert "42 paquets" in out
    assert "snaplen" in out
    assert "65535" in out
    assert "duree" in out
    assert "10.500" in out
    assert "materiel" in out
    assert "TestHW" in out
    assert "OS" in out
    assert "Linux" in out
    assert "application" in out
    assert "dumpcap" in out
    assert "pertes" in out
    assert "interface : 2" in out
    assert "eth0" in out
    assert "recus" in out
    assert "perdus(iface)" in out


def test_print_report_capture_infos_sans_drops_n_affiche_pas_pertes(capsys):
    r = Report(points=["A"])
    r.capture_infos = [
        {
            "label": "A",
            "file_type": "pcap",
            "version": "2.4",
            "packet_count": 5,
            "interfaces": [],
        },
    ]
    print_report(r)
    out = capsys.readouterr().out
    assert "paquets perdus" not in out


def test_print_report_capture_infos_sans_snaplen_n_affiche_pas_snaplen(capsys):
    r = Report(points=["A"])
    r.capture_infos = [
        {
            "label": "A",
            "file_type": "pcap",
            "version": "2.4",
            "packet_count": 5,
        },
    ]
    print_report(r)
    out = capsys.readouterr().out
    assert "snaplen" not in out


# -- link type dans le rapport (issue #263) -----------------------------------


def _rapport(capture_infos, capsys):
    """Rend print_report() sur un Report minimal et renvoie la sortie."""
    r = Report(points=["A"])
    r.capture_infos = capture_infos
    print_report(r)
    return capsys.readouterr().out


def test_le_rapport_affiche_l_encapsulation_au_niveau_fichier(capsys):
    """Issue #263 : `encapsulation` etait lu par capinfos, propage jusqu'au
    dict du rapport... et jamais affiche."""
    sortie = _rapport(
        [
            {
                "label": "POINT_A",
                "file_type": "pcapng",
                "version": "1.0",
                "encapsulation": "ether",
                "packet_count": 42,
                "interfaces": [{"index": 0, "linktype": 1, "name": "eth0"}],
            }
        ],
        capsys,
    )
    assert "encapsulation ether" in sortie


def test_le_rapport_traduit_le_code_dlt_en_nom_lisible(capsys):
    """`linktype 1` ne dit rien a un lecteur ; `1 (Ethernet)` si."""
    sortie = _rapport(
        [
            {
                "label": "POINT_A",
                "file_type": "pcap",
                "version": "2.4",
                "interfaces": [{"index": 0, "linktype": 1, "name": "eth0"}],
            }
        ],
        capsys,
    )
    assert "linktype 1 (Ethernet)" in sortie


def test_un_code_dlt_inconnu_reste_affiche_tel_quel(capsys):
    """Un code absent de la table est affiche brut plutot que masque : sa
    presence dans un rapport est ce qui permettra d'enrichir la table."""
    sortie = _rapport(
        [
            {
                "label": "POINT_A",
                "file_type": "pcap",
                "version": "2.4",
                "interfaces": [{"index": 0, "linktype": 9999, "name": "exotique"}],
            }
        ],
        capsys,
    )
    assert "linktype 9999" in sortie


def test_encapsulation_visible_meme_sans_detail_par_interface(capsys):
    """Cas du fichier compresse : le cadrage binaire echoue donc
    `interfaces` est vide, mais capinfos a quand meme lu l'encapsulation.
    C'est precisement le cas ou l'absence d'affichage privait le rapport de
    TOUTE information de link type (issue #263)."""
    sortie = _rapport(
        [
            {
                "label": "POINT_A",
                "file_type": "pcapng",
                "version": "1.0",
                "encapsulation": "Linux cooked (SLL)",
                "packet_count": 7,
                "interfaces": [],
            }
        ],
        capsys,
    )
    assert "encapsulation Linux cooked (SLL)" in sortie
    assert "non renseigne" not in sortie


def test_absence_totale_de_link_type_est_signalee_explicitement(capsys):
    """Regle de tracabilite : une information absente est tracee, pas omise.
    Sans cette ligne, un rapport sans link type serait indistinguable d'un
    rapport ou la question ne se pose pas."""
    sortie = _rapport(
        [
            {
                "label": "POINT_A",
                "file_type": "pcap",
                "version": "2.4",
                "packet_count": 3,
                "interfaces": [],
            }
        ],
        capsys,
    )
    assert "link type : non renseigne" in sortie
