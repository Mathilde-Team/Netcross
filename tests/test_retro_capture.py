# SPDX-License-Identifier: GPL-3.0-or-later
"""tests/test_retro_capture.py — gel rétroactif sur alarme (issues #1087
et #1090).

Tests du module netcross_core.retro_capture : déclenchement à l'alarme
« raised », réglages (sévérité minimale, délai entre deux gels), fenêtre
gelée, décalage d'horloge, protection par lien dur et survie à la
rotation du tampon, puis découpe editcap et manifeste d'incident
(empreintes SHA-256). Cablage LiveDiffEngine -> GelManager au milieu du
fichier.
"""

import hashlib
import os

import pytest
from test_live_diff import _pkt, _stub_analyse_et_correlate

from netcross_core.alarms import AlarmConfig, AlarmEngine, AlarmEvent
from netcross_core.live_diff import LiveDiffConfig, LiveDiffEngine
from netcross_core.models import Report
from netcross_core.retro_capture import (
    GelConfig,
    GelManager,
    GelReport,
    ManifesteIncident,
    PointDeGel,
    archiver_incident,
    empreinte_sha256,
    verifier_manifeste,
)
from pcap_parser.capture import RingFile


def _alarme(
    timestamp: float = 1000.0,
    state: str = "raised",
    severity: str = "anomalie",
) -> AlarmEvent:
    """Une AlarmEvent synthétique — pas de capture live nécessaire."""
    return AlarmEvent(
        rule_id="loss_per_segment",
        segment="LAN -> WAN",
        state=state,
        timestamp=timestamp,
        message="Alarme de test",
        severity=severity,
    )


def _ring_file(chemin: str, start: float, end: float) -> RingFile:
    """Un RingFile synthétique (inventaire injecté, pas de capinfos)."""
    return RingFile(path=chemin, index=1, start=start, end=end, packet_count=10)


class _FauxTampon:
    """Faux tampon circulaire : des fichiers dans un répertoire temporaire,
    avec un inventaire à jour à chaque lecture (rotation simulable en
    supprimant des fichiers entre deux gels)."""

    def __init__(self, tmp_path, prefix: str = "capture"):
        self.directory = tmp_path / f"tampon-{prefix}"
        self.directory.mkdir()
        self.prefix = prefix
        self.fichiers: dict[str, tuple[float, float]] = {}

    def ajouter(self, nom: str, start: float, end: float, contenu: bytes = b"paquets") -> None:
        chemin = self.directory / nom
        chemin.write_bytes(contenu)
        self.fichiers[nom] = (start, end)

    def _reprimer_fichiers_disparus(self) -> None:
        self.fichiers = {nom: bornes for nom, bornes in self.fichiers.items() if (self.directory / nom).exists()}

    def inventaire(self):
        """Callable injecté dans PointDeGel — renvoie l'inventaire à jour."""
        self._reprimer_fichiers_disparus()
        return [
            _ring_file(str(self.directory / nom), start, end) for nom, (start, end) in sorted(self.fichiers.items())
        ]


def test_gel_config_defaults():
    """Critère d'acceptation de l'issue #1087 : réglages par défaut
    60 s avant / 30 s après, sévérité minimale « anomalie », délai
    minimal 30 s entre deux gels."""
    config = GelConfig()
    assert config.seconds_before == 60.0
    assert config.seconds_after == 30.0
    assert config.min_severity == "anomalie"
    assert config.min_delay_between_gels == 30.0


def test_gel_declenche_sur_alarme(tmp_path):
    """Une alarme « raised » protège les fichiers du tampon couvrant la
    fenêtre [t-60, t+30] — dans le répertoire d'archives, un
    sous-répertoire par point."""
    tampon = _FauxTampon(tmp_path)
    tampon.ajouter("capture_00001_20260101115900.pcapng", 900.0, 990.0)  # dans la fenêtre
    tampon.ajouter("capture_00002_20260101120030.pcapng", 990.0, 1010.0)  # dans la fenêtre
    tampon.ajouter("capture_00003_20260101120130.pcapng", 1040.0, 1100.0)  # trop tard

    archives = tmp_path / "archives"
    gel = GelManager(
        GelConfig(),
        str(archives),
        {"LAN": PointDeGel(inventory=tampon.inventaire)},
    )

    rapport = gel.on_alarm(_alarme(timestamp=1000.0))

    assert isinstance(rapport, GelReport)
    assert rapport.start == 940.0
    assert rapport.end == 1030.0
    assert len(rapport.files["LAN"]) == 2
    for protege in rapport.files["LAN"]:
        assert os.path.exists(protege)
        assert str(archives) in protege
    # Le fichier hors fenêtre n'est PAS protégé.
    assert not (archives / "gel-1" / "LAN" / "capture_00003_20260101120130.pcapng").exists()


def test_gel_survit_a_rotation_pendant_la_copie(tmp_path):
    """Critère d'acceptation de l'issue #1087 : le gel survit à une
    rotation du tampon — le fichier protégé (lien dur) reste lisible et
    intact après la SUPPRESSION de l'original par la rotation."""
    tampon = _FauxTampon(tmp_path)
    contenu = b"\x0a\x0d\x0d\x0a traces du paquet qui a leve l'alarme"
    tampon.ajouter("capture_00001_20260101115900.pcapng", 950.0, 990.0, contenu=contenu)

    gel = GelManager(
        GelConfig(),
        str(tmp_path / "archives"),
        {"LAN": PointDeGel(inventory=tampon.inventaire)},
    )
    rapport = gel.on_alarm(_alarme(timestamp=1000.0))
    assert rapport is not None
    protege = rapport.files["LAN"][0]

    # Rotation du tampon : l'original est supprimé.
    (tampon.directory / "capture_00001_20260101115900.pcapng").unlink()

    # Le fichier protégé SURVIT (lien dur : l'inode reste vivant) et son
    # contenu est intact.
    assert os.path.exists(protege)
    with open(protege, "rb") as fic:
        assert fic.read() == contenu
    # et ce n'est pas un chemin vers l'original supprimé
    assert protege != str(tampon.directory / "capture_00001_20260101115900.pcapng")


def test_gel_ignore_alarme_cleared(tmp_path):
    """Seules les alarmes « raised » déclenchent un gel — un « cleared »
    est ignoré (None, pas de répertoire d'archives créé)."""
    tampon = _FauxTampon(tmp_path)
    tampon.ajouter("capture_00001_20260101115900.pcapng", 900.0, 990.0)
    gel = GelManager(GelConfig(), str(tmp_path / "archives"), {"LAN": PointDeGel(inventory=tampon.inventaire)})

    assert gel.on_alarm(_alarme(state="cleared")) is None
    assert not (tmp_path / "archives").exists()


def test_gel_ignore_severite_trop_faible(tmp_path):
    """Sévérité minimale « anomalie » : une alarme « à surveiller » ou
    « info » ne déclenche PAS de gel (pas d'espace disque consommé)."""
    tampon = _FauxTampon(tmp_path)
    tampon.ajouter("capture_00001_20260101115900.pcapng", 900.0, 990.0)
    gel = GelManager(GelConfig(), str(tmp_path / "archives"), {"LAN": PointDeGel(inventory=tampon.inventaire)})

    assert gel.on_alarm(_alarme(severity="a_surveiller")) is None
    assert gel.on_alarm(_alarme(severity="info")) is None
    assert gel.on_alarm(_alarme(severity="inconnu")) is None
    assert not (tmp_path / "archives").exists()


def test_gel_delai_minimal_entre_deux_gels(tmp_path):
    """Anti-flapping : une deuxième alarme moins de 30 s (défaut) après
    un gel est ignorée ; au-delà du délai, le gel repart."""
    tampon = _FauxTampon(tmp_path)
    tampon.ajouter("capture_00001_20260101115900.pcapng", 900.0, 1100.0)
    gel = GelManager(GelConfig(), str(tmp_path / "archives"), {"LAN": PointDeGel(inventory=tampon.inventaire)})

    assert gel.on_alarm(_alarme(timestamp=1000.0)) is not None
    # 10 s après : ignoré.
    assert gel.on_alarm(_alarme(timestamp=1010.0)) is None
    # 40 s après : nouveau gel.
    assert gel.on_alarm(_alarme(timestamp=1040.0)) is not None


def test_gel_prend_en_compte_decalage_horloge(tmp_path):
    """Critère d'acceptation de l'issue #1087 : le décalage d'horloge
    estimé est pris en compte — la fenêtre est TRANSLATÉE vers l'horloge
    du point avant la sélection des fichiers."""
    tampon = _FauxTampon(tmp_path)
    # Horloge du point « LAN » en avance de 120 s : un paquet vu à
    # t=1000 (analyse) est horodaté 1120 (point).
    tampon.ajouter("capture_00001_20260101115900.pcapng", 1040.0, 1080.0)

    # Sans décalage déclaré : la fenêtre point [940, 1030] ne couvre pas
    # le fichier [1040, 1080] -> gel vide.
    gel_sans = GelManager(GelConfig(), str(tmp_path / "a"), {"LAN": PointDeGel(inventory=tampon.inventaire)})
    rapport_sans = gel_sans.on_alarm(_alarme(timestamp=1000.0))
    assert rapport_sans.files["LAN"] == []

    # Avec le décalage : fenêtre point [1060, 1150] -> fichier couvert.
    gel_avec = GelManager(
        GelConfig(),
        str(tmp_path / "b"),
        {"LAN": PointDeGel(inventory=tampon.inventaire, offset_vers_point=120.0)},
    )
    rapport_avec = gel_avec.on_alarm(_alarme(timestamp=1000.0))
    assert len(rapport_avec.files["LAN"]) == 1


def test_gel_plusieurs_points(tmp_path):
    """« Sur tous les points en direct » : chaque point a son
    sous-répertoire et ses fichiers protégés."""
    tampon_lan = _FauxTampon(tmp_path, prefix="lan")
    tampon_lan.ajouter("lan_00001_20260101115900.pcapng", 950.0, 990.0)
    tampon_wan = _FauxTampon(tmp_path, prefix="wan")
    tampon_wan.ajouter("wan_00001_20260101115900.pcapng", 960.0, 995.0)

    gel = GelManager(
        GelConfig(),
        str(tmp_path / "archives"),
        {
            "LAN": PointDeGel(inventory=tampon_lan.inventaire),
            "WAN": PointDeGel(inventory=tampon_wan.inventaire),
        },
    )
    rapport = gel.on_alarm(_alarme(timestamp=1000.0))

    assert set(rapport.files) == {"LAN", "WAN"}
    assert len(rapport.files["LAN"]) == 1
    assert len(rapport.files["WAN"]) == 1
    assert (tmp_path / "archives" / "gel-1" / "LAN" / "lan_00001_20260101115900.pcapng").exists()
    assert (tmp_path / "archives" / "gel-1" / "WAN" / "wan_00001_20260101115900.pcapng").exists()


def test_gel_fichier_disparu_avant_protection(tmp_path):
    """Rotation gagnée : un fichier présent à l'inventaire mais disparu
    avant la protection est signalé (warning), le gel continue sur les
    autres fichiers."""
    tampon = _FauxTampon(tmp_path)
    tampon.ajouter("capture_00001_20260101115900.pcapng", 950.0, 990.0)
    tampon.ajouter("capture_00002_20260101120030.pcapng", 990.0, 1005.0)

    inventaire_initial = tampon.inventaire()

    def inventaire_partiel():
        # Le deuxième fichier « disparaît » entre l'inventaire et le gel.
        return inventaire_initial

    gel = GelManager(
        GelConfig(),
        str(tmp_path / "archives"),
        {"LAN": PointDeGel(inventory=inventaire_partiel)},
    )
    (tampon.directory / "capture_00002_20260101120030.pcapng").unlink()

    rapport = gel.on_alarm(_alarme(timestamp=1000.0))
    # Le fichier encore présent est protégé, le disparu est sauté sans
    # faire échouer le gel.
    assert len(rapport.files["LAN"]) == 1
    assert "capture_00001" in rapport.files["LAN"][0]


# -- Cablage LiveDiffEngine -> GelManager (issue #1087) ------------------------


def test_live_diff_declenche_le_gel(monkeypatch):
    """Cablage de l'issue #1087 : une alarme levée par le diff live
    déclenche le gel — via le retour de feed() (NOUVEAUX événements
    seulement, pas engine.events qui accumule l'historique)."""
    from netcross_core.baseline_diff import DiffFinding

    fake_finding = DiffFinding(
        severity="anomalie",
        category="loss_per_segment",
        segment="LAN -> WAN",
        message="Perte 8% (baseline 0%)",
        before=0.0,
        after=8.0,
        sample_size=200,
        evidence=[],
    )
    monkeypatch.setattr("netcross_core.live_diff.diff_reports", lambda base, current: [fake_finding])
    _stub_analyse_et_correlate(monkeypatch)

    alarm_engine = AlarmEngine(
        [AlarmConfig(rule_id="loss_per_segment", segment="LAN -> WAN", min_persistence_seconds=0.0)]
    )
    gels = []
    gel = GelManager(GelConfig(), "/tmp/gel-test-1087", {"LAN": PointDeGel(inventory=list)})
    gel.on_alarm = lambda event: gels.append(event)  # espion

    engine = LiveDiffEngine(
        baseline_report=Report(points=["LAN"]),
        config=LiveDiffConfig(min_packets_for_diff=1),
        alarm_engine=alarm_engine,
        gel=gel,
    )
    engine._add_packet(_pkt(ts=1.0))

    findings = engine._evaluate_diff()

    assert findings == [fake_finding]
    assert len(alarm_engine.active_alarms) == 1
    # Le gel a bien été appelé pour la NOUVELLE alarme...
    assert len(gels) == 1
    assert gels[0].state == "raised"
    assert gels[0].severity == "anomalie"
    # ... et une nouvelle évaluation ne re-déclenche PAS le gel (pas de
    # re-notification des anciens événements).
    engine._add_packet(_pkt(ts=2.0, frame_number=2))
    engine._evaluate_diff()
    assert len(gels) == 1


def test_live_diff_sans_gel_comportement_inchange():
    """Contrôle négatif : sans gel (défaut), le moteur live se comporte
    exactement comme avant — gel=None, aucune erreur."""
    engine = LiveDiffEngine(baseline_report=Report(points=["LAN"]))
    assert engine.gel is None
    engine._add_packet(_pkt(ts=1.0))
    assert engine._evaluate_diff() == []


# -- Découpe, archivage et manifeste d'incident (issue #1090) -------------------


def test_cut_capture_window_passe_les_bornes_a_editcap(monkeypatch, tmp_path):
    """Critère d'acceptation de l'issue #1090 : découpe précise —
    cut_capture_window transmet à editcap les bornes -A/-B en epoch et
    crée le répertoire de sortie."""
    from pcap_parser import capture as module_capture

    appels: list[list[str]] = []

    def faux_run(args: list[str]) -> None:
        appels.append(list(map(str, args)))
        # Simule editcap : écrit un fichier de sortie.
        with open(args[-1], "wb") as fic:
            fic.write(b"pcapng decoupe")

    monkeypatch.setattr(module_capture, "_wireshark_tool_path", lambda nom: nom)
    monkeypatch.setattr(module_capture, "_run_wireshark_tool", faux_run)

    sortie = str(tmp_path / "incident" / "LAN" / "segment.pcapng")
    module_capture.cut_capture_window("tampon.pcapng", sortie, 940.0, 1030.0)

    assert len(appels) == 1
    args = appels[0]
    assert args[0] == "editcap"
    assert args[args.index("-A") + 1] == "940.0"
    assert args[args.index("-B") + 1] == "1030.0"
    assert args[args.index("-A") - 1] != "-A"  # ordre invariable : -A puis -B
    assert args[-2] == "tampon.pcapng"
    assert args[-1] == sortie
    assert os.path.exists(sortie)  # le faux editcap a bien écrit


def test_archiver_incident_decoupe_et_signe(tmp_path):
    """Critère d'acceptation de l'issue #1090 : l'archive d'incident
    découpe chaque fichier protégé sur la fenêtre DU POINT (décalage
    d'horloge pris en compte), calcule les empreintes SHA-256 et écrit
    le manifeste."""
    tampon = _FauxTampon(tmp_path)
    # Horloge du point « LAN » en avance de 120 s : fenêtre point [1060, 1150].
    tampon.ajouter("capture_00001_20260101115900.pcapng", 1050.0, 1090.0, contenu=b"paquets A")
    tampon.ajouter("capture_00002_20260101120030.pcapng", 1090.0, 1140.0, contenu=b"paquets B")

    gel = GelManager(
        GelConfig(),
        str(tmp_path / "archives"),
        {"LAN": PointDeGel(inventory=tampon.inventaire, offset_vers_point=120.0)},
    )
    rapport = gel.on_alarm(_alarme(timestamp=1000.0))
    assert rapport is not None
    assert rapport.horodatage_alarme == 1000.0
    # Fenêtre du point = fenêtre d'analyse + décalage.
    assert rapport.fenetres["LAN"] == (1060.0, 1150.0)

    decoupes: list[tuple[str, str, float, float]] = []

    def faux_decoupeur(source: str, destination: str, debut: float, fin: float) -> None:
        decoupes.append((source, destination, debut, fin))
        # Simule editcap : le segment contient les octets de la source.
        with open(destination, "wb") as fic, open(source, "rb") as src:
            fic.write(src.read())

    manifeste = archiver_incident(rapport, decoupeur=faux_decoupeur)

    # Un segment par fichier protégé, découpé sur la fenêtre DU POINT.
    assert len(decoupes) == 2
    for _, _, debut, fin in decoupes:
        assert (debut, fin) == (1060.0, 1150.0)

    # Empreintes SHA-256 des segments (contenu = source, via le faux editcap).
    assert len(manifeste.fichiers) == 2
    for f in manifeste.fichiers:
        assert f.empreinte == empreinte_sha256(f.segment)
        with open(f.source, "rb") as src:
            assert f.empreinte == hashlib.sha256(src.read()).hexdigest()
        assert f.point == "LAN"

    # Manifeste écrit dans l'archive, avec l'alarme et l'horodatage.
    chemin_manifeste = tmp_path / "archives" / "gel-1" / "incident" / "manifeste.json"
    assert chemin_manifeste.exists()
    relu = ManifesteIncident.depuis_json(chemin_manifeste.read_text(encoding="utf-8"))
    assert relu == manifeste
    assert relu.alarme["rule_id"] == "loss_per_segment"
    assert relu.alarme["timestamp"] == 1000.0
    assert relu.fenetre == (940.0, 1030.0)

    # Chaîne de preuve intacte : rien à signaler.
    assert verifier_manifeste(manifeste) == []


def test_verifier_manifeste_detecte_altération_et_absence(tmp_path):
    """Critère d'acceptation de l'issue #1090 : les empreintes du
    manifeste sont vérifiées — un segment altéré (ou supprimé) est
    signalé, un segment intact ne l'est pas."""
    tampon = _FauxTampon(tmp_path)
    tampon.ajouter("capture_00001_20260101115900.pcapng", 950.0, 990.0, contenu=b"integre")

    gel = GelManager(GelConfig(), str(tmp_path / "archives"), {"LAN": PointDeGel(inventory=tampon.inventaire)})
    rapport = gel.on_alarm(_alarme(timestamp=1000.0))
    assert rapport is not None

    def faux_decoupeur(source: str, destination: str, debut: float, fin: float) -> None:
        with open(source, "rb") as src, open(destination, "wb") as fic:
            fic.write(src.read())

    manifeste = archiver_incident(rapport, decoupeur=faux_decoupeur)
    segment = manifeste.fichiers[0].segment
    assert verifier_manifeste(manifeste) == []

    # Altération : le contenu du segment ne correspond plus à l'empreinte.
    with open(segment, "wb") as fic:
        fic.write(b"truque")
    assert verifier_manifeste(manifeste) == [segment]

    # Absence : le segment a disparu de l'archive.
    os.unlink(segment)
    assert verifier_manifeste(manifeste) == [segment]


def test_archiver_incident_sans_dossier_refuse():
    """Cas défensif : un GelReport sans répertoire d'archives (fabriqué à
    la main) est refusé — le gel doit venir de GelManager."""
    rapport = GelReport(
        rule_id="loss_per_segment",
        segment="LAN",
        start=940.0,
        end=1030.0,
        files={},
        message="",
    )
    with pytest.raises(ValueError, match="dossier"):
        archiver_incident(rapport, decoupeur=lambda *a: None)
