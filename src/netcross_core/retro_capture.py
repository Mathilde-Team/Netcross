# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.retro_capture — gel rétroactif sur alarme (issue #1087,
chantier #1001 : enregistrement rétroactif des incidents).

Quand une alarme se lève en analyse live, les paquets qui l'ont provoquée
risquent d'être déjà partis du tampon circulaire (rotation). Le « gel »
protège à chaud, sur TOUS les points en direct, les fichiers du tampon
qui couvrent la fenêtre [t - secondes_avant, t + secondes_après] autour
de l'alarme : la reconstruction de l'incident (découpe + archivage +
manifeste, issue #1090) pourra alors travailler sur des données
garanties.

Mécanisme de protection : LIEN DUR (os.link) vers un sous-répertoire
d'archives — le fichier protégé survit à la rotation du tampon (la
rotation supprime le nom, l'inode reste vivant tant que le lien existe).
Si le système de fichiers ne supporte pas les liens durs, repli sur une
copie (shutil.copy2) : moins sûr (une rotation PENDANT la copie peut
faire perdre le fichier), d'où le lien dur en premier choix.

Ce module vit dans netcross_core (couche la plus basse du contrat
netcross_gtk4 -> netcross_report -> netcross_core -> pcap_parser) :
- il PEUT importer pcap_parser (RingFile, select_ring_files — comme
  live_diff importe déjà capture.CaptureRingBuffer) ;
- il NE PEUT PAS importer netcross_report (couche au-dessus) — la
  hiérarchie de sévérités est donc redéfinie localement (SEVERITES) ;
- il ne fait AUCUNE capture ni rotation lui-même : l'appelant (GUI/CLI)
  fournit, par point, un inventaire des fichiers du tampon.

Le décalage d'horloge estimé entre un point et l'horloge d'analyse est
pris en compte : la fenêtre de gel est TRANSLATÉE vers l'horloge du
point avant la sélection des fichiers.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Callable

from netcross_core.alarms import AlarmEvent
from netcross_core.logging_config import get_logger, summarize
from pcap_parser.capture import RingFile, cut_capture_window, select_ring_files

logger = get_logger(__name__)

# Hiérarchie des sévérités, de la plus grave à la plus faible. Copie
# LOCALE de netcross_report.synthesis.SEVERITY_ORDER (mêmes libellés) :
# netcross_core ne peut pas importer netcross_report (contrat de
# couches). Toute sévérité inconnue est traitée comme « info ».
SEVERITES = ("anomalie", "a_surveiller", "info")


def _rang_severite(severite: str) -> int:
    """Rang d'une sévérité (0 = la plus grave, « anomalie »). Toute
    sévérité inconnue est traitée comme « info » (prudence : ne pas
    lever de gel sur un libellé non standard)."""
    logger.debug("_rang_severite: entrée ({})", severite)
    if severite in SEVERITES:
        logger.debug("_rang_severite: retour rang connu")
        return SEVERITES.index(severite)
    logger.debug("_rang_severite: sévérité inconnue -> rang info")
    return SEVERITES.index("info")


@dataclass(frozen=True)
class GelConfig:
    """Réglages du gel rétroactif (issue #1087).

    seconds_before / seconds_after : taille de la fenêtre gelée autour
    de l'alarme (défauts 60 s avant / 30 s après).

    min_severity : sévérité minimale d'une alarme pour déclencher un
    gel (« anomalie » par défaut — un « info » ou « à surveiller » ne
    consomme pas d'espace disque).

    min_delay_between_gels : délai minimal entre deux gels
    (anti-flapping : une salve d'alarmes voisines ne produit qu'un gel).
    """

    seconds_before: float = 60.0
    seconds_after: float = 30.0
    min_severity: str = "anomalie"
    min_delay_between_gels: float = 30.0


@dataclass(frozen=True)
class PointDeGel:
    """Un point de capture en direct, vu par le gel.

    inventory : callable sans argument renvoyant l'inventaire à jour des
    fichiers du tampon du point (typiquement un partial de
    pcap_parser.capture.ring_inventory — les fichiers tournent, l'inventaire
    est relu À CHAQUE gel, jamais mis en cache).

    offset_vers_point : décalage d'horloge ESTIMÉ entre l'horloge
    d'analyse et l'horloge du point : à AJOUTER à un horodatage d'analyse
    pour obtenir l'horodatage correspondant du point. 0.0 par défaut
    (aucun décalage connu). Issu de la baseline
    (Report.clock_offset_estimate), converti par l'appelant.
    """

    inventory: Callable[[], Sequence[RingFile]]
    offset_vers_point: float = 0.0


@dataclass(frozen=True)
class GelReport:
    """Bilan d'un gel déclenché (ou ignoré).

    files : par point, la liste des fichiers protégés (chemins dans le
    répertoire d'archives — des liens durs vers les originaux, ou des
    copies). Vide si aucun fichier ne couvrait la fenêtre.

    fenetres : par point, la fenêtre gelée TRANSLATÉE vers l'horloge du
    point ((début, fin)) — c'est elle que la découpe editcap de
    l'archivage d'incident (issue #1090) doit utiliser.

    dossier : répertoire d'archives du gel (``<archives>/gel-<N>``) —
    les fichiers protégés vivent dans ``<dossier>/<point>/``.

    horodatage_alarme : horodatage de l'AlarmEvent à l'origine du gel
    (en horloge d'analyse) — reporté dans le manifeste d'incident
    (#1090). None si absent (GelReport fabriqué à la main).

    ignored_reason : None si le gel a bien été déclenché ; sinon la
    raison du refus (sévérité trop faible, délai minimal, alarme non
    « raised »).
    """

    rule_id: str
    segment: str
    start: float
    end: float
    files: Mapping[str, Sequence[str]]
    message: str
    fenetres: Mapping[str, tuple[float, float]] = field(default_factory=dict)
    dossier: str = ""
    horodatage_alarme: float | None = None
    ignored_reason: str | None = None


class GelManager:
    """Déclenche le gel rétroactif à chaque alarme levée.

    Branché sur AlarmEngine via le callback d'alarme de LiveDiffEngine
    (on_alarm) : le moteur live appelle on_alarm(event) pour chaque
    AlarmEvent émis. Le gel ne retient que les « raised », au-dessus de
    la sévérité minimale, et respecte le délai minimal entre deux gels.

    Chaque gel écrit dans ``<archives_dir>/gel-<N>/<point>/`` (N =
    compteur d'incidents), un sous-répertoire par point, un fichier
    protégé par fichier du tampon. Le chemin est préfixé « gel- » (et
    non « incident- ») pour ne PAS être confondu avec l'archive finale
    d'un incident reconstitué (issue #1090), qui vit elle aussi dans le
    répertoire d'archives mais après découpe et manifeste.
    """

    def __init__(
        self,
        config: GelConfig,
        archives_dir: str,
        points: Mapping[str, PointDeGel],
    ):
        logger.debug("GelManager.__init__: entrée (archives_dir={}, points={})", archives_dir, sorted(points))
        self._config = config
        self._archives_dir = archives_dir
        self._points = dict(points)
        self._last_gel: float | None = None
        self._counter = itertools.count(1)
        logger.debug("GelManager.__init__: fin")

    def on_alarm(self, event: AlarmEvent) -> GelReport | None:
        """Traite un AlarmEvent : déclenche un gel si l'alarme est
        « raised », au-dessus de la sévérité minimale, et hors délai
        minimal. Renvvoie un GelReport si un gel a été déclenché (même
        vide — la fenêtre peut ne couvrir aucun fichier), None si
        l'événement a été ignoré."""
        logger.debug("GelManager.on_alarm: entrée ({})", summarize(event, "event"))

        if event.state != "raised":
            logger.debug("GelManager.on_alarm: état != raised -> retour None")
            return None

        if _rang_severite(event.severity) > _rang_severite(self._config.min_severity):
            logger.debug(
                "GelManager.on_alarm: sévérité {} < min_severity {} -> retour None",
                event.severity,
                self._config.min_severity,
            )
            return None

        if self._last_gel is not None:
            ecoule = event.timestamp - self._last_gel
            if ecoule < self._config.min_delay_between_gels:
                logger.debug("GelManager.on_alarm: délai {} < min_delay_between_gels -> retour None", ecoule)
                return None

        self._last_gel = event.timestamp
        report = self._geler(event)
        logger.debug("GelManager.on_alarm: retour GelReport")
        return report

    def _geler(self, event: AlarmEvent) -> GelReport:
        """Déclenche le gel proprement dit : fenêtre autour de
        l'alarme, protection des fichiers de chaque point (lien dur,
        repli copie). Aucune exception ne remonte — un échec de
        protection est journalisé, le gel continue sur les autres
        fichiers/points."""
        logger.debug("GelManager._geler: entrée ({})", summarize(event, "event"))
        numero = next(self._counter)
        start = event.timestamp - self._config.seconds_before
        end = event.timestamp + self._config.seconds_after
        logger.info(
            "Gel #{} : alarme {} sur {} (sévérité {}), fenêtre [{:.0f}, {:.0f}]",
            numero,
            event.rule_id,
            event.segment,
            event.severity,
            start,
            end,
        )

        fichiers: dict[str, list[str]] = {}
        fenetres: dict[str, tuple[float, float]] = {}
        for point, def_point in self._points.items():
            fichiers[point] = self._geler_point(numero, point, def_point, start, end)
            # Fenêtre TRANSLATÉE vers l'horloge du point — c'est elle que
            # la découpe editcap de l'archivage d'incident (#1090) doit
            # utiliser, pas [start, end] qui est en horloge d'analyse.
            offset = def_point.offset_vers_point
            fenetres[point] = (start + offset, end + offset)

        total = sum(len(f) for f in fichiers.values())
        dossier = os.path.join(self._archives_dir, f"gel-{numero}")
        message = (
            f"Gel #{numero} : {total} fichier(s) protégé(s) sur {len(fichiers)} point(s) "
            f"({dossier}, fenêtre [{start:.0f}, {end:.0f}])"
        )
        logger.info("{}", message)
        logger.debug("GelManager._geler: retour GelReport")
        return GelReport(
            rule_id=event.rule_id,
            segment=event.segment,
            start=start,
            end=end,
            files=fichiers,
            message=message,
            fenetres=fenetres,
            dossier=dossier,
            horodatage_alarme=event.timestamp,
        )

    def _geler_point(
        self,
        numero: int,
        point: str,
        def_point: PointDeGel,
        start: float,
        end: float,
    ) -> list[str]:
        """Protège les fichiers du tampon d'UN point pour la fenêtre
        [start, end] (horloge d'analyse). La fenêtre est translatée
        vers l'horloge du point (décalage estimé) avant sélection.
        Renvvoie les chemins protégés (dans le répertoire d'archives)."""
        logger.debug("GelManager._geler_point: entrée (point={})", point)

        # Traduire la fenêtre vers l'horloge du point.
        offset = def_point.offset_vers_point
        inventaire = def_point.inventory()
        selection = select_ring_files(inventaire, start + offset, end + offset)

        dossier_point = os.path.join(self._archives_dir, f"gel-{numero}", point)
        proteges: list[str] = []
        for ring_file in selection:
            destination = os.path.join(dossier_point, os.path.basename(ring_file.path))
            if self._proteger_fichier(ring_file.path, destination):
                proteges.append(destination)
            else:
                logger.warning("GelManager._geler_point: {} non protégé (rotation pendant le gel ?)", ring_file.path)

        logger.debug("GelManager._geler_point: retour {} fichier(s) protégé(s) pour {}", len(proteges), point)
        return proteges

    def _proteger_fichier(self, source: str, destination: str) -> bool:
        """Protège UN fichier : lien dur si possible (survit à la
        rotation), sinon copie (shutil.copy2, métadonnées conservées).
        Renvvoie True si protégé, False si le fichier a disparu entre
        l'inventaire et la protection (la rotation a gagné)."""
        logger.debug("GelManager._proteger_fichier: entrée ({} -> {})", source, destination)
        dossier = os.path.dirname(destination)
        if dossier:
            os.makedirs(dossier, exist_ok=True)

        # Lien dur d'abord : atomique, et le fichier protégé survit à la
        # rotation du tampon (suppression du nom d'origine = l'inode
        # reste vivant tant que le lien existe).
        try:
            os.link(source, destination)
            logger.debug("GelManager._proteger_fichier: lien dur posé, retour True")
            return True
        except FileNotFoundError:
            # Fichier parti avant le lien : rotation gagnée, rien à
            # protéger (ne PAS essayer la copie — il n'y a plus de source).
            logger.debug("GelManager._proteger_fichier: source disparue, retour False")
            return False
        except OSError:
            # Lien dur impossible (FS sans support, droits...) : repli
            # copie. Moins sûr (rotation pendant la copie) mais le
            # fichier reste protégé dans le cas général.
            logger.debug("GelManager._proteger_fichier: lien dur impossible, repli copie")

        try:
            shutil.copy2(source, destination)
        except FileNotFoundError:
            logger.debug("GelManager._proteger_fichier: source disparue pendant la copie, retour False")
            return False
        logger.debug("GelManager._proteger_fichier: copie posée, retour True")
        return True


# -- Archivage d'incident (issue #1090) ----------------------------------------


@dataclass(frozen=True)
class FichierIncident:
    """Un fichier de l'archive d'incident, avec sa chaîne de preuve.

    source : fichier PROTÉGÉ du gel (lien dur vers le tampon) d'où le
    segment est découpé.

    segment : découpe editcap [début, fin] de la source, écrite dans
    ``<dossier du gel>/incident/<point>/``.

    empreinte : SHA-256 du segment — vérifiable a posteriori par
    verifier_manifeste().
    """

    point: str
    source: str
    segment: str
    empreinte: str


@dataclass(frozen=True)
class ManifesteIncident:
    """Manifeste d'un incident archivé (issue #1090) : l'alarme, l'horodatage,
    les points, les fichiers et leurs empreintes SHA-256 — la chaîne de
    preuve de l'archive. Sérialisable en JSON (vers_json/depuis_json)."""

    incident: str
    alarme: Mapping[str, object]
    fenetre: tuple[float, float]
    fichiers: tuple[FichierIncident, ...]

    def vers_json(self) -> str:
        """Sérialise le manifeste en JSON (indenté, trié) — le fichier
        ``manifeste.json`` de l'archive d'incident."""
        logger.debug("ManifesteIncident.vers_json: entrée")
        charge = {
            "incident": self.incident,
            "alarme": dict(self.alarme),
            "fenetre": {"debut": self.fenetre[0], "fin": self.fenetre[1]},
            "fichiers": [
                {
                    "point": f.point,
                    "source": f.source,
                    "segment": f.segment,
                    "empreinte": f.empreinte,
                }
                for f in self.fichiers
            ],
        }
        logger.debug("ManifesteIncident.vers_json: retour json.dumps(…)")
        return json.dumps(charge, indent=2, sort_keys=True, ensure_ascii=False)

    @classmethod
    def depuis_json(cls, texte: str) -> ManifesteIncident:
        """Reconstruit un manifeste depuis son JSON (réciproque de
        vers_json). Lève KeyError/ValueError si un champ manque."""
        logger.debug("ManifesteIncident.depuis_json: entrée")
        charge = json.loads(texte)
        manifeste = cls(
            incident=charge["incident"],
            alarme=dict(charge["alarme"]),
            fenetre=(charge["fenetre"]["debut"], charge["fenetre"]["fin"]),
            fichiers=tuple(
                FichierIncident(
                    point=f["point"],
                    source=f["source"],
                    segment=f["segment"],
                    empreinte=f["empreinte"],
                )
                for f in charge["fichiers"]
            ),
        )
        logger.debug("ManifesteIncident.depuis_json: retour ManifesteIncident")
        return manifeste


def empreinte_sha256(chemin: str) -> str:
    """SHA-256 hexadécimal (64 caractères) du contenu d'un fichier, lu
    par blocs (les captures peuvent être volumineuses)."""
    logger.debug("empreinte_sha256: entrée ({})", chemin)
    hachage = hashlib.sha256()
    with open(chemin, "rb") as fic:
        for bloc in iter(lambda: fic.read(65536), b""):
            hachage.update(bloc)
    logger.debug("empreinte_sha256: retour hexdigest")
    return hachage.hexdigest()


def archiver_incident(
    rapport: GelReport,
    *,
    decoupeur: Callable[[str, str, float, float], None] = cut_capture_window,
) -> ManifesteIncident:
    """Archive exactement la fenêtre d'un incident à partir des fichiers
    PROTÉGÉS par le gel : découpe editcap précise ([début, fin] en
    horloge du point — rapport.fenetres), puis manifeste avec les
    empreintes SHA-256 (issue #1090).

    ``decoupeur`` : fonction de découpe (défaut pcap_parser.capture.
    cut_capture_window, enveloppe editcap -A/-B), injectable pour les
    tests. Écrit les segments dans ``<dossier du gel>/incident/<point>/``
    et le manifeste dans ``<dossier du gel>/incident/manifeste.json``.

    L'archive vit DANS le répertoire du gel : les segments comme le
    manifeste sont au même endroit que les fichiers protégés — un seul
    répertoire à sauvegarder par incident.
    """
    logger.debug("archiver_incident: entrée ({})", summarize(rapport, "rapport"))
    if not rapport.dossier:
        logger.debug("archiver_incident: si not rapport.dossier -> levée ValueError")
        raise ValueError(
            "archiver_incident : le GelReport ne porte pas de répertoire d'archives "
            "(dossier vide) — le gel doit venir de GelManager.on_alarm()"
        )

    fichiers_incident: list[FichierIncident] = []
    for point, proteges in rapport.files.items():
        fenetre_point = rapport.fenetres.get(point)
        if fenetre_point is None:
            # Point sans fenêtre connue (cas défensif) : fenêtre d'analyse.
            logger.warning("archiver_incident: point {} sans fenêtre, repli horloge d'analyse", point)
            fenetre_point = (rapport.start, rapport.end)
        for protege in proteges:
            segment = os.path.join(rapport.dossier, "incident", point, os.path.basename(protege))
            dossier_segment = os.path.dirname(segment)
            if dossier_segment:
                os.makedirs(dossier_segment, exist_ok=True)
            decoupeur(protege, segment, fenetre_point[0], fenetre_point[1])
            fichiers_incident.append(
                FichierIncident(
                    point=point,
                    source=protege,
                    segment=segment,
                    empreinte=empreinte_sha256(segment),
                )
            )

    manifeste = ManifesteIncident(
        incident=os.path.basename(rapport.dossier),
        alarme={
            "rule_id": rapport.rule_id,
            "segment": rapport.segment,
            "timestamp": rapport.horodatage_alarme
            if rapport.horodatage_alarme is not None
            else rapport.start + (rapport.end - rapport.start) / 2,
        },
        fenetre=(rapport.start, rapport.end),
        fichiers=tuple(fichiers_incident),
    )
    chemin_manifeste = os.path.join(rapport.dossier, "incident", "manifeste.json")
    os.makedirs(os.path.dirname(chemin_manifeste), exist_ok=True)
    with open(chemin_manifeste, "w", encoding="utf-8") as fic:
        fic.write(manifeste.vers_json())
    logger.info(
        "Incident {} archivé : {} segment(s), manifeste {}",
        manifeste.incident,
        len(fichiers_incident),
        chemin_manifeste,
    )
    logger.debug("archiver_incident: retour ManifesteIncident")
    return manifeste


def verifier_manifeste(manifeste: ManifesteIncident) -> list[str]:
    """Vérifie les empreintes SHA-256 des segments d'un manifeste
    d'incident. Renvvoie la liste des segments NON conformes (empreinte
    différente ou fichier absent) — vide = chaîne de preuve intacte."""
    logger.debug("verifier_manifeste: entrée ({})", manifeste.incident)
    non_conformes: list[str] = []
    for f in manifeste.fichiers:
        if not os.path.exists(f.segment):
            logger.warning("verifier_manifeste: segment absent {}", f.segment)
            non_conformes.append(f.segment)
            continue
        if empreinte_sha256(f.segment) != f.empreinte:
            logger.warning("verifier_manifeste: empreinte divergente {}", f.segment)
            non_conformes.append(f.segment)
    logger.debug("verifier_manifeste: retour {} non conforme(s)", len(non_conformes))
    return non_conformes
