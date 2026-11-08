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

import itertools
import os
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Callable

from netcross_core.alarms import AlarmEvent
from netcross_core.logging_config import get_logger, summarize
from pcap_parser.capture import RingFile, select_ring_files

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
        for point, def_point in self._points.items():
            fichiers[point] = self._geler_point(numero, point, def_point, start, end)

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
