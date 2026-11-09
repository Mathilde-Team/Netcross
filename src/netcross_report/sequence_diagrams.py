# SPDX-License-Identifier: GPL-3.0-or-later
"""netcross_report.sequence_diagrams -- diagrammes de sequence multi-points
du rapport HTML (issue #1079, sous-issue 4/6 du chantier #1000).

Le PDF plafonnait un flux a 30 lignes (``sequence_view.DEFAULT_MAX_STEPS``)
: au-dela, la troncature etait plus honnete qu'une image illisible. Le
rapport HTML, lui, peut DEFILEER : ce module prepare les donnees NON
TRONQUEES des flux principaux, et ne degrade la fidelite que lorsque le
poids du fichier le demande -- par echantillonnage regulier, signale noir
sur blanc (jamais une silently tronquee).

Meme source que les preuves cliquables (#1077) : le dict ``{cle: {point:
[Pkt, ...]}}`` de ``correlate()``, deja transmis au JSON pour
``evidence_frames``. La carte des communications (#909) en est deduite
par la meme occasion : les hotes du diagramme et ceux de la carte
racontent la meme capture.

Couche : ``netcross_report`` peut importer ``netcross_core``, jamais
l'inverse. Ce module ne fait aucun rendu : il produit des dict JSON
stables (tri deterministe, cles triees a la serialisation).
"""

from __future__ import annotations

import json

from netcross_core.logging_config import get_logger, summarize
from netcross_report.comm_map import build_comm_map, comm_map_to_dict
from netcross_report.sequence_view import top_flow_views

logger = get_logger(__name__)

# Budget des donnees de sequence dans le JSON embarque (issue #1079 : le
# seuil d'echantillonnage vise un FICHIER de ~20 Mo). Le rendu statique
# <noscript> repete les lignes : on budgetise donc les donnees a moitie du
# seuil fichier, la carte des communications et le reste du document
# prenant l'autre moitie. Au-dela : echantillonnage regulier, SIGNE.
BUDGET_DONNEES_DEFAUT = 10 * 1024 * 1024

# Flux rendus : les plus volumineux d'abord (meme critere que le PDF, la
# gravite appartiendrait aux constats). Trois diagrammes suffisent a lire
# un echange ; le reste est de la repetition.
MAX_FLUX_DEFAUT = 3


def _etape_dict(step) -> dict:
    """Une ligne de diagramme, telle qu'elle sera serialisee : tout ce que
    le rendu JS affiche (fleche, libelle, retransmission), rien d'autre."""
    logger.debug("_etape_dict: entrée")
    etape = {
        "rel_ms": step.rel_ms,
        "delta_ms": step.delta_ms,
        "src": step.src,
        "dst": step.dst,
        "point": step.point,
        "length": step.length,
        "proto": step.proto,
        "sport": step.sport,
        "dport": step.dport,
        "flags": step.flags,
        "frame_number": step.frame_number,
        "is_retransmission": step.is_retransmission,
        "label": step.label,
    }
    logger.debug("_etape_dict: retour dictionnaire")
    return etape


def _poids(steps: list[dict]) -> int:
    """Poids serialize des etapes (octets) : le budget porte sur le JSON
    embarque, pas sur le nombre de lignes."""
    logger.debug("_poids: entrée ({} étapes)", len(steps))
    taille = len(json.dumps(steps, ensure_ascii=False))
    logger.debug("_poids: retour {}", taille)
    return taille


def _echantillonner(steps: list[dict], budget: int) -> tuple[list[dict], int]:
    """Reduit les etapes tant qu'elles depassent le budget : on garde 1
    ligne sur ``k`` (toujours la premiere et la derniere -- le debut porte
    le diagnostic, la fin dit ou l'echange s'arrete). ``k`` double jusqu'a
    tenir. Les ``delta_ms`` sont recalcules entre lignes conservees : un
    delta mensonger (ecart vers une ligne supprimee) serait pire qu'aucun
    delta."""
    logger.debug("_echantillonner: entrée ({} étapes, budget={})", len(steps), budget)
    k = 1
    while _poids(steps) > budget and k < len(steps):
        k *= 2
        if k >= len(steps):
            k = max(len(steps) - 1, 1)
        gardes = steps[::k]
        if steps[-1] is not gardes[-1]:
            gardes.append(steps[-1])
        prev = None
        for etape in gardes:
            etape["delta_ms"] = 0.0 if prev is None else etape["rel_ms"] - prev
            prev = etape["rel_ms"]
        steps = gardes
    logger.debug("_echantillonner: retour ({} étapes, 1/{})", len(steps), k)
    return steps, k


def build_sequence_diagrams(
    packet_flows,
    *,
    max_flows: int = MAX_FLUX_DEFAUT,
    budget_octets: int = BUDGET_DONNEES_DEFAUT,
) -> list[dict]:
    """Diagrammes de sequence NON TRONQUES des flux principaux, en dict
    JSON-stables. Chaque diagramme :

    - ``title`` / ``hosts`` / ``points`` : structure (colonnes du dessin)
    - ``steps`` : lignes, echantillonnees si le budget l'exige
    - ``sampled_step`` : pas d'echantillonnage (1 = fidele, jamais mentir)
    - ``total_steps`` : lignes d'origine, AVANT echantillonnage

    Le budget est global (somme des diagrammes) : ce qui compte est le
    poids du fichier, pas l'equite entre flux.
    """
    logger.debug(
        "build_sequence_diagrams: packet_flows={} max_flows={} budget_octets={}",
        summarize(packet_flows, "packet_flows"),
        summarize(max_flows, "max_flows"),
        summarize(budget_octets, "budget_octets"),
    )
    vues = top_flow_views(packet_flows or {}, max_flows=max_flows, max_steps=None)
    diagrams: list[dict] = []
    for vue in vues:
        steps = [_etape_dict(s) for s in vue.steps]
        total = len(steps)
        steps, k = _echantillonner(steps, budget_octets)
        budget_octets -= _poids(steps)
        diagrams.append(
            {
                "title": vue.title,
                "hosts": list(vue.hosts),
                "points": list(vue.points),
                "steps": steps,
                "sampled_step": k,
                "total_steps": total,
            }
        )
    logger.debug("build_sequence_diagrams: retour {} diagramme(s)", len(diagrams))
    return diagrams


def build_comm_map_dict(packet_flows) -> dict:
    """Carte des communications (issue #909) en dict JSON, depuis la meme
    correlation que les preuves et les diagrammes : noeuds, aretes
    orientees, protocoles, anomalies. Aucun filtre ici : la carte complete,
    le filtrage appartient a la vue."""
    logger.debug("build_comm_map_dict: entrée ({} cle(s))", len(packet_flows or {}))
    carte = comm_map_to_dict(build_comm_map(packet_flows or {}))
    logger.debug("build_comm_map_dict: retour dictionnaire")
    return carte
