# SPDX-License-Identifier: GPL-3.0-or-later
"""Raccordement conservateur des constats aux mesures actives (#1068)."""

from __future__ import annotations

from collections import defaultdict

from netcross_core.active.confirmation import confirmer
from netcross_core.active.planner import ineligibility_reason
from netcross_core.i18n import _
from netcross_core.logging_config import get_logger
from netcross_report.expert_events import build_expert_events
from netcross_report.synthesis import build_findings

logger = get_logger(__name__)


def confirmer_rapport(rapport, flows, *, enabled=False, dry_run=False, redact=False) -> dict:
    """Preuves paquet univoques ou clés exactes fournies par le détecteur.

    Les numéros de trame peuvent se répéter entre fichiers d'un même point :
    toute preuve correspondant à plusieurs clés distinctes est refusée.
    Le mode NAT reste inéligible selon le contrat du planificateur.
    """
    logger.debug("confirmer_rapport: entrée")
    if redact and (enabled or dry_run):
        logger.debug("confirmer_rapport: anonymisation incompatible -> refus")
        raise ValueError(_("confirmation active incompatible avec redact : les cibles ont été anonymisées"))
    if not enabled and not dry_run:
        resultat = confirmer([], enabled=False, dry_run=False)
        logger.debug("confirmer_rapport: retour désactivé")
        return resultat
    index: dict[tuple[str, int], set[tuple]] = defaultdict(set)
    for cle, par_point in flows.items():
        for point, paquets in par_point.items():
            for paquet in paquets:
                if paquet.frame_number is not None:
                    index[(point, paquet.frame_number)].add(cle)
    events = build_expert_events(build_findings(rapport))
    for event in events:
        event.flow_keys.extend(
            cle for cle in rapport.active_flow_evidence.get((event.rule_id, event.segment), []) if cle in flows
        )
        for preuve in event.evidence:
            if preuve.packet is not None:
                point = preuve.packet.point
                # Les preuves PMTUD portent le segment, mais leur numéro
                # vient du paquet retransmis au point amont (analysis.py).
                if event.rule_id == "pmtud_blackhole":
                    sources = [a for a, b in rapport.pairs if f"{a} -> {b}" == point]
                    if len(sources) != 1:
                        continue
                    point = sources[0]
                cles = index.get((point, preuve.packet.frame_number), set())
                if len(cles) == 1:
                    cle = next(iter(cles))
                    if cle not in event.flow_keys:
                        event.flow_keys.append(cle)
    resultat = confirmer(events, enabled=enabled, dry_run=dry_run)
    resultat["ineligible"] = [
        {"rule_id": event.rule_id, "segment": event.segment, "reason": raison}
        for event in events
        if (raison := ineligibility_reason(event)) is not None
    ]
    rapport.active_confirmation = resultat
    logger.debug("confirmer_rapport: retour")
    return resultat


def lignes_confirmation(document: dict | None) -> list[str]:
    """Texte commun aux surfaces, sans markup ni promesse de perte par saut."""
    logger.debug("lignes_confirmation: entrée")
    if not document:
        logger.debug("lignes_confirmation: retour vide")
        return []
    lignes = [_("Simulation sans émission.") if document["dry_run"] else _("Activation explicite.")]
    for mesure in document["measurements"]:
        proposition = mesure["proposal"]
        lignes.append(
            _("{segments} / {regles} : {type} : {statut}").format(
                segments=", ".join(proposition["segments"]),
                regles=", ".join(proposition["rule_ids"]),
                type=proposition["kind"],
                statut=mesure["status"],
            )
        )
        if mesure.get("command"):
            lignes.append(_("Commande : ") + mesure["command"])
        if mesure.get("error"):
            lignes.append(_("Erreur : ") + mesure["error"])
        resultat = mesure.get("result")
        if resultat:
            lignes.append(resultat["message"])
            lignes.extend(
                _(
                    "TTL {ttl} : {reponses}, non-réponse={taux} % (un silence ICMP ne prouve pas une perte réseau)."
                ).format(
                    ttl=saut["ttl"],
                    reponses=saut["reponses"],
                    taux=saut["non_reponse_pct"],
                )
                for saut in resultat.get("sauts", [])
            )
            if "statistiques" in resultat:
                lignes.append(_("RTT et pertes TWAMP : {statistiques}").format(statistiques=resultat["statistiques"]))
            lignes.append(mesure["divergence"])
    lignes.append(_("Mesures supplémentaires non exécutées (budget) : {nombre}.").format(nombre=document["omitted"]))
    lignes.extend(
        _("Constat non sondable {regle} / {segment} : {raison}.").format(
            regle=ignore["rule_id"],
            segment=ignore["segment"],
            raison=ignore["reason"],
        )
        for ignore in document.get("ineligible", [])
    )
    logger.debug("lignes_confirmation: retour")
    return lignes
