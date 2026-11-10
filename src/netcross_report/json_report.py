# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_report.json_report -- serialise un Report/DiffFinding en JSON
structure, pour l'integration externe (dashboard, ticketing, pipeline
CI qui veut parser un resultat sans dependre du format texte console).

Pendant de pdf.py, mais sans aucune dependance externe (json et
datetime sont dans la bibliotheque standard) : contrairement a
generate_pdf/generate_diff_pdf (None si reportlab/matplotlib/networkx
absents), generate_json_report/generate_json_diff sont toujours
disponibles, y compris dans un environnement minimal.

Reutilise exactement le meme calcul (build_findings/rank_segments) que
pdf.py plutot que de re-deriver quoi que ce soit depuis Report : le
JSON et le PDF doivent toujours s'accorder sur les memes constats/le
meme triage pour un meme Report.
"""

import dataclasses
import datetime
import json

from netcross_core.dechiffrement import document_json
from netcross_core.logging_config import get_logger, summarize
from netcross_report.path_metrics import build_path_metrics
from netcross_report.synthesis import build_findings
from netcross_report.triage import health_label, health_score, rank_segments

logger = get_logger(__name__)


def _horloge_annoncee(r, point: str) -> dict | None:
    """Issue #1103 : horloge ANNONCÉE par la sonde du point (déclarée par
    chrony/timesyncd, pas estimée par l'analyse), None si la sonde n'a rien
    annoncé (--sonde-meta absent ou clé clock vide)."""
    logger.debug("_horloge_annoncee: entrée (point {})", point)
    annonce = (getattr(r, "horloges_sondes", None) or {}).get(point) or None
    logger.debug("_horloge_annoncee: retour")
    return annonce


def _evidence_list_dict(evidence) -> list[dict]:
    """Serialise une liste d'EvidenceLink -- factorise entre _finding_dict
    et _expert_event_dict (Session 36), meme format des deux cotes
    (point/text/frame_number optionnel)."""
    logger.debug("_evidence_list_dict: retour liste")
    return [
        {
            "point": e.point,
            "text": e.text,
            **({"frame_number": e.packet.frame_number} if e.packet is not None else {}),
        }
        for e in evidence
    ]


def _finding_dict(f) -> dict:
    """Finding et DiffFinding partagent severity/category/segment/message ;
    DiffFinding ajoute before/after, les deux partagent sample_size
    (optionnels, None/absent sur ce qui n'est pas annote -- via getattr
    plutot qu'un isinstance pour rester duck-type, meme esprit que
    triage.rank_segments). sample_size : taille de l'echantillon derriere
    une valeur ESTIMEE (taux/moyenne/MOS) -- voir synthesis.py/
    baseline_diff.py pour le detail de ce qui est annote a ce jour.
    evidence (Session 32, etendu a DiffFinding en Session 33) : liste
    d'EvidenceLink (netcross_core.expert_model) sur les Finding/DiffFinding
    qui en portent -- meme getattr defensif qu'avant/apres pour rester
    duck-type, aucune modification necessaire ici pour couvrir DiffFinding :
    la seule chose qui a change est que ce champ est desormais peuple par
    netcross_core.baseline_diff.diff_reports() en plus de
    netcross_report.synthesis.build_findings(). frame_number (Session 35) :
    cle optionnelle par ligne d'evidence, presente uniquement quand
    EvidenceLink.packet (PacketEvidence) est renseigne -- aujourd'hui
    uniquement pour la categorie PMTUD (voir synthesis.py). rule_id
    (Session 48) : meme convention que sample_size/evidence ci-dessus --
    cle absente (pas de None explicite) quand le Finding/DiffFinding ne
    correspond a aucune regle du catalogue netcross_core.expert_rules
    (voir docstring de module de synthesis.py pour la liste des Finding
    volontairement sans correspondance) ; DiffFinding ne declare pas ce
    champ, meme getattr defensif."""
    d = {
        "severity": f.severity,
        "category": f.category,
        "segment": f.segment,
        "message": f.message,
    }
    before = getattr(f, "before", None)
    after = getattr(f, "after", None)
    if before is not None or after is not None:
        d["before"] = before
        d["after"] = after
    sample_size = getattr(f, "sample_size", None)
    if sample_size is not None:
        d["sample_size"] = sample_size
    evidence = getattr(f, "evidence", None)
    if evidence:
        d["evidence"] = _evidence_list_dict(evidence)
    rule_id = getattr(f, "rule_id", None)
    if rule_id is not None:
        d["rule_id"] = rule_id
    logger.debug("_finding_dict: retour d={}", summarize(d, "d"))
    return d


def _flow_dict(flow, names=None) -> dict:
    """Serialise un Flow (netcross_core.expert_model, Session 36) -- la
    cle brute (tuple Python) n'est pas JSON-serialisable telle quelle,
    convertie en liste. Si ``names`` est fourni, ajoute ``endpoints_labels``
    (noms logiques resolus) a cote des ``endpoints`` bruts."""
    endpoints = list(flow.endpoints) if flow.endpoints is not None else None
    doc = {
        "key": list(flow.key),
        "endpoints": endpoints,
        "points": list(flow.points),
        "packet_count": dict(flow.packet_count),
        "byte_count": dict(flow.byte_count),
        "first_ts": dict(flow.first_ts),
        "last_ts": dict(flow.last_ts),
    }
    if names is not None and endpoints is not None:
        doc["endpoints_labels"] = [names.display(a) for a in endpoints]
    logger.debug("_flow_dict: retour doc={}", summarize(doc, "doc"))
    return doc


def _conversation_dict(conv, names=None) -> dict:
    """Serialise une Conversation (netcross_core.expert_model, Session 36).
    Si ``names`` est fourni, ajoute ``endpoints_labels`` (noms logiques
    resolus) a cote des ``endpoints`` bruts."""
    endpoints = list(conv.endpoints)
    doc = {
        "endpoints": endpoints,
        "flow_keys": [list(k) for k in conv.flow_keys],
        "packet_count": conv.packet_count,
        "byte_count": conv.byte_count,
    }
    if names is not None:
        doc["endpoints_labels"] = [names.display(a) for a in endpoints]
    logger.debug("_conversation_dict: retour doc={}", summarize(doc, "doc"))
    return doc


def _expert_event_dict(ev) -> dict:
    """Serialise un ExpertEvent (netcross_core.expert_model, Session 36) --
    cause/impact toujours None dans cette passe (voir docstring de
    expert_model.py, moteur de causalite absent), exposes tels quels
    plutot que masques : un consommateur externe doit pouvoir constater
    lui-meme qu'ils ne sont pas encore renseignes. source (ajoute avec
    netcross_core.wireshark_expert) : "netcross" pour un evenement issu
    d'un Finding/DiffFinding deja diagnostique, "tshark" pour un signal
    brut du moteur de dissection tshark -- voir expert_model.ExpertEvent.
    confidence/first_seen/last_seen (Session 40, premier lot de la
    Session 2 de FEATURES.md section 13.3) : toujours None cote
    "netcross" a ce jour, exposes tels quels comme cause/impact plutot
    que masques -- meme raisonnement, voir expert_model.ExpertEvent.
    layer/protocol (Session 41, deuxieme lot de la Session 2) : meme
    convention -- toujours None cote "netcross", exposes tels quels.
    flow_keys (Session 43, troisieme lot de la Session 2) : meme
    convention que Conversation.flow_keys ci-dessus (tuples convertis en
    listes pour rester serialisables JSON) -- toujours [] cote
    "netcross". packet_evidence (Session 44, quatrieme lot de la
    Session 2) : liste COMPLETE de PacketEvidence (tous les numeros de
    trame, pas seulement ceux des _MAX_EXAMPLES exemples deja portes par
    "evidence" ci-dessus) -- meme format point/frame_number que la cle
    frame_number optionnelle de _evidence_list_dict, toujours [] cote
    "netcross". remediation (Session 45, cinquieme et dernier lot de la
    Session 2) : piste de verification textuelle REDIGEE (pas calculee),
    disponible uniquement pour les onze flags tshark deja connus de
    netcross_core.wireshark_expert._KNOWN_FLAGS -- None pour tout autre
    flag ET toujours None cote "netcross" (voir expert_model.ExpertEvent
    pour le detail complet). rule_id (Session 48) : miroir exact de
    remediation ci-dessus mais dans l'autre sens -- expose tel quel comme
    cause/impact, renseigne UNIQUEMENT cote "netcross" (recopie de
    Finding.rule_id quand le Finding source correspond a une regle du
    catalogue netcross_core.expert_rules), toujours None cote "tshark"
    (voir expert_model.ExpertEvent pour le detail complet)."""
    logger.debug("_expert_event_dict: retour dictionnaire")
    return {
        "category": ev.category,
        "severity": ev.severity,
        "segment": ev.segment,
        "message": ev.message,
        "evidence": _evidence_list_dict(ev.evidence),
        "cause": ev.cause,
        "impact": ev.impact,
        "source": ev.source,
        "confidence": ev.confidence,
        "first_seen": ev.first_seen,
        "last_seen": ev.last_seen,
        "layer": ev.layer,
        "protocol": ev.protocol,
        "flow_keys": [list(k) for k in ev.flow_keys],
        "packet_evidence": [{"point": pe.point, "frame_number": pe.frame_number} for pe in ev.packet_evidence],
        "remediation": ev.remediation,
        "rule_id": ev.rule_id,
    }


def _diagnosis_dict(diag) -> dict:
    """Serialise un Diagnosis (netcross_core.expert_model, Session 36) --
    meme raisonnement que _expert_event_dict pour cause/impact."""
    logger.debug("_diagnosis_dict: retour dictionnaire")
    return {
        "segment": diag.segment,
        "events": [_expert_event_dict(ev) for ev in diag.events],
        "cause": diag.cause,
        "impact": diag.impact,
    }


def _compliance_dict(result) -> dict:
    """Serialise un ComplianceResult (netcross_core.expert_model,
    Session 36)."""
    logger.debug("_compliance_dict: retour dictionnaire")
    return {
        "reference": {
            "id": result.reference.id,
            "metric": result.reference.metric,
            "operator": result.reference.operator,
            "threshold": result.reference.threshold,
            "unit": result.reference.unit,
            "source": result.reference.source,
        },
        "observed": result.observed,
        "status": result.status,
    }


def _path_segment_dict(m) -> dict:
    """Un ``SegmentMetrics`` (path_metrics) en dict JSON (issue #1075).

    Toutes les metriques du segment, plus ``segment`` (meme libelle que les
    constats, pour les rapprocher) et ``measured`` : un segment non
    mesurable reste dans la liste, ses valeurs inconnues a ``None``.
    """
    logger.debug("_path_segment_dict: entrée ({})", m.label)
    d = dataclasses.asdict(m)
    d["segment"] = m.label
    d["measured"] = m.measured
    d["latency_measurable"] = m.latency_measurable
    logger.debug("_path_segment_dict: retour dict")
    return d


def _segment_score_dict(s) -> dict:
    """Le detail des findings du segment n'est pas re-imbrique ici : ils
    sont deja tous presents dans la liste "findings" de premier niveau
    (voir generate_json_report/generate_json_diff) -- seul le compte est
    donne, pour eviter une duplication complete de l'arbre. low_confidence :
    voir netcross_report.triage.rank_segments (echantillon(s) faible(s)
    derriere les findings qui pesent dans le score de ce segment)."""
    logger.debug("_segment_score_dict: retour dictionnaire")
    return {
        "segment": s.segment,
        "score": s.score,
        "categories": list(s.categories),
        "convergent": s.convergent,
        "low_confidence": s.low_confidence,
        "finding_count": len(s.findings),
    }


def _now_iso() -> str:
    logger.debug("_now_iso: retour datetime.datetime.now().astimezone().is…(…)")
    return datetime.datetime.now().astimezone().isoformat()


def _write(doc: dict, output_path) -> str:
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
    logger.debug("_write: retour output_path={}", summarize(output_path, "output_path"))
    return output_path


def build_json_report_document(
    r,
    title="Analyse croisee de captures reseau",
    meta=None,
    findings=None,
    tls_findings=None,
    quic_findings=None,
    flows=None,
    conversations=None,
    expert_events=None,
    diagnoses=None,
    compliance=None,
    wireshark_expert_events=None,
    rule_engine_findings=None,
    names=None,
    security_report=None,
    packet_flows=None,
    sequence_budget_octets=None,
    evidence_pcaps=None,
    redaction=None,
) -> dict:
    """
    Document de ``--json-report``, sans l'ecrire : servi tel quel par
    ``GET /analyses/{id}/report`` de l'API (issue #330), pour qu'une meme
    capture donne les memes constats, triage et score de sante quelle que
    soit la surface. ``generate_json_report()`` l'ecrit dans un fichier.

    r : objet Report (netcross_core.analyse). meta : dict optionnel de metadonnees libres (ex:
    {"Ticket": "INC-1234", "Auteur": "Mathilde"}), reporte tel quel.
    findings : liste de Finding deja calculee (synthesis.build_findings(r))
    si l'appelant l'a deja fait (evite un recalcul) ; sinon calculee ici --
    meme convention que generate_pdf().
    tls_findings / quic_findings : listes de TlsFinding optionnelles ;
    si fournies, integrees au triage (meme melange que generate_pdf) et
    exposees chacune dans leur propre cle de premier niveau.

    flows / conversations / expert_events / diagnoses / compliance
    (Session 36, objets de contrat de la Session 0, FEATURES.md
    section 13.3) : listes optionnelles deja construites par l'appelant
    (netcross_core.correlate.build_flows()/build_conversations(),
    netcross_report.build_expert_events()/build_diagnoses(),
    netcross_core.compliance.evaluate_compliance()) -- memes conventions
    que tls_findings/quic_findings ci-dessus : absentes (None) -> cle
    JSON absente, jamais recalculees ici.

    wireshark_expert_events (Session 1, netcross_core.wireshark_expert.
    build_wireshark_expert_events()) : liste optionnelle d'ExpertEvent de
    source "tshark" -- signaux d'expertise BRUTS du moteur de dissection
    tshark, jamais fondus dans "expert_events" ci-dessus (qui ne porte
    que des ExpertEvent de source "netcross", issus de Finding/
    DiffFinding deja diagnostiques) : cle JSON de premier niveau
    distincte, meme convention d'absence que les autres objets Session 0.

    packet_flows (issue #1077) : correlation brute de ``correlate()`` (cle
    de paquet -> {point: [Pkt]}), a ne pas confondre avec ``flows``
    ci-dessus. Si fournie, la cle ``evidence_frames`` decrit chaque preuve
    des constats vue a chaque point (``netcross_report.evidence_frames``) ;
    les cles ``sequence_diagrams`` (flux principaux NON TRONQUES,
    echantillonnes au-dela d'un budget de poids, issue #1079) et ``comm_map``
    (carte des communications, issue #909) en sont deduitees ; absentes sinon.

    evidence_pcaps (issue #1081) : liste produite par
    ``netcross_core.extract.evidence_pcaps.extraire_preuves_pcaps()``
    (une entree par preuve, ``ref``/``point``/``frame_number``/
    ``fichier``), reportee telle quelle sous la cle ``evidence_pcaps``
    pour que le HTML reference les extraits par des liens relatifs ;
    absente sinon (rien n'est extrait par ce module).
    """
    logger.debug(
        "build_json_report_document: r={} title={} meta={} findings={} tls_findings={} "
        "quic_findings={} flows={} conversations={} expert_events={} diagnoses={} compliance={} "
        "wireshark_expert_events={} rule_engine_findings={} names={} security_report={} "
        "redaction={}",
        summarize(r, "r"),
        summarize(title, "title"),
        summarize(meta, "meta"),
        summarize(findings, "findings"),
        summarize(tls_findings, "tls_findings"),
        summarize(quic_findings, "quic_findings"),
        summarize(flows, "flows"),
        summarize(conversations, "conversations"),
        summarize(expert_events, "expert_events"),
        summarize(diagnoses, "diagnoses"),
        summarize(compliance, "compliance"),
        summarize(wireshark_expert_events, "wireshark_expert_events"),
        summarize(rule_engine_findings, "rule_engine_findings"),
        summarize(names, "names"),
        summarize(security_report, "security_report"),
        summarize(redaction, "redaction"),
    )
    if findings is None:
        findings = build_findings(r)
    ranked = rank_segments(list(findings) + list(tls_findings or []) + list(quic_findings or []))
    score = health_score(ranked)

    doc = {
        "title": title,
        "generated_at": _now_iso(),
        "points": list(r.points),
        "active_confirmation": getattr(r, "active_confirmation", None),
        "pairs": [list(p) for p in r.pairs],
        # Issue #996 : estimation d'horloge par paire -- decalage a t0,
        # derive (ppm), intervalles 95 %, echantillons et methode ; les
        # latences du rapport sont DEJA corrigees (par paquet), ces
        # valeurs permettent d'auditer la correction. Issue #1103 : quand
        # les sondes ont annonce leur horloge (--sonde-meta), l'annonce
        # accompagne l'estimation pour la confronter.
        "clock_offsets": [
            {
                "pair": [a, b],
                "offset_ms": est.decalage_ms,
                "t0": est.t0,
                "drift_ppm": est.derive_ppm,
                "ci_offset_ms": est.ic_decalage_ms,
                "ci_drift_ppm": est.ic_derive_ppm,
                "samples": est.n_echantillons,
                "kept": est.n_conserves,
                "method": est.methode,
                "sources": list(est.sources),
                "forced": est.manuel,
                "annonce": {
                    point: _horloge_annoncee(r, point) for point in (a, b) if _horloge_annoncee(r, point) is not None
                },
            }
            for (a, b), est in r.clock_offset_estimate.items()
        ],
        # Issue #1075 : metriques par segment, dans l'ordre du chemin deduit
        # (netcross_report.path_metrics, memes chiffres que le PDF) -- lues
        # par la vue « Chemin » du rapport HTML. Toujours presente (liste
        # vide sans paire de points).
        "path_metrics": [_path_segment_dict(m) for m in build_path_metrics(r)],
        "meta": dict(meta) if meta else {},
        # Issue #1159 : encart « Anonymisation » -- certifie le périmètre
        # appliqué (portée, compteurs, pcapng, table). Absent sans --redact.
        "redaction": dict(redaction) if redaction else None,
        "findings": [_finding_dict(f) for f in findings],
        "microbursts": r.microbursts,
        "microburst_correlations": r.microburst_correlations,
        "link_speeds": r.link_speeds,
        "triage": [_segment_score_dict(s) for s in ranked],
        # health_score/health_label : voir netcross_report.triage --
        # derives de "triage" ci-dessus (jamais un calcul independant), la
        # cle courte (health_label, meme vocabulaire que severity/category)
        # plutot que le libelle affichable (HEALTH_LABELS) pour rester
        # stable cote consommateur externe (dashboard/ticketing/CI) --
        # a lui de choisir sa propre traduction/presentation.
        "health_score": score,
        "health_label": health_label(score),
        "http_objects": list(getattr(r, "http_objects", [])),
        # SCENARIO-4 (#150) : fichiers extraits (HTTP, email, SMB, FTP) --
        # rempli par `netcross_core.analysis.analyse` via
        # `extract.carver.detect_extracted_files`, mais inerte sans cette
        # exposition (issue #349 : un executable PE telecharge en HTTP etait
        # invisible jusqu'ici). Toujours present (liste vide = rien trouve),
        # meme convention que http_objects.
        "extracted_files": list(getattr(r, "extracted_files", [])),
        # Issue #350 : inventaire d'actifs -- toujours present (liste
        # vide = rien trouve), meme convention que http_objects.
        "asset_inventory": list(getattr(r, "asset_inventory", [])),
        # flow_anomalies et lateral_movement_events : meme convention.
        "flow_anomalies": list(getattr(r, "flow_anomalies", [])),
        "lateral_movement_events": list(getattr(r, "lateral_movement_events", [])),
    }
    # Issue #1043 : couverture du dechiffrement TLS/QUIC par point -- cle
    # absente si aucun point n'a de cle ni de session dechiffree.
    # Correlation en flux (#1022) : posee par la CLI avec --streaming.
    if getattr(r, "streaming", None):
        doc["streaming"] = r.streaming
    # Issue #1103 : métadonnées de sonde par point (pertes DÉCLARÉES,
    # horloge ANNONCÉE) -- à distinguer des pertes réseau estimées. Clés
    # absentes sans --sonde-meta (convention « section absente si la
    # fonctionnalité n'a pas tourné »).
    pertes_sondes = getattr(r, "pertes_sondes", None)
    horloges_sondes = getattr(r, "horloges_sondes", None)
    if pertes_sondes or horloges_sondes:
        doc["sondes"] = {
            "capture_loss": dict(pertes_sondes or {}),
            "clock": dict(horloges_sondes or {}),
        }
    decryption = document_json(r)
    if decryption:
        doc["decryption"] = {"by_point": decryption}
    if getattr(r, "duplicate_count", None):
        # Job 41/issue #161 : cle absente si la detection n'a rien trouve
        # (meme convention que voip_calls ci-dessous).
        doc["duplicates"] = {
            "excluded": bool(getattr(r, "duplicates_excluded", False)),
            "by_pair": [{"points": list(pair), "count": count} for pair, count in sorted(r.duplicate_count.items())],
        }
    # issue #329 : chaque détection doit apparaître dans le rapport JSON.
    # Cles dedicatées pour les consommateurs machine (en plus de security_findings).
    if getattr(r, "exfiltration_alerts", None):
        doc["exfiltration_alerts"] = list(r.exfiltration_alerts)
    if getattr(r, "sequence_gaps", None):
        doc["sequence_gaps"] = [
            {
                "point": g.point,
                "src": g.src,
                "sport": g.sport,
                "dst": g.dst,
                "dport": g.dport,
                "start_seq": g.start_seq,
                "end_seq": g.end_seq,
                "missing_bytes": g.missing_bytes,
                "ts": g.ts,
                "frame_number": g.frame_number,
                "cause": g.cause,
                "evidence": g.evidence,
            }
            for g in r.sequence_gaps
        ]
    # Job 43/issue #163 (rebranche par #667) : checksums IP/TCP/UDP invalides,
    # toujours presents (liste vide si aucune erreur).
    doc["checksum_errors"] = [
        {"point": e.point, "frame_number": e.frame_number, "protocol": e.protocol, "checksum": e.checksum}
        for e in (getattr(r, "checksum_errors", None) or [])
    ]
    # #1121 : jambes d'un meme flux RTP a plusieurs points (NAT/SBC).
    if getattr(r, "rtp_matches", None):
        doc["rtp_matches"] = list(r.rtp_matches)
    if getattr(r, "rtp_segments", None):
        doc["rtp_segments"] = list(r.rtp_segments)
    if getattr(r, "voip_calls", None):
        doc["voip_calls"] = list(r.voip_calls)
        doc["voip_quality_distribution"] = dict(r.voip_quality_distribution)
    # Echelle SIP multi-points (issue #1125), omise sans SIP.
    if getattr(r, "sip_ladders", None):
        doc["sip_ladders"] = list(r.sip_ladders)
    if tls_findings is not None:
        doc["tls_findings"] = [_finding_dict(f) for f in tls_findings]
    if quic_findings is not None:
        doc["quic_findings"] = [_finding_dict(f) for f in quic_findings]
    if flows is not None:
        doc["flows"] = [_flow_dict(f, names) for f in flows]
    if conversations is not None:
        doc["conversations"] = [_conversation_dict(c, names) for c in conversations]
    if expert_events is not None:
        doc["expert_events"] = [_expert_event_dict(ev) for ev in expert_events]
    if diagnoses is not None:
        doc["diagnoses"] = [_diagnosis_dict(d) for d in diagnoses]
    if compliance is not None:
        doc["compliance"] = [_compliance_dict(c) for c in compliance]
    if wireshark_expert_events is not None:
        doc["wireshark_expert_events"] = [_expert_event_dict(ev) for ev in wireshark_expert_events]
    # security_report (issue #218) : SecurityReport optionnel
    # (netcross_report.security_report.build_security_report). La cle est
    # ecrite DANS LES DEUX CAS -- avec la raison de l'absence quand il n'y
    # en a pas. Un consommateur doit pouvoir distinguer "pas de rapport de
    # securite demande" de "rapport demande, rien trouve" et de "version de
    # netcross qui ne produit pas cette cle" ; omettre la cle rendrait ces
    # trois situations identiques. Meme regle de tracabilite que le rendu
    # texte, qui ecrit ses sections vides.
    if security_report is not None:
        from netcross_report.security_report import security_report_to_dict

        doc["security_report"] = security_report_to_dict(security_report)
    else:
        doc["security_report"] = None
        doc["security_report_absent"] = "non demande (--security-report absent de l'appel)"
    if rule_engine_findings is not None:
        doc["rule_engine"] = {
            rule_id: [_finding_dict(f) for f in rule_list]
            for rule_id, rule_list in rule_engine_findings.items()
            if rule_list  # omet les regles sans Finding (liste vide)
        }
    if packet_flows is not None:
        from netcross_report.evidence_frames import build_evidence_frames
        from netcross_report.sequence_diagrams import (
            BUDGET_DONNEES_DEFAUT,
            build_comm_map_dict,
            build_sequence_diagrams,
        )

        doc["evidence_frames"] = build_evidence_frames(
            doc["findings"], packet_flows, list(r.points), getattr(r, "clock_offset_estimate", None)
        )
        # Diagrammes de sequence non tronques + carte des communications
        # (issue #1079) : meme correlation, meme document, une seule
        # source de verite pour les trois surfaces.
        doc["sequence_diagrams"] = build_sequence_diagrams(
            packet_flows, budget_octets=sequence_budget_octets or BUDGET_DONNEES_DEFAUT
        )
        doc["comm_map"] = build_comm_map_dict(packet_flows)

    # Extraits pcap de preuve par constat (issue #1081) : liste produite par
    # netcross_core.extract.evidence_pcaps.extraire_preuves_pcaps(), pas
    # calculee ici -- netcross_report ne relit pas les fichiers de capture.
    if evidence_pcaps:
        doc["evidence_pcaps"] = evidence_pcaps

    logger.debug("build_json_report_document: retour doc={}", summarize(doc, "doc"))
    return doc


def generate_json_report(r, output_path, title="Analyse croisee de captures reseau", **kwargs) -> str:
    """Ecrit dans ``output_path`` le document de ``build_json_report_document()``
    (memes arguments nommes : meta, findings, tls_findings...) et retourne
    le chemin."""
    logger.debug("generate_json_report: output_path={}", summarize(output_path, "output_path"))
    doc = build_json_report_document(r, title=title, **kwargs)
    logger.debug("generate_json_report: retour _write(…)")
    return _write(doc, output_path)


def generate_json_diff(
    findings,
    baseline,
    current,
    output_path,
    title="Comparaison avant / apres",
    meta=None,
    tls_findings_baseline=None,
    tls_findings_current=None,
    quic_findings_baseline=None,
    quic_findings_current=None,
    flows=None,
    conversations=None,
    expert_events=None,
    diagnoses=None,
    compliance=None,
    wireshark_expert_events=None,
    names=None,
) -> str:
    """
    Pendant de generate_diff_pdf() : findings est la liste de DiffFinding
    (baseline_diff.diff_reports()), baseline/current les deux Report
    compares (uniquement pour lister leurs points respectifs).

    tls_findings_baseline/current, quic_findings_baseline/current :
    memes listes optionnelles que generate_diff_pdf, exposees chacune
    dans leur propre cle -- **volontairement pas fondues** dans
    "findings"/"triage" ci-dessus, meme raison que dans generate_diff_pdf
    (vocabulaire de severite different, TLS/QUIC ne connaissent qu'un
    etat a un instant donne, pas une paire avant/apres -- voir
    netcross_report/pdf.py et claude.md Session 8 pour la discussion
    complete).

    flows / conversations / expert_events / diagnoses / compliance
    (Session 37, parite avec generate_json_report -- Session 36) :
    listes optionnelles construites par l'appelant sur le rapport
    COURANT UNIQUEMENT, jamais le baseline -- meme decision que
    `DiffFinding.evidence` (Session 33) : c'est l'etat qu'on evalue
    MAINTENANT qui a besoin de ces vues analytiques, un flux/une
    conformite historique du baseline n'apporterait pas la meme valeur
    diagnostique (et doublerait la taille du document pour un usage
    marginal). Absentes (None) -> cle JSON absente, jamais recalculees ici.

    wireshark_expert_events (Session 1, netcross_core.wireshark_expert.
    build_wireshark_expert_events()) : meme convention que sur
    generate_json_report() ci-dessus -- signaux d'expertise BRUTS tshark,
    toujours cote rapport COURANT uniquement (meme raisonnement que
    flows/conversations/expert_events/diagnoses/compliance ci-dessus),
    cle JSON distincte de "expert_events" (qui ne porte que des
    ExpertEvent de source "netcross").
    """
    logger.debug(
        "generate_json_diff: findings={} baseline={} current={} output_path={} title={} meta={} "
        "tls_findings_baseline={} tls_findings_current={} quic_findings_baseline={} "
        "quic_findings_current={} flows={} conversations={} expert_events={} diagnoses={} "
        "compliance={} wireshark_expert_events={} names={}",
        summarize(findings, "findings"),
        summarize(baseline, "baseline"),
        summarize(current, "current"),
        summarize(output_path, "output_path"),
        summarize(title, "title"),
        summarize(meta, "meta"),
        summarize(tls_findings_baseline, "tls_findings_baseline"),
        summarize(tls_findings_current, "tls_findings_current"),
        summarize(quic_findings_baseline, "quic_findings_baseline"),
        summarize(quic_findings_current, "quic_findings_current"),
        summarize(flows, "flows"),
        summarize(conversations, "conversations"),
        summarize(expert_events, "expert_events"),
        summarize(diagnoses, "diagnoses"),
        summarize(compliance, "compliance"),
        summarize(wireshark_expert_events, "wireshark_expert_events"),
        summarize(names, "names"),
    )
    ranked = rank_segments(findings)
    score = health_score(ranked)

    doc = {
        "title": title,
        "generated_at": _now_iso(),
        "baseline_points": list(baseline.points),
        "current_points": list(current.points),
        "meta": dict(meta) if meta else {},
        "findings": [_finding_dict(f) for f in findings],
        "triage": [_segment_score_dict(s) for s in ranked],
        # health_score/health_label : sur un diff, reflete l'ampleur des
        # regressions detectees (100 = aucune regression significative),
        # pas un etat absolu -- voir netcross_report.triage.health_score.
        "health_score": score,
        "health_label": health_label(score),
    }
    if tls_findings_baseline is not None:
        doc["tls_findings_baseline"] = [_finding_dict(f) for f in tls_findings_baseline]
    if tls_findings_current is not None:
        doc["tls_findings_current"] = [_finding_dict(f) for f in tls_findings_current]
    if quic_findings_baseline is not None:
        doc["quic_findings_baseline"] = [_finding_dict(f) for f in quic_findings_baseline]
    if quic_findings_current is not None:
        doc["quic_findings_current"] = [_finding_dict(f) for f in quic_findings_current]
    if flows is not None:
        doc["flows"] = [_flow_dict(f, names) for f in flows]
    if conversations is not None:
        doc["conversations"] = [_conversation_dict(c, names) for c in conversations]
    if expert_events is not None:
        doc["expert_events"] = [_expert_event_dict(ev) for ev in expert_events]
    if diagnoses is not None:
        doc["diagnoses"] = [_diagnosis_dict(d) for d in diagnoses]
    if compliance is not None:
        doc["compliance"] = [_compliance_dict(c) for c in compliance]
    if wireshark_expert_events is not None:
        doc["wireshark_expert_events"] = [_expert_event_dict(ev) for ev in wireshark_expert_events]

    logger.debug("generate_json_diff: retour _write(…)")
    return _write(doc, output_path)
