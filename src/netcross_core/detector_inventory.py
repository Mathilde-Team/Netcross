"""Inventaire des détecteurs et de leur besoin de vue globale (issue #1020, chantier #995).

Avant de passer le pipeline en flux (#995 : fenêtre glissante #1022, état
par flux avec expiration #1023, débordement sur disque #1024, seconde passe
ciblée #1025), chaque détecteur est classé selon ce qu'il doit garder en
mémoire pour décider :

- ``incremental`` : une seule passe, état indépendant du nombre de paquets
  (compteurs, agrégats par point / clé / tranche de temps, éventuellement
  finalisés en fin de capture). Compatible tel quel avec un pipeline en flux ;
- ``fenetre_bornee`` : doit rapprocher des paquets (copies d'un même paquet
  à plusieurs points, requête et réponse, messages d'une transaction) ;
  l'état par clé peut être expiré une fois la fenêtre écoulée. Relève de la
  fenêtre glissante (#1022) et de l'expiration par flux (#1023) ;
- ``seconde_passe`` : la décision dépend de la capture entière (topologie,
  vue globale fournie aux greffons) ou relit les fichiers avec tshark ;
  relève de la seconde passe ciblée (#1025).

L'inventaire est déclaratif ; ``tests/test_detector_inventory.py`` vérifie
qu'aucune phase de :func:`netcross_core.analysis.analyse` ni aucun
détecteur de signatures enregistré n'y manque, que les champs du rapport
cités existent, et que le tableau de ``docs/detectors.md`` est à jour
(:func:`tableau_markdown`).
"""

from __future__ import annotations

from dataclasses import dataclass

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

INCREMENTAL = "incremental"
FENETRE_BORNEE = "fenetre_bornee"
SECONDE_PASSE = "seconde_passe"
CLASSES = (INCREMENTAL, FENETRE_BORNEE, SECONDE_PASSE)

# Provenance d'un détecteur : phase nommée de analyse() (``with _phase(...)``),
# bloc en ligne de analyse(), registre des signatures d'exploits, détecteurs
# de security.findings.apply_security_findings (--security-report), diagnostic
# lancé par la CLI après analyse(), greffons.
PHASE = "phase"
EN_LIGNE = "en_ligne"
SIGNATURE = "signature"
SECURITE = "securite"
DIAGNOSTIC = "diagnostic"
GREFFON = "greffon"
PROVENANCES = (PHASE, EN_LIGNE, SIGNATURE, SECURITE, DIAGNOSTIC, GREFFON)

DEBUT_TABLEAU = "<!-- inventaire-detecteurs:debut (généré par netcross_core.detector_inventory) -->"
FIN_TABLEAU = "<!-- inventaire-detecteurs:fin -->"


@dataclass(frozen=True)
class Detecteur:
    """Une entrée de l'inventaire."""

    nom: str
    provenance: str
    classe: str
    etat: str
    fenetre: str
    champs: tuple[str, ...] = ()
    note: str = ""


DETECTEURS: tuple[Detecteur, ...] = (
    # -- phases nommées de analyse(), dans l'ordre d'exécution ------------------
    Detecteur(
        "infer_topology",
        PHASE,
        SECONDE_PASSE,
        "écarts de TTL et ensembles de flux vus par paire de points",
        "capture entière",
        ("topology_edges",),
        "recouvrement de Jaccard entre ensembles complets ; sans objet avec --order",
    ),
    Detecteur(
        "compute_throughput",
        PHASE,
        INCREMENTAL,
        "octets par (point, tranche)",
        "aucune",
        ("throughput",),
    ),
    Detecteur(
        "detect_extracted_files",
        PHASE,
        FENETRE_BORNEE,
        "charges utiles en cours de réassemblage par flux",
        "durée du transfert de l'objet",
        ("extracted_files",),
    ),
    Detecteur(
        "application_transactions",
        PHASE,
        FENETRE_BORNEE,
        "requêtes HTTP/DNS en attente de réponse",
        "seuil de réponse du protocole ; « réponse manquante » décidée à l'expiration",
        ("application_transactions",),
    ),
    Detecteur(
        "pmtud",
        PHASE,
        FENETRE_BORNEE,
        "segments retransmis en amont, par flux ; drapeau « ICMP trop grand vu » par point",
        "durée des retransmissions d'un segment",
        ("pmtud_blackhole",),
        "l'absence d'ICMP « sur toute la capture » est un drapeau par point, finalisé en fin de capture",
    ),
    Detecteur(
        "idle_timeout",
        PHASE,
        FENETRE_BORNEE,
        "plus long silence et reprise par connexion TCP (5-tuple orienté)",
        "vie de la connexion, potentiellement toute la capture",
        ("idle_timeout_dropped",),
        "connexions longues : candidat au débordement sur disque (#1024)",
    ),
    Detecteur(
        "arp_ip_conflict",
        PHASE,
        INCREMENTAL,
        "adresses MAC revendiquées par IP, par point",
        "aucune",
        ("arp_ip_conflict",),
    ),
    Detecteur(
        "stp_instability",
        PHASE,
        INCREMENTAL,
        "compteurs TCN/TC et ponts racines vus, par point",
        "aucune",
        ("stp_topology_change", "stp_root_change"),
    ),
    Detecteur(
        "tls_certificate",
        PHASE,
        FENETRE_BORNEE,
        "numéro de série du certificat par connexion et par point",
        "latence entre points adjacents",
        ("tls_cert_invalid_dates", "tls_cert_mismatch"),
        "dates invalides : par paquet ; substitution : comparaison entre points",
    ),
    Detecteur(
        "tls_handshake",
        PHASE,
        FENETRE_BORNEE,
        "ClientHello en attente de ServerHello par (IP, port)",
        "délai de poignée de main",
        ("tls_handshake_incomplete", "tls_handshake_no_reply"),
    ),
    Detecteur(
        "retransmission_types",
        PHASE,
        INCREMENTAL,
        "compteurs par point (drapeaux tcp.analysis de tshark)",
        "aucune",
        ("retrans_fast", "retrans_rto", "retrans_spurious"),
    ),
    Detecteur(
        "tcp_expert_signals",
        PHASE,
        INCREMENTAL,
        "compteurs par point (drapeaux tcp.analysis de tshark)",
        "aucune",
        ("out_of_order", "lost_segment", "window_update"),
    ),
    Detecteur(
        "detect_sequence_gaps",
        PHASE,
        FENETRE_BORNEE,
        "trous de séquence ouverts par flux orienté et par point",
        "réordonnancement ; trou « jamais comblé » décidé en fin de flux",
        ("sequence_gaps",),
        "aujourd'hui tri des paquets de chaque flux : à remplacer par un suivi des trous ouverts",
    ),
    Detecteur(
        "validate_checksums",
        PHASE,
        INCREMENTAL,
        "aucun (vérification paquet par paquet)",
        "aucune",
        ("checksum_errors",),
    ),
    Detecteur(
        "apply_expert_correlation",
        PHASE,
        FENETRE_BORNEE,
        "alertes Expert Info horodatées par flux et par hôte",
        "fenêtres des seuils de fuzzing / débordement / DoS",
        ("expert_malformed", "exploit_suspicion"),
        "seuls les paquets en anomalie sont retenus",
    ),
    Detecteur(
        "saturation",
        PHASE,
        INCREMENTAL,
        "aucun paquet : débit par tranche et pertes déjà agrégés",
        "aucune",
        ("saturation_verdict",),
        "aval du rapport agrégé",
    ),
    Detecteur(
        "bufferbloat",
        PHASE,
        INCREMENTAL,
        "aucun paquet : latence par tranche et débit déjà agrégés",
        "aucune",
        ("bufferbloat_hint",),
        "aval du rapport agrégé",
    ),
    Detecteur(
        "handshake",
        PHASE,
        FENETRE_BORNEE,
        "SYN en attente de SYN-ACK, par point",
        "délai de connexion TCP (retransmissions du SYN comprises)",
        ("syn_no_synack", "syn_reply_missing", "clock_offset_estimate"),
        "fournit aussi l'estimation de décalage d'horloge utilisée par rtp",
    ),
    Detecteur(
        "tcp_options",
        PHASE,
        FENETRE_BORNEE,
        "options du SYN / SYN-ACK par point",
        "latence entre points adjacents",
        ("mss_clamped", "wscale_stripped", "sack_stripped"),
    ),
    Detecteur(
        "rtp",
        PHASE,
        INCREMENTAL,
        "par flux RTP (5-tuple + SSRC) et par point : dernière séquence, gigue, compteurs",
        "aucune",
        ("rtp_streams",),
        "le délai bout en bout dépend du décalage d'horloge estimé par handshake",
    ),
    Detecteur(
        "response_time",
        PHASE,
        FENETRE_BORNEE,
        "client de chaque connexion (SYN) et dernière requête en attente de réponse",
        "temps de réponse serveur ; client connu pendant la vie de la connexion",
        ("server_think_time",),
    ),
    Detecteur(
        "dhcp",
        PHASE,
        FENETRE_BORNEE,
        "messages par xid et par point",
        "durée d'une transaction DHCP",
        ("dhcp_missing", "dhcp_duration_ms"),
    ),
    Detecteur(
        "sip",
        PHASE,
        FENETRE_BORNEE,
        "messages par Call-ID et par point",
        "durée de l'appel",
        ("sip_missing", "sip_setup_duration_ms", "sip_failed_calls"),
    ),
    Detecteur(
        "build_calls",
        PHASE,
        FENETRE_BORNEE,
        "signalisation par Call-ID et résumés des flux RTP",
        "appel + 300 s après le dernier message SIP sans BYE",
        ("voip_calls",),
    ),
    Detecteur(
        "dns",
        PHASE,
        FENETRE_BORNEE,
        "requêtes par dns.id et par point",
        "délai de réponse DNS ; « sans réponse » décidé à l'expiration",
        ("dns_missing", "dns_timeout", "dns_duration_ms"),
    ),
    Detecteur(
        "http",
        PHASE,
        FENETRE_BORNEE,
        "requêtes HTTP/1.x en attente de réponse, par point",
        "délai de réponse HTTP ; « sans réponse » décidé à l'expiration",
        ("http_missing", "http_timeout", "http_response_time_ms"),
    ),
    Detecteur(
        "detect_exfiltration",
        PHASE,
        INCREMENTAL,
        "octets, protocoles et bornes temporelles par (point, source, destination)",
        "aucune",
        ("exfiltration_alerts",),
        "garde aussi la liste des numéros de trame par couple : à borner pour un état constant",
    ),
    # -- blocs en ligne de analyse() ---------------------------------------------
    Detecteur(
        "topn_timeseries",
        EN_LIGNE,
        INCREMENTAL,
        "octets par (point, catégorie, tranche)",
        "aucune",
        ("topn_timeseries",),
        "classement top-N en fin de capture ; état proportionnel au nombre de catégories",
    ),
    Detecteur(
        "http_objects",
        EN_LIGNE,
        FENETRE_BORNEE,
        "requêtes HTTP en attente par flux",
        "durée de la transaction",
        ("http_objects",),
    ),
    Detecteur(
        "order_consistency",
        EN_LIGNE,
        SECONDE_PASSE,
        "arêtes de topologie inférées",
        "capture entière (dépend de infer_topology)",
        ("topology_order_conflicts",),
    ),
    Detecteur(
        "vlan_encap_vus",
        EN_LIGNE,
        INCREMENTAL,
        "ensembles de VLAN et d'encapsulations par point",
        "aucune",
        ("vlan_seen", "encap_seen"),
    ),
    Detecteur(
        "compteurs_flux_par_point",
        EN_LIGNE,
        FENETRE_BORNEE,
        "copies de chaque segment (clé de flux) par point",
        "délai maximal entre deux copies d'un même segment (retransmission)",
        ("retrans", "dup_ack", "zero_window", "rst_count", "ttl_unstable", "rst_localized"),
        "rst_localized exige de savoir que le segment n'est vu qu'à un point",
    ),
    Detecteur(
        "pertes",
        EN_LIGNE,
        FENETRE_BORNEE,
        "clés vues en amont et pas encore en aval ; conversations vues par point",
        "latence maximale entre points + marge",
        ("loss_count", "off_path_count", "loss_event_buckets"),
        "la règle « hors chemin » (#352) demande l'état de conversation par point avec expiration (#1023)",
    ),
    Detecteur(
        "comparaison_paires",
        EN_LIGNE,
        FENETRE_BORNEE,
        "première copie de chaque clé à chaque point",
        "latence maximale entre points + marge",
        (
            "latency",
            "latency_by_bucket",
            "qos_change",
            "hop_delta",
            "qos_l2_remark",
            "qos_l3_remark",
            "vlan_change",
            "pcp_change",
            "vlan_tag_flip",
            "encap_change",
        ),
    ),
    Detecteur(
        "hop_delta_outliers",
        EN_LIGNE,
        INCREMENTAL,
        "histogramme des écarts de TTL par paire",
        "aucune",
        ("hop_delta_outliers",),
        "mode calculé en fin de capture sur l'histogramme (petit)",
    ),
    Detecteur(
        "fragmentation",
        EN_LIGNE,
        FENETRE_BORNEE,
        "état fragmenté / encapsulation par datagramme (src, dst, ip.id) et par point",
        "délai de réassemblage IP",
        ("icmpv6_too_big", "icmp_frag_needed", "frag_count", "frag_new", "encap_frag_correlated"),
        "compteurs ICMP : incrémentaux",
    ),
    # -- signatures d'exploits (netcross_core.exploit_signatures) -----------------
    *(
        Detecteur(
            nom,
            SIGNATURE,
            INCREMENTAL,
            "état de flux des signatures (_FlowState)",
            "aucune",
            (),
            "lecture dédiée des charges utiles de chaque fichier (security.findings.scan_capture_exploits)",
        )
        for nom in ("http2_rapid_reset", "rdp_bluekeep", "smb1_eternalblue", "tls_compression", "tls_heartbleed")
    ),
    # -- security.findings.apply_security_findings (--security-report) -------------
    # detect_exfiltration et detect_extracted_files y sont rappelés : voir les phases.
    Detecteur(
        "build_service_fingerprints",
        SECURITE,
        INCREMENTAL,
        "logiciels identifiés, dédupliqués par (point, hôte, port, logiciel, version)",
        "aucune",
        ("service_fingerprints",),
    ),
    Detecteur(
        "build_fingerprint_records",
        SECURITE,
        INCREMENTAL,
        "empreintes JA4/HASSH dédupliquées par (point, hôte, type, valeur)",
        "aucune",
        ("service_fingerprints",),
    ),
    Detecteur(
        "detect_protocol_mismatches",
        SECURITE,
        INCREMENTAL,
        "aucun (décision paquet par paquet)",
        "aucune",
        (),
        "la liste des cas croît avec le nombre d'occurrences",
    ),
    Detecteur(
        "count_protocol_mismatches",
        SECURITE,
        INCREMENTAL,
        "compteurs par protocole et description",
        "aucune",
        ("protocol_mismatches",),
    ),
    Detecteur(
        "detect_dga",
        SECURITE,
        INCREMENTAL,
        "score et compteurs de réponses NXDOMAIN par domaine",
        "aucune",
        (),
    ),
    Detecteur(
        "detect_fast_flux",
        SECURITE,
        FENETRE_BORNEE,
        "adresses A/AAAA horodatées par (point, nom)",
        "window_seconds des seuils fast flux",
        (),
    ),
    Detecteur(
        "detect_lateral_movement",
        SECURITE,
        FENETRE_BORNEE,
        "cibles et tentatives par source (scans de ports et d'hôtes, force brute, protocoles, connexions)",
        "fenêtres des seuils LateralMovementThresholds",
        (),
        "nouvelles connexions : comparaison à une base, incrémentale",
    ),
    Detecteur(
        "analyze_flow_stats",
        SECURITE,
        INCREMENTAL,
        "par couple (source, destination) : premières tailles (SPLT), distributions, entropie, régularité",
        "aucune",
        (),
        "garde aujourd'hui les paquets de chaque couple : à remplacer par des agrégats",
    ),
    Detecteur(
        "build_asset_inventory",
        SECURITE,
        INCREMENTAL,
        "fiche par hôte (adresses, ports, services, points)",
        "aucune",
        (),
    ),
    Detecteur(
        "detect_dns_tunneling",
        SECURITE,
        INCREMENTAL,
        "statistiques des requêtes par domaine parent",
        "aucune",
        (),
    ),
    Detecteur(
        "detect_beaconing",
        SECURITE,
        FENETRE_BORNEE,
        "série d'horodatages par couple (source, destination)",
        "durée d'observation d'une balise (plusieurs périodes)",
        (),
        "séries longues : candidat au débordement sur disque (#1024)",
    ),
    Detecteur(
        "audit_tls_certificates",
        SECURITE,
        INCREMENTAL,
        "certificats vus, dédupliqués",
        "aucune",
        (),
    ),
    Detecteur(
        "dns_tunnel_sources",
        SECURITE,
        INCREMENTAL,
        "(point, IP source) des requêtes vers les domaines suspects",
        "aucune",
        (),
    ),
    # -- diagnostics lancés par la CLI après analyse() ---------------------------------
    Detecteur(
        "tls_diagnostics",
        DIAGNOSTIC,
        SECONDE_PASSE,
        "événements TLS de chaque point",
        "capture entière",
        (),
        "--tls : relit les fichiers avec tshark (pipeline indépendant)",
    ),
    Detecteur(
        "quic_diagnostics",
        DIAGNOSTIC,
        SECONDE_PASSE,
        "paquets QUIC Initial de chaque point",
        "capture entière",
        (),
        "--quic : relit les fichiers avec tshark",
    ),
    # -- greffons -------------------------------------------------------------------
    Detecteur(
        "greffons",
        GREFFON,
        SECONDE_PASSE,
        "DetectorContext : tous les paquets et le rapport, en lecture seule",
        "capture entière",
        (),
        "contrat de netcross_core.plugins.api ; un mode en flux devra proposer un contrat incrémental",
    ),
)


def par_nom() -> dict[str, Detecteur]:
    """Inventaire indexé par nom."""
    logger.debug("par_nom: entrée")
    index = {d.nom: d for d in DETECTEURS}
    logger.debug("par_nom: retour")
    return index


def classe_de(nom: str) -> str:
    """Classe déclarée du détecteur ``nom`` ; ``KeyError`` s'il n'est pas inventorié."""
    logger.debug("classe_de: entrée")
    classe = par_nom()[nom].classe
    logger.debug("classe_de: retour")
    return classe


def tableau_markdown() -> str:
    """Tableau publié dans ``docs/detectors.md`` (entre les marqueurs), plus le décompte par classe."""
    logger.debug("tableau_markdown: entrée")
    lignes = [
        DEBUT_TABLEAU,
        "",
        "| Détecteur | Provenance | Classe | État conservé | Fenêtre | Champs du rapport | Note |",
        "|---|---|---|---|---|---|---|",
    ]
    for d in DETECTEURS:
        champs = ", ".join(f"`{c}`" for c in d.champs)
        lignes.append(f"| `{d.nom}` | {d.provenance} | {d.classe} | {d.etat} | {d.fenetre} | {champs} | {d.note} |")
    decompte = {c: sum(1 for d in DETECTEURS if d.classe == c) for c in CLASSES}
    lignes += [
        "",
        f"Total : {len(DETECTEURS)} détecteurs -- " + ", ".join(f"{c} : {n}" for c, n in decompte.items()) + ".",
        "",
        FIN_TABLEAU,
    ]
    logger.debug("tableau_markdown: retour")
    return "\n".join(lignes)
