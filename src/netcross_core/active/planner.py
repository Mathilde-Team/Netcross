"""
netcross_core.active.planner -- planificateur « constat localise -> mesure
active proposee » (issue #1063, sous-issue 1/5 du chantier #999).

Pour chaque constat (`ExpertEvent`) LOCALISE et ELIGIBLE, le planificateur
propose la mesure active qui permettrait de passer de « le probleme est sur
ce segment » a « le probleme est sur ce saut », ciblee sur le flux EXACT
designe par le diagnostic passif (memes adresses, ports et protocole, donc
meme chemin ECMP -- principe du traceroute a la Paris).

Module PUR : aucune emission reseau, aucun socket, aucun sous-processus,
aucune resolution DNS. Il ne fait que produire des `ProposedMeasurement`
(donnees), que d'autres modules executeront plus tard sur accord explicite
(#1065, #1066, #1068).

Regles d'eligibilite (toutes requises) :

1. `rule_id` dans `ELIGIBLE_RULES` : symptomes de chemin reseau (pertes,
   retransmissions, PMTUD, silence NAT/pare-feu, variation de TTL, sauts
   aberrants, SYN sans reponse, RST localise) ou de file d'attente
   (bufferbloat, saturation). Les constats applicatifs (DNS, HTTP, TLS,
   temps serveur) ou purement locaux L2 (ARP, STP, VLAN, DHCP) sont exclus :
   une mesure de chemin n'y apporterait rien.
2. constat LOCALISE : `segment` non vide et different de « global ».
3. severite differente de « info ».
4. au moins une cle de flux STRICTE exploitable dans `flow_keys`
   (`(proto, src, sport, dst, dport, key_id)` de `correlate.flow_key`,
   proto TCP/UDP/ICMP/ICMPv6, adresses renseignees, ports renseignes pour
   TCP/UDP). Les cles du mode `--nat-tolerant` (`("NAT", ...)`) n'ont pas
   de 5-uplet : elles sont ignorees. Sans 5-uplet, aucune mesure n'est
   proposee (on ne devine jamais une cible).

Types de mesure :

- `paris_traceroute` : sonde du protocole du flux (`tcp-syn` pour TCP,
  `udp` pour UDP, `icmp-echo` pour ICMP/ICMPv6) avec le 5-uplet conserve,
  pour localiser le saut fautif ;
- `twamp_light` (RFC 5357 annexe I) : delai/pertes aller-retour vers un
  reflecteur proche de la destination, pour les symptomes de perte ou de
  file d'attente. Le reflecteur reel est choisi a l'execution (#1066).

Les propositions identiques (meme type, meme 5-uplet) issues de plusieurs
constats sont fusionnees : `rule_ids`/`segments` cumulent leurs origines,
dans l'ordre de premiere rencontre (sortie deterministe).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from netcross_core.expert_model import Diagnosis, ExpertEvent
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

PARIS_TRACEROUTE = "paris_traceroute"
TWAMP_LIGHT = "twamp_light"

# rule_id -> types de mesure proposes (ordre = ordre de proposition)
ELIGIBLE_RULES: dict[str, tuple[str, ...]] = {
    "loss_per_segment": (PARIS_TRACEROUTE, TWAMP_LIGHT),
    "tcp_retransmission_rto": (PARIS_TRACEROUTE, TWAMP_LIGHT),
    "tcp_retransmission_fast": (PARIS_TRACEROUTE, TWAMP_LIGHT),
    "bufferbloat": (TWAMP_LIGHT,),
    "saturation": (TWAMP_LIGHT,),
    "hop_delta_outliers": (PARIS_TRACEROUTE, TWAMP_LIGHT),
    "pmtud_blackhole": (PARIS_TRACEROUTE,),
    "icmp_fragmentation_needed": (PARIS_TRACEROUTE,),
    "nat_fw_silent_drop": (PARIS_TRACEROUTE,),
    "ttl_variation": (PARIS_TRACEROUTE,),
    "tcp_syn_no_synack": (PARIS_TRACEROUTE,),
    "syn_reply_missing": (PARIS_TRACEROUTE,),
    "tcp_rst_localized": (PARIS_TRACEROUTE,),
}

_SONDES_TRACEROUTE = {"TCP": "tcp-syn", "UDP": "udp", "ICMP": "icmp-echo", "ICMPV6": "icmp-echo"}
_SEGMENTS_NON_LOCALISES = {"", "global"}

# Port UDP bien connu de TWAMP (RFC 5357 section 4 / IANA « twamp-control »)
TWAMP_PORT = 862


@dataclass(frozen=True)
class FiveTuple:
    """5-uplet du flux cible ; ports `None` pour ICMP/ICMPv6."""

    proto: str  # "TCP", "UDP", "ICMP", "ICMPv6"
    src: str
    sport: int | None
    dst: str
    dport: int | None

    def __str__(self) -> str:
        logger.debug("FiveTuple.__str__: entrée")
        if self.sport is None or self.dport is None:
            logger.debug("FiveTuple.__str__: si sans ports -> retour str")
            return f"{self.proto} {self.src} -> {self.dst}"
        logger.debug("FiveTuple.__str__: retour str avec ports")
        return f"{self.proto} {self.src}:{self.sport} -> {self.dst}:{self.dport}"


@dataclass
class ProposedMeasurement:
    """Mesure active proposee pour un ou plusieurs constats (rien n'est emis)."""

    kind: str  # PARIS_TRACEROUTE | TWAMP_LIGHT
    five_tuple: FiveTuple
    protocol: str  # sonde : "tcp-syn", "udp", "icmp-echo" (traceroute) ; "udp" (TWAMP)
    target_port: int | None  # port vise par la sonde (dport du flux ; 862 pour TWAMP)
    reason: str
    rule_ids: list[str] = field(default_factory=list)
    segments: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Representation JSON (rapport, API) -- types natifs uniquement."""
        logger.debug("ProposedMeasurement.to_dict: retour dict")
        return {
            "kind": self.kind,
            "five_tuple": {
                "proto": self.five_tuple.proto,
                "src": self.five_tuple.src,
                "sport": self.five_tuple.sport,
                "dst": self.five_tuple.dst,
                "dport": self.five_tuple.dport,
            },
            "protocol": self.protocol,
            "target_port": self.target_port,
            "reason": self.reason,
            "rule_ids": list(self.rule_ids),
            "segments": list(self.segments),
        }


def five_tuple_from_flow_key(key: tuple) -> FiveTuple | None:
    """5-uplet d'une cle stricte de `correlate.flow_key`, sinon None."""
    logger.debug("five_tuple_from_flow_key: entrée")
    if len(key) < 5 or key[0] == "NAT":
        logger.debug("five_tuple_from_flow_key: si cle NAT ou trop courte -> retour None")
        return None
    proto, src, sport, dst, dport = key[:5]
    proto_norm = str(proto).upper() if proto else ""
    if proto_norm not in _SONDES_TRACEROUTE or not src or not dst:
        logger.debug("five_tuple_from_flow_key: si protocole non sondable ou adresse absente -> retour None")
        return None
    if proto_norm in ("TCP", "UDP"):
        if sport is None or dport is None:
            logger.debug("five_tuple_from_flow_key: si port TCP/UDP absent -> retour None")
            return None
        logger.debug("five_tuple_from_flow_key: retour FiveTuple TCP/UDP")
        return FiveTuple("TCP" if proto_norm == "TCP" else "UDP", str(src), int(sport), str(dst), int(dport))
    logger.debug("five_tuple_from_flow_key: retour FiveTuple ICMP")
    return FiveTuple("ICMP" if proto_norm == "ICMP" else "ICMPv6", str(src), None, str(dst), None)


def ineligibility_reason(event: ExpertEvent) -> str | None:
    """Raison pour laquelle un constat n'appelle pas de mesure, sinon None."""
    logger.debug("ineligibility_reason: entrée")
    if event.rule_id not in ELIGIBLE_RULES:
        logger.debug("ineligibility_reason: si regle non eligible -> retour str")
        return f"regle {event.rule_id!r} sans mesure active pertinente"
    if (event.segment or "").strip().lower() in _SEGMENTS_NON_LOCALISES:
        logger.debug("ineligibility_reason: si constat non localise -> retour str")
        return "constat non localise (segment vide ou global)"
    if event.severity == "info":
        logger.debug("ineligibility_reason: si severite info -> retour str")
        return "constat informatif"
    if not any(five_tuple_from_flow_key(k) for k in event.flow_keys):
        logger.debug("ineligibility_reason: si aucun 5-uplet -> retour str")
        return "aucun 5-uplet exploitable dans flow_keys"
    logger.debug("ineligibility_reason: retour None (eligible)")
    return None


def _proposition(kind: str, ft: FiveTuple, event: ExpertEvent) -> ProposedMeasurement:
    logger.debug("_proposition: entrée")
    if kind == PARIS_TRACEROUTE:
        mesure = ProposedMeasurement(
            kind=kind,
            five_tuple=ft,
            protocol=_SONDES_TRACEROUTE[ft.proto.upper()],
            target_port=ft.dport,
            reason=f"localiser le saut fautif sur le segment {event.segment} ({event.rule_id})",
        )
        logger.debug("_proposition: retour traceroute")
        return mesure
    mesure = ProposedMeasurement(
        kind=kind,
        five_tuple=ft,
        protocol="udp",
        target_port=TWAMP_PORT,
        reason=f"mesurer delai et pertes aller-retour sur le segment {event.segment} ({event.rule_id})",
    )
    logger.debug("_proposition: retour TWAMP")
    return mesure


def plan_measurements(events: Iterable[ExpertEvent], max_flows_per_event: int = 1) -> list[ProposedMeasurement]:
    """Propose les mesures actives pour les constats localises eligibles.

    `max_flows_per_event` (>= 1) : nombre de flux distincts retenus par
    constat, dans l'ordre de `flow_keys` (defaut 1 : le premier flux, pour
    limiter le nombre de sondes). Aucune emission reseau.
    """
    logger.debug("plan_measurements: entrée (max_flows_per_event={})", max_flows_per_event)
    if max_flows_per_event < 1:
        logger.debug("plan_measurements: si max_flows_per_event < 1 -> ValueError")
        raise ValueError("max_flows_per_event doit etre >= 1")
    par_cle: dict[tuple[str, FiveTuple], ProposedMeasurement] = {}
    ignores = 0
    for event in events:
        raison = ineligibility_reason(event)
        if raison is not None:
            ignores += 1
            logger.trace("plan_measurements: constat {} ignore : {}", event.rule_id, raison)
            continue
        tuples: list[FiveTuple] = []
        for key in event.flow_keys:
            ft = five_tuple_from_flow_key(key)
            if ft is not None and ft not in tuples:
                tuples.append(ft)
            if len(tuples) >= max_flows_per_event:
                break
        for ft in tuples:
            for kind in ELIGIBLE_RULES[event.rule_id or ""]:
                mesure = par_cle.get((kind, ft))
                if mesure is None:
                    mesure = _proposition(kind, ft, event)
                    par_cle[(kind, ft)] = mesure
                if event.rule_id not in mesure.rule_ids:
                    mesure.rule_ids.append(event.rule_id or "")
                if event.segment not in mesure.segments:
                    mesure.segments.append(event.segment)
    mesures = list(par_cle.values())
    logger.debug("plan_measurements: retour {} mesure(s), {} constat(s) ignore(s)", len(mesures), ignores)
    return mesures


def plan_from_diagnoses(diagnoses: Iterable[Diagnosis], max_flows_per_event: int = 1) -> list[ProposedMeasurement]:
    """Meme chose que `plan_measurements` sur les evenements des diagnostics."""
    logger.debug("plan_from_diagnoses: entrée")
    mesures = plan_measurements((e for d in diagnoses for e in d.events), max_flows_per_event)
    logger.debug("plan_from_diagnoses: retour {} mesure(s)", len(mesures))
    return mesures
