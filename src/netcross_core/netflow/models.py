# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.netflow.models -- structure de donnees partagee pour un
flux agrege NetFlow/sFlow (FlowRecord), distincte de Pkt.

Voir docs/adr/netflow-sflow-architecture.md pour la decision
d'architecture complete. En resume : NetFlow/sFlow ne fournit jamais
de paquets individuels, seulement des agregats (5-tuple, octets,
paquets, bornes temporelles) -- FlowRecord modelise cet agregat tel
quel, sans essayer de simuler des paquets qui n'existent pas.
`adapter.py` convertit ensuite un FlowRecord en Pkt synthetique pour
reutiliser le pipeline d'analyse existant (correlate/analyse), avec
les limitations documentees dans l'ADR.
"""

from __future__ import annotations

from dataclasses import dataclass

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


@dataclass(slots=True)
class FlowRecord:
    """Un flux agrege, tel qu'exporte par un routeur/switch NetFlow ou
    un agent sFlow. Champs communs aux deux protocoles ; les champs
    absents d'une source donnee restent a None (ex: sFlow ne fournit
    pas toujours tos/tcp_flags de maniere fiable -- voir ADR)."""

    # Identite de l'exportateur (routeur/switch), pas un "point" au sens
    # multi-points pcap de Pkt.point -- voir ADR section "Correlation
    # multi-points ne s'applique pas".
    exporter: str
    version: int  # 5, 9 (NetFlow) ou 5 (sFlow, espace de version distinct)

    src_addr: str
    dst_addr: str
    src_port: int | None
    dst_port: int | None
    protocol: int  # numero de protocole IP (6=TCP, 17=UDP, 1=ICMP...)

    packets: int
    octets: int

    # Bornes temporelles du flux, en secondes Unix (epoch). NetFlow v5
    # exprime nativement `First`/`Last` en millisecondes depuis le
    # demarrage de l'exportateur (SysUptime) -- le parseur reconstitue
    # l'epoch a partir de unix_secs/unix_nsecs/SysUptime de l'en-tete,
    # voir netflow_v5.py.
    start_ts: float
    end_ts: float

    tcp_flags: int | None = None  # OR cumule des flags TCP du flux (NetFlow v5)
    tos: int | None = None  # ToS/DSCP au sens large, octet brut
    src_as: int | None = None
    dst_as: int | None = None
    src_mask: int | None = None
    dst_mask: int | None = None
    input_snmp: int | None = None  # index SNMP interface d'entree
    output_snmp: int | None = None  # index SNMP interface de sortie
    next_hop: str | None = None

    # Metadonnees d'export, utiles pour le diagnostic (pas pour l'analyse) :
    sampling_interval: int | None = None
    engine_type: int | None = None
    engine_id: int | None = None
    flow_sequence: int | None = None
