# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.netflow -- ingestion NetFlow/sFlow comme source de
donnees alternative aux captures pcap (Job 32, issue #32).

Voir docs/adr/netflow-sflow-architecture.md pour la decision
d'architecture complete (placement, structure, limitations assumees,
plan d'implementation par phases).

Etat actuel (Phase 1 + 2 du plan) : parseur NetFlow v5 (le format le
plus simple et le plus repandu) et adaptateur FlowRecord -> Pkt pour
reutiliser le pipeline d'analyse existant. NetFlow v9 (templates),
sFlow et le collecteur UDP live restent a faire (Phases 3-5, voir
l'ADR) -- volontairement hors scope de cette session pour livrer une
premiere brique testee plutot qu'une ebauche des cinq protocoles a la
fois.

Utilisation typique (mode fichier, rejeu) ::

    from netcross_core.netflow import iter_netflow_v5_file, flow_records_to_pkts

    flows = list(iter_netflow_v5_file("export.netflow5", exporter="10.0.0.1"))
    pkts = flow_records_to_pkts(flows)  # reutilisable par correlate()/analyse()

Depuis le CLI (issue #362) : `--netflow [EXPORTATEUR=]FICHIER`, resume
texte et `--json-report` (voir netcross_core.netflow.summary).
"""

from netcross_core.logging_config import get_logger
from netcross_core.netflow.adapter import flow_record_to_pkt, flow_records_to_pkts
from netcross_core.netflow.models import FlowRecord
from netcross_core.netflow.netflow_v5 import (
    NetflowV5Error,
    iter_netflow_v5_file,
    parse_netflow_v5_packet,
)
from netcross_core.netflow.summary import format_flow_summary, summarize_flow_records

logger = get_logger(__name__)

__all__ = [
    "FlowRecord",
    "NetflowV5Error",
    "flow_record_to_pkt",
    "flow_records_to_pkts",
    "format_flow_summary",
    "iter_netflow_v5_file",
    "parse_netflow_v5_packet",
    "summarize_flow_records",
]
