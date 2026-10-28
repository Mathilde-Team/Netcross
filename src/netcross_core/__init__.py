# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core -- moteur d'analyse croisee de captures Wireshark
multi-points, sans dependance a une interface (CLI, GTK4, PDF...).

Utilisation typique :

    from netcross_core import parse_capture, correlate, analyse, print_report

    packets = []
    for label, path in [("LAN", "lan.pcapng"), ("WAN", "wan.pcapng")]:
        packets.extend(parse_capture(label, path))

    flows = correlate(packets)
    report = analyse(flows, points_order=["LAN", "WAN"], all_packets=packets)
    print_report(report)
"""

from netcross_core.analysis import analyse
from netcross_core.baseline_diff import DiffFinding, diff_reports, print_diff_report, write_diff_csv
from netcross_core.client_diff import (
    ClientComparisonResult,
    ClientReport,
    compare_clients,
    print_client_comparison,
    write_client_diff_csv,
)
from netcross_core.compliance import DEFAULT_REFERENCES, evaluate_compliance
from netcross_core.content import HttpObject, extract_http_objects, objects_to_dicts
from netcross_core.correlate import (
    build_conversations,
    build_flows,
    compute_throughput,
    compute_topn_series,
    correlate,
    flow_key,
)
from netcross_core.discovery import (
    AssetInventory,
    ExposedService,
    HostAsset,
    OsGuess,
    build_asset_inventory,
    load_baseline_hosts,
)
from netcross_core.live_diff import LiveDiffConfig, LiveDiffEngine, LiveDiffState, finding_to_alarm_signal
from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt, Report
from netcross_core.parsing import (
    compute_mos,
    detect_encapsulation,
    parse_capture,
    parse_captures_parallel,
    parse_live,
    parse_live_multi,
    parse_rtp,
    parse_sip,
    read_capture_comments,
    read_capture_infos,
)
from netcross_core.redact import AddressRedactor, redact_packets, write_redaction_map_csv
from netcross_core.report_text import print_report, write_detail_csv
from netcross_core.stats import compute_stats, export_csv, export_json
from netcross_core.voip import Call, build_calls
from netcross_core.wireshark_expert import build_wireshark_expert_events
from pcap_parser.capfile import first_timestamp
from pcap_parser.capture import (
    TcpreplayError,
    TcpreplayNotFoundError,
    adjust_timestamps,
    convert_capture,
    export_filtered,
    merge_captures,
    replay_capture,
    split_capture,
)

logger = get_logger(__name__)

__all__ = [
    "DEFAULT_REFERENCES",
    "AddressRedactor",
    "AssetInventory",
    "Call",
    "ClientComparisonResult",
    "ClientReport",
    "DiffFinding",
    "ExposedService",
    "HostAsset",
    "HttpObject",
    "LiveDiffConfig",
    "LiveDiffEngine",
    "LiveDiffState",
    "OsGuess",
    "Pkt",
    "Report",
    "TcpreplayError",
    "TcpreplayNotFoundError",
    "adjust_timestamps",
    "analyse",
    "build_asset_inventory",
    "build_calls",
    "build_conversations",
    "build_flows",
    "build_wireshark_expert_events",
    "compare_clients",
    "compute_mos",
    "compute_stats",
    "compute_throughput",
    "compute_topn_series",
    "convert_capture",
    "correlate",
    "detect_encapsulation",
    "diff_reports",
    "evaluate_compliance",
    "export_csv",
    "export_filtered",
    "export_json",
    "extract_http_objects",
    "finding_to_alarm_signal",
    "first_timestamp",
    "flow_key",
    "load_baseline_hosts",
    "merge_captures",
    "objects_to_dicts",
    "parse_capture",
    "parse_captures_parallel",
    "parse_live",
    "parse_live_multi",
    "parse_rtp",
    "parse_sip",
    "print_client_comparison",
    "print_diff_report",
    "print_report",
    "read_capture_comments",
    "read_capture_infos",
    "redact_packets",
    "replay_capture",
    "split_capture",
    "write_client_diff_csv",
    "write_detail_csv",
    "write_diff_csv",
    "write_redaction_map_csv",
]
