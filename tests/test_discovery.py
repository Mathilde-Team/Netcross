# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.discovery -- tests de l'inventaire passif des actifs
reseau (assets.py) et de l'empreinte OS passive (os_detect.py), issue
#151 (SCENARIO-5, parent #141). Pkt synthetiques (make_pkt), aucune
capture ni tshark -- meme discipline que le reste de la suite (voir
conftest.py et tests/test_client_diff.py).
"""

import json

import pytest
from conftest import make_pkt

from netcross_core.discovery.assets import (
    build_asset_inventory,
    load_baseline_hosts,
)
from netcross_core.discovery.os_detect import (
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    guess_initial_ttl,
    guess_os_from_ttl,
    refine_with_tcp_options,
)
from netcross_core.models import ROLE_CLIENT, ROLE_SERVER, Banner

# -- os_detect ---------------------------------------------------------


@pytest.mark.parametrize(
    ("observed", "expected_initial"),
    [
        (64, 64),
        (63, 64),
        (48, 64),
        (128, 128),
        (117, 128),
        (255, 255),
        (250, 255),
    ],
)
def test_guess_initial_ttl_standard_buckets(observed, expected_initial):
    assert guess_initial_ttl(observed) == expected_initial


def test_guess_initial_ttl_never_exceeds_255():
    # TTL est sur 8 bits : jamais observe > 255 en pratique, mais la
    # fonction ne doit pas planter si on la sollicite hors bornes.
    assert guess_initial_ttl(300) == 255


def test_guess_os_from_ttl_linux_family():
    guess = guess_os_from_ttl(61)
    assert guess.family == "Linux/BSD/macOS"
    assert guess.guessed_initial_ttl == 64
    assert guess.hop_estimate == 3
    assert guess.confidence == CONFIDENCE_LOW


def test_guess_os_from_ttl_windows_family():
    guess = guess_os_from_ttl(125)
    assert guess.family == "Windows"
    assert guess.guessed_initial_ttl == 128
    assert guess.hop_estimate == 3


def test_guess_os_from_ttl_hop_zero_when_exact_match():
    guess = guess_os_from_ttl(64)
    assert guess.hop_estimate == 0


def test_refine_with_tcp_options_raises_confidence_when_coherent():
    guess = guess_os_from_ttl(61)
    refined = refine_with_tcp_options(guess, wscale_shift=7, sack_permitted=True, mss_val=1460)
    assert refined.confidence == CONFIDENCE_MEDIUM
    assert "wscale=7" in refined.evidence
    assert refined.family == guess.family  # jamais reclasse, seulement corrobore


def test_refine_with_tcp_options_keeps_low_confidence_when_incomplete():
    guess = guess_os_from_ttl(61)
    # SACK permis mais pas de window scale : combinaison incomplete,
    # ne suffit pas a relever la confiance.
    refined = refine_with_tcp_options(guess, wscale_shift=None, sack_permitted=True, mss_val=1460)
    assert refined.confidence == CONFIDENCE_LOW
    assert refined is guess or refined == guess


def test_refine_with_tcp_options_is_idempotent():
    guess = guess_os_from_ttl(61)
    once = refine_with_tcp_options(guess, wscale_shift=7, sack_permitted=True, mss_val=1460)
    twice = refine_with_tcp_options(once, wscale_shift=9, sack_permitted=True, mss_val=1400)
    # deuxieme appel sans effet : la confiance ne degrade ni ne change
    # une fois deja relevee (voir docstring de refine_with_tcp_options)
    assert twice == once


# -- build_asset_inventory : inventaire de base --------------------------


def test_inventory_lists_both_src_and_dst_hosts():
    pkts = [make_pkt(src="10.0.0.1", dst="10.0.0.2", ts=1.0)]
    inv = build_asset_inventory(pkts)
    assert set(inv.hosts) == {"10.0.0.1", "10.0.0.2"}


def test_inventory_tracks_first_and_last_seen():
    pkts = [
        make_pkt(src="10.0.0.1", dst="10.0.0.2", ts=5.0),
        make_pkt(src="10.0.0.1", dst="10.0.0.2", ts=1.0),
        make_pkt(src="10.0.0.1", dst="10.0.0.2", ts=9.0),
    ]
    inv = build_asset_inventory(pkts)
    host = inv.hosts["10.0.0.1"]
    assert host.first_seen == 1.0
    assert host.last_seen == 9.0
    assert host.packet_count == 3


def test_inventory_tracks_points_and_vlan():
    pkts = [
        make_pkt(src="10.0.0.1", dst="10.0.0.2", point="A", vlan_id=10),
        make_pkt(src="10.0.0.1", dst="10.0.0.2", point="B", vlan_id=20),
    ]
    inv = build_asset_inventory(pkts)
    host = inv.hosts["10.0.0.1"]
    assert host.points == {"A", "B"}
    assert host.vlan_ids == {10, 20}


def test_inventory_records_mac_from_arp_sender():
    pkts = [
        make_pkt(proto="ARP", src="10.0.0.1", dst="10.0.0.2", arp_sender_mac="aa:bb:cc:dd:ee:ff"),
    ]
    inv = build_asset_inventory(pkts)
    assert inv.hosts["10.0.0.1"].mac == "aa:bb:cc:dd:ee:ff"
    # le destinataire de la trame ARP ne se voit jamais attribuer la
    # MAC de l'emetteur -- seul le champ arp_sender_mac fait foi.
    assert inv.hosts["10.0.0.2"].mac is None


# -- ports exposes : uniquement confirmes par une reponse positive -------


def test_synack_marks_source_port_as_exposed():
    pkts = [make_pkt(proto="TCP", src="10.0.0.5", dst="10.0.0.1", sport=443, dport=51000, flags="SA")]
    inv = build_asset_inventory(pkts)
    server = inv.hosts["10.0.0.5"]
    assert (443, "tcp") in server.ports
    assert server.ports[(443, "tcp")].transport == "tcp"


def test_syn_alone_never_marks_a_port_exposed():
    # un SYN sans SYN-ACK observe ne prouve rien -- discipline "100%
    # passif" du module (voir docstring de assets.py).
    pkts = [make_pkt(proto="TCP", src="10.0.0.9", dst="10.0.0.5", sport=51000, dport=443, flags="S")]
    inv = build_asset_inventory(pkts)
    assert inv.hosts["10.0.0.5"].ports == {}
    assert inv.hosts["10.0.0.9"].ports == {}


def test_banner_attaches_service_and_version_to_source_host():
    banner = Banner(protocol="ssh", service="OpenSSH", version="8.9p1", raw="SSH-2.0-OpenSSH_8.9p1", role=ROLE_SERVER)
    pkts = [
        make_pkt(
            proto="TCP",
            src="10.0.0.5",
            dst="10.0.0.1",
            sport=22,
            dport=51000,
            flags=".......",
            service_banners=(banner,),
        )
    ]
    inv = build_asset_inventory(pkts)
    svc = inv.hosts["10.0.0.5"].ports[(22, "tcp")]
    assert svc.service == "OpenSSH"
    assert svc.version == "8.9p1"


def test_client_banner_role_is_not_attached_to_a_port():
    # un User-Agent HTTP (ROLE_CLIENT) decrit le LOGICIEL CLIENT de
    # l'emetteur, pas un service qu'il expose -- ne doit jamais
    # apparaitre comme un port ouvert.
    banner = Banner(protocol="http", service="curl", version="8.4.0", raw="curl/8.4.0", role=ROLE_CLIENT)
    pkts = [
        make_pkt(
            proto="TCP",
            src="10.0.0.9",
            dst="10.0.0.5",
            sport=51000,
            dport=80,
            flags=".......",
            service_banners=(banner,),
        )
    ]
    inv = build_asset_inventory(pkts)
    assert inv.hosts["10.0.0.9"].ports == {}


def test_synack_then_banner_merge_into_same_port_entry():
    banner = Banner(protocol="http", service="nginx", version="1.25", raw="Server: nginx/1.25", role=ROLE_SERVER)
    pkts = [
        make_pkt(proto="TCP", src="10.0.0.5", dst="10.0.0.1", sport=80, dport=51000, flags="SA"),
        make_pkt(
            proto="TCP",
            src="10.0.0.5",
            dst="10.0.0.1",
            sport=80,
            dport=51000,
            flags=".......",
            service_banners=(banner,),
        ),
    ]
    inv = build_asset_inventory(pkts)
    svc = inv.hosts["10.0.0.5"].ports[(80, "tcp")]
    assert svc.service == "nginx"
    assert svc.version == "1.25"


# -- empreinte OS integree a l'inventaire ---------------------------------


def test_inventory_attaches_os_guess_from_synack_ttl():
    pkts = [
        make_pkt(
            proto="TCP",
            src="10.0.0.5",
            dst="10.0.0.1",
            sport=443,
            dport=51000,
            flags="SA",
            ttl=61,
            wscale_shift=7,
            sack_permitted=True,
        )
    ]
    inv = build_asset_inventory(pkts)
    guess = inv.hosts["10.0.0.5"].os_guess
    assert guess is not None
    assert guess.family == "Linux/BSD/macOS"
    assert guess.confidence == CONFIDENCE_MEDIUM


def test_inventory_uses_most_common_ttl_when_noisy():
    pkts = [
        make_pkt(proto="TCP", src="10.0.0.5", dst="10.0.0.1", sport=443, dport=51000, flags="SA", ttl=61),
        make_pkt(proto="TCP", src="10.0.0.5", dst="10.0.0.2", sport=443, dport=51001, flags="SA", ttl=61),
        # un seul paquet avec un TTL aberrant (route asymetrique) ne
        # doit pas dominer l'hypothese.
        make_pkt(proto="TCP", src="10.0.0.5", dst="10.0.0.3", sport=443, dport=51002, flags="SA", ttl=118),
    ]
    inv = build_asset_inventory(pkts)
    assert inv.hosts["10.0.0.5"].os_guess.guessed_initial_ttl == 64


def test_host_with_no_ttl_sample_has_no_os_guess():
    pkts = [make_pkt(proto="UDP", src="10.0.0.7", dst="10.0.0.1", sport=5353, dport=5353, ttl=None)]
    inv = build_asset_inventory(pkts)
    assert inv.hosts["10.0.0.7"].os_guess is None


# -- baseline / nouveaux hotes --------------------------------------------


def test_no_baseline_means_no_new_hosts_reported():
    pkts = [make_pkt(src="10.0.0.1", dst="10.0.0.2")]
    inv = build_asset_inventory(pkts, baseline_hosts=None)
    assert inv.new_hosts == ()
    assert inv.baseline_size == 0


def test_baseline_flags_hosts_absent_from_it():
    pkts = [
        make_pkt(src="10.0.0.1", dst="10.0.0.2"),
        make_pkt(src="10.0.0.99", dst="10.0.0.2"),
    ]
    inv = build_asset_inventory(pkts, baseline_hosts={"10.0.0.1", "10.0.0.2"})
    assert inv.new_hosts == ("10.0.0.99",)
    assert inv.baseline_size == 2


def test_baseline_containing_all_hosts_reports_nothing_new():
    pkts = [make_pkt(src="10.0.0.1", dst="10.0.0.2")]
    inv = build_asset_inventory(pkts, baseline_hosts={"10.0.0.1", "10.0.0.2"})
    assert inv.new_hosts == ()


def test_load_baseline_hosts_flat_list(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(["10.0.0.1", "10.0.0.2"]), encoding="utf-8")
    assert load_baseline_hosts(path) == {"10.0.0.1", "10.0.0.2"}


def test_load_baseline_hosts_object_with_hosts_key(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"hosts": ["10.0.0.5"]}), encoding="utf-8")
    assert load_baseline_hosts(path) == {"10.0.0.5"}


def test_load_baseline_hosts_missing_file_returns_empty_set(tmp_path):
    assert load_baseline_hosts(tmp_path / "absent.json") == set()


def test_load_baseline_hosts_malformed_json_returns_empty_set(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text("{not valid json", encoding="utf-8")
    assert load_baseline_hosts(path) == set()


def test_load_baseline_hosts_unexpected_shape_returns_empty_set(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"other_key": [1, 2]}), encoding="utf-8")
    assert load_baseline_hosts(path) == set()


# -- to_records : sortie structuree (integration SIEM) --------------------


def test_to_records_shape_and_is_new_flag():
    pkts = [
        make_pkt(src="10.0.0.1", dst="10.0.0.2", ts=1.0),
        make_pkt(proto="TCP", src="10.0.0.2", dst="10.0.0.1", sport=443, dport=51000, flags="SA", ttl=61),
    ]
    inv = build_asset_inventory(pkts, baseline_hosts={"10.0.0.1"})
    records = {r["ip"]: r for r in inv.to_records()}

    assert set(records) == {"10.0.0.1", "10.0.0.2"}
    assert records["10.0.0.1"]["is_new"] is False
    assert records["10.0.0.2"]["is_new"] is True

    server_record = records["10.0.0.2"]
    assert server_record["ports"] == [{"port": 443, "transport": "tcp", "service": None, "version": None}]
    assert server_record["os_guess"]["family"] == "Linux/BSD/macOS"


def test_to_records_os_guess_none_when_no_ttl_observed():
    pkts = [make_pkt(src="10.0.0.1", dst="10.0.0.2", ttl=None)]
    inv = build_asset_inventory(pkts)
    records = {r["ip"]: r for r in inv.to_records()}
    assert records["10.0.0.1"]["os_guess"] is None


def test_to_records_is_sorted_by_ip():
    pkts = [make_pkt(src="10.0.0.9", dst="10.0.0.1")]
    inv = build_asset_inventory(pkts)
    records = inv.to_records()
    assert [r["ip"] for r in records] == ["10.0.0.1", "10.0.0.9"]
