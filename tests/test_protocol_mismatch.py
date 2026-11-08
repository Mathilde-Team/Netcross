# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests de netcross_core.security.protocol_mismatch (issue #142, FLOW-1).

Teste la détection de mismatches protocole/port en utilisant les champs
déjà décodés de Pkt (http_*, dns_*, tls_*, service_banners) — aucune
dissection tshark supplémentaire.
"""

from __future__ import annotations

from typing import Any

from netcross_core.models import Banner, Pkt
from netcross_core.security.protocol_mismatch import (
    count_protocol_mismatches,
    detect_protocol_mismatch,
    detect_protocol_mismatches,
    protocol_mismatch_findings,
)

# -- Helpers ------------------------------------------------------------------


def _make_pkt(
    *,
    proto: str = "TCP",
    sport: int | None = None,
    dport: int | None = None,
    frame_number: int | None = 1,
    http_method: str | None = None,
    http_is_request: bool = False,
    http_is_response: bool = False,
    dns_qry_name: str | None = None,
    dns_txn_id: int | None = None,
    tls_client_hello: bool = False,
    tls_server_hello: bool = False,
    tls_application_data: bool = False,
    sip_msg_type: str | None = None,
    sip_call_id: str | None = None,
    service_banners: tuple[Banner, ...] = (),
) -> Pkt:
    """Construit un Pkt minimal avec seulement les champs utiles au test."""
    # Pkt est un dataclass(slots=True) : on passe par la construction
    # réelle avec des valeurs par défaut pour les champs non testés.
    kwargs: dict[str, Any] = {
        "point": "A",
        "ts": 0.0,
        "frame_number": frame_number,
        "proto": proto,
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "sport": sport,
        "dport": dport,
        "length": 100,
        "ttl": 64,
        "dscp": 0,
        "ecn": 0,
        "seq": None,
        "ack": None,
        "window": None,
        "flags": None,
        "key_id": None,
        "payload_hash": None,
        "ip_id": None,
        "is_fragment": False,
        "df": False,
        "is_retransmission": False,
        "is_fast_retransmission": False,
        "is_spurious_retransmission": False,
        "mss_val": None,
        "wscale_shift": None,
        "sack_permitted": False,
        "icmp_type": None,
        "icmp_code": None,
        "icmpv6_type": None,
        "icmpv6_code": None,
        "arp_opcode": None,
        "arp_sender_mac": None,
        "arp_is_gratuitous": False,
        "stp_bpdu_type": None,
        "stp_flags_tc": False,
        "stp_root_id": None,
        "tls_cert_not_before": None,
        "tls_cert_not_after": None,
        "tls_cert_san": None,
        "tls_cert_serial": None,
        "tls_cert_issuer": None,
        "tls_cert_subject": None,
        "tls_cert_sig_hash": None,
        "tls_cert_key_type": None,
        "tls_cert_key_bits": None,
        "tls_cert_san_ip": None,
        "tls_cert_chain_len": None,
        "tls_client_hello": tls_client_hello,
        "tls_server_hello": tls_server_hello,
        "tls_application_data": tls_application_data,
        "vlan_id": None,
        "vlan_prio": None,
        "is_rtp": False,
        "rtp_seq": None,
        "rtp_ts": None,
        "rtp_ssrc": None,
        "encap_tags": (),
        "dhcp_xid": None,
        "dhcp_msg_type": None,
        "dhcp_server_id": None,
        "dhcp_vendor_class": None,
        "sip_call_id": sip_call_id,
        "sip_msg_type": sip_msg_type,
        "sip_cseq": None,
        "sip_user_agent": None,
        "sip_server": None,
        "dns_txn_id": dns_txn_id,
        "dns_is_response": False,
        "dns_qry_name": dns_qry_name,
        "dns_rcode": None,
        "http_is_request": http_is_request,
        "http_is_response": http_is_response,
        "http_method": http_method,
        "http_uri": None,
        "http_status_code": None,
        "http_response_time_ms": None,
        "expert_flags": (),
        "expert_details": (),
        "service_banners": service_banners,
    }
    return Pkt(**kwargs)


# -- detect_protocol_mismatch : cas positifs (mismatch) -----------------------


def test_ssh_sur_443_banniere():
    """SSH détecté via service_banners sur port 443 (contournement firewall)."""
    pkt = _make_pkt(
        dport=443,
        service_banners=(Banner(protocol="ssh", service="OpenSSH", version="8.9", raw="SSH-2.0-OpenSSH_8.9"),),
    )
    result = detect_protocol_mismatch(pkt)
    assert result is not None
    assert result[0] == "SSH"
    assert "443" in result[1]


def test_ssh_sur_22_pas_de_mismatch():
    """SSH sur port 22 = pas de mismatch."""
    pkt = _make_pkt(
        dport=22,
        service_banners=(Banner(protocol="ssh", service="OpenSSH", version="8.9", raw="SSH-2.0-OpenSSH_8.9"),),
    )
    assert detect_protocol_mismatch(pkt) is None


def test_http_sur_22_via_champs_http():
    """HTTP détecté via http_method sur port 22 (mismatch : SSH attendu)."""
    pkt = _make_pkt(dport=22, http_method="GET", http_is_request=True)
    result = detect_protocol_mismatch(pkt)
    assert result is not None
    assert result[0] == "HTTP"
    assert "22" in result[1]


def test_http_sur_80_pas_de_mismatch():
    """HTTP sur port 80 = pas de mismatch."""
    pkt = _make_pkt(dport=80, http_method="GET", http_is_request=True)
    assert detect_protocol_mismatch(pkt) is None


def test_dns_sur_80_via_champs_dns():
    """DNS détecté via dns_qry_name sur port 80 (mismatch)."""
    pkt = _make_pkt(dport=80, dns_qry_name="example.com", dns_txn_id=1234)
    result = detect_protocol_mismatch(pkt)
    assert result is not None
    assert result[0] == "DNS"


def test_dns_sur_53_pas_de_mismatch():
    """DNS sur port 53 = pas de mismatch."""
    pkt = _make_pkt(dport=53, dns_qry_name="example.com", dns_txn_id=1234)
    assert detect_protocol_mismatch(pkt) is None


def test_https_tls_sur_443_pas_de_mismatch():
    """TLS/HTTPS sur port 443 = pas de mismatch."""
    pkt = _make_pkt(dport=443, tls_client_hello=True)
    assert detect_protocol_mismatch(pkt) is None


def test_https_tls_sur_80_mismatch():
    """TLS/HTTPS sur port 80 = mismatch."""
    pkt = _make_pkt(dport=80, tls_server_hello=True)
    result = detect_protocol_mismatch(pkt)
    assert result is not None
    assert result[0] == "HTTPS"


def test_ftp_sur_80_banniere():
    """FTP détecté via service_banners sur port 80 (mismatch)."""
    pkt = _make_pkt(
        dport=80,
        service_banners=(Banner(protocol="ftp", service="vsftpd", version="3.0", raw="220 vsftpd"),),
    )
    result = detect_protocol_mismatch(pkt)
    assert result is not None
    assert result[0] == "FTP"


def test_ftp_sur_21_pas_de_mismatch():
    """FTP sur port 21 = pas de mismatch."""
    pkt = _make_pkt(
        dport=21,
        service_banners=(Banner(protocol="ftp", service="vsftpd", version="3.0", raw="220 vsftpd"),),
    )
    assert detect_protocol_mismatch(pkt) is None


def test_smtp_sur_80_banniere():
    """SMTP détecté via service_banners sur port 80 (mismatch)."""
    pkt = _make_pkt(
        dport=80,
        service_banners=(Banner(protocol="smtp", service="Postfix", version=None, raw="220 smtp"),),
    )
    result = detect_protocol_mismatch(pkt)
    assert result is not None
    assert result[0] == "SMTP"


def test_smtp_sur_25_pas_de_mismatch():
    """SMTP sur port 25 = pas de mismatch."""
    pkt = _make_pkt(
        dport=25,
        service_banners=(Banner(protocol="smtp", service="Postfix", version=None, raw="220 smtp"),),
    )
    assert detect_protocol_mismatch(pkt) is None


def test_http_sur_port_source_mismatch():
    """HTTP détecté sur le port source (sport=22) = mismatch."""
    pkt = _make_pkt(sport=22, dport=12345, http_method="GET", http_is_request=True)
    result = detect_protocol_mismatch(pkt)
    assert result is not None
    assert result[0] == "HTTP"


def test_icmp_tunneling_http():
    """Paquet ICMP avec champ HTTP peuplé = tunneling suspect."""
    pkt = _make_pkt(proto="ICMP", sport=None, dport=None, http_method="GET", http_is_request=True)
    result = detect_protocol_mismatch(pkt)
    assert result is not None
    assert result[0] == "ICMP_TUNNEL"
    assert "HTTP" in result[1]


def test_icmp_tunneling_dns():
    """Paquet ICMP avec champ DNS peuplé = tunneling suspect."""
    pkt = _make_pkt(proto="ICMP", dns_qry_name="tunnel.example.com", dns_txn_id=42)
    result = detect_protocol_mismatch(pkt)
    assert result is not None
    assert result[0] == "ICMP_TUNNEL"


def test_icmp_normal_pas_de_mismatch():
    """Paquet ICMP sans champ applicatif = pas de mismatch."""
    pkt = _make_pkt(proto="ICMP")
    assert detect_protocol_mismatch(pkt) is None


def test_icmpv6_tunneling():
    """Paquet ICMPv6 avec champ HTTP = tunneling suspect."""
    pkt = _make_pkt(proto="ICMPv6", http_method="POST", http_is_request=True)
    result = detect_protocol_mismatch(pkt)
    assert result is not None
    assert result[0] == "ICMP_TUNNEL"


def test_pas_de_champ_applicatif_pas_de_mismatch():
    """Paquet sans champ applicatif = pas de mismatch."""
    pkt = _make_pkt(dport=443)
    assert detect_protocol_mismatch(pkt) is None


def test_http_sur_8080_pas_de_mismatch():
    """HTTP sur port 8080 (HTTP-ALT) = pas de mismatch."""
    pkt = _make_pkt(dport=8080, http_method="GET", http_is_request=True)
    assert detect_protocol_mismatch(pkt) is None


def test_sip_sur_5060_pas_dans_table():
    """SIP sur port non standard (5060 n'est pas dans STANDARD_PORTS)."""
    pkt = _make_pkt(dport=5060, sip_msg_type="INVITE", sip_call_id="abc")
    # 5060 n'est pas dans la table -> pas de mismatch possible
    assert detect_protocol_mismatch(pkt) is None


# -- detect_protocol_mismatches (liste) --------------------------------------


def test_detect_protocol_mismatches_liste():
    """Plusieurs paquets, certains avec mismatch."""
    pkts = [
        _make_pkt(frame_number=1, dport=22, http_method="GET", http_is_request=True),  # mismatch
        _make_pkt(frame_number=2, dport=80, http_method="GET", http_is_request=True),  # OK
        _make_pkt(frame_number=3, dport=80, dns_qry_name="test.com", dns_txn_id=1),  # mismatch
    ]
    details = detect_protocol_mismatches(pkts)
    assert len(details) == 2
    assert details[0]["detected_proto"] == "HTTP"
    assert details[0]["dport"] == 22
    assert details[1]["detected_proto"] == "DNS"


def test_detect_protocol_mismatches_vide():
    """Liste vide = aucun détail."""
    assert detect_protocol_mismatches([]) == []


# -- count_protocol_mismatches -----------------------------------------------


def test_count_protocol_mismatches_vide():
    """Liste vide = compteur vide."""
    assert count_protocol_mismatches([]) == {}


def test_count_protocol_mismatches_multiple():
    """Comptage par protocole et description."""
    pkts = [
        _make_pkt(frame_number=1, dport=22, http_method="GET", http_is_request=True),
        _make_pkt(frame_number=2, dport=22, http_method="POST", http_is_request=True),
        _make_pkt(frame_number=3, dport=80, dns_qry_name="x", dns_txn_id=1),
    ]
    counts = count_protocol_mismatches(pkts)
    assert "HTTP" in counts
    assert "DNS" in counts
    # Les deux paquets HTTP sur 443 ont la même description
    http_descs = list(counts["HTTP"].values())
    assert http_descs[0] == 2


# -- protocol_mismatch_findings ----------------------------------------------


def test_protocol_mismatch_findings_severite():
    """ICMP_TUNNEL = elevee, autres = moyenne."""
    details = [
        {
            "frame_number": 1,
            "proto": "TCP",
            "sport": 12345,
            "dport": 443,
            "detected_proto": "SSH",
            "description": "SSH détecté sur port 443 (attendu : HTTPS)",
        },
        {
            "frame_number": 2,
            "proto": "ICMP",
            "sport": None,
            "dport": None,
            "detected_proto": "ICMP_TUNNEL",
            "description": "Payload HTTP dans paquet ICMP (tunneling suspect)",
        },
    ]
    findings = protocol_mismatch_findings(details)
    assert len(findings) == 2
    assert findings[0]["severity"] == "moyenne"
    assert findings[1]["severity"] == "elevee"
    assert findings[0]["category"] == "anomalie"
    assert findings[1]["category"] == "anomalie"
    expected_detail_0 = "incoherence de protocole : SSH détecté sur port 443 (attendu : HTTPS) -- trame 1"
    expected_detail_1 = "incoherence de protocole : Payload HTTP dans paquet ICMP (tunneling suspect) -- trame 2"
    assert findings[0]["detail"] == expected_detail_0
    assert findings[1]["detail"] == expected_detail_1


def test_protocol_mismatch_findings_vide():
    """Liste vide = aucun finding."""
    assert protocol_mismatch_findings([]) == []
