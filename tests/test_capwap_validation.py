# SPDX-License-Identifier: GPL-3.0-or-later
"""
tests/test_capwap_validation.py — Validation de la détection CAPWAP/DTLS
(issue #29).

Valide la détection DTLS sur des patterns EK simulés pour différentes
marques de points d'accès / contrôleurs WiFi (Fortinet, Cisco, Aruba).
Ces tests ne remplacent PAS la validation sur captures réelles (critère
d'acceptation de l'issue), mais garantissent que la logique de
détection dans pcap_parser.tunnels._capwap_tags couvre les patterns
connus de chaque marque.

Le critère d'acceptation « Détection DTLS confirmée sur au moins une
marque » est PARTIELLEMENT rempli : la détection logique est confirmée
en synthétique, mais la validation sur vraie capture reste nécessaire
(dépendance explicite de l'issue #29).
"""

from pcap_parser.tunnels import detect_encapsulation


def test_dtls_fortinet_controle_port_5246():
    """Fortinet : canal de contrôle CAPWAP sur port 5246, chiffré DTLS.
    tshark expose la couche 'dtls' au-dessus de UDP — pas de
    'capwap_control' décodable (chiffré)."""
    layers = {
        "dtls": {},
        "udp": {
            "udp_udp_srcport": "5246",
            "udp_udp_dstport": "12345",
        },
    }
    tags = detect_encapsulation(layers)
    assert "CAPWAP(chiffre DTLS)" in tags


def test_dtls_fortinet_data_port_5247():
    """Fortinet : canal de données CAPWAP sur port 5247, chiffré DTLS.
    tshark expose 'capwap_data' avec preamble_type=1 (chiffré)."""
    layers = {
        "capwap_data": {"capwap_capwap_preamble_type": "1"},
    }
    tags = detect_encapsulation(layers)
    assert "CAPWAP(chiffre DTLS)" in tags


def test_dtls_cisco_wlc_controle_port_5246():
    """Cisco WLC : canal de contrôle CAPWAP sur port 5246, chiffré DTLS.
    Même pattern que Fortinet — la détection est vendor-agnostic."""
    layers = {
        "dtls": {},
        "udp": {
            "udp_udp_srcport": "5246",
            "udp_udp_dstport": "5247",
        },
    }
    tags = detect_encapsulation(layers)
    assert "CAPWAP(chiffre DTLS)" in tags


def test_dtls_aruba_controle_port_5246():
    """Aruba : canal de contrôle CAPWAP sur port 5246, chiffré DTLS."""
    layers = {
        "dtls": {},
        "udp": {
            "udp_udp_srcport": "12345",
            "udp_udp_dstport": "5246",
        },
    }
    tags = detect_encapsulation(layers)
    assert "CAPWAP(chiffre DTLS)" in tags


def test_dtls_capwap_data_decapsule_fortinet():
    """Fortinet : canal de données CAPWAP non chiffré (preamble_type=0),
    tshark a décodé la trame interne. La détection doit retourner
    'CAPWAP(decapsule)', pas DTLS."""
    layers = {
        "capwap_data": {"capwap_capwap_preamble_type": "0"},
        "frame": {"frame_frame_protocols": "eth:ethertype:ip:udp:capwap.data:eth:ip:tcp"},
    }
    tags = detect_encapsulation(layers)
    assert "CAPWAP(decapsule)" in tags


def test_dtls_capwap_controle_non_chiffre():
    """CAPWAP contrôle sans DTLS (rare en pratique, mais possible en
    laboratoire). La détection doit retourner 'CAPWAP(controle)'."""
    layers = {"capwap_control": {}}
    tags = detect_encapsulation(layers)
    assert "CAPWAP(controle)" in tags


def test_dtls_hors_capwap_ignore():
    """DTLS sur un port non-CAPWAP (ex: 443) ne doit pas être détecté
    comme CAPWAP."""
    layers = {
        "dtls": {},
        "udp": {
            "udp_udp_srcport": "443",
            "udp_udp_dstport": "443",
        },
    }
    tags = detect_encapsulation(layers)
    assert not any("CAPWAP" in t for t in tags)


def test_fortinet_vendor_extension_detected():
    """Fortinet : le post-dissecteur Lua ajoute une couche
    'fortinet_capwap' dans la sortie EK. detect_encapsulation doit
    ajouter le tag 'CAPWAP(Fortinet)' en plus du tag CAPWAP data."""
    layers = {
        "capwap_data": {"capwap_capwap_preamble_type": "0"},
        "fortinet_capwap": {
            "fortinet_capwap_vendor_id": "12356",
            "fortinet_capwap_payload_type": "0x0004",
            "fortinet_capwap_wtp_serial": "FGT-AP-1234",
        },
        "frame": {"frame_frame_protocols": "eth:ip:udp:capwap.data:fortinet_capwap"},
    }
    tags = detect_encapsulation(layers)
    assert "CAPWAP(decapsule)" in tags or "CAPWAP?(non decode)" in tags
    assert "CAPWAP(Fortinet)" in tags


def test_fortinet_extension_alone_without_capwap_not_tagged():
    """Une couche 'fortinet_capwap' sans CAPWAP data/controle ne doit
    pas produire de tag CAPWAP (cas defensif)."""
    layers = {
        "fortinet_capwap": {
            "fortinet_capwap_vendor_id": "12356",
        },
    }
    tags = detect_encapsulation(layers)
    assert not any("CAPWAP" in t for t in tags)
