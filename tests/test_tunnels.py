# SPDX-License-Identifier: GPL-3.0-or-later
"""
pcap_parser.tunnels -- detection de la pile d'encapsulation et choix de
la couche IP/TCP/UDP/ICMP la plus interne. Le format textuel des tags
(VLAN100, GRE, VXLAN(vni=...), ...) est un contrat implicite avec les
rapports/baselines existants (voir claude.md, Session 1) : ce module ne
doit pas y toucher sans le vouloir explicitement.
"""

from pcap_parser.tunnels import detect_encapsulation, is_tunnel, select_innermost_layers


def test_is_tunnel_faux_sans_couche_tunnel():
    assert is_tunnel({"ip": {}, "tcp": {}}) is False


def test_is_tunnel_vrai_avec_gre():
    assert is_tunnel({"gre": {}}) is True


def test_is_tunnel_vlan_seul_n_est_pas_un_tunnel():
    # VLAN ne re-encapsule pas une nouvelle paire IP -- distinction
    # documentee explicitement dans le module.
    assert is_tunnel({"vlan": {}}) is False


def test_detect_encapsulation_vide_sans_rien():
    assert detect_encapsulation({}) == ()


def test_detect_encapsulation_vlan_simple():
    layers = {"vlan": {"vlan_vlan_id": "100"}}
    assert detect_encapsulation(layers) == ("VLAN100",)


def test_detect_encapsulation_qinq_double_vlan():
    layers = {"vlan": [{"vlan_vlan_id": "100"}, {"vlan_vlan_id": "200"}]}
    assert detect_encapsulation(layers) == ("VLAN100", "VLAN200")


def test_detect_encapsulation_mpls_empile():
    layers = {"mpls": [{"mpls_mpls_label": "100"}, {"mpls_mpls_label": "200"}]}
    assert detect_encapsulation(layers) == ("MPLS[100,200]",)


def test_detect_encapsulation_gre():
    assert detect_encapsulation({"gre": {}}) == ("GRE",)


def test_detect_encapsulation_vxlan_avec_vni():
    layers = {"vxlan": {"vxlan_vxlan_vni": "4242"}}
    assert detect_encapsulation(layers) == ("VXLAN(vni=4242)",)


def test_detect_encapsulation_gtp_avec_teid_hex():
    layers = {"gtp": {"gtp_gtp_teid": "0x000004d2"}}
    assert detect_encapsulation(layers) == ("GTP-U(teid=1234)",)


def test_detect_encapsulation_erspan():
    assert detect_encapsulation({"erspan": {}}) == ("ERSPAN",)


def test_detect_encapsulation_capwap_controle():
    assert detect_encapsulation({"capwap_control": {}}) == ("CAPWAP(controle)",)


def test_detect_encapsulation_capwap_data_decapsule():
    layers = {
        "capwap_data": {"capwap_capwap_preamble_type": "0"},
        "frame": {"frame_frame_protocols": "eth:ethertype:ip:udp:capwap.data:eth:ip:tcp"},
    }
    assert detect_encapsulation(layers) == ("CAPWAP(decapsule)",)


def test_detect_encapsulation_capwap_data_non_decode():
    layers = {
        "capwap_data": {"capwap_capwap_preamble_type": "0"},
        "frame": {"frame_frame_protocols": "eth:ethertype:ip:udp:capwap.data"},
    }
    assert detect_encapsulation(layers) == ("CAPWAP?(non decode)",)


def test_detect_encapsulation_capwap_data_chiffre_dtls():
    layers = {"capwap_data": {"capwap_capwap_preamble_type": "1"}}
    assert detect_encapsulation(layers) == ("CAPWAP(chiffre DTLS)",)


def test_detect_encapsulation_capwap_control_chiffre_via_dtls_seul():
    layers = {
        "dtls": {},
        "udp": {"udp_udp_srcport": "5246", "udp_udp_dstport": "54321"},
    }
    assert detect_encapsulation(layers) == ("CAPWAP(chiffre DTLS)",)


def test_detect_encapsulation_dtls_hors_ports_capwap_ignore():
    layers = {
        "dtls": {},
        "udp": {"udp_udp_srcport": "44300", "udp_udp_dstport": "44301"},
    }
    assert detect_encapsulation(layers) == ()


def test_detect_encapsulation_capwap_fortinet_extension_detectee():
    # Job 30 (issue #30) -- le post-dissecteur Lua
    # netcross_capwap_fortinet.lua ajoute une couche "fortinet_capwap"
    # quand les extensions vendor-specific Fortinet (vendor ID 12356)
    # sont presentes dans le canal data CAPWAP deja decapsule par
    # tshark. _capwap_tags() doit alors ajouter CAPWAP(Fortinet) en
    # plus du tag CAPWAP standard.
    layers = {
        "capwap_data": {"capwap_capwap_preamble_type": "0"},
        "frame": {"frame_frame_protocols": "eth:ethertype:ip:udp:capwap.data:eth:ip:tcp"},
        "fortinet_capwap": {},
    }
    assert detect_encapsulation(layers) == ("CAPWAP(decapsule)", "CAPWAP(Fortinet)")


def test_detect_encapsulation_capwap_fortinet_sans_couche_capwap_ignore():
    # La couche "fortinet_capwap" seule, sans aucune couche
    # CAPWAP/DTLS associee, ne doit jamais produire de tag : c'est la
    # garde `if "fortinet_capwap" in layers and tags:` de
    # _capwap_tags() qui l'empeche (le post-dissecteur ne peut en
    # pratique jamais s'activer hors du contexte CAPWAP data).
    layers = {"fortinet_capwap": {}}
    assert detect_encapsulation(layers) == ()


def test_detect_encapsulation_pile_combinee_ordre_stable():
    layers = {
        "vlan": {"vlan_vlan_id": "100"},
        "gre": {},
        "vxlan": {"vxlan_vxlan_vni": "42"},
    }
    assert detect_encapsulation(layers) == ("VLAN100", "GRE", "VXLAN(vni=42)")


def test_select_innermost_layers_sans_tunnel_prend_layer_simple():
    layers = {"ip": [{"marker": "outer"}, {"marker": "should-not-happen"}]}
    result = select_innermost_layers(layers)
    assert result["is_tunnel"] is False
    assert result["ip4"] == {"marker": "outer"}


def test_select_innermost_layers_avec_tunnel_prend_la_plus_interne():
    layers = {
        "gre": {},
        "ip": [{"marker": "tunnel-outer"}, {"marker": "vrai-client"}],
        "tcp": [{"marker": "tunnel-tcp"}, {"marker": "vrai-tcp"}],
    }
    result = select_innermost_layers(layers)
    assert result["is_tunnel"] is True
    assert result["ip4"] == {"marker": "vrai-client"}
    assert result["tcp"] == {"marker": "vrai-tcp"}


def test_select_innermost_layers_couches_absentes_sont_none():
    result = select_innermost_layers({"ip": {}})
    assert result["udp"] is None
    assert result["icmp"] is None
    assert result["icmpv6"] is None
    assert result["arp"] is None
    assert result["stp"] is None


def test_select_innermost_layers_icmpv6_sans_tunnel():
    # Session 22 -- meme picker() generique que icmp, juste une nouvelle
    # cle de couche EK ("icmpv6" plutot que "icmp").
    layers = {"ipv6": {}, "icmpv6": {"marker": "icmpv6-simple"}}
    result = select_innermost_layers(layers)
    assert result["icmpv6"] == {"marker": "icmpv6-simple"}


def test_select_innermost_layers_icmpv6_avec_tunnel_prend_la_plus_interne():
    layers = {
        "gre": {},
        "ipv6": [{"marker": "tunnel-outer"}, {"marker": "vrai-client"}],
        "icmpv6": [{"marker": "tunnel-icmpv6"}, {"marker": "vrai-icmpv6"}],
    }
    result = select_innermost_layers(layers)
    assert result["is_tunnel"] is True
    assert result["icmpv6"] == {"marker": "vrai-icmpv6"}


def test_select_innermost_layers_arp_sans_tunnel():
    # Session 24 -- meme picker() generique que icmp/icmpv6, juste une
    # nouvelle cle de couche EK ("arp"). Pas d'"ip"/"ipv6" dans ce cas
    # (une trame ARP n'a structurellement pas d'en-tete IP, RFC 826).
    layers = {"eth": {}, "arp": {"marker": "arp-simple"}}
    result = select_innermost_layers(layers)
    assert result["arp"] == {"marker": "arp-simple"}


def test_select_innermost_layers_arp_avec_tunnel_prend_la_plus_interne():
    # ARP n'est en pratique jamais rencontre a l'interieur d'un tunnel
    # gere ici, mais le picker reste generique (voir docstring de
    # select_innermost_layers) -- verifie par coherence avec icmp/icmpv6.
    layers = {
        "gre": {},
        "arp": [{"marker": "tunnel-arp"}, {"marker": "vrai-arp"}],
    }
    result = select_innermost_layers(layers)
    assert result["is_tunnel"] is True
    assert result["arp"] == {"marker": "vrai-arp"}


def test_select_innermost_layers_stp_sans_tunnel():
    # Session 25 -- meme picker() generique que arp/icmp/icmpv6, juste
    # une nouvelle cle de couche EK ("stp"). Pas d'"ip"/"ipv6" non plus
    # (une trame STP n'a pas d'en-tete IP, IEEE 802.1D).
    layers = {"eth": {}, "llc": {}, "stp": {"marker": "stp-simple"}}
    result = select_innermost_layers(layers)
    assert result["stp"] == {"marker": "stp-simple"}


def test_select_innermost_layers_stp_avec_tunnel_prend_la_plus_interne():
    # STP n'est en pratique jamais rencontre a l'interieur d'un tunnel
    # gere ici, meme raisonnement que ARP -- verifie par coherence.
    layers = {
        "gre": {},
        "stp": [{"marker": "tunnel-stp"}, {"marker": "vrai-stp"}],
    }
    result = select_innermost_layers(layers)
    assert result["is_tunnel"] is True
    assert result["stp"] == {"marker": "vrai-stp"}
