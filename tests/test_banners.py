# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.application.banners -- tests de l'extraction passive des
bannieres de versions et de la construction de
`Report.service_fingerprints` (CVE-1, issue #135).

Tout est synthetique : les charges utiles sont fabriquees octet par octet
(formats sur le fil documentes : RFC 9110/4253/5321/959/1035, MS-CIFS,
MS-SMB2), aucune capture et aucun tshark -- comme le reste de la suite.
"""

import struct

import pytest
from conftest import make_pkt

from netcross_core.application.banners import MAX_BANNERS_PER_PACKET, build_service_fingerprints, extract_banners
from netcross_core.models import Banner, Report
from netcross_report.security_report import build_security_report


def _found(*args):
    return [(b.service, b.version, b.role) for b in extract_banners(*args)]


# -- HTTP ----------------------------------------------------------------------


def test_http_server_header_donne_un_logiciel_par_jeton_versionne():
    payload = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f\r\nContent-Length: 0\r\n\r\n"
    assert _found("TCP", 80, 51000, payload) == [("Apache", "2.4.41", "server"), ("OpenSSL", "1.1.1f", "server")]


def test_http_server_sans_version_identifie_quand_meme_le_logiciel():
    assert _found("TCP", 80, 51000, b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n") == [("nginx", None, "server")]


def test_http_server_header_insensible_a_la_casse_et_aux_espaces():
    assert _found("TCP", 8080, 51000, b"HTTP/1.0 200 OK\r\nserver:   lighttpd/1.4.55  \r\n\r\n") == [
        ("lighttpd", "1.4.55", "server")
    ]


def test_http_user_agent_est_un_logiciel_client():
    payload = b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/7.68.0\r\n\r\n"
    assert _found("TCP", 51000, 80, payload) == [("curl", "7.68.0", "client")]


def test_http_user_agent_navigateur_ecarte_le_bruit_de_compatibilite():
    payload = b"GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (X11; Linux) Gecko/20100101 Firefox/91.0\r\n\r\n"
    assert _found("TCP", 51000, 80, payload) == [("Firefox", "91.0", "client")]


def test_http_sans_en_tete_server_ne_donne_rien():
    assert _found("TCP", 80, 51000, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n") == []


def test_http_le_server_du_corps_de_reponse_est_ignore():
    payload = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nServer: Apache/9.9.9\r\n"
    assert _found("TCP", 80, 51000, payload) == []


# -- SSH -----------------------------------------------------------------------


def test_ssh_banniere_serveur():
    assert _found("TCP", 22, 51000, b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n") == [("OpenSSH", "8.2p1", "server")]


def test_ssh_banniere_cliente_sur_le_port_22_de_destination():
    assert _found("TCP", 51000, 22, b"SSH-2.0-OpenSSH_for_Windows_8.1\r\n") == [
        ("OpenSSH for Windows", "8.1", "client")
    ]


def test_ssh_logiciel_sans_version():
    assert _found("TCP", 22, 51000, b"SSH-2.0-CustomSSH\r\n") == [("CustomSSH", None, "server")]


# -- SMTP / FTP / IMAP / POP3 ----------------------------------------------------


@pytest.mark.parametrize(
    ("sport", "payload", "expected"),
    [
        (21, b"220 (vsFTPd 3.0.3)\r\n", ("vsftpd", "3.0.3")),
        (21, b"220 ProFTPD 1.3.5 Server (Debian) [10.0.0.1]\r\n", ("ProFTPD", "1.3.5")),
        (21, b"220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------\r\n", ("Pure-FTPd", None)),
        (25, b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", ("Postfix", None)),
        (25, b"220 mx ESMTP Exim 4.94.2 Tue, 22 Sep 2026 10:00:00\r\n", ("Exim", "4.94.2")),
        (587, b"220 smtp.example.com ESMTP Sendmail 8.15.2/8.15.2; Tue, 22 Sep 2026\r\n", ("Sendmail", "8.15.2")),
        (143, b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n", ("Dovecot", None)),
        (143, b"* OK Courier-IMAP ready. Copyright 1998-2011\r\n", ("Courier-IMAP", None)),
        (143, b"* OK example.org Cyrus IMAP 3.0.8 server ready\r\n", ("Cyrus IMAP", "3.0.8")),
        (110, b"+OK Dovecot ready.\r\n", ("Dovecot", None)),
    ],
)
def test_salutations_serveur(sport, payload, expected):
    assert _found("TCP", sport, 51000, payload) == [(*expected, "server")]


def test_salutation_multiligne_seule_la_premiere_ligne_compte():
    assert _found("TCP", 25, 51000, b"220-mail ESMTP Postfix\r\n220 Exim 4.0.0\r\n") == [("Postfix", None, "server")]


def test_nom_de_produit_dans_un_nom_d_hote_n_est_pas_un_produit():
    assert _found("TCP", 25, 51000, b"220 postfix.example.com ESMTP\r\n") == []
    assert _found("TCP", 25, 51000, b"220 postfix-relay.example.com ESMTP\r\n") == []


def test_salutation_hors_port_de_service_ignoree():
    assert _found("TCP", 8080, 51000, b"220 (vsFTPd 3.0.3)\r\n") == []


def test_salutation_envoyee_par_le_client_ignoree():
    assert _found("TCP", 51000, 21, b"220 (vsFTPd 3.0.3)\r\n") == []


# -- DNS version.bind -------------------------------------------------------------


def _dns_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def _version_bind_response(txt, qname="version.bind", qclass=3, flags=0x8400):
    question = _dns_name(qname) + struct.pack("!HH", 16, qclass)
    rdata = bytes([len(txt)]) + txt.encode()
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 16, qclass, 0, len(rdata)) + rdata
    return struct.pack("!HHHHHH", 0x1234, flags, 1, 1, 0, 0) + question + answer


def test_dns_version_bind_udp_donne_bind_et_sa_version():
    assert _found("UDP", 53, 40000, _version_bind_response("9.16.1-Ubuntu")) == [("BIND", "9.16.1", "server")]


def test_dns_version_bind_tcp_avec_prefixe_de_longueur():
    msg = _version_bind_response("9.11.3")
    assert _found("TCP", 53, 40000, struct.pack("!H", len(msg)) + msg) == [("BIND", "9.11.3", "server")]


def test_dns_version_bind_produit_connu():
    assert _found("UDP", 53, 40000, _version_bind_response("dnsmasq-2.80")) == [("dnsmasq", "2.80", "server")]


def test_dns_version_bind_texte_sans_version_ne_donne_rien():
    assert _found("UDP", 53, 40000, _version_bind_response("none of your business")) == []


def test_dns_requete_ignoree_seule_la_reponse_porte_la_version():
    assert _found("UDP", 40000, 53, _version_bind_response("9.16.1", flags=0x0100)) == []


def test_dns_reponse_a_une_autre_question_ignoree():
    assert _found("UDP", 53, 40000, _version_bind_response("9.16.1", qname="example.com", qclass=1)) == []


def test_dns_charge_utile_tronquee_ou_en_boucle_ne_leve_pas():
    full = _version_bind_response("9.16.1")
    for cut in range(len(full)):
        assert isinstance(extract_banners("UDP", 53, 40000, full[:cut]), tuple)
    loop = struct.pack("!HHHHHH", 1, 0x8400, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 16, 3)
    assert _found("UDP", 53, 40000, loop) == []


# -- SMB -----------------------------------------------------------------------


def _smb1(command, words=b"", data=b"", flags2=0x0000):
    header = b"\xffSMB" + bytes([command]) + b"\x00" * 4 + bytes([0x80]) + struct.pack("<H", flags2) + b"\x00" * 20
    assert len(header) == 32
    message = header + bytes([len(words) // 2]) + words + struct.pack("<H", len(data)) + data
    return b"\x00" + len(message).to_bytes(3, "big") + message


def _utf16(text):
    return text.encode("utf-16-le") + b"\x00\x00"


def test_smb1_negotiate_identifie_le_protocole():
    assert _found("TCP", 445, 50000, _smb1(0x72, b"\x00" * 34)) == [("SMB", "1.0", "server")]


def test_smb1_session_setup_ascii_revele_samba_et_sa_version():
    payload = _smb1(0x73, b"\xff\x00\x00\x00\x00\x00", b"Unix\x00Samba 4.9.5-Debian\x00WORKGROUP\x00")
    assert _found("TCP", 445, 50000, payload) == [("SMB", "1.0", "server"), ("Samba", "4.9.5", "server")]
    assert "NativeOS=Unix" in extract_banners("TCP", 445, 50000, payload)[0].raw


def test_smb1_session_setup_unicode_garde_l_os_dans_le_texte_source():
    data = b"\x00" + _utf16("Windows Server 2008 R2 Standard 7601 Service Pack 1") + _utf16("Windows Server 2008 R2")
    banners = extract_banners("TCP", 445, 50000, _smb1(0x73, b"\xff\x00\x00\x00\x00\x00", data + _utf16("W"), 0x8000))
    assert [b.service for b in banners] == ["SMB"]
    assert "Windows Server 2008 R2 Standard 7601 Service Pack 1" in banners[0].raw


def test_smb1_requete_client_ignoree():
    payload = bytearray(_smb1(0x72, b"\x00" * 34))
    payload[4 + 9] = 0x00  # flags : bit reponse a 0
    assert _found("TCP", 445, 50000, bytes(payload)) == []


def test_smb2_negotiate_donne_le_dialecte():
    smb2 = bytearray(b"\xfeSMB" + b"\x00" * 60)
    struct.pack_into("<H", smb2, 12, 0)  # commande NEGOTIATE
    struct.pack_into("<I", smb2, 16, 1)  # reponse serveur
    smb2 += struct.pack("<HHH", 65, 1, 0x0311) + b"\x00" * 10
    assert _found("TCP", 445, 50000, b"\x00" + len(smb2).to_bytes(3, "big") + bytes(smb2)) == [
        ("SMB", "3.1.1", "server")
    ]


# -- robustesse / aucun faux positif ---------------------------------------------


@pytest.mark.parametrize(
    ("proto", "sport", "dport", "payload"),
    [
        ("TCP", 443, 51000, b"\x16\x03\x03\x00\x30" + b"\x00" * 48),  # TLS
        ("TCP", 5432, 51000, b"R\x00\x00\x00\x08\x00\x00\x00\x00"),  # binaire quelconque
        ("UDP", 5060, 5060, b"INVITE sip:bob@example.com SIP/2.0\r\nUser-Agent: Foo/1.0\r\n\r\n"),
        ("UDP", 51000, 443, b"Server: Apache/2.4.41\r\n"),
        ("TCP", 22, 51000, b"pas une banniere SSH\r\n"),
        ("ICMP", 22, 1, b"SSH-2.0-OpenSSH_8.2p1\r\n"),
        ("TCP", 80, 51000, b""),
    ],
)
def test_trafic_sans_banniere_ne_produit_rien(proto, sport, dport, payload):
    assert extract_banners(proto, sport, dport, payload) == ()


def test_octets_aleatoires_ne_levent_jamais():
    import random

    rng = random.Random(1135)
    for _ in range(300):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 120)))
        for proto, sport, dport in (("TCP", 445, 1), ("TCP", 53, 1), ("UDP", 53, 1), ("TCP", 21, 1), ("TCP", 1, 22)):
            assert isinstance(extract_banners(proto, sport, dport, blob), tuple)


def test_nombre_de_bannieres_par_paquet_plafonne():
    tokens = " ".join(f"Prod{i}/1.{i}" for i in range(MAX_BANNERS_PER_PACKET + 5))
    payload = f"HTTP/1.1 200 OK\r\nServer: {tokens}\r\n\r\n".encode()
    assert len(extract_banners("TCP", 80, 51000, payload)) == MAX_BANNERS_PER_PACKET


def test_banner_forme_produit_slash_version():
    assert Banner("http", "Apache", "2.4.41", "x").banner == "Apache/2.4.41"
    assert Banner("http", "nginx", None, "x").banner == "nginx"


# -- consolidation en Report.service_fingerprints ----------------------------------


def _pkt(point="A", src="10.0.0.5", sport=80, banners=(), **kw):
    return make_pkt(point=point, src=src, sport=sport, service_banners=tuple(banners), **kw)


APACHE = Banner("http", "Apache", "2.4.41", "Apache/2.4.41 (Ubuntu)")
CURL = Banner("http", "curl", "7.68.0", "curl/7.68.0", "client")


def test_fingerprints_serveur_porte_hote_et_port_source():
    (fp,) = build_service_fingerprints([_pkt(banners=[APACHE])])
    assert (fp["service"], fp["version"], fp["host"], fp["port"], fp["point"]) == (
        "Apache",
        "2.4.41",
        "10.0.0.5",
        80,
        "A",
    )
    assert (fp["protocol"], fp["role"], fp["banner"]) == ("http", "server", "Apache/2.4.41 (Ubuntu)")


def test_fingerprints_client_n_a_pas_de_port():
    (fp,) = build_service_fingerprints([_pkt(src="10.0.0.9", sport=51234, banners=[CURL])])
    assert (fp["service"], fp["host"], fp["port"], fp["role"]) == ("curl", "10.0.0.9", None, "client")


def test_fingerprints_dedupliques_par_point_hote_port_logiciel_version():
    pkts = [
        _pkt(banners=[APACHE]),
        _pkt(banners=[APACHE]),
        _pkt(sport=8080, banners=[APACHE]),
        _pkt(point="B", banners=[APACHE]),
    ]
    fps = build_service_fingerprints(pkts)
    assert [(f["point"], f["port"]) for f in fps] == [("A", 80), ("A", 8080), ("B", 80)]


def test_fingerprints_garde_le_texte_source_le_plus_long():
    short = Banner("smb", "SMB", "1.0", "SMB1 negotiate response")
    long_ = Banner("smb", "SMB", "1.0", "SMB1 NativeOS=Unix; NativeLanMan=Samba 4.9.5")
    (fp,) = build_service_fingerprints([_pkt(sport=445, banners=[short]), _pkt(sport=445, banners=[long_])])
    assert fp["banner"] == long_.raw


def test_fingerprints_paquets_sans_banniere_donnent_une_liste_vide():
    assert build_service_fingerprints([_pkt(), _pkt(point="B")]) == []


def test_fingerprints_ordre_deterministe():
    pkts = [
        _pkt(point="B", banners=[APACHE]),
        _pkt(point="A", src="10.0.0.6", banners=[APACHE]),
        _pkt(banners=[APACHE]),
    ]
    assert [(f["point"], f["host"]) for f in build_service_fingerprints(pkts)] == [
        ("A", "10.0.0.5"),
        ("A", "10.0.0.6"),
        ("B", "10.0.0.5"),
    ]


def test_fingerprints_alimentent_le_rapport_de_securite():
    """Bout en bout : Pkt -> service_fingerprints -> rapport ; une CVE
    de meme service+version marque le service, une autre version non."""
    r = Report()
    r.service_fingerprints = build_service_fingerprints(
        [_pkt(banners=[APACHE]), _pkt(src="10.0.0.6", banners=[Banner("http", "Apache", "2.4.58", "Apache/2.4.58")])]
    )
    r.security_findings = [
        {"category": "cve", "cve_id": "CVE-2021-41773", "cvss": 7.5, "service": "Apache", "version": "2.4.41"}
    ]
    sr = build_security_report(r)
    assert {(s.host, s.vulnerable) for s in sr.services} == {("10.0.0.5", True), ("10.0.0.6", False)}
    assert sr.dashboard.services_total == 2
    assert sr.dashboard.services_vulnerable == 1
