"""Tests de la reconnaissance de QUIC v2 (RFC 9369) -- issue #1061.

Les vecteurs (secrets, cles, en-tetes, paquet protege complet) sont
recopies tels quels de l'Annexe A de la RFC 9369 :
https://www.rfc-editor.org/rfc/rfc9369.txt -- ils ne sont PAS calcules
par le module teste.
"""

from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from netcross_core import quic_diagnostics as qd
from netcross_core.quic_diagnostics import (
    QUIC_V1,
    QUIC_V2,
    QUIC_V2_INITIAL_SALT,
    QUIC_VERSIONS,
    QuicEvent,
    _decrypt_initial,
    _parse_long_header,
    _remove_header_protection,
    derive_initial_secrets,
    derive_packet_protection_keys,
    diagnose_quic,
    parse_quic_capture,
)

DCID = bytes.fromhex("8394c8f03e515708")

# RFC 9369 Annexe A.1
RFC_CLIENT_INITIAL_SECRET = "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b"
RFC_CLIENT_KEY = "8b1a0bc121284290a29e0971b5cd045d"
RFC_CLIENT_IV = "91f73e2351d8fa91660e909f"
RFC_CLIENT_HP = "45b95e15235d6f45a6b19cbcb0294ba9"
RFC_SERVER_INITIAL_SECRET = "0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1"
RFC_SERVER_KEY = "82db637861d55e1d011f19ea71d5d2a7"
RFC_SERVER_IV = "dd13c276499c0249d3310652"
RFC_SERVER_HP = "edf6d05c83121201b436e16877593c3a"

# RFC 9369 Annexe A.2 : en-tete en clair puis paquet Client Initial protege
RFC_A2_UNPROTECTED_HEADER = "d36b3343cf088394c8f03e5157080000449e00000002"
RFC_A2_PROTECTED_PACKET = bytes.fromhex(
    "d76b3343cf088394c8f03e5157080000449ea0c95e82ffe67b6abcdb4298b485"
    "dd04de806071bf03dceebfa162e75d6c96058bdbfb127cdfcbf903388e99ad04"
    "9f9a3dd4425ae4d0992cfff18ecf0fdb5a842d09747052f17ac2053d21f57c5d"
    "250f2c4f0e0202b70785b7946e992e58a59ac52dea6774d4f03b55545243cf1a"
    "12834e3f249a78d395e0d18f4d766004f1a2674802a747eaa901c3f10cda5500"
    "cb9122faa9f1df66c392079a1b40f0de1c6054196a11cbea40afb6ef5253cd68"
    "18f6625efce3b6def6ba7e4b37a40f7732e093daa7d52190935b8da58976ff33"
    "12ae50b187c1433c0f028edcc4c2838b6a9bfc226ca4b4530e7a4ccee1bfa2a3"
    "d396ae5a3fb512384b2fdd851f784a65e03f2c4fbe11a53c7777c023462239dd"
    "6f7521a3f6c7d5dd3ec9b3f233773d4b46d23cc375eb198c63301c21801f6520"
    "bcfb7966fc49b393f0061d974a2706df8c4a9449f11d7f3d2dcbb90c6b877045"
    "636e7c0c0fe4eb0f697545460c806910d2c355f1d253bc9d2452aaa549e27a1f"
    "ac7cf4ed77f322e8fa894b6a83810a34b361901751a6f5eb65a0326e07de7c12"
    "16ccce2d0193f958bb3850a833f7ae432b65bc5a53975c155aa4bcb4f7b2c4e5"
    "4df16efaf6ddea94e2c50b4cd1dfe06017e0e9d02900cffe1935e0491d77ffb4"
    "fdf85290fdd893d577b1131a610ef6a5c32b2ee0293617a37cbb08b847741c3b"
    "8017c25ca9052ca1079d8b78aebd47876d330a30f6a8c6d61dd1ab5589329de7"
    "14d19d61370f8149748c72f132f0fc99f34d766c6938597040d8f9e2bb522ff9"
    "9c63a344d6a2ae8aa8e51b7b90a4a806105fcbca31506c446151adfeceb51b91"
    "abfe43960977c87471cf9ad4074d30e10d6a7f03c63bd5d4317f68ff325ba3bd"
    "80bf4dc8b52a0ba031758022eb025cdd770b44d6d6cf0670f4e990b22347a7db"
    "848265e3e5eb72dfe8299ad7481a408322cac55786e52f633b2fb6b614eaed18"
    "d703dd84045a274ae8bfa73379661388d6991fe39b0d93debb41700b41f90a15"
    "c4d526250235ddcd6776fc77bc97e7a417ebcb31600d01e57f32162a8560cacc"
    "7e27a096d37a1a86952ec71bd89a3e9a30a2a26162984d7740f81193e8238e61"
    "f6b5b984d4d3dfa033c1bb7e4f0037febf406d91c0dccf32acf423cfa1e70710"
    "10d3f270121b493ce85054ef58bada42310138fe081adb04e2bd901f2f13458b"
    "3d6758158197107c14ebb193230cd1157380aa79cae1374a7c1e5bbcb80ee23e"
    "06ebfde206bfb0fcbc0edc4ebec309661bdd908d532eb0c6adc38b7ca7331dce"
    "8dfce39ab71e7c32d318d136b6100671a1ae6a6600e3899f31f0eed19e3417d1"
    "34b90c9058f8632c798d4490da4987307cba922d61c39805d072b589bd52fdf1"
    "e86215c2d54e6670e07383a27bbffb5addf47d66aa85a0c6f9f32e59d85a44dd"
    "5d3b22dc2be80919b490437ae4f36a0ae55edf1d0b5cb4e9a3ecabee93dfc6e3"
    "8d209d0fa6536d27a5d6fbb17641cde27525d61093f1b28072d111b2b4ae5f89"
    "d5974ee12e5cf7d5da4d6a31123041f33e61407e76cffcdcfd7e19ba58cf4b53"
    "6f4c4938ae79324dc402894b44faf8afbab35282ab659d13c93f70412e85cb19"
    "9a37ddec600545473cfb5a05e08d0b209973b2172b4d21fb69745a262ccde96b"
    "a18b2faa745b6fe189cf772a9f84cbfc"
)
# Debut de la charge CRYPTO en clair (RFC 9369 A.2)
RFC_A2_CRYPTO_PREFIX = "060040f1010000ed0303ebf8fa56f129"


# -- constantes et derivation (A.1) ---------------------------------------------


def test_constantes_v2_publiees_par_la_rfc():
    assert QUIC_V2 == 0x6B3343CF
    assert QUIC_V2_INITIAL_SALT.hex() == "0dede3def700a6db819381be6e269dcbf9bd2ed9"
    assert QUIC_VERSIONS[QUIC_V2].label_prefix == "quicv2"
    assert QUIC_VERSIONS[QUIC_V2].initial_type == 0b01
    assert QUIC_VERSIONS[QUIC_V1].initial_type == 0b00


def test_derive_initial_secrets_v2_vecteur_officiel_a1():
    client_secret, server_secret = derive_initial_secrets(DCID, QUIC_V2)
    assert client_secret.hex() == RFC_CLIENT_INITIAL_SECRET
    assert server_secret.hex() == RFC_SERVER_INITIAL_SECRET


def test_derive_packet_protection_keys_v2_client_et_serveur():
    client_secret, server_secret = derive_initial_secrets(DCID, QUIC_V2)
    assert [x.hex() for x in derive_packet_protection_keys(client_secret, QUIC_V2)] == [
        RFC_CLIENT_KEY,
        RFC_CLIENT_IV,
        RFC_CLIENT_HP,
    ]
    assert [x.hex() for x in derive_packet_protection_keys(server_secret, QUIC_V2)] == [
        RFC_SERVER_KEY,
        RFC_SERVER_IV,
        RFC_SERVER_HP,
    ]


def test_v1_reste_le_defaut_et_differe_de_v2():
    assert derive_initial_secrets(DCID) == derive_initial_secrets(DCID, QUIC_V1)
    assert derive_initial_secrets(DCID)[0] != derive_initial_secrets(DCID, QUIC_V2)[0]


# -- paquet officiel A.2 ----------------------------------------------------------


def test_parse_long_header_reconnait_initial_v2_officiel():
    info = _parse_long_header(RFC_A2_PROTECTED_PACKET)
    assert info == {"version": QUIC_V2, "dcid": DCID, "pn_offset": 18, "remaining_len": 1182}


def test_levee_protection_en_tete_redonne_l_en_tete_en_clair_a2():
    _, _, hp = derive_packet_protection_keys(derive_initial_secrets(DCID, QUIC_V2)[0], QUIC_V2)
    buf = bytearray(RFC_A2_PROTECTED_PACKET)
    assert _remove_header_protection(buf, 18, hp) == 4
    assert bytes(buf[:22]).hex() == RFC_A2_UNPROTECTED_HEADER


def test_dechiffrement_initial_v2_officiel():
    info = _parse_long_header(RFC_A2_PROTECTED_PACKET)
    client_secret, _ = derive_initial_secrets(info["dcid"], info["version"])
    plaintext = _decrypt_initial(RFC_A2_PROTECTED_PACKET, client_secret, info)
    assert plaintext is not None
    assert len(plaintext) == 1162
    assert plaintext.hex().startswith(RFC_A2_CRYPTO_PREFIX)


def test_dechiffrement_v2_avec_cles_v1_echoue():
    info = _parse_long_header(RFC_A2_PROTECTED_PACKET)
    secret_v1, _ = derive_initial_secrets(DCID, QUIC_V1)
    assert _decrypt_initial(RFC_A2_PROTECTED_PACKET, secret_v1, {**info, "version": QUIC_V1}) is None


# -- discrimination des types d'en-tete long --------------------------------------


def _en_tete(first_byte: int, version: int, remaining_len: int = 20) -> bytes:
    header = bytes([first_byte]) + struct.pack("!I", version)
    header += bytes([len(DCID)]) + DCID + b"\x00" + b"\x00"
    header += bytes([0x40 | (remaining_len >> 8), remaining_len & 0xFF])
    return header + b"\x00" * remaining_len


@pytest.mark.parametrize(
    ("first_byte", "version", "attendu"),
    [
        (0xC3, QUIC_V1, True),  # v1 Initial (0b00)
        (0xD3, QUIC_V1, False),  # v1 0-RTT (0b01)
        (0xD3, QUIC_V2, True),  # v2 Initial (0b01)
        (0xC3, QUIC_V2, False),  # v2 Retry (0b00)
        (0xE3, QUIC_V2, False),  # v2 0-RTT (0b10)
        (0xF3, QUIC_V2, False),  # v2 Handshake (0b11)
        (0xC3, 0x709A50C4, False),  # brouillon v2 : non gere
    ],
)
def test_type_initial_depend_de_la_version(first_byte, version, attendu):
    assert (_parse_long_header(_en_tete(first_byte, version)) is not None) is attendu


# -- aller-retour synthetique v2 --------------------------------------------------


def _initial_v2_chiffre(plaintext: bytes, packet_number: int = 7) -> bytes:
    key, iv, hp = derive_packet_protection_keys(derive_initial_secrets(DCID, QUIC_V2)[0], QUIC_V2)
    pn = packet_number.to_bytes(1, "big")
    remaining = len(pn) + len(plaintext) + 16
    fixe = _en_tete(0xD0, QUIC_V2, remaining)[:-remaining]  # pn_length = 1
    nonce = bytes(a ^ b for a, b in zip(iv, packet_number.to_bytes(12, "big"), strict=True))
    buf = bytearray(fixe + pn + AESGCM(key).encrypt(nonce, plaintext, fixe + pn))
    pn_offset = len(fixe)
    sample = bytes(buf[pn_offset + 4 : pn_offset + 20])
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    buf[0] ^= mask[0] & 0x0F
    buf[pn_offset] ^= mask[1]
    return bytes(buf)


def test_aller_retour_synthetique_v2():
    clair = b"\x01\x00\x00\x08trame CRYPTO simulee v2"
    paquet = _initial_v2_chiffre(clair)
    info = _parse_long_header(paquet)
    assert info["version"] == QUIC_V2
    secret, _ = derive_initial_secrets(info["dcid"], QUIC_V2)
    assert _decrypt_initial(paquet, secret, info) == clair


# -- parse_quic_capture -----------------------------------------------------------


def _raw(payload: bytes) -> SimpleNamespace:
    return SimpleNamespace(
        ts=1.0, proto="UDP", src="10.0.0.1", dst="10.0.0.2", sport=4433, dport=443, length=len(payload), payload=payload
    )


def test_parse_quic_capture_initial_v2_officiel_sni(monkeypatch):
    monkeypatch.setattr("pcap_parser.parse_capture", lambda path, raise_on_error=False: [_raw(RFC_A2_PROTECTED_PACKET)])
    events = parse_quic_capture("A", "/fake/v2.pcap")
    assert len(events) == 1
    ev = events[0]
    assert ev.quic_version == "v2"
    assert ev.decryptable is True
    assert ev.sni == "example.com"
    assert ev.dcid == DCID


def test_parse_quic_capture_initial_v2_non_dechiffrable(monkeypatch):
    paquet = bytearray(RFC_A2_PROTECTED_PACKET)
    paquet[-1] ^= 0xFF  # tag GCM corrompu
    monkeypatch.setattr("pcap_parser.parse_capture", lambda path, raise_on_error=False: [_raw(bytes(paquet))])
    events = parse_quic_capture("A", "/fake/v2.pcap")
    assert len(events) == 1
    assert events[0].quic_version == "v2"
    assert events[0].decryptable is False
    assert events[0].sni is None


# -- diagnose_quic ------------------------------------------------------------------


def _ev(point: str, version: str = "v2", **kw) -> QuicEvent:
    base = {
        "point": point,
        "ts": 0.0,
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "sport": 1,
        "dport": 443,
        "dcid": b"\x01",
        "decryptable": True,
        "sni": "example.com",
        "quic_version": version,
    }
    base.update(kw)
    return QuicEvent(**base)


def test_quic_event_version_par_defaut_v1():
    ev = QuicEvent(point="A", ts=0.0, src="a", dst="b", sport=1, dport=2, dcid=b"", decryptable=False)
    assert ev.quic_version == "v1"


def test_diagnose_v2_vu_partout_libelle_et_constat_version():
    findings = diagnose_quic([_ev("A"), _ev("B")], ["A", "B"])
    messages = [f.message for f in findings]
    assert any("ClientHello QUIC v2 (SNI example.com) vu a tous les points" in m for m in messages)
    v2 = [f for f in findings if "RFC 9369" in f.message]
    assert [(f.segment, f.severity) for f in v2] == [("A", "info"), ("B", "info")]
    assert "0x6b3343cf" in v2[0].message


def test_diagnose_v2_disparition_libelle():
    findings = diagnose_quic([_ev("A")], ["A", "B"])
    assert any("ClientHello QUIC v2 (SNI example.com) vu jusqu'a A" in f.message for f in findings)


def test_diagnose_v1_messages_inchanges_sans_constat_v2():
    findings = diagnose_quic([_ev("A", "v1"), _ev("B", "v1")], ["A", "B"])
    assert any("ClientHello QUIC (SNI example.com)" in f.message for f in findings)
    assert not any("RFC 9369" in f.message for f in findings)


def test_diagnose_v2_sans_ordre_de_points():
    findings = diagnose_quic([_ev("A", decryptable=False, sni=None), _ev("A", decryptable=False, sni=None)])
    v2 = [f for f in findings if "RFC 9369" in f.message]
    assert len(v2) == 1
    assert v2[0].message.startswith("2 paquet(s) Initial QUIC v2")


def test_print_quic_report_sans_trafic(capsys):
    qd.print_quic_diagnostics([])
    assert "aucun trafic QUIC Initial (v1 ou v2) detecte" in capsys.readouterr().out
