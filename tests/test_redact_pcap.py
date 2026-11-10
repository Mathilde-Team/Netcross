# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.redact_pcap -- réécriture pcapng anonymisée (#1157).

Couvre la réécriture au niveau des octets : adresses MAC/IP remplacées par
les pseudonymes du run, charges utiles zéroées par défaut (longueurs
conservées), sommes de contrôle recalculées (aucun « bad checksum » ajouté),
horodatages conservés ou décalés uniformément, cohérence multi-points
(même hôte => même pseudonyme sur chaque pcap produit), équivalence des
constats original/anonymisé (via tshark, comme le reste de la suite) et le
câblage CLI --redact --redact-pcap.
"""

import struct
from pathlib import Path

import pytest

from netcross_core.redact import AddressRedactor
from netcross_core.redact_pcap import _iterer_trames, ecrire_pcapng_anonymise

CLIENT_IP = "10.0.0.5"
SERVEUR_IP = "93.184.216.34"
# MAC « constructeur » (hors espace des pseudonymes 02:00:00:xx:xx:xx).
CLIENT_MAC = b"\x3c\x22\xfb\x11\x22\x33"
SERVEUR_MAC = b"\x3c\x22\xfb\x44\x55\x66"


def _somme(donnees: bytes) -> int:
    """RFC 1071, indépendante du module testé."""
    if len(donnees) % 2:
        donnees += b"\x00"
    total = sum(struct.unpack(f"!{len(donnees) // 2}H", donnees))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ip_bytes(adresse: str) -> bytes:
    return bytes(int(o) for o in adresse.split("."))


def _trame_tcp(src_ip: str, dst_ip: str, charge: bytes, ident: int = 1) -> bytes:
    """Trame Ethernet/IPv4/TCP avec sommes de contrôle justes."""
    tcp = struct.pack("!HHIIBBHHH", 44000, 443, 1000, 0, 5 << 4, 0x18, 65535, 0, 0) + charge
    pseudo = _ip_bytes(src_ip) + _ip_bytes(dst_ip) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", _somme(pseudo + tcp)) + tcp[18:]
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        ident,
        0x4000,
        64,
        6,
        0,
        _ip_bytes(src_ip),
        _ip_bytes(dst_ip),
    )
    ip = ip[:10] + struct.pack("!H", _somme(ip)) + ip[12:]
    return SERVEUR_MAC + CLIENT_MAC + b"\x08\x00" + ip + tcp


def _ecrire_pcap(capture: Path, trames: list[bytes], ts_base: float = 1_700_000_000.0) -> None:
    with capture.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, trame in enumerate(trames):
            f.write(struct.pack("<IIII", int(ts_base), i * 1000, len(trame), len(trame)))
            f.write(trame)


def _lire_pcapng(chemin: Path):
    """Renvoie [(ts, len, linktype, trame)] d'un pcapng écrit par le module."""
    return list(_iterer_trames(str(chemin)))


def _redactor():
    return AddressRedactor(scope="adresses")


# ---------------------------------------------------------------------
# Réécriture d'une trame
# ---------------------------------------------------------------------


def test_adresses_mac_ip_remplacees_et_longueurs_conservees(tmp_path):
    capture = tmp_path / "a.pcap"
    _ecrire_pcap(capture, [_trame_tcp(CLIENT_IP, SERVEUR_IP, b"donnees secretes")])
    redactor = _redactor()
    sortie = ecrire_pcapng_anonymise("A", [str(capture)], redactor, tmp_path / "A.pcapng")

    trames = _lire_pcapng(sortie)
    assert len(trames) == 1
    _ts, longueur, _linktype, trame = trames[0]
    assert longueur == 14 + 20 + 20 + len(b"donnees secretes")
    assert len(trame) == longueur  # charge utile zéroée en place, taille identique
    assert bytes(trame[0:6]) != SERVEUR_MAC
    assert bytes(trame[6:12]) != CLIENT_MAC
    ip_src = ".".join(str(b) for b in trame[26:30])
    ip_dst = ".".join(str(b) for b in trame[30:34])
    assert ip_src != CLIENT_IP
    assert ip_dst != SERVEUR_IP
    mapping = redactor.mapping
    assert ip_src == mapping[CLIENT_IP]
    assert ip_dst == mapping[SERVEUR_IP]


def test_charge_utile_zeroee_par_defaut_et_conservee_sur_option(tmp_path):
    capture = tmp_path / "a.pcap"
    _ecrire_pcap(capture, [_trame_tcp(CLIENT_IP, SERVEUR_IP, b"donnees secretes")])
    redactor = _redactor()

    zero = ecrire_pcapng_anonymise("A", [str(capture)], redactor, tmp_path / "zero.pcapng")
    _ts, _l, _lt, trame = _lire_pcapng(zero)[0]
    assert bytes(trame[54:]) == b"\x00" * len(b"donnees secretes")

    garde = ecrire_pcapng_anonymise("A", [str(capture)], _redactor(), tmp_path / "garde.pcapng", garder_payload=True)
    _ts, _l, _lt, trame_garde = _lire_pcapng(garde)[0]
    assert bytes(trame_garde[54:]) == b"donnees secretes"


def test_sommes_de_controle_valides(tmp_path):
    """Aucun « bad checksum » ajouté : IPv4 et TCP recalculés justes."""
    capture = tmp_path / "a.pcap"
    _ecrire_pcap(
        capture,
        [
            _trame_tcp(CLIENT_IP, SERVEUR_IP, b"charge", ident=1),
            _trame_tcp(SERVEUR_IP, CLIENT_IP, b"reponse plus longue", ident=2),
        ],
    )
    sortie = ecrire_pcapng_anonymise("A", [str(capture)], _redactor(), tmp_path / "A.pcapng")
    for _ts, _l, _lt, trame in _lire_pcapng(sortie):
        ip = bytes(trame[14:])
        assert _somme(ip[:20]) == 0  # somme d'en-tête IPv4 nulle = juste
        tcp = ip[20:]
        src, dst = ip[12:16], ip[16:20]
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp))
        assert _somme(pseudo + tcp) == 0  # somme TCP juste


def test_horodatages_conservees_puis_decalees_uniformement(tmp_path):
    capture = tmp_path / "a.pcap"
    _ecrire_pcap(capture, [_trame_tcp(CLIENT_IP, SERVEUR_IP, b"x"), _trame_tcp(SERVEUR_IP, CLIENT_IP, b"y", ident=2)])

    conserve = ecrire_pcapng_anonymise("A", [str(capture)], _redactor(), tmp_path / "c.pcapng")
    ts = [t for t, *_ in _lire_pcapng(conserve)]
    assert ts[0] == pytest.approx(1_700_000_000.0, abs=1e-5)
    assert ts[1] == pytest.approx(1_700_000_000.001, abs=1e-5)

    decale = ecrire_pcapng_anonymise("A", [str(capture)], _redactor(), tmp_path / "d.pcapng", decalage=-3600.0)
    ts2 = [t for t, *_ in _lire_pcapng(decale)]
    assert ts2[0] == pytest.approx(1_700_000_000.0 - 3600.0, abs=1e-4)
    # L'écart entre paquets est conservé (le décalage est uniforme).
    assert abs((ts2[1] - ts2[0]) - (ts[1] - ts[0])) < 1e-4


def test_meme_hote_meme_pseudonyme_sur_chaque_point(tmp_path):
    """Deux points qui voient le même hôte : pseudonyme identique dans les
    deux pcapng produits (critère d'acceptation de #1157)."""
    point_a = tmp_path / "a.pcap"
    point_b = tmp_path / "b.pcap"
    _ecrire_pcap(point_a, [_trame_tcp(CLIENT_IP, SERVEUR_IP, b"x")])
    _ecrire_pcap(point_b, [_trame_tcp(CLIENT_IP, "10.0.0.9", b"y", ident=7)])
    redactor = _redactor()

    sortie_a = ecrire_pcapng_anonymise("A", [str(point_a)], redactor, tmp_path / "A.pcapng")
    sortie_b = ecrire_pcapng_anonymise("B", [str(point_b)], redactor, tmp_path / "B.pcapng")

    src_a = bytes(_lire_pcapng(sortie_a)[0][3][26:30])
    src_b = bytes(_lire_pcapng(sortie_b)[0][3][26:30])
    assert src_a == src_b


def test_plusieurs_fichiers_d_un_meme_point_fusionnes(tmp_path):
    un = tmp_path / "a1.pcap"
    deux = tmp_path / "a2.pcap"
    _ecrire_pcap(un, [_trame_tcp(CLIENT_IP, SERVEUR_IP, b"x")])
    _ecrire_pcap(deux, [_trame_tcp(SERVEUR_IP, CLIENT_IP, b"y", ident=2)], ts_base=1_700_000_100.0)
    sortie = ecrire_pcapng_anonymise("A", [str(un), str(deux)], _redactor(), tmp_path / "A.pcapng")
    assert len(_lire_pcapng(sortie)) == 2


def test_libpcap_indisponible_remonte_lerreur(monkeypatch):
    import netcross_core.redact_pcap as module

    def _introuvable():
        raise module.LibpcapIndisponibleError("absente")

    monkeypatch.setattr(module, "_charger_libpcap", _introuvable)
    with pytest.raises(module.LibpcapIndisponibleError):
        list(module._iterer_trames("/inexistant.pcap"))


# ---------------------------------------------------------------------
# Équivalence des constats (nécessite tshark, comme le reste de la suite)
# ---------------------------------------------------------------------


def test_equivalence_des_constats_original_anonymise(tmp_path):
    """L'analyse du pcap anonymisé donne les mêmes constats réseau :
    protocoles, ports, longueurs, séquences, drapeaux -- pseudonymes mis à
    part. Les noms applicatifs ne sont PAS comparés (charges utiles
    zéroées par défaut, c'est le comportement demandé par #1157)."""
    import shutil

    if shutil.which("tshark") is None:
        pytest.skip("tshark absent")
    from pcap_parser import parse_capture

    trames = [
        _trame_tcp(CLIENT_IP, SERVEUR_IP, b"charge applicative", ident=1),
        _trame_tcp(SERVEUR_IP, CLIENT_IP, b"reponse", ident=2),
    ]
    capture = tmp_path / "original.pcap"
    _ecrire_pcap(capture, trames)
    redactor = _redactor()
    sortie = ecrire_pcapng_anonymise("A", [str(capture)], redactor, tmp_path / "A.pcapng")

    avant = parse_capture(str(capture))
    apres = parse_capture(str(sortie))
    assert len(avant) == len(apres) == 2
    mapping = redactor.mapping
    for p1, p2 in zip(avant, apres, strict=True):
        assert p1.proto == p2.proto
        assert p1.sport == p2.sport
        assert p1.dport == p2.dport
        assert p1.length == p2.length
        assert p1.seq == p2.seq
        assert p2.src == mapping[p1.src]
        assert p2.dst == mapping[p1.dst]


def test_cli_redact_pcap_ecrit_les_pcaps_par_point(monkeypatch, tmp_path, capsys):
    """--redact --redact-pcap DOSSIER : un pcapng par point, aucune adresse
    réelle dedans (relu et comparé à la table)."""
    import sys

    import cross_capture_analyzer_cli as cli

    capture = tmp_path / "a.pcap"
    _ecrire_pcap(capture, [_trame_tcp(CLIENT_IP, SERVEUR_IP, b"secret")])
    dossier = tmp_path / "partage"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cross_capture_analyzer_cli.py",
            "--capture",
            f"A={capture}",
            "--redact",
            "--redact-pcap",
            str(dossier),
        ],
    )
    code = cli.main()
    assert code in (0, None)
    produit = dossier / "A.pcapng"
    assert produit.exists()
    trames = _lire_pcapng(produit)
    assert trames
    for _ts, _l, _lt, trame in trames:
        ip_src = ".".join(str(b) for b in trame[26:30])
        assert ip_src not in (CLIENT_IP, SERVEUR_IP)
    assert f"Capture anonymisee ecrite dans {produit}" in capsys.readouterr().out


def test_cli_redact_pcap_sans_redact_refuse(monkeypatch, tmp_path, capsys):
    import sys

    import cross_capture_analyzer_cli as cli

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cross_capture_analyzer_cli.py",
            "--capture",
            f"A={tmp_path / 'a.pcap'}",
            "--redact-pcap",
            str(tmp_path / "out"),
        ],
    )
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    assert "--redact-pcap necessite --redact" in capsys.readouterr().err
