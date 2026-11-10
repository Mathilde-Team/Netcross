# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests de l'extraction des pcap de preuve par constat (issue #1081) :
chaque trame citee en preuve doit se retrouver dans l'extrait du bon
point, avec un commentaire de paquet indiquant le constat."""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from types import SimpleNamespace

from netcross_core.extract.evidence_pcaps import (
    CONTEXTE_DEFAUT,
    extraire_preuves_pcaps,
)
from netcross_report.html_report import DATA_ELEMENT_ID, render_html_report

# -- fabricants de captures ---------------------------------------------------


def _pcap(chemin: Path, n: int = 10, marqueur: int = 0xAA) -> Path:
    """Capture pcap classique de ``n`` trames Ethernet (identifiant de
    trame dans les 2 premiers octets, marqueur pour distinguer les
    fichiers entre eux)."""
    with open(chemin, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i in range(1, n + 1):
            donnees = struct.pack("!HH", i, i + 1) + bytes([marqueur] * (40 + i))
            f.write(struct.pack("<IIII", 1700000000 + i, i * 1000, len(donnees), len(donnees)))
            f.write(donnees)
    return chemin


def _pcapng(chemin: Path, n: int = 6, tsresol_ns: bool = False) -> Path:
    """Capture pcapng de ``n`` EPB, resolution nanoseconde optionnelle."""
    with open(chemin, "wb") as f:
        f.write(struct.pack("<II", 0x0A0D0D0A, 32))
        f.write(b"\x4d\x3c\x2b\x1a" + struct.pack("<HHQ", 1, 0, 0xFFFFFFFFFFFFFFFF))
        f.write(b"\x00\x00\x00\x00" * 2)
        idb = struct.pack("<HHI", 1, 0, 65535)
        if tsresol_ns:
            idb += struct.pack("<HH", 9, 1) + b"\x09\x00\x00\x00"
        idb += b"\x00\x00\x00\x00"
        total_idb = 8 + len(idb) + 4
        f.write(struct.pack("<II", 1, total_idb) + idb + struct.pack("<I", total_idb))
        for i in range(1, n + 1):
            donnees = struct.pack("!HH", i, i + 1) + bytes([0xBB] * 28)
            ts = (
                (1700000000 + i) * 1_000_000_000 + i * 1_000_000
                if tsresol_ns
                else (1700000000 + i) * 1_000_000 + i * 1000
            )
            corps = struct.pack("<IIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(donnees)) + donnees
            corps += b"\x00\x00\x00\x00"
            total = 8 + len(corps) + 4
            f.write(struct.pack("<II", 6, total) + corps + struct.pack("<I", total))
    return chemin


def _lire_epb(chemin: Path) -> list[dict]:
    """EPB d'un pcapng : horodatage (microsecondes), donnees,
    commentaires de paquet."""
    brut = chemin.read_bytes()
    pos, epbs = 0, []
    while pos < len(brut):
        type_bloc, total = struct.unpack_from("<II", brut, pos)
        assert total % 4 == 0, "bloc pcapng non aligne"
        corps = brut[pos + 8 : pos + total - 4]
        if type_bloc == 6:
            caplen = struct.unpack_from("<I", corps, 12)[0]
            _if_id, ts_haut, ts_bas, _cap = struct.unpack_from("<IIII", corps, 0)
            donnees = corps[16 : 16 + caplen]
            commentaires, o = [], 16 + caplen
            while o + 4 <= len(corps):
                code, lg = struct.unpack_from("<HH", corps, o)
                o += 4
                if code == 0:
                    break
                if code == 1:
                    commentaires.append(corps[o : o + lg].decode("utf-8"))
                o += lg + (-lg % 4)
            epbs.append({"ts": ts_haut * (1 << 32) + ts_bas, "data": donnees, "commentaires": commentaires})
        pos += total
    return epbs


def _constat(point: str, trame: int, **champs) -> dict:
    base = {
        "severity": "P1",
        "category": "TCP",
        "message": "retransmission en rafale",
        "evidence": [{"point": point, "text": f"trame {trame}", "frame_number": trame}],
    }
    base.update(champs)
    return base


# -- extraction ---------------------------------------------------------------


def test_chaque_trame_citee_est_dans_l_extrait_du_bon_point(tmp_path):
    """Critere d'acceptation : la trame de preuve (identifiant dans les
    donnees) est presente dans l'extrait du point cite."""
    source = _pcap(tmp_path / "lan.pcap", marqueur=0xAA)
    source_wan = _pcap(tmp_path / "wan.pcap", n=6, marqueur=0xCC)
    extraits = extraire_preuves_pcaps(
        {"LAN": str(source), "WAN": str(source_wan)},
        [_constat("LAN", 5), _constat("WAN", 2)],
        str(tmp_path / "preuves"),
    )
    par_point = {e["point"]: e["fichier"] for e in extraits}
    lan = _lire_epb(tmp_path / "preuves" / par_point["LAN"])
    wan = _lire_epb(tmp_path / "preuves" / par_point["WAN"])
    assert any(struct.unpack_from("!H", e["data"], 0)[0] == 5 for e in lan)
    assert any(struct.unpack_from("!H", e["data"], 0)[0] == 2 for e in wan)
    # l'extrait de WAN ne contient aucune trame du fichier LAN (marqueur)
    assert all(e["data"][-1] == 0xCC for e in wan)
    assert all(e["data"][-1] == 0xAA for e in lan)


def test_commentaire_de_paquet_indique_le_constat(tmp_path):
    source = _pcap(tmp_path / "lan.pcap")
    extraire_preuves_pcaps({"LAN": str(source)}, [_constat("LAN", 5)], str(tmp_path / "preuves"))
    (epb,) = [e for e in _lire_epb(tmp_path / "preuves" / "constat-001-LAN.pcapng") if e["commentaires"]]
    assert "P1" in epb["commentaires"][0] and "retransmission" in epb["commentaires"][0]
    # les trames de contexte ne portent pas le commentaire
    sans = [e for e in _lire_epb(tmp_path / "preuves" / "constat-001-LAN.pcapng") if not e["commentaires"]]
    assert len(sans) == 2 * CONTEXTE_DEFAUT


def test_contexte_configurable(tmp_path):
    source = _pcap(tmp_path / "lan.pcap", n=12)
    for contexte, attendu in [(0, 1), (1, 3), (3, 7)]:
        extraire_preuves_pcaps(
            {"LAN": str(source)},
            [_constat("LAN", 6)],
            str(tmp_path / "preuves"),
            contexte=contexte,
        )
        epbs = _lire_epb(tmp_path / "preuves" / "constat-001-LAN.pcapng")
        assert len(epbs) == attendu, f"contexte {contexte}"


def test_trames_dans_l_ordre_chronologique(tmp_path):
    """Les trames voisines encadrent la preuve : l'extrait se lit comme la
    capture, pas comme un tas."""
    source = _pcap(tmp_path / "lan.pcap", n=12)
    extraire_preuves_pcaps({"LAN": str(source)}, [_constat("LAN", 6)], str(tmp_path / "preuves"))
    numeros = [
        struct.unpack_from("!H", e["data"], 0)[0] for e in _lire_epb(tmp_path / "preuves" / "constat-001-LAN.pcapng")
    ]
    assert numeros == [3, 4, 5, 6, 7, 8, 9]


def test_plusieurs_constats_fichiers_distincts(tmp_path):
    """Un pcapng par constat ET par point : deux constats sur le meme
    point donnent deux fichiers."""
    source = _pcap(tmp_path / "lan.pcap", n=12)
    extraire_preuves_pcaps(
        {"LAN": str(source)},
        [_constat("LAN", 3), _constat("LAN", 9, severity="P3", message="perte isolee")],
        str(tmp_path / "preuves"),
    )
    fichiers = sorted(p.name for p in (tmp_path / "preuves").iterdir())
    assert fichiers == ["constat-001-LAN.pcapng", "constat-002-LAN.pcapng"]
    premier = _lire_epb(tmp_path / "preuves" / "constat-001-LAN.pcapng")
    second = _lire_epb(tmp_path / "preuves" / "constat-002-LAN.pcapng")
    assert next(e["data"] for e in premier if e["commentaires"]) != next(e["data"] for e in second if e["commentaires"])


def test_source_pcapng_et_conversion_microsecondes(tmp_path):
    """Une source pcapng (nanosecondes) donne un extrait pcapng en
    microsecondes : l'ordre et les donnees sont conserves."""
    source = _pcapng(tmp_path / "lan.pcapng", n=6, tsresol_ns=False)
    extraire_preuves_pcaps({"LAN": str(source)}, [_constat("LAN", 3)], str(tmp_path / "preuves"))
    epbs = _lire_epb(tmp_path / "preuves" / "constat-001-LAN.pcapng")
    assert len(epbs) == 6  # contexte borde par le debut du fichier
    assert all(struct.unpack_from("!H", e["data"], 0)[0] == i for i, e in enumerate(epbs, 1))


def test_point_sans_fichier_sans_extrait(tmp_path):
    """Une preuve dont le point n'a pas de fichier source reste sans
    extrait : rien n'est invente, pas d'erreur."""
    source = _pcap(tmp_path / "lan.pcap")
    extraits = extraire_preuves_pcaps({"LAN": str(source)}, [_constat("WAN", 4)], str(tmp_path / "preuves"))
    assert extraits == []
    assert not (tmp_path / "preuves" / "constat-001-WAN.pcapng").exists()


def test_trame_absente_journalisee_pas_inventee(tmp_path):
    """Un numero de trame inconnu du fichier n'apparait pas dans l'extrait."""
    source = _pcap(tmp_path / "lan.pcap", n=4)
    extraits = extraire_preuves_pcaps({"LAN": str(source)}, [_constat("LAN", 99)], str(tmp_path / "preuves"))
    assert extraits == []
    assert list((tmp_path / "preuves").iterdir()) == []


def test_preuve_de_segment_point_amont(tmp_path):
    """Une preuve de segment ``A -> B`` designe une trame du point amont
    A : l'extrait est pris dans la capture de A."""
    source = _pcap(tmp_path / "amont.pcap", n=8)
    extraits = extraire_preuves_pcaps({"A": str(source)}, [_constat("A -> B", 3)], str(tmp_path / "preuves"))
    assert [e["point"] for e in extraits] == ["A"]
    assert any(
        struct.unpack_from("!H", e["data"], 0)[0] == 3 for e in _lire_epb(tmp_path / "preuves" / "constat-001-A.pcapng")
    )


def test_findings_objets_au_lieu_de_dicts(tmp_path):
    """Les Finding du rapport (EvidenceLink avec .packet.frame_number)
    sont acceptes directement."""
    source = _pcap(tmp_path / "lan.pcap")
    constat = SimpleNamespace(
        severity="P2",
        category="DNS",
        message="resolution lente",
        evidence=[
            SimpleNamespace(
                point="LAN",
                text="trame 2",
                packet=SimpleNamespace(frame_number=2),
            )
        ],
    )
    extraits = extraire_preuves_pcaps({"LAN": str(source)}, [constat], str(tmp_path / "preuves"))
    assert extraits[0]["ref"] == "LAN#2"
    assert (tmp_path / "preuves" / extraits[0]["fichier"]).is_file()


def test_references_relatives_pour_le_rapport(tmp_path):
    """Les entrees renvoyees alimentent la cle ``evidence_pcaps`` du
    rapport : ref/point/frame_number/fichier relatif au dossier."""
    source = _pcap(tmp_path / "lan.pcap")
    extraits = extraire_preuves_pcaps(
        {"LAN": str(source), "DC": str(_pcap(tmp_path / "dc.pcap"))},
        [_constat("LAN", 4), _constat("DC", 7)],
        str(tmp_path / "preuves"),
    )
    refs = {(e["ref"], e["fichier"]) for e in extraits}
    assert ("LAN#4", "constat-001-LAN.pcapng") in refs
    assert ("DC#7", "constat-002-DC.pcapng") in refs
    for e in extraits:
        assert "/" not in e["fichier"]


def test_nom_de_fichier_slugifie(tmp_path):
    source = _pcap(tmp_path / "lan.pcap")
    extraits = extraire_preuves_pcaps(
        {"Point: amont/1": str(source)}, [_constat("Point: amont/1", 2)], str(tmp_path / "preuves")
    )
    assert extraits[0]["fichier"] == "constat-001-Point_amont_1.pcapng"


# -- anonymisation des extraits (issue #1083) ---------------------------------


def _trame_ethernet_ipv4(src_ip: str, dst_ip: str, marqueur: bytes = b"") -> bytes:
    """Trame Ethernet + IPv4 minimaliste (proto TCP) avec les adresses
    donnees -- les octets MAC/IP reels sont ce que la table de pseudonymes
    doit remplacer."""
    entete_ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(marqueur),
        1,
        0,
        64,
        6,
        0,
        bytes(int(x) for x in src_ip.split(".")),
        bytes(int(x) for x in dst_ip.split(".")),
    )
    # MAC reelles (f8:1e:...): hors de la plage des pseudonymes MAC
    # (02:00:00:00:00:XX), pour distinguer les deux dans les assertions.
    return bytes.fromhex("f81e34abcd01") + bytes.fromhex("f81e34abcd02") + b"\x08\x00" + entete_ip + marqueur


def _pcap_ethernet(chemin: Path, trames: list[bytes]) -> Path:
    with open(chemin, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, trame in enumerate(trames, 1):
            f.write(struct.pack("<IIII", 1700000000 + i, i * 1000, len(trame), len(trame)))
            f.write(trame)
    return chemin


def test_redact_les_adresses_des_extraits_sont_pseudonymisees(tmp_path):
    """Issue #1083 : avec --redact, aucune adresse reelle (IP ou MAC) ne
    doit figurer dans les extraits -- memes pseudonymes que le rapport."""
    import socket

    from netcross_core.redact import AddressRedactor

    source = _pcap_ethernet(
        tmp_path / "lan.pcap",
        [_trame_ethernet_ipv4("192.168.1.10", "192.168.1.11", b"preuve") for _ in range(4)],
    )
    redactor = AddressRedactor()
    redactor.redact([])
    extraits = extraire_preuves_pcaps(
        {"LAN": str(source)},
        [_constat("LAN", 3)],
        str(tmp_path / "preuves"),
        redactor=redactor,
    )
    assert extraits
    for epb in _lire_epb(tmp_path / "preuves" / "constat-001-LAN.pcapng"):
        assert socket.inet_aton("192.168.1.10") not in epb["data"]
        assert socket.inet_aton("192.168.1.11") not in epb["data"]
        assert bytes.fromhex("f81e34abcd01") not in epb["data"]
        assert bytes.fromhex("f81e34abcd02") not in epb["data"]
        # des adresses de pseudonymes (plages RFC 5737) y figurent
        assert socket.inet_aton("192.0.2.1") in epb["data"] or socket.inet_aton("192.0.2.2") in epb["data"]
    # la charge utile (marqueur) est conservee : elle fait partie de la preuve
    trames = [e["data"] for e in _lire_epb(tmp_path / "preuves" / "constat-001-LAN.pcapng")]
    assert any(b"preuve" in t for t in trames)


def test_redact_portee_noms_les_adresses_restant_reelles(tmp_path):
    """--redact-scope noms : la table ne touche pas les adresses, les
    extraits gardent les adresses reelles (meme perimetre que le rapport)."""
    import socket

    from netcross_core.redact import SCOPE_NAMES, AddressRedactor

    trames = [_trame_ethernet_ipv4("192.168.1.10", "192.168.1.11", b"preuve") for _ in range(4)]
    source = _pcap_ethernet(tmp_path / "lan.pcap", trames)
    extraits = extraire_preuves_pcaps(
        {"LAN": str(source)},
        [_constat("LAN", 3)],
        str(tmp_path / "preuves"),
        redactor=AddressRedactor(scope=SCOPE_NAMES),
    )
    assert extraits
    for epb in _lire_epb(tmp_path / "preuves" / "constat-001-LAN.pcapng"):
        assert socket.inet_aton("192.168.1.10") in epb["data"]  # inchangée : portée « noms »


def test_sans_redact_les_extraits_sont_copies_telles_quelles(tmp_path):
    """Sans table (defaut), les trames sont recopies telles quelles."""
    import socket

    trames = [_trame_ethernet_ipv4("192.168.1.10", "192.168.1.11", b"preuve") for _ in range(4)]
    source = _pcap_ethernet(tmp_path / "lan.pcap", trames)
    extraits = extraire_preuves_pcaps(
        {"LAN": str(source)},
        [_constat("LAN", 3)],
        str(tmp_path / "preuves"),
    )
    assert extraits
    for epb in _lire_epb(tmp_path / "preuves" / "constat-001-LAN.pcapng"):
        assert socket.inet_aton("192.168.1.10") in epb["data"]


# -- integration rapport JSON / HTML ------------------------------------------


def _doc_avec_extrait(evidence_pcaps):
    from netcross_core.expert_model import EvidenceLink, PacketEvidence
    from netcross_core.models import Report
    from netcross_report.json_report import build_json_report_document
    from netcross_report.synthesis import Finding

    r = Report(points=["LAN", "WAN"])
    constat = Finding(
        "P1",
        "TCP",
        "LAN->WAN",
        "retransmission",
        evidence=[EvidenceLink("LAN", "trame 5", packet=PacketEvidence("LAN", 5))],
    )
    return build_json_report_document(r, title="Extraction", findings=[constat], evidence_pcaps=evidence_pcaps)


def test_le_rapport_json_porte_les_references_des_extraits(tmp_path):
    source = _pcap(tmp_path / "lan.pcap")
    extraits = extraire_preuves_pcaps({"LAN": str(source)}, [_constat("LAN", 5)], str(tmp_path / "preuves"))
    doc = _doc_avec_extrait(extraits)
    assert doc["evidence_pcaps"] == extraits
    assert doc["evidence_pcaps"][0]["fichier"] == "constat-001-LAN.pcapng"


def test_le_rapport_json_sans_extraits_n_a_pas_la_cle(tmp_path):
    doc = _doc_avec_extrait(None)
    assert "evidence_pcaps" not in doc


def test_le_html_reference_les_extraits_par_liens_relatifs(tmp_path):
    """Critere d'acceptation : liens relatifs depuis le HTML, dans le rendu
    statique noscript ET dans le rendu interactif."""
    source = _pcap(tmp_path / "lan.pcap")
    extraits = extraire_preuves_pcaps({"LAN": str(source)}, [_constat("LAN", 5)], str(tmp_path / "preuves"))
    doc = _doc_avec_extrait(extraits)
    page = render_html_report(doc)
    # noscript : lien relatif vers l'extrait
    noscript = re.search(r"<noscript>(.*)</noscript>", page, re.S).group(1)
    assert 'href="constat-001-LAN.pcapng"' in noscript
    # interactif : le JSON embarque porte les references
    embarque = json.loads(
        re.search(rf'<script type="application/json" id="{DATA_ELEMENT_ID}">(.*?)</script>', page, re.S).group(1)
    )
    assert embarque["evidence_pcaps"] == extraits
    # jamais d'URL absolue
    assert 'href="/' not in noscript
