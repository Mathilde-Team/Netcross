# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests de pcap_parser.capture.export_filtered (Job 36, issue #156) et de la
CLI --export-pcap.

Meme convention que test_split_capture.py : par defaut tshark est SIMULE
(monkeypatch de shutil.which + subprocess.run) et on verifie la ligne de
commande construite. Les tests de la derniere section lancent le VRAI
tshark et sont sautes s'il est absent.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest
from pcap_builders import (
    read_pcap,
    synthetic_packets,
    write_pcap,
)

requires_tshark = pytest.mark.skipif(
    shutil.which("tshark") is None,
    reason="tshark non installe",
)


# -- _build_display_filter --------------------------------------------------


def test_build_display_filter_aucun_critere_donne_none():
    from pcap_parser.capture import _build_display_filter

    assert _build_display_filter() is None


def test_build_display_filter_time_start_seul():
    from pcap_parser.capture import _build_display_filter

    f = _build_display_filter(time_start=10.0)
    assert "frame.time_relative >= 10" in f
    assert "frame.time_relative <= " not in f


def test_build_display_filter_time_end_seul():
    from pcap_parser.capture import _build_display_filter

    f = _build_display_filter(time_end=60.0)
    assert "frame.time_relative <= 60" in f


def test_build_display_filter_plage_complete():
    from pcap_parser.capture import _build_display_filter

    f = _build_display_filter(time_start=10.0, time_end=60.0)
    assert "frame.time_relative >= 10" in f
    assert "frame.time_relative <= 60" in f
    assert "&&" in f


def test_build_display_filter_endpoints():
    from pcap_parser.capture import _build_display_filter

    f = _build_display_filter(endpoints=["192.168.1.1", "10.0.0.1"])
    assert "ip.addr == 192.168.1.1" in f
    assert "ip.addr == 10.0.0.1" in f
    assert "||" in f


def test_build_display_filter_combine_tout():
    from pcap_parser.capture import _build_display_filter

    f = _build_display_filter(time_start=5.0, time_end=30.0, endpoints=["192.168.1.1"])
    assert "frame.time_relative >= 5" in f
    assert "frame.time_relative <= 30" in f
    assert "ip.addr == 192.168.1.1" in f


# -- export_filtered : validation des arguments -----------------------------


def test_export_filtered_capture_inexistante(tmp_path):
    from pcap_parser.capture import export_filtered

    with pytest.raises(FileNotFoundError):
        export_filtered(str(tmp_path / "absent.pcap"), str(tmp_path / "out.pcap"))


def test_export_filtered_endpoints_vides_leve_valueerror(tmp_path):
    from pcap_parser.capture import export_filtered

    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))
    with pytest.raises(ValueError, match="endpoints ne peut pas"):
        export_filtered(str(src), str(tmp_path / "out.pcap"), endpoints=[])


def test_export_filtered_time_start_superieur_time_end(tmp_path):
    from pcap_parser.capture import export_filtered

    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))
    with pytest.raises(ValueError, match=r"time_start.*>.*time_end"):
        export_filtered(str(src), str(tmp_path / "out.pcap"), time_start=60.0, time_end=10.0)


# -- export_filtered : construction de la ligne de commande tshark ----------


def _fake_tshark(monkeypatch, returncode=0, stderr=""):
    """Monkeypatch shutil.which pour tshark et subprocess.run pour
    verifier la ligne de commande construite sans lancer tshark."""

    def fake_which(name):
        if name == "tshark":
            return "/usr/bin/tshark"
        return shutil.which(name)

    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args=args, returncode=returncode, stdout="", stderr=stderr)

    monkeypatch.setattr(shutil, "which", fake_which)
    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def test_export_filtered_sans_filtre_recopie_tout(monkeypatch, tmp_path):
    calls = _fake_tshark(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))
    out = str(tmp_path / "out.pcap")

    from pcap_parser.capture import export_filtered

    export_filtered(str(src), out)
    assert len(calls) == 1
    args = calls[0]
    assert "-r" in args
    assert "-w" in args
    assert str(src) in args
    assert out in args
    # Aucun filtre : pas de -f ni -Y
    assert "-f" not in args
    assert "-Y" not in args


def test_export_filtered_replie_le_filtre_dans_y_et_jamais_dans_f(monkeypatch, tmp_path):
    """Issue #261 : le critere libre part dans -Y, jamais dans -f.

    tshark refuse `-f` (filtre de capture) combine a `-r` (relecture de
    fichier) : "Only read filters, not capture filters, can be specified
    when reading a capture file". Tout appel avec bpf_filter levait donc
    TsharkError. L'ancien test verifiait la presence de `-f`, c'est-a-dire
    exactement le bug.
    """
    calls = _fake_tshark(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import export_filtered

    export_filtered(str(src), str(tmp_path / "out.pcap"), bpf_filter="tcp.port == 80")
    args = calls[0]
    assert "-f" not in args
    assert args[args.index("-Y") + 1] == "(tcp.port == 80)"


def test_export_filtered_rejette_une_syntaxe_bpf_avec_la_traduction(monkeypatch, tmp_path):
    """Une expression manifestement BPF doit produire une erreur lisible
    cote appelant, pas un message de parseur tshark."""
    _fake_tshark(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import export_filtered

    with pytest.raises(ValueError) as err:
        export_filtered(str(src), str(tmp_path / "out.pcap"), bpf_filter="tcp port 80")
    message = str(err.value)
    assert "BPF" in message
    assert "tcp.port == 80" in message


def test_export_filtered_impose_le_format_selon_l_extension(monkeypatch, tmp_path):
    """Issue #262 : sans -F, tshark ecrit du pcapng meme vers un .pcap."""
    calls = _fake_tshark(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import export_filtered

    export_filtered(str(src), str(tmp_path / "out.pcap"))
    assert calls[0][calls[0].index("-F") + 1] == "pcap"

    export_filtered(str(src), str(tmp_path / "out.pcapng"))
    assert calls[1][calls[1].index("-F") + 1] == "pcapng"


def test_export_filtered_avec_plage_temporelle_ajoute_y(monkeypatch, tmp_path):
    calls = _fake_tshark(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import export_filtered

    export_filtered(str(src), str(tmp_path / "out.pcap"), time_start=10.0, time_end=60.0)
    args = calls[0]
    assert "-Y" in args
    y_idx = args.index("-Y")
    display_filter = args[y_idx + 1]
    assert "frame.time_relative >= 10" in display_filter
    assert "frame.time_relative <= 60" in display_filter


def test_export_filtered_avec_endpoints_ajoute_y(monkeypatch, tmp_path):
    calls = _fake_tshark(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import export_filtered

    export_filtered(str(src), str(tmp_path / "out.pcap"), endpoints=["192.168.1.1", "10.0.0.1"])
    args = calls[0]
    assert "-Y" in args
    y_idx = args.index("-Y")
    display_filter = args[y_idx + 1]
    assert "ip.addr == 192.168.1.1" in display_filter
    assert "ip.addr == 10.0.0.1" in display_filter
    assert "||" in display_filter


def test_export_filtered_combine_bpf_et_display_filter(monkeypatch, tmp_path):
    calls = _fake_tshark(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import export_filtered

    export_filtered(
        str(src),
        str(tmp_path / "out.pcap"),
        bpf_filter="tcp",
        time_start=5.0,
        endpoints=["10.0.0.1"],
    )
    args = calls[0]
    assert "-f" not in args
    # Les trois criteres sont combines en ET dans un unique -Y, et
    # l'expression libre est parenthesee pour que ses eventuels || ne se
    # combinent pas de travers avec le && qui l'enchaine aux autres.
    filtre = args[args.index("-Y") + 1]
    assert filtre.count("&&") == 2
    assert "(tcp)" in filtre
    assert "frame.time_relative >= 5" in filtre
    assert "ip.addr == 10.0.0.1" in filtre


def test_export_filtered_tshark_absent_leve_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import export_filtered
    from pcap_parser.ek_source import TsharkNotFoundError

    with pytest.raises(TsharkNotFoundError):
        export_filtered(str(src), str(tmp_path / "out.pcap"))


def test_export_filtered_tshark_echoue_leve_tshark_error(monkeypatch, tmp_path):
    _fake_tshark(monkeypatch, returncode=1, stderr="bad filter")
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import export_filtered
    from pcap_parser.ek_source import TsharkError

    with pytest.raises(TsharkError, match="echoue"):
        export_filtered(str(src), str(tmp_path / "out.pcap"), bpf_filter="invalid filter")


# -- Tests reels (tshark installe) -----------------------------------------


@requires_tshark
def test_reel_export_100_paquets_d_un_pcap_de_1000(tmp_path):
    """Exporte 100 paquets d'un PCAP de 1000 (par count via BPF impossiblesur
    des paquets synthetiques sans IP -- on filtre par plage temporelle)."""
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(1000))

    from pcap_parser.capture import export_filtered

    # synthetic_packets : 1 paquet / 100ms, duree 100s pour 1000 paquets
    # Plage [0, 10s] = ~100 paquets
    out = str(tmp_path / "out.pcap")
    export_filtered(str(src), out, time_start=0.0, time_end=10.0)

    assert os.path.isfile(out)
    _, packets = read_pcap(out)
    assert 90 <= len(packets) <= 110  # tolerance pour les bornes


@requires_tshark
def test_reel_export_plage_temporelle_verifie_timestamps(tmp_path):
    """Filtre par plage temporelle et verifie que tous les paquets
    exportes sont dans la plage."""
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(1000))

    from pcap_parser.capture import export_filtered

    out = str(tmp_path / "out.pcap")
    export_filtered(str(src), out, time_start=20.0, time_end=40.0)

    _, packets = read_pcap(out)
    # Les paquets synthetiques sont a 0, 0.1, 0.2, ... secondes
    # Plage [20, 40] -> paquets 200 a 400 (environ)
    assert len(packets) > 0
    # Verifie que tous les indices de paquets sont dans la plage attendue
    from pcap_builders import frame_index

    indices = [frame_index(d) for _sec, _frac, d in packets]
    assert min(indices) >= 190  # tolerance
    assert max(indices) <= 410  # tolerance


@requires_tshark
def test_reel_export_sans_filtre_recopie_tout(tmp_path):
    """Sans aucun filtre, la capture entiere est recopiee."""
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(100))

    from pcap_parser.capture import export_filtered

    out = str(tmp_path / "out.pcap")
    export_filtered(str(src), out)

    _, packets = read_pcap(out)
    assert len(packets) == 100


@requires_tshark
def test_reel_export_format_pcapng(tmp_path):
    """Le format de sortie depend de l'extension."""
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(10))

    from pcap_parser.capture import export_filtered

    out = str(tmp_path / "out.pcapng")
    export_filtered(str(src), out)

    assert os.path.isfile(out)
    # Verifier que c'est un pcapng (magic number 0x0A0D0D0A)
    with open(out, "rb") as f:
        magic = f.read(4)
    assert magic == b"\x0a\x0d\x0d\x0a"


# -- tests reels : format de sortie et filtre (issues #261 et #262) -----------
#
# Ces tests exigent un vrai tshark. Ils existent parce que les 4 tests
# @requires_tshark livres avec l'issue #156 n'avaient jamais pu s'executer :
# tshark etait absent de tous les environnements de developpement du projet,
# et deux bugs bien reels sont restes invisibles pendant des mois.


def _ip_udp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes = b"netcross") -> bytes:
    """Construit une trame Ethernet/IPv4/UDP minimale mais VALIDE.

    `synthetic_packets` produit des trames sans protocole identifiable :
    tshark n'y voit rien a filtrer, donc aucun filtre d'affichage portant
    sur ip/udp/tcp ne peut y etre exerce. D'ou ce constructeur local.
    """
    import socket
    import struct

    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload

    total_len = 20 + udp_len
    ip_sans_somme = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0,
        0,
        64,
        socket.IPPROTO_UDP,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    mots = struct.unpack("!10H", ip_sans_somme)
    somme = sum(mots)
    somme = (somme & 0xFFFF) + (somme >> 16)
    somme = ~((somme & 0xFFFF) + (somme >> 16)) & 0xFFFF
    ip = ip_sans_somme[:10] + struct.pack("!H", somme) + ip_sans_somme[12:]

    ethernet = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
    return ethernet + ip + udp


def _magic(path) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(4)


PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


@requires_tshark
def test_pcap_et_pcapng_sont_bien_supportes_par_l_outil_installe():
    """Verifie l'hypothese sur laquelle repose _output_format_args.

    Le code passe "-F pcap"/"-F pcapng" sans interroger l'outil, au motif
    que ces deux formats sont le coeur de wiretap et presents dans toute
    construction de Wireshark. Plutot que de croire cette affirmation, on
    la verifie contre le binaire reellement installe : si une version les
    retirait, ce test echouerait au lieu de laisser l'export se degrader
    en silence.
    """
    for outil in ("tshark", "editcap"):
        chemin = shutil.which(outil)
        if chemin is None:  # pragma: no cover - garde-fou
            pytest.skip(f"{outil} absent")
        proc = subprocess.run([chemin, "-F"], capture_output=True, text=True, check=False)
        sortie = proc.stdout + proc.stderr
        assert "\n    pcap -" in sortie, f"{outil} n'annonce pas le format pcap"
        assert "\n    pcapng -" in sortie, f"{outil} n'annonce pas le format pcapng"


@requires_tshark
def test_reel_extension_pcap_produit_vraiment_du_pcap(tmp_path):
    """Issue #262 : le coeur du bug, verifie sur les octets ecrits."""
    from pcap_parser.capture import export_filtered

    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(10))

    out_pcap = tmp_path / "out.pcap"
    export_filtered(str(src), str(out_pcap))
    assert _magic(out_pcap) in PCAP_MAGIC, "extension .pcap mais contenu pcapng (bug #262)"

    out_pcapng = tmp_path / "out.pcapng"
    export_filtered(str(src), str(out_pcapng))
    assert _magic(out_pcapng) == PCAPNG_MAGIC


@requires_tshark
def test_reel_filtre_sur_port_udp_selectionne_les_bons_paquets(tmp_path):
    """Issue #261 : bpf_filter etait inutilisable, tout appel levait
    TsharkError. On l'exerce ici sur de vraies trames UDP."""
    from pcap_parser.capture import export_filtered

    paquets = []
    for i in range(6):
        port = 80 if i % 2 == 0 else 443
        paquets.append((1_700_000_000_000_000 + i * 100_000, _ip_udp_frame("10.0.0.1", "10.0.0.2", 5000, port)))
    src = tmp_path / "cap.pcap"
    write_pcap(src, paquets)

    out = tmp_path / "out.pcap"
    export_filtered(str(src), str(out), bpf_filter="udp.dstport == 443")
    _, gardes = read_pcap(out)
    assert len(gardes) == 3, "seuls les 3 paquets vers le port 443 devaient etre gardes"


@requires_tshark
def test_reel_filtre_combine_avec_endpoints_et_plage_temporelle(tmp_path):
    """Les criteres doivent se combiner en ET dans un unique -Y."""
    from pcap_parser.capture import export_filtered

    paquets = []
    for i in range(10):
        source = "10.0.0.1" if i < 5 else "10.0.0.9"
        paquets.append((1_700_000_000_000_000 + i * 1_000_000, _ip_udp_frame(source, "10.0.0.2", 5000, 80)))
    src = tmp_path / "cap.pcap"
    write_pcap(src, paquets)

    out = tmp_path / "out.pcap"
    # udp + emetteur 10.0.0.1 (5 paquets) + t >= 2s (paquets 2,3,4) -> 3
    export_filtered(str(src), str(out), bpf_filter="udp", endpoints=["10.0.0.1"], time_start=2.0)
    _, gardes = read_pcap(out)
    assert len(gardes) == 3


@requires_tshark
def test_reel_filtre_en_syntaxe_bpf_echoue_avant_d_appeler_tshark(tmp_path):
    """L'erreur doit venir de nous, avec la traduction, et non d'un
    message de parseur tshark."""
    from pcap_parser.capture import export_filtered

    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(3))
    out = tmp_path / "out.pcap"

    with pytest.raises(ValueError, match="BPF"):
        export_filtered(str(src), str(out), bpf_filter="udp port 443")
    assert not out.exists(), "aucun fichier ne doit etre produit quand le filtre est rejete"
