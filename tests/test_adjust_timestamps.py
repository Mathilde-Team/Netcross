# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests de pcap_parser.capture.adjust_timestamps / first_timestamp (Job 45,
issue #165) et de la CLI --adjust-time-output.

Meme convention que test_split_capture.py : par defaut editcap est SIMULE
et on verifie la ligne de commande construite. Les tests reels lancent le
VRAI editcap et sont sautes s'il est absent.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess

import pytest
from pcap_builders import (
    read_pcap,
    synthetic_packets,
    write_pcap,
)

requires_editcap = pytest.mark.skipif(
    shutil.which("editcap") is None,
    reason="editcap non installe",
)


# -- Helpers pour fabriquer des pcaps avec timestamps connus --------------


def _write_pcap_with_ts(path, ts_sec, ts_frac=0, nsec=False):
    """Ecrit un pcap minimal d'un seul paquet avec un timestamp precis."""
    magic = b"\x4d\x3c\xb2\xa1" if nsec else b"\xd4\xc3\xb2\xa1"
    # en-tete global (24 octets) : magic, version 2.4, thiszone=0,
    # sigfigs=0, snaplen=65535, linktype=1 (Ethernet)
    header = magic + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    # un seul paquet : ts_sec, ts_frac, incl_len, orig_len
    pkt_data = b"\x00" * 64
    record = struct.pack("<IIII", ts_sec, ts_frac, len(pkt_data), len(pkt_data)) + pkt_data
    path.write_bytes(header + record)


# -- first_timestamp --------------------------------------------------------


def test_first_timestamp_capture_inexistante(tmp_path):
    from pcap_parser.capture import first_timestamp

    with pytest.raises(FileNotFoundError):
        first_timestamp(str(tmp_path / "absent.pcap"))


def test_first_timestamp_format_inconnu_donne_valueerror(tmp_path):
    from pcap_parser.capture import first_timestamp

    (tmp_path / "bad.bin").write_bytes(b"NOT_A_PCAP")
    with pytest.raises(ValueError, match="format non reconnu"):
        first_timestamp(str(tmp_path / "bad.bin"))


def test_first_timestamp_pcap_classique(tmp_path):
    from pcap_parser.capture import first_timestamp

    path = tmp_path / "cap.pcap"
    _write_pcap_with_ts(path, 1000, 500000)  # 1000.5
    assert first_timestamp(str(path)) == pytest.approx(1000.5)


def test_first_timestamp_pcap_nanoseconde(tmp_path):
    from pcap_parser.capture import first_timestamp

    path = tmp_path / "cap.pcap"
    _write_pcap_with_ts(path, 2000, 500000000, nsec=True)  # 2000.5
    assert first_timestamp(str(path)) == pytest.approx(2000.5)


def test_first_timestamp_pcap_sans_paquet(tmp_path):
    from pcap_parser.capture import first_timestamp

    path = tmp_path / "empty.pcap"
    # en-tete global seul, aucun record
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
    with pytest.raises(ValueError, match="sans paquet"):
        first_timestamp(str(path))


def test_first_timestamp_synthetic_packets(tmp_path):
    from pcap_parser.capture import first_timestamp

    path = tmp_path / "cap.pcap"
    write_pcap(path, synthetic_packets(10))
    # synthetic_packets : premier paquet a une epoch fixe
    ts = first_timestamp(str(path))
    assert ts > 1_000_000_000  # epoch recente


# -- adjust_timestamps : validation ----------------------------------------


def test_adjust_timestamps_capture_inexistante(tmp_path):
    from pcap_parser.capture import adjust_timestamps

    with pytest.raises(FileNotFoundError):
        adjust_timestamps(str(tmp_path / "absent.pcap"), str(tmp_path / "out.pcap"))


# -- adjust_timestamps : ligne de commande editcap --------------------------


def _fake_editcap(monkeypatch, returncode=0, stderr=""):
    """Monkeypatch pour simuler editcap sans le lancer."""

    def fake_which(name):
        if name == "editcap":
            return "/usr/bin/editcap"
        return shutil.which(name)

    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args=args, returncode=returncode, stdout="", stderr=stderr)

    monkeypatch.setattr(shutil, "which", fake_which)
    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def test_adjust_offset_fixe_appelle_editcap_t(monkeypatch, tmp_path):
    calls = _fake_editcap(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import adjust_timestamps

    adjust_timestamps(str(src), str(tmp_path / "out.pcap"), offset_seconds=10.0)
    assert len(calls) == 1
    args = calls[0]
    assert "-t" in args
    t_idx = args.index("-t")
    assert "10.0" in args[t_idx + 1]


def test_adjust_offset_negatif(monkeypatch, tmp_path):
    calls = _fake_editcap(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import adjust_timestamps

    adjust_timestamps(str(src), str(tmp_path / "out.pcap"), offset_seconds=-3600.0)
    args = calls[0]
    t_idx = args.index("-t")
    assert "-3600" in args[t_idx + 1]


def test_adjust_normalize_calcule_offset_negatif_du_premier_paquet(monkeypatch, tmp_path):
    """En mode normalize, l'offset applique est -first_timestamp(path_in)."""
    calls = _fake_editcap(monkeypatch)
    src = tmp_path / "cap.pcap"
    _write_pcap_with_ts(src, 1000, 500000)  # 1000.5

    from pcap_parser.capture import adjust_timestamps

    adjust_timestamps(str(src), str(tmp_path / "out.pcap"), normalize=True)
    args = calls[0]
    t_idx = args.index("-t")
    offset_str = args[t_idx + 1]
    offset = float(offset_str)
    assert offset == pytest.approx(-1000.5)


def test_adjust_normalize_synthetic_packets_offset_negatif(monkeypatch, tmp_path):
    """Avec synthetic_packets, normalize donne offset = -first_timestamp."""
    calls = _fake_editcap(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import adjust_timestamps, first_timestamp

    adjust_timestamps(str(src), str(tmp_path / "out.pcap"), normalize=True)
    args = calls[0]
    t_idx = args.index("-t")
    offset = float(args[t_idx + 1])
    expected = -first_timestamp(str(src))
    assert offset == pytest.approx(expected, abs=0.001)


def test_adjust_align_to_calcule_difference(monkeypatch, tmp_path):
    """En mode align_to, l'offset est ref_ts - src_ts."""
    calls = _fake_editcap(monkeypatch)
    src = tmp_path / "src.pcap"
    ref = tmp_path / "ref.pcap"
    _write_pcap_with_ts(src, 1000, 0)  # 1000.0
    _write_pcap_with_ts(ref, 2000, 0)  # 2000.0

    from pcap_parser.capture import adjust_timestamps

    adjust_timestamps(str(src), str(tmp_path / "out.pcap"), align_to=str(ref))
    args = calls[0]
    t_idx = args.index("-t")
    offset = float(args[t_idx + 1])
    assert offset == pytest.approx(1000.0)  # 2000 - 1000


def test_adjust_align_to_prioritaire_sur_normalize(monkeypatch, tmp_path):
    """Si align_to et normalize sont fournis, align_to est prioritaire."""
    calls = _fake_editcap(monkeypatch)
    src = tmp_path / "src.pcap"
    ref = tmp_path / "ref.pcap"
    _write_pcap_with_ts(src, 1000, 0)
    _write_pcap_with_ts(ref, 3000, 0)

    from pcap_parser.capture import adjust_timestamps

    adjust_timestamps(str(src), str(tmp_path / "out.pcap"), normalize=True, align_to=str(ref))
    args = calls[0]
    t_idx = args.index("-t")
    offset = float(args[t_idx + 1])
    # align_to : 3000 - 1000 = 2000, pas normalize : -1000
    assert offset == pytest.approx(2000.0)


def test_adjust_sans_mode_recopie_avec_offset_zero(monkeypatch, tmp_path):
    """Sans mode (offset=0, normalize=False, align_to=None), offset=0."""
    calls = _fake_editcap(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import adjust_timestamps

    adjust_timestamps(str(src), str(tmp_path / "out.pcap"))
    args = calls[0]
    t_idx = args.index("-t")
    assert float(args[t_idx + 1]) == 0.0


def test_adjust_editcap_absent_leve_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import adjust_timestamps
    from pcap_parser.ek_source import TsharkNotFoundError

    with pytest.raises(TsharkNotFoundError):
        adjust_timestamps(str(src), str(tmp_path / "out.pcap"), offset_seconds=10.0)


def test_adjust_editcap_echoue_leve_tshark_error(monkeypatch, tmp_path):
    _fake_editcap(monkeypatch, returncode=1, stderr="bad format")
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import adjust_timestamps
    from pcap_parser.ek_source import TsharkError

    with pytest.raises(TsharkError):
        adjust_timestamps(str(src), str(tmp_path / "out.pcap"), offset_seconds=10.0)


# -- Tests reels (editcap installe) ----------------------------------------


@requires_editcap
def test_reel_offset_plus_10s(tmp_path):
    """Decale de +10s et verifie les nouveaux timestamps."""
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))
    out = tmp_path / "out.pcap"

    from pcap_parser.capture import adjust_timestamps

    adjust_timestamps(str(src), str(out), offset_seconds=10.0)
    assert os.path.isfile(out)
    _, packets = read_pcap(out)
    assert len(packets) == 5
    # synthetic_packets demarre a l'epoch 1_700_000_000 (pas a zero :
    # l'ancien commentaire de ce test l'affirmait a tort, et l'assertion
    # qui en decoulait n'avait jamais pu etre executee faute d'editcap).
    # On compare donc au premier timestamp de la SOURCE plutot qu'a une
    # constante, pour que le test survive a un changement de base.
    _, sources = read_pcap(src)
    src_first = sources[0][0] + sources[0][1] / 1e6
    first_ts = packets[0][0] + packets[0][1] / 1e6
    assert first_ts == pytest.approx(src_first + 10.0, abs=0.01)
    # L'ecart entre paquets doit etre preserve : un offset decale, il ne
    # reechelonne pas.
    second_ts = packets[1][0] + packets[1][1] / 1e6
    assert second_ts - first_ts == pytest.approx(0.1, abs=0.01)


@requires_editcap
def test_reel_normalize_premier_paquet_a_zero(tmp_path):
    """Normalise et verifie que le premier paquet est a t=0."""
    src = tmp_path / "cap.pcap"
    _write_pcap_with_ts(src, 1000, 500000)  # 1000.5
    out = tmp_path / "out.pcap"

    from pcap_parser.capture import adjust_timestamps

    adjust_timestamps(str(src), str(out), normalize=True)
    assert os.path.isfile(out)
    _, packets = read_pcap(out)
    first_ts = packets[0][0] + packets[0][1] / 1e6
    assert first_ts == pytest.approx(0.0, abs=0.01)


@requires_editcap
def test_reel_align_to(tmp_path):
    """Aligne src sur ref et verifie que le premier paquet de src correspond
    au premier paquet de ref."""
    src = tmp_path / "src.pcap"
    ref = tmp_path / "ref.pcap"
    _write_pcap_with_ts(src, 1000, 0)
    _write_pcap_with_ts(ref, 2000, 0)
    out = tmp_path / "out.pcap"

    from pcap_parser.capture import adjust_timestamps, first_timestamp

    adjust_timestamps(str(src), str(out), align_to=str(ref))
    out_ts = first_timestamp(str(out))
    ref_ts = first_timestamp(str(ref))
    assert out_ts == pytest.approx(ref_ts, abs=0.01)


@requires_editcap
def test_reel_extension_pcap_produit_vraiment_du_pcap(tmp_path):
    """Issue #262 : editcap aussi ecrivait du pcapng vers un .pcap."""
    from pcap_parser.capture import adjust_timestamps

    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    out_pcap = tmp_path / "out.pcap"
    adjust_timestamps(str(src), str(out_pcap), offset_seconds=1.0)
    with open(out_pcap, "rb") as fh:
        magic = fh.read(4)
    assert magic in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}, (
        "extension .pcap mais contenu pcapng (bug #262)"
    )

    out_pcapng = tmp_path / "out.pcapng"
    adjust_timestamps(str(src), str(out_pcapng), offset_seconds=1.0)
    with open(out_pcapng, "rb") as fh:
        assert fh.read(4) == b"\x0a\x0d\x0d\x0a"
