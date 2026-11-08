"""Inventaire horodate du tampon circulaire et selection par fenetre (issue #1086)."""

from __future__ import annotations

import shutil
import struct
from types import SimpleNamespace

import pytest

from pcap_parser.capture import RingFile, ring_inventory, select_ring_files

T0 = 1_790_000_000.0


def _info(start, end, count=10):
    return SimpleNamespace(start_time=start, end_time=end, packet_count=count)


def _ring(tmp_path, intervals, prefix="capture", ext="pcapng"):
    """Cree les fichiers du tampon et un lecteur factice qui renvoie leurs intervalles."""
    infos = {}
    for i, iv in enumerate(intervals, start=1):
        path = tmp_path / f"{prefix}_{i:05d}_20261030120{i:03d}.{ext}"
        path.write_bytes(b"")
        infos[str(path)] = None if iv is None else _info(*iv)
    return infos.get


# -- RingFile -------------------------------------------------------------------------


def test_ringfile_covers_bornes_incluses():
    f = RingFile("f", 1, 10.0, 20.0)
    assert f.known
    assert f.covers(20.0, 30.0)  # fin du fichier == debut de fenetre
    assert f.covers(0.0, 10.0)  # debut du fichier == fin de fenetre
    assert f.covers(12.0, 13.0)  # fenetre incluse
    assert f.covers(0.0, 100.0)  # fichier inclus
    assert not f.covers(20.000001, 30.0)
    assert not f.covers(0.0, 9.999999)


def test_ringfile_intervalle_inconnu():
    for f in (RingFile("f", 1, None, None), RingFile("f", 1, 1.0, None), RingFile("f", 1, None, 1.0)):
        assert not f.known
        assert not f.covers(0.0, 1e12)


# -- ring_inventory -----------------------------------------------------------------------


def test_inventaire_trie_par_rotation_avec_intervalles(tmp_path):
    reader = _ring(tmp_path, [(T0, T0 + 10), (T0 + 10, T0 + 20), (T0 + 20, T0 + 25)])
    (tmp_path / "autre.pcapng").write_bytes(b"")  # hors tampon
    (tmp_path / "capture.pcapng").write_bytes(b"")  # nom de base sans rotation
    (tmp_path / "x_00001_20261030120001.pcapng").write_bytes(b"")  # autre prefixe
    inv = ring_inventory(str(tmp_path), reader=reader)
    assert [f.index for f in inv] == [1, 2, 3]
    assert [(f.start, f.end) for f in inv] == [(T0, T0 + 10), (T0 + 10, T0 + 20), (T0 + 20, T0 + 25)]
    assert all(f.packet_count == 10 for f in inv)
    assert inv[0].path.endswith("capture_00001_20261030120001.pcapng")


def test_inventaire_tri_numerique_au_dela_de_99999(tmp_path):
    for name in ("capture_100000_20261030120000.pcapng", "capture_99999_20261030120000.pcapng"):
        (tmp_path / name).write_bytes(b"")
    inv = ring_inventory(str(tmp_path), reader=lambda p: _info(T0, T0))
    assert [f.index for f in inv] == [99999, 100000]


def test_inventaire_prefixe_et_extension_pcap(tmp_path):
    reader = _ring(tmp_path, [(T0, T0 + 1)], prefix="ring-P1", ext="pcap")
    inv = ring_inventory(str(tmp_path), prefix="ring-P1", reader=reader)
    assert len(inv) == 1
    assert inv[0].known


def test_inventaire_intervalles_inconnus_ou_incoherents(tmp_path):
    reader = _ring(tmp_path, [None, (None, None), (T0 + 5, T0)])
    inv = ring_inventory(str(tmp_path), reader=reader)
    assert len(inv) == 3
    assert not any(f.known for f in inv)
    assert inv[0].packet_count is None


def test_inventaire_repertoire_absent(tmp_path):
    assert ring_inventory(str(tmp_path / "absent"), reader=lambda p: pytest.fail("ne doit pas lire")) == []


def test_inventaire_lecteur_par_defaut(tmp_path, monkeypatch):
    import pcap_parser.capinfos_source as cs

    vus = []
    monkeypatch.setattr(cs, "read_capture_info", lambda p: vus.append(p) or _info(T0, T0 + 1))
    _ring(tmp_path, [(0, 0)])
    assert ring_inventory(str(tmp_path))[0].start == T0
    assert len(vus) == 1


# -- select_ring_files -------------------------------------------------------------------------


@pytest.fixture
def inventaire():
    return [
        RingFile("f1", 1, 0.0, 10.0),
        RingFile("f2", 2, 10.0, 20.0),  # chevauche f1 a la borne 10.0
        RingFile("f3", 3, 15.0, 30.0),  # chevauche f2
        RingFile("f4", 4, None, None),  # intervalle inconnu
        RingFile("f5", 5, 40.0, 50.0),  # apres un trou
    ]


def _noms(fichiers):
    return [f.path for f in fichiers]


@pytest.mark.parametrize(
    ("debut", "fin", "attendu"),
    [
        (10.0, 10.0, ["f1", "f2"]),  # borne exacte partagee par deux fichiers
        (12.0, 16.0, ["f2", "f3"]),  # chevauchement
        (0.0, 0.0, ["f1"]),  # premier paquet exact
        (50.0, 50.0, ["f5"]),  # dernier paquet exact
        (31.0, 39.0, []),  # trou entre deux fichiers
        (30.0, 40.0, ["f3", "f5"]),  # bornes exactes des deux cotes du trou
        (-5.0, 100.0, ["f1", "f2", "f3", "f5"]),  # tout le tampon
        (50.000001, 60.0, []),  # juste apres la fin
    ],
)
def test_selection_fenetre(inventaire, debut, fin, attendu):
    assert _noms(select_ring_files(inventaire, debut, fin)) == attendu


def test_selection_inclut_les_inconnus_sur_demande(inventaire):
    assert _noms(select_ring_files(inventaire, 31.0, 39.0, include_unknown=True)) == ["f4"]
    assert _noms(select_ring_files(inventaire, 12.0, 16.0, include_unknown=True)) == ["f2", "f3", "f4"]


def test_selection_fenetre_invalide(inventaire):
    with pytest.raises(ValueError):
        select_ring_files(inventaire, 2.0, 1.0)


def test_selection_inventaire_vide():
    assert select_ring_files([], 0.0, 1.0) == []


# -- bout en bout avec capinfos reel -----------------------------------------------------------


def _pcap(path, timestamps):
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    frame = bytes(14)  # en-tete Ethernet nul
    for ts in timestamps:
        data += struct.pack("<IIII", int(ts), round((ts % 1) * 1e6), len(frame), len(frame)) + frame
    path.write_bytes(data)


@pytest.mark.skipif(shutil.which("capinfos") is None, reason="capinfos (wireshark-common) absent")
def test_bout_en_bout_capinfos(tmp_path):
    _pcap(tmp_path / "capture_00001_20261030120000.pcap", [T0, T0 + 4.5])
    _pcap(tmp_path / "capture_00002_20261030120005.pcap", [T0 + 5, T0 + 9])
    inv = ring_inventory(str(tmp_path))
    assert [(f.start, f.end, f.packet_count) for f in inv] == [(T0, T0 + 4.5, 2), (T0 + 5, T0 + 9, 2)]
    assert [f.index for f in select_ring_files(inv, T0 + 4.5, T0 + 5)] == [1, 2]
    assert [f.index for f in select_ring_files(inv, T0 + 6, T0 + 7)] == [2]
