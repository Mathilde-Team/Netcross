# SPDX-License-Identifier: GPL-3.0-or-later
"""
pcap_parser.capture.split_capture -- decoupage par duree / nombre de
paquets (wrapper editcap) et par taille (pcap_parser.capfile) -- Job 35,
issue #155.

Meme convention que le reste de la suite (voir test_ek_source.py) : par
defaut editcap est SIMULE (shutil.which + subprocess.run monkeypatches) et
on verifie la ligne de commande construite et le traitement de ce qu'il
produit. Les tests de la derniere section lancent le VRAI editcap et sont
sautes s'il est absent -- ils sont la seule preuve que le decoupage est
reellement correct (10 fichiers de 100 paquets, coherence temporelle...).
"""

import os
import shutil
import types

import pytest
from pcap_builders import (
    EPB,
    epb,
    frame,
    frame_index,
    idb,
    pcap_bytes,
    pcapng_packets,
    read_pcap,
    read_pcapng,
    shb,
    synthetic_packets,
    write_bytes,
    write_pcap,
)

import pcap_parser.capture as capture_mod
from pcap_parser import TsharkError, TsharkNotFoundError, split_capture
from pcap_parser.capfile import FORMAT_NSECPCAP, FORMAT_PCAP, FORMAT_PCAPNG, detect_format

FAKE_EDITCAP = "/usr/bin/editcap"


def _fake_editcap(monkeypatch, produce=None, returncode=0, stderr=""):
    """Simule editcap. `produce(out_base)` cree les fichiers qu'editcap
    aurait ecrits (out_base = dernier argument de la ligne de commande).
    Renvoie la liste ou s'accumulent les lignes de commande recues."""
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if produce is not None:
            produce(args[-1])
        return types.SimpleNamespace(returncode=returncode, stderr=stderr, stdout="")

    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: FAKE_EDITCAP)
    monkeypatch.setattr(capture_mod.subprocess, "run", fake_run)
    return calls


def _segment_name(out_base, index, stamp="20231114221320"):
    """Nommage d'editcap : <nom>_<NNNNN>_<horodatage><ext>."""
    stem, ext = os.path.splitext(out_base)
    return f"{stem}_{index:05d}_{stamp}{ext}"


# -- arguments invalides ---------------------------------------------------------


@pytest.mark.parametrize(
    ("by", "value"),
    [
        ("taille", 10),  # critere inconnu
        ("time", 0),
        ("time", -1),
        ("time", float("nan")),
        ("time", float("inf")),
        ("time", True),  # bool est un int en Python : refuse explicitement
        ("time", "60"),
        ("count", 1.5),  # nombre de paquets : entier
        ("size", 1000.5),  # octets : entier
    ],
)
def test_split_capture_refuse_des_arguments_invalides(tmp_path, by, value):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(3))
    with pytest.raises(ValueError):
        split_capture(str(src), str(tmp_path / "out"), by, value)
    assert not (tmp_path / "out").exists()  # rien n'est cree avant validation


def test_split_capture_accepte_un_float_entier_pour_count(tmp_path, monkeypatch):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(3))
    calls = _fake_editcap(monkeypatch)
    split_capture(str(src), str(tmp_path / "out"), "count", 100.0)
    assert calls[0][calls[0].index("-c") + 1] == "100"


def test_split_capture_capture_absente(tmp_path):
    with pytest.raises(FileNotFoundError):
        split_capture(str(tmp_path / "absent.pcap"), str(tmp_path / "out"))


# -- editcap absent --------------------------------------------------------------


@pytest.mark.parametrize(("by", "value"), [("time", 10), ("count", 10)])
def test_split_capture_leve_si_editcap_absent(tmp_path, monkeypatch, by, value):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(3))
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: None)
    with pytest.raises(TsharkNotFoundError, match="tshark"):
        split_capture(str(src), str(tmp_path / "out"), by, value)
    assert not (tmp_path / "out").exists()


def test_split_capture_size_n_a_pas_besoin_d_editcap(tmp_path, monkeypatch):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(100))
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: None)

    segments = split_capture(str(src), str(tmp_path / "out"), "size", 24 + 10 * 116)

    assert len(segments) == 10  # mode realise en Python pur (pcap_parser.capfile)


# -- ligne de commande editcap -----------------------------------------------------


def test_split_capture_time_pcap_conserve_le_format(tmp_path, monkeypatch):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(3))
    calls = _fake_editcap(monkeypatch)

    split_capture(str(src), str(tmp_path / "out"), "time", 60.0)

    # -F pcap : sans lui editcap ecrirait du pcapng dans un fichier nomme .pcap
    assert calls == [[FAKE_EDITCAP, "-F", "pcap", "-i", "60", str(src), str(tmp_path / "out" / "cap.pcap")]]


def test_split_capture_time_fractionnaire(tmp_path, monkeypatch):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(3))
    calls = _fake_editcap(monkeypatch)
    split_capture(str(src), str(tmp_path / "out"), "time", 0.5)
    assert calls[0][calls[0].index("-i") + 1] == "0.5"


def test_split_capture_count_pcapng(tmp_path, monkeypatch):
    src = tmp_path / "cap.pcapng"
    write_bytes(src, shb(), idb(), epb(frame(0)))
    calls = _fake_editcap(monkeypatch)

    split_capture(str(src), str(tmp_path / "out"), "count", 10000)

    assert calls == [[FAKE_EDITCAP, "-F", "pcapng", "-c", "10000", str(src), str(tmp_path / "out" / "cap.pcapng")]]


def test_split_capture_pcap_nanoseconde(tmp_path, monkeypatch):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(3), nsec=True)
    calls = _fake_editcap(monkeypatch)
    split_capture(str(src), str(tmp_path / "out"), "count", 5)
    assert calls[0][1:3] == ["-F", FORMAT_NSECPCAP]
    assert calls[0][-1].endswith("cap.pcap")


def test_split_capture_format_inconnu_sans_option_f_et_sortie_pcapng(tmp_path, monkeypatch):
    src = tmp_path / "cap.pcap.gz"
    src.write_bytes(b"\x1f\x8b\x08\x00 compresse")
    calls = _fake_editcap(monkeypatch)
    split_capture(str(src), str(tmp_path / "out"), "count", 5)
    assert "-F" not in calls[0]
    assert calls[0][-1] == str(tmp_path / "out" / "cap.pcap.pcapng")  # nom = fichier sans sa derniere extension


def test_split_capture_cree_le_repertoire_de_sortie(tmp_path, monkeypatch):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(3))
    _fake_editcap(monkeypatch)
    cible = tmp_path / "a" / "b" / "segments"
    split_capture(str(src), str(cible), "count", 2)
    assert cible.is_dir()


# -- traitement de ce qu'editcap produit ------------------------------------------


def test_split_capture_ecarte_les_segments_vides_et_trie_numeriquement(tmp_path, monkeypatch):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(3))
    plein = pcap_bytes(synthetic_packets(2))
    vide = pcap_bytes([])

    def produce(out_base):
        # index volontairement dans le desordre alphabetique : "100000" < "99999"
        # en tri lexicographique, mais vient APRES en tri numerique
        for index, contenu in ((100000, plein), (9, plein), (10, vide), (11, plein), (99999, plein)):
            with open(_segment_name(out_base, index), "wb") as f:
                f.write(contenu)

    _fake_editcap(monkeypatch, produce)

    segments = split_capture(str(src), str(tmp_path / "out"), "time", 10)

    assert [int(os.path.basename(s).split("_")[1]) for s in segments] == [9, 11, 99999, 100000]
    assert not any("_00010_" in name for name in os.listdir(tmp_path / "out"))  # le vide est supprime du disque


def test_split_capture_editcap_en_echec_leve_et_nettoie(tmp_path, monkeypatch):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(3))

    def produce(out_base):  # editcap a eu le temps d'ecrire un segment avant d'echouer
        with open(_segment_name(out_base, 0), "wb") as f:
            f.write(pcap_bytes(synthetic_packets(1)))

    _fake_editcap(monkeypatch, produce, returncode=3, stderr="editcap: disque plein\n")

    with pytest.raises(TsharkError, match="code 3") as excinfo:
        split_capture(str(src), str(tmp_path / "out"), "count", 1)

    assert excinfo.value.returncode == 3
    assert "disque plein" in excinfo.value.stderr
    assert os.listdir(tmp_path / "out") == []  # pas de jeu partiel trompeur


def test_split_capture_refuse_de_melanger_avec_des_segments_existants(tmp_path, monkeypatch):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(3))
    sortie = tmp_path / "out"
    sortie.mkdir()
    ancien = sortie / "cap_00000_20200101000000.pcap"
    ancien.write_bytes(b"segment d'un run precedent")
    calls = _fake_editcap(monkeypatch)

    with pytest.raises(FileExistsError, match="cap"):
        split_capture(str(src), str(sortie), "count", 1)

    assert calls == []  # editcap n'est meme pas lance
    assert ancien.read_bytes() == b"segment d'un run precedent"


def test_split_capture_ne_confond_pas_les_segments_d_une_autre_capture(tmp_path, monkeypatch):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(3))
    sortie = tmp_path / "out"
    sortie.mkdir()
    (sortie / "autre_00000_20200101000000.pcap").write_bytes(pcap_bytes(synthetic_packets(1)))
    _fake_editcap(monkeypatch)  # ne produit rien

    assert split_capture(str(src), str(sortie), "count", 1) == []  # pas de FileExistsError, et pas de fuite


# -- vrai editcap -----------------------------------------------------------------

requires_editcap = pytest.mark.skipif(shutil.which("editcap") is None, reason="editcap absent")


def _timestamps_us(segment):
    return [sec * 1_000_000 + frac for sec, frac, _data in read_pcap(segment)[1]]


@requires_editcap
def test_reel_count_1000_paquets_en_10_fichiers_de_100(tmp_path):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(1000))

    segments = split_capture(str(src), str(tmp_path / "out"), "count", 100)

    assert len(segments) == 10
    assert [len(read_pcap(s)[1]) for s in segments] == [100] * 10
    assert all(detect_format(s) == FORMAT_PCAP for s in segments)  # format d'origine conserve
    indices = [frame_index(d) for s in segments for _sec, _frac, d in read_pcap(s)[1]]
    assert indices == list(range(1000))


@requires_editcap
def test_reel_time_coherence_temporelle(tmp_path):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(1000))  # 100 s de trafic, 1 paquet / 100 ms
    intervalle_us = 10_000_000

    segments = split_capture(str(src), str(tmp_path / "out"), "time", 10)

    assert len(segments) == 10
    tranches = [_timestamps_us(s) for s in segments]
    for ts in tranches:
        assert ts == sorted(ts)
        assert ts[-1] - ts[0] <= intervalle_us  # un segment ne depasse jamais l'intervalle
    for avant, apres in zip(tranches, tranches[1:], strict=False):
        assert avant[-1] < apres[0]  # segments consecutifs, sans chevauchement
    # aucun paquet perdu ni duplique, dans l'ordre
    indices = [frame_index(d) for s in segments for _sec, _frac, d in read_pcap(s)[1]]
    assert indices == list(range(1000))


@requires_editcap
def test_reel_time_un_silence_ne_produit_pas_de_segment_vide(tmp_path):
    src = tmp_path / "cap.pcap"
    # 300 paquets a 1 s d'ecart, mais 60 s de silence apres le 100e
    paquets = [(1_700_000_000_000_000 + i * 1_000_000 + (60_000_000 if i >= 100 else 0), frame(i)) for i in range(300)]
    write_pcap(src, paquets)

    segments = split_capture(str(src), str(tmp_path / "out"), "time", 10)

    assert all(len(read_pcap(s)[1]) > 0 for s in segments)
    assert sum(len(read_pcap(s)[1]) for s in segments) == 300
    numeros = [int(os.path.basename(s).split("_")[1]) for s in segments]
    assert max(numeros) + 1 > len(segments)  # des numeros manquent : ce sont les silences


@requires_editcap
def test_reel_count_pcapng(tmp_path):
    src = tmp_path / "cap.pcapng"
    write_bytes(src, shb(), idb(), *[epb(frame(i), ts_us=1_700_000_000_000_000 + i) for i in range(1000)])

    segments = split_capture(str(src), str(tmp_path / "out"), "count", 100)

    assert len(segments) == 10
    assert all(s.endswith(".pcapng") and detect_format(s) == FORMAT_PCAPNG for s in segments)
    assert all(sum(1 for b in read_pcapng(s) if b[0] == EPB) == 100 for s in segments)
    indices = [frame_index(d) for s in segments for _i, d in pcapng_packets(s)]
    assert indices == list(range(1000))
