# SPDX-License-Identifier: GPL-3.0-or-later
"""Relit les échantillons des WAV alignés, pas seulement leurs en-têtes (#1127)."""

import hashlib
import json
import math
import shutil
import sys
import wave
from dataclasses import replace
from pathlib import Path

import pytest
from pcap_builders import write_pcap
from test_content_extraction import rtp
from test_content_extraction_pcap import _udp

import cross_capture_analyzer_cli as cli
from netcross_core.extract import media
from netcross_core.extract.media import RtpStream, _RtpPacket, decode_g711, export_aligned_audio
from netcross_core.rtp_match import SEQ_MOD, TS_MOD


def stream(point, *, missing=(), seq_offset=0, ts_offset=0, codec="PCMU", n=20):
    packets = [
        _RtpPacket(
            arrival=10 + i * 0.02 + (0.005 if point != "A" else 0),
            seq=(SEQ_MOD - 5 + i + seq_offset) % SEQ_MOD,
            ts=(TS_MOD - 800 + i * 160 + ts_offset) % TS_MOD,
            pt=0 if codec == "PCMU" else 8,
            marker=False,
            payload=bytes([128 + i % 30]) * 160,
        )
        for i in range(n)
        if i not in missing
    ]
    return RtpStream(
        point,
        "10.1.0.1",
        40000,
        "10.2.0.2",
        50000,
        123 if not seq_offset else 456,
        0 if codec == "PCMU" else 8,
        codec=codec,
        clock_rate=8000,
        kind="audio",
        packets=packets,
    )


def read(path):
    with wave.open(str(path), "rb") as source:
        return source.getparams(), source.readframes(source.getnframes())


def test_trois_points_origine_duree_silences_et_stereo_exacts(tmp_path):
    a = stream("A")
    b = stream("B", missing=(0, 1, 10, 19))
    c = stream("C", missing=(3,), seq_offset=32000, ts_offset=5000)
    records, errors = export_aligned_audio([c, b, a], tmp_path, ["A", "B", "C"])
    assert errors == []
    (record,) = records
    assert record["origin_rtp_timestamp"] == TS_MOD - 800
    assert record["samples"] == 3200 and record["duration_s"] == 0.4
    assert record["sample_rate"] == 8000
    assert record["stereo"]["left"] == "A" and record["stereo"]["right"] == "C"
    pcm = {}
    for info in record["mono"]:
        params, data = read(info["path"])
        assert params.nchannels == 1 and params.nframes == 3200 and params.framerate == 8000
        assert params.sampwidth == 2
        assert Path(info["path"]).stat().st_mode & 0o777 == 0o600
        assert hashlib.sha256(Path(info["path"]).read_bytes()).hexdigest() == info["sha256"]
        pcm[info["point"]] = data
    for i in range(20):
        expected = decode_g711("PCMU", bytes([128 + i]) * 160)
        assert pcm["A"][i * 320 : (i + 1) * 320] == expected
        assert pcm["B"][i * 320 : (i + 1) * 320] == (bytes(320) if i in (0, 1, 10, 19) else expected)
        assert pcm["C"][i * 320 : (i + 1) * 320] == (bytes(320) if i == 3 else expected)
    params, stereo = read(record["stereo"]["path"])
    assert params.nchannels == 2 and params.nframes == 3200 and params.framerate == 8000
    assert stereo[0::4] == pcm["A"][0::2] and stereo[1::4] == pcm["A"][1::2]
    assert stereo[2::4] == pcm["C"][0::2] and stereo[3::4] == pcm["C"][1::2]
    assert Path(record["stereo"]["path"]).stat().st_mode & 0o777 == 0o600


def test_blocs_stereo_multiples_et_codecs_g711_differents(tmp_path):
    records, errors = export_aligned_audio([stream("A", n=250), stream("B", codec="PCMA", n=250)], tmp_path)
    assert errors == []
    (record,) = records
    _, left = read(record["mono"][0]["path"])
    _, right = read(record["mono"][1]["path"])
    _, stereo = read(record["stereo"]["path"])
    assert stereo[0::4] == left[0::2] and stereo[1::4] == left[1::2]
    assert stereo[2::4] == right[0::2] and stereo[3::4] == right[1::2]


def test_aucune_identification_inventee_pour_flux_isole_chiffre_ou_incompatible(tmp_path):
    a = stream("A")
    for excluded in [
        replace(stream("B"), encrypted=True),
        replace(stream("B"), codec="G729"),
        replace(stream("B"), kind="video"),
        replace(stream("B"), packets=[]),
    ]:
        assert export_aligned_audio([a, excluded], tmp_path) == ([], [])
    assert not list(tmp_path.rglob("*.wav"))


@pytest.mark.parametrize("budget", [0, -1, math.nan, math.inf])
def test_budget_invalide_refuse(budget, tmp_path):
    with pytest.raises(ValueError, match="fini et strictement positif"):
        export_aligned_audio([], tmp_path, max_duration_seconds=budget)


def test_budget_excede_refuse_sans_tronquer_ni_allouer(tmp_path):
    records, errors = export_aligned_audio([stream("A"), stream("B")], tmp_path, max_duration_seconds=0.1)
    assert not records and "budget" in errors[0]
    assert not list(tmp_path.rglob("*.wav"))


@pytest.mark.parametrize("variant", ["horloge", "pt", "chevauchement", "vide"])
def test_flux_non_alignable_signale_sans_fichier(variant, tmp_path):
    a, b = stream("A"), stream("B")
    if variant == "horloge":
        b.clock_rate = 16000
    elif variant == "pt":
        b.packets[5] = replace(b.packets[5], pt=101)
    elif variant == "chevauchement":
        b.packets[5] = replace(b.packets[5], payload=bytes(320))
    else:
        a.packets = [replace(packet, payload=b"") for packet in a.packets]
        b.packets = [replace(packet, payload=b"") for packet in b.packets]
        a.packets = [replace(packet, ts=42) for packet in a.packets]
        b.packets = [replace(packet, ts=42) for packet in b.packets]
    records, errors = export_aligned_audio([a, b], tmp_path)
    assert records == [] and errors
    assert not list(tmp_path.rglob("*.wav"))


@pytest.mark.parametrize("collision", ["aligne-0001-01.wav", "aligne-0001-02.wav", "comparaison-0001-stereo.wav"])
def test_refus_ecrasement_et_nettoyage_limite_aux_nouveaux_fichiers(collision, tmp_path):
    target = tmp_path / "audio"
    target.mkdir()
    existing = target / collision
    existing.write_bytes(b"preuve preexistante")
    records, errors = export_aligned_audio([stream("A"), stream("B")], tmp_path)
    assert not records and "écraser" in errors[0]
    assert existing.read_bytes() == b"preuve preexistante"
    assert list(target.iterdir()) == [existing]


def test_echec_io_nettoie_les_wav_de_ce_groupe(tmp_path, monkeypatch):
    def failure(*args):
        raise OSError("espace insuffisant")

    monkeypatch.setattr(media, "_write_aligned_wav", failure)
    records, errors = export_aligned_audio([stream("A"), stream("B")], tmp_path)
    assert not records and "espace insuffisant" in errors[0]
    assert not list(tmp_path.rglob("*.wav"))


@pytest.mark.parametrize("channels", [1, 2])
def test_erreur_wave_nettoie_mono_et_stereo_partiels(channels, tmp_path, monkeypatch):
    original = wave.Wave_write.writeframesraw

    def failure(output, data):
        if output.getnchannels() == channels:
            raise wave.Error("écriture WAV impossible")
        return original(output, data)

    monkeypatch.setattr(wave.Wave_write, "writeframesraw", failure)
    records, errors = export_aligned_audio([stream("A"), stream("B")], tmp_path)
    assert not records and "écriture WAV impossible" in errors[0]
    assert not list(tmp_path.rglob("*.wav"))


def test_creation_concurrente_ne_supprime_pas_le_fichier_tiers(tmp_path, monkeypatch):
    original = Path.open
    name = "aligne-0001-01.wav"

    def race(path, mode="r", *args, **kwargs):
        if path.name == name and mode == "xb":
            with original(path, "wb") as existing:
                existing.write(b"creation concurrente")
        return original(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", race)
    records, errors = export_aligned_audio([stream("A"), stream("B")], tmp_path)
    assert not records and errors
    assert (tmp_path / "audio" / name).read_bytes() == b"creation concurrente"
    assert len(list(tmp_path.rglob("*.wav"))) == 1


def test_doublons_et_desordre_ne_changent_pas_les_echantillons(tmp_path):
    a, b = stream("A"), stream("B")
    b.packets = [*reversed(b.packets), b.packets[5]]
    records, errors = export_aligned_audio([a, b], tmp_path)
    assert not errors
    assert read(records[0]["mono"][0]["path"])[1] == read(records[0]["mono"][1]["path"])[1]


def test_vraie_cli_trois_pcap_ordre_physique_manifeste_et_audio_exact(tmp_path, monkeypatch, capsys):
    assert shutil.which("tshark"), "TShark est requis : pas de saut pour le décodage réel"
    args = ["cli"]
    for source in [
        stream("C", missing=(3,), seq_offset=32000, ts_offset=5000),
        stream("B", missing=(0, 1, 10, 19)),
        stream("A"),
    ]:
        frames = [
            (
                1_700_000_000_000_000 + round(packet.arrival * 1_000_000),
                _udp(
                    source.src,
                    source.dst,
                    source.sport,
                    source.dport,
                    rtp(packet.seq, packet.ts, pt=packet.pt, ssrc=source.ssrc, payload=packet.payload),
                ),
            )
            for packet in source.packets
        ]
        path = tmp_path / f"{source.point}.pcap"
        write_pcap(path, frames)
        args.extend(["--capture", f"{source.point}={path}"])
    out = tmp_path / "extraction"
    args.extend(["--order", "A,B,C", "--extract-contents", str(out), "--extract-kinds", "audio"])
    monkeypatch.setattr(sys, "argv", args)
    cli.main()
    captured = capsys.readouterr()
    assert "A à gauche / C à droite" in captured.out
    assert "Rappel d'usage raisonne" in captured.err
    manifest = json.loads((out / "manifest.json").read_text())
    (record,) = manifest["audio_comparisons"]
    assert not manifest["errors"]
    assert record["samples"] == 3200
    assert [item["point"] for item in record["mono"]] == ["A", "B", "C"]
    assert len(list(out.rglob("*.wav"))) == 4  # Trois mono alignés, une stéréo ; aucun original redondant.
    assert {quality["exported"] for quality in manifest["media"]} == {info["path"] for info in record["mono"]}
    for info in [*record["mono"], record["stereo"]]:
        params, _data = read(info["path"])
        assert params.nframes == record["samples"]
        assert hashlib.sha256(Path(info["path"]).read_bytes()).hexdigest() == info["sha256"]
    assert Path(record["mono"][0]["path"]).parent.stat().st_mode & 0o777 == 0o700
    _, left = read(record["mono"][0]["path"])
    _, right = read(record["mono"][-1]["path"])
    _, stereo = read(record["stereo"]["path"])
    assert right[3 * 320 : 4 * 320] == bytes(320) and left[3 * 320 : 4 * 320] != bytes(320)
    assert stereo[0::4] == left[0::2] and stereo[1::4] == left[1::2]
    assert stereo[2::4] == right[0::2] and stereo[3::4] == right[1::2]
