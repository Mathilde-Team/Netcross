# SPDX-License-Identifier: GPL-3.0-or-later
"""
Fusion de captures (Job 34, issue #154) : pcap_parser.capture.merge_captures
et le flag --merge de cross_capture_analyzer_cli.py.

Deux familles de tests, comme le reste de la suite pour tshark :
  - unitaires, SANS aucun outil Wireshark : shutil.which/subprocess.run
    sont remplaces, on verifie la sequence d'outils lancee, leurs
    arguments, la gestion d'erreur et le nettoyage des intermediaires ;
  - d'integration, avec les VRAIS mergecap/reordercap/editcap, sautes
    (skipif) s'ils ne sont pas dans le PATH. Les fichiers d'entree sont
    de petits pcap ecrits a la main (struct), donc lisibles sans tshark.
"""

import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

import cross_capture_analyzer_cli as analyzer_cli
import pcap_parser
import pcap_parser.capture as capture_mod
from pcap_parser.ek_source import TsharkError, TsharkNotFoundError

_TOOLS = ("mergecap", "reordercap", "editcap")
requires_wireshark_tools = pytest.mark.skipif(
    any(shutil.which(tool) is None for tool in _TOOLS),
    reason="mergecap/reordercap/editcap absents du PATH (paquet tshark)",
)

# ---------------------------------------------------------------------
# Fabrique / lecteur de pcap classique (sans dependance a tshark)
# ---------------------------------------------------------------------


def _frame(payload: bytes, ident: int = 1) -> bytes:
    """Trame Ethernet/IPv4/UDP minimale et valide."""
    udp = struct.pack("!HHHH", 1000, 2000, 8 + len(payload), 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ident, 0, 64, 17, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
    )
    eth = bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") + b"\x08\x00"
    return eth + ip + udp


def _write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> str:
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in packets:
            sec = int(ts)
            usec = round((ts - sec) * 1e6)
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            f.write(data)
    return str(path)


def _read_pcap(path) -> list[tuple[float, bytes]]:
    """Relit un pcap classique little-endian (microsecondes ou nanosecondes)."""
    raw = Path(path).read_bytes()
    magic = struct.unpack("<I", raw[:4])[0]
    assert magic in (0xA1B2C3D4, 0xA1B23C4D), f"pas un pcap classique little-endian : {magic:#x}"
    divisor = 1e6 if magic == 0xA1B2C3D4 else 1e9
    packets, offset = [], 24
    while offset < len(raw):
        sec, frac, caplen, _origlen = struct.unpack("<IIII", raw[offset : offset + 16])
        offset += 16
        packets.append((sec + frac / divisor, raw[offset : offset + caplen]))
        offset += caplen
    return packets


def _timestamps(path) -> list[float]:
    return [ts for ts, _data in _read_pcap(path)]


# ---------------------------------------------------------------------
# Unitaires : outils Wireshark simules
# ---------------------------------------------------------------------


class _FakeRun:
    """Remplace subprocess.run : enregistre chaque appel et, s'il reussit,
    cree le fichier de sortie de l'outil (que os.replace deplacera ensuite).
    fail_on="editcap" fait echouer cet outil seulement."""

    def __init__(self, fail_on: str | None = None, stderr: str = "boom"):
        self.calls: list[list[str]] = []
        self.fail_on = fail_on
        self.stderr = stderr

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        tool = os.path.basename(args[0])
        if tool == self.fail_on:
            return subprocess.CompletedProcess(args, 2, "", self.stderr)
        out = args[args.index("-w") + 1] if tool == "mergecap" else args[-1]
        Path(out).write_bytes(b"contenu-fusionne")
        return subprocess.CompletedProcess(args, 0, "", "")

    @property
    def tools(self) -> list[str]:
        return [os.path.basename(c[0]) for c in self.calls]


@pytest.fixture
def fake_tools(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    fake = _FakeRun()
    monkeypatch.setattr(subprocess, "run", fake)
    return fake


@pytest.fixture
def two_inputs(tmp_path):
    a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
    a.write_bytes(b"")
    b.write_bytes(b"")
    return str(a), str(b)


def test_merge_sans_dedup_lance_mergecap_puis_reordercap_seulement(fake_tools, two_inputs, tmp_path):
    a, b = two_inputs
    out = tmp_path / "fusion.pcapng"
    capture_mod.merge_captures([a, b], str(out))

    assert fake_tools.tools == ["mergecap", "reordercap"]
    mergecap_call = fake_tools.calls[0]
    assert mergecap_call[:3] == ["/usr/bin/mergecap", "-F", "pcapng"]
    assert mergecap_call[-2:] == [a, b]
    assert "-a" not in mergecap_call  # fusion par timestamp, PAS concatenation
    assert out.read_bytes() == b"contenu-fusionne"


def test_merge_dedup_ajoute_editcap_fenetre_de_temps_nulle(fake_tools, two_inputs, tmp_path):
    a, b = two_inputs
    capture_mod.merge_captures([a, b], str(tmp_path / "fusion.pcapng"), dedup=True)

    assert fake_tools.tools == ["mergecap", "reordercap", "editcap"]
    editcap_call = fake_tools.calls[2]
    # fenetre de temps 0 : meme contenu ET meme timestamp, jamais une
    # retransmission (meme contenu, autre instant)
    assert editcap_call[1:3] == ["-w", "0"]
    # editcap lit la sortie de reordercap, pas celle de mergecap
    assert editcap_call[-2] == fake_tools.calls[1][-1]


@pytest.mark.parametrize(
    ("nom_sortie", "format_attendu"),
    [("fusion.pcap", "pcap"), ("FUSION.PCAP", "pcap"), ("fusion.pcapng", "pcapng"), ("fusion", "pcapng")],
)
def test_merge_format_de_sortie_selon_extension(fake_tools, two_inputs, tmp_path, nom_sortie, format_attendu):
    a, b = two_inputs
    capture_mod.merge_captures([a, b], str(tmp_path / nom_sortie), dedup=True)
    for call in (fake_tools.calls[0], fake_tools.calls[2]):  # mergecap et editcap
        assert call[call.index("-F") + 1] == format_attendu


def test_merge_liste_vide_leve_value_error(fake_tools, tmp_path):
    with pytest.raises(ValueError, match="au moins un fichier"):
        capture_mod.merge_captures([], str(tmp_path / "fusion.pcapng"))
    assert fake_tools.calls == []


def test_merge_entree_absente_leve_file_not_found(fake_tools, two_inputs, tmp_path):
    a, _b = two_inputs
    with pytest.raises(FileNotFoundError, match=r"absent\.pcap"):
        capture_mod.merge_captures([a, str(tmp_path / "absent.pcap")], str(tmp_path / "fusion.pcapng"))
    assert fake_tools.calls == []


def test_merge_sortie_identique_a_une_entree_refusee(fake_tools, two_inputs):
    a, b = two_inputs
    with pytest.raises(ValueError, match="aussi une entree"):
        capture_mod.merge_captures([a, b], a)
    assert fake_tools.calls == []
    assert Path(a).read_bytes() == b""  # l'entree n'a pas ete ecrasee


def test_merge_repertoire_de_sortie_inexistant(fake_tools, two_inputs, tmp_path):
    a, b = two_inputs
    with pytest.raises(FileNotFoundError, match="repertoire de sortie"):
        capture_mod.merge_captures([a, b], str(tmp_path / "inexistant" / "fusion.pcapng"))


def test_merge_outil_absent_leve_tshark_not_found(monkeypatch, two_inputs, tmp_path):
    a, b = two_inputs
    monkeypatch.setattr(shutil, "which", lambda name: None if name == "reordercap" else f"/usr/bin/{name}")
    with pytest.raises(TsharkNotFoundError, match="reordercap"):
        capture_mod.merge_captures([a, b], str(tmp_path / "fusion.pcapng"))


def test_merge_editcap_absent_ne_bloque_pas_sans_dedup(monkeypatch, two_inputs, tmp_path):
    a, b = two_inputs
    monkeypatch.setattr(shutil, "which", lambda name: None if name == "editcap" else f"/usr/bin/{name}")
    monkeypatch.setattr(subprocess, "run", _FakeRun())
    capture_mod.merge_captures([a, b], str(tmp_path / "fusion.pcapng"))  # ne leve pas
    with pytest.raises(TsharkNotFoundError, match="editcap"):
        capture_mod.merge_captures([a, b], str(tmp_path / "fusion.pcapng"), dedup=True)


def test_merge_echec_outil_leve_tshark_error_sans_rien_laisser(monkeypatch, two_inputs, tmp_path):
    a, b = two_inputs
    out = tmp_path / "fusion.pcapng"
    out.write_bytes(b"ancienne-sortie")
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(subprocess, "run", _FakeRun(fail_on="editcap", stderr="fichier corrompu"))

    with pytest.raises(TsharkError) as exc_info:
        capture_mod.merge_captures([a, b], str(out), dedup=True)

    assert exc_info.value.returncode == 2
    assert "fichier corrompu" in exc_info.value.stderr
    assert "editcap" in str(exc_info.value)
    # ecriture atomique : la sortie preexistante est intacte, et aucun
    # intermediaire (mergecap/reordercap avaient pourtant reussi) ne traine
    assert out.read_bytes() == b"ancienne-sortie"
    assert sorted(os.listdir(tmp_path)) == ["a.pcap", "b.pcap", "fusion.pcapng"]


def test_merge_captures_exposee_par_pcap_parser_et_netcross_core():
    import netcross_core

    assert pcap_parser.merge_captures is capture_mod.merge_captures
    assert netcross_core.merge_captures is capture_mod.merge_captures


# ---------------------------------------------------------------------
# Integration : vrais mergecap / reordercap / editcap
# ---------------------------------------------------------------------


@pytest.fixture
def captures(tmp_path):
    """Deux points de capture de 3 paquets, dont UN paquet strictement
    identique (meme contenu, meme timestamp 104.0) present dans les deux."""
    a = _write_pcap(tmp_path / "a.pcap", [(100.0, _frame(b"a1")), (102.0, _frame(b"a2")), (104.0, _frame(b"commun"))])
    b = _write_pcap(tmp_path / "b.pcap", [(101.0, _frame(b"b1")), (103.0, _frame(b"b2")), (104.0, _frame(b"commun"))])
    return a, b


@requires_wireshark_tools
def test_fusion_de_deux_pcap_compte_tous_les_paquets(captures, tmp_path):
    out = tmp_path / "fusion.pcap"
    capture_mod.merge_captures(list(captures), str(out))
    assert len(_read_pcap(out)) == 6


@requires_wireshark_tools
def test_fusion_intercale_par_timestamp_quel_que_soit_l_ordre_des_fichiers(captures, tmp_path):
    a, b = captures
    out_ab, out_ba = tmp_path / "ab.pcap", tmp_path / "ba.pcap"
    capture_mod.merge_captures([a, b], str(out_ab))
    capture_mod.merge_captures([b, a], str(out_ba))
    attendu = [100.0, 101.0, 102.0, 103.0, 104.0, 104.0]
    assert _timestamps(out_ab) == attendu
    assert _timestamps(out_ba) == attendu


@requires_wireshark_tools
def test_fusion_reordonne_une_entree_non_ordonnee(captures, tmp_path):
    a, _b = captures
    desordre = _write_pcap(tmp_path / "desordre.pcap", [(110.0, _frame(b"c1")), (105.0, _frame(b"c0"))])
    out = tmp_path / "fusion.pcap"
    capture_mod.merge_captures([a, desordre], str(out))
    timestamps = _timestamps(out)
    assert timestamps == sorted(timestamps)
    assert len(timestamps) == 5


@requires_wireshark_tools
def test_fusion_sans_dedup_conserve_les_doublons(captures, tmp_path):
    out = tmp_path / "fusion.pcap"
    capture_mod.merge_captures(list(captures), str(out), dedup=False)
    contenus = [data for _ts, data in _read_pcap(out)]
    assert contenus.count(_frame(b"commun")) == 2


@requires_wireshark_tools
def test_fusion_dedup_supprime_les_paquets_communs_aux_deux_captures(captures, tmp_path):
    out = tmp_path / "fusion.pcap"
    capture_mod.merge_captures(list(captures), str(out), dedup=True)
    packets = _read_pcap(out)
    assert len(packets) == 5  # 6 - 1 doublon
    assert [data for _ts, data in packets].count(_frame(b"commun")) == 1


@requires_wireshark_tools
def test_fusion_dedup_conserve_une_retransmission_a_un_autre_instant(tmp_path):
    # meme contenu, timestamps differents : pas un doublon (c'est la donnee
    # que l'analyse multi-points cherche), dedup ou pas
    a = _write_pcap(tmp_path / "a.pcap", [(100.0, _frame(b"x")), (100.5, _frame(b"x"))])
    b = _write_pcap(tmp_path / "b.pcap", [(101.0, _frame(b"x"))])
    out = tmp_path / "fusion.pcap"
    capture_mod.merge_captures([a, b], str(out), dedup=True)
    assert _timestamps(out) == [100.0, 100.5, 101.0]


@requires_wireshark_tools
def test_fusion_pcapng_par_defaut_et_formats_d_entree_melanges(captures, tmp_path):
    a, b = captures
    a_pcapng = tmp_path / "a.pcapng"
    capture_mod.merge_captures([a], str(a_pcapng))
    assert a_pcapng.read_bytes()[:4] == b"\n\r\r\n"  # en-tete de section pcapng

    out = tmp_path / "fusion.pcap"  # pcapng + pcap en entree, pcap en sortie
    capture_mod.merge_captures([str(a_pcapng), b], str(out))
    assert len(_read_pcap(out)) == 6


@requires_wireshark_tools
def test_fusion_ne_laisse_aucun_intermediaire(captures, tmp_path):
    capture_mod.merge_captures(list(captures), str(tmp_path / "fusion.pcap"), dedup=True)
    assert sorted(os.listdir(tmp_path)) == ["a.pcap", "b.pcap", "fusion.pcap"]


@requires_wireshark_tools
def test_fusion_fichier_illisible_leve_tshark_error_et_epargne_la_sortie(captures, tmp_path):
    a, _b = captures
    corrompu = tmp_path / "corrompu.pcap"
    corrompu.write_bytes(b"ceci n'est pas une capture")
    out = tmp_path / "fusion.pcap"
    with pytest.raises(TsharkError):
        capture_mod.merge_captures([a, str(corrompu)], str(out))
    assert not out.exists()


# ---------------------------------------------------------------------
# CLI : cross_capture_analyzer_cli.py --merge
# ---------------------------------------------------------------------


def _run_cli(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", *args])
    analyzer_cli.main()


@pytest.fixture
def merge_spy(monkeypatch):
    calls = []
    monkeypatch.setattr(
        analyzer_cli, "merge_captures", lambda paths, out, dedup=False: calls.append((list(paths), out, dedup))
    )

    def analyse_interdite(*_a, **_k):
        raise AssertionError("--merge ne doit lancer AUCUNE analyse")

    monkeypatch.setattr(analyzer_cli, "parse_capture", analyse_interdite)
    monkeypatch.setattr(analyzer_cli, "parse_captures_parallel", analyse_interdite)
    return calls


def test_cli_merge_transmet_tous_les_chemins_sans_analyser(monkeypatch, capsys, merge_spy):
    _run_cli(monkeypatch, "--capture", "LAN=a.pcap,b.pcap", "--capture", "WAN=c.pcap", "--merge", "fusion.pcapng")
    assert merge_spy == [(["a.pcap", "b.pcap", "c.pcap"], "fusion.pcapng", False)]
    assert "3 fichier(s) fusionne(s) dans fusion.pcapng." in capsys.readouterr().out


def test_cli_merge_dedup_transmis(monkeypatch, capsys, merge_spy):
    _run_cli(monkeypatch, "--capture", "LAN=a.pcap", "--capture", "WAN=b.pcap", "--merge", "f.pcap", "--merge-dedup")
    assert merge_spy == [(["a.pcap", "b.pcap"], "f.pcap", True)]
    assert "dedupliques" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("args", "fragment"),
    [
        (["--capture", "LAN=a.pcap", "--merge-dedup"], "--merge-dedup necessite --merge"),
        (["--live", "LAN:eth0", "--merge", "f.pcap"], "--merge necessite --capture"),
        (
            ["--capture", "LAN=a.pcap", "--merge", "f.pcap", "--pdf-report", "r.pdf", "--triage"],
            "incompatible avec --pdf-report, --triage",
        ),
        (["--capture", "LAN=a.pcap", "--merge", "f.pcap", "--parallel"], "incompatible avec --parallel"),
        (["--capture", "LAN=a.pcap,", "--merge", "f.pcap"], "Format invalide pour --capture"),
    ],
)
def test_cli_merge_arguments_invalides(monkeypatch, capsys, merge_spy, args, fragment):
    with pytest.raises(SystemExit) as exc_info:
        _run_cli(monkeypatch, *args)
    assert exc_info.value.code == 1
    assert fragment in capsys.readouterr().err
    assert merge_spy == []


@pytest.mark.parametrize(
    "erreur",
    [
        FileNotFoundError("capture absente"),
        ValueError("sortie == entree"),
        TsharkNotFoundError("mergecap absent"),
        TsharkError("echec"),
    ],
)
def test_cli_merge_erreur_de_fusion_sortie_propre(monkeypatch, capsys, erreur):
    def echoue(paths, out, dedup=False):
        raise erreur

    monkeypatch.setattr(analyzer_cli, "merge_captures", echoue)
    with pytest.raises(SystemExit) as exc_info:
        _run_cli(monkeypatch, "--capture", "LAN=a.pcap", "--merge", "f.pcap")
    assert exc_info.value.code == 1
    assert f"--merge : {erreur}" in capsys.readouterr().err


@requires_wireshark_tools
def test_cli_merge_bout_en_bout_avec_les_vrais_outils(monkeypatch, capsys, captures, tmp_path):
    a, b = captures
    out = tmp_path / "fusion.pcap"
    _run_cli(monkeypatch, "--capture", f"LAN={a}", "--capture", f"WAN={b}", "--merge", str(out), "--merge-dedup")
    assert len(_read_pcap(out)) == 5
    assert "2 fichier(s) fusionne(s)" in capsys.readouterr().out
